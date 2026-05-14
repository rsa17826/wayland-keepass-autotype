from __future__ import annotations
import argparse
import base64
import fnmatch
import hashlib
import hmac
import json
import os
import signal
import struct
import subprocess
import time
import evdev
from evdev import InputDevice, ecodes, UInput
from urllib.parse import parse_qs, urlparse

import evdev
from evdev import UInput, ecodes as e

from pykeepass.pykeepass import PyKeePass
from sopsy import Sops

# ── CLI args ──────────────────────────────────────────────────────────────────
_parser = argparse.ArgumentParser(description="KeePass autotype for Hyprland")
_ = _parser.add_argument(
  "--db",
  "-d",
  default="keepass.kdbx",
  help="Path to the .kdbx database file",
)
_ = _parser.add_argument(
  "--secrets",
  "-s",
  default="secrets.yml",
  help="Path to the sops-encrypted secrets file",
)
_ = _parser.add_argument(
  "--cache-ttl",
  "-c",
  type=int,
  default=0,
  metavar="SECONDS",
  help="Cache the KeePass password for this many seconds of inactivity (0 = disabled)",
)
_ = _parser.add_argument(
  "--password-only",
  "-p",
  action="store_true",
  help="Type only the password instead of the full autotype sequence",
)
_ = _parser.add_argument(
  "--otp-only",
  "-o",
  action="store_true",
  help="Type only the current OTP/TOTP code instead of the full autotype sequence",
)
args = _parser.parse_args()

if args.password_only and args.otp_only:
  _parser.error("--password-only and --otp-only are mutually exclusive")

# ── KeePass password: cache + watchdog auto-expiry ───────────────────────────
_USER = os.getenv("USER", "user")
_CACHE_FILE = f"/tmp/.kp_pw_cache_{_USER}"
_WATCHDOG_PID = f"/tmp/.kp_pw_watchdog_{_USER}.pid"


def _kill_old_watchdog() -> None:
  """Terminate any previously spawned watchdog process."""
  try:
    with open(_WATCHDOG_PID) as f:
      pid = int(f.read().strip())
    os.kill(pid, signal.SIGTERM)
  except (FileNotFoundError, ProcessLookupError, ValueError, PermissionError):
    pass
  try:
    os.unlink(_WATCHDOG_PID)
  except FileNotFoundError:
    pass


def _start_watchdog(ttl: int) -> None:
  """Spawn a detached process that deletes the cache after ttl seconds.

  Kills any existing watchdog first, effectively resetting the timer on
  each call (i.e. each successful autotype invocation).
  """
  _kill_old_watchdog()
  if ttl <= 0:
    return
  proc = subprocess.Popen(
    [
      "sh",
      "-c",
      f"sleep {ttl} && rm -f {_CACHE_FILE} {_WATCHDOG_PID}",
    ],
    start_new_session=True, # detach from our process group
    close_fds=True,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
  )
  fd = os.open(_WATCHDOG_PID, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
  with os.fdopen(fd, "w") as f:
    _ = f.write(str(proc.pid))


def _read_cache(ttl: int) -> str | None:
  """Return cached password if the cache file exists (watchdog enforces TTL)."""
  if ttl <= 0:
    return None
  try:
    with open(_CACHE_FILE) as f:
      return f.read()
  except FileNotFoundError:
    return None


def _write_cache(password: str, ttl: int) -> None:
  if ttl <= 0:
    return
  fd = os.open(_CACHE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
  with os.fdopen(fd, "w") as f:
    f.write(password)


def _ask_password_rofi() -> str:
  result = subprocess.run(
    ["rofi", "-dmenu", "-password", "-p", "KeePass password"],
    input="",
    capture_output=True,
    text=True,
  )
  if result.returncode != 0 or not result.stdout:
    print("Aborted.")
    raise SystemExit(0)
  return result.stdout.rstrip("\n")


def _get_password(secrets_path: str, ttl: int) -> str:
  cached = _read_cache(ttl)
  if cached is not None:
    print("Using cached password.")
    return cached

  try:
    sops = Sops(secrets_path)
    pw = sops.get("my_secret_key") # pyright: ignore[reportAny]
    if pw is None:
      raise KeyError("my_secret_key not found in sops file")
    password: str = pw # type: ignore[assignment] # pyright: ignore[reportAny]
  except Exception as e:
    print(f"sops unavailable ({e}), falling back to password prompt.")
    password = _ask_password_rofi()

  _write_cache(password, ttl)
  _start_watchdog(ttl)
  return password


kdbx_password = _get_password(args.secrets, args.cache_ttl)

# ── Active Hyprland window ────────────────────────────────────────────────────
win = json.loads(subprocess.check_output(["hyprctl", "activewindow", "-j"]))
# hyprctl gives "class" (e.g. "firefox") and "title" (e.g. "GitHub — Mozilla Firefox")
win_class: str = win.get("class", "")
win_title: str = win.get("title", "")


"""
KeePass autotype sequence executor for Wayland/Hyprland via evdev/uinput.

  {DELAY=N}   set inter-keypress delay to N ms (persists)
  {DELAY N}   one-shot sleep of N ms
  {TAB}       Tab key
  {RETURN}     Enter / Return key
  {UserName}  entry username  (typed literally)
  {Password}  entry password  (typed literally, + inside value is just +)
  {kpotp}     current TOTP code
  +{KEY}      Shift+KEY  (e.g. +{TAB} = Shift+Tab)
  +c          Shift+c
"""


import re

KEY_MAP: dict[str, int] = {
  "TAB": e.KEY_TAB,
  "RETURN": e.KEY_ENTER,
  "ENTER": e.KEY_ENTER,
  "BACKSPACE": e.KEY_BACKSPACE,
  "BS": e.KEY_BACKSPACE,
  "DELETE": e.KEY_DELETE,
  "DEL": e.KEY_DELETE,
  "INSERT": e.KEY_INSERT,
  "INS": e.KEY_INSERT,
  "SPACE": e.KEY_SPACE,
  "ESC": e.KEY_ESC,
  "UP": e.KEY_UP,
  "DOWN": e.KEY_DOWN,
  "LEFT": e.KEY_LEFT,
  "RIGHT": e.KEY_RIGHT,
  "HOME": e.KEY_HOME,
  "END": e.KEY_END,
  "PGUP": e.KEY_PAGEUP,
  "PGDN": e.KEY_PAGEDOWN,
  "CAPSLOCK": e.KEY_CAPSLOCK,
  "WIN": e.KEY_LEFTMETA,
  **{f"F{i}": getattr(e, f"KEY_F{i}") for i in range(1, 17)},
}

# US QWERTY: character → (keycode, needs_shift)
_CHAR_MAP: dict[str, tuple[int, bool]] = {
  **{
    c: (getattr(e, f"KEY_{c.upper()}"), False) for c in "abcdefghijklmnopqrstuvwxyz"
  },
  **{c: (getattr(e, f"KEY_{c}"), True) for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
  "1": (e.KEY_1, False),
  "2": (e.KEY_2, False),
  "3": (e.KEY_3, False),
  "4": (e.KEY_4, False),
  "5": (e.KEY_5, False),
  "6": (e.KEY_6, False),
  "7": (e.KEY_7, False),
  "8": (e.KEY_8, False),
  "9": (e.KEY_9, False),
  "0": (e.KEY_0, False),
  "!": (e.KEY_1, True),
  "@": (e.KEY_2, True),
  "#": (e.KEY_3, True),
  "$": (e.KEY_4, True),
  "%": (e.KEY_5, True),
  "^": (e.KEY_6, True),
  "&": (e.KEY_7, True),
  "*": (e.KEY_8, True),
  "(": (e.KEY_9, True),
  ")": (e.KEY_0, True),
  "-": (e.KEY_MINUS, False),
  "_": (e.KEY_MINUS, True),
  "=": (e.KEY_EQUAL, False),
  "+": (e.KEY_EQUAL, True),
  "[": (e.KEY_LEFTBRACE, False),
  "{": (e.KEY_LEFTBRACE, True),
  "]": (e.KEY_RIGHTBRACE, False),
  "}": (e.KEY_RIGHTBRACE, True),
  "\\": (e.KEY_BACKSLASH, False),
  "|": (e.KEY_BACKSLASH, True),
  ";": (e.KEY_SEMICOLON, False),
  ":": (e.KEY_SEMICOLON, True),
  "'": (e.KEY_APOSTROPHE, False),
  '"': (e.KEY_APOSTROPHE, True),
  "`": (e.KEY_GRAVE, False),
  "~": (e.KEY_GRAVE, True),
  ",": (e.KEY_COMMA, False),
  "<": (e.KEY_COMMA, True),
  ".": (e.KEY_DOT, False),
  ">": (e.KEY_DOT, True),
  "/": (e.KEY_SLASH, False),
  "?": (e.KEY_SLASH, True),
  " ": (e.KEY_SPACE, False),
}

_ALL_KEYS: list[int] = sorted(
  {kc for kc, _ in _CHAR_MAP.values()} | set(KEY_MAP.values()) | {e.KEY_LEFTSHIFT}
)


_TOKEN_RE = re.compile(
  r"\{DELAY=(\d+)\}" # group 1: {DELAY=N}  global delay
  + r"|\{DELAY\s+(\d+)\}" # group 2: {DELAY N}  one-shot sleep
  + r"|(\+?)\{([^ }]+)(?: (\d))?\}" # group 3,4: [+]{TOKEN}
  + r"|(\+)([\s\S])" # group 5,6: +<char>   shift+literal char
  + r"|([^{+]+)" # group 7: plain text chunk
  + r"|([\s\S])", # group 8: fallback single char
  re.IGNORECASE,
)


def run_autotype(
  sequence: str | None,
  username: str = "",
  password: str = "",
  otp: str = "",
) -> None:
  if not sequence:
    sequence = "{UserName}{TAB}{Password}{RETURN}"

  resolved: dict[str, str] = {
    "USERNAME": username or "",
    "PASSWORD": password or "",
    "KPOTP": otp or "",
    "OTP": otp or "",
  }
  delay_ms = 0

  with UInput({e.EV_KEY: _ALL_KEYS}, name="KeePass-Virtual-Output") as ui:
    time.sleep(0.5) # Small buffer for rofi to close and focus to return

    def type_char(char):
      # Same logic as autocorrect.py: Map char to keycode and shift state
      if char in _CHAR_MAP:
        keycode, needs_shift = _CHAR_MAP[char]
        if needs_shift:
          ui.write(e.EV_KEY, e.KEY_LEFTSHIFT, 1)
        ui.write(e.EV_KEY, keycode, 1)
        ui.write(e.EV_KEY, keycode, 0)
        if needs_shift:
          ui.write(e.EV_KEY, e.KEY_LEFTSHIFT, 0)
        ui.syn()
        if delay_ms > 0:
          time.sleep(delay_ms / 1000)
      else:
        print(char, "error")

    for m in _TOKEN_RE.finditer(sequence):
      g_delay, o_delay, mod, key_name, count, plus, p_char, plain, fall = (
        m.groups()
      )
      print('['+repr(g_delay)+']'+'['+repr( o_delay)+']'+'['+repr( mod)+']'+'['+repr( key_name)+']'+'['+repr( count)+']'+'['+repr( plus)+']'+'['+repr( p_char)+']'+'['+repr( plain)+']'+'['+repr( fall)+']')
      # continue
      if g_delay!=None:
        delay_ms=int(g_delay)
        continue
      if o_delay:
        time.sleep(int(o_delay) / 1000)
        continue
      if mod=="+":
        ui.write(e.EV_KEY, e.KEY_LEFTSHIFT, 1)
        if delay_ms > 0:
          time.sleep(delay_ms / 1000)
      if key_name:
        upper = key_name.upper()
        if upper in resolved:
          for c in resolved[upper]:
            type_char(c)
        elif upper in KEY_MAP:
          # appears to need extra delay with tabs to work well
          for _ in range(int(count or 1)):
            ui.write(e.EV_KEY, KEY_MAP[upper], 1)
            time.sleep(.01)
            ui.write(e.EV_KEY, KEY_MAP[upper], 0)
            ui.syn()
            if delay_ms > 0:
              time.sleep(delay_ms / 1000)
            time.sleep(.01)
      elif plain:
        for c in plain:
          type_char(c)
      if mod=="+":
        ui.write(e.EV_KEY, e.KEY_LEFTSHIFT, 0)
        if delay_ms > 0:
          time.sleep(delay_ms / 1000)
    # exiting the with too early seems to cause the typing to abort sometimes
    time.sleep(1)


def matches_entry(entry) -> bool:
  """Return True if this entry should be offered for the active window."""

  # 1. Autotype window-association patterns (KeePass wildcard syntax → fnmatch)
  for a in entry._element.findall("AutoType/Association"):
    pattern = (a.findtext("Window") or "").strip()
    if pattern and (
      fnmatch.fnmatch(win_title, pattern) or fnmatch.fnmatch(win_class, pattern)
    ):
      return True

  # 2. Entry URL appears somewhere in the window title (browser tab matching)
  url = entry.url or ""
  if url:
    # Strip scheme so "https://github.com" matches "github.com" in the title
    bare = url.removeprefix("https://").removeprefix("http://").rstrip("/")
    if bare and bare in win_title:
      return True

  return False


def _open_keepass(db_path: str, password: str, ttl: int) -> PyKeePass:
  """Open the database, re-prompting via rofi on wrong password until correct or aborted."""
  while True:
    try:
      return PyKeePass(db_path, password=password) # pyright: ignore[reportAny]
    except Exception as e:
      # Wipe bad cached password so we don't re-use it next run
      try:
        os.unlink(_CACHE_FILE)
      except FileNotFoundError:
        pass
      _kill_old_watchdog()
      print(f"Failed to open database: {e}")
      password = _ask_password_rofi()
      if not password:
        print("Aborted.")
        raise SystemExit(0)
      # Cache the new password so a successful open persists it below
      _write_cache(password, ttl)


kp = _open_keepass(args.db, kdbx_password, args.cache_ttl)

print(f"Active window: class={win_class!r}  title={win_title!r}\n")
matched = [e for e in kp.entries if matches_entry(e)]

if not matched:
  print("No matching entries.")
  raise SystemExit(0)

if len(matched) == 1:
  entry = matched[0]
else:
  # Build a label list: "Title (username)" for disambiguation
  labels = [f"{e.title}  [{e.username or ''}]  {e.url or ''}" for e in matched]
  menu_input = "\n".join(labels)

  result = subprocess.run(
    [
      "rofi",
      "-dmenu",
      "-i", # case-insensitive filter
      "-p",
      "KeePass",
      "-format",
      "i", # return selected index, not text
      "-no-custom", # disallow free-form input
    ],
    input=menu_input,
    capture_output=True,
    text=True,
  )

  if result.returncode != 0 or not result.stdout.strip():
    # ESC pressed or no selection
    print("Aborted.")
    raise SystemExit(0)

  entry = matched[int(result.stdout.strip())]

print(f"=== {entry.title} ===")

# ── Basic fields ─────────────────────────────────────────────────────────
print(f"  Title:    {entry.title}")
print(f"  Username: {entry.username}")
print(f"  Password: {entry.password}")
print(f"  URL:      {entry.url}")

# ── OTP (TOTP / HOTP) ────────────────────────────────────────────────────
otp_uri = entry.otp # e.g. "otpauth://totp/label?secret=BASE32SECRET&..."
print(f"  OTP URI:  {otp_uri}")
code = None
if otp_uri:
  parsed = urlparse(otp_uri)
  params = parse_qs(parsed.query)
  secret_b32 = params.get("secret", [None])[0]

  # Check for Steam encoder/issuer
  encoder = params.get('encoder', [''])[0].lower()
  issuer = params.get('issuer', [''])[0].lower()
  is_steam = "steam" in encoder or "steam" in issuer or "steam" in parsed.path.lower()

  if secret_b32:
    try:
      # 1. Standard HMAC-SHA1 Setup (shared between TOTP and Steam)
      key = base64.b32decode(secret_b32.upper() + ("=" * (-len(secret_b32) % 8)))
      counter = struct.pack(">Q", int(time.time()) // 30)
      mac = hmac.new(key, counter, hashlib.sha1).digest()
      offset = mac[-1] & 0x0F
      # Extract the 31-bit integer
      header = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF

      if is_steam:
        # 2. Steam Specific Encoding
        steam_chars = "23456789BCDFGHJKMNPQRTVWXY"
        steam_code = []
        for _ in range(5):
          steam_code.append(steam_chars[header % len(steam_chars)])
          header //= len(steam_chars)
        code = "".join(steam_code)
      else:
        # 3. Standard 6-digit TOTP
        code = f"{(header % 1_000_000):06d}"

      print(f"  OTP Code: {code} {'(Steam)' if is_steam else ''}")
    except Exception as e:
      print(f"  OTP Error: {e}")

# ── Select autotype sequence based on flags ───────────────────────────────
if args.password_only:
  autotype_sequence = "{Password}"
elif args.otp_only:
  if not code:
    print("No OTP available for this entry.")
    raise SystemExit(1)
  autotype_sequence = "{KPOTP}"
else:
  autotype_sequence = entry.autotype_sequence # None → default in run_autotype

run_autotype(autotype_sequence, entry.username, entry.password, code)

# Reset the inactivity timer — new watchdog kills old one and starts fresh
_start_watchdog(args.cache_ttl)

# ── Auto-Type ─────────────────────────────────────────────────────────────
print(f"  AutoType enabled:  {entry.autotype_enabled}")
print(f"  AutoType sequence: {entry.autotype_sequence}")

associations = [
  {
    "window": a.findtext("Window"),
    "sequence": a.findtext("KeystrokeSequence") or None,
  }
  for a in entry._element.findall("AutoType/Association")
]
if associations:
  print("  AutoType associations:")
  for assoc in associations:
    print(f"    window={assoc['window']!r}  sequence={assoc['sequence']!r}")
else:
  print("  AutoType associations: (none)")

# ── Custom properties ─────────────────────────────────────────────────────
custom = entry.custom_properties # dict[str, str]
if custom:
  print("  Custom properties:")
  for k, v in custom.items():
    print(f"    {k}: {v}")

print()
