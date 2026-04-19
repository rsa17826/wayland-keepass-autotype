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
from urllib.parse import parse_qs, urlparse

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
KeePass autotype sequence executor for Wayland/Hyprland via wtype.

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

KEY_MAP: dict[str, str] = {
  "TAB": "tab",
  "RETURN": "Return",
  "BACKSPACE": "BackSpace",
  "BS": "BackSpace",
  "DELETE": "Delete",
  "DEL": "Delete",
  "INSERT": "Insert",
  "INS": "Insert",
  "SPACE": "space",
  "ESC": "Escape",
  "UP": "Up",
  "DOWN": "Down",
  "LEFT": "Left",
  "RIGHT": "Right",
  "HOME": "Home",
  "END": "End",
  "PGUP": "Prior",
  "ENTER": "Return",
  "PGDN": "Next",
  "CAPSLOCK": "Caps_Lock",
  "WIN": "super",
  **{f"F{i}": f"F{i}" for i in range(1, 17)},
}

_TOKEN_RE = re.compile(
  r"\{DELAY=(\d+)\}" # group 1: {DELAY=N}  global delay
  + r"|\{DELAY\s+(\d+)\}" # group 2: {DELAY N}  one-shot sleep
  + r"|(\+?)\{([^ }]+)(?: (\d))?\}" # group 3,4: [+]{TOKEN}
  + r"|(\+)([\s\S])" # group 5,6: +<char>   shift+literal char
  + r"|([^{+]+)" # group 7: plain text chunk
  + r"|([\s\S])", # group 8: fallback single char
  re.IGNORECASE,
)


def _wtype(*args: str) -> None:
  print(args)
  _ = subprocess.run(["wtype", *args], check=True)


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
  text_buf: list[str] = []

  # Characters wtype cannot type as literals — map to XKB keysym names.
  _KEYSYM_CHARS: dict[str, str] = {
    "`": "grave",
    "~": "asciitilde",
    "\\": "backslash",
    "|": "bar",
  }

  def flush_text() -> None:
    if not text_buf:
      return
    chunk = "".join(text_buf)
    text_buf.clear()
    if not chunk: # skip empty — e.g. {kpotp} when otp=""
      return

    # Split into runs of normal chars and individual keysym chars.
    run: list[str] = []

    def _flush_run() -> None:
      if not run:
        return
      normal = "".join(run)
      run.clear()
      w_args: list[str] = []
      if delay_ms > 0:
        w_args += ["-d", str(delay_ms)]
      w_args += ["--", normal]
      _wtype(*w_args)

    for ch in chunk:
      if ch in _KEYSYM_CHARS:
        _flush_run()
        press_key(_KEYSYM_CHARS[ch])
      else:
        run.append(ch)
    _flush_run()

  def press_key(xkb_key: str, shift: bool = False) -> None:
    args: list[str] = []
    if delay_ms > 0:
      args += ["-s", str(delay_ms)]
    if shift:
      args += ["-M", "shift"]
    args += ["-k", xkb_key]
    if shift:
      args += ["-m", "shift"]
    _wtype(*args)

  for m in _TOKEN_RE.finditer(sequence):
    (
      global_delay,
      once_delay,
      modifier,
      key_name,
      key_count,
      _plus,
      plus_char,
      plain,
      fallback,
    ) = m.groups()

    if global_delay is not None:
      flush_text()
      delay_ms = int(global_delay)

    elif once_delay is not None:
      flush_text()
      time.sleep(int(once_delay) / 1000)

    elif key_name is not None:
      upper = key_name.upper()
      shift = modifier == "+"
      if key_count is None:
        key_count = 1
      else:
        key_count = int(key_count)
      for _ in range(0, key_count):
        if upper in resolved:
          # placeholder → always literal text, + inside value is never a modifier
          text_buf.append(resolved[upper])
        elif upper in KEY_MAP:
          flush_text()
          press_key(KEY_MAP[upper], shift=shift)
        else:
          text_buf.append(m.group(0)) # unknown {TOKEN}, type literally

    elif plus_char is not None:
      flush_text()
      press_key(plus_char, shift=True)

    elif plain is not None:
      text_buf.append(plain)

    elif fallback is not None:
      text_buf.append(fallback)

  flush_text()


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

  if secret_b32:
    try:
      key = base64.b32decode(secret_b32.upper() + ("=" * (-len(secret_b32) % 8)))
      counter = struct.pack(">Q", int(time.time()) // 30)
      mac = hmac.new(key, counter, hashlib.sha1).digest()
      offset = mac[-1] & 0x0F
      code = str(
        (struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF)
        % 1_000_000
      )
      print(f"  OTP Code: {code:0>6}")
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
