from __future__ import annotations
import base64
import fnmatch
import hashlib
import hmac
import json
import struct
import subprocess
import time
from urllib.parse import parse_qs, urlparse

from pykeepass.pykeepass import PyKeePass
from sopsy import Sops

sops = Sops("secrets.yml")

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
  "TAB":       "tab",
  "RETURN":     "Return",
  "BACKSPACE": "BackSpace",
  "BS":        "BackSpace",
  "DELETE":    "Delete",
  "DEL":       "Delete",
  "INSERT":    "Insert",
  "INS":       "Insert",
  "SPACE":     "space",
  "ESC":       "Escape",
  "UP":        "Up",
  "DOWN":      "Down",
  "LEFT":      "Left",
  "RIGHT":     "Right",
  "HOME":      "Home",
  "END":       "End",
  "PGUP":      "Prior",
  "ENTER":      "Return",
  "PGDN":      "Next",
  "CAPSLOCK":  "Caps_Lock",
  "WIN":       "super",
  **{f"F{i}": f"F{i}" for i in range(1, 17)},
}

_TOKEN_RE = re.compile(
  r"\{DELAY=(\d+)\}"       # group 1: {DELAY=N}  global delay
 +r"|\{DELAY\s+(\d+)\}"    # group 2: {DELAY N}  one-shot sleep
 +r"|(\+?)\{([^}]+)\}"     # group 3,4: [+]{TOKEN}
 +r"|(\+)([\s\S])"          # group 5,6: +<char>   shift+literal char
 +r"|([^{+]+)"              # group 7: plain text chunk
 +r"|([\s\S])",             # group 8: fallback single char
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
    "KPOTP":    otp or "",
    "OTP":    otp or "",
  }

  delay_ms = 0
  text_buf: list[str] = []

  def flush_text() -> None:
    if not text_buf:
      return
    chunk = "".join(text_buf)
    text_buf.clear()
    if not chunk:          # skip empty — e.g. {kpotp} when otp=""
      return
    args: list[str] = []
    if delay_ms > 0:
      args += ["-d", str(delay_ms)]
    args += ["--", chunk]
    _wtype(*args)

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
    global_delay, once_delay, modifier, key_name, _plus, plus_char, plain, fallback = m.groups()

    if global_delay is not None:
      flush_text()
      delay_ms = int(global_delay)

    elif once_delay is not None:
      flush_text()
      time.sleep(int(once_delay) / 1000)

    elif key_name is not None:
      upper = key_name.upper()
      shift = modifier == "+"
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
      fnmatch.fnmatch(win_title, pattern)
      or fnmatch.fnmatch(win_class, pattern)
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

kp: PyKeePass = PyKeePass("/home/nyix/keepassdb/keepass.kdbx", password=sops.get("my_secret_key")) # pyright: ignore[reportAny]
import os
print(f"Active window: class={win_class!r}  title={win_title!r}\n")

matched = [e for e in kp.entries if matches_entry(e)]

if not matched:
  print("No matching entries.")

for entry in matched:
  print(f"=== {entry.title} ===")

  # ── Basic fields ─────────────────────────────────────────────────────────
  print(f"  Title:    {entry.title}")
  print(f"  Username: {entry.username}")
  print(f"  Password: {entry.password}")
  print(f"  URL:      {entry.url}")

  # ── OTP (TOTP / HOTP) ────────────────────────────────────────────────────
  otp_uri = entry.otp # e.g. "otpauth://totp/label?secret=BASE32SECRET&..."
  print(f"  OTP URI:  {otp_uri}")
  code=None
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
        code = str((struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000)
        print(f"  OTP Code: {code:06d}")
      except Exception as e:
        print(f"  OTP Error: {e}")
  run_autotype(entry.autotype_sequence, entry.username, entry.password, code)

  # ── Auto-Type ─────────────────────────────────────────────────────────────
  print(f"  AutoType enabled:  {entry.autotype_enabled}")
  print(f"  AutoType sequence: {entry.autotype_sequence}")

  associations = [
    {
      "window":   a.findtext("Window"),
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