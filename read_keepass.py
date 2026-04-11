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
raw = subprocess.check_output(["hyprctl", "activewindow", "-j"])
win = json.loads(raw)
# hyprctl gives "class" (e.g. "firefox") and "title" (e.g. "GitHub — Mozilla Firefox")
win_class: str = win.get("class", "")
win_title: str = win.get("title", "")

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
from autotype import run_autotype # if used as a module

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
@regex -
  # ── Custom properties ─────────────────────────────────────────────────────
  custom = entry.custom_properties # dict[str, str]
  if custom:
    print("  Custom properties:")
    for k, v in custom.items():
      print(f"    {k}: {v}")

  print()