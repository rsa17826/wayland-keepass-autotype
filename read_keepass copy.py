from pykeepass.pykeepass import PyKeePass
from sopsy import Sops
sops = Sops(
  "secrets.yml",
)

kp: PyKeePass = PyKeePass("/home/nyix/keepassdb/keepass.kdbx", password=sops.get("my_secret_key")) # pyright: ignore[reportAny]
# kp = PyKeePass("database.kdbx", keyfile="path/to/keyfile.key")

for entry in kp.entries:
  print(f"=== {entry.title} ===")

  # ── Basic fields ──────────────────────────────────────────────────────────
  print(f"  Title:    {entry.title}")
  print(f"  Username: {entry.username}")
  print(f"  Password: {entry.password}")
  print(f"  URL:      {entry.url}")

  # ── OTP (TOTP / HOTP) ────────────────────────────────────────────────────
  # Stored as a custom attribute named "otp" (a otpauth:// URI).
  # entry.otp returns the URI string; use the `otp` library to generate codes.
  otp_uri = entry.otp # e.g. "otpauth://totp/label?secret=BASE32SECRET&..."
  print(f"  OTP URI:  {otp_uri}")

  if otp_uri:
    # Generate the current TOTP code without extra dependencies:
    import hmac, hashlib, struct, time, base64
    from urllib.parse import urlparse, parse_qs

    parsed = urlparse(otp_uri)
    params = parse_qs(parsed.query)
    secret_b32 = params.get("secret", [None])[0]

    if secret_b32:
      try:
        key = base64.b32decode(secret_b32.upper()+ ("=" * (-len(secret_b32) % 8)))
        counter = struct.pack(">Q", int(time.time()) // 30)
        mac = hmac.new(key, counter, hashlib.sha1).digest()
        offset = mac[-1] & 0x0F
        code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
        print(f"  OTP Code: {code:06d}")
      except Exception as e:
        print("ERROR: ", str(e))

  # ── Auto-Type ─────────────────────────────────────────────────────────────
  # autotype_enabled  – bool (None if not set, treated as True by KeePass)
  # autotype_sequence – default sequence for this entry (None = use group/global default)
  # autotype_window   – convenience property: only returns the FIRST association's window
  # For all associations walk the raw XML (pykeepass has no autotype_associations property)
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
      window   = assoc["window"]    # window title pattern (supports wildcards)
      sequence = assoc["sequence"] # None means use the entry's default sequence
      print(f"    window={window!r}  sequence={sequence!r}")
  else:
    print("  AutoType associations: (none)")

  # ── All custom attributes (everything beyond the standard fields) ─────────
  custom = entry.custom_properties # dict[str, str]
  if custom:
    print("  Custom properties:")
    for k, v in custom.items():
      print(f"    {k}: {v}")

  print()