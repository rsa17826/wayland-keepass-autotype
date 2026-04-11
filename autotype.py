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

from __future__ import annotations

import re
import subprocess
import time

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
  r"|\{DELAY\s+(\d+)\}"    # group 2: {DELAY N}  one-shot sleep
  r"|(\+?)\{([^}]+)\}"     # group 3,4: [+]{TOKEN}
  r"|(\+)([\s\S])"          # group 5,6: +<char>   shift+literal char
  r"|([^{+]+)"              # group 7: plain text chunk
  r"|([\s\S])",             # group 8: fallback single char
  re.IGNORECASE,
)

def _wtype(*args: str) -> None:
  print(args)
  subprocess.run(["wtype", *args], check=True)

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


