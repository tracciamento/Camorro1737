# encode.py — تشفير الحمولات
import base64, urllib.parse, binascii
from core.registry import module

@module("encode", "payload", "تشفير الحمولات")
def run(base, a, R):
    text = getattr(a, "token", None) or "echo VFZQTEST"
    R.info(f"الإدخال: {text}")
    R.info("  base64:   " + base64.b64encode(text.encode()).decode())
    R.info("  url:      " + urllib.parse.quote(text))
    R.info("  hex:      " + text.encode().hex())
    R.info("  rot13:    " + text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")))
    R.info("  char():   " + "".join(f"chr({ord(c)})" + ("." if i % 8 == 7 else "" )
            for i, c in enumerate(text)))
