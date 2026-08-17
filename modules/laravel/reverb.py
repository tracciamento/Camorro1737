# reverb.py — فحص Reverb CVE-2026-23524
from core.registry import module
from core.http import req, get

@module("reverb", "laravel", "فحص Reverb (CVE-2026-23524)")
def run(base, a, R):
    st, _, b = req(base + "/apps", headers={"X-Requested-With": "XMLHttpRequest"})
    if st == 200 and b.strip().startswith(b"["):
        R.vuln("Reverb Dashboard مكشوف — CVE-2026-23524 (RCE عبر unserialize) محتمل إذا كانت النسخة < 1.6.3")
    else:
        R.info(f"/apps -> HTTP {st} (غير مكشوف)")
    for port in (6001, 8080):
        import socket
        host = __import__("urllib.parse").urlsplit(base).hostname
        try:
            with socket.create_connection((host, port), timeout=3):
                R.warn(f"منفذ WebSocket {port} مفتوح — قد يكون Reverb")
        except Exception:
            pass
