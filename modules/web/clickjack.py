# clickjack.py — Clickjacking
from core.registry import module
from core.http import get

@module("clickjack", "web", "فحص Clickjacking")
def run(base, a, R):
    _, h, _ = get(base + "/")
    xfo = h.get("x-frame-options", "")
    csp = h.get("content-security-policy", "")
    if "DENY" in xfo.upper() or "SAMEORIGIN" in xfo.upper():
        R.good(f"X-Frame-Options: {xfo}")
    elif "frame-ancestors" in csp:
        R.good("CSP frame-ancestors موجود")
    else:
        R.vuln("لا حماية Clickjacking (لا XFO ولا frame-ancestors) — قابل للتأطير")
