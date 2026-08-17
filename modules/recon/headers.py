# headers.py — ترويسات الأمان
from core.registry import module
from core.http import get

@module("headers", "recon", "فحص ترويسات الأمان")
def run(base, a, R):
    _, h, _ = get(base + "/")
    needed = {"strict-transport-security":"HSTS","content-security-policy":"CSP",
              "x-frame-options":"XFO","x-content-type-options":"XCTO",
              "referrer-policy":"RP","permissions-policy":"PP"}
    for k, name in needed.items():
        if k not in h: R.warn(f"مفقودة: {name}")
        else: R.good(f"موجودة: {name}")
