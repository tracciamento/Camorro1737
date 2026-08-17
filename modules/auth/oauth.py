# oauth.py — سوء إعداد OAuth
import urllib.parse
from core.registry import module
from core.http import req

@module("oauth", "auth", "فحص سوء إعداد OAuth")
def run(base, a, R):
    endpoints = ["/oauth/authorize", "/oauth/token", "/oauth/redirect", "/login/oauth/authorize"]
    for ep in endpoints:
        st, h, _ = req(base + ep + "?response_type=code&client_id=test&redirect_uri=https://evil.com",
                       redirects=False)
        loc = h.get("location", "")
        if st in (302, 301) and "evil.com" in loc:
            R.vuln(f"OAuth Open Redirect: {ep} يقبل redirect_uri خارجي -> {loc[:80]}")
        elif st in (200, 302):
            R.warn(f"{ep} -> HTTP {st} — تحقق من التحقق من redirect_uri")
        else:
            R.info(f"{ep} -> HTTP {st}")
    R.info("اختبر أيضاً: state مفقود؟ token في URL؟")
