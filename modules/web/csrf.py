# csrf.py — فحص CSRF على النماذج
import re
from core.registry import module
from core.http import get, req

@module("csrf", "web", "فحص CSRF")
def run(base, a, R):
    st, _, b = get(base + "/")
    forms = re.findall(r"<form[^>]*>", b, re.I)
    if not forms:
        R.info("لا نماذج في الصفحة الرئيسية — جرّب --login-url"); return
    for f in forms:
        has_csrf = "csrf" in f.lower() or "_token" in f.lower()
        method = re.search(r'method=["\'](post|get)["\']', f, re.I)
        if method and method.group(1).lower() == "post" and not has_csrf:
            R.warn("نموذج POST بدون CSRF token: " + f[:100])
    # اختبار مباشر: POST لنقطة دخول بدون توكن
    login = getattr(a, "login_url", None)
    if login:
        st2, _, _ = req(base + login, method="POST", data="user=x&pass=y",
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
        if st2 not in (419, 400, 403, 405):
            R.vuln(f"POST إلى {login} بدون CSRF token تم قبوله (HTTP {st2}) — CSRF محتمل!")
