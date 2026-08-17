# sanctum.py — فحص Sanctum API
from core.registry import module
from core.http import req

@module("sanctum", "laravel", "فحص Sanctum")
def run(base, a, R):
    st, h, _ = req(base + "/sanctum/csrf-cookie")
    if st in (200, 204) and "xsrf-token" in str(h.get("set-cookie","")).lower():
        R.info("Sanctum مثبت — /sanctum/csrf-cookie يستجيب")
        st2, _, _ = req(base + "/api/user", headers={"X-Requested-With": "XMLHttpRequest"})
        if st2 == 401: R.info("API محمية بـ Sanctum (401 بدون توكن)")
        elif st2 == 200: R.vuln("/api/user يستجيب بدون مصادقة!")
    else:
        R.good("لا Sanctum مكشوف")
