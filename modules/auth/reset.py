# reset.py — استعادة كلمة المرور
from core.registry import module
from core.http import get

@module("reset", "auth", "فحص استعادة كلمة المرور")
def run(base, a, R):
    for p in ["/password/reset", "/forgot-password", "/password/forgot",
              "/auth/forgot", "/reset"]:
        st, _, _ = get(base + p)
        if st == 200:
            R.info(f"{p} -> 200 (نموذج الاستعادة موجود)")
            for u in ["admin@test.com", "nonexistent-xyz@test.com"]:
                s2, _, b2 = get(base + p + "?email=" + u)
                R.info(f"  البريد {u} -> HTTP {s2}, الطول {len(b2)}")
            R.warn("قارن الأطوال أعلاه: اختلاف = تسريب وجود المستخدم (User Enumeration)")
            return
    R.info("لا نقطة استعادة مكشوفة")
