# horizon.py — كشف Laravel Horizon
from core.registry import module
from core.http import get

@module("horizon", "laravel", "فحص Horizon")
def run(base, a, R):
    st, _, b = get(base + "/horizon")
    if st == 200 and ("horizon" in b.lower() or "Laravel" in b):
        R.vuln("/horizon مكشوف — إدارة الوظائف المجدولة بدون مصادقة!")
    elif st in (302, 401, 403):
        R.info(f"/horizon -> HTTP {st} (محمي)")
    else:
        R.good("لا Horizon مكشوف")
