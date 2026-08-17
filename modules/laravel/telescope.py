# telescope.py — كشف Laravel Telescope
from core.registry import module
from core.http import get

@module("telescope", "laravel", "فحص Telescope")
def run(base, a, R):
    st, _, b = get(base + "/telescope")
    if st == 200 and ("telescope" in b.lower() or "Laravel" in b):
        R.vuln("/telescope مكشوف بدون مصادقة — تسريب جلسات وطلبات وقواعد بيانات!")
    elif st in (302, 401, 403):
        R.info(f"/telescope -> HTTP {st} (محمي)")
    else:
        R.good("لا Telescope مكشوف")
