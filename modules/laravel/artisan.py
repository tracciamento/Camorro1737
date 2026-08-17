# artisan.py — كشف ملف artisan
from core.registry import module
from core.http import get

@module("artisan", "laravel", "فحص كشف artisan")
def run(base, a, R):
    st, _, b = get(base + "/artisan")
    if st == 200 and "#!/usr/bin/env php" in b:
        R.vuln("ملف artisan مكشوف كمصدر — تسريب كود التطبيق!")
    elif st == 500:
        R.info("artisan موجود لكنه يُنفذ (500 طبيعي — PHP يرفض التنفيذ خارج CLI)")
    else:
        R.good("artisan غير مكشوف")
