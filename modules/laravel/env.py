# env.py — تسريب ملف .env
import re
from core.registry import module
from core.http import get

@module("env", "laravel", "فحص تسريب /.env")
def run(base, a, R):
    st, _, b = get(base + "/.env")
    if st == 200 and "APP_KEY" in b:
        keys = [l.split("=",1)[0] for l in b.splitlines() if "=" in l and not l.startswith("#")]
        R.vuln("CRITICAL: /.env مكشوف! المفاتيح: " + ", ".join(keys[:20]))
        m = re.search(r"APP_KEY=(\S+)", b)
        if m: R.warn("APP_KEY مسرّب — جرب وحدة appkey و serial-rce")
    else:
        R.good("/.env غير متاح (محمي أو غير موجود)")
    for p in [".env.backup", ".env.old", ".env.save", ".env.example", "app/.env", "public/.env"]:
        s2, _, b2 = get(base + "/" + p)
        if s2 == 200 and ("APP_KEY" in b2 or "DB_" in b2 or "MAIL_" in b2):
            R.vuln(f"نسخة .env مكشوفة: /{p}")
