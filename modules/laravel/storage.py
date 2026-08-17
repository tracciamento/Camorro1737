# storage.py — كشف مجلدات storage
from core.registry import module
from core.http import get

@module("storage", "laravel", "فحص storage/logs و framework")
def run(base, a, R):
    for p in ["storage/logs/laravel.log", "storage/framework/sessions",
              "storage/framework/cache", "storage/logs"]:
        st, _, b = get(base + "/" + p)
        if st == 200 and len(b) > 300:
            if "ERROR" in b or "Exception" in b:
                R.vuln(f"/{p} مقروء — تسريب أخطاء واستثناءات!")
            else:
                R.vuln(f"/{p} مقروء (فهرسة أدلة أو ملف) — حجم {len(b)} بايت")
        elif st in (403, 404):
            R.info(f"/{p} -> HTTP {st} (آمن)")
