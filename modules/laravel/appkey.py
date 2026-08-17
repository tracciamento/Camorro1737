# appkey.py — تحليل صيغة APP_KEY
import re
from core.registry import module
from core.http import get

@module("appkey", "laravel", "تحليل APP_KEY والصيغة")
def run(base, a, R):
    st, _, b = get(base + "/.env")
    if st != 200 or "APP_KEY" not in b:
        R.info("لا APP_KEY مكشوف"); return
    m = re.search(r"APP_KEY=(\S+)", b)
    if not m: return
    key = m.group(1)
    R.warn("APP_KEY (مخفية جزئياً): " + key[:12] + "..." + key[-4:])
    if key.startswith("base64:"):
        R.info("الصيغة: base64 (AES-256-CBC في Laravel الحديث)")
    elif len(key) == 32:
        R.vuln("APP_KEY مفتاح 32 حرفاً غير مشفر — Laravel قديم ≤5.5 أو إعداد ضعيف")
    else:
        R.info(f"الصيغة غير معروفة (الطول {len(key)})")
