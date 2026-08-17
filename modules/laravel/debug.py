# debug.py — وضع التصحيح (APP_DEBUG)
import re
from core.registry import module
from core.http import get

@module("debug", "laravel", "فحص وضع التصحيح")
def run(base, a, R):
    st, _, b = get(base + "/definitely-not-here-xyz123")
    if st == 200 and ("Whoops" in b or "_ignition" in b.lower() or
                      "Stack trace" in b or "vendor/laravel" in b or "Exception" in b):
        R.vuln("APP_DEBUG=true — صفحة الخطأ تسرّب الكود والمتغيرات!")
        if "ignition" in b.lower():
            R.warn("CVE-2021-3129 محتمل (Ignition + debug) — شغل وحدة ignition")
        m = re.search(r"Laravel\s+v?(\d+\.\d+\.\d+)", b)
        if m: R.info(f"نسخة Laravel من صفحة الخطأ: {m.group(1)}")
        if re.search(r"11\.(?:9|1[0-9]|2[0-9]|3[0-5])\.\d+", b):
            R.vuln("CVE-2024-13918/13919 محتمل: XSS عبر صفحة الخطأ (11.9.0–11.35.1)")
    else:
        R.good("وضع التصحيح غير مفعل (لا تسريب)")
