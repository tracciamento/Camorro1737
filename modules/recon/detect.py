# detect.py — كشف التقنيات و Laravel
import re
from core.registry import module
from core.http import get

@module("detect", "recon", "كشف التقنيات والإطار")
def run(base, a, R):
    st, h, b = get(base + "/")
    R.good(f"HTTP {st} — Server: {h.get('server','?')} | X-Powered-By: {h.get('x-powered-by','?')}")
    low = b.lower(); hints = []
    if "laravel_session" in str(h.get("set-cookie","")): hints.append("laravel_session")
    if "xsrf-token" in str(h.get("set-cookie","")).lower(): hints.append("XSRF-TOKEN")
    if 'csrf-token' in low: hints.append("Blade csrf-token")
    if 'wp-content' in low or 'wp-includes' in low: hints.append("WordPress")
    if 'drupal' in low: hints.append("Drupal")
    if 'joomla' in low: hints.append("Joomla")
    if '_next/' in low: hints.append("Next.js")
    if '__nuxt' in low: hints.append("Nuxt")
    for p in ["_ignition/health-check","sanctum/csrf-cookie","telescope","horizon",
              "vendor/composer/installed.json"]:
        s2, _, _ = get(base + "/" + p)
        if s2 in (200, 204, 302): hints.append(f"{p}->{s2}")
    if hints: R.vuln("التقنيات: " + ", ".join(hints))
    else: R.info("لا مؤشرات مباشرة")
    s3, _, b3 = get(base + "/vendor/composer/installed.json")
    if s3 == 200:
        m = re.search(r'"name"\s*:\s*"laravel/framework".{0,400}?"version"\s*:\s*"([^"]+)"', b3, re.S)
        if m: R.info(f"laravel/framework نسخة: {m.group(1)}")
