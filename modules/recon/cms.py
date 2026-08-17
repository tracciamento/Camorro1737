# cms.py — فحص إضافي لـ CMS الشهيرة
import re
from core.registry import module
from core.http import get

@module("cms", "recon", "كشف تفصيلي لـ CMS")
def run(base, a, R):
    st, h, b = get(base + "/")
    low = b.lower()
    hits = []
    if "wp-content" in low or "wp-json" in low: hits.append("WordPress")
    if "wp-json" in low:
        s2, _, b2 = get(base + "/wp-json/")
        if s2 == 200:
            m = re.search(r'"generator"\s*:\s*"WordPress/([\d.]+)"', b2)
            if m: hits.append(f"WP نسخة {m.group(1)}")
    if 'drupal' in low or 'drupal.js' in low: hits.append("Drupal")
    if 'joomla' in low: hits.append("Joomla")
    if 'generator' in low:
        m = re.search(r'<meta name="generator" content="([^"]+)"', b)
        if m: hits.append(m.group(1))
    if hits: R.vuln("CMS: " + ", ".join(hits))
    else: R.info("لا CMS معروفة")
