# waf.py — كشف جدار الحماية
from core.registry import module
from core.http import get

WAF_HINTS = ["cloudflare","cf-ray","__cfduid","mod_security","modsecurity","owasp",
 "imperva","incapsula","akamai","sucuri","barracuda","wordfence","f5 bigip",
 "blocked","access denied","request blocked","attention required","captcha",
 "verify you are human","cf-chl","forbidden"]

@module("waf", "recon", "كشف جدار الحماية WAF")
def run(base, a, R):
    for pay in ["?id=1' OR '1'='1", "?q=<script>alert(1)</script>"]:
        st, h, b = get(base + pay)
        blob = (b + " " + str(h)).lower()
        hits = [w for w in WAF_HINTS if w in blob]
        if st in (403, 406, 429) or hits:
            R.vuln(f"WAF محتمل (HTTP {st}): " + ", ".join(dict.fromkeys(hits)) if hits else f"HTTP {st} على {pay}")
            return
    R.good("لا مؤشرات WAF واضحة")
