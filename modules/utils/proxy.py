# proxy.py — إعداد بروكسي للوحدة
from core.registry import module
from core.http import req

@module("proxy", "utils", "اختبار البروكسي")
def run(base, a, R):
    p = getattr(a, "proxy", None)
    if not p:
        R.info("--proxy http://127.0.0.1:8080 لتمرير الطلبات عبر Burp/ZAP"); return
    st, h, b = req(base + "/", proxy=p)
    R.good(f"عبر البروكسي {p}: HTTP {st} — Server: {h.get('server','?')}")
    R.info("استخدم --proxy مع أي وحدة أخرى لتسجيل الطلبات في Burp")
