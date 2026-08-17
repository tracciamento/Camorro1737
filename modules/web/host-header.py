# host-header.py — حقن ترويسة المضيف
from core.registry import module
from core.http import req

@module("host-header", "web", "حقن ترويسة Host")
def run(base, a, R):
    st, h, b = req(base + "/", headers={"Host": "evil.com"})
    blob = b.decode("utf-8","replace")
    if "evil.com" in blob or "http://evil.com" in blob:
        R.vuln("Host Header Injection: evil.com ينعكس في الاستجابة — تسميم كاش محتمل!")
    elif st in (302, 301) and "evil.com" in h.get("location",""):
        R.vuln("Host Header Injection: تحويل إلى evil.com — Password Reset Poisoning محتمل!")
    else:
        R.info("Host لا ينعكس (آمن)")
