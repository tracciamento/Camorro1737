# crlf.py — حقن CRLF في الترويسات
from core.registry import module
from core.http import raw_request

@module("crlf", "web", "حقن CRLF")
def run(base, a, R):
    data = raw_request(base + "/%0d%0aX-Injected:%20shadowforge%0d%0a")
    if b"X-Injected: shadowforge" in data:
        R.vuln("CRLF Injection: تم حقن ترويسة X-Injected في الاستجابة!")
    elif data.startswith(b"HTTP/1.1 4"):
        R.info("الخادم يرفض CRLF (%s)" % data.split(b"\r\n",1)[0].decode(errors="replace"))
    else:
        R.info("لا CRLF ظاهر")
