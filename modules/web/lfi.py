# lfi.py — تضمين الملفات
import re, urllib.parse
from core.registry import module
from core.helpers import norm_target, get_params
from core.http import get
from core.wordlists import COMMON_PARAMS, LFI_PAYLOADS

@module("lfi", "web", "تضمين الملفات LFI")
def run(turl, a, R):
    base = norm_target(turl)
    for p in get_params(turl) or COMMON_PARAMS:
        for pay in LFI_PAYLOADS:
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            if "root:" in b and "/bin/" in b:
                R.vuln(f"LFI في {p}: /etc/passwd مقروء! ({pay})")
                break
            if "php://filter" in pay and "cm9vdA" in b:
                R.vuln(f"LFI (php://filter) في {p}: قراءة ملفات مصدرية base64!")
                break
    R.info("اكتمل فحص LFI")
