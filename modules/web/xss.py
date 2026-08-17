# xss.py — XSS منعكسة
import urllib.parse
from core.registry import module
from core.helpers import norm_target, get_params
from core.http import get
from core.wordlists import COMMON_PARAMS, XSS_PAYLOADS

@module("xss", "web", "XSS منعكسة")
def run(turl, a, R):
    base = norm_target(turl)
    for p in get_params(turl) or COMMON_PARAMS:
        for pay in XSS_PAYLOADS:
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            if pay in b:
                R.vuln(f"XSS منعكسة في {p}: {pay}")
                break
    R.info("اكتمل فحص XSS")
