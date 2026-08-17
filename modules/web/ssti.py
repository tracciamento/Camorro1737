# ssti.py — حقن القوالب
import urllib.parse
from core.registry import module
from core.helpers import norm_target, get_params
from core.http import get
from core.wordlists import COMMON_PARAMS, SSTI_PAYLOADS

@module("ssti", "web", "حقن القوالب SSTI")
def run(turl, a, R):
    base = norm_target(turl)
    for p in get_params(turl) or COMMON_PARAMS:
        for pay in SSTI_PAYLOADS:
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            if pay == "{{7*7}}" and "49" in b: R.vuln(f"SSTI (Jinja/Blade) في {p}")
            elif pay == "${7*7}" and "49" in b: R.vuln(f"SSTI في {p}")
            elif pay == "{{7*'7'}}" and "7777777" in b: R.vuln(f"SSTI (Twig) في {p}")
            elif pay == "<%= 7*7 %>" and "49" in b: R.vuln(f"SSTI (ERB) في {p}")
    R.info("اكتمل فحص SSTI")
