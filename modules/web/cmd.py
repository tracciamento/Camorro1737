# cmd.py — حقن الأوامر
import time, urllib.parse
from core.registry import module
from core.helpers import norm_target, get_params
from core.http import get
from core.wordlists import COMMON_PARAMS, CMD_PAYLOADS

@module("cmd", "web", "حقن الأوامر")
def run(turl, a, R):
    base = norm_target(turl)
    for p in get_params(turl) or COMMON_PARAMS:
        for pay, marker in CMD_PAYLOADS:
            t1 = time.time()
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            dt = time.time() - t1
            if marker and marker in b:
                R.vuln(f"Command Injection في {p} (مخرجات ظاهرة): {pay}")
            elif marker is None and dt >= 2.5:
                R.vuln(f"Command Injection (زمني) في {p}: {dt:.1f}s")
    R.info("اكتمل فحص حقن الأوامر")
