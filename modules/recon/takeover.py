# takeover.py — استيلاء النطاقات الفرعية
import concurrent.futures
from core.registry import module
from core import dns as D
from core.wordlists import TAKEOVER
from modules.recon.subdomains import crt_subs

@module("takeover", "recon", "فحص استيلاء النطاقات")
def run(base, a, R):
    host = __import__("urllib.parse").urlsplit(base).hostname
    dom = host.split(".", 1)[-1] if host.count(".") >= 2 else host
    subs = crt_subs(dom)
    if not subs: R.info("لا نطاقات للفحص"); return
    def chk(sub):
        r = D.dns_query(sub, 5)
        if r and r != "NXDOMAIN":
            for typ, cn in r:
                if typ == "CNAME" and any(svc in cn.lower() for svc in TAKEOVER):
                    ar = D.dns_query(cn, 1)
                    if ar == "NXDOMAIN" or not ar:
                        return (sub, cn)
        return None
    thr = getattr(a, "threads", 10)
    with concurrent.futures.ThreadPoolExecutor(max_workers=thr) as ex:
        for res in ex.map(chk, list(subs)):
            if res:
                R.vuln(f"استيلاء محتمل: {res[0]} -> CNAME {res[1]} (لا يحل!)")
    R.info("اكتمل فحص الاستيلاء")
