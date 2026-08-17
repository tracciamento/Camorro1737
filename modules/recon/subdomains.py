# subdomains.py — استكشاف نطاقات فرعية عبر crt.sh
import json
from core.registry import module
from core.http import req

def crt_subs(domain, timeout=25):
    names = set()
    try:
        st, _, b = req(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=timeout)
        if st == 200:
            for e in json.loads(b.decode("utf-8","replace")):
                for n in (e.get("name_value") or "").split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain): names.add(n)
    except Exception:
        pass
    return names

@module("subdomains", "recon", "استكشاف النطاقات الفرعية")
def run(base, a, R):
    host = __import__("urllib.parse").urlsplit(base).hostname
    dom = host.split(".", 1)[-1] if host.count(".") >= 2 else host
    subs = crt_subs(dom)
    if subs:
        R.vuln(f"وجدنا {len(subs)} نطاقاً فرعياً")
        for n in sorted(subs)[:40]: R.info("  " + n)
    else:
        R.info("لا نتائج من crt.sh")
