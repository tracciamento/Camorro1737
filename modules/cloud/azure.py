# azure.py — فحص تخزين Azure
from core.registry import module
from core.http import req
from modules.recon.subdomains import crt_subs

@module("azure", "cloud", "فحص Azure Blob")
def run(base, a, R):
    host = __import__("urllib.parse").urlsplit(base).hostname
    dom = host.split(".", 1)[-1] if host.count(".") >= 2 else host
    names = set([host, dom])
    for s in crt_subs(dom):
        names.add(s); names.add(s.replace("." + dom, ""))
    for name in list(names)[:25]:
        url = f"https://{name}.blob.core.windows.net/?restype=container&comp=list"
        st, _, b = req(url, timeout=10)
        if st == 200:
            R.vuln(f"Azure Blob مفتوح: {name}.blob.core.windows.net (قائمة الملفات!)")
            R.info("  " + b[:200].decode("utf-8","replace"))
        elif st == 403:
            R.warn(f"حاوية Azure موجودة (403): {name}.blob.core.windows.net")
    R.info("اكتمل فحص Azure")
