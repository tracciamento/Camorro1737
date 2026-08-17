# gcp.py — فحص دلاء Google Cloud Storage
from core.registry import module
from core.http import req
from modules.recon.subdomains import crt_subs

@module("gcp", "cloud", "فحص دلاء GCS")
def run(base, a, R):
    host = __import__("urllib.parse").urlsplit(base).hostname
    dom = host.split(".", 1)[-1] if host.count(".") >= 2 else host
    names = set([host, dom])
    for s in crt_subs(dom):
        names.add(s); names.add(s.replace("." + dom, ""))
    for name in list(names)[:25]:
        url = f"https://storage.googleapis.com/{name}?list-type=2"
        st, _, b = req(url, timeout=10)
        if st == 200 and b"<ListBucketResult" in b:
            R.vuln(f"دلو GCS مفتوح: {name} (قائمة الملفات مكشوفة!)")
        elif st == 200 and b"<Error" not in b:
            R.warn(f"دلو GCS موجود: {name}")
    R.info("اكتمل فحص GCS")
