# s3.py — فحص دلاء S3
from core.registry import module
from core.http import req
from modules.recon.subdomains import crt_subs

@module("s3", "cloud", "فحص دلاء S3")
def run(base, a, R):
    host = __import__("urllib.parse").urlsplit(base).hostname
    dom = host.split(".", 1)[-1] if host.count(".") >= 2 else host
    names = set([host, dom])
    for s in crt_subs(dom):
        names.add(s)
        names.add(s.replace("." + dom, ""))
    for name in list(names)[:25]:
        url = f"https://{name}.s3.amazonaws.com/"
        st, h, b = req(url, timeout=10)
        if st == 200:
            R.vuln(f"S3 عام قابل للقراءة: {name}.s3.amazonaws.com (HTTP 200)")
            if b"<ListBucketResult" in b:
                R.vuln(f"  قائمة الملفات مكشوفة! عدد الملفات: {b.count(b'<Key>')}")
        elif st == 403 and b"AccessDenied" in b:
            R.warn(f"دلو S3 موجود (403): {name}.s3.amazonaws.com")
    R.info("اكتمل فحص S3")
