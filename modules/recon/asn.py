# asn.py — استعلام ASN عبر DNS (Team Cymru)
from core.registry import module
from core import dns as D

@module("asn", "recon", "بحث ASN عبر Team Cymru")
def run(base, a, R):
    host = __import__("urllib.parse").urlsplit(base).hostname
    ip = host
    try:
        import socket as _s
        ip = _s.gethostbyname(host)
        R.good(f"IP: {ip}")
    except Exception:
        R.warn("تعذر حل الاسم"); return
    r = D.dns_query(f"{ip}.origin.asn.cymru.com", 16)
    if r and r != "NXDOMAIN":
        for typ, val in r:
            R.good(f"ASN: {val}")
    else:
        R.info("لا ASN متاح")
