# dns.py — سجلات DNS + Zone Transfer
from core.registry import module
from core import dns as D

@module("dns", "recon", "سجلات DNS + AXFR")
def run(base, a, R):
    host = __import__("urllib.parse").urlsplit(base).hostname
    for qt, name in [(1,"A"),(2,"NS"),(15,"MX"),(16,"TXT"),(28,"AAAA")]:
        r = D.dns_query(host, qt)
        if r and r != "NXDOMAIN":
            for typ, val in r:
                if name == "A" and typ == "A": R.good(f"A: {val}")
                if name == "NS" and typ == "NS": R.good(f"NS: {val}")
                if name == "MX" and typ == "MX": R.good(f"MX: {val}")
                if name == "TXT" and typ == "TXT": R.info(f"TXT: {val[:90]}")
                if name == "AAAA" and typ == "AAAA": R.good(f"AAAA: {val}")
    nss = D.dns_query(host, 2)
    if nss and nss != "NXDOMAIN":
        for typ, ns in nss:
            cnt = D.axfr(host, ns)
            if cnt and cnt > 0:
                R.vuln(f"Zone Transfer ناجح عبر {ns} — {cnt} سجل!")
            else:
                R.info(f"AXFR عبر {ns} مرفوض")
