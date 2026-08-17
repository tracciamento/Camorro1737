# tls.py — إصدارات TLS والشهادة
import socket, ssl, time
from core.registry import module
from core.http import UA

@module("tls", "recon", "فحص TLS والشهادة")
def run(base, a, R):
    host = __import__("urllib.parse").urlsplit(base).hostname
    if not base.startswith("https://"): R.info("الهدف HTTP — تخطي"); return
    for ver, label in [(ssl.TLSVersion.TLSv1, "TLSv1.0"), (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
                       (ssl.TLSVersion.TLSv1_2, "TLSv1.2"), (ssl.TLSVersion.TLSv1_3, "TLSv1.3")]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver; ctx.maximum_version = ver
            with socket.create_connection((host, 443), timeout=6):
                pass
            with socket.create_connection((host, 443), timeout=6) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    if ver in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                        R.vuln(f"{label} مدعوم — إصدار ضعيف")
                    else:
                        R.good(f"{label} مدعوم")
        except Exception:
            pass
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                cert = t.getpeercert()
        exp = cert.get("notAfter", "?")
        try:
            days = (time.mktime(time.strptime(exp, "%b %d %H:%M:%S %Y %Z")) - time.time()) / 86400
            if days < 0: R.vuln(f"الشهادة منتهية ({exp})")
            elif days < 30: R.warn(f"تنتهي قريباً: {exp} ({int(days)} يوم)")
            else: R.good(f"الشهادة صالحة حتى {exp}")
        except Exception:
            R.info(f"انتهاء الشهادة: {exp}")
        iss = cert.get("issuer")
        if iss: R.info("المُصدر: " + str(dict(iss[0]).get("organizationName", iss[0])))
    except Exception:
        R.warn("تعذر قراءة الشهادة")
