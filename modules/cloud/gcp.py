# gcp.py — فحص دلاء GCS
from core.registry import module
from core.http import req
from modules.recon.subdomains import crt_subs

@module("gcp", "cloud", "فحص دلاء Google Cloud")
def run(base, a, R):
    host = __import__("urllib.parse").urlsplit(base).hostname
    dom = host.split(".", 1)[-1] if host.count
