# redirect.py — تحويل مفتوح
import urllib.parse
from core.registry import module
from core.helpers import norm_target
from core.http import req
from core.wordlists import REDIRECT_PARAMS

@module("redirect", "web", "تحويل مفتوح")
def run(turl, a, R):
    base = norm_target(turl)
    host = urllib.parse.urlsplit(base).hostname
    for p in REDIRECT_PARAMS:
        st, h, _ = req(f"{base}/?{p}=https://evil.com", redirects=False)
        loc = h.get("location", "")
        if st in (301, 302, 303, 307, 308) and loc:
            lh = urllib.parse.urlsplit(loc).hostname
            if lh and "evil.com" in lh:
                R.vuln(f"Open Redirect عبر {p}: {loc[:80]}")
    R.info("اكتمل فحص التحويل المفتوح")
