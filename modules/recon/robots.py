# robots.py — robots.txt و sitemap.xml
import re
from core.registry import module
from core.http import get

@module("robots", "recon", "robots.txt + sitemap.xml")
def run(base, a, R):
    st, _, b = get(base + "/robots.txt")
    if st == 200:
        for line in b.splitlines():
            if line.lower().startswith("disallow") and line.split(":",1)[-1].strip() not in ("", "/"):
                R.warn("robots: " + line.strip())
    st2, _, b2 = get(base + "/sitemap.xml")
    if st2 == 200:
        urls = re.findall(r"<loc>(.*?)</loc>", b2, re.I)
        R.good(f"sitemap: {len(urls)} رابط")
        for u in urls[:10]: R.info("  " + u)
