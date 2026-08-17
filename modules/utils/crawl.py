# crawl.py — زاحف روابط بسيط
import re, urllib.parse
from core.registry import module
from core.http import get

@module("crawl", "utils", "زحف الروابط")
def run(base, a, R):
    seen, queue = set(), [base + "/"]
    host = urllib.parse.urlsplit(base).hostname
    limit = 100
    while queue and len(seen) < limit:
        url = queue.pop(0)
        if url in seen: continue
        seen.add(url)
        st, _, b = get(url, timeout=6)
        if st != 200: continue
        for m in re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', b, re.I):
            u = urllib.parse.urljoin(url, m)
            u = urllib.parse.urlsplit(u)
            if u.hostname == host and u.scheme in ("http", "https"):
                u = f"{u.scheme}://{u.netloc}{u.path}" + ("?" + u.query if u.query else "")
                if u not in seen and len(seen) < limit:
                    queue.append(u)
    R.good(f"زحفنا {len(seen)} رابطاً")
    for u in sorted(seen)[:60]: R.info("  " + u)
    open("crawl.txt", "w").write("\n".join(sorted(seen)))
    R.info("الحفظ: crawl.txt")
