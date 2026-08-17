# mass-scan.py — فحص عدة أهداف
import concurrent.futures
from core.registry import module
from core.helpers import R, load_list, norm_target
from core.http import get

def _scan_one(url):
    try:
        st, h, b = get(url + "/", timeout=6)
        return (url, st, h.get("server", ""), len(b))
    except Exception:
        return (url, 0, "", 0)

@module("mass-scan", "utils", "فحص جماعي للأهداف")
def run(base, a, R):
    wl = getattr(a, "wordlist", None)
    if not wl:
        R.info("--wordlist targets.txt (سطر لكل هدف)"); return
    targets = load_list(wl)
    R.good(f"فحص {len(targets)} هدفاً")
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        for url, st, srv, size in ex.map(_scan_one, targets):
            if st in (200, 301, 302, 403):
                R.info(f"  {url:<50} HTTP {st}  {srv}  ({size} بايت)")
            else:
                R.warn(f"  {url:<50} لا يستجيب/HTTP {st}")
