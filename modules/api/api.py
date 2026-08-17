# api.py — استكشاف نقاط API
import json
from core.registry import module
from core.http import get, req
from core.wordlists import API_PATHS
from core.helpers import load_list

@module("api", "api", "استكشاف نقاط API")
def run(base, a, R):
    wl = load_list(getattr(a, "wordlist", "") or "") if getattr(a, "wordlist", None) else API_PATHS
    for p in wl:
        st, h, b = get(f"{base}/{p}")
        if st in (200, 401, 403, 500):
            ct = h.get("content-type", "")
            R.vuln(f"API: /{p} -> HTTP {st} ({ct[:40]})")
            if st == 200:
                try:
                    data = json.loads(b)
                    R.info("  JSON: " + json.dumps(data)[:150])
                except Exception:
                    R.info("  " + b[:120].replace("\n", " "))
    R.info("اكتمل استكشاف API")
