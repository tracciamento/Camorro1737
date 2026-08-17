# idor.py — فحص IDOR عبر المعرفات المتسلسلة
from core.registry import module
from core.http import get

@module("idor", "api", "فحص IDOR")
def run(base, a, R):
    patterns = ["/api/user/{n}", "/api/users/{n}", "/api/items/{n}", "/api/orders/{n}",
                "/api/profile/{n}", "/api/files/{n}", "/user/{n}", "/profile/{n}"]
    tested = False
    for pat in patterns:
        results = []
        for n in (1, 2, 3, 100, 1000):
            st, _, b = get(base + pat.format(n=n))
            results.append((st, len(b)))
        if results and any(st == 200 for st, _ in results):
            statuses = [st for st, _ in results]
            R.info(f"{pat}: {statuses}")
            tested = True
            if statuses.count(200) >= 2:
                R.vuln(f"IDOR محتمل: {pat} يرجع بيانات لعدة معرفات بدون مصادقة!")
    if not tested:
        R.info("لا أنماط IDOR معروفة تستجيب — حدد نقطة API حقيقية")
