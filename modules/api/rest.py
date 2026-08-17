# rest.py — اختبار أفعال REST
from core.registry import module
from core.http import req, get
from core.wordlists import API_PATHS

@module("rest", "api", "اختبار أفعال REST (PUT/DELETE)")
def run(base, a, R):
    candidates = []
    for p in API_PATHS[:20]:
        st, _, _ = get(base + "/" + p)
        if st in (200, 401, 403, 405): candidates.append(p)
    if not candidates:
        R.info("لا نقاط API واضحة لاختبارها"); return
    for p in candidates[:8]:
        st, h, _ = req(base + "/" + p, method="OPTIONS")
        allow = h.get("allow", "")
        if allow:
            R.info(f"OPTIONS /{p}: Allow={allow}")
            if any(v in allow.upper() for v in ["PUT", "PATCH", "DELETE"]):
                R.vuln(f"/{p} يسمح بـ {allow} — جرّب تعديل/حذف موارد!")
        st2, _, b2 = req(base + "/" + p, method="PUT", data='{"test":1}',
                         headers={"Content-Type": "application/json"})
        if st2 in (200, 201, 204):
            R.vuln(f"PUT إلى /{p} -> HTTP {st2} — إنشاء/تعديل موارد بدون مصادقة محتمل!")
    R.info("اكتمل اختبار REST")
