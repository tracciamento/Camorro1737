# swagger.py — اكتشاف Swagger/OpenAPI
import json, re
from core.registry import module
from core.http import get

@module("swagger", "api", "اكتشاف Swagger/OpenAPI")
def run(base, a, R):
    for p in ["swagger", "swagger-ui.html", "swagger/index.html", "api-docs",
              "v2/api-docs", "v3/api-docs", "openapi.json", "swagger.json", "docs"]:
        st, _, b = get(base + "/" + p)
        if st == 200:
            if "swagger" in b.lower() or "openapi" in b.lower() or p.endswith(".json"):
                R.vuln(f"توثيق API مكشوف: /{p} (HTTP {st})")
                if p.endswith(".json"):
                    try:
                        d = json.loads(b)
                        paths = d.get("paths", {})
                        R.info(f"  {len(paths)} نقطة API موثقة")
                        for k in list(paths)[:15]: R.info("    " + k)
                    except Exception:
                        pass
            else:
                R.info(f"/{p} -> HTTP {st} (ليس توثيقاً)")
    R.info("اكتمل فحص Swagger")
