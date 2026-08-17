# graphql.py — هجمات GraphQL
import json
from core.registry import module
from core.http import req

@module("graphql", "api", "هجمات GraphQL")
def run(base, a, R):
    found = False
    for ep in ["/graphql", "/graphiql", "/api/graphql", "/gql", "/v1/graphql"]:
        st, _, b = req(base + ep, method="POST", data='{"query":"{__typename}"}',
                       headers={"Content-Type": "application/json"})
        if st == 200 and "__typename" in b.decode("utf-8","replace"):
            found = True
            R.vuln(f"GraphQL endpoint: {ep}")
            st2, _, b2 = req(base + ep, method="POST",
                             data='{"query":"{__schema{types{name}}}"}',
                             headers={"Content-Type": "application/json"})
            if st2 == 200 and '"types"' in b2.decode("utf-8","replace"):
                R.vuln("Introspection مفتوح — كشف schema كامل!")
                try:
                    types = [t["name"] for t in json.loads(b2)["data"]["__schema"]["types"]
                             if not t["name"].startswith("__")]
                    R.info("الأنواع: " + ", ".join(types[:25]))
                except Exception:
                    pass
            # اختبار Batch (تجاوز معدل الطلبات)
            batch = json.dumps([{"query": "{__typename}"}] * 20)
            st3, _, _ = req(base + ep, method="POST", data=batch,
                            headers={"Content-Type": "application/json"})
            if st3 == 200:
                R.warn("GraphQL Batching يعمل — تجاوز rate limit محتمل!")
            break
    if not found:
        R.info("لا GraphQL مكشوف")
