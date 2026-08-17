# deserialize.py — كشف نقاط إلغاء التسلسل
import re, base64
from core.registry import module
from core.http import get

@module("deserialize", "web", "كشف إلغاء التسلسل")
def run(base, a, R):
    st, h, b = get(base + "/")
    blob = b + " " + str(h)
    hits = []
    if re.search(r"O:\d+:\"[A-Za-z_]+", blob):
        hits.append("كائن PHP متسلسل (O:n:) في الاستجابة/الكوكيز")
    if "rO0AB" in blob:
        hits.append("Java serialized (rO0AB) في الاستجابة")
    if "base64" in blob.lower() and re.search(r"[A-Za-z0-9+/]{200,}={0,2}", b):
        hits.append("حقل base64 كبير محتمل التسلسل")
    for name, val in h.items():
        if name == "set-cookie" and re.search(r"O:\d+:", val):
            hits.append(f"كوكيز PHP object: {val[:60]}")
    if hits:
        R.vuln("مؤشرات إلغاء تسلسل: " + "; ".join(hits))
        R.info("جرّب phpggg/ysoserial على هذه النقاط حسب التقنية")
    else:
        R.info("لا مؤشرات تسلسل مباشرة")
