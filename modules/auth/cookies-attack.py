# cookies-attack.py — هجوم الكوكيز
import base64, re, json
from core.registry import module
from core.http import get

@module("cookies-attack", "auth", "تحليل وهجوم الكوكيز")
def run(base, a, R):
    _, h, _ = get(base + "/")
    sc = h.get("set-cookie", "")
    if not sc: R.info("لا كوكيز"); return
    for part in sc.split(","):
        if "=" not in part: continue
        name, val = part.split("=",1)[0].strip(), part.split("=",1)[1].split(";")[0].strip()
        if not val: continue
        decoded = None
        try:
            dec = base64.b64decode(val + "=" * (-len(val) % 4))
            if dec:
                decoded = dec.decode("utf-8", "replace")
                if re.match(r"^[A-Za-z0-9_\-\s:,.\"']+$", decoded):
                    R.warn(f"cookie {name} base64: {decoded[:80]}")
                    if "user" in decoded.lower() or "admin" in decoded.lower() or "role" in decoded.lower():
                        R.vuln(f"cookie {name} تحتوي بيانات قابلة للتعديل: {decoded[:120]} — جرّب التلاعب!")
        except Exception:
            pass
        if not decoded:
            R.info(f"cookie {name} = {val[:40]}... (غير base64)")
    R.info("جرّب: تعديل قيمة الكوكي وإعادة إرسالها، وفحص توقيعها")
