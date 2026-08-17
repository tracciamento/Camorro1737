# cookies.py — خصائص الكوكيز
from core.registry import module
from core.http import get

@module("cookies", "recon", "فحص خصائص ملفات تعريف الارتباط")
def run(base, a, R):
    _, h, _ = get(base + "/")
    sc = h.get("set-cookie", "")
    if not sc: R.info("لا Set-Cookie"); return
    for part in sc.split(","):
        part = part.strip()
        if not part or "=" not in part: continue
        name = part.split("=",1)[0].strip()
        flags = [f.lower() for f in part.split(";")[1:]]
        for f in ["httponly","secure","samesite"]:
            if not any(f in fl for fl in flags): R.warn(f"cookie {name}: مفقودة {f}")
        if any("samesite=none" in fl for fl in flags) and not any("secure" in fl for fl in flags):
            R.vuln(f"cookie {name}: SameSite=None بدون Secure")
