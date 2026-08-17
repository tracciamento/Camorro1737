# session.py — تحليل الجلسات
from core.registry import module
from core.http import get

@module("session", "auth", "تحليل الجلسات")
def run(base, a, R):
    _, h1, _ = get(base + "/")
    _, h2, _ = get(base + "/")
    c1 = h1.get("set-cookie", ""); c2 = h2.get("set-cookie", "")
    if not c1: R.info("لا جلسات"); return
    s1 = c1.split("=",1)[1].split(";")[0] if "=" in c1 else ""
    s2 = c2.split("=",1)[1].split(";")[0] if "=" in c2 else ""
    if s1 == s2 and len(s1) > 4:
        R.vuln(f"معرف الجلسة ثابت بين الطلبات — تثبيت جلسة محتمل! ({s1[:20]}...)")
    elif len(s1) < 16:
        R.warn(f"معرف جلسة قصير ({len(s1)} حرفاً) — قابل للتخمين")
    else:
        R.good(f"معرف الجلسة متغير وطويل ({len(s1)} حرفاً)")
    R.info(f"اسم الكوكي: {c1.split('=',1)[0]}")
