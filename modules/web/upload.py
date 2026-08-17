# upload.py — اكتشاف نماذج الرفع
import re
from core.registry import module
from core.http import get

@module("upload", "web", "اكتشاف نماذج الرفع")
def run(base, a, R):
    st, _, b = get(base + "/")
    forms = re.findall(r"<form[^>]*>", b, re.I)
    found = False
    for f in forms:
        if "multipart/form-data" in f.lower() and ("file" in f.lower() or "upload" in f.lower()):
            action = re.search(r'action=["\']([^"\']*)["\']', f, re.I)
            R.vuln("نموذج رفع ملفات: " + (action.group(1) if action else "(نفس الصفحة)"))
            found = True
    if not found:
        for p in ["upload", "uploads", "upload.php", "upload-file", "files/upload"]:
            s2, _, _ = get(base + "/" + p)
            if s2 in (200, 302, 405):
                R.info(f"/{p} -> HTTP {s2} — تحقق من نموذج رفع")
    R.info("جرّب رفع .php/.phtml/.phar وفحص الفلترة (التحقق من نوع الملف)")
