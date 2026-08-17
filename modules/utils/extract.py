# extract.py — استخراج بيانات من صفحة
import re, urllib.parse
from core.registry import module
from core.http import get

@module("extract", "utils", "استخراج بيانات (إيميلات/رموز)")
def run(base, a, R):
    st, _, b = get(base + "/")
    if st != 200:
        R.info("الصفحة غير قابلة للقراءة"); return
    emails = sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", b)))
    tokens = sorted(set(re.findall(r"(?:api[_-]?key|token|secret|password)\s*[=:]\s*[\"']?([A-Za-z0-9_\-\.]{8,})", b, re.I)))
    urls = sorted(set(re.findall(r'https?://[^\s"\'<>]+', b)))
    if emails:
        R.vuln(f"إيميلات: {len(emails)}")
        for e in emails[:15]: R.info("  " + e)
    if tokens:
        R.vuln(f"رموز/مفاتيح محتملة: {len(tokens)}")
        for t in tokens[:10]: R.info("  " + t)
    R.good(f"روابط: {len(urls)}")
    for u in urls[:10]: R.info("  " + u)
    if not emails and not tokens:
        R.info("لا بيانات حساسة في الصفحة الرئيسية")
