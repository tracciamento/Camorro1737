# report.py — توليد تقرير HTML/Markdown
import html, time
from core.registry import module

def gen_report(base, a, R):
    fn = getattr(a, "out", "report")
    md = [f"# ShadowForge Report — {base}", "",
          f"الوقت: {time.ctime()}", f"النتائج الحرجة: {len(R.finds)}", ""]
    if R.finds:
        md.append("## الثغرات")
        for f in R.finds: md.append(f"- [ ] {f}")
    md.append("\n## السجل الكامل")
    for kind, msg in R.lines: md.append(f"- {kind}: {msg}")
    open(fn + ".md", "w", encoding="utf-8").write("\n".join(md))

    hh = ["<!DOCTYPE html><html><head><meta charset='utf-8'><title>ShadowForge</title>",
          "<style>body{font-family:monospace;margin:40px;background:#111;color:#eee}",
          ".vuln{color:#f66}.info{color:#6cf}.warn{color:#fc6}",
          "table{border-collapse:collapse}td,th{border:1px solid #444;padding:6px}</style></head><body>"]
    hh.append(f"<h1>ShadowForge — {html.escape(base)}</h1>")
    hh.append(f"<p>{time.ctime()} — {len(R.finds)} نتيجة حرجة</p>")
    if R.finds:
        hh.append("<h2>الثغرات</h2><table><tr><th>#</th><th>الوصف</th></tr>")
        for i, f in enumerate(R.finds, 1):
            hh.append(f"<tr><td>{i}</td><td class='vuln'>{html.escape(f)}</td></tr>")
        hh.append("</table>")
    hh.append("<h2>السجل</h2><ul>")
    for kind, msg in R.lines:
        cls = "vuln" if kind == "vuln" else ("warn" if kind == "warn" else "info")
        hh.append(f"<li class='{cls}'>{html.escape(msg)}</li>")
    hh.append("</ul></body></html>")
    open(fn + ".html", "w", encoding="utf-8").write("\n".join(hh))

@module("report", "utils", "توليد تقرير من النتائج")
def run(base, a, R):
    gen_report(base, a, R)
    R.good("التقريران: report.md و report.html")
