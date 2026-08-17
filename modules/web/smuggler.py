# smuggler.py — تهريب الطلبات (CL.TE / TE.CL)
from core.registry import module
from core.http import raw_request

@module("smuggler", "web", "تهريب الطلبات")
def run(base, a, R):
    # اختبار CL.TE
    data = raw_request(base + "/", b"Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n")
    if data.startswith(b"HTTP/1.1 400") or data.startswith(b"HTTP/1.1 505"):
        R.info("الخادم يرفض TE+CL (قد يكون محمياً)")
    else:
        R.warn("الخادم قبل TE مع CL — استكمل اختبار CL.TE يدوياً")
    # اختبار TE.CL
    data2 = raw_request(base + "/", b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    if b"HTTP/1.1 400" not in data2 and len(data2) > 200:
        R.warn("الخادم قبل TE.CL — استكمل الاختبار اليدوي بـ Turbo Intruder")
    R.info("التهريب يتطلب تحققاً يدوياً دقيقاً (توقيت/خطأ تحليل)")
