# cors.py — سوء إعداد CORS
from core.registry import module
from core.http import req

@module("cors", "web", "سوء إعداد CORS")
def run(base, a, R):
    st, h, _ = req(base + "/", headers={"Origin": "https://evil.com"})
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")
    if acao == "https://evil.com" and acac.lower() == "true":
        R.vuln("CORS خطير: يعكس أي Origin مع Credentials — سرقة بيانات!")
    elif acao == "*" and acac.lower() == "true":
        R.vuln("CORS: ACAO=* مع Credentials=true")
    elif acao == "https://evil.com":
        R.warn("CORS يعكس Origin (بدون Credentials)")
    else:
        R.good("CORS آمن")
