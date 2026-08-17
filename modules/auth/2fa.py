# 2fa.py — فحص 2FA
from core.registry import module
from core.http import get

@module("2fa", "auth", "فحص التحقق بخطوتين")
def run(base, a, R):
    paths = ["/2fa", "/2fa/setup", "/mfa", "/otp", "/verify", "/verify-otp",
             "/two-factor", "/two-factor/setup", "/auth/2fa"]
    for p in paths:
        st, _, b = get(base + p)
        if st == 200:
            low = b.lower()
            if "enabled" in low or "setup" in low or "otp" in low or "authenticator" in low:
                R.warn(f"/{p} -> 200: صفحة 2FA متاحة — تحقق من حمايتها (2FA bypass محتمل)")
            else:
                R.info(f"/{p} -> 200")
        elif st in (302, 401, 403):
            R.info(f"/{p} -> HTTP {st} (محمي)")
    R.info("جرّب أيضاً: تسجيل الدخول بدون رمز 2FA، إعادة إرسال الرمز، استبدال الرد")
