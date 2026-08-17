# livewire.py — فحص Livewire CVE-2025-54068
import re
from core.registry import module
from core.http import get, req

@module("livewire", "laravel", "فحص Livewire (CVE-2025-54068)")
def run(base, a, R):
    st, _, b = get(base + "/")
    if "livewire" in b.lower() or "livewire.js" in b.lower() or "@livewire" in b:
        R.info("Livewire مستخدم في الصفحة")
        m = re.search(r"livewire@v?([\d.]+)", b) or re.search(r'"livewire"\s*:\s*"([\d.]+)"', b)
        if m:
            v = m.group(1)
            R.info(f"نسخة Livewire: {v}")
            try:
                if tuple(map(int, v.split("."))) < (3, 6, 4):
                    R.vuln(f"Livewire {v} < 3.6.4 — CVE-2025-54068 (حقن كود/RCE)")
            except Exception:
                pass
        st2, _, _ = req(base + "/livewire/message", method="POST", data="{}",
                        headers={"Content-Type": "application/json"})
        if st2 == 419: R.info("CSRF يحمي livewire/message (419)")
        elif st2 in (200, 422): R.warn("livewire/message يستجيب — اختبر CVE-2025-54068 يدوياً")
    else:
        R.info("لا Livewire في الصفحة الرئيسية")
