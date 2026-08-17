# composer.py — تحليل composer.json / installed.json
import json, re
from core.registry import module
from core.http import get

def _ver(v):
    try: return tuple(map(int, re.findall(r"\d+", v)[:3]))
    except Exception: return (0,)

@module("composer", "laravel", "فحص إصدارات الحزم (composer)")
def run(base, a, R):
    st, _, b = get(base + "/vendor/composer/installed.json")
    if st == 200:
        try:
            data = json.loads(b)
            pkgs = data.get("packages", data) if isinstance(data, dict) else data
            for p in pkgs:
                name = p.get("name", ""); v = p.get("version", "")
                if name == "laravel/framework":
                    R.good(f"laravel/framework: {v}")
                    if _ver(v) <= (5, 6, 29): R.vuln("≤5.6.29 — CVE-2018-15133 (RCE عبر APP_KEY)")
                    if (6,) <= _ver(v) <= (6, 20, 10): R.vuln("CVE-2024-47823 محتمل (SQLi)")
                    if (7,) <= _ver(v) <= (7, 30, 1): R.vuln("CVE-2024-47823 محتمل (SQLi)")
                    if (8,) <= _ver(v) <= (8, 22, 0): R.vuln("CVE-2024-47823 محتمل (SQLi)")
                if name == "facade/ignition" and _ver(v) <= (2, 5, 1):
                    R.vuln(f"facade/ignition {v} — CVE-2021-3129 (RCE)")
                if "livewire" in name and _ver(v) < (3, 6, 4):
                    R.vuln(f"{name} {v} — CVE-2025-54068")
                if "reverb" in name and _ver(v) < (1, 6, 3):
                    R.vuln(f"{name} {v} — CVE-2026-23524 (RCE عبر Redis unserialize)")
        except Exception as e:
            R.warn(f"تعذر تحليل installed.json: {e}")
    else:
        R.info("installed.json غير متاح")
