#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║  SHADOWFORGE — Web Application Security Framework                ║
║  72 modules · 8 categories · Laravel/PHP focused                 ║
║  Platform : Termux / Linux (pure Python, zero dependencies)      ║
║  Usage    : python3 shadowforge.py [module] [target] [options]   ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import difflib
import argparse
import importlib
import pkgutil
import signal
import threading

# ---------------------------------------------------------------- #
#  المسار الأساسي حتى يعمل الملف من أي مكان
# ---------------------------------------------------------------- #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import core.registry as registry
from core.helpers import R, norm_target

# ---------------------------------------------------------------- #
#  حمولة القائمة: يتم استيراد كل ملف في modules/ تلقائياً،
#  وكل @module يسجّل نفسه في السجل. أي وحدة جديدة تضيفها
#  تظهر تلقائياً في --list و --all دون تعديل أي شيء هنا.
# ---------------------------------------------------------------- #
def load_all_modules():
    """استيراد جميع الوحدات من مجلد modules/ (بما فيها الوحدات الجديدة)."""
    import modules
    count = 0
    for mod in pkgutil.walk_packages(modules.__path__, prefix="modules."):
        if mod.ispkg:
            continue
        try:
            importlib.import_module(mod.name)
            count += 1
        except Exception as e:
            print(f"[!] فشل تحميل {mod.name}: {e}")
    return count

# ---------------------------------------------------------------- #
#  ALL_SUITE: ترتيب تنفيذ الفحص الشامل — استطلاع ثم Laravel ثم ويب
#  ثم مصادقة/API/سحابة ثم الأدوات وينتهي بتقرير.
# ---------------------------------------------------------------- #
ALL_SUITE = [
    # recon (12)
    "detect", "headers", "robots", "cookies", "waf", "ports",
    "tls", "dns", "subdomains", "takeover", "asn", "cms",
    # laravel (14)
    "env", "debug", "ignition", "telescope", "horizon", "sanctum",
    "reverb", "livewire", "serial-rce", "appkey", "artisan",
    "storage", "composer", "mass-assignment",
    # web (18)
    "sqli", "xss", "ssti", "cmd", "lfi", "rfi", "ssrf", "redirect",
    "cors", "csrf", "clickjack", "xxe", "deserialize", "upload",
    "path-traversal", "crlf", "host-header", "smuggler",
    # auth (8)
    "brute", "jwt", "oauth", "session", "2fa", "reset",
    "cookies-attack", "basic-auth",
    # api (6)
    "api", "graphql", "swagger", "rest", "websocket", "idor",
    # cloud (4)
    "s3", "azure", "gcp", "metadata",
    # utils (جزئي — crawl/extract قبل التقرير)
    "crawl", "extract",
    # التقرير أخيراً
    "report",
]

# ---------------------------------------------------------------- #
#  البانر
# ---------------------------------------------------------------- #
BANNER = r"""
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ███████╗███████║███████║██║  ██║██║   ██║██║    █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║    ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝██║    ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
            Web Application Security Framework  —  {v}  —  {n} modules
"""

VERSION = "1.0.0"

# ---------------------------------------------------------------- #
#  بناء وسائط سطر الأوامر
# ---------------------------------------------------------------- #
def build_parser():
    p = argparse.ArgumentParser(
        prog="shadowforge.py",
        description="ShadowForge — إطار اختبار اختراق لتطبيقات الويب (Laravel/PHP).",
        epilog="مثال: python3 shadowforge.py --all https://target.com",
        add_help=False)
    p.add_argument("module",   nargs="?", help="اسم الوحدة (مثال: sqli, laravel-env)")
    p.add_argument("target",   nargs="?", help="الهدف: URL أو دومين (اختياري لبعض الوحدات)")
    p.add_argument("--list",   action="store_true", help="عرض كل الوحدات مصنفة")
    p.add_argument("--all",    action="store_true", help="تشغيل الفحص الشامل ALL_SUITE")
    p.add_argument("--interactive", "-i", action="store_true", help="القائمة التفاعلية")
    p.add_argument("--proxy",  default=None, help="بروكسي: http://127.0.0.1:8080")
    p.add_argument("--wordlist", default=None, help="قائمة كلمات (مسارات/أهداف/أسرار)")
    p.add_argument("--passlist", default=None, help="قائمة كلمات مرور (للـ brute)")
    p.add_argument("--user",   default=None, help="اسم المستخدم (للـ brute/auth)")
    p.add_argument("--login-url", default=None, help="رابط تسجيل الدخول (للـ brute)")
    p.add_argument("--token",  default=None, help="رمز (JWT/API) لبعض الوحدات")
    p.add_argument("--callback", default=None, help="عنوان استرجاع (SSRF/RFI): http://IP:PORT")
    p.add_argument("--out",    default="report", help="اسم ملف التقرير (افتراضي: report)")
    p.add_argument("--timeout", type=int, default=8, help="مهلة الطلبات بالثواني")
    p.add_argument("--threads", type=int, default=10, help="عدد الخيوط للفحص الجماعي")
    p.add_argument("--no-color", action="store_true", help="تعطيل الألوان")
    p.add_argument("-h", "--help", action="store_true", help="عرض المساعدة")
    return p

# ---------------------------------------------------------------- #
#  عرض القائمة
# ---------------------------------------------------------------- #
def show_list():
    from core.helpers import c
    print(c("=" * 72, "1;36"))
    print(c("  وحدات ShadowForge — {n} وحدة في {g} فئات".format(
        n=len(registry.MODULES), g=len(registry.CATEGORIES)), "1;36"))
    print(c("=" * 72, "1;36"))
    total = 0
    for cat in registry.CATEGORIES:
        names = registry.CATEGORIES[cat]
        total += len(names)
        print(c(f"\n[{cat}]  ({len(names)})", "1;33"))
        for name in names:
            desc = registry.MODULES[name][1]
            print(f"  {c(name, '1;32'):<20} {desc}")
    print(c("\n" + "=" * 72, "1;36"))
    print(c(f"  الإجمالي: {total} وحدة", "1;36"))
    print(c("  استخدم: python3 shadowforge.py <module> <target> [options]", "1;37"))
    print(c("=" * 72 + "\n", "1;36"))

# ---------------------------------------------------------------- #
#  تشغيل وحدة واحدة
# ---------------------------------------------------------------- #
def run_module(name, target, args, silent=False):
    """تشغيل وحدة بالاسم مع معالجة الأخطاء."""
    if name not in registry.MODULES:
        close = difflib.get_close_matches(name, registry.MODULES.keys(), n=3)
        print(f"[!] وحدة غير موجودة: {name}")
        if close:
            print(f"[*] هل تقصد: {', '.join(close)}؟")
        else:
            print("[*] شاهد القائمة الكاملة بـ: python3 shadowforge.py --list")
        return False
    cat, desc, fn = registry.MODULES[name]
    if not silent:
        from core.helpers import c
        print(c(f"\n▶ الوحدة: {name}  ({desc})", "1;35"))
        print(c(f"  الهدف : {target}", "1;35"))
        print(c("─" * 60, "1;35"))
    R_obj = R(target)
    t0 = time.time()
    try:
        fn(target, args, R_obj)
    except KeyboardInterrupt:
        print("\n[!] تم الإيقاف يدوياً")
    except Exception as e:
        from core.helpers import c
        print(c(f"[!] خطأ أثناء التنفيذ: {e}", "1;31"))
    dt = time.time() - t0
    if not silent:
        from core.helpers import c
        print(c("─" * 60, "1;35"))
        print(c(f"  انتهت الوحدة {name} خلال {dt:.1f}s — نتائج حرجة: {len(R_obj.finds)}", "1;35"))
    return R_obj

# ---------------------------------------------------------------- #
#  الفحص الشامل
# ---------------------------------------------------------------- #
def run_all(target, args):
    from core.helpers import c
    print(c("\n" + "█" * 72, "1;31"))
    print(c("  الفحص الشامل SHADOWFORGE — ALL SUITE", "1;31"))
    print(c(f"  الهدف: {target}  |  الوحدات: {len(ALL_SUITE)}", "1;31"))
    print(c("█" * 72, "1;31"))
    all_finds = []
    all_lines = []
    for i, name in enumerate(ALL_SUITE, 1):
        if name not in registry.MODULES:
            continue
        print(c(f"\n[{i}/{len(ALL_SUITE)}] ", "1;36") + c(name, "1;33"))
        R_obj = run_module(name, target, args, silent=True)
        if R_obj:
            all_finds.extend(R_obj.finds)
            all_lines.extend(R_obj.lines)
    # تقرير موحد
    from modules.utils.report import gen_report
    R_final = R(target)
    R_final.finds = all_finds
    R_final.lines = all_lines
    gen_report(target, args, R_final)
    print(c("\n" + "█" * 72, "1;31"))
    print(c(f"  اكتمل الفحص الشامل — {len(all_finds)} نتيجة حرجة", "1;31"))
    print(c("█" * 72 + "\n", "1;31"))

# ---------------------------------------------------------------- #
#  الوضع التفاعلي
# ---------------------------------------------------------------- #
def interactive(args):
    from core.helpers import c
    while True:
        print(c("\n" + "─" * 50, "1;36"))
        print(c("  ShadowForge — القائمة التفاعلية", "1;36"))
        print(c("─" * 50, "1;36"))
        print(c("  0)  الفحص الشامل (ALL)", "1;33"))
        idx = 0
        flat = []
        for cat in registry.CATEGORIES:
            print(c(f"\n  [{cat}]", "1;35"))
            for name in registry.CATEGORIES[cat]:
                idx += 1
                flat.append(name)
                print(f"  {idx:>3}) {name:<20} {registry.MODULES[name][1]}")
        print(c(f"\n  {idx+1}) خروج", "1;31"))
        try:
            choice = input(c("\nاختر رقم الوحدة أو الاسم: ", "1;36")).strip()
        except (KeyboardInterrupt, EOFError):
            break
        if choice == "":
            continue
        if choice == "0":
            t = input(c("أدخل الهدف: ", "1;36")).strip()
            if t:
                run_all(norm_target(t), args)
            continue
        if choice.lower() in ("q", "quit", "exit", str(idx + 1)):
            break
        # بالاسم
        if choice in registry.MODULES:
            t = input(c("أدخل الهدف (Enter = تخطي): ", "1;36")).strip()
            run_module(choice, norm_target(t) if t else "http://target.invalid", args)
            continue
        # بالرقم
        try:
            n = int(choice)
            if 1 <= n <= len(flat):
                name = flat[n - 1]
                t = input(c(f"أدخل الهدف لوحدة {name}: ", "1;36")).strip()
                run_module(name, norm_target(t) if t else "http://target.invalid", args)
                continue
        except ValueError:
            pass
        print(c("[!] اختيار غير صالح — حاول مجدداً", "1;31"))

# ---------------------------------------------------------------- #
#  الدخول الرئيسي
# ---------------------------------------------------------------- #
def main():
    parser = build_parser()
    args = parser.parse_args()

    # تعطيل الألوان عند الطلب
    if args.no_color:
        os.environ["SF_NO_COLOR"] = "1"

    # تحميل الوحدات قبل أي شيء
    n = load_all_modules()

    # إعداد البروكسي العام في طبقة HTTP
    if args.proxy:
        try:
            from core import http as sfhttp
            sfhttp.set_proxy(args.proxy)
            print(f"[*] البروكسي مفعّل: {args.proxy}")
        except Exception as e:
            print(f"[!] تعذر ضبط البروكسي: {e}")

    from core.helpers import c
    print(c(BANNER.format(v=VERSION, n=n), "1;36"))
    print(c(f"[*] تم تحميل {n} وحدة في {len(registry.CATEGORIES)} فئات", "1;32"))

    # المساعدة
    if args.help or (len(sys.argv) == 1):
        parser.print_help()
        print("\n[*] شاهد الوحدات: python3 shadowforge.py --list")
        return

    # قائمة الوحدات
    if args.list:
        show_list()
        return

    # الوضع التفاعلي
    if args.interactive:
        interactive(args)
        return

    # الفحص الشامل
    if args.all:
        if not args.target:
            print(c("[!] --all يتطلب هدفاً: python3 shadowforge.py --all https://target.com", "1;31"))
            return
        run_all(norm_target(args.target), args)
        return

    # تشغيل وحدة محددة
    if args.module:
        target = norm_target(args.target) if args.target else "http://target.invalid"
        run_module(args.module, target, args)
        return

    parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] تم الإيقاف. وداعاً.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] خطأ غير متوقع: {e}")
        sys.exit(1)
