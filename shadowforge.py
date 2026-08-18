#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SHADOWFORGE — Web Application Security Framework
Version 1.1.0

Usage:
    python3 shadowforge.py --list
    python3 shadowforge.py headers https://target.example
    python3 shadowforge.py --all https://target.example
    python3 shadowforge.py --interactive
"""

import os
import sys
import time
import difflib
import argparse
import importlib
import pkgutil
import traceback


# ================================================================
# PATH
# ================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


# ================================================================
# CORE
# ================================================================

try:
    import core.registry as registry
    from core.helpers import R, norm_target
except Exception as exc:
    print(f"[!] فشل تحميل core: {exc}")
    sys.exit(1)


# ================================================================
# CONFIG
# ================================================================

VERSION = "1.1.0"


ALL_SUITE = [
    # recon
    "detect",
    "headers",
    "robots",
    "cookies",
    "waf",
    "ports",
    "tls",
    "dns",
    "subdomains",
    "takeover",
    "asn",
    "cms",

    # laravel
    "env",
    "debug",
    "ignition",
    "telescope",
    "horizon",
    "sanctum",
    "reverb",
    "livewire",
    "serial-rce",
    "appkey",
    "artisan",
    "storage",
    "composer",
    "mass-assignment",

    # web
    "sqli",
    "xss",
    "ssti",
    "cmd",
    "lfi",
    "rfi",
    "ssrf",
    "redirect",
    "cors",
    "csrf",
    "clickjack",
    "xxe",
    "deserialize",
    "upload",
    "path-traversal",
    "crlf",
    "host-header",
    "smuggler",

    # auth
    "brute",
    "jwt",
    "oauth",
    "session",
    "2fa",
    "reset",
    "cookies-attack",
    "basic-auth",

    # api
    "api",
    "graphql",
    "swagger",
    "rest",
    "websocket",
    "idor",

    # cloud
    "s3",
    "azure",
    "gcp",
    "metadata",

    # utils
    "crawl",
    "extract",

    # report
    "report",
]


BANNER = r"""
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ███████╗███████║███████║██║  ██║██║   ██║██║    █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║    ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝██║    ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

             Web Application Security Framework — {v} — {n} modules
"""


# ================================================================
# COLORS
# ================================================================

def c(text, code="0"):
    if os.environ.get("SF_NO_COLOR") == "1":
        return str(text)

    return f"\033[{code}m{text}\033[0m"


def info(text):
    print(c(f"[*] {text}", "1;36"))


def success(text):
    print(c(f"[+] {text}", "1;32"))


def warning(text):
    print(c(f"[!] {text}", "1;33"))


def error(text):
    print(c(f"[!] {text}", "1;31"))


# ================================================================
# PACKAGE CHECK
# ================================================================

def ensure_package_files():
    """
    يتأكد من وجود __init__.py داخل modules والمجلدات الفرعية.
    """

    modules_dir = os.path.join(BASE_DIR, "modules")

    if not os.path.isdir(modules_dir):
        error(f"مجلد modules غير موجود: {modules_dir}")
        return False

    root_init = os.path.join(modules_dir, "__init__.py")

    if not os.path.exists(root_init):
        try:
            with open(root_init, "w", encoding="utf-8") as f:
                f.write("# ShadowForge modules package\n")
        except Exception as exc:
            error(f"تعذر إنشاء modules/__init__.py: {exc}")
            return False

    for name in os.listdir(modules_dir):

        path = os.path.join(modules_dir, name)

        if not os.path.isdir(path):
            continue

        if name.startswith("."):
            continue

        init_file = os.path.join(path, "__init__.py")

        if not os.path.exists(init_file):
            try:
                with open(init_file, "w", encoding="utf-8") as f:
                    f.write(f"# ShadowForge {name} package\n")
            except Exception as exc:
                warning(
                    f"تعذر إنشاء {name}/__init__.py: {exc}"
                )

    return True


# ================================================================
# DISCOVER MODULES
# ================================================================

def discover_module_files():
    """
    اكتشاف ملفات Python الموجودة فعلياً داخل modules/.
    """

    modules_dir = os.path.join(BASE_DIR, "modules")

    found = []

    if not os.path.isdir(modules_dir):
        return found

    for root, dirs, files in os.walk(modules_dir):

        # تجاهل cache
        dirs[:] = [
            d for d in dirs
            if d != "__pycache__" and not d.startswith(".")
        ]

        for filename in files:

            if not filename.endswith(".py"):
                continue

            if filename == "__init__.py":
                continue

            if filename.startswith("_"):
                continue

            full_path = os.path.join(root, filename)
            found.append(full_path)

    return sorted(found)


def path_to_module_name(path):
    """
    modules/recon/detect.py
    ->
    modules.recon.detect
    """

    relative = os.path.relpath(path, BASE_DIR)

    parts = relative.split(os.sep)

    if parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]

    return ".".join(parts)


# ================================================================
# LOAD MODULES
# ================================================================

def load_all_modules():
    """
    تحميل جميع modules.

    يرجع عدد ملفات Python التي تم تحميلها بنجاح.
    """

    if not ensure_package_files():
        return 0

    importlib.invalidate_caches()

    try:
        import modules
    except Exception as exc:
        error(f"فشل تحميل package modules: {exc}")
        return 0

    files = discover_module_files()

    info(
        f"تم العثور على {len(files)} ملف Python داخل modules/"
    )

    loaded = 0
    failed = 0

    for file_path in files:

        module_name = path_to_module_name(file_path)

        try:
            importlib.import_module(module_name)

            loaded += 1

            print(
                c(
                    f"[+] Loaded: {module_name}",
                    "1;32"
                )
            )

        except Exception as exc:

            failed += 1

            print(
                c(
                    f"[!] فشل تحميل: {module_name}",
                    "1;31"
                )
            )

            print(
                f"    السبب: {exc}"
            )

            if os.environ.get("SF_DEBUG") == "1":
                traceback.print_exc()

    print()

    if failed:
        warning(
            f"تم تحميل {loaded} module وفشل {failed}"
        )
    else:
        success(
            f"تم تحميل {loaded} module"
        )

    return loaded


# ================================================================
# REGISTRY
# ================================================================

def registered_count():
    try:
        return len(registry.MODULES)
    except Exception:
        return 0


def categories_count():
    try:
        return len(registry.CATEGORIES)
    except Exception:
        return 0


# ================================================================
# PARSER
# ================================================================

def build_parser():

    parser = argparse.ArgumentParser(
        prog="shadowforge.py",
        description=(
            "ShadowForge — "
            "إطار اختبار أمان تطبيقات الويب"
        ),
        epilog=(
            "مثال: "
            "python3 shadowforge.py --all https://example.com"
        ),
        add_help=False
    )

    # ------------------------------------------------------------
    # Positional arguments
    # ------------------------------------------------------------

    parser.add_argument(
        "module",
        nargs="?",
        help="اسم الوحدة"
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="الهدف"
    )

    # ------------------------------------------------------------
    # Main options
    # ------------------------------------------------------------

    parser.add_argument(
        "--list",
        action="store_true",
        help="عرض جميع الوحدات"
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="تشغيل الفحص الشامل"
    )

    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="القائمة التفاعلية"
    )

    # ------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------

    parser.add_argument(
        "--proxy",
        default=None,
        help="HTTP proxy"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="مهلة HTTP"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="عدد threads"
    )

    # ------------------------------------------------------------
    # Other options
    # ------------------------------------------------------------

    parser.add_argument(
        "--wordlist",
        default=None,
        help="Wordlist"
    )

    parser.add_argument(
        "--passlist",
        default=None,
        help="Password list"
    )

    parser.add_argument(
        "--user",
        default=None,
        help="Username"
    )

    parser.add_argument(
        "--login-url",
        default=None,
        help="Login URL"
    )

    parser.add_argument(
        "--token",
        default=None,
        help="API/JWT token"
    )

    parser.add_argument(
        "--callback",
        default=None,
        help="Callback URL"
    )

    parser.add_argument(
        "--out",
        default="report",
        help="اسم التقرير"
    )

    # ------------------------------------------------------------
    # UI / Debug
    # ------------------------------------------------------------

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="تعطيل الألوان"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="إظهار تفاصيل الأخطاء"
    )

    parser.add_argument(
        "-h",
        "--help",
        action="store_true",
        help="عرض المساعدة"
    )

    return parser


# ================================================================
# SHOW LIST
# ================================================================

def show_list():

    modules = registry.MODULES
    categories = registry.CATEGORIES

    print()
    print(c("=" * 72, "1;36"))

    print(
        c(
            f"  وحدات ShadowForge — "
            f"{len(modules)} وحدة في {len(categories)} فئات",
            "1;36"
        )
    )

    print(c("=" * 72, "1;36"))

    total = 0

    for category, names in categories.items():

        print()
        print(
            c(
                f"[{category}] ({len(names)})",
                "1;33"
            )
        )

        for name in names:

            total += 1

            try:
                description = modules[name][1]
            except Exception:
                description = "بدون وصف"

            print(
                f"  {c(name, '1;32'):<25} "
                f"{description}"
            )

    print()
    print(c("=" * 72, "1;36"))

    print(
        c(
            f"  الإجمالي: {total} وحدة",
            "1;36"
        )
    )

    print(
        c(
            "  الاستخدام:",
            "1;37"
        )
    )

    print(
        c(
            "  python3 shadowforge.py <module> <target>",
            "1;37"
        )
    )

    print(c("=" * 72, "1;36"))
    print()


# ================================================================
# RUN ONE MODULE
# ================================================================

def run_module(
    name,
    target,
    args,
    silent=False
):

    modules = registry.MODULES

    if name not in modules:

        close = difflib.get_close_matches(
            name,
            modules.keys(),
            n=3,
            cutoff=0.35
        )

        error(
            f"الوحدة غير موجودة: {name}"
        )

        if close:
            print(
                f"[*] ربما تقصد: {', '.join(close)}"
            )
        else:
            print(
                "[*] استعمل: "
                "python3 shadowforge.py --list"
            )

        return None

    try:

        category, description, function = modules[name]

    except Exception as exc:

        error(
            f"تعريف الوحدة {name} غير صالح: {exc}"
        )

        return None

    if not silent:

        print()

        print(
            c(
                f"▶ Module: {name}",
                "1;35"
            )
        )

        print(
            c(
                f"  Category: {category}",
                "1;35"
            )
        )

        print(
            c(
                f"  Description: {description}",
                "1;35"
            )
        )

        print(
            c(
                f"  Target: {target}",
                "1;35"
            )
        )

        print(
            c(
                "─" * 60,
                "1;35"
            )
        )

    try:

        result = R(target)

    except Exception as exc:

        error(
            f"تعذر إنشاء R object: {exc}"
        )

        return None

    start = time.time()

    try:

        function(
            target,
            args,
            result
        )

    except KeyboardInterrupt:

        print()
        warning(
            "تم إيقاف الوحدة يدوياً."
        )

    except Exception as exc:

        error(
            f"خطأ داخل {name}: {exc}"
        )

        if os.environ.get("SF_DEBUG") == "1":
            traceback.print_exc()

    elapsed = time.time() - start

    # ضمان وجود الحقول
    if not hasattr(result, "finds"):
        result.finds = []

    if not hasattr(result, "lines"):
        result.lines = []

    if not silent:

        print(
            c(
                "─" * 60,
                "1;35"
            )
        )

        print(
            c(
                f"انتهت الوحدة {name} "
                f"خلال {elapsed:.2f}s",
                "1;36"
            )
        )

        print(
            c(
                f"النتائج: {len(result.finds)}",
                "1;36"
            )
        )

    return result


# ================================================================
# RUN ALL
# ================================================================

def run_all(target, args):

    print()
    print(c("█" * 72, "1;31"))

    print(
        c(
            "  SHADOWFORGE — ALL SUITE",
            "1;31"
        )
    )

    print(
        c(
            f"  الهدف: {target}",
            "1;31"
        )
    )

    print(
        c(
            f"  الوحدات المطلوبة: {len(ALL_SUITE)}",
            "1;31"
        )
    )

    print(c("█" * 72, "1;31"))

    available = [
        name
        for name in ALL_SUITE
        if name in registry.MODULES
    ]

    missing = [
        name
        for name in ALL_SUITE
        if name not in registry.MODULES
    ]

    print()

    success(
        f"الوحدات المتاحة للفحص: {len(available)}"
    )

    if missing:

        warning(
            f"وحدات غير مسجلة: {len(missing)}"
        )

    all_finds = []
    all_lines = []

    for index, name in enumerate(
        available,
        1
    ):

        print()

        print(
            c(
                f"[{index}/{len(available)}] {name}",
                "1;33"
            )
        )

        result = run_module(
            name,
            target,
            args,
            silent=True
        )

        if result is None:
            continue

        try:
            all_finds.extend(
                result.finds
            )
        except Exception:
            pass

        try:
            all_lines.extend(
                result.lines
            )
        except Exception:
            pass

    # ============================================================
    # REPORT
    # ============================================================

    if "report" in registry.MODULES:

        try:

            report_function = (
                registry.MODULES["report"][2]
            )

            final_result = R(target)

            final_result.finds = all_finds
            final_result.lines = all_lines

            report_function(
                target,
                args,
                final_result
            )

            success(
                "تم إنشاء التقرير."
            )

        except Exception as exc:

            error(
                f"تعذر إنشاء التقرير: {exc}"
            )

            if os.environ.get("SF_DEBUG") == "1":
                traceback.print_exc()

    else:

        warning(
            "Module report غير مسجل."
        )

    print()
    print(c("█" * 72, "1;31"))

    print(
        c(
            f"اكتمل الفحص — "
            f"عدد النتائج: {len(all_finds)}",
            "1;31"
        )
    )

    print(c("█" * 72, "1;31"))
    print()


# ================================================================
# INTERACTIVE
# ================================================================

def interactive(args):

    while True:

        print()
        print(c("─" * 55, "1;36"))

        print(
            c(
                "  ShadowForge — Interactive",
                "1;36"
            )
        )

        print(c("─" * 55, "1;36"))

        print(
            c(
                "  0) ALL SUITE",
                "1;33"
            )
        )

        flat = []
        index = 0

        for category in registry.CATEGORIES:

            print(
                c(
                    f"\n  [{category}]",
                    "1;35"
                )
            )

            for name in registry.CATEGORIES[category]:

                index += 1

                flat.append(name)

                description = (
                    registry.MODULES[name][1]
                )

                print(
                    f"  {index:>3}) "
                    f"{name:<22} "
                    f"{description}"
                )

        exit_number = index + 1

        print(
            c(
                f"\n  {exit_number}) خروج",
                "1;31"
            )
        )

        try:

            choice = input(
                c(
                    "\nاختر رقم الوحدة أو الاسم: ",
                    "1;36"
                )
            ).strip()

        except (
            KeyboardInterrupt,
            EOFError
        ):

            print()
            return

        if not choice:
            continue

        # --------------------------------------------------------
        # ALL
        # --------------------------------------------------------

        if choice == "0":

            target = input(
                c(
                    "أدخل الهدف: ",
                    "1;36"
                )
            ).strip()

            if target:

                run_all(
                    norm_target(target),
                    args
                )

            continue

        # --------------------------------------------------------
        # EXIT
        # --------------------------------------------------------

        if choice.lower() in (
            "q",
            "quit",
            "exit",
            str(exit_number)
        ):

            return

        # --------------------------------------------------------
        # NAME
        # --------------------------------------------------------

        if choice in registry.MODULES:

            target = input(
                c(
                    f"أدخل الهدف لـ {choice}: ",
                    "1;36"
                )
            ).strip()

            if not target:

                warning(
                    "لم يتم إدخال target."
                )

                continue

            run_module(
                choice,
                norm_target(target),
                args
            )

            continue

        # --------------------------------------------------------
        # NUMBER
        # --------------------------------------------------------

        try:

            number = int(choice)

            if 1 <= number <= len(flat):

                name = flat[number - 1]

                target = input(
                    c(
                        f"أدخل الهدف لـ {name}: ",
                        "1;36"
                    )
                ).strip()

                if not target:

                    warning(
                        "لم يتم إدخال target."
                    )

                    continue

                run_module(
                    name,
                    norm_target(target),
                    args
                )

                continue

        except ValueError:
            pass

        error(
            "اختيار غير صالح."
        )


# ================================================================
# PROXY
# ================================================================

def configure_proxy(proxy):

    if not proxy:
        return

    try:

        from core import http as sfhttp

        if hasattr(sfhttp, "set_proxy"):

            sfhttp.set_proxy(proxy)

            info(
                f"البروكسي مفعّل: {proxy}"
            )

        else:

            warning(
                "core.http لا يحتوي set_proxy()."
            )

    except Exception as exc:

        warning(
            f"تعذر ضبط البروكسي: {exc}"
        )


# ================================================================
# TARGET RESOLUTION
# ================================================================

def resolve_all_target(args):
    """
    إصلاح المشكلة الأساسية:

    الأمر:

        python3 shadowforge.py --all https://example.com

    يجعل argparse يضع الرابط في args.module
    لأن module هو positional argument الأول.

    لذلك نستخدم:
        args.target
    أو:
        args.module
    """

    if args.target:
        return args.target

    if args.module:
        return args.module

    return None


# ================================================================
# MAIN
# ================================================================

def main():

    parser = build_parser()

    args = parser.parse_args()

    # ------------------------------------------------------------
    # Environment
    # ------------------------------------------------------------

    if args.no_color:
        os.environ["SF_NO_COLOR"] = "1"

    if args.debug:
        os.environ["SF_DEBUG"] = "1"

    # ------------------------------------------------------------
    # Load modules
    # ------------------------------------------------------------

    loaded = load_all_modules()

    registered = registered_count()
    categories = categories_count()

    print()

    print(
        c(
            BANNER.format(
                v=VERSION,
                n=registered
            ),
            "1;36"
        )
    )

    print(
        c(
            f"[*] Python files discovered : {loaded}",
            "1;36"
        )
    )

    print(
        c(
            f"[*] Registered modules      : {registered}",
            "1;32"
        )
    )

    print(
        c(
            f"[*] Categories              : {categories}",
            "1;32"
        )
    )

    # ------------------------------------------------------------
    # Proxy
    # ------------------------------------------------------------

    configure_proxy(args.proxy)

    # ------------------------------------------------------------
    # Help
    # ------------------------------------------------------------

    if args.help or len(sys.argv) == 1:

        parser.print_help()

        print()

        print(
            "[*] عرض الوحدات:"
        )

        print(
            "    python3 shadowforge.py --list"
        )

        return

    # ------------------------------------------------------------
    # LIST
    # ------------------------------------------------------------

    if args.list:

        show_list()
        return

    # ------------------------------------------------------------
    # INTERACTIVE
    # ------------------------------------------------------------

    if args.interactive:

        interactive(args)
        return

    # ------------------------------------------------------------
    # ALL
    # ------------------------------------------------------------

    if args.all:

        target_value = resolve_all_target(args)

        if not target_value:

            error(
                "--all يتطلب target."
            )

            print(
                "الصيغة الصحيحة:"
            )

            print(
                "python3 shadowforge.py "
                "--all https://example.com"
            )

            return

        # إذا كان عندنا positional target ثاني
        # فلا مشكلة.
        target = norm_target(
            target_value
        )

        run_all(
            target,
            args
        )

        return

    # ------------------------------------------------------------
    # SINGLE MODULE
    # ------------------------------------------------------------

    if args.module:

        # إذا args.module عبارة عن URL بدون module
        if (
            args.module.startswith("http://")
            or args.module.startswith("https://")
        ):

            error(
                "يبدو أنك أدخلت URL بدون اسم module."
            )

            print(
                "مثال:"
            )

            print(
                "python3 shadowforge.py "
                "headers https://example.com"
            )

            return

        target = (
            norm_target(args.target)
            if args.target
            else "http://target.invalid"
        )

        run_module(
            args.module,
            target,
            args
        )

        return

    # ------------------------------------------------------------
    # FALLBACK
    # ------------------------------------------------------------

    parser.print_help()


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print()
        warning(
            "تم الإيقاف بواسطة المستخدم."
        )

        sys.exit(130)

    except Exception as exc:

        error(
            f"خطأ غير متوقع: {exc}"
        )

        if os.environ.get("SF_DEBUG") == "1":
            traceback.print_exc()

        sys.exit(1)
