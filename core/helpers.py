# helpers.py — أدوات مساعدة مشتركة
import sys, time, urllib.parse, base64, html

def c(text, code):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

class R:
    def __init__(self, target):
        self.target = target; self.finds = []; self.lines = []
    def good(self, m):  self.lines.append(("info", m));  print(c("[*]", "1;36") + " " + m)
    def info(self, m):  self.lines.append(("info", m));  print(c("[*]", "1;36") + " " + m)
    def warn(self, m):  self.lines.append(("warn", m));  print(c("[!]", "1;33") + " " + m)
    def vuln(self, m):  self.finds.append(m); self.lines.append(("vuln", m))
                        print(c("[VULN]", "1;31") + " " + m)

def norm_target(t):
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    u = urllib.parse.urlsplit(t)
    return f"{u.scheme}://{u.netloc}"

def load_list(path):
    try:
        return [l.strip() for l in open(path, encoding="utf-8", errors="replace")
                if l.strip() and not l.startswith("#")]
    except Exception:
        sys.exit(f"[-] لا يمكن قراءة {path}")

def get_params(url):
    return [k for k, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)]

def b64e(b):  return base64.b64encode(b).decode()
def b64d(s):
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)
