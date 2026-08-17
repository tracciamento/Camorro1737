# ports.py — فحص المنافذ
import socket, concurrent.futures
from core.registry import module
from core.wordlists import PORTS

@module("ports", "recon", "فحص المنافذ المفتوحة")
def run(base, a, R):
    host = __import__("urllib.parse").urlsplit(base).hostname
    thr = getattr(a, "threads", 10)
    def chk(p):
        try:
            with socket.create_connection((host, p), timeout=3): return p
        except Exception: return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=thr) as ex:
        open_ports = [p for p in ex.map(chk, PORTS) if p]
    if open_ports:
        R.vuln("منافذ مفتوحة: " + ", ".join(map(str, open_ports)))
        svc = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
               143:"IMAP",443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
               6379:"Redis",8080:"HTTP-alt",8443:"HTTPS-alt",9200:"Elasticsearch",
               27017:"MongoDB",6001:"Reverb/WS",1883:"MQTT",15672:"RabbitMQ"}
        for p in open_ports:
            if p in svc: R.info(f"  {p} -> {svc[p]}")
    else:
        R.good("لا منافذ إضافية مفتوحة")
