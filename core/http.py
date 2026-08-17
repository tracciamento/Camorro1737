# http.py — عميل HTTP كامل + طلب خام (Raw) للحالات الخاصة
import http.client, ssl, urllib.parse, socket
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

def req(url, method="GET", data=None, headers=None, timeout=8,
        redirects=False, max_redir=3, proxy=None):
    u = urllib.parse.urlsplit(url)
    if proxy:
        pu = urllib.parse.urlsplit(proxy)
        conn = http.client.HTTPConnection(pu.hostname, pu.port, timeout=timeout)
        path = url
    elif u.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ctx)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity"}
    if headers: h.update(headers)
    try:
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse(); body = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        conn.close()
    except Exception:
        conn.close(); return 0, {}, b""
    if redirects and r.status in (301, 302, 303, 307, 308) and "location" in hdrs:
        return req(urllib.parse.urljoin(url, hdrs["location"]), method, data, headers,
                   timeout, redirects, max_redir - 1, proxy)
    return r.status, hdrs, body

def get(url, **kw):
    st, h, b = req(url, **kw)
    return st, h, b.decode("utf-8", "replace")

def raw_request(url, raw_extra=b"", timeout=8):
    """إرسال طلب HTTP خام عبر سوكيت (لـ CRLF و Smuggling)"""
    import ssl as _ssl
    u = urllib.parse.urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    s = socket.create_connection((u.hostname, port), timeout)
    if u.scheme == "https":
        ctx = _ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=u.hostname)
    s.settimeout(timeout)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    reql = (f"GET {path} HTTP/1.1\r\nHost: {u.hostname}\r\n"
            f"User-Agent: {UA}\r\nConnection: close\r\n").encode() + raw_extra
    s.sendall(reql)
    data = b""
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk: break
        data += chunk
    s.close()
    return data
