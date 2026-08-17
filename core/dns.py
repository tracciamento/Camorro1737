# dns.py — محلل DNS من الصفر (بدون مكتبات خارجية)
import random, socket, struct

def _enc_name(name):
    out = b""
    for lbl in name.rstrip(".").split("."):
        if lbl: out += bytes([len(lbl)]) + lbl.encode()
    return out + b"\x00"

def _resolver():
    try:
        for line in open("/etc/resolv.conf"):
            if line.startswith("nameserver"):
                return line.split()[1]
    except Exception: pass
    return "8.8.8.8"

def _parse_name(data, off):
    labels, jumped, end = [], False, off
    while True:
        l = data[off]
        if l & 0xC0 == 0xC0:
            if not jumped: end = off + 2
            off = ((l & 0x3F) << 8) | data[off+1]; jumped = True
        elif l == 0:
            if not jumped: end = off + 1
            break
        else:
            off += 1; labels.append(data[off:off+l].decode(errors="replace")); off += l
    return ".".join(labels), end

def _parse_dns(data, qtype):
    if len(data) < 12: return None
    rcode = struct.unpack_from(">H", data, 2)[0] & 0xF
    ancount = struct.unpack_from(">H", data, 6)[0]
    off = 12
    while True:
        if data[off] == 0: off += 1; break
        if data[off] & 0xC0 == 0xC0: off += 2; break
        off += 1 + data[off]
    off += 4
    ans = []
    for _ in range(ancount):
        name, off = _parse_name(data, off)
        rtype, rclass, ttl, rdlen = struct.unpack_from(">HHIH", data, off); off += 10
        rstart = off - rdlen
        if rtype == 1 and rdlen == 4:
            ans.append(("A", socket.inet_ntoa(data[rstart:rstart+4])))
        elif rtype == 28 and rdlen == 16:
            ans.append(("AAAA", socket.inet_ntop(socket.AF_INET6, data[rstart:rstart+16])))
        elif rtype == 5:
            cn, _ = _parse_name(data, rstart); ans.append(("CNAME", cn))
        elif rtype == 2:
            ns, _ = _parse_name(data, rstart); ans.append(("NS", ns))
        elif rtype == 15:
            pref = struct.unpack_from(">H", data, rstart)[0]
            mx, _ = _parse_name(data, rstart+2); ans.append(("MX", f"{pref} {mx}"))
        elif rtype == 16:
            p, txt = rstart, b""
            while p < rstart + rdlen:
                n = data[p]; p += 1; txt += data[p:p+n]; p += n
            ans.append(("TXT", txt.decode(errors="replace")))
    if rcode == 3: return "NXDOMAIN"
    return ans or None

def dns_query(name, qtype, server=None, timeout=3):
    try:
        tid = random.randint(0, 0xFFFF)
        q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + \
            _enc_name(name) + struct.pack(">HH", qtype, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(q, (server or _resolver(), 53))
        data, _ = s.recvfrom(4096); s.close()
        return _parse_dns(data, qtype)
    except Exception:
        return None

def axfr(domain, ns, timeout=4):
    try:
        tid = random.randint(0, 0xFFFF)
        q = struct.pack(">HHHHHH", tid, 0x0000, 1, 0, 0, 0) + \
            _enc_name(domain) + struct.pack(">HH", 252, 1)
        s = socket.create_connection((ns, 53), timeout)
        s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(q)) + q)
        ln = struct.unpack(">H", s.recv(2))[0]
        data = b""
        while len(data) < ln:
            chunk = s.recv(ln - len(data))
            if not chunk: break
            data += chunk
        s.close()
        return struct.unpack_from(">H", data, 6)[0] if len(data) >= 12 else 0
    except Exception:
        return None
