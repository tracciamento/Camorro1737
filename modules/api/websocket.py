# websocket.py — اكتشاف WebSocket
import base64, os
from core.registry import module
from core.http import req

@module("websocket", "api", "اكتشاف WebSocket")
def run(base, a, R):
    key = base64.b64encode(os.urandom(16)).decode()
    for p in ["/ws", "/websocket", "/socket.io/", "/ws/chat", "/realtime",
              "/reverb", "/app", "/live", "/sockjs-node"]:
        st, h, _ = req(base + p, headers={
            "Connection": "Upgrade", "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": key})
        if st == 101:
            R.vuln(f"WebSocket مفتوح: {p} -> 101 Switching Protocols!")
        elif st in (200, 426, 400):
            R.info(f"{p} -> HTTP {st} (قد يكون WS محمي)")
    R.info("اختبر بعد الاتصال: فحص المصادقة، حقن الأوامر، قراءة رسائل المستخدمين الآخرين")
