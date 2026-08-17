# بيانات اختيارية
ضع هنا قوائم مخصصة:
- `paths.txt`  -> --wordlist paths.txt (لوحدات dirs/admin/api)
- `passwords.txt` -> --passlist passwords.txt (للـ brute)
- `secrets.txt`  -> --wordlist secrets.txt (لكسر JWT)
- `targets.txt`  -> --wordlist targets.txt (لـ mass-scan)


# ShadowForge — Web Application Security Framework

إطار هجومي متكامل بـ **72 وحدة** في 8 فئات، متخصص بحماية **Laravel/PHP**،
يعمل على **Termux و Linux** بـ Python فقط (بدون أي مكتبات خارجية).

## التثبيت
```bash
chmod +x setup.sh && ./setup.sh

python3 shadowforge.py --list                    # عرض الوحدات
python3 shadowforge.py --all https://target.com  # الفحص الشامل + تقرير
python3 shadowforge.py laravel-any https://target.com
python3 shadowforge.py sqli "https://site.com/item?id=1"
python3 shadowforge.py brute https://site.com --user admin --login-url /login --passlist words.txt
python3 shadowforge.py ssrf https://site.com --callback http://10.0.0.5:8000
python3 shadowforge.py jwt https://site.com --token eyJ...
python3 shadowforge.py --interactive

python3 shadowforge.py --list        # يجب أن يعرض 72 وحدة
python3 shadowforge.py --all http://localhost:8000   # اختبره على تطبيق Laravel محلي
   # القائمة التفاعلية
أ	عيد الفصح	3
استطلاع	12	اكتشاف العناوين، والروبوتات، وملفات تعريف الارتباط، وجدار حماية تطبيقات الويب، والمنافذ، وبروتوكول TLS، ونظام أسماء النطاقات، والنطاقات الفرعية، والاستحواذ، ورقم النظام المستقل، ونظام إدارة المحتوى
لارافيل	14	env debug ignition telescope horizon sanctum reverb livewire serial-rce appkey artisan storage composer mass-assignment
الويب	18	SQLI، XSS، SSI، CMD، LFI، RFI، SSRF، إعادة التوجيه، CORS، CSRF، Clickjack، XXE، فك التسلسل، التحميل، اجتياز المسار، CRLF، رأس المضيف، Smuggler
المصادقة	8	هجوم اختراق JWT OAuth، جلسة OAuth، إعادة تعيين المصادقة الثنائية، هجوم ملفات تعريف الارتباط، المصادقة الأساسية
واجهة برمجة التطبيقات	6	واجهة برمجة التطبيقات GraphQL Swagger REST WebSocket IDO
سحاب	4	بيانات تعريف S3 Azure GCP
الحمولة	5	xss-polyglot sqli-payload cmd-payload webshell encode
الأدوات المساعدة	5	تقرير زحف استخراج وكيل مسح جماعي
