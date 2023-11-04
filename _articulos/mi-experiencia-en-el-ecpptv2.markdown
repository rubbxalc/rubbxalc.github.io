---
layout: post
title: Mi experiencia en el eCPPTv2
date: 2023-08-26
description:
cover_id: 
fig-caption:
tags: []
---
___


# Certificado

<center><img src="/img/articulos/mi-experiencia-en-el-ecpptv2/ecpptv2.png" alt=""></center>

# Análisis e impresiones

Hace un tiempo me examiné de esta certificación de eLearnSecurity, a lo largo de este artículo explicaré si de verdad merece la pena y que tan complicada es. El proceso de evaluación consiste en un laboratorio con una serie de máquinas (tanto Linux como Windows), las cuales tienen diferentes segmentos y subredes, por lo que no todas tienen conectividad entre sí. El objetivo final es llegar al final de este "camino" y hacer un reporte, técnico y ejecutivo, poniendo en conocimiento las diferentes vulnerabilidades, nivel de criticidad y posibles remediaciones.

## Capacidades y conocimientos

Como dije anteriormente, existen subredes por lo que hay que aplicar **PIVOTING**, una técnica que consiste en crear una serie de túneles mediante los cuales conseguir alcance desde la propia máquina de atacante. Los haters utilizarán *Metasploit*, pero yo no lo recomiendo, ya que es una herramienta de "botón gordo" y no se tiene control sobre lo que está haciendo en caso de que algo no funcione. Yo utilicé *chisel*, se puede descargar desde su repo de [Github](https://github.com/jpillora/chisel), *socat* que viene instalado por defecto en las máquinas Linux y para las Windows su correspondiente, *netsh*. Teniendo experiencia en *Remote Port Forwarding* y *Dinamic Port Forwarding* no debería ser complicado de entender, y de hecho, la complejidad del examen reside en esto y la enumeración. El único problema que tuve fue encontrar una versión de *chisel* que se adaptase a la arquitectura de una de las máquinas del laboratorio, ya que es un error que nunca había tenido, pero con un poco de lógica se solventa.

El resto de habilidades necesarias, se resume a *Pentesting Web* muy básico, formas de escalar de privilegios y enumeración de archivos, versiones... además de un **BUFFER OVERFLOW**, el más básico, *Stack Based* y sin protecciones. Recomiendo la máquina **BrainPan**, que se puede obtener de forma gratuita desde la plataforma de [Vulnhub](https://www.vulnhub.com/entry/brainpan-1,51/), muy similar al del examen.

## Comienzo del examen

He de decir que yo tuve problemas con el archivo de configuración de la VPN que proporcionan, debido a la versión que usaba de VPN (la más actualizada de la fecha). Tuve que realizar bastantes búsquedas por Google hasta encontrar una solución. Si alguien tiene este problema, que añada el parámetro ``--data-ciphers AES-128-CBC:AES-128-GCM:CHACHA20-POLY1305`` al conectarse, esto fue lo que me lo solucionó. Perdí aproximadamente 1 hora y media de tiempo, pero no fue problema ya que el laboratorio lo terminé en unas 7 horas ese mismo día, y a la mañana siguiente hice el informe. El plazo máximo son 7 días de examen y otros 7 para entregar el reporte, pero no es necesario tanto tiempo. El soporte de eLearnSecurity me respondió a un correo que les envié acerca de mi error con la VPN, pero ya había terminado cuando terminé. Recomiendo realizar capturas y tomar apuntes mientras se va avanzando, simplifica y ayuda mucho a seguir un orden y a no dejarse nada sin documentar.

## Precio y valor en el mercado laboral

En mi caso, compré el voucher con una oferta por 300 dólares. Esto incluye dos intentos de examen y hasta 180 días para intentarlo. He visto bastantes ofertas en Linkedin que contemplan esta certificación como requisito recomendable, no imprescindible. Si que es reconocida, pero no tan valorada como puede ser un OSCP de Offensive Security, entre otras cosas porque el eCPPTv2 no es proctored, es decir, no está supervisada y se puede utilizar cualquier herramienta, mientras que en el OSCP se está más limitado y la dificultad es mayor.

## Opinión personal

Está bien como introductoria en el campo, pero en mi opinión no es imprescindible tenerla. Es preferible tener un Portfolio donde publicar writeups o crear otro tipo de contenido, demostrando que se dedica tiempo al campo, mostrando interés. El hecho de tener más certs no hace tener más conocimientos. De hecho una Ingeniería Informática tampoco hace un experto, pero aporta un extra que puede ser de utilidad. En ningún campo se puede saber todo, y menos en este que avanza tan rápido. Teniendo una base y una buena metodología, es posible llegar muy lejos.