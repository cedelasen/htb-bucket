# Hack the box - Bucket

IP: 10.10.10.212

## Nmap
```
┌──(kali㉿kali)-[~/htb-bucket]
└─$ nmap -A 10.10.10.212 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-08 14:56 EST
Nmap scan report for 10.10.10.212
Host is up (0.044s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://bucket.htb/
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.09 seconds

```

## add bucket.htb to /etc/hosts
```
┌──(kali㉿kali)-[~/htb-bucket]
└─$ cat /etc/hosts                
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.215    academy.htb
10.10.10.215    dev-staging-01.academy.htb
10.10.10.216    laboratory.htb
10.10.10.216    git.laboratory.htb
127.0.0.1       gitlab.example.com
10.10.10.206    passage.htb
10.10.10.209    doctors.htb
10.10.10.212    bucket.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

## gobuster
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir --wordlist SecLists/Discovery/Web-Content/common.txt --url http://bucket.htb
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://bucket.htb
[+] Threads:        10
[+] Wordlist:       SecLists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/08 15:00:08 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/index.html (Status: 200)
/server-status (Status: 403)
===============================================================
2021/01/08 15:00:29 Finished
===============================================================

```

## static web page has reference to subdomain: s3.bucket.htb
![web page](./images/s3-bucket.png "web page")

s3 are AWS storage solutions, could be something similar imitating it

## add s3.bucket.htb to /etc/hosts
```
┌──(kali㉿kali)-[~/htb-bucket]
└─$ cat /etc/hosts                
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.215    academy.htb
10.10.10.215    dev-staging-01.academy.htb
10.10.10.216    laboratory.htb
10.10.10.216    git.laboratory.htb
127.0.0.1       gitlab.example.com
10.10.10.206    passage.htb
10.10.10.209    doctors.htb
10.10.10.212    bucket.htb
10.10.10.212    s3.bucket.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

### now images are loaded
![web page full loaded](./images/s3-bucket-vhost.png "web page full loaded")

## gobuster s3.bucket.htb
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir --wordlist SecLists/Discovery/Web-Content/common.txt --url http://s3.bucket.htb
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://s3.bucket.htb
[+] Threads:        10
[+] Wordlist:       SecLists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/08 19:08:16 Starting gobuster
===============================================================
/health (Status: 200)
/server-status (Status: 403)
/shell (Status: 200)
===============================================================
2021/01/08 19:09:06 Finished
===============================================================

```

```
┌──(kali㉿kali)-[~]
└─$ curl http://s3.bucket.htb:80/shell -v
*   Trying 10.10.10.212:80...
* Connected to s3.bucket.htb (10.10.10.212) port 80 (#0)
> GET /shell HTTP/1.1
> Host: s3.bucket.htb
> User-Agent: curl/7.72.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 
< Date: Sat, 09 Jan 2021 00:18:12 GMT
< Server: hypercorn-h11
< content-type: text/html; charset=utf-8
< content-length: 0
< refresh: 0; url=http://444af250749d:4566/shell/
< access-control-allow-origin: *
< access-control-allow-methods: HEAD,GET,PUT,POST,DELETE,OPTIONS,PATCH
< access-control-allow-headers: authorization,content-type,content-md5,cache-control,x-amz-content-sha256,x-amz-date,x-amz-security-token,x-amz-user-agent,x-amz-target,x-amz-acl,x-amz-version-id,x-localstack-target,x-amz-tagging
< access-control-expose-headers: x-amz-version-id
< 
* Connection #0 to host s3.bucket.htb left intact

```

## 444af250749d to /etc/hosts
```
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts                                
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.215    academy.htb
10.10.10.215    dev-staging-01.academy.htb
10.10.10.216    laboratory.htb
10.10.10.216    git.laboratory.htb
127.0.0.1       gitlab.example.com
10.10.10.206    passage.htb
10.10.10.209    doctors.htb
10.10.10.212    bucket.htb
10.10.10.212    s3.bucket.htb
10.10.10.212    444af250749d

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

```

## gobuster s3.bucket.htb/shell
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir --wordlist SecLists/Discovery/Web-Content/common.txt --url http://s3.bucket.htb/shell      130 ⨯
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://s3.bucket.htb/shell
[+] Threads:        10
[+] Wordlist:       SecLists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/08 19:14:58 Starting gobuster
===============================================================
/css (Status: 200)
/index.html (Status: 200)
/img (Status: 200)
/images (Status: 200)
/lib (Status: 200)
/src (Status: 200)
===============================================================
2021/01/08 19:18:51 Finished
===============================================================

```

