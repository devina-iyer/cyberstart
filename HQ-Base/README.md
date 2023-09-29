### Headquarters Base- Cyberstart

Here's a basic overview of how I got the solutions to the Cyberstart Challenges.

#### Level 1

C1 - noticed that his username contained 1986, his year of birth, giving away his age. Skills: Math, Observation.
C2 - were able to successfully spot that the email supposed to be from cloudnine bank had a misspelt domain name with two k's. Skills: Observation, Social Engineering
C3
C4
C5
C6
C7
C8
C9
C10
C11
C12

#### Level 8

W0088 - Konami code- type console.log() in console for it to listen, and then press the following keys: up, up, down, down, left, right, left, right, b, a. Flag was then revealed.

Hidra- 
first, crack the password with hydra:
$ hydra -l secure_user -P words.txt ftp://services.cyberprotection.agency -s 2121
yielded pw: mutineers
connect to ftp server:
ftp services.cyberprotection.agency 2121
after entering username and password, used ls to list files and "get FLAG.txt" to download the file.

#### Level 9 C06 - Mission Extension

connect to server via ssh, and find image files with the following:
$ find . -name '*' -exec file {} \; | grep -o -P '^.+: \w+ image'
Once I found the image, I had to exit the ssh connection to the server and establish an scp connection to download the file:

$ scp -P26041 9XtXpQhrht@54.229.163.112:./Contents/M5KDAN44 ~/

C11
Uploading the images to aperisolve showed that one had a zip file in it. Extracted it with binwalk -e, which yielded an ELF named "msg". Running it gave the flag. 

Level 9 C10: 
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

C05
enter the server, then:
$man -K matryoshka

apparently could have used apropos

C11 - extracted first image using binwalk -e, pw for zipfile was Vidanya_Das

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
