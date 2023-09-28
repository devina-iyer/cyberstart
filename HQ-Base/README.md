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
