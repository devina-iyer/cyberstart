### Level 2
C01 - Zoom in on the image.

C02 - Uploaded the image to hexedit, found binary instead of hex in the bottom section. Decoding it gave the flag. 

C03 - downloaded hivexsh onto linux to analyze this registry file. Used the hashxsh tool to navigate through the hive (with ls and cd) and get to Microsoft\Windows\CurrentVersion\Run to see the malicious process, and used lsval to get the flag.

C04 - Looked through the evtx in xml and found the account name. 

C05 - downloaded and unzipped the memory dump in windows. Downloaded volatility, and ran

```
python vol.py -f memdump.mem windows.info.Info
```
#### Level 3

C01-C04 - These were fairly simple challenges.

C05 - The challenge was to find the suspicious process in the memory dump to find the flag, so I ran the following on windows command line:

```
python vol.py -f memdump.mem windows.pslist.PsList
```

Going through the list I found a process called 19hglski!hg which was the flag!
#### Level 4

C01 - Social Safari - I downloaded the files in windows, had to put them together into a zip file via the command line:
```
C:\Users\Me\Downloads\Hacked>copy /B hacked_laptop.z* output.zip
hacked_laptop.zip.001
hacked_laptop.zip.002
hacked_laptop.zip.003
        1 file(s) copied.
```
Change permissions:
```
C:\Users\Me\Downloads\Hacked>icacls "C:\Users\Me\Downloads\Hacked\output.zip" /GRANT *S-1-1-0:F
processed file: C:\Users\Me\Downloads\Hacked\output.zip
Successfully processed 1 files; Failed processing 0 files
```
that was the easy part. I spent SO MUCH TIME on this challenge, and it was just worth a couple of hundred points. I finally found the security.evtx file, and had to scroll through thousands but I found it!

C02 - This challenge had a pcap file, which took me forever to figure out. the clue should have been that it was website related, the hint wasn't super helpful. I ended up going to File (in Wireshark), ---> Export Objects ---> HTTP, and there it was, an html page on evilthingshere.net. The url had a base64 cipher, which gave the flag.

C03- The files for this challenge were the same as the first one on this level, and I think I found the files needed in the "Recent Documents" folder. I believe there was a password for a zip file, fairly easy to find. I ended up solving this before the first challenge.

C04 - Uploaded the image to Aperisolve and Steghide extracted the flag file.

C05 - Did a Keyword search in Autopsy for the word "flag" with 'Regular Expression' selected, and I got a few files in the results. Looking through them, I found what appeared to be the correct flag: Gr3p15th3friendyf1nd3r

#### Level 5
C01 - This was a picture, which I just uploaded to Aperisolve. Strings showed a password, so I ran it through again, this time giving Aperisolve the password to extract files using steghide. The file contained the flag.

C02 - this was a hard one. The hives zipped folder contained two registry files called SAM and SYSTEM. I had to extract the hashes from both of these into one file, and then run it against the provided password list with John the Ripper.

```
┌──(devina㉿kali)-[~]
└─$ creddump7 -h                                                                                       
creddump7 - Python tool to extract credentials and secrets from Windows registry hives
/usr/share/creddump7
├── __pycache__
├── cachedump.py
├── framework
├── lsadump.py
└── pwdump.py
┌──(devina㉿kali)-[/usr/share/creddump7]
└─$ cd /usr/share/creddump7

┌──(devina㉿kali)-[/usr/share/creddump7]
└─$ ./pwdump.py /home/devina/Downloads/SYSTEM /home/devina/Downloads/SAM > ~/Downloads/Hashes.txt

```
Navigate back to Downloads folder and execute the following:

```
┌──(devina㉿kali)-[~/Downloads]
└─$ john Hashes.txt -wordlist="words.txt"
Warning: detected hash type "LM", but the string is also recognized as "NT"
Use the "--format=NT" option to force loading these as that type instead
Using default input encoding: UTF-8
Using default target encoding: CP850
Loaded 1 password hash (LM [DES 256/256 AVX2])
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2023-10-14 17:18) 0g/s 91000p/s 91000c/s 91000C/s PIUS'S..RESTORA
Session completed. 

```
Redid it with the NT format:

```
┌──(devina㉿kali)-[~/Downloads]
└─$ john Hashes.txt -wordlist="words.txt" --format=NT                                                  
Using default input encoding: UTF-8
Loaded 3 password hashes with no different salts (NT [MD4 256/256 AVX2 8x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
D@rj33l1ng       (sshd_server)     
1g 0:00:00:00 DONE (2023-10-14 17:19) 100.0g/s 91000p/s 91000c/s 220400C/s Pius's..restoration's
Warning: passwords printed above might not be all those cracked
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
```
This also did the trick:

```
┌──(devina㉿kali)-[~/Downloads]
└─$ john --format=NT --show Hashes.txt                                                                   
sshd_server:D@rj33l1ng:1003:aad3b435b51404eeaad3b435b51404ee:8d0a16cfc061c3359db455d00ec27035:::
```
C03- in wireshark I entered the following filter:
ip.src==192.168.120.101 and tcp.flags.ack==0x12
to find the open ports.

C04- I think this was an Autopsy challenge - had to locate the file "coms.txt" in the Recycle Bin. Can't remember if I had to do anything else to get the flag, but it wasn't that challenging I don't think.

C05 - fixed the pcap on kali:
```
┌──(devina㉿kali)-[~/Downloads]
└─$ pcapfix -v Taipei\ malicious\ capture.pcapng
```
Filtered for http on the fixed file, and found the flag in the strings.


#### Level 6

C01 - uploaded the image to hexed.it, and at the bottom in ascii was md5: ilovesteggivemetheflag. Converting it to md5 gave the hash c53fa35e5b2ed699ccc304088c3d9c8e, which I then uploaded with the image into Aperisolve. Steghide produced a txt file with a Base64 cipher, which I decrypted using Cyberchef. That gave the flag.

C02 - The image wouldn't load, so examining the hex data in hexed.it showed an incorrect JPEG header, which I corrected, and an extra 30 bytes, which I eliminated. The image then loaded and I could read the flag.

C03 - Downloaded a pcapng file, found an .eml file that looked suspicious (with an attachment). It took me forever to figure out how to extract it, but I followed the tcp stream and found the right app to open up the .eml file, which allowed me to download and extract an ELF from the gzip. The email itself had a question to which I just googled the answer (1997). Ran the ELF on linux which prompted me for the answer. On inputing it, it spit out the flag which I had to decode from Base64.

C04 - I downloaded the files and opened it through Autopsy. I first stumbled on a zip file called "Mailcious Tools", which showed in the strings that it contained a file called ZmxhZw==.txt which was password protected. So I went looking for the password, which was fairly simple to find. Navigating to the documents folder belonging to the user "Bad", I saw a file called cGFzc3dvcmQ=.txt, which decrypts as "password.txt". It contained the password for extraction- 3xtract0r, so I exported the MaliciousTools.7z file and extracted it with a password, and voila! The flag file in it contained a hex string which I plugged into cyberchef for the flag: Flag is v0lat1l1ty_MFT_GAM30v3R

Turns out this was not the flag for this challenge, so I put it aside and looked again. I also realised that I was supposed to have used volatility to find that flag? Well, anyway. Back to the original challenge - the briefing said that the filename of one of the programs contained the flag. Sifting through the folders I came across an .exe file that looked like it was a Caesar Cipher, so decrypting it gave the flag "PREFETCHWIN".

C05 - Digging through the entire log, I saw that one part looked different and had a Base64 encoded string. Decoding it gave the flag. 

#### Level 7

C01- the briefing was to retrieve the hash of the admin account from the memory dump, so I ran the following on windows CLI:

```
C:\Users\Me\Downloads\volatility3-2.5.0\volatility3-2.5.0>python vol.py -f memdump.mem windows.hashdump.Hashdump
Volatility 3 Framework 2.5.0
Progress:  100.00               PDB scanning finished
User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        fc525c9683e8fe067095ba2ddc971889
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
IEUser  1001    aad3b435b51404eeaad3b435b51404ee        fc525c9683e8fe067095ba2ddc971889
sshd    1002    aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
sshd_server     1003    aad3b435b51404eeaad3b435b51404ee        8d0a16cfc061c3359db455d00ec27035
```

The second hex string for Administrator was the flag.

C02 - Opened this file through Autopsy as well, and looking through I found a zip file called GITS. Downloading it showed some files that I opened through notepad, and it had a link to a github account. The URL had the flag file. 

C03- Uploaded the "empty" pdf to cyberchef and checked the strings. What seemed like decimal code stood out, so I copied it and put it into cyberchef and it revealed the flag.

C04 - I opened the file in notepad and did a Control+F for the word "command" because the briefing said to find the command to get the flag. After a few clicks through I found a base64 encoded string, which gave the flag. The flag had "." between each letter, and it wouldn't work, so I had to take it out. 

C05 - I think I was supposed to use Mimikatz to do this, but I simply ran lsadump, because the briefing said to look for a plaintext password, and lsadump revealed secrets from memory?

```
C:\Users\Me\Downloads\volatility3-2.5.0\volatility3-2.5.0>python vol.py -f memdump.mem windows.lsadump.Lsadump
Volatility 3 Framework 2.5.0
Progress:  100.00               PDB scanning finished
Key     Secret  Hex

DefaultPassword ▲               M 1 m 1 K a t z _ 0 w n 1 n g           1e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4d 00 31 00 6d 00 31 00 4b 00 61 00 74 00 7a 00 5f 00 30 00 77 00 6e 00 31 00 6e 00 67 00 00 00
DPAPI_SYSTEM    ,               ☺   ´svBT yÉ)a▲`ñ{↑¬¶U-mHË/ä°¶mX.ã¶↓Ä♣H            2c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 b4 73 76 42 54 a0 79 c9 29 61 1e 60 f1 7b 18 ac 9f 91 9a 97 99 b6 55 2d 6d 48 cb 2f e4 b0 14 6d 58 2e e3 14 19 c4 05 48 00 00 00 00

```

#### Level 8
C01 - Had to go through a memory dump in volatility, but I have to use windows because there is not enough storage on my virtual linux system for the file.
First ran:
```
C:\Users\Me\Downloads\volatility3-2.5.0\volatility3-2.5.0>python vol.py -f 0801.mem windows.filescan.FileScan
```
Once I had the list, I spotted the .pst file I was looking for and copied its offset.
```
C:\Users\Me\Downloads\volatility3-2.5.0\volatility3-2.5.0>python vol.py -f 0801.mem -o "C:\Users\Me\Downloads" windows.dumpfiles.DumpFiles --physaddr 0x32d186d0
```
Uploading the pst file to an online viewer gave me all the info I needed to fill the report for the challenge. Had to check the "raw props" for a lot of info.

C02 - The given file was a pst file, so I uploaded it to an online pst viewer (Goldfynch), which showed that there was a "notes" file and a file in "deleted items". The one in the deleted folder was a zip, that probably contained the flag but it was password protected. The notes contained what seemed to be the password in Base64, but putting in the decoded password didn't work, so I tried putting in the encoded password and it worked!

C03 - There was a big chunk of what looked like Base64 encoding in the file. I put that into Cyberchef and had to sift through it for the answers.

C04 - This challenge had a pcap file, which when pulled up in Wireshark showed some weird TCP packets. Following the stream showed "WAV" in the ASCII data, so I converted it to raw and saved it, then uploaded it to Cyberchef, which recognized it as an audio file. The audio said that the flag was the word "wireshark" in MD5.

C05 - The flag for this turned out to be the red herring I found in L6C04!

