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
C02 - This challenge had a pcap file, which took me forever to figure out. the clue should have been that it was website related, the hint wasn't super helpful. I ended up going to File (in Wireshark), ---> Export Objects ---> HTTP, and there it was, an html page on evilthingshere.net. The url had a base64 cipher, which gave the flag.

C04 - Uploaded the image to Aperisolve and Steghide extracted the flag file.

#### Level 5
C01 - This was a picture, which I just uploaded to Aperisolve. Strings showed a password, so I ran it through again, this time giving Aperisolve the password to extract files using steghide. The file contained the flag.

C03- in wireshark I entered the following filter:
ip.src==192.168.120.101 and tcp.flags.ack==0x12
to find the open ports.

C04-

C05 - 


#### Level 6

C01 - uploaded the image to hexed.it, and at the bottom in ascii was md5: ilovesteggivemetheflag. Converting it to md5 gave the hash c53fa35e5b2ed699ccc304088c3d9c8e, which I then uploaded with the image into Aperisolve. Steghide produced a txt file with a Base64 cipher, which I decrypted using Cyberchef. That gave the flag.

C02 - The image wouldn't load, so examining the hex data in hexed.it showed an incorrect JPEG header, which I corrected, and an extra 30 bytes, which I eliminated. The image then loaded and I could read the flag.

C03 - Downloaded a pcapng file, found an .eml file that looked suspicious (with an attachment). It took me forever to figure out how to extract it, but I followed the tcp stream and found the right app to open up the .eml file, which allowed me to download and extract an ELF from the gzip. The email itself had a question to which I just googled the answer (1997). Ran the ELF on linux which prompted me for the answer. On inputing it, it spit out the flag which I had to decode from Base64.

C04 - I downloaded the files and opened it through Autopsy. I first stumbled on a zip file called "Mailcious" something, so I pursued that track, found a password to extract it and found the file with the flag in Base64. Turns out this was not the flag for this challenge, so I put it aside and looked again. The briefing sais that the filename of one of the programs contained the flag. Sifting through the folders I came across an .exe file that looked like it was a Caesar Cipher, so decrypting it gave the flag "PREFETCHWIN".

C05 - Digging through the entire log, I saw that one part looked different and had a Base64 encoded string. Decoding it gave the flag. 

#### Level 7
C02 - Opened this file through Autopsy as well, and looking through I found a zip file called GITS. Downloading it showed some files that I opened through notepad, and it had a link to a github account. The URL had the flag file. 

C03- Uploaded the "empty" pdf to cyberchef and checked the strings. What seemed like decimal code stood out, so I copied it and put it into cyberchef and it revealed the flag.

C04 - I opened the file in notepad and did a Control+F for the word "command" because the briefing said to find the command to get the flag. After a few clicks through I found a base64 encoded string, which gave the flag. The flag had "." between each letter, and it wouldn't work, so I had to take it out. 

#### Level 8

C02 - The given file was a pst file, so I uploaded it to an online pst viewer (Goldfynch), which showed that there was a "notes" file and a file in "deleted items". The one in the deleted folder was a zip, that probably contained the flag but it was password protected. The notes contained what seemed to be the password in Base64, but putting in the decoded password didn't work, so I tried putting in the encoded password and it worked!

C03 - There was a big chunk of what looked like Base64 encoding in the file. I put that into Cyberchef and had to sift through it for the answers.

C04 - This challenge had a pcap file, which when pulled up in Wireshark showed some weird TCP packets. Following the stream showed "WAV" in the ASCII data, so I converted it to raw and saved it, then uploaded it to Cyberchef, which recognized it as an audio file. The audio said that the flag was the word "wireshark" in MD5.

C05 - The flag for this turned out to be the red herring I found in L6C04!

