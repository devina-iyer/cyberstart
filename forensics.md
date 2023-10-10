#### Level 4
C02 - This challenge had a pcap file, which took me forever to figure out. the clue should have been that it was website related, the hint wasn't super helpful. I ended up going to File (in Wireshark), ---> Export Objects ---> HTTP, and there it was, an html page on evilthingshere.net. The url had a base64 cipher, which gave the flag.

#### Level 5
C03- in wireshark I entered the following filter:
ip.src==192.168.120.101 and tcp.flags.ack==0x12

to find the open ports.

#### Level 6

C01 - uploaded the image to hexed.it, and at the bottom in ascii was md5: ilovesteggivemetheflag. Converting it to md5 gave the hash c53fa35e5b2ed699ccc304088c3d9c8e, which I then uploaded with the image into Aperisolve. Steghide produced a txt file with a Base64 cipher, which I decrypted using Cyberchef. That gave the flag.

C02 - The image wouldn't load, so examining the hex data in hexed.it showed an incorrect JPEG header, which I corrected, and an extra 30 bytes, which I eliminated. The image then loaded and I could read the flag.

#### Level 7
C03- Uploaded the "empty" pdf to cyberchef and checked the strings. What seemed like decimal code stood out, so I copied it and put it into cyberchef and it revealed the flag.
