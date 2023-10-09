#### Level 4
C02 - This challenge had a pcap file, which took me forever to figure out. the clue should have been that it was website related, the hint wasn't super helpful. I ended up going to File (in Wireshark), ---> Export Objects ---> HTTP, and there it was, an html page on evilthingshere.net. The url had a base64 cipher, which gave the flag.

#### Level 5
C03- in wireshark I entered the following filter:
ip.src==192.168.120.101 and tcp.flags.ack==0x12

to find the open ports.
