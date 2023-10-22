#### Level 12
##### C01
Going through the log, I found the person that had sent the most emails.

##### C02
Had to change char[8] to char[13] because the command "take_pictures" has 13 characters.

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
