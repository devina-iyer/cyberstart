#### Level 13

##### C1

Change url:
https://jiaozi-restaurants.com/booking-form?venue=shanghai&seedID=0:0:0:0&name=a&date=a

solve the captcha and submit. Do the whole thing 5 times and you get the flag.

##### C2

After much trial and error, just press enter until it says "Welcome", then type "flag" and it outputs the flag.

##### C3
connected to the server on netcat, it gave some strange output. so I moved the output to a file, it turned out to be a gzip file. gunzip wouldn't work, so I used 7z, and even though there were some errors it ended up unzipping and the resulting file had the flag.

##### C4-
I'm pretty sure I didn't do this the way it was intended - we had to connect to a server and find a file - that was fairly obvious, the file was called "weird". It tried executing it, but it wanted the user to be called challenge011306. I downloaded it to my machine, and then created a user called challenge011306 and executed it there, but I think I was supposed to do some binary patching?

##### C05
The hint said to use a cyclic pattern tool for the binary exploit, so I first generated a pattern with an arbitrary length of 200:

$ msf-pattern_create -l 200

I ran the ELF within gdb and pasted the cyclic pattern, which resulted in a segmentation fault. I copied the memory address of the fault and found the offset with the msf-pattern_offset command (-q flag), and then executed the binary with a python print command to call the input at the given memory address of 0x80484b1.
4UPzOlkhlUBvY8bHikd


##### C6
Strings don't give anything useful, though catting the file reveals r4ndOmd4t4isfun444all. Had to scramble this a bit to get the flag right.

##### C7
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
Running the ELf outputted the flag! Compiling it in 32 bit was actually really important - without that it kept segfaulting.

##### C8
found the password list on the router site through $ (cat /etc/passwd)

Running it through hashcat: $ hashcat -m 500 -a 0 hash.txt rockyou.txt --show yielded: $1$gaiiqAXv$UykKlBl6vUsgBc.rUiFk80:topcat

##### C09- Encrypted
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
##### C10 - Connecting to the server gave this:
Pzmxizm bw jm kwvncaml!
(^_^)?
0n65 0n69 0n83
3840 / (22 - 7)
0j43 0j42 0j43
xrl=6875726E6763736E6F646B68796A737000000000000000000000000000000000
vi =6D617366666674766F726B6468797162
RZZ3BM6yfMWwrXG/RmLVQ7eYdlnsIMvlWjE4hOSiXRW4aKWVjbmMNWgLnFC6oIpu
The first few lines were easy enough to decrypt, but the first line was confusing, since rotating the letters gives "Hrepare to be confused!" and the tip they provided was "Decrypt all the things! Are you sure the first line is fully decrypted?". This was a very confusing tip, because it kept indicating that I had done it wrong, whereas the whole time the first letter not decrypting correctly was a clue to deselect the option to rotate upper characters for the final cipher on the last line.

Another trick was they rotated the letters for "key" and "iv", and I tried inputing the rotated numbers as well but had to use the numbers as given.

The last line, the cipher, went through multiple decryption layers: first, from ROT13 (lower case characters only), then from Base 64, then from AES, and lastly from Hex. Cyberchef was invaluable for this.

##### C11
There were a bunch of strings on the page- had to convert each one, find the one that converted to hexadecimal, enter the encoded (Base 64) version of it into the comment box, and then it outputed two strings that looked very similar, so I XORed them and that revealed the flag.

##### c12 - Trial by File
OK, this one took a long time to understand and get right. In the end, it was actually not more than a couple of steps. I first had to disable the ptrace, which kept kicking me out of gdb - I opened the file in a hexeditor and changed 75 to 74 on line 720:

from c4 10 83 f8 ff 75 1c 83 to c4 10 83 f8 ff 74 1c 83

I just found this method online, and it worked.

I then used gdb to disassemble the main function. I set a breakpoint at the call function before the one that prompted for the password, and jumped to the call function AFTER the password check, which revealed the flag.
