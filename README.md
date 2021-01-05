# Rubicon - a New Custom Encryption Algorithm/Tool

## Disclaimer
DO NOT use this project for purposes other than legitimate red teaming/pentesting jobs, or research.  DO NOT use this for illegal activity of any kind, and know that this project is intended for research purposes and to help advance the missions of both red and blue teams.  

## Purpose 
This project is designed to provide a barebones custom encryption algorithm (which I encourage you to further customize!) called Rubicon.  It is a basic stream cipher which is implemented as, fundamentally, a Caesar cipher.  It is NOT meant to be cryptographically secure, but to prevent automated detection/analysis from detecting malicious payloads.  

## Basic Methodology
The version included here is very barebones, and is conceptually quite simple (I will show a simple example below of it in action).  Rubicon will generate a key of random bytes (which you can specify to be between 15-50 bytes long, although the default is 16), which will be used to encrypt the data.  We will calculate the total of the integer values of these bytes between 0-255, although 0 and 255 specifically will never be allowed to be bytes in the key - you will see why in a minute. Once we have the total, we will use it to divide the total size of our shellcode (.bin file) into "key total" sized sections - aka if our total value of bytes from the key was 50, we will have sections 50 bytes long of our original shellcode.  Each section will then be encrypted by a different byte of the key - the first section by the first byte, the second section by the second byte, etc.  If there are more sections than there are bytes in the key, then we will use modulus operations to return to the appropriate index of the key; as an example, if we had 17 sections but only a 15 byte key, the 16th section would be encrypted by the first byte of the key, and the 17th section would be encrypted by the 2nd byte of the key.

When I say "encrypted" by a byte in the key, I actually mean shifted.  So if our original shellcode byte was \x00, and our key byte was \x03, then our encrypted byte = 0 + 3 = \x03.  Each byte in the section we are encrypting will be shifted over to the right by the same amount. If we escape the boundary of integer values of single bytes, we will simply shift into the lower values of bytes again.  As an example, if our original byte is \xfe (int value of 254) and our key byte is \x05 (int value of 5), our encrypted byte is: 254 + 5 = 259 -> shift back into the lower bytes by subtracting 256 -> 259-256 = 3 = \x03.  We repeat this for all original bytes until each section is encrypted with its appropriate key.  To retrieve our original shellcode, we simply subtract the key byte from the appropriate section bytes.  This decryption process happens entirely in memory, and so is not detected by most AV (I submitted several earlier prototypes to VT and got around 7-8/70-80 detections. I think that was more due to meterpreter behavior once connecting to our c2 as opposed to the encryption itself, and I was also using the most basic CreateThread example for shellcode injection).

I wrote the encryption python script to generate new keys each run, and also to build a ready-to-compile version in C++ for you in the file called "custom_decrypt.cpp."  Simply plug this into your compiler of choice (I only tested with Visual Studio but it should work with any C++ compiler). Python entirely builds this file for you, it should be copy+paste and compile.

I have also included a python decryption script as well as a script to measure your decrypted.bin with your original.bin just for debugging purposes. 

## Requirements
Python3 (only tested with Python3.9+), and some associated Python libraries - pip3 should take care of any python dependencies you need.

## Opsec Concerns
I wouldn't recommend using this project in its default form for operations.  There are numerous optimizations and tricks that can be added to buff of the difficulty of analyzing this algorithm and solutions in memory.  Some ideas include: add randomized bytes so that your encrypted shellcode size != size of your original shellcode as it currently does by default, which I consider a weakness.  I may tweak this in the public version with an idea soon, but have not decided as of yet. Randomized bytes will also make it harder to guess shifting patterns to try to manually decrypt the data without the key, making that MUCH more difficult to correctly do.  I would also not recommend including the bytes of your payload or the bytes of your key directly in the payload as done here, as it makes it easier to RE - instead consider fetching them from somewhere, such as a server you control, so that if you suspect your payload is compromised you can remove access to these things, making actual RE much more difficult if not impossible. There are other generic tricks to prevent automated analysis that you could also employ, but that would be a project in and of itself so I will not elaborate further here - there are numerous resources/ideas in other crypters and blog posts.  


## Detection/Prevention
This is hard.  The base form can be detected by simply trying all byte value shifts from 0-255 on the first 4 bytes and checking if the MZ header exists, but if other customizations are added this detection fails.  Looking for byte entropy and also looking at the weakness of Caesar cipher (trying to find a common byte value in suspected payloads and shifting from that assumption) MIGHT work, but it depends on the shellcode and actual shellcode optimizations, so definitely not guaranteed. 

## Testing 
This technique has tested against Windows Defender on the latest x64 version of Windows, with internet/cloud enabled and bypassed detection with basic meterpreter x64 https stageless payloads.  

## Contributions/Comments/Criticisms
I am very open to receiving comments and to collaboration!  Hopefully this helps generate useful discussion around the topic of custom crypto, or provides researchers some new insights.  


