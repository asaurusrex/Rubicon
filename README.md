# Rubicon - a New Custom Encryption Algorithm/Tool

## Disclaimer
DO NOT use this project for purposes other than legitimate red teaming/pentesting jobs, or research.  DO NOT use this for illegal activity of any kind, and know that this project is intended for research purposes and to help advance the missions of both red and blue teams.  

## Purpose 
Rubicon is designed to provide a barebones custom encryption algorithm (which I encourage you to further customize!) which will be crafted into C++ payloads for you! That's right, you won't have to write any C++ (but you will need to compile it), but you will benefit from your shellcode being custom encrypted in unmanaged code.  It is a basic stream cipher which is implemented as, fundamentally, a Caesar cipher.  It is NOT meant to be cryptographically secure, but to prevent automated detection/analysis from detecting malicious payloads. It calls NO crypto libraries when decrypted (except python does call the library secrets, but that isn't inherently for crypto as opposed to randomness), which is a big plus to avoiding automated detection. 

## Requirements
Python3 (only tested with Python3.9+), and some associated Python libraries - pip3 should take care of any python dependencies you need.

## Usage

### Encryption
The encryption functionality is built into custom_crypto_encrypt.py.  Its usage is as follows:

```
usage: custom_crypto_encrypt.py [-h] [-path PATH] [-o OUTPUT] [-len_key LENGTH_OF_KEY] [-compile_file COMPILE_FILE] [-split_shellcode SPLIT_SHELLCODE]

Generate encryption for shellcode.

optional arguments:
  -h, --help            show this help message and exit
  -path PATH            Provide the path to the .bin file which contains your shellcode.
  -o OUTPUT             Provide the path where you want your encrypted .bin to be placed.
  -len_key LENGTH_OF_KEY
                        Provide a positive integer that will be the length of the key in bytes. Longer keys will take longer to encrypt/decrypt
  -compile_file COMPILE_FILE
                        Provide the path to the C++ file you want to edit.
  -split_shellcode SPLIT_SHELLCODE
                        Provide a positive integer that will be the number of times to split the encrypted shellcode, so that it works properly with Visual Studio strings for c++
                        compilation.
```
The code will also generate a C++ file which you can readily compile with no changes with your favorite C++ compiler, in the file custom_decrypt.cpp.  The simplest example:

```
python3 custom_crypto.py -path my_plain_shellcode.bin
```

This will compile the C++ file for you with default options for key length and split_shellcode, and will also create an encrypted .bin file under "encrypted.bin."

### Decryption
**WARNING: I know custom_decrypt.cpp looks like it has a lot of empty space, but that is intentional! DO NOT remove the extra space between sections, it is designed to make sure python never overwrites anything important!**

The C++ code, once compiled, will handle decryption for you.  It locally injects with a very basic set of Win32 APIs, I recommend you change this method for real operations.

The Python decryptor code is contained in custom_crypto_decrypt.py.  The usage looks like:
```
usage: custom_crypto_decrypt.py [-h] [-path PATH] [-o OUTPUT] [-key KEY]

Decryption for shellcode.

optional arguments:
  -h, --help  show this help message and exit
  -path PATH  Provide the path to the .bin file which contains your decrypted shellcode.
  -o OUTPUT   Provide the path where you want your decrypted .bin to be placed.
  -key KEY    Provide the key needed to decrypt. This should be a byte array. Example: -key b"\xa0"
  ```

  This script is not QUITE finished, in that one annoying feature remains - you need to hard code the key in the script itself (your command line input will not matter.  I have had trouble figuring out how to get python to accept byte arrays as command line arguments, so if someone knows how to do this, please let me know).  So in line 155 of the script, copy and paste your key as a BYTE ARRAY (b"" format). Other than that, it is as simple as:

  ```
  python3 custom_crypto_decrypt.py -path my_encrypted.bin -key doesnotmatter
  ```

  This will decrypt your binary and place it in your directory as "decrypted.bin" by default.  Future ideas include adding an execution element to the python script so that it is more portable across different OS's, but at the moment that is not a feature (with a little work you could make python execute the decrypted shellcode, however).

## Opsec Concerns
I wouldn't recommend using this project in its default form for operations.  There are numerous optimizations and tricks that can be added to buff of the difficulty of analyzing this algorithm and solutions in memory.  Some ideas include: add randomized bytes so that your encrypted shellcode size != size of your original shellcode as it currently does by default, which I consider a weakness.  I may tweak this in the public version with an idea soon, but have not decided as of yet. Randomized bytes will also make it harder to guess shifting patterns to try to manually decrypt the data without the key, making that MUCH more difficult to correctly do.  I would also not recommend including the bytes of your payload or the bytes of your key directly in the payload as done here, as it makes it easier to RE - instead consider fetching them from somewhere, such as a server you control, so that if you suspect your payload is compromised you can remove access to these things, making actual RE much more difficult if not impossible. The shellcode injection technique is the most basic there is, using CreateThread, VirtualAlloc, and VirtualProtect, so please change that to something less obvious.  There are other generic tricks to prevent automated analysis that you could also employ, but that would be a project in and of itself so I will not elaborate further here - there are numerous resources/ideas in other crypters and blog posts.  


## Detection/Prevention
This is hard.  The base form can be detected by simply trying all byte value shifts from 0-255 on the first 4 bytes and checking if the MZ header exists (with the exact same shift mind you), but if other customizations are added this detection fails.  Looking for byte entropy and also looking at the weakness of Caesar cipher (trying to find a common byte value in suspected payloads and shifting from that assumption) MIGHT work, but it depends on the shellcode and actual shellcode optimizations, so definitely not guaranteed. 

## Testing 
This technique has tested against Windows Defender on the latest x64 version of Windows, with internet/cloud enabled and bypassed detection with basic meterpreter x64 https stageless payloads.  

## Basic Methodology
The version included here is very barebones, and is conceptually quite simple (I will show a simple example below of it in action).  Rubicon will generate a key of random bytes (which you can specify to be between 15-50 bytes long, although the default is 16), which will be used to encrypt the data.  We will calculate the total of the integer values of these bytes between 0-255, although 0 and 255 specifically will never be allowed to be bytes in the key - you will see why in a minute. Once we have the total, we will use it to divide the total size of our shellcode (.bin file) into "key total" sized sections - aka if our total value of bytes from the key was 50, we will have sections 50 bytes long of our original shellcode.  Each section will then be encrypted by a different byte of the key - the first section by the first byte, the second section by the second byte, etc.  If there are more sections than there are bytes in the key, then we will use modulus operations to return to the appropriate index of the key; as an example, if we had 17 sections but only a 15 byte key, the 16th section would be encrypted by the first byte of the key, and the 17th section would be encrypted by the 2nd byte of the key.

When I say "encrypted" by a byte in the key, I actually mean shifted.  So if our original shellcode byte was \x00, and our key byte was \x03, then our encrypted byte = 0 + 3 = \x03.  Each byte in the section we are encrypting will be shifted over to the right by the same amount. If we escape the boundary of integer values of single bytes, we will simply shift into the lower values of bytes again.  As an example, if our original byte is \xfe (int value of 254) and our key byte is \x05 (int value of 5), our encrypted byte is: 254 + 5 = 259 -> shift back into the lower bytes by subtracting 256 -> 259-256 = 3 = \x03.  We repeat this for all original bytes until each section is encrypted with its appropriate key.  To retrieve our original shellcode, we simply subtract the key byte from the appropriate section bytes.  This decryption process happens entirely in memory, and so is not detected by most AV (I submitted several earlier prototypes to VT and got around 7-8/70-80 detections. I think that was more due to meterpreter behavior once connecting to our c2 as opposed to the encryption itself, and I was also using the most basic CreateThread example for shellcode injection).

I wrote the encryption python script to generate new keys each run, and also to build a ready-to-compile version in C++ for you in the file called "custom_decrypt.cpp."  Simply plug this into your compiler of choice (I only tested with Visual Studio but it should work with any C++ compiler). Python entirely builds this file for you, it should be copy+paste and compile.

I have also included a python decryption script as well as a script to measure your decrypted.bin with your original.bin just for debugging purposes. 

## Contributions/Comments/Criticisms
I am very open to receiving comments and to collaboration!  Hopefully this helps generate useful discussion around the topic of custom crypto, or provides researchers some new insights.  


