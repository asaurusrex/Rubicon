#!/usr/bin/python
import sys

filename1 = sys.argv[1]
filename2 = sys.argv[2]
filename3 = sys.argv[3]

with open(filename1, 'rb') as f:
    shellcode1 = f.read()

with open(filename2, 'rb') as f:
    shellcode2 = f.read()

with open(filename3, 'rb') as f:
    shellcode3 = f.read()

for i in range(len(shellcode1)):
    if shellcode1[i] != shellcode2[i]:
        print("There is a difference!")
        print("Shellcode1: ", shellcode1[i], "vs Shellcode2: ", shellcode2[i], "The encrypted byte is: ", shellcode3[i], "at position: ", i+1)
    
    # if 11182 < i < 11186:
    #     print("Shellcode1: ", shellcode1[i], "vs Shellcode2: ", shellcode2[i], "at position: ", i)