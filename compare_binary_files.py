"""
BSD 4-Clause License

Copyright (c) 2020, asaurusrex
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
   
3. All advertising materials mentioning features or use of this software must display the following acknowledgement:
   This product includes software developed by AsaurusRex.

4. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

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