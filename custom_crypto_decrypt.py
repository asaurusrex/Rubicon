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
import argparse
import sys


#this code is designed to read in a .bin file of shellcode, and decrypt it with our custom decryption
#this decryption will rely on shifting bytes to one of 256 positions, which we will shift depending on the unique key of 16 bytes

#first, read in the .bin file - might need to do this with chunks, not sure yet
def read_bin(filename):

    with open(filename, 'rb') as f:
        plain_shellcode = f.read()
        
    length_of_shellcode = len(plain_shellcode)

    return length_of_shellcode, plain_shellcode

def examine_key(key):
    
    print("Length of key is: ", len(key))
    print("Key is: ", key)
    #get bytes as integers, and add them up - we will decrypt the shellcode in "total" size chunks
    total = 0
    #make sure key is 
    for i in range(len(key)):
        total += int(key[i])

    print("total of key is: ", total)
    return total

def split_shellcode(shellcode, key_total_len):
    
    len_shellcode = len(shellcode) #measures the length of the shellcode
    

    list_of_shellcode_pieces = list() #empty list to capture divided shellcode pieces
    number_of_pieces = round(len_shellcode/key_total_len)

    for i in range(number_of_pieces):
        piece_length = key_total_len
        
    
        #special cases - first and last piece of the string
         

        if i == 0: #the first case

            first_piece = shellcode[:piece_length] #beginning to the end of the first piece
            
            list_of_shellcode_pieces.append(first_piece)

        if 0 < i < key_total_len-1:

            shellcode_piece = shellcode[(piece_length*(i)):(piece_length*(i+1))] # from end of x-1 piece to the end of x piece (e.g. end of
            #first piece to the end of the second piece, completing the second piece
            
            list_of_shellcode_pieces.append(shellcode_piece)
            
        if i == key_total_len - 1: #the last case
            final_piece = shellcode[(piece_length*(i)):] #length of the final piece
            
            list_of_shellcode_pieces.append(final_piece)
            
            
    #print("The full shellcode list:", list_of_shellcode_pieces)
    
    
    return list_of_shellcode_pieces #returns full list of shellcode, after it has been divided by the number of splits requested. 



def decrypt_shellcode(shellcode_list, key):
    decrypted_shellcode = b""
    #take piece from shellcode list, and decrypt it with a byte in the key
    number_of_pieces = len(shellcode_list)

    keylen = len(key) #number of bytes in the key

   
    for i in range(len(shellcode_list)): 
        if  i < keylen:
            piece = shellcode_list[i] #get a piece out of our list
            for byte in piece: #get each from that piece, and shift it - this should already convert bytes to ints for us
                new_byte = byte - key[i]
                
                if new_byte < 0: #exists outside of hex range, so need to move it back into range
                    new_byte = bytes([256 + new_byte])
                    decrypted_shellcode += new_byte

                else:
                    new_byte = bytes([new_byte])
                    decrypted_shellcode += new_byte

        else: #we need to do modular arithmetic here to get a new index for the keylen that does not exceed its length
            index = i % keylen
            piece = shellcode_list[i]
            for byte in piece:
                new_byte = byte - key[index]

                if new_byte < 0: #exists outside of hex range, so need to move it back into range
                    new_byte = bytes([256 + new_byte])
                    decrypted_shellcode += new_byte

                else:
                    new_byte = bytes([new_byte])
                    decrypted_shellcode += new_byte


    return decrypted_shellcode

def write_output(decrypted_shellcode, output_file):
    with open(output_file, 'wb') as f:
        f.write(decrypted_shellcode) #write the shellcode to the output file

    return True

def main(path, output, key):
    #hardcode key here
    key = b"\xde\xa2\x7e\xfc\xd8\x96\x03\x80\x3c\xa0\x2d\x94\xab\x5b\xba\x02\x3b\xb4\xdc\xd4\x57\xe1\xd2\x10\x23\x78\x13\x8e\xbd"
    len_shellcode, shellcode = read_bin(path)
    print("Total length of decrypted shellcode: ", len_shellcode)

    key_total = examine_key(key)
    print("Total from key bytes: ", key_total)

    shellcode_list =  split_shellcode(shellcode, key_total)
    number_of_pieces = len(shellcode_list)
    print("Created shellcode piece list, which has {} pieces".format(number_of_pieces))

    decrypted_shellcode = decrypt_shellcode(shellcode_list, key)
    print("Length of decrypted shellcode: ", len(decrypted_shellcode))

    write_output(decrypted_shellcode, output)
    print("Wrote decrypted shellcode to {}!".format(output))
    


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Decryption for shellcode.")
    parser.add_argument('-path', action='store', dest="path", default="", help="Provide the path to the .bin file which contains your decrypted shellcode.")
    parser.add_argument('-o', action='store', dest="output", default="decrypted.bin", help="Provide the path where you want your decrypted .bin to be placed.")
    parser.add_argument('-key', action='store', dest="key", default="", help="Provide the key needed to decrypt.  This should be a byte array. Example: -key b\"\\xa0")

    args = parser.parse_args()

    if str(args.path) == "":
        print("You have not supplied a .bin file to decrypt!  Please provide something such as: -path example.bin")
        parser.print_help()
        sys.exit()

    if args.key == "":
        print("You have not supplied a key to decrypt the shellcode.  This key is required.")
        parser.print_help()
        sys.exit()
    

        

    main(str(args.path), str(args.output), args.key)