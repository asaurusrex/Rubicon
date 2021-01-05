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
#TODO add c++ compilation file, byte randomization at beginning
import argparse
import sys
import secrets

#this code is designed to read in a .bin file of shellcode, and encrypt it with our custom encryption
#this encryption will rely on shifting bytes to one of 256 positions, which we will shift depending on the unique key of 16 bytes

#first, read in the .bin file - might need to do this with chunks, not sure yet
def read_bin(filename):

    with open(filename, 'rb') as f:
        plain_shellcode = f.read()
        
    length_of_shellcode = len(plain_shellcode)

    return length_of_shellcode, plain_shellcode

def gen_key(length_of_key):
    key = secrets.token_bytes(length_of_key) #generate x random bytes
    bad_byte = False

    if b"\xff" or b"\x00" in key: #we need to move the bytes by at least 1
        bad_byte = True
    
    while(bad_byte == True): #make sure \xff is not in key, or it will shift byte back to itself
        key = secrets.token_bytes(length_of_key) #generate x random bytes
        bad_byte = False

        if b"\xff" in key:
            bad_byte = True

    hex_key = ""
    for i in range(len(key)):
        if len(hex(key[i])) == 3:
            byte = hex(key[i])
            byte = byte.replace("0x", "\\x0")
            hex_key += byte
        else:

            hex_key += hex(key[i])
    
    hex_key = hex_key.replace("0x", "\\x")

    
    print("Successfully generated key: ", hex_key, "\n", key)

    #get bytes as integers, and add them up - we will encrypt the shellcode in "total" size chunks
    total = 0
    #make sure key is 
    for i in range(len(key)):
        integer = int(key[i])
        total += integer

    print("Total length of each section is approximately: {}".format(total))
    return key, total, hex_key

def create_shellcode_sections(shellcode, key_total_len):
    
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



def encrypt_shellcode(shellcode_list, key):
    encrypted_shellcode = b""
    #take piece from shellcode list, and encrypt it with a byte in the key
    number_of_pieces = len(shellcode_list)

    keylen = len(key) #number of bytes in the key

    for i in range(len(shellcode_list)): 
        if  i < keylen:
            piece = shellcode_list[i] #get a piece out of our list
            for byte in piece: #get each byte from that piece, and shift it - this should already convert bytes to ints for us
                new_byte = byte + key[i]
                
                if new_byte > 255: #exists outside of hex range, so need to move it back into range
                    new_byte = bytes([new_byte - 256])
                    encrypted_shellcode += new_byte

                else:
                    new_byte = bytes([new_byte])
                    encrypted_shellcode += new_byte

        else: #we need to do modular arithmetic here to get a new index for the keylen that does not exceed its length
            index = i % keylen
            piece = shellcode_list[i]
            for byte in piece:
                new_byte = byte + key[index]

                if new_byte > 255: #exists outside of hex range, so need to move it back into range
                    new_byte = bytes([new_byte - 256])
                    encrypted_shellcode += new_byte

                else:
                    new_byte = bytes([new_byte])
                    encrypted_shellcode += new_byte    

    
    return encrypted_shellcode

def write_encrypted_output(encrypted_shellcode, output_file):
    with open(output_file, 'wb') as f:
        f.write(encrypted_shellcode) #write the shellcode to the output file

    return True

#every function below for c++ code file generation

def cleanup_cpp_file(compile_file): #cleanup file for next compilation round
    with open(compile_file, 'r+') as f:
        lines = f.readlines()
        for i in range(len(lines)):
            if "unsigned char string_" in lines[i]:
                lines[i] = "\n"

            if "memcpy(string" in lines[i]:
                lines[i] = "\n"
            
            if "std::vector<unsigned char> section_" in lines[i]:
                lines[i] = "\n"
            
            if "std::copy(" in lines[i]:
                lines[i] = "\n"
            
    with open(compile_file, 'w') as f:
        f.writelines(lines)
        f.close()
            
    return 

def split_shellcode(shellcode, split_number):

    length_of_shellcode = len(shellcode) #measures the length of the shellcode
    print("The length of the shellcode in bytes is:", length_of_shellcode)

    list_of_shellcode_pieces = list() #empty list to capture divided shellcode pieces

    piece_length = round(length_of_shellcode/split_number)
    
    for i in range(split_number):
        #special cases - first and last piece of the string
        
        if i == 0: #the first case

            first_shellcode_piece = shellcode[:piece_length] #beginning to the end of the first piece
            list_of_shellcode_pieces.append(first_shellcode_piece)

        if 0 < i < split_number-1:

            shellcode_piece = shellcode[(piece_length*(i)):(piece_length*(i+1))] # from end of x-1 piece to the end of x piece 
            list_of_shellcode_pieces.append(shellcode_piece)
            
        if i == split_number - 1: #the last case
            final_shellcode_piece = shellcode[(piece_length*(i)):] #length of the final piece
            list_of_shellcode_pieces.append(final_shellcode_piece)      
                
    print("\nEach piece is approximately {} bytes".format(piece_length))
    print("There are {} pieces".format(split_number))
    
    return list_of_shellcode_pieces  

def write_compile_file(shellcode_list, compile_file, shellcode_total_length, key, key_total, number_sections):
    
    with open(compile_file, 'r+') as f:
        lines = f.readlines()
        for i in range(len(lines)):

            if "NEED TO PLACE KEY TOTAL HERE" in lines[i]:
                lines[i+1] = "unsigned char decrypted_code[{}];\n".format(key_total)

            if "Place key here" in lines[i]:
                lines[i+1] = "unsigned char key[] = \"{}\";\n".format(key)

            if "place encrypted byte pieces here" in lines[i]:

                for index in range(len(shellcode_list)):
                    shellcode_list[index] = '\\x'.join(format(x, '02x') for x in shellcode_list[index])
                    shellcode_list[index] = "\\x" + shellcode_list[index] #add \x to beginning of each element, since previous line does not do this
                    shellcode_list[index] = shellcode_list[index].replace(" ", "") #remove any spaces if they exist
                    lines[i+1+index] = "unsigned char string_{0}[] = \"{1}\";\n".format(index, shellcode_list[index])
                    
            if "place memcpy operations here" in lines[i]:
                lines[i+1] = "unsigned char string[{}];\n".format(shellcode_total_length)
                mem_length = 0 #how much space we need to move over to continue allocating in memory
                for x in range(len(shellcode_list)):
                    length_piece = round(len(shellcode_list[x])/4) 
                    if x != 0:
                        length_previous_piece = round(len(shellcode_list[x-1])/4) 
                        if x == 1:
                            mem_length = length_previous_piece
                            lines[i+3] = "memcpy(string + {0}, string_{1}, {2});\n".format(mem_length, x, length_piece)
                            
                        else:
                            mem_length += length_previous_piece
                            lines[i+2+x] = "memcpy(string + {0}, string_{1}, {2});\n".format(mem_length, x, length_piece)
                    else:
                        lines[i+2]= "memcpy(string, string_0, {});\n".format(length_piece)
                        
            if "place byte count here" in lines[i]: #manually put in length multiple times to avoid defining a var for it in c++ code
                lines[i+1] = "std::vector<unsigned char> bytes(string, string + {});\n".format(shellcode_total_length)
                
            if "place number of sections here" in lines[i]:
                lines[i+1] = "int number_sections = {};\n".format(number_sections)

            if "place vector operations here" in lines[i]: #TODO START HERE WHEN YOU RESUME
                #first measure big the final piece of code to be decrypted will be
                final_section_size = shellcode_total_length % key_total
                    
                if final_section_size == 0:
                    final_section_size = key_total
                
                print("There are {} sections".format(number_sections))

                #define values for the next for loop
                previous_section_size = key_total
                section_size = key_total

                for x in range(number_sections):
                    key_index = x % len(key)
                    if x != 0: 
                        if x == 1:
                            section_size += key_total
                            lines[i+3] = "std::vector<unsigned char> section_{0} = std::vector<unsigned char>(bytes.begin() + {1}, bytes.begin() + {2});\n".format(x, key_total, section_size)
                            lines[i+4] = "std::vector<unsigned char> section_1_decrypted = DecryptBytes(section_1, key[1], 1, {}, sizeof(key));\n".format(key_total)
                            
                        elif x == number_sections-1: #final piece
                            section_size += final_section_size
                            previous_section_size += key_total
                            lines[i+(x*2)+1] = "std::vector<unsigned char> section_{0} = std::vector<unsigned char>(bytes.begin() + {2}, bytes.begin() + {3});\n".format(x, final_section_size, previous_section_size, section_size)
                            lines[i+(x*2)+2] = "std::vector<unsigned char> section_{0}_decrypted = DecryptBytes(section_{0}, key[{2}], {0}, {1}, sizeof(key));\n".format(x, final_section_size, key_index)
                            
                        else:
                            section_size += key_total
                            previous_section_size += key_total
                            lines[i+(x*2)+1] = "std::vector<unsigned char> section_{0} = std::vector<unsigned char>(bytes.begin() + {2}, bytes.begin() + {3});\n".format(x, key_total, previous_section_size, section_size)
                            lines[i+(x*2)+2] = "std::vector<unsigned char> section_{0}_decrypted = DecryptBytes(section_{0}, key[{2}], {0}, {1}, sizeof(key));\n".format(x, key_total, key_index)
                            

                    else: 
                        lines[i+1] = "std::vector<unsigned char> section_{0} = std::vector<unsigned char>(bytes.begin(), bytes.begin() + {1});\n".format(x, key_total)
                        lines[i+2] = "std::vector<unsigned char> section_0_decrypted = DecryptBytes(section_0, key[0], 0, {}, sizeof(key));\n".format(key_total)
                        

            if "place copy operations here" in lines[i]:

                #vector appending/copying piece
                for x in range(number_sections):
                    if x != 0:
                        lines[i+x+1] = "std::copy(section_{0}_decrypted.begin(), section_{0}_decrypted.end(), std::back_inserter(code_decrypted));\n".format(x)
                        
                    else:
                        lines[i+1] = "std::vector<unsigned char> code_decrypted(section_0_decrypted);\n"
                
            if "place size here" in lines[i]:
                lines[i+1] = "\tSIZE_T size = {};\n".format(shellcode_total_length)
    
    #write lines to file
    with open(compile_file, 'w+') as f:
        f.writelines(lines)
        f.close()

    return
    

def main(path, output, keylen, cpp_compile_file, split_number):

    len_shellcode, shellcode = read_bin(path)
    print("Total length of shellcode: ", len_shellcode)

    key, key_total, hex_key = gen_key(keylen)
    print("Total from key bytes: ", key_total)

    shellcode_list =  create_shellcode_sections(shellcode, key_total)
    number_of_sections = len(shellcode_list)
    print("Created shellcode piece list, which has {} pieces".format(number_of_sections))

    encrypted_shellcode = encrypt_shellcode(shellcode_list, key)
    print("Length of encrypted shellcode: ", len(encrypted_shellcode))
    
    if len(encrypted_shellcode)!= len_shellcode:
        main(path, output, keylen, cpp_compile_file, split_number)
        sys.exit()

    else:
        write_encrypted_output(encrypted_shellcode, output)
        print("Wrote encrypted shellcode to {}!".format(output))
        

    #generate the cpp compile_file

    list_of_pieces = split_shellcode(encrypted_shellcode, split_number)
    print("Cleaning up {}...".format(cpp_compile_file))
    cleanup_cpp_file(cpp_compile_file)
    print("Finished cleaning up {}.".format(cpp_compile_file))

    print("Crafting {}...".format(cpp_compile_file))
    length_encrypted_shellcode = len(encrypted_shellcode)
    write_compile_file(list_of_pieces, cpp_compile_file, length_encrypted_shellcode, hex_key, key_total, number_of_sections)
    print("Finished up! Check out {} for compilation".format(cpp_compile_file))

    
    


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate encryption for shellcode.")
    parser.add_argument('-path', action='store', dest="path", default="", help="Provide the path to the .bin file which contains your shellcode.")
    parser.add_argument('-o', action='store', dest="output", default="encrypted.bin", help="Provide the path where you want your encrypted .bin to be placed.")
    parser.add_argument('-len_key', action='store', dest="length_of_key", default=16, help="Provide a positive integer that will be the length of the key in bytes. Longer keys will take longer to encrypt/decrypt")
    parser.add_argument('-compile_file', action='store', dest="compile_file", default="custom_decrypt.cpp", help="Provide the path to the C++ file you want to edit.")
    parser.add_argument('-split_shellcode', action='store', dest="split_shellcode", default=20, help="Provide a positive integer that will be the number of times to split the encrypted shellcode, so that it works properly with Visual Studio strings for c++ compilation.")
    args = parser.parse_args()

    if str(args.path) == "":
        print("You have not supplied a .bin file to encrypt!  Please provide something such as: -path example.bin")
        parser.print_help()
        sys.exit()

    if int(args.length_of_key) < 0:
        print("You cannot supply a negative key length, choose a positive integer.  The default is 16.")
        parser.print_help()
        sys.exit()

    elif int(args.length_of_key) > 50:
        print("You cannot supply a key length longer than 50 bytes")
        parser.print_help()
        sys.exit()
    
    if int(args.split_shellcode) < 0:
        print("You cannot supply a split length for shellcode, choose a positive integer.  The default is 20.")
        parser.print_help()
        sys.exit()
        

    main(str(args.path), str(args.output), int(args.length_of_key), str(args.compile_file), int(args.split_shellcode))