
# coding: utf-8

#           PROGRAM: Triple DES with Keying option 1 and blocking mode ECB, CBC and OFB and padding method PKCS5
#                Input from USER:
#                  1. Password: Should not be null 
#                  2. Message: Minimum of 1 character and maximum of 16 characters
#                     This is done to show all possible combinations and to demonstrate each blocking mode and padding scheme
#                  3. Choice of blocking mode, 1 for ECB, 2 for CBC and 3 for OFB
#                  4. Choice for decryption required, 1 if yes, otherwise, 2 if no
#                  
#                 Output:
#                   Encrypted/Decrypted message in ASCII format
#   
#   
#                   
#                 
# 
# 

# In[1]:

#!/usr/bin/env python3
"""
                                 keyGen Function
            It will generate the round keys for triple DES encryption/Decryption
            input:
               pwd --> A variable length password, minimum of length 1, passed as an argument
            output:
               key1, key2, key3 --> lists of 16 keys, each key is of 48 bit length
               
            Algorithm:
            
             1. Generate a SHA224 hash in binary format from the input password
             2. Create key[0],key[1],key[2] from the hashed password, each a 64 bit length unique bit string
             3. Define keyRound function and pass above created key list to it
                      
                      1. Apply permutation, PC1 on it --> 56 bit string
                      2. Divide above permuted, 56 bit length string into two equal halves, C0, D0
                      3. For i from 1 to 16:
                          1. Shift both C0, D0 according to LSHIFT_MAP, save shifted C0, D0 as C and D
                          2. Create s = C+D
                          3. Apply permutation PC2 on it --> 48 bit string
                          4. Save key in K[i]
                      4. Return K which is list of 16 keys, each of 48 bit length
                      
             4. Call keyRound function with each key[0],key[1],key[2] and save results in key1, key2, key3
             5. Return key1, key2, key3
               
"""
def keyGen(pwd = ''):
    # library to use SHA224
    import hashlib   
    
    # permutation choice PC1
    PC1 = [57,  49,  41,  33,  25,  17,   9,
        1,  58,  50,  42,  34,  26,  18,
       10,   2,  59,  51,  43,  35,  27,
       19,  11,   3,  60,  52,  44,  36,
       63,  55,  47,  39,  31,  23,  15,
        7,  62,  54,  46,  38,  30,  22,
       14,   6,  61,  53,  45,  37,  29,
       21,  13,   5,  28,  20,  12,   4]
    
    # permutation choice PC2
    PC2 = [14,  17,   11,    24,     1,    5,
        3,  28,   15,     6,    21,   10,
       23,  19,   12,     4,    26,    8,
       16,  7,   27,    20,    13,    2,
       41,  52,   31,    37,    47,   55,
       30,  40,   51,    45,    33,   48,
       44,  49,   39,    56,    34,   53,
       46,  42,   50,    36,    29,   32]
    
    # number of left rotations for permuted bit string 
    LSHIFT_MAP = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    #create hash digest of 224 length
    hashpwd = hashlib.sha224(pwd.encode()).digest()
    
    #convert hashed password in binary 
    pwdlst = ''.join('{0:08b}'.format(x, 'b') for x in bytearray(hashpwd))
    
    key = [[-1]*64]*3
    key[0] = pwdlst[:64]
    
    key[1] = pwdlst[64:128]
    
    key[2] = pwdlst[128:192]
    
    
    #Function to create 16 round keys
    def keyRound(ini_key = [-1]*64):
        new_pwd = [-1]*56
        
        #apply PC1 and generate 56 bit string
        for i in range(0,len(PC1)):
            temp = ini_key[PC1[i]-1]
            new_pwd[i] = temp
            
        # Split into Left and Right sections
        C0 = new_pwd[:28]
        D0 = new_pwd[28:]
        K = [[-1]*48]*16
        C = [-1]*28
        D = [-1]*28
        for i in range(0,16):
            new_key = [-1]*48
            
            #apply lft shifts
            for j in range(0,LSHIFT_MAP[i]):
                C = C0[1:]
                C.append(C0[0])
                D = D0[1:]
                D.append(D0[0])
                C0 = C
                D0 = D
            shift_k = C+D
            s = list(shift_k)
            
            #apply permutation PC2 and generate 48 bit length string
            for k in range(0,len(PC2)):
                temp = s[PC2[k]-1]
                new_key[k] = temp
            K[i] = new_key
        return K
    
    key1 = [[-1]*48]*16
    key2 = [[-1]*48]*16
    key3 = [[-1]*48]*16
    key1 = keyRound(key[0])
    key2 = keyRound(key[1])
    key3 = keyRound(key[2])
    return key1,key2,key3


"""
                                       DES ENCRYPTION/DECRYPTION
                    Perform DES encryption and decryption 
                    Input:
                       msg --> plaintext to be encrypted in the form of list
                       __mode --> can have any one value: encrypt/decrypt
                       K --> list of 16 round keys, each of 48 bit length
                    Output:
                       ciphertext --> Encrypted/Decrypted binary string
                    Algorithm:
                       1. Apply initial permuation IP on msg --> 64 bit length output
                       2. Divide permuted msg into equal halves, L,R
                       3. Create L, R as follows:
                          for k from 1 to 16
                            1. tempR = R
                            2. Expand R from 32 bits to 48 bits using expansion table E
                            if __mode == 'encrypt'
                            3. Calculate S = XOR K[k] and expanded R 
                            if __mode == 'decrypt'
                            3. Calculate S = XOR K[15-k] and expanded R 
                            4. divide S into blocks of length 6 each --> 8 such blocks
                            5. Apply S boxes SBoxes on each block
                            6. Add result of each Sbox subtitution, results into 32 bit string
                            7. Apply permutation P on S box output
                            8. Calculate R = XOR L and permuted output from above step
                            9. L = tempR
                      4. Calculate final = R+L
                      8. Apply inverse permutation IP_INVERSE on final
                      9. Return the permuted bit string
"""
# Permutation and translation tables for DES
IP = [58,  50,  42,  34,  26,  18,  10,   2,

      60,  52,  44,  36,  28,  20,  12,   4,

      62,  54,  46,  38,  30,  22,  14,   6,

      64,  56,  48,  40,  32,  24,  16,   8,

      57,  49,  41,  33,  25,  17,   9,   1,

      59,  51,  43,  35,  27,  19,  11,   3,

      61,  53,  45,  37,  29,  21,  13,   5,

      63,  55,  47,  39,  31,  23,  15,   7]

E = [32,   1,   2,   3,   4,   5,

      4,   5,   6,   7,   8,   9,

      8,   9,  10,  11,  12,  13,

     12,  13,  14,  15,  16,  17,

     16,  17,  18,  19,  20,  21,

     20,  21,  22,  23,  24,  25,

     24,  25,  26,  27,  28,  29,

     28,  29,  30,  31,  32,   1]

SBOXES = {0:

            [[14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],

             [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],

             [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],

             [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]],

          1:

            [[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],

             [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],

             [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],

             [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]],
          2:
          
          [[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],

             [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],

             [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],

             [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]],

          3:

            [[ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],

             [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],

             [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],

             [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]],

          4:

            [[ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],

             [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],

             [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],

             [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]],

          5:

            [[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],

             [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],

             [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],

             [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]],

          6:

            [[ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],

             [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],

             [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],

             [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]],

          7:

            [[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],

             [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],

             [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],

             [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]]}
P = [16,   7,  20,  21,

     29,  12,  28,  17,

      1,  15,  23,  26,

      5,  18,  31,  10,

      2,   8,  24,  14,

     32,  27,   3,   9,

     19,  13,  30,   6,

     22,  11,   4,  25]
IP_INVERSE = [40,   8,  48,  16,  56,  24,  64,  32,

              39,   7,  47,  15,  55,  23,  63,  31,

              38,   6,  46,  14,  54,  22,  62,  30,

              37,   5,  45,  13,  53,  21,  61,  29,

              36,   4,  44,  12,  52,  20,  60,  28,

              35,   3,  43,  11,  51,  19,  59,  27,

              34,   2,  42,  10,  50,  18,  58,  26,

              33,   1,  41,   9,  49,  17,  57,  25]

def des(msg = [-1]*64,__mode = '', K = [[-1]*48]*16):
    
    new_msg = [-1]*64
    
    # apply initial permutation IP
    for i in range(0,64):
        temp = msg[(IP[i])-1]
        new_msg[i] = temp
    #divide into equal halves
    L = new_msg[:32]
    R = new_msg[32:]

    row_no = 0
    col_no = 0

    for k in range(0,16):
        result = ''
    
        tempR = R[:]
        
    
        msg_ex = [-1]*48
        
        #apply expansion table E
        for j in range(0,len(E)):
            temp = R[E[j]-1]
            msg_ex[j] = temp
        
        if __mode == 'encrypt':
            
            S = [ord(a) ^ ord(b) for a,b in zip(msg_ex,K[k])]
        if __mode == 'decrypt':
            S = [ord(a) ^ ord(b) for a,b in zip(msg_ex,K[15-k])]
    
        B = [S[:6],S[6:12],S[12:18],S[18:24],S[24:30],S[30:36],S[36:42],S[42:]]
    
        # S Box implementation
        for l in range(0,8):
            row = [B[l][0],B[l][5]]
            column = B[l][1:5]
        
            row_no = ''.join(format(x, 'b') for x in bytearray(row))
            col_no = ''.join(format(x, 'b') for x in bytearray(column))
            row_no = int(row_no,2)
            col_no = int(col_no,2)
            res = SBOXES[l][row_no][col_no]
       
            result+= '{0:04b}'.format(res)
        
        result = list(result)
    
        RS = [-1]*32
        for o in range(0,len(P)):
            temp = result[P[o]-1]
            RS[o] = temp
    
    
    
        R = [str(ord(a) ^ ord(b)) for a,b in zip(L,RS)]
        L = tempR
    # calulate final string as R(16)+L(16)
    final = R+L

    cipher = [-1]*64

    #apply IP_INVERSE
    for p in range(0,len(IP_INVERSE)):
        temp = final[IP_INVERSE[p]-1]
        cipher[p] = temp

    ciphertext = ''
    for i in range(0,64):
        ciphertext = ciphertext + cipher[i]
    return ciphertext
   

# Function to convert binary string into string of ascii characters
def bit_to_ascii(message = ''):
    length = 8
    input_l = [message[i:i+length] for i in range(0,len(message),length)]
    input_c = [chr(int(c,base=2)) for c in input_l]
    asci = ''.join(input_c)
    return asci

# Function for applying triple DES encryption
# Uses keying option 1
def tripledes_encrypt(plain = [-1]*64,k1 = [[-1]*48]*16, k2 = [[-1]*48]*16, k3 = [[-1]*48]*16):
    
    result = des(plain,'encrypt',k1)
    result = des(result,'decrypt',k2)
    result = des(result,'encrypt',k3)
    return result

# Function for applying triple DES decryption
# Uses keying option 1
def tripledes_decrypt(encrypted = [-1]*64,k1 = [[-1]*48]*16, k2 = [[-1]*48]*16, k3 = [[-1]*48]*16):
    
    result = des(encrypted,'decrypt',k3)
    result = des(result,'encrypt',k2)
    result = des(result,'decrypt',k1)
    return result
    
"""
                               MODES OF ENCRYPTION/DECRYPTION
                        In the section below, we will be performing the following tasks:
                        1. Taking password and plaintext from user
                        2. Encrypting/Decrypting according to the blocking mode selected by user
                        3. Implementing ECB, CBC and OFB modes
                        4. Padding scheme PKCS#5
                        5. IV in CBC and OFB is generated by a string 'shivi@uw'
"""
nkey1 = [[-1]*48]*16
nkey2 = [[-1]*48]*16
nkey3 = [[-1]*48]*16
count = 1

while count == 1:
    pwd = input('Enter password: ')
    if len(pwd)!= 0:
        nkey1,nkey2,nkey3 = keyGen(pwd)
        count = 0
    else:
        print('Password length should be atleast one character!')
count1 = 1

bin_plaintext = ''
pad = 0
while count1 == 1:
    plaintext = input('Enter your message.\n Message length should not be more than 16 characters: ')
    if len(plaintext)<= 16 and len(plaintext)!= 0:
        
        bin_plaintext = ''.join('{0:08b}'.format(x, 'b') for x in bytearray(plaintext,'utf8'))
        
        no = (len(bin_plaintext))%64
        if no!= 0:
            pad = 64 - no
            pad = int(pad/8)
            
            bin_pad = '{0:08b}'.format(pad)
            
            for padding in range(0,pad):
                bin_plaintext+= bin_pad
            
        
        count1 = 0
    else:
        print('Message length should be atleast one character and not more than 16 characters!')

bin_plaintext = list(bin_plaintext)
no = int(len(bin_plaintext)/64)

block = []
if no == 1:
    block = [-1]*64
    block = bin_plaintext
    
if no == 2:
    block = [[-1]*64]*2
    block[0] = bin_plaintext[:64]
    block[1] = bin_plaintext[64:]

count2 = 1
while count2 == 1:
    mode = input('choose any one mode: ECB, CBC, OFB\n Enter 1 for ECB, 2 for CBC and 3 for OFB:  ')
    if mode == '1' or mode == '2' or mode == '3':
        count2 = 0
        if mode == '1':
            if no == 1:
                cipher_text = tripledes_encrypt(block,nkey1,nkey2,nkey3)
                ascii_string = bit_to_ascii(cipher_text)
                print('Encrypted message is : ', ascii_string)
                
                
                cx = 1
                while cx == 1:
                    choice = input('Do you want to decrypt it too??\n Enter 1 if yes, 2 if no: ')
                    if choice == '1':
                        cipher_text = list(cipher_text)
                        pad_text = tripledes_decrypt(cipher_text,nkey1,nkey2,nkey3)
                        length = 64-8*pad
                
                        message = pad_text[:length]
                        ascii_string = bit_to_ascii(message)
                        print('Decrypted message is : ', ascii_string)
                        cx = 0
                    
                    elif choice == '2':
                        print('Thank You!')
                        cx = 0
                    else:
                        print('Improper Input')
            if no == 2:
                
                ECB_cipher = [[-1]*64]*2
                encrypted = ''
                for i in range(0,2):
                    ECB_cipher[i] = tripledes_encrypt(block[i],nkey1,nkey2,nkey3)
                    encrypted+= bit_to_ascii(ECB_cipher[i])
                print('Encrypted message is: ', encrypted )
                
                cx = 1
                decrypted = ''
                while cx == 1:
                    choice = input('Would you like to decrypt it too?\n Enter 1 if yes, 2 if no: ')
                    if choice == '1':
                        for i in range(0,2):
                            cipher_text = list(ECB_cipher[i])
                            
                            if i == 0:
                                unpad_text = tripledes_decrypt(cipher_text,nkey1,nkey2,nkey3)
                                asci = bit_to_ascii(unpad_text)
                                decrypted = asci
                            if i == 1:
                                pad_text = tripledes_decrypt(cipher_text,nkey1,nkey2,nkey3)
                                length = 64-8*pad
                                message = pad_text[:length]
                                asci = bit_to_ascii(message)
                                decrypted+= asci
                        print('Decrypted message is: ',decrypted)
                        cx = 0
                    elif choice == '2':
                        print('Thank You!')
                        cx = 0
                    else:
                        print('Improper Input\n Enter either 1 or 2')
                                
                            
                        
                        
            
        if mode == '2':
            IV = list(''.join('{0:08b}'.format(x, 'b') for x in bytearray('shivi@uw','utf8')))
            if no == 1:
                CBC_msg = [str(ord(a) ^ ord(b)) for a,b in zip(block,IV)]
                cipher_text = tripledes_encrypt(CBC_msg,nkey1,nkey2,nkey3)
                ascii_string = bit_to_ascii(cipher_text)
                print('Encrypted message is: ',ascii_string)
                cx = 1
                while cx == 1:
                    choice = input('Would you like to decrypt it too??\n Enter 1 if yes, 2 if no: ')
                
                    if choice == '1':
                        cipher_text = list(cipher_text)
                        pad_text = tripledes_decrypt(cipher_text,nkey1,nkey2,nkey3)
                        pad_text = [str(ord(a) ^ ord(b)) for a,b in zip(pad_text,IV)]
                        length = 64-8*pad
                        pad_str = ''
                        for w in range(0,len(pad_text)):
                            pad_str+= pad_text[w]
                        message = pad_str[:length]
                        ascii_string = bit_to_ascii(message)
                        print('Decrypted message is: ',ascii_string)
                        cx = 0
                    elif choice == '2':
                        print('Thank You!')
                        cx = 0
                    else:
                        print('Improper Input')
                
            if no == 2:
                encrypted = ''
                CBC_cipher = [[-1]*64]*2
                for rounds in range(0,2):
                    
                    CBC_msg = [str(ord(a) ^ ord(b)) for a,b in zip(block[rounds],IV)]
                    temp = tripledes_encrypt(CBC_msg,nkey1,nkey2,nkey3)
                    encrypted+= bit_to_ascii(temp)
                    CBC_cipher[rounds] = list(temp)
                    IV = CBC_cipher[rounds]    
                print('Encrypted message is: ', encrypted)
            
                
                decrypted = ''
                cx = 1
                while cx == 1:
                    choice = input('Would you like to decrypt it too?\n Enter 1 if yes, 2 if no: ')
                    IV = list(''.join('{0:08b}'.format(x, 'b') for x in bytearray('shivi@uw','utf8')))
                    if choice == '1':
                    
                        CBC_plain = [[-1]*64]*2
                    
                        for i in range(0,2):
                            pad_str = ''
                        
                            temp = tripledes_decrypt(CBC_cipher[i],nkey1,nkey2,nkey3)
                            CBC_plain[i] = list(temp)
                        
                            if i == 0:
                            
                                unpad_text = [str(ord(a) ^ ord(b)) for a,b in zip(CBC_plain[i],IV)]
                                for w in range(0,64):
                                    pad_str+= unpad_text[w]
                                asci = bit_to_ascii(pad_str)
                                decrypted = asci
                           
                                IV = CBC_cipher[i]
                            if i == 1:
                            
                                pad_text = [str(ord(a) ^ ord(b)) for a,b in zip(CBC_plain[i],IV)]
                                length = 64-8*pad
                            
                                for w in range(0,64):
                                    pad_str+= pad_text[w]
                        
                                message = pad_str[:length]
                                asci = bit_to_ascii(message)
                                decrypted+= asci
                        print('Decrypted message is: ',decrypted)        
                        cx = 0
                    elif choice == '2':
                        print('Thank You!')
                        cx = 0
                    else:
                        print('Improper Input')
                    
        if mode == '3':
            IV = list(''.join('{0:08b}'.format(x, 'b') for x in bytearray('shivi@uw','utf8')))
            if no == 1:
                cipher_t = tripledes_encrypt(IV,nkey1,nkey2,nkey3)
                cipher_text = [str(ord(a) ^ ord(b)) for a,b in zip(cipher_t,block)]
                bit_string = ''
                for i in range(0,64):
                    bit_string+= cipher_text[i]
                encrypt_msg = bit_to_ascii(bit_string)
                print('Encrypted message is: ',encrypt_msg)
                cx = 1
                while cx == 1:
                    choice = input('Would you like to decrypt it too??\n Enter 1 if yes, 2 if no: ')
                
                    if choice == '1':
                        cipher_text = list(cipher_text)
                        pad_text = tripledes_encrypt(IV,nkey1,nkey2,nkey3)
                        pad_text = [str(ord(a) ^ ord(b)) for a,b in zip(pad_text,cipher_text)]
                        length = 64-8*pad
                        pad_str = ''
                        for w in range(0,len(pad_text)):
                            pad_str+= pad_text[w]
                        message = pad_str[:length]
                        asci = bit_to_ascii(message)
                        print('Decrypted message is: ',asci)
                        cx = 0
                
                    elif choice == '2':
                        print('Thank You!')
                        cx = 0
                    else:
                        print('Improper Input')
            if no == 2:
                OFB_cipher = [[-1]*64]*2
                for rounds in range(0,2):
                    cipher_t = tripledes_encrypt(IV,nkey1,nkey2,nkey3)
                    temp = [str(ord(a) ^ ord(b)) for a,b in zip(cipher_t,block[rounds])]
                    bit_string = ''
                    encrypt_msg = ''
                    for i in range(0,64):
                        bit_string+= temp[i]
                    encrypt_msg+= bit_to_ascii(bit_string)
                    OFB_cipher[rounds] = temp
                    IV = list(cipher_t)
                print('Encrypted message is: ',encrypt_msg)
                
                decrypted = ''
                cx = 1
                while cx == 1:
                    choice = input('Would you like to decrypt it too??\n Enter 1 if yes, 2 if no: ')
                    IV = list(''.join('{0:08b}'.format(x, 'b') for x in bytearray('shivi@uw','utf8')))
                    if choice == '1':
                    
                        OFB_plain = [[-1]*64]*2
                    
                        for i in range(0,2):
                            pad_str = ''
                        
                            temp = tripledes_encrypt(IV,nkey1,nkey2,nkey3)
                            OFB_plain[i] = list(temp)
                        
                            if i == 0:
                                
                                unpad_text = [str(ord(a) ^ ord(b)) for a,b in zip(OFB_plain[i],OFB_cipher[i])]
                                for w in range(0,64):
                                    pad_str+= unpad_text[w]
                        
                                asci = bit_to_ascii(pad_str)
                                decrypted = asci
                           
                                IV = OFB_plain[i]
                            if i == 1:
                            
                                pad_text = [str(ord(a) ^ ord(b)) for a,b in zip(OFB_plain[i],OFB_cipher[i])]
                                length = 64-8*pad
                            
                                for w in range(0,64):
                                    pad_str+= pad_text[w]
                        
                                message = pad_str[:length]
                                asci = bit_to_ascii(message)
                                decrypted+= asci
                        print('Decrypted message is: ',decrypted)        
                        cx = 0
                   
                    elif choice == '2':
                        print('Thank You!')
                        cx = 0
                    else:
                        print('Improper Input')
                    
            
            
    else:
        print('Invalid mode option.')


print('Thank you for using this program')
print('................................')


# In[ ]:




# In[ ]:




# In[ ]:








# In[ ]:




# In[ ]:



