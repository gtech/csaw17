import hashlib
import sys
import os
sys.path.append(os.path.abspath('../cryptopals/'))
import CA

import pdb
import math

# def xor(s1,s2):
#     return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

# def repeat(s, l):
#     return (s*(int(l/len(s))+1))[:l]

# # key = sys.argv[1]
# # plaintext = sys.argv[2] + key


# ciphet_text = sys.argv[1]
# plaintext += hashlib.md5(plaintext).hexdigest()
# cipher = xor(plaintext, repeat(key, len(plaintext)))
# print cipher.encode('hex')

#ciphhertext =  encrypt(plain + key + md5(hash+key))
#plaintext =  plain + key + md5(hash+key)

items = os.listdir('./xortool_out/')

#pdb.set_trace()

#split = CA.split_by_n(ciphertext,4)

#

#print ciphertext

#print len('f3b94238ed01e29724f6b911217b65f6')
# candidates = {}
# chis = []
# for f in items:
#     i = open('./xortool_out/'+f).readlines()[0]
#     chi2 = CA.getChi2(i)
#     candidates[chi2] = i
#     chis.append(chi2)

# chis = sorted(chis)
# #for i in chis[0:10]:
#     #print candidates[i]

#--------------------------------------------------

ciphertext = open('encrypted').readlines()[0][:-1].decode('hex')

CA.find_key_size(100,136,ciphertext)

#This is our keysize to test
block_size = 67
#Consecutive blocks of the block_size length
raw_block_list = list(CA.split_by_n(ciphertext,block_size))
#Key: Key_Index, Value: Key_Index'th byte of every block concatenated together
block_strings = {k:'' for k in range(0,block_size)}

#May be pointless:
#truncated_key_size = len(ciphertext) % block_size
#print("End of ciphertext has this many key bytes: " + str(truncated_key_size))

#Creates block_strings
#Purpose: Each block string can be used to find a key byte for that index in the blocks
#Hash:
#Keys: index of the block
#Values: String of bytes, one byte at each index of all blocks
for key_byte_i in range(0,block_size):
    for block in raw_block_list:
        if len(block) > key_byte_i:
            block_strings[key_byte_i] += block[key_byte_i]

#For testing our keys by eye
#Changing our block_size gives us varying chi2's of our top most relevant keys
#Use these two lines to observe those Chi2's to ensure you have the correct block size
decrypted = CA.find_byte_encrypted_candidates(block_strings[3])
CA.print_top_candidates(decrypted, 10, False)

key_bytes = list()
for n in range(0,block_size):
    decrypted = CA.find_byte_encrypted_candidates(block_strings[n])
    key_bytes.append(chr(CA.get_top_candidate(decrypted)[2]))

#------------------------------------------------------------------------------------------

print(''.join(key_bytes))
print(CA.repeating_key_xor(key_bytes,ciphertext))
