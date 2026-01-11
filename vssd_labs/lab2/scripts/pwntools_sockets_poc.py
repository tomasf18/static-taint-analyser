from pwn import *
import re # find numbers easily

SERVER = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25055
MORE_COMMAND = b'MORE'
FINISH_COMMAND = b'FINISH'

# connect
session = remote(SERVER, PORT)

initial_data = session.recvuntil(b'FINISH)?').decode()
print("Initial Data received:\n", initial_data)

# using Regex to find the target
match = re.search(r'until you get to (\d+)', initial_data)
if match:
    target = float(match.group(1))
    print(f"Target: {target}")
else:
    print("Could not find target!")
    exit()

sum = 0

while float(sum) != float(target):
    session.sendline(MORE_COMMAND)
    response = session.recvuntil(b'FINISH)?').decode()
    print(response)
    new_value_match = re.search(r'Here you have: ([-]?[\d\.]+)', response) # match a sequence of digits, possibly with a decimal point and possibly negative
    if new_value_match:
        new_value = float(new_value_match.group(1))
    else:
        print("Could not find new value!")
        break
    print("New Value: ", new_value)
    sum += float(new_value)
    print("Sum = ", sum)
    print("Target: ", target)
    
session.sendline(FINISH_COMMAND)
flag = session.recvall().decode()
print(f'Flag: {flag}')

session.close()