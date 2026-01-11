import requests

SERVER = 'http://mustard.stt.rnl.tecnico.ulisboa.pt'
PORT = 25053
STARTING_ENDPOINT = '/hello'
MORE_ENDPOINT = '/more'
FINISH_ENDPOINT = '/finish'

base_link = f'{SERVER}:{PORT}'
starting_link = f'{base_link}{STARTING_ENDPOINT}'
ask_more_numbers_link = f'{base_link}{MORE_ENDPOINT}'
finish_link = f'{base_link}{FINISH_ENDPOINT}'

# create a session object to persist parameters and cookies across requests
session = requests.Session()

# access the initial page to establish a session and set the user cookie
response = session.get(base_link)

hello_response = session.get(starting_link)
response_parts_dot = hello_response.text.split(".")
target = response_parts_dot[1].split(" ")[-1]

print(response.text)
print(f"Target: {target}")

sum = 0

while float(sum) != float(target):
    more_response = session.get(ask_more_numbers_link)
    new_value = more_response.text.split("<br>")[0].split(" ")[-1]
    print("New Value: ", new_value)
    sum += float(new_value)
    print("Sum = ", sum)
    print("Target: ", target)
    
finish_response = session.get(finish_link)
flag = finish_response.text.split(" ")[-1]
print(f'Flag: {flag}')
    


