import requests

SERVER = 'http://mustard.stt.rnl.tecnico.ulisboa.pt'
PORT = 25052

link = f'{SERVER}:{PORT}'

# create a session object to persist parameters and cookies across requests
session = requests.Session()

# access the initial page to establish a session and set the user cookie
session.get(link)

min = 0
max = 100000
current = (max - min) // 2

response: requests.Response = requests.Response()

while True:
    response = session.get(f'{link}/number/{current}')
    if "SSof" in response.text:
        break;
    elif "Higher!" in response.text:
        min = current
    elif "Lower!" in response.text:
        max = current
    print(f'Try: {current}')
    print(f'Body: {response.text}')
    current = min + (max - min) // 2
    print(f'New min: {min}')
    print(f'New max: {max}')
    print(f'New current: {current}')
    
print(f'Number: {current}')
print(f'Flag: {response.text}')
        