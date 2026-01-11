# Challenge `Another jackpot` writeup

* **Flag:** `SSof{There_was_never_an_admin_user}`
* **Vulnerability:** Session Race Condition (TOCTOU) in session authentication logic
* **Where:** `/login` and `/jackpot` endpoints of the Flask web application
* **Impact:** Allows an unauthenticated user to obtain a session cookie containing username `admin`, granting access to the admin-only jackpot endpoint
* **NOTE:** The vulnerability exists because the server writes `session["username"]` before validating the credentials.

---

## Steps to reproduce

1. Access the application to obtain a valid session cookie:

```text
http://mustard.stt.rnl.tecnico.ulisboa.pt:25652
```

2. Using the same session cookie, start a login (endpoint /login) request with:

```
username=admin
password=any
```

3. Due to a race condition in the server, the backend temporarily sets the session cookie to `username=admin` before validating the password.

4. Immediately, using the same session, send a request to:

```text
/jackpot
```

5. If timed correctly, the request is processed while the session still contains:

```
username=admin
```

6. The server incorrectly treats the user as the administrator and returns the jackpot flag.

[(POC)](another_jackpot_poc.py)