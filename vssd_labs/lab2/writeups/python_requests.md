# Challenge `Python requests` writeup

* **Flag:** `SSof{Learning_python_requests_is_a_good_complement_to_ZAP}`
* **Vulnerability:** Predictable game logic with state stored in cookies
  * The server exposes deterministic numeric responses and relies solely on cookies for tracking progress.
* **Where:** Endpoints `/hello`, `/more`, `/finish`
* **Impact:** By repeatedly requesting `/more` while maintaining cookies, an attacker can fully automate the game loop and reach the exact target value without manual interaction.

## Steps to reproduce

1. Start a session with `requests.Session()` to preserve cookies automatically.
2. Access `/hello` to initialize the game and retrieve the **target** number from the response text.
3. Initialize a running sum at 0.
4. Repeatedly request `/more`, extract the number provided, and add it to the sum.
5. Continue until the running sum equals the target value.
6. Once equal, send a request to `/finish`.
7. The server verifies the sum and returns the flag when the target is matched exactly.

[(POC)](../scripts/python_requests_poc.py)
