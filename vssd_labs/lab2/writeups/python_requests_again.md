# Challenge `Python requests Again` writeup

* **Flag:** `SSof{Client_side_validation_is_a_big_NO}`
* **Vulnerability:** Client-side trust of security-critical state (cookie tampering)
  * The number of remaining attempts is stored entirely in a client-controlled cookie.
* **Where:** Cookie `remaining_tries`, used by endpoints `/more` and `/finish`
* **Impact:** An attacker can arbitrarily increase their allowed number of attempts by modifying the cookie value, effectively bypassing the “single try” restriction and winning the game.

## Steps to reproduce

1. Start a session and access `/hello` to read the target number and initialize cookies.
2. Observe that the server sets a cookie containing `remaining_tries=1`.
3. Before each call to `/more`, manually overwrite this cookie value using `session.cookies.set('remaining_tries', '1', domain=..., path='/')`.
4. Request `/more` repeatedly, each time receiving a new number and updating the sum.
5. Continue until the sum equals the target.
6. Once matched, request `/finish` to obtain the flag.

[(POC)](../scripts/python_requests_again_poc.py)
