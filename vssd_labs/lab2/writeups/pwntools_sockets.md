# Challenge `PwnTools Sockets` writeup

* **Flag:** `SSof{You_can_also_script_over_sockets}`
* **Vulnerability:** Predictable game logic over raw sockets with no authentication or rate-limiting
  * The server exposes the same “number accumulation” game as the HTTP version, now over plain TCP.
* **Where:** Raw TCP service on port `25055`, expecting commands `MORE` and `FINISH`
* **Impact:** An attacker can fully automate interaction with the socket server using `pwntools`, repeatedly requesting numbers until reaching the target and then issuing `FINISH` to obtain the flag.

## Steps to reproduce

1. Use `remote(SERVER, PORT)` from `pwntools` to open a TCP connection.
2. Read the initial banner and extract the target numeric value using a regex.
3. Initialize a running sum at 0.
4. Repeatedly send the command `MORE` via `session.sendline(MORE_COMMAND)`.
5. After each response, parse the number returned by the server with regex and update the sum.
6. Continue until the sum exactly matches the target.
7. Send the command `FINISH`.
8. Read the final server output, which contains the flag.

[(POC)](../scripts/pwntools_sockets_poc.py)
