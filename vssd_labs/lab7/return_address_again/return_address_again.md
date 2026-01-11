# Challenge `Return Address Again` writeup

* **Flag:** `SSof{returning_to_the_same_old_things}`
* **Vulnerability:** Format String Vulnerability (Stack Return Address Overwrite)
* **Where:** `printf` buffer
* **Impact:** Hijacks control flow by overwriting the return address on the stack.

## Steps to reproduce

1. Leak a stack address (saved EBP) using `%42$p` to calculate the location of the return address (EBP + 4).
2. Disconnect and reconnect to start a fresh session with the calculated offsets.
3. Construct a payload similar to the GOT exploit, but targeting the calculated stack return address.
4. Overwrite the return address with the address of `win` using split writes (`%hn`).

[(POC)](./return_address_again_poc.py)