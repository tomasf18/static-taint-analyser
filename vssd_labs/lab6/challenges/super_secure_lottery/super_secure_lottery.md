# Challenge `Super Secure Lottery` writeup

* **Flag:** SSof{You_will_NeVeR_guess_a_totally_random_lottery}
* **Vulnerability:** Buffer Overflow (Logic/Memory Corruption)
* **Where:** `run_lottery` function
* **Impact:** Manipulating the comparison between the prize and the guess.

## Steps to reproduce

1. The program uses `memcmp` to check if your `guess` matches a random `prize`.
2. Both `lottery` (the prize) and `guess` are stored on the stack.
3. By overflowing the `guess` buffer (64 bytes), we can reach and overwrite the `lottery` variable itself.
4. Sending 64 bytes of 'a's makes both the prize and the guess identical in memory.
5. The `memcmp` returns 0, and the program grants the flag.

[(POC)](./super_secure_lottery_poc.py)
    

    