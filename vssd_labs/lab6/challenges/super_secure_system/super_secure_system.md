# Challenge `Super Secure System` writeup

* **Flag:** SSof{Jump_to_wherever_you_want}
* **Vulnerability:** Stack-based Buffer Overflow via `strcpy`
* **Where:** `check_password` function
* **Impact:** Bypassing authentication by jumping directly to the flag-printing logic in `main`.

## Steps to reproduce

1. Identify the jump target: The `printf` call in `main` at `0x080487d9`.
2. Calculate the offset: GDB shows 36 bytes between the start of `buffer` and the Saved EBP.
3. Overwrite the Saved EBP with a stable address (e.g., an offset `0x804a021`) to prevent a crash.
4. Overwrite the Saved EIP (next 4 bytes) with the target address `0x080487d9`.
5. The `check_password` function returns directly to the flag reveal logic, bypassing the `strcmp`.

[(POC)](./super_secure_system_poc.py)
