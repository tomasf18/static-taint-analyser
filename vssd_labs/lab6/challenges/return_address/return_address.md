# Challenge `Return Address` writeup

* **Flag:** SSof{Overflow_of_saved_r37urn_address}
* **Vulnerability:** Buffer Overflow (Instruction Pointer Overwrite)
* **Where:** `challenge` function
* **Impact:** Hijacking the control flow by overwriting the Saved EIP on the stack.

## Steps to reproduce

1. Find the address of the `win` function: `0x080486f1` (disassemble using pwndbg).
2. Use pwndbg to find the offset from `buffer` to the Saved EIP: `0xffffcc0c - 0xffffcbf6 = 22 bytes`.
3. Send 22 bytes of padding to fill the buffer and reach the return address slot.
4. Append the address of `win` (`\xf1\x86\x04\x08`).
5. When the `challenge` function returns, the CPU pops the address into EIP, executing `win`.

[(POC)](./return_address_poc.py)