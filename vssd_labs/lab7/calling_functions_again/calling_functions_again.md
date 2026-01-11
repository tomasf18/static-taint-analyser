# Challenge `Calling Functions Again` writeup

* **Flag:** `SSof{you_GOT_me}`
* **Vulnerability:** Format String Vulnerability (GOT Overwrite)
* **Where:** `printf` buffer
* **Impact:** Hijacks control flow by overwriting the Global Offset Table (GOT) entry of `puts` to point to the `win` function.

## Steps to reproduce

1. Locate the address of `win` and the GOT entry for `puts`.
2. Split the `win` address into high and low 16-bit parts.
3. Construct a payload placing the GOT addresses on the stack.
4. Use `%[padding]x` and `%hn` (write 2 bytes) to overwrite the `puts` GOT entry in two parts, effectively redirecting execution to `win` when `puts` is next called.

[(POC)](./calling_functions_again_poc.py)