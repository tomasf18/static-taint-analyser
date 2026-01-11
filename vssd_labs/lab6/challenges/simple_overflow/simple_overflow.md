# Challenge `Simple Overflow` writeup

* **Flag:** SSof{Buffer_Overflow_to_control_local_variables}
* **Vulnerability:** Stack-based Buffer Overflow
* **Where:** `main` function (vulnerable `gets(buffer)` call)
* **Impact:** Overwriting the adjacent `test` variable to bypass a conditional check.

## Steps to reproduce

1. Analyze the stack layout in pwndbg: `&test` is at `0xffffcc9c` and `&buffer` is at `0xffffcc1c`.
2. Calculate the offset: `0x80` (128 bytes).
3. The `gets()` function does not check bounds, allowing us to write past the 128-byte limit of `buffer`.
4. Provide an input of 129 bytes (e.g., 129 'a' characters) to overwrite the `test` variable with a non-zero value.
5. The `if(test != 0)` condition evaluates to true, revealing the flag.

[(POC)](./simple_overflow_poc.py)

