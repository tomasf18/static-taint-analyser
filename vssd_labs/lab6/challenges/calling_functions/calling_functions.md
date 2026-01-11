# Challenge `Calling Functions` writeup

* **Flag:** SSof{Buffer_Overflow_can_also_change_function_pointers}
* **Vulnerability:** Function Pointer Overwrite via Buffer Overflow
* **Where:** `main` function
* **Impact:** Redirecting program execution to an uncalled function (`win`).

## Steps to reproduce

1. Locate the address of the `win` function in GDB: `0x080486f1` (disassemble using pwndbg).
2. Find the distance between `buffer` and the function pointer `fp`: `0xffffcbec - 0xffffcbcc = 32 bytes`.
3. Provide 32 bytes of padding to reach the pointer.
4. Overwrite `fp` with the address of `win` (`\xf1\x86\x04\x08` in Little-Endian).
5. When `fp()` is called, the program jumps to `win` and reveals the flag.

[(POC)](./calling_functions_poc.py)