# Challenge `Write to Memory` writeup

* **Flag:** `SSof{You_can_write_wherever_you_want}`
* **Vulnerability:** Format String Vulnerability (Arbitrary Write)
* **Where:** `printf` buffer
* **Impact:** Allows overwriting global variables (specifically `target`) to modify program logic.

## Steps to reproduce

1. Identify the memory address of the global variable `target` using the ELF binary symbols.
2. Construct a payload containing the address of `target` at the beginning (which places it at stack offset 7).
3. Append `%7$n` to the payload. The `%n` specifier writes the number of bytes printed so far into the address stored at the 7th stack position, changing `target` from 0.

[(POC)](./write_to_memory_poc.py)