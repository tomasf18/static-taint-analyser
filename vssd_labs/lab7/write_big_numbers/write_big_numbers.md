# Challenge `Write Big Numbers` writeup

* **Flag:** `SSof{and_write_Very_BIIIIIG_numbers}`
* **Vulnerability:** Format String Vulnerability (Multi-byte Arbitrary Write)
* **Where:** `printf` buffer
* **Impact:** Allows writing large arbitrary values (e.g., `0xdeadbeef`) by writing one byte at a time.

## Steps to reproduce

1. Decompose the target value `0xdeadbeef` into 4 bytes: `0xef`, `0xbe`, `0xad`, `0xde`.
2. Place the addresses of the 4 bytes of `target` onto the stack (offsets 7, 8, 9, 10).
3. Calculate the cumulative padding required to reach each byte value sequentially (modulo 256).
4. Chain `%[padding]x` and `%[pos]$hhn` to write each byte successively in a single payload.

[(POC)](./write_big_numbers_poc.py)