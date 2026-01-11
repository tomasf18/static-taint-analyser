# Challenge `Match an Exact Value` writeup

* **Flag:** SSof{Buffer_Overflow_to_change_values_to_wh4t3v3r_you_want}
* **Vulnerability:** Stack-based Buffer Overflow
* **Where:** `main` function (vulnerable `gets(buffer)` call)
* **Impact:** Modifying a specific memory location (`test` variable) to match a required constant.

## Steps to reproduce

1. Identify the target value: `0x61626364` (disassemble using pwndbg), which corresponds to ASCII "abcd".
2. Identify the buffer size: 64 bytes.
3. Account for Little-Endian architecture: To store `0x61626364`, the bytes must be sent in reverse order (`\x64\x63\x62\x61` or "dcba").
4. Send 64 bytes of padding followed by "dcba".
5. The program validates that `test == 0x61626364` and prints the flag.

[(POC)](./match_an_exact_value_poc.py)

