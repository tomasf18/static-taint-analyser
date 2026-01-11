# Challenge `Write Specific Byte` writeup

* **Flag:** `SSof{and_write_big_numbers}`
* **Vulnerability:** Format String Vulnerability (Byte Granularity Write)
* **Where:** `printf` buffer
* **Impact:** Allows modifying specific bytes of a variable using format modifiers.

## Steps to reproduce

1. Identify the address of the Most Significant Byte (MSB) of the `target` variable (`target_addr + 3`).
2. Construct a payload containing this specific byte address.
3. Add padding (`%254x`) so the total character count ends with the desired byte value (`0x02` in this case).
4. Use `%7$hhn` (half-half-n) to write a single byte to the target address.

[(POC)](./write_specific_byte_poc.py)