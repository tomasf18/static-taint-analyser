# Challenge `Write Specific Value` writeup

* **Flag:** `SSof{And_you_can_write_whatever_you_want}`
* **Vulnerability:** Format String Vulnerability (Arbitrary Write with value control)
* **Where:** `printf` buffer
* **Impact:** Allows writing a specific integer value to a memory address.

## Steps to reproduce

1. Determine the address of the `target` variable.
2. Calculate the required padding to equal the specific target value when printed.
3. Send the `target` address followed by `%[padding]x` to output the necessary number of characters.
4. Use `%7$n` to write the total character count (which now equals the desired value) to the `target` address.

[(POC)](./write_specific_value_poc.py)