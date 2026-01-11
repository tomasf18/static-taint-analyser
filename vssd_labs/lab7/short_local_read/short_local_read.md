# Challenge `Short Local Read` writeup

* **Flag:** `SSof{Positional_arguments_ftw}`
* **Vulnerability:** Format String Vulnerability (Direct Parameter Access)
* **Where:** `printf` with a small input buffer
* **Impact:** Allows reading specific stack values at arbitrary offsets without traversing previous values.

## Steps to reproduce

1. Analyze the binary to find the stack offset where the flag pointer is stored.
2. Iterate through positions (brute-force or calculation) to find the correct index (found at index 7).
3. Use the positional argument syntax `%{pos}$s` (specifically `%7$s`) to read the string directly from that stack position.

[(POC)](./short_local_read_poc.py)