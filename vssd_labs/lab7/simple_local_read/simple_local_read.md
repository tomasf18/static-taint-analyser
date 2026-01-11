# Challenge `Simple Local Read` writeup

* **Flag:** `SSof{There_are_no_secrets_in_stack}`
* **Vulnerability:** Format String Vulnerability (Arbitrary Read)
* **Where:** `printf` buffer
* **Impact:** Allows reading arbitrary values from the stack, including the secret string.

## Steps to reproduce

1. Analyze the binary locally using `pwndbg` and break at the vulnerability (`sub esp, 0xc`).
2. Locate the `secret_value` address (e.g., `0x804d1e0`) using `p secret_value`.
3. Send a probe payload (`AAAA` followed by multiple `%08x`) to leak stack values.
4. Identify the `secret_value` address in the output (observed as the 7th value in the leaked stack).
5. Send the final payload using `%s` at the identified position (e.g., `AAAA.%08x...%s`) to read the secret string from memory.

[(POC)](./simple_local_read_poc.py)
