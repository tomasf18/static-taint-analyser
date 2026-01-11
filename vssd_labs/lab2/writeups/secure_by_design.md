# Challenge `Secure by Design` writeup

* **Flag:** `SSof{Base64_encoding_is_not_a_protection}`
* **Vulnerability:** Client-side privilege control (cookie manipulation)
  * The server stores the authenticated username, and thus the user’s privilege level, directly in a Base64-encoded cookie controlled by the client.
* **Where:** Cookie `user` (Base64-encoded username), used to determine whether the visitor is an admin
* **Impact:** An attacker can bypass access controls entirely by rewriting the `user` cookie to contain `"admin"` encoded in Base64, gaining administrator privileges and retrieving the flag.
* **NOTE:** This demonstrates a classic security design flaw: *never trust client-side state for authorization decisions*.

## Steps to reproduce

1. Submit any username through the login form (e.g., `tomas`), prompting the server to issue a `user` cookie.
2. Observe that the cookie value is simply Base64-encoded text (e.g., `fake-admin` -> `ZmFrZS1hZG1pbg==`).
3. Decode the cookie to confirm its structure.
4. Replace the content with `"admin"`, encode it as Base64, and overwrite the `user` cookie in the session.
5. Send a new request to the main endpoint using the modified cookie.
6. The server now treats the request as coming from an administrator and returns the flag.

[(POC)](../scripts/secure_by_design_poc.py)
