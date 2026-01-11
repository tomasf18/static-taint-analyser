# Challenge `Guess a BIG Number` writeup

* **Flag:** `SSof{A_little_scripting_is_all_you_need}`
* **Vulnerability:** Lack of rate-limiting and information disclosure (server reveals direction of the correct answer)
* **Where:** `GET /number/<guess>` endpoint
* **Impact:** Allows an attacker to efficiently locate the secret number using binary search instead of brute-forcing 100,000 possibilities

## Steps to reproduce

1. Access the base endpoint to start a session and receive cookies.
2. Submit any guess using `/number/<guess>`.
3. Observe the server response:
   * `"Higher!"` -> the secret number is larger
   * `"Lower!"` -> the secret number is smaller
   * Contains `"SSof"` -> the flag has been found
4. Use these responses to update the search interval (`min`, `max`) and compute the next midpoint.
5. Repeat until the response contains the flag.
6. The server eventually responds with `SSof{...}`, revealing the flag.

[(POC)](../scripts/guess_a_big_number_poc.py)
