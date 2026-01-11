# Challenge `I will take care of this site` 

* **Flag:** `SSof{SQLi_on_SELECT_allows_you_to_become_an_administrator}`
* **Vulnerability:** SQL Injection on authentication query (authentication bypass)
* **Where:** Login form (`username` and `password` fields), vulnerable `SELECT` query
* **Impact:** Allows any attacker to bypass authentication and log in as the `admin` user, granting full administrative access to the application and disclosure of sensitive information.

---

## Steps to reproduce

1. Access the login page of the vulnerable blog posts application.

2. In the **username field**, inject the following SQL payload:

```sql
admin' or 1=1 -- 
```

*(Note: a whitespace is required after `--` to properly comment out the remaining query.)*

4. In the password field, insert any random string (it is irrelevant since I just commented the rest of the query).

5. Click the Login button.

6. As a result of the injected condition `OR 1=1`, the SQL `SELECT` query always evaluates to true, bypassing authentication and logging the attacker in as the `admin` user.

7. After logging in, click on the “Profile (admin)” button located at the top-right corner of the page.

8. Inside the admin profile page, locate the Bio section, which reveals the following message along with the flag:

```
I'm the admin! I control everything!! If only they knew this they could be like me: 
SSof{SQLi_on_SELECT_allows_you_to_become_an_administrator}
```