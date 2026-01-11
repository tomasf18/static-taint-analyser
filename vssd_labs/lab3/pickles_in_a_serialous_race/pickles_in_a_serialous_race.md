# Challenge `Pickles in a seri(al)ous race` writeup

* **Flag:** `SSof{It_is_alwasy_an_easy_race_with_Pickles_RCE}`
* **Vulnerability:** Insecure deserialization (Python `pickle` Remote Code Execution) and race condition, by writing with one mode and reading with the other
* **Where:** Deserialization of user-controlled data in `CLASSY` note read functionality (`pickle.loads`)
* **Impact:** Allows arbitrary command execution on the server, enabling full filesystem exploration and flag disclosure
* **NOTE:** The exploit was developed after researching for:

  * [https://www.redhat.com/en/blog/remote-code-execution-serialized-data](https://www.redhat.com/en/blog/remote-code-execution-serialized-data)
  * [https://github.com/advisories/GHSA-655q-fx9r-782v](https://github.com/advisories/GHSA-655q-fx9r-782v)

---

## Steps to reproduce

1. Connect to the service.

2. Open two simultaneous connections using the same username:
   * One in CLASSY mode
   * One in FREE mode

3. In FREE mode, write a malicious pickle payload as raw text to a note file.
   The payload uses `__reduce__` to execute arbitrary OS commands, for example:

```python
return (eval, ("__import__('os').popen('cat home/ctf/flag').read()",))
```

4. Because FREE mode writes raw bytes to disk, the malicious pickle is stored without modification.

5. The server mode is then switched back to CLASSY mode using the second connection.

6. In CLASSY mode, read the same note file.

7. The backend executes:

```python
pickle.loads(note_content)
```

8. During deserialization attempt, the embedded OS command is executed on the server and the flag is printed as the note output (as the server has a Linux filesystem, the commands used were a sequence of `ls` and `cat` to explore it and find the flag - the final command was `cat home/ctf/flag`).

[(POC)](pickles_in_a_serialous_race_poc.py)
