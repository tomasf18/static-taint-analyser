# Challenge `Sometimes we are just temporarily blind-v2`

* **Flag:** `SSof{I_am_just_partially_blind_since_I_can_gEt_yoUr_datA_using_Boolean_Injections}`
* **Vulnerability:** Blind SQL Injection (Inference-based / Boolean-based SQL Injection)
* **Where:** Blog post search input on the landing page
* **Impact:** Allows extraction of sensitive data through Boolean inference, even when no query results are directly shown.
* **NOTE:** This challenge is a continuation of `Sometimes we are just temporarily blind` and focuses on case-sensitive flag extraction.

---

## Steps to reproduce

1. Complete the challenge [Sometimes we are just temporarily blind](Sometimes_we_are_just_temporarily_blind.md) and extract the secret value using Boolean-based blind SQL injection.

```
SSof{I_am_just_partially_blind_since_I_can_gEt_yoUr_datA_using_Boolean_Injections}
```