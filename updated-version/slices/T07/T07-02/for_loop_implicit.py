# AUTHORED BY: Test ist1102428-02: For loop with implicit flow
# Tests that implicit flow is detected when loop variable influences assignments

secret = get_secret()
for i in secret:
    msg = "processing"
    log(msg)