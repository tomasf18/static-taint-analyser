# AUTHORED BY: ist1102428-01: For loop with explicit flow
# Tests that taint propagates from iterable to loop variable

users = get_users()
for user in users:
    display(user)