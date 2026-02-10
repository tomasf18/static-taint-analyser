# AUTHORED BY: Test ist1102428-04: Mixed for and while loops
# Tests that both loop types work together

users = get_users()
for user in users:
    i = 0
    while i < 3:
        send(user)
        i = i + 1