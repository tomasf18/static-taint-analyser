# AUTHORED BY: Test ist1102428-03: Nested for loops
# Tests that taint propagates through nested iterations

data = fetch_data()
for row in data:
    for item in row:
        process(item)