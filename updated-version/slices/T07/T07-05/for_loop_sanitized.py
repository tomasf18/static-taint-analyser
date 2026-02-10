# AUTHORED BY: Test ist1102428-05: For loop with sanitization
# Tests that sanitizers are correctly tracked in for loops

inputs = get_inputs()
for input in inputs:
    safe_input = sanitize(input)
    process(safe_input)