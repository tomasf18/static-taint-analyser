a = source()
sink(a)  # Vulnerability reported here - OK

a = ""  # Cleared
sink(a)  # FALSE POSITIVE if reported again from first assignment