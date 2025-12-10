import ast
import json
import sys
from astexport import export
inputs = sys.argv
with open(inputs[1], "r") as fp1:
    py_str = fp1.read()
    ast_py = ast.parse(py_str)
    ast_dict = export.export_dict(ast_py)
    ast_json=json.dumps(ast_dict, indent=4)

print(ast_dict)

# for exercise 1 oof tool (fourth part)
# python3 asts.py mini.py 