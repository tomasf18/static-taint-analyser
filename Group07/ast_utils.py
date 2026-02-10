import ast
import json
from itertools import product

from astexport import export
from pathlib import Path

class ASTUtils:
    def __init__(self):
        self.binary_operators = {
            'Add': '+', 'Sub': '-', 'Mult': '*', 'Div': '/',
            'Mod': '%', 'Pow': '**', 'FloorDiv': '//',
            'Eq': '==', 'NotEq': '!=', 'Lt': '<', 'LtE': '<=',
            'Gt': '>', 'GtE': '>=', 'Is': 'is', 'IsNot': 'is not',
            'In': 'in', 'NotIn': 'not in'
        }
    
    # ====== Public methods ======
    
    def read_python_file(self, file_path: Path) -> str:
        """
        Reads the content of a Python file.
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
        
    def generate_ast(self, python_code: str) -> dict:
        """
        Generates an AST from the given code string.
        """
        # Parse and convert AST
        ast_tree = ast.parse(python_code)
        ast_dict = export.export_dict(ast_tree)
        return ast_dict
    
    def save_ast_to_json_file(self, ast_dict: dict, file_path: Path):
        """
        Saves the given AST dictionary to a JSON file.
        """
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(ast_dict, f, ensure_ascii=False, indent=4)
            
    def print_ast_types(self, node: dict | list) -> None:
        """
        Print all the types in the AST.
        """
        self._traverse_ast(node)
     
    def print_traces(self, node: dict | list, max_loop: int = 2) -> None:
        """
        Print all possible execution paths on the AST.
        """
        traces = self._traverse_traces(node, max_loop)
        for i, t in enumerate(traces, 1):
            separator = '\n -> '
            print(f"{i}. {separator.join(t)}")
                
    def deal_target(self, node: dict) -> str:
        return self._format_leaf_node(node)
    
    def deal_name(self, node: dict) -> str:
        return self._format_leaf_node(node)
    
    def deal_attribute(self, node: dict) -> str:
        return self._format_leaf_node(node)
    
    # ====== Internal methods for trace traversal ======
            
    def _traverse_ast(self, node: dict | list) -> None:
        """
        Traverse AST and print all the types: each node either is a dict or a list of dicts.
        """
        if isinstance(node, dict):
            ast_type = node.get('ast_type')
            if ast_type:
                print(f"ast_type: {ast_type}, lineno: {node.get('lineno', 'No lineno')}")

            for child in node.values():
                self._traverse_ast(child)

        elif isinstance(node, list):
            for item in node:
                self._traverse_ast(item)
    
    def _traverse_traces(self, node: dict | list, max_loop: int = 2) -> list[list[str]]:
        """
        Traverse all possible execution paths on the AST.
        Returns a list of traces, where each trace is a list of strings representing the steps. (e.g., [[step1, step2], [step1, step3]])
        """
        if isinstance(node, list):
            traces = [[]]
            for child in node:
                child_traces = self._traverse_traces(child, max_loop)
                new_traces = []
                for t in traces:
                    for ct in child_traces:
                        new_traces.append(t + ct)
                traces = new_traces
            return traces

        ast_type = node.get('ast_type')

        switcher = {
            'Module': lambda node: self._traverse_traces(node.get('body', []), max_loop),
            'Assign': lambda node: self._handle_assign(node),
            'Expr': lambda node: self._handle_expr(node),
            'If': lambda node: self._handle_if(node, max_loop),
            'While': lambda node: self._handle_while(node, max_loop),
            #'For': lambda node: self._handle_for(node, max_loop), # -> For bonus
        }
        return switcher.get(ast_type)(node)
        
    def _handle_assign(self, node: dict) -> list[list[str]]:
        targets = node.get('targets')
        target = self.deal_target(targets[0]) if targets else None
        value_node: dict = node.get('value', {})
        value_type = value_node.get('ast_type')

        switcher = {
            'Name': lambda value_node: self.deal_name(value_node),
            'Constant': lambda value_node: self._deal_constant(value_node),
            'Call': lambda value_node: self._deal_call(value_node),
            'BinOp': lambda value_node: self._deal_binop(value_node),
            'Subscript': lambda value_node: self._deal_subscript(value_node),
        }
        return [[f"{target} := {switcher.get(value_type)(value_node)}"]]
    
    def _handle_expr(self, node: dict) -> list[list[str]]:
        value_node = node.get('value', {})
        value_type = value_node.get('ast_type')
        
        switcher = {
            'Name': lambda value_node: self.deal_name(value_node),
            'Constant': lambda value_node: self._deal_constant(value_node),
            'Call': lambda value_node: self._deal_call(value_node),
            'BinOp': lambda value_node: self._deal_binop(value_node),
            'Subscript': lambda value_node: self._deal_subscript(value_node),
        }
        
        return [[f"{switcher.get(value_type)(value_node)}"]]
        
    def _handle_if(self, node: dict, max_loop: int) -> list[list[str]]:
        test_node = node.get('test', {})
        test = self._deal_test(test_node)
            
        body_traces = self._traverse_traces(node.get('body', []), max_loop)
        else_traces = self._traverse_traces(node.get('orelse', []), max_loop)
        
        combined_traces = []
        for bt in body_traces:
            combined_traces.append([f"if {test} (True):"] + bt)

        for et in else_traces:
            combined_traces.append([f"if {test} (False):"] + et)

        return combined_traces
    
    def _handle_while(self, node: dict, max_loop: int) -> list[list[str]]:
        test_node = node.get('test', {})
        test = self._deal_test(test_node)
        
        body_traces = self._traverse_traces(node.get('body', []), max_loop)
        else_traces = self._traverse_traces(node.get('orelse', []), max_loop)
        combined_traces = []

        if not body_traces:
            body_traces = [[]]

        for i in range(1, max_loop + 1):
            num_iterations = i
            prefixes = [f"while {test} (True, iter: {j}):" for j in range(1, num_iterations + 1)]

            for combo in product(body_traces, repeat=num_iterations):
                combined_trace = []
                for prefix, body_trace in zip(prefixes, combo):
                    combined_trace.append(prefix)
                    combined_trace.extend(body_trace)
                combined_traces.append(combined_trace + [f"while {test} (False, exit after {num_iterations} iterations):"])
                
        for et in else_traces:
            combined_traces.append(et)
            
        return combined_traces
    
    def _convert_op(self, op_type: str) -> str:
        return self.binary_operators.get(op_type, op_type)
    
    def _format_leaf_node(self, leaf_node: dict) -> str:
        """
        Recursively format any leaf node to string.
        Central dispatch function for all leaf types.
        """
        if not isinstance(leaf_node, dict):
            return "?"
        
        expr_type = leaf_node.get('ast_type')
        
        if expr_type == 'Constant':
            return repr(leaf_node.get('value'))
        
        elif expr_type == 'Name':
            return leaf_node.get('id', '?')
        
        elif expr_type == 'Attribute':
            value = leaf_node.get("value", {})
            base = self._format_leaf_node(value)
            attr = leaf_node.get("attr", "?")
            return f"{base}.{attr}"
        
        elif expr_type == 'Subscript':
            value = leaf_node.get("value", {})
            slice_node = leaf_node.get("slice", {})
            base = self._format_leaf_node(value)
            slice_str = self._format_leaf_node(slice_node)
            return f"{base}[{slice_str}]"
        
        elif expr_type == 'BinOp':
            left = self._format_leaf_node(leaf_node.get('left', {}))
            right = self._format_leaf_node(leaf_node.get('right', {}))
            op = self._convert_op(leaf_node.get('op', {}).get('ast_type', '?'))
            return f"{left} {op} {right}"
        
        elif expr_type == 'Call':
            func = self._format_leaf_node(leaf_node.get('func', {}))
            args = [self._format_leaf_node(arg) for arg in leaf_node.get('args', [])]
            return f"{func}({', '.join(args)})"
        
        elif expr_type == 'Compare':
            left = self._format_leaf_node(leaf_node.get("left", {}))
            ops = leaf_node.get("ops", [])
            comparators = leaf_node.get("comparators", [])
            
            parts = [left]
            for op, comp in zip(ops, comparators):
                op_symbol = self._convert_op(op.get("ast_type"))
                parts.append(f"{op_symbol} {self._format_leaf_node(comp)}")
            
            return " ".join(parts)
        
        else:
            return expr_type or "?"
    
    def _deal_test(self, node: dict) -> str:
        return self._format_leaf_node(node)
    
    def _deal_constant(self, node: dict) -> str:
        return self._format_leaf_node(node)

    def _deal_call(self, node: dict) -> str:
        return self._format_leaf_node(node)
    
    def _deal_binop(self, node: dict) -> str:
        return self._format_leaf_node(node)
    
    def _deal_subscript(self, node: dict) -> str:
        return self._format_leaf_node(node)
    

#--- Example usage --- 
if __name__ == "__main__":
    ast_utils = ASTUtils()
    list_of_paths: list[str] = ["./slices/1-basic-flow/1a-basic-flow.py",
                                "./slices/1-basic-flow/1b-basic-flow.py",
                                "./slices/2-expr-binary-ops/2-expr-binary-ops.py",
                                "./slices/3-expr/3a-expr-func-calls.py",
                                "./slices/3-expr/3b-expr-func-calls.py",
                                "./slices/3-expr/3c-expr-attributes.py",
                                "./slices/3-expr/3d-expr-subscript.py",
                                "./slices/4-conds-branching/4a-conds-branching.py",
                                "./slices/4-conds-branching/4b-conds-branching.py",
                                "./slices/5-loops/5a-loops-unfolding.py",
                                "./slices/5-loops/5b-loops-unfolding.py",
                                "./slices/5-loops/5c-loops-unfolding.py",
                                "./slices/6-sanitization/6a-sanitization.py",
                                "./slices/6-sanitization/6b-sanitization.py",
                                "./slices/7-conds-implicit/7-conds-implicit.py",
                                "./slices/8-loops-implicit/8-loops-implicit.py",
                                "./slices/9-regions-guards/9-regions-guards.py",
                                ]
    
    # Get filename: file_path.name  -> "1a-basic-flow.py"
    # Get stem (no extension): file_path.stem  -> "1a-basic-flow"
    # Get parent directory: file_path.parent  -> "slices/1-basic-flow"
    # Get category (e.g., "1-basic-flow"): file_path.parent.name  -> "1-basic-flow"

    for path in list_of_paths:
        print(f"Analysing: {path} ...\n")
        file_path = Path(path)
        code = ast_utils.read_python_file(file_path)
        ast_dict = ast_utils.generate_ast(code)
        ast_utils.save_ast_to_json_file(ast_dict, Path(f"{file_path.parent}/{file_path.stem}.ast-to.json"))
    
    # print traces of list_of_paths[6]
    file_path = Path(list_of_paths[10])
    code = ast_utils.read_python_file(file_path)
    ast_dict = ast_utils.generate_ast(code)
    
    ast_utils.print_traces(ast_dict, 5)

    