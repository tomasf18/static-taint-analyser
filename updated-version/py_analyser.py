import sys
import json
from pathlib import Path
from tool.multilabel import MultiLabel
from tool.pattern import Pattern
from tool.multilabelling import MultiLabelling
from tool.policy import Policy
from tool.vulnerabilities import Vulnerabilities
from tool.traces import TracesTraversal
from tool.ast_utils import ASTUtils
from tool.execution_state import ExecutionState

def process_json_file(filepath):
    """Process the JSON file containing vulnerability patterns."""
    patterns = []
    with open(filepath, 'r', encoding='utf-8') as f:
        json_list = json.load(f)

    for entry in json_list:
        patterns.append(Pattern(
            vulnerability_name=entry['vulnerability'],
            sources=set(entry['sources']),
            sink_names=set(entry['sinks']),
            sanitizers=entry['sanitizers'],
            implicit_flows=entry['implicit']
        ))
        print(patterns[-1])
    return patterns

def main():
    ast_utils = ASTUtils()
    
    if len(sys.argv) != 3:
        print("USAGE: python3 py_analyser.py <file.py> <file.json>")
        sys.exit(1)

    python_file_path = Path(sys.argv[1])
    json_file_path = Path(sys.argv[2])

    # read and parse the Python file
    code = ast_utils.read_python_file(python_file_path)
    ast_dict = ast_utils.generate_ast(code)
    
    # process the json file
    patterns = process_json_file(json_file_path)
    policy = Policy(patterns)
    vulnerabilities = Vulnerabilities()

    # create initial execution state
    initial_state = ExecutionState(
        multilabelling=MultiLabelling(),
        initialized_vars=set(),
        policy=policy.deepcopy()
    )
    
    # analyze program
    traversal = TracesTraversal()
    final_states = traversal.analyse_program(
        ast_dict, 
        [initial_state],  # start with one state
        vulnerabilities
    )
    
    print(f"\n[DEBUG] Analysis complete. Final number of execution paths: {len(final_states)}")
    
    # write output
    output_dir = Path('./output')
    output_dir.mkdir(exist_ok=True)
    
    output_file = output_dir / f'{python_file_path.stem}.output.json'
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(vulnerabilities.to_json(), f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    main()