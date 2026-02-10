# Software Security: Static Taint Analyser for Python

### `Grade: 19.4/20`

## Overview

This project implements a static taint analysis tool for detecting security vulnerabilities in Python web applications. The tool identifies dangerous data flows from untrusted sources (entry points) to sensitive operations (sinks), with support for sanitization detection.

The analyzer uses multi-label taint tracking to trace how tainted data propagates through program slices, supporting:
- **Explicit flows**: Direct data propagation through assignments and expressions
- **Implicit flows**: Information leakage through control flow (conditionals and loops)
- **Sanitization detection**: Identifying when tainted data passes through sanitizer functions
- **Multiple vulnerability patterns**: Customizable security policies via JSON configuration

### Key Features

- Analysis of Python code slices for vulnerability patterns  
- Multi-label taint propagation tracking  
- Support for explicit and implicit information flows  
- Sanitization function detection  
- Customizable vulnerability patterns (sources, sinks, sanitizers)  
- Handles complex control flow (conditionals, loops, nested structures)  
- Expression analysis (function calls, attributes, subscripts, binary operations)

## Project Structure

```
static-taint-analyser/
├── py_analyser.py          # Main entry point for the analyzer
├── tool/                   # Core analysis modules
│   ├── ast_utils.py        # AST parsing and utilities
│   ├── execution_state.py  # Program state representation
│   ├── label.py            # Single taint label
│   ├── multilabel.py       # Multi-label container
│   ├── multilabelling.py   # Variable-to-labels mapping
│   ├── pattern.py          # Vulnerability pattern definition
│   ├── policy.py           # Security policy management
│   ├── traces.py           # Program trace analysis
│   └── vulnerabilities.py  # Vulnerability reporting
├── slices/                 # Test program slices
│   ├── 1-basic-flow/       # Basic taint propagation
│   ├── 2-expr-binary-ops/  # Binary operations
│   ├── 3-expr/             # Function calls, attributes, subscripts
│   ├── 4-conds-branching/  # Conditional statements
│   ├── 5-loops/            # Loop unfolding
│   ├── 6-sanitization/     # Sanitization detection
│   ├── 7-conds-implicit/   # Implicit flows in conditionals
│   ├── 8-loops-implicit/   # Implicit flows in loops
│   └── 9-regions-guards/   # Complex control flow regions
├── test/                   # Testing infrastructure
│   ├── run_all_tests.py    # Test runner for all slices
│   ├── validate.py         # Output validation script
│   └── 5_patterns.json     # Sample vulnerability patterns
├── output/                 # Generated analysis results
├── docs/                   # Documentation
│   └── project-specification.md
└── updated-version/        # Extended implementation (see below)
```

## Getting Started

### Prerequisites

- **Python 3.11.2 - 3.12**
- **astexport** (for AST generation)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd static-taint-analyser
```

2. Set up the virtual environment (optional but recommended):
```bash
python3 -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate
```

3. Install dependencies:
```bash
pip install astexport
```

## Usage

### Running the Analyzer

The tool analyzes Python code slices against vulnerability patterns and outputs detected vulnerabilities.

**Syntax:**
```bash
python py_analyser.py <path_to_slice.py> <path_to_patterns.json>
```

**Example:**
```bash
python py_analyser.py slices/1-basic-flow/1a-basic-flow.py slices/1-basic-flow/1a-basic-flow.patterns.json
```

**Output:**  
Results are saved to `./output/<slice_name>.output.json`

### Input Format

#### Program Slice (`.py` file)
A Python code snippet containing variables and operations to analyze:
```python
a = ""
b = c()
d(a)
e(b)
```

#### Vulnerability Patterns (`.json` file)
JSON array defining security policies:
```json
[
    {
        "vulnerability": "XSS",
        "sources": ["request.GET", "request.POST"],
        "sanitizers": ["escape", "bleach.clean"],
        "sinks": ["mark_safe", "render"],
        "implicit": "yes"
    }
]
```

- **vulnerability**: Name of the vulnerability type
- **sources**: Entry points (taint sources)
- **sanitizers**: Functions that sanitize tainted data
- **sinks**: Sensitive operations
- **implicit**: `"yes"` to track implicit flows, `"no"` for explicit only

**Note:** Any uninitialized variable in the slice is automatically treated as a potential source.

### Output Format

The tool generates JSON output with detected vulnerabilities:
```json
[
    {
        "vulnerability": "XSS_1",
        "source": ["request.GET", 2],
        "sink": ["mark_safe", 5],
        "flows": [
            ["explicit", []],
            ["explicit", ["escape"]]
        ]
    }
]
```

- **vulnerability**: Unique identifier (pattern name + instance number)
- **source**: `[function/variable, line_number]`
- **sink**: `[function/variable, line_number]`
- **flows**: List of `[flow_type, [sanitizers]]` paths
  - `flow_type`: `"explicit"` or `"implicit"`
  - `sanitizers`: List of sanitization functions applied

### Running All Tests

To validate the analyzer against all test cases:

```bash
cd test
python run_all_tests.py
```

This script:
1. Runs `py_analyser.py` on all test slices (directories 1-9)
2. Validates outputs against expected results
3. Reports any discrepancies

Individual test validation:
```bash
cd test
python validate.py -o ../output/<test>.output.json -t ../slices/<dir>/<test>.output.json
```

## Documentation

For complete project specifications, including:
- Detailed vulnerability analysis methodology
- Taint propagation rules
- Multi-label semantics
- Evaluation criteria

See: [docs/project-specification.md](docs/project-specification.md)

## Extended Version (Practice Implementation)

The `updated-version/` folder contains an extended implementation developed for practical exam preparation, including:

### Additional Features

- **AnnAssign Support**: Type-annotated assignments (`x: int = 5`)
- **AugAssign Support**: Augmented assignments (`x += 1`, `y *= 2`)
- **Column Number Tracking**: Enhanced source location reporting with column information
- **Sanitizer Modes**:
  - `omit`: Exclude specific sanitizers from reporting
  - `show`: Only report flows through specified sanitizers
- **Variable Scope Support**: Proper handling of local/global variable scoping

These extensions demonstrate deeper understanding of taint analysis and prepare for exam scenarios requiring tool adaptation.

## Authors

| <div align="center"><a href="https://github.com/tomasf18"><img src="https://avatars.githubusercontent.com/u/122024767?v=4" width="150px;" alt="Tomás Santos"/></a><br/><strong>Tomás Santos</strong><br/>116122<br/></div> | <div align="center"><a href="https://github.com/andrepires2211"><img src="https://avatars.githubusercontent.com/u/163666619?v=4" width="150px;" alt="André Pires"/></a><br/><strong>André Pires</strong><br/>116452<br/></div> | <div align="center"><img src="https://avatars.githubusercontent.com/u/163666619?v=4" width="150px;" alt="Guilherme Pais"/></a><br/><strong>Guilherme Pais</strong><br/>116496<br/></div> |
| --- | --- | --- |

---

**Note**: This is the delivered version of the course project. The `updated-version/` folder contains experimental extensions beyond the original specification.
