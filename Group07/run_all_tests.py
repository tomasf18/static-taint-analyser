#!/usr/bin/env python3
"""
Script to run all validation tests for test cases in slices/ directories 1-9
"""

import subprocess
import glob
from pathlib import Path

def run_py_analyser(py_file, patterns_file):
    """Run py_analyser.py to generate/update output files"""
    test_name = Path(py_file).stem
    print(f"\n{'='*80}")
    print(f"Analyzing: {test_name}")
    print(f"{'='*80}")
    
    cmd = [
        "python3", "py_analyser.py",
        py_file,
        patterns_file
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return result.returncode == 0
    except Exception as e:
        print(f"ERROR running py_analyser: {e}")
        return False

def run_validation_test(test_name, slice_path, output_path):
    """Run validation for a single test case"""
    print(f"\n{'='*80}")
    print(f"Testing: {test_name}")
    print(f"{'='*80}")
    
    cmd = [
        "python3", "validate.py",
        "-o", output_path,
        "-t", slice_path
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print("-"*20 + " RESULT FROM TEST " + "-"*20)
        print(result.stdout)   
        print("-"*60) 
        if "MISSING" in result.stdout or "WRONG" in result.stdout:
            print(f"[FAILED] {test_name}")
            return False
        else:
            print(f"[PASSED] {test_name}")
            return True
    except Exception as e:
        print(f"ERROR running test: {e}")
        return False

def main():
    """Main function to run all tests"""
    base_dir = Path(__file__).parent
    slices_dir = base_dir / "slices"
    output_dir = base_dir / "output"
    
    # Find all .py files in slices directories (these are the analysis targets)
    py_files = []
    for i in range(1, 10):  # Folders 1-9
        pattern1 = f"{slices_dir}/{i}-*/*.py"
        py_files.extend(glob.glob(pattern1))

    # Collect T07 cases once (not once per i)
    py_files.extend(glob.glob(f"{slices_dir}/T07/*/*.py"))
    
    # Sort for consistent ordering
    py_files.sort()
    
    if not py_files:
        print("No Python files found!")
        return
    
    print(f"\n{'='*80}")
    print(f"PHASE 1: RUNNING PY_ANALYSER FOR {len(py_files)} TEST CASE(S)")
    print(f"{'='*80}")
    
    # First, run py_analyser for all files to generate/update outputs
    analyser_passed = 0
    analyser_failed = 0
    
    for py_file in py_files:
        py_path = Path(py_file)
        patterns_file = py_path.with_suffix(".patterns.json")
        
        if not patterns_file.exists():
            print(f"[SKIPPED] {py_path.stem} - patterns file not found: {patterns_file}")
            continue
        
        success = run_py_analyser(str(py_path), str(patterns_file))
        if success:
            analyser_passed += 1
        else:
            analyser_failed += 1
    
    print(f"\n{'='*80}")
    print(f"PY_ANALYSER SUMMARY: {analyser_passed} passed, {analyser_failed} failed")
    print(f"{'='*80}")
    
    # Now find all test output files for validation
    test_files = []
    for i in range(1, 10):  # Folders 1-9
        pattern1 = f"{slices_dir}/{i}-*/*.output.json"
        test_files.extend(glob.glob(pattern1))

    # Collect T07 outputs once
    test_files.extend(glob.glob(f"{slices_dir}/T07/*/*.output.json"))
    
    # Sort test files for consistent ordering
    test_files.sort()
    
    if not test_files:
        print("No test files found for validation!")
        return
    
    print(f"\n{'='*80}")
    print(f"PHASE 2: RUNNING VALIDATION TESTS FOR {len(test_files)} TEST CASE(S)")
    print(f"{'='*80}")
    
    # Track validation results
    passed = 0
    failed = 0
    skipped = 0
    
    print(f"Test files: {test_files}")
    
    for test_file_path in test_files:
        test_file = Path(test_file_path)
        test_name = test_file.stem  # e.g., "1a-basic-flow"
        
        # Check if corresponding output file exists
        output_file = output_dir / f"{test_name}.json"
        
        if not output_file.exists():
            print(f"\n[SKIPPED] {test_name} - output file not found: {output_file}")
            skipped += 1
            continue
        
        # Run the test
        success = run_validation_test(test_name, str(test_file), str(output_file))
        
        if success:
            passed += 1
        else:
            failed += 1
    
    # Print summary
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    print(f"Total tests: {len(test_files)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Skipped: {skipped}")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()
