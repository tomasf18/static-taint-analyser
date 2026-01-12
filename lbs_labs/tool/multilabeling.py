import copy
from pattern import Pattern
from multilabel import MultiLabel

class MultiLabelling:
    """
    Represents a mapping from variable names to multilabels.
    
    This class acts as the environment state for the information flow analysis,
    tracking the current security levels of all variables in the program scope.
    """

    def __init__(self) -> None:
        """
        Constructor of a MultiLabelling object
        """
        # The mapping structure: { "variable_name": MultiLabel_object }
        self.variable_map: dict[str, MultiLabel] = {}

    # --- Selectors ---

    def get_multilabel(self, variable_name: str) -> MultiLabel | None:
        """
        Returns the multilabel assigned to a given variable name.
        """
        if variable_name not in self.variable_map:
            print(f"Variable '{variable_name}' not found. Please add it first with the corresponding patterns.")
            return
        
        return self.variable_map[variable_name]

    # --- Mutators ---

    def update_multilabel(self, variable_name: str, multilabel: MultiLabel) -> None:
        """
        Updates the multilabel assigned to a specific variable name.
        
        This is used when a variable is assigned a new value (e.g., x := y),
        updating its security history.
        """
        self.variable_map[variable_name] = multilabel

    def __repr__(self) -> str:
        """Provides a clean string representation of the entire program state."""
        if not self.variable_map:
            return "MultiLabelling(Empty)"
        
        parts = []
        for var_name in sorted(self.variable_map.keys()):
            label = self.variable_map[var_name]
            # For brevity, only show variables that are actually tainted
            if label.is_tainted():
                # Indent the MultiLabel representation for readability
                label_str = str(label).replace("\n", "\n    ")
                parts.append(f"'{var_name}': {label_str}")
            else:
                parts.append(f"'{var_name}': Untainted")
        
        return "MultiLabelling(\n  " + "\n  ".join(parts) + "\n)"


# --- Example Usage ---
if __name__ == "__main__":
    
    # 1. Define the vulnerability patterns to track
    xss_pattern = Pattern(
        vulnerability_name="XSS",
        sources={"$_GET"},
        sink_names={"echo"},
        sanitizer_names={"escape_html"},
    )
    
    sqli_pattern = Pattern(
        vulnerability_name="SQL Injection",
        sources={"$_GET", "$_POST"},
        sink_names={"mysql_query"},
        sanitizer_names={"mysql_escape"},
    )
    all_patterns = [xss_pattern, sqli_pattern]

    # 2. Initialize the Labelling Environment (The "Memory")
    labelling_map = MultiLabelling()

    print("--- Initial State ---")
    print(labelling_map)

    # 3. Simulate: $input = $_GET['user'];
    print("\n--- $input = $_GET['user']; ---")
    # Logic:
    #   a. Create a new MultiLabel tracking the specific patterns.
    #   b. Taint it with the source '$_GET'.
    #   c. Assign it to variable '$input'.
    expr_label = MultiLabel(all_patterns)
    expr_label.add_source("$_GET")
    
    labelling_map.update_multilabel("$input", expr_label)
    
    # Verify individual state
    print(labelling_map.get_multilabel("$input"))


    # 4. Simulate: $clean = escape_html($input);
    print("\n--- $clean = escape_html($input); ---")
    # Logic: 
    #   a. Retrieve label of argument '$input'.
    #   b. Copy it (since $input itself isn't changing, we are creating a new value).
    #   c. Apply sanitizer to the copy.
    #   d. Assign the result to '$clean'.
    
    input_label = labelling_map.get_multilabel("$input")
    
    # We must check if input_label exists before using it
    if input_label:
        result_label = copy.deepcopy(input_label)
        result_label.add_sanitizer("escape_html")
        
        labelling_map.update_multilabel("$clean", result_label)
        print(labelling_map.get_multilabel("$clean"))


    # 5. Simulate: $query = "SELECT..." . $input; (Unsafe usage)
    print("\n--- $query = 'SELECT...' . $input; ---")
    # Logic:
    #   a. Retrieve label of $input (string concatenation propagates taint).
    #   b. Update map for '$query'.
    
    if input_label:
        # Simplification: reusing input_label directly as concatenation result
        labelling_map.update_multilabel("$query", input_label)
    
    
    # 6. Final Program State
    print("\n--- Final Program Analysis State ---")
    print(labelling_map)
    
    # Notice: 
    # $input is tainted for both XSS and SQLi.
    # $clean is Safe for XSS, but still Tainted for SQLi.
    # $query is tainted for both.