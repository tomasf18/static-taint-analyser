import copy
from pattern import Pattern
from label import Label
from multilabel import MultiLabel

class Policy:
    """
    Represents an information flow policy.
    It uses a database of patterns to recognize and detect illegal 
    information flows.
    """

    def __init__(self, patterns: list[Pattern]) -> None:
        """
        Constructor of a Policy object.
        Receives as input the list of patterns to be considered.
        """
        self.patterns = patterns

    # --- Selectors ---

    def get_vulnerabilities_by_source(self, source_name: str) -> list[str]:
        """
        Returns the names of vulnerabilities that have the given name as a source.
        """
        return [p.get_name() for p in self.patterns if p.is_source(source_name)]

    def get_vulnerabilities_by_sanitizer(self, sanitizer_name: str) -> list[str]:
        """
        Returns the names of vulnerabilities that have the given name as a sanitizer.
        """
        return [p.get_name() for p in self.patterns if p.is_sanitizer(sanitizer_name)]

    def get_vulnerabilities_by_sink(self, sink_name: str) -> list[str]:
        """
        Returns the names of vulnerabilities that have the given name as a sink.
        """
        return [p.get_name() for p in self.patterns if p.is_sink(sink_name)]

    # --- Core Logic ---

    def detect_illegal_flows(self, sink_name: str, multi_label: MultiLabel) -> MultiLabel:
        """
        Determines corresponding illegal flows given a sink name and the 
        MultiLabel accumulating the history of a variable.

        It checks, for each pattern:
        1. Is the given 'sink_name' actually a sink for this pattern?
        2. If yes, are there flows in the label that reached this point 
           without passing through a valid sanitizer for this pattern?

        Returns:
            A new MultiLabel containing ONLY the illegal flows.
        """
        # Initialize a new MultiLabel to hold the report.
        # We use the same patterns defined in this policy.
        multi_label_report = MultiLabel(self.patterns)

        for pattern in self.patterns:
            vuln_name = pattern.get_name()

            # 1. Check if this operation is a sensitive sink for this specific pattern
            if not pattern.is_sink(sink_name):
                continue

            # 2. Retrieve the data history (Label) for this pattern
            current_label = multi_label.get_label(vuln_name)
            if not current_label or not current_label.is_tainted():
                continue

            # 3. Analyze flows to find illegal paths
            # We need to construct a specific Label containing only the bad paths
            illegal_label = Label()
            
            # Access flows directly: dict[source, set[frozenset[sanitizers]]]
            flows = current_label.get_flows()

            for source, paths in flows.items():
                # Double check: Is this source relevant to the pattern?
                # (MultiLabel logic usually ensures this, but safety first)
                if not pattern.is_source(source):
                    continue
                
                illegal_paths = set()

                for path in paths:
                    # path is a frozenset of sanitizer names encountered.
                    # valid_sanitizers is the set of sanitizers allowed by the pattern.
                    
                    # Check intersection: Did we hit ANY valid sanitizer?
                    # If the intersection is empty, the flow is ILLEGAL (Raw or wrong sanitizer).
                    valid_sanitizers_encountered = path.intersection(pattern.get_sanitizers())
                    
                    if not valid_sanitizers_encountered:
                        # This is an illegal flow!
                        illegal_paths.add(path)

                # If we found illegal paths for this source, add them to our report label
                if illegal_paths:
                    illegal_label.flows[source] = illegal_paths

            # 4. If the illegal_label is not empty, add it to the MultiLabel report
            if illegal_label.is_tainted():
                multi_label_report.vulnerabilities[vuln_name] = (pattern, illegal_label)

        return multi_label_report

# --- Example Usage ---
if __name__ == "__main__":
    
    # 1. Setup Patterns
    xss_pattern = Pattern(
        vulnerability_name="XSS",
        possible_sources={"$_GET"},
        sink_names={"echo", "print"},
        sanitizer_names={"escape_html"},
    )
    
    sqli_pattern = Pattern(
        vulnerability_name="SQL Injection",
        possible_sources={"$_GET", "$_POST"},
        sink_names={"mysql_query"},
        sanitizer_names={"mysql_escape"},
    )

    all_patterns = [xss_pattern, sqli_pattern]

    # 2. Initialize Policy
    policy = Policy(all_patterns)

    print("--- Testing Selectors ---")
    print(f"Vulns with source '$_GET':      {policy.get_vulnerabilities_by_source('$_GET')}")
    print(f"Vulns with sink 'mysql_query':  {policy.get_vulnerabilities_by_sink('mysql_query')}")

    # 3. Create a Scenario
    # Scenario: Data comes from $_GET, is sanitized by 'escape_html', 
    # and is then passed to 'mysql_query'.
    
    print("\n--- $var = None    # initializing the variable (untainted) ---")
    variable_label = MultiLabel()
    print(variable_label)
    
    # Step A: Taint
    print("\n--- $var = $_GET    # tainting $var with source $_GET ---")
    variable_label.add_patterns(all_patterns)
    variable_label.add_source("$_GET")
    print(variable_label)
    
    # Step B: Sanitize (escape_html is valid for XSS, but NOT for SQLi)
    print("\n--- $var = escape_html($var)    # sanitizing $var (escape_html is valid for XSS, but NOT for SQLi) ---")
    variable_label.add_sanitizer("escape_html")
    print(variable_label)

    # 4. Detect Illegal Flows at Sinks
    
    # Case A: Passed to 'echo' (XSS Sink)
    # Expected: Safe, because it was sanitized by escape_html
    print(f"\n--- echo $var    # (XSS Sink) ---")
    report_echo = policy.detect_illegal_flows("echo", variable_label)
    print(report_echo) 
    # Should be Untainted because escape_html fixed the XSS risk.

    # Case B: Passed to 'mysql_query' (SQLi Sink)
    # Expected: Illegal! $_GET is a source for SQLi, and escape_html is NOT a valid sanitizer for SQLi.
    print(f"\n--- mysql_query($var)    # (SQLi Sink) ---")
    report_sql = policy.detect_illegal_flows("mysql_query", variable_label)
    print(report_sql)
    # Should show SQL Injection vulnerability.