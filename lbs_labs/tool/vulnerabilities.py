import copy
from pattern import Pattern
from label import Label
from multilabel import MultiLabel
from policy import Policy 

class Vulnerabilities:
    """
    Collects and organizes illegal information flows discovered during 
    program analysis.
    """

    def __init__(self) -> None:
        """
        Constructor of a Vulnerabilities object.
        
        Initializes a structure to collect relevant info on illegal flows,
        organized by vulnerability names.
        """
        # Structure: { "Vulnerability Name": [ list_of_incident_details ] }
        self.detected_vulnerabilities: dict[str, list[dict]] = {}

    def add_vulnerability(self, sink_name: str, illegal_flows: MultiLabel) -> None:
        """
        Operation that takes a sink name and a MultiLabel representing 
        detected illegal flows, and saves them for reporting.
        """
        # Retrieve all (Pattern, Label) pairs from the MultiLabel
        vuln_list = illegal_flows.get_patterns_labels()

        for pattern, label in vuln_list:
            # We must check if this specific pattern actually recorded an illegal flow.
            # Since MultiLabel initializes all patterns by default in the constructor, some might be empty.
            if not label.is_tainted():
                continue

            vuln_name = pattern.get_name()

            incident_record = {
                "sink": sink_name,
                "sources": list(label.get_sources()),
                "flows": label.get_flows() 
            }

            if vuln_name not in self.detected_vulnerabilities:
                self.detected_vulnerabilities[vuln_name] = []

            self.detected_vulnerabilities[vuln_name].append(incident_record)

    def __repr__(self) -> str:
        """
        Generates a human-readable report of all collected vulnerabilities.
        """
        if not self.detected_vulnerabilities:
            return "No vulnerabilities detected."

        report_lines = ["--- Vulnerability Report ---"]
        
        for vuln_name, incidents in self.detected_vulnerabilities.items():
            report_lines.append(f"\n[Vulnerability]: {vuln_name}")
            
            for i, incident in enumerate(incidents, 1):
                sink = incident['sink']
                sources = incident['sources']
                flows = incident['flows']
                
                report_lines.append(f"  Incident #{i}:")
                report_lines.append(f"    Sink: '{sink}'")
                report_lines.append(f"    Sources Involved: {sources}")
                
                # Detail the specific bad paths
                report_lines.append(f"    Illegal Paths:")
                for source, paths in flows.items():
                    for path in paths:
                        sanitizers = ", ".join(path) if path else "None (Raw Flow)"
                        report_lines.append(f"      - From '{source}' via sanitizers: [{sanitizers}]")

        return "\n".join(report_lines)


# --- Example Usage ---
if __name__ == "__main__":
    
    # 1. Setup Patterns
    xss_pattern = Pattern("XSS", {"$_GET"}, {"echo"}, {"escape_html"})
    sqli_pattern = Pattern("SQL Injection", {"$_GET", "$_POST"}, {"mysql_query"}, {"mysql_escape"})
    all_patterns = [xss_pattern, sqli_pattern]

    # 2. Initialize Helper Classes
    policy = Policy(all_patterns)
    vulnerabilities_log = Vulnerabilities()

    # 3. Simulation Scenario
    # Variable $bad_input comes from $_GET, passes through 'escape_html'.
    # This makes it safe for XSS, but ILLEGAL for SQL Injection.
    
    print("--- Simulating Analysis ---")
    
    print(" --- $var = None --- ")
    var_label = MultiLabel()
    print(var_label)    
    
    # Create the MultiLabel for the variable
    print("\n --- $var = $_GET --- ")
    var_label = MultiLabel(all_patterns)
    var_label.add_source("$_GET")
    print(var_label)
    
    print("\n --- $var = escape_html($var) --- ")
    var_label.add_sanitizer("escape_html")
    print(var_label)
    
    # 4. Analyze Sink: 'mysql_query'
    # The policy will detect that 'escape_html' is NOT a valid sanitizer for SQLi.
    print("\n --- mysql_query($var) --- ")
    print("Analyzing sink 'mysql_query'...")
    illegal_flows = policy.detect_illegal_flows("mysql_query", var_label)
    print(illegal_flows)
    
    # If the resulting MultiLabel is tainted, it means we found bugs.
    if illegal_flows.is_tainted():
        # 5. Log the vulnerability
        vulnerabilities_log.add_vulnerability("mysql_query", illegal_flows)

    # 6. Analyze Sink: 'echo'
    # The policy should see 'escape_html' and return an empty/untainted label.
    print("\n --- echo($var) --- ")
    print("Analyzing sink 'echo'...")
    illegal_flows_echo = policy.detect_illegal_flows("echo", var_label)
    print(illegal_flows_echo)
    
    if illegal_flows_echo.is_tainted():
        vulnerabilities_log.add_vulnerability("echo", illegal_flows_echo)

    # 7. Final Report
    print("\n" + "="*30)
    print(vulnerabilities_log)
    print("="*30)