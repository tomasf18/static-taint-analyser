import copy
from tool.pattern import Pattern
from tool.label import Label
from tool.multilabel import MultiLabel

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

    def get_vulnerabilities_by_source(self, source_name: str) -> list[Pattern]:
        """
        Returns the names of vulnerabilities that have the given name as a source.
        """
        return [p for p in self.patterns if p.is_source(source_name)]

    def get_vulnerabilities_by_sanitizer(self, sanitizer_name: str) -> list[Pattern]:
        """
        Returns the names of vulnerabilities that have the given name as a sanitizer.
        """
        return [p for p in self.patterns if p.is_sanitizer(sanitizer_name)]

    def get_vulnerabilities_by_sink(self, sink_name: str) -> list[Pattern]:
        """
        Returns the names of vulnerabilities that have the given name as a sink.
        """
        return [p for p in self.patterns if p.is_sink(sink_name)]

    # --- Core Logic ---
    
    def add_source_to_all_patterns(self, source_name: str) -> None:
        """
        Adds the given source name to all patterns in the policy.
        """
        for pattern in self.patterns:
            pattern.sources.add(source_name)

    def add_source_to_all_implicit_patterns(self, source_name: str) -> None:
        """
        Adds the given source name to all patterns in the policy that have 
        implicit flows enabled.
        """
        for pattern in self.patterns:
            if pattern.is_implicit():
                pattern.sources.add(source_name)

    def detect_illegal_flows(self, sink_name: str, multi_label: MultiLabel) -> MultiLabel:
        """
        Determines corresponding illegal flows given a sink name and the 
        MultiLabel accumulating the history of a variable.

        Returns:
            A new MultiLabel containing ONLY the illegal flows.
        """
        multi_label_report = MultiLabel()

        for pattern in self.patterns:
            vuln_name = pattern.get_name()

            if not pattern.is_sink(sink_name):
                continue

            current_label = multi_label.get_label(vuln_name)
            if not current_label:
                continue

            illegal_label = Label()
            flows = current_label.get_flows()

            for source, line_path_list in flows.items():
                if not pattern.is_source(source):
                    continue
                
                for (source_line, path) in line_path_list:
                    # extract sanitizer names from path
                    sanitizer_names_in_path = set()
                    for item in path:
                        if isinstance(item, tuple) and len(item) == 2:
                            sanitizer_names_in_path.add(item[0])
                    
                    # check if ANY valid sanitizer was encountered
                    valid_sanitizers_encountered = sanitizer_names_in_path.intersection(pattern.get_sanitizers())
                    
                    if not valid_sanitizers_encountered:
                        print(f"[ILLEGAL FLOW - VULN '{vuln_name}'] From '{source}' line {source_line} to '{sink_name}' line {sink_name} without valid sanitization.")
                    
                    # add ALL paths (teachers want all, even sanitized)
                    if source not in illegal_label.flows:
                        illegal_label.flows[source] = []
                    illegal_label.flows[source].append((source_line, path))

            if illegal_label.get_flows():
                multi_label_report.add_pattern(pattern)
                multi_label_report.vulnerabilities[vuln_name] = (pattern, illegal_label)

        return multi_label_report

    def deepcopy(self) -> 'Policy':
        """
        Returns a deep copy of the Policy object.
        """
        copied_patterns = [p.deepcopy() for p in self.patterns]
        return Policy(copied_patterns)
    
    def __repr__(self) -> str:
        return f"Policy(patterns={self.patterns})"
    
    def __eq__(self, other):
        if not isinstance(other, Policy):
            return False
        
        if len(self.patterns) != len(other.patterns):
            return False
        
        for p1, p2 in zip(self.patterns, other.patterns):
            if p1 != p2:
                return False
        
        return True