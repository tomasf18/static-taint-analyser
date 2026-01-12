import copy

from tool.pattern import Pattern
from tool.label import Label

class MultiLabel:
    """
    Generalizes the Label class to be able to represent distinct labels
    corresponding to different vulnerability patterns.
    """
    def __init__(self, patterns_to_track: list[Pattern] | None = None) -> None:
        """
        Constructor: Initializes a new, untainted MultiLabel.
        It creates an empty Label for each vulnerability pattern
        it needs to track.
        """
        # Data structure: { "vuln_name": (Pattern, Label) }
        self.vulnerabilities: dict[str, tuple[Pattern, Label]] = {}
        if patterns_to_track:
            for pattern in patterns_to_track:
                self.vulnerabilities[pattern.get_name()] = (pattern, Label())
            
    def add_pattern(self, pattern: Pattern) -> None:
        """
        Adds a new vulnerability pattern to be tracked,
        initializing its Label as untainted.
        """
        if pattern.get_name() not in self.vulnerabilities:
            self.vulnerabilities[pattern.get_name()] = (pattern, Label())
            
    def add_patterns(self, patterns: list[Pattern]) -> None:
        """
        Adds multiple vulnerability patterns to be tracked,
        initializing their Labels as untainted.
        """
        for pattern in patterns:
            if pattern.get_name() not in self.vulnerabilities:
                self.add_pattern(pattern)

    def add_source(self, source_name: str, line_number: int, col_number: int) -> None:
        for pattern, label in self.vulnerabilities.values():
            if pattern.is_source(source_name):
                label.add_source(source_name, line_number, col_number)

    def add_sanitizer(self, sanitizer_name: str, line_number: int) -> None:
        for pattern, label in self.vulnerabilities.values():
            if pattern.is_sanitizer(sanitizer_name):
                label.add_sanitizer(sanitizer_name, line_number)

    def combine(self, other_multi_label: 'MultiLabel') -> 'MultiLabel':
        """
        combine: Returns a new MultiLabel that merges the labels from
        'self' and 'other_multi_label' for each tracked vulnerability.
        """
        # Identify all unique pattern names involved in either label
        self_vulns = self.vulnerabilities
        other_vulns = other_multi_label.vulnerabilities
        all_keys = set(self_vulns.keys()) | set(other_vulns.keys())
        
        # Create result container (initially empty)
        new_multi_label = MultiLabel()
        
        for name in all_keys:
            if name in self_vulns and name in other_vulns:
                # Case 1: Both track this vulnerability -> Combine them
                pattern, self_label = self_vulns[name]
                _, other_label = other_vulns[name]
                
                combined_label = self_label.combine(other_label)
                new_multi_label.vulnerabilities[name] = (pattern, combined_label)
            
            elif name in self_vulns:
                # Case 2: Only self tracks it -> Deep copy self
                pattern, label = self_vulns[name]
                new_multi_label.vulnerabilities[name] = (pattern, copy.deepcopy(label))
            
            else:
                # Case 3: Only other tracks it -> Deep copy other
                pattern, label = other_vulns[name]
                new_multi_label.vulnerabilities[name] = (pattern, copy.deepcopy(label))
        
        return new_multi_label

    # --- Selectors ---
    
    def get_patterns_labels(self) -> list[tuple[Pattern, Label]]:
        """Selector for the list of (Pattern, Label) tuples being tracked."""
        return list(self.vulnerabilities.values())
    
    def set_vulnerability_label(self, vulnerability_name: str, label: Label) -> None:
        """Setter for updating the Label of a specific vulnerability."""
        if vulnerability_name in self.vulnerabilities:
            pattern = self.vulnerabilities[vulnerability_name][0]
            self.vulnerabilities[vulnerability_name] = (pattern, label)
        else:
            print(f"Vulnerability '{vulnerability_name}' is not being tracked.")

    def get_patterns(self) -> list[Pattern]:
        """Selector for the list of patterns being tracked."""
        return [pattern for pattern, _ in self.vulnerabilities.values()]

    def get_label(self, vulnerability_name: str) -> Label | None:
        """Selector for the specific Label of one vulnerability."""
        if vulnerability_name in self.vulnerabilities:
            return self.vulnerabilities[vulnerability_name][1]
        return None

    def is_tainted(self) -> bool:
        """Helper selector to check if any tracked label is tainted."""
        return any(label.is_tainted() for _, label in self.vulnerabilities.values())

    def __repr__(self) -> str:
        """Provides a clean string representation for debugging."""
        if not self.is_tainted():
            return "MultiLabel(Untainted)"
        
        parts = []
        for vuln_name in sorted(self.vulnerabilities.keys()):
            pattern, label = self.vulnerabilities[vuln_name]
            if label.get_flows():
                parts.append(f"  [{pattern.get_name()}]: {label}")
        
        return "MultiLabel(\n" + "\n".join(parts) + "\n)"
    
    def __eq__(self, other):
        if not isinstance(other, MultiLabel):
            return False
        
        if set(self.vulnerabilities.keys()) != set(other.vulnerabilities.keys()):
            return False
        
        for name in self.vulnerabilities:
            pattern_self, label_self = self.vulnerabilities[name]
            pattern_other, label_other = other.vulnerabilities[name]
            if pattern_self != pattern_other or label_self != label_other:
                return False
        
        return True