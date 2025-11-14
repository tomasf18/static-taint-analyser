import copy

from pattern import Pattern
from label import Label

class MultiLabel:
    """
    Generalizes the Label class to be able to represent distinct labels
    corresponding to different vulnerability patterns.
    """

    def __init__(self, patterns_to_track: list[Pattern]) -> None:
        """
        Constructor: Initializes a new, untainted MultiLabel.
        It creates an empty Label for each vulnerability pattern
        it needs to track.
        """
        # Data structure: { "vuln_name": (Pattern, Label) }
        self.vulnerabilities: dict[str, tuple[Pattern, Label]] = {}
        for pattern in patterns_to_track:
            self.vulnerabilities[pattern.get_name()] = (pattern, Label())

    def add_source(self, source_name: str) -> None:
        """
        Adds a source taint, but *only* to the labels for
        patterns that recognize this name as a source.
        """
        for pattern, label in self.vulnerabilities.values():
            if pattern.is_source(source_name):
                label.add_source(source_name)

    def add_sanitizer(self, sanitizer_name: str) -> None:
        """
        Applies a sanitizer, but *only* to the labels for
        patterns that recognize this name as a sanitizer.
        """
        for pattern, label in self.vulnerabilities.values():
            if pattern.is_sanitizer(sanitizer_name):
                label.add_sanitizer(sanitizer_name)

    def combinor(self, other_multi_label: 'MultiLabel') -> 'MultiLabel':
        """
        Combinor: Returns a new MultiLabel that merges the labels from
        'self' and 'other_multi_label' for each tracked vulnerability.
        
        Note: This assumes both MultiLabel objects were initialized with the
        same set of patterns.
        """
        # Create a new, empty MultiLabel with the same patterns
        current_patterns = self.get_patterns()
        new_multi_label = MultiLabel(current_patterns)

        # Manually combine the labels for each vulnerability
        for vuln_name, (pattern, self_label) in self.vulnerabilities.items():
            # Get the corresponding label from the other object
            # (This will raise a KeyError if patterns don't match)
            other_label = other_multi_label.vulnerabilities[vuln_name][1]

            # Use the Label's combinor to merge them
            combined_label = self_label.combinor(other_label)

            # Store the new combined label in the new MultiLabel
            new_multi_label.vulnerabilities[vuln_name] = (pattern, combined_label)

        return new_multi_label

    # --- Selectors ---

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
            if label.is_tainted():
                parts.append(f"  [{pattern.get_name()}]: {label}")
        
        return "MultiLabel(\n" + "\n".join(parts) + "\n)"


# --- Example Usage ---
if __name__ == "__main__":

    # 1. Define the vulnerability patterns to track
    xss_pattern = Pattern(
        vulnerability_name="XSS",
        possible_sources={"$_GET"},
        sink_names={"echo"},
        sanitizer_names={"escape_html"},
    )
    
    sqli_pattern = Pattern(
        vulnerability_name="SQL Injection",
        possible_sources={"$_GET", "$_POST"},
        sink_names={"mysql_query"},
        sanitizer_names={"mysql_escape"},
    )

    all_patterns = [xss_pattern, sqli_pattern]

    # 2. Simulate variable '$a' getting $_GET
    # $a = $_GET['user'];
    print("--- $a = $_GET['user']; ---")
    label_a = MultiLabel(all_patterns)
    label_a.add_source("$_GET") # '$_GET' is a source for BOTH patterns
    print(label_a)
    # This correctly taints BOTH the XSS label and the SQLi label.

    # 3. Simulate variable '$b' getting $_POST
    # $b = $_POST['pass'];
    print("\n--- $b = $_POST['pass']; ---")
    label_b = MultiLabel(all_patterns)
    label_b.add_source("$_POST") # '$_POST' is a source ONLY for SQLi
    print(label_b)
    # This correctly taints ONLY the SQLi label.

    # 4. Simulate variable '$c' being a sanitized version of '$a'
    # $c = escape_html($a);
    print("\n--- $c = escape_html($a); ---")
    label_c = copy.deepcopy(label_a)
    label_c.add_sanitizer("escape_html") # 'escape_html' is a sanitizer ONLY for XSS
    print(label_c)
    # This correctly sanitizes the XSS label, but leaves the SQLi label raw.

    # 5. Simulate variable '$d' combining '$b' and '$c'
    # $d = $b . $c;
    print("\n--- $d = $b . $c; ---")
    label_d = label_b.combinor(label_c)
    print(label_d)
    # The final label shows:
    # - XSS is tainted *only* by $_GET and is sanitized.
    # - SQLi is tainted by $_POST (raw) and $_GET (raw).