import copy

class Label:
    """
    Represents the integrity of information that is carried by a resource.

    It captures the sources that might have influenced a certain piece
    of information, and which sanitizers might have intercepted the
    information since its flow from each source.

    The internal structure is a dictionary mapping a source (str) to a
    set of frozensets (each frozenset represents a unique sanitizer path).
    Example:
    {
        '$_GET': { frozenset(), frozenset({'escape_html'}) },
        '$_POST': { frozenset() }
    }
    This represents info influenced by:
    - $_GET (raw, unsanitized)
    - $_GET (sanitized by 'escape_html')
    - $_POST (raw, unsanitized)
    """

    def __init__(self) -> None:
        """
        Constructor of a Label object.
        Initializes an empty (untainted) label.
        """
        # The structure is: { 'source_name': {frozenset_of_sanitizers_1, ...} } -> The value for each source is a set, because a variable might be influenced by the same source through multiple different paths.
        self.flows: dict[str, set[frozenset[str]]] = {}

    def add_source(self, source_name: str) -> None:
        """
        Adds a new, raw (unsanitized) flow from a given source.
        This mutates the label.
        """
        # A raw flow is represented by a path with an empty set of sanitizers.
        raw_flow_path = frozenset()

        if source_name not in self.flows:
            # First time we see this source
            self.flows[source_name] = {raw_flow_path}
        else:
            # Source exists; add this new raw path to its set of paths
            self.flows[source_name].add(raw_flow_path)

    def add_sanitizer(self, sanitizer_name: str) -> None:
        """
        Applies a sanitizer to all existing flows in this label.
        This mutates the label, updating every flow path.
        """
        new_flows: dict[str, set[frozenset[str]]] = {}
        for source, paths in self.flows.items():
            new_paths = set()
            for path in paths:
                # Create a new path by adding the sanitizer
                # We convert to list, add, then convert back to frozenset
                new_path_list = list(path)
                new_path_list.append(sanitizer_name)
                new_paths.add(frozenset(new_path_list))
            
            # This source is now associated with the new set of sanitized paths
            new_flows[source] = new_paths
        
        # Mutate the label's state
        self.flows = new_flows

    # --- Selectors ---

    def get_flows(self) -> dict[str, set[frozenset[str]]]:
        """Selector for the entire flow structure."""
        return self.flows

    def get_sources(self) -> set[str]:
        """Selector for all unique source names in the label."""
        return set(self.flows.keys())

    def is_tainted(self) -> bool:
        """Helper selector to check if the label is tainted at all, by checking if any source exists associated with this label/variable."""
        return bool(self.flows)

    def is_tainted_by(self, source_name: str) -> bool:
        """Helper selector to check if tainted by a specific source."""
        return source_name in self.flows

    # --- Combinor ---

    def combinor(self, other_label: 'Label') -> 'Label':
        """
        Returns a new label that represents the integrity of information
        resulting from combining two pieces of information.

        (Note) The new label is independent of the original ones.
        """
        # 1. Create a new, independent label
        # Start by deep-copying our own flows
        new_label = Label()
        new_label.flows = copy.deepcopy(self.flows)

        # 2. Merge in the other_label's flows
        for source, other_paths in other_label.flows.items():
            if source not in new_label.flows:
                # This source is new, just add it (deep copy)
                new_label.flows[source] = copy.deepcopy(other_paths)
            else:
                # Source already exists, union the sets of paths
                # .update() merges the 'other_paths' set into our existing set
                new_label.flows[source].update(other_paths)
        
        return new_label

    def __repr__(self) -> str:
        """Provides a clean string representation for debugging."""
        if not self.is_tainted():
            return "Label(Untainted)"
        
        parts = []
        for source, paths in sorted(self.flows.items()):
            path_strs = []
            for path in sorted(paths, key=len): # Sort paths for consistent output
                if not path:
                    path_strs.append("RAW")
                else:
                    path_strs.append(f"Sanitized_by({', '.join(sorted(path))})")
            parts.append(f"  Source='{source}': {{ {', '.join(path_strs)} }}")
        
        return "Label(\n" + "\n".join(parts) + "\n)"

# --- Example Usage ---
if __name__ == "__main__":
    
    # 1. Variable 'a' gets raw input from $_GET
    # $a = $_GET['user'];
    label_a = Label()
    label_a.add_source("$_GET")
    print(f"--- Label A ---\n{label_a}")

    # 2. Variable 'b' is a sanitized version of 'a'
    # $b = escape_html($a);
    label_b = copy.deepcopy(label_a) # Start with 'a's label
    label_b.add_sanitizer("escape_html")
    print(f"--- Label B (Sanitized A) ---\n{label_b}")
    
    # 3. Variable 'c' combines the raw input 'a' and sanitized input 'b'
    # $c = $a . $b;
    label_c = label_a.combinor(label_b)
    print(f"--- Label C (A + B) ---\n{label_c}")

    # 4. Variable 'd' gets raw input from $_POST
    # $d = $_POST['pass'];
    label_d = Label()
    label_d.add_source("$_POST")
    print(f"--- Label D ---\n{label_d}")
    
    # 5. Variable 'e' combines 'c' and 'd'
    # $e = $c . $d;
    label_e = label_c.combinor(label_d)
    print(f"--- Label E (C + D) ---\n{label_e}")
    
    # 6. Variable 'f' is a sanitized version of 'e'
    # $f = mysql_escape($e);
    label_f = copy.deepcopy(label_e)
    label_f.add_sanitizer("mysql_escape")
    print(f"--- Label F (Sanitized E) ---\n{label_f}")