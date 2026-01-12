import copy

class Label:

    def __init__(self) -> None:
        # Structure: { 'source_name': [ (line, path_tuple), (line, path_tuple) ] }
        # This tracks each unique (line, path) combination
        self.flows: dict[str, list[tuple]] = {}

    def add_source(self, source_name: str, line_number: int) -> None:
        """Adds a new, raw (unsanitized) flow from a given source."""
        raw_flow_path = tuple()  # RAW flow represented as empty tuple
        
        if source_name not in self.flows:
            self.flows[source_name] = []
        
        new_flow_path = (line_number, raw_flow_path)
        if new_flow_path not in self.flows[source_name]:
            self.flows[source_name].append(new_flow_path)

    def add_sanitizer(self, sanitizer_name: str, line_no: int) -> None:
        """Applies a sanitizer to all existing flows."""
        new_flows: dict[str, list[tuple]] = {}

        for source, line_path_list in self.flows.items():
            new_source_line_path_list = []
            for (line, path) in line_path_list:
                # Convert path to set to remove duplicates, then back to sorted tuple
                sanitizers_set = set(path)  # Remove existing duplicates
                sanitizers_set.add((sanitizer_name, line_no))  # Add new sanitizer
                new_path = tuple(sanitizers_set)  # Convert back to tuple

                new_flow = (line, new_path)
                new_source_line_path_list.append(new_flow)

            new_flows[source] = new_source_line_path_list

        self.flows = new_flows

    # --- Selectors ---
    def get_flows(self) -> dict[str, list[tuple]]:
        """Selector for the entire flow structure."""
        return self.flows

    def get_sources(self) -> set[str]:
        """Selector for all unique source names in the label."""
        return set(self.flows.keys())

    def is_tainted(self) -> bool:
        """Check if the label has any unsanitized (raw) flows."""
        for line_path_list in self.flows.values():
            for (line, path) in line_path_list:
                if path == tuple():  # Raw flow
                    return True
        return False

    def is_tainted_by(self, source_name: str) -> bool:
        """Helper selector to check if tainted by a specific source."""
        if source_name not in self.flows:
            return False
        line_path_list = self.flows[source_name]
        for (line, path) in line_path_list:
            if path == tuple():
                return True
        return False

    # --- Combine ---
    def combine(self, other_label: 'Label') -> 'Label':
        """Returns a new label that combines two labels."""
        new_label = Label()
        new_label.flows = copy.deepcopy(self.flows)

        for source, other_line_path_list in other_label.get_flows().items():
            if source not in new_label.flows: # if this label doesn't have the source yet, and the other does
                new_label.flows[source] = copy.deepcopy(other_line_path_list)
            else:
                # merge the (line, path) lists
                for flow in other_line_path_list:
                    new_label.flows[source] = list(set(new_label.flows[source]) | {flow})
        return new_label

    def __repr__(self) -> str:
        """Provides a clean string representation for debugging."""
        parts = []
        for source in sorted(self.flows.keys()):
            line_path_list = self.flows[source]
            # Group by line for display
            line_groups = {}
            for (line, path) in line_path_list:
                if line not in line_groups:
                    line_groups[line] = []
                if not path:
                    line_groups[line].append("RAW")
                else:
                    line_groups[line].append(f"Sanitized_by({', '.join(str(s) for s in path)})")
            
            for line in sorted(line_groups.keys()):
                paths_str = ', '.join(line_groups[line])
                parts.append(f"\tSource='{source}' (line {line}): {{ {paths_str} }}")
        
        return "Label(\n" + "\n".join(parts) + "\n\t)"
    
    def __eq__(self, other):
        if not isinstance(other, Label):
            return False
        return self.flows == other.flows  # dict comparison