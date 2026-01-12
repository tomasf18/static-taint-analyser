from tool.pattern import Pattern
from tool.multilabel import MultiLabel
from tool.policy import Policy


class Vulnerabilities:
    """
    Collects and organizes illegal information flows discovered during
    program analysis.
    """

    def __init__(self) -> None:
        """
        Constructor of a Vulnerabilities object.
        """
        # dictionary mapping (vuln_name, source_name, source_line, sink_name, sink_line) to (numbered_name, flows_tuple)
        self.detected_vulnerabilities: dict = {}
        # counter for each vulnerability pattern to track numbering
        self.vulnerability_counters: dict[str, int] = {}
        # maintains the order in which patterns first hit a sink
        self.pattern_order: list[str] = []

    def add_vulnerability(self, sink_name: str, sink_line_number: int, sink_col_number: int, illegal_flows: MultiLabel, flow_type: str = "explicit") -> None:
        """
        Operation that takes a sink name and a MultiLabel representing
        detected illegal flows, and saves them for reporting.

        Args:
            sink_name: The name of the sink where the flow ends
            line_number: The line number of the sink
            illegal_flows: MultiLabel containing all the illegal flows
            flow_type: Either "explicit" or "implicit"
        """
        for pattern, label in illegal_flows.get_patterns_labels():
            # FILTER: Only add implicit flows if the pattern allows them
            if flow_type == "implicit" and not pattern.is_implicit():
                print(f"[DEBUG] Skipping implicit flow for pattern '{pattern.get_name()}' (implicit_flows=False)")
                continue
            
            self._process_flows_for_pattern(pattern, label.get_flows(), sink_name, sink_line_number, sink_col_number, flow_type)

    def _record_pattern_discovery(self, vuln_name: str) -> None:
        """Record the discovery order of a pattern."""
        if vuln_name not in self.pattern_order:
            self.pattern_order.append(vuln_name)

    def _process_flows_for_pattern(self, pattern: Pattern, flows_dict: dict, sink_name: str, sink_line: int, sink_col: int, flow_type: str) -> None:
        """Process all flows for a given vulnerability pattern."""
        for source_name, linecol_path_list in flows_dict.items():
            paths_by_source_line = self._group_paths_by_source_line(linecol_path_list)

            for (source_line, source_col), paths in paths_by_source_line.items():
                paths_without_sanitizers_to_omit = set()
                for path in paths:
                    print("TESTING PATH: ", path)
                    if len(path) == 0:
                        paths_without_sanitizers_to_omit.add(path)
                    else:
                        filtered_source_path = set()
                        for (sanitizer_name, line) in path: # (sanitizer_name, line), i.e., it's not a RAW flow
                            if pattern.show_sanitizer(sanitizer_name):
                                filtered_source_path.add((sanitizer_name, line)) 
                        filtered_source_path = tuple(filtered_source_path)
                        if len(filtered_source_path) > 0:
                            paths_without_sanitizers_to_omit.add(filtered_source_path) # otherwise all paths are to omit

                paths_without_sanitizers_to_omit = tuple(paths_without_sanitizers_to_omit)
                if len(paths_without_sanitizers_to_omit) == 0:
                    continue
                    
                self._record_pattern_discovery(pattern.get_name())
                self._add_vulnerability_if_new(pattern.get_name(), source_name, source_line, source_col, sink_name, sink_line, sink_col, paths_without_sanitizers_to_omit, flow_type)

    def _group_paths_by_source_line(self, linecol_path_list: list) -> dict:
        """
        Group paths by their source line.
        Each linecol_path_list entry is (source_line, path) where path is either ()
        or a tuple of (sanitizer_name, line_no) tuples.
        """
        paths_by_line = {}
        for source_line, path in linecol_path_list:
            if source_line not in paths_by_line:
                paths_by_line[source_line] = []
            paths_by_line[source_line].append(path)
        return paths_by_line

    def _add_vulnerability_if_new(self, vuln_name: str, source_name: str, source_line: int, source_col: int, sink_name: str,
                                  sink_line: int, sink_col: int, paths: tuple, flow_type: str) -> None:
        """Add a vulnerability if it doesn't already exist, or merge flows if it does."""
        key = (vuln_name, source_name, source_line, source_col, sink_name, sink_line, sink_col)
        paths_without_duplicates = self._deduplicate_within_paths(paths)
        new_flows = self._build_flows_tuple(paths_without_duplicates, flow_type)

        if key in self.detected_vulnerabilities:
            # merge flows with existing vulnerability
            numbered_vuln_name, existing_flows = self.detected_vulnerabilities[key]
            # combine flows, avoiding duplicates
            merged_flows = self._merge_flows(existing_flows, new_flows)
            self.detected_vulnerabilities[key] = (numbered_vuln_name, merged_flows)
        else:
            # new vulnerability - generate numbered name
            numbered_vuln_name = self._generate_numbered_vuln_name(vuln_name)
            self.detected_vulnerabilities[key] = (numbered_vuln_name, new_flows)

    def _deduplicate_within_paths(self, paths: tuple) -> list:
        """Remove duplicate items within each path while preserving order."""
        deduplicated = []
        for path in paths:
            # remove duplicates from tuple while preserving order
            seen = set()
            unique_path = tuple(item for item in path if not (item in seen or seen.add(item)))
            deduplicated.append(unique_path)
        return deduplicated

    def _build_flows_tuple(self, paths: list, flow_type: str) -> tuple:
        """Convert paths into a flows tuple."""
        flows_list = [(flow_type, tuple(tuple(item) for item in path)) for path in paths]
        return tuple(flows_list)

    def _merge_flows(self, existing_flows: tuple, new_flows: tuple) -> tuple:
        """Merge two flows tuples, avoiding duplicates."""
        merged = list(existing_flows)
        for flow in new_flows:
            if flow not in merged:
                merged.append(flow)
        return tuple(merged)

    def _generate_numbered_vuln_name(self, vuln_name: str) -> str:
        """Generate a numbered vulnerability name."""
        if vuln_name not in self.vulnerability_counters:
            self.vulnerability_counters[vuln_name] = 0
        self.vulnerability_counters[vuln_name] += 1
        return f"{vuln_name}_{self.vulnerability_counters[vuln_name]}"

    def to_json(self) -> list[dict]:
        """Returns the vulnerabilities in the required JSON format."""
        report_list = []
        for (vuln_name, source_name, source_line, source_col, sink_name, sink_line, sink_col), (numbered_vuln_name, flows) in self.detected_vulnerabilities.items():
            report_list.append({
                "vulnerability": numbered_vuln_name,
                "source": [source_name, source_line, source_col],
                "sink": [sink_name, sink_line, sink_col],
                "flows": [[f[0], [list(san) for san in f[1]]] for f in flows]
            })

        # Sort by the discovery order of the pattern base, then by the vulnerability number
        return sorted(report_list, key=lambda x: (
            self.pattern_order.index(x["vulnerability"].split('_')[0]),
            int(x["vulnerability"].split('_')[1])
        ))