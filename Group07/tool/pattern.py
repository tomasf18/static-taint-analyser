#!/usr/bin/env python3

class Pattern:
    """
    Represents a vulnerability pattern, including its sources,
    sinks, and sanitizers.
    """

    def __init__(
        self,
        vulnerability_name: str,
        sources: set[str],
        sink_names: set[str],
        sanitizers: list[str],
        implicit_flows: str
    ) -> None:
        """
        Constructor for a Pattern object.
        Receives a vulnerability name and lists of names for
        sources, sanitizers, and sinks.
        """
        self.vulnerability_name = vulnerability_name
        self.sources = sources
        self.sink_names = sink_names
        self.sanitizers = sanitizers
        self.sanitizers_dict = {sanitizer[0]: sanitizer[1] for sanitizer in sanitizers}
        self.sanitizer_names = set(self.sanitizers_dict.keys())
        self.implicit_flows = implicit_flows.lower() == "yes"

    def is_sink(self, name: str) -> bool:
        """
        Tests if a given name is a sink for this pattern.
        """
        return name in self.sink_names

    def is_source(self, name: str) -> bool:
        """
        Tests if a given name is a source for this pattern.
        """
        return name in self.sources

    def is_sanitizer(self, name: str) -> bool:
        """
        Tests if a given name is a sanitizer for this pattern.
        """
        return name in self.sanitizer_names
    
    def show_sanitizer(self, name: str) -> bool:
        return self.sanitizers_dict[name] == "show"

    def is_implicit(self) -> bool:
        """
        Tests if is an implicit flow for this pattern.
        """
        return self.implicit_flows

    # --- Selector Methods  ---

    def get_name(self) -> str:
        """Selector for the vulnerability name."""
        return self.vulnerability_name

    def get_sources(self) -> set[str]:
        """Selector for the set of source names."""
        return self.sources

    def get_sanitizers(self) -> set[str]:
        """Selector for the set of sanitizer names."""
        return self.sanitizer_names

    def get_sinks(self) -> set[str]:
        """Selector for the set of sink names."""
        return self.sink_names

    def __repr__(self) -> str:
        """Provides a clean string representation for debugging."""
        return (
            f"Pattern(\n"
            f"  name='{self.vulnerability_name}', \n"
            f"  sources={self.sources}, \n"
            f"  sinks={self.sink_names}, \n"
            f"  sanitizers={self.sanitizers}\n)"
        )
    
    def __eq__(self, other):
        if not isinstance(other, Pattern):
            return False
        return (
            self.vulnerability_name == other.vulnerability_name and
            self.sources == other.sources and
            self.sink_names == other.sink_names and
            self.sanitizer_names == other.sanitizer_names and
            getattr(self, 'implicit_flows', False) == getattr(other, 'implicit_flows', False)
        )
        
    def deepcopy(self) -> 'Pattern':
        """
        Returns a deep copy of the Pattern object.
        """
        return Pattern(
            vulnerability_name=self.vulnerability_name,
            sources=set(self.sources),
            sink_names=set(self.sink_names),
            sanitizers=self.sanitizers,
            implicit_flows=("yes" if self.implicit_flows else "no")
        )