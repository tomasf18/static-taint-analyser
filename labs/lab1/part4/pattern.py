#!/usr/bin/env python3

class Pattern:
    """
    Represents a vulnerability pattern, including its sources,
    sinks, and sanitizers.
    """

    def __init__(
        self,
        vulnerability_name: str,
        possible_sources: set[str],
        sink_names: set[str],
        sanitizer_names: set[str],
    ) -> None:
        """
        Constructor for a Pattern object.
        Receives a vulnerability name and lists of names for
        sources, sanitizers, and sinks.
        """
        self.vulnerability_name = vulnerability_name
        self.possible_sources = possible_sources
        self.sink_names = sink_names
        self.sanitizer_names = sanitizer_names

    def is_sink(self, name: str) -> bool:
        """
        Tests if a given name is a sink for this pattern.
        """
        return name in self.sink_names

    def is_source(self, name: str) -> bool:
        """
        Tests if a given name is a source for this pattern.
        """
        return name in self.possible_sources

    def is_sanitizer(self, name: str) -> bool:
        """
        Tests if a given name is a sanitizer for this pattern.
        """
        return name in self.sanitizer_names

    # --- Selector Methods  ---

    def get_name(self) -> str:
        """Selector for the vulnerability name."""
        return self.vulnerability_name

    def get_sources(self) -> set[str]:
        """Selector for the set of source names."""
        return self.possible_sources

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
            f"  sources={self.possible_sources}, \n"
            f"  sinks={self.sink_names}, \n"
            f"  sanitizers={self.sanitizer_names}\n)"
        )


# --- Example Usage ---
if __name__ == "__main__":
    
    # 1. Define a vulnerability pattern
    sql_injection_pattern = Pattern(
        vulnerability_name="SQL Injection",
        possible_sources={"$_GET", "$_POST", "request.form"},
        sanitizer_names={"mysql_real_escape_string", "prepare_statement"},
        sink_names={"mysql_query", "execute_sql", "system"},
    )

    # 2. Test the methods
    print(f"--- Testing Pattern: {sql_injection_pattern.get_name()} ---")
    
    # Test sources 
    print(f"Is '$_POST' a source?               -> {sql_injection_pattern.is_source('$_POST')}")
    print(f"Is 'request.headers' a source?      -> {sql_injection_pattern.is_source('request.headers')}")

    # Test sinks 
    print(f"Is 'mysql_query' a sink?            -> {sql_injection_pattern.is_sink('mysql_query')}")
    print(f"Is 'echo' a sink?                   -> {sql_injection_pattern.is_sink('echo')}")

    # Test sanitizers 
    print(f"Is 'prepare_statement' a sanitizer? -> {sql_injection_pattern.is_sanitizer('prepare_statement')}")
    print(f"Is 'str_replace' a sanitizer?       -> {sql_injection_pattern.is_sanitizer('str_replace')}")

    # 3. Test Selectors 
    print(f"\nAll Sources:     {sql_injection_pattern.get_sources()}")
    print(f"All Sinks:       {sql_injection_pattern.get_sinks()}")
    print(f"All Sanitizers:  {sql_injection_pattern.get_sanitizers()}")

    # 4. Show the object representation
    print(f"\nObject Representation:\n{sql_injection_pattern}")