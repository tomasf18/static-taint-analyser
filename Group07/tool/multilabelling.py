import copy
from tool.multilabel import MultiLabel

class MultiLabelling:
    """
    Represents a mapping from variable names to multilabels.
    
    This class acts as the environment state for the information flow analysis,
    tracking the current security levels of all variables in the program scope.
    """

    def __init__(self) -> None:
        """
        Constructor of a MultiLabelling object
        """
        # The mapping structure: { "variable_name": MultiLabel_object }
        self.variable_map: dict[str, MultiLabel] = {}

    # --- Selectors ---

    def get_multilabel(self, variable_name: str) -> MultiLabel | None:
        """
        Returns the multilabel assigned to a given variable name.
        """
        if variable_name not in self.variable_map:
            return
        
        return self.variable_map[variable_name]

    def get_deepcopy(self) -> "MultiLabelling":
        """
        Returns a deep copy of the MultiLabelling object.
        """
        return copy.deepcopy(self)

    # --- Mutators ---

    def update_multilabel(self, variable_name: str, multilabel: MultiLabel) -> None:
        """
        Updates the multilabel assigned to a specific variable name.
        
        This is used when a variable is assigned a new value (e.g., x := y),
        updating its security history.
        """
        self.variable_map[variable_name] = multilabel

    def combine(self, other: "MultiLabelling") -> "MultiLabelling":
        """
        Method responsible for combining two MultiLabelling objects.
        """
        result = MultiLabelling()
        all_keys = set(self.variable_map.keys()).union(other.variable_map.keys())

        for key in all_keys:
            multilabel_self = self.variable_map.get(key)
            multilabel_other = other.variable_map.get(key)
            if multilabel_self and multilabel_other:
                combined = multilabel_self.combine(multilabel_other)
            elif multilabel_self:
                combined = copy.deepcopy(multilabel_self)
            elif multilabel_other:
                combined = copy.deepcopy(multilabel_other)
            else:
                continue

            result.update_multilabel(key, combined)

        return result

    def __repr__(self) -> str:
        """Provides a clean string representation of the entire program state."""
        if not self.variable_map:
            return "MultiLabelling(Empty)"
        
        parts = []
        for var_name in sorted(self.variable_map.keys()):
            label = self.variable_map[var_name]
            # For brevity, only show variables that are actually tainted
            if label.is_tainted():
                # Indent the MultiLabel representation for readability
                label_str = str(label).replace("\n", "\n    ")
                parts.append(f"Variable '{var_name}': {label_str}")
            else:
                parts.append(f"Variable '{var_name}': Untainted")
        
        return "MultiLabelling(\n  " + "\n  ".join(parts) + "\n)"
    
    def __eq__(self, other):
        if not isinstance(other, MultiLabelling):
            return False
        
        if set(self.variable_map.keys()) != set(other.variable_map.keys()):
            return False
        
        for var_name in self.variable_map:
            if self.variable_map[var_name] != other.variable_map[var_name]:
                return False
        
        return True