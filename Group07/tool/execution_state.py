import copy

from tool.multilabel import MultiLabel
from tool.multilabelling import MultiLabelling
from tool.policy import Policy

class ExecutionState:
    """Represents the state of one possible execution path."""
    def __init__(self, multilabelling: MultiLabelling, initialized_vars: set[str], policy: Policy, pc: list[MultiLabel] | None = None):
        self.multilabelling = multilabelling
        self.initialized_vars = initialized_vars
        self.policy = policy
        self.pc = pc if pc is not None else []
        self.pc_multilabelling = MultiLabelling()
        self.scope_level = 0

    def current_pc(self) -> MultiLabel:
        """Return the combined PC from the entire stack."""
        combined = MultiLabel(self.policy.patterns)
        for ml in self.pc:
            combined = combined.combine(ml)
        return combined
    
    def push_pc(self, ml: MultiLabel):
        self.pc.append(ml)

    def pop_pc(self):
        if self.pc:
            self.pc.pop()
    
    def copy(self):
        new_state = ExecutionState(
            self.multilabelling.get_deepcopy(),
            copy.deepcopy(self.initialized_vars),
            copy.deepcopy(self.policy),
            copy.deepcopy(self.pc),
        )
        new_state.scope_level = self.scope_level
        new_state.pc_multilabelling = self.pc_multilabelling.get_deepcopy()
        return new_state
    
    def __repr__(self):
        part_1 = f'\n-- Policy --\n {self.policy}'
        part_2 = f'\n-- Initialized Vars --\n {self.initialized_vars}'
        part_3 = f'\n-- Multilabelling --\n {self.multilabelling}'
        part_4 = f'\n-- PC Multilabelling --\n {self.pc_multilabelling}\n'
        return part_1 + part_2 + part_3 + part_4
    
    def __eq__(self, other):
        if not isinstance(other, ExecutionState):
            return False
        return (self.multilabelling == other.multilabelling and
                self.initialized_vars == other.initialized_vars and
                self.policy == other.policy and
                self.pc == other.pc)