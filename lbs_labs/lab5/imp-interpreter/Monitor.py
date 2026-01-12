from imp_ast import *

 #SEE SLIDE 62 OF CLASS 5
class Monitor:
    def __init__(self):
        self.monstack = ["L"]
    
    def step(self, label): # given a lablel, decide wheter or not to accept
        # possible labels: "nop", "branching" (b(t)), "end" (f), "assignment" (x, a)
        if label["type"] == "assign":
            # for every class correspponding to expressios, if we define a def level(self), we can use it here
            if label["level"] == "l" and self.monstack[-1] == "H":
                raise RuntimeError("Security Error: Cannot assigns a low variable to a high context")
            if label["first"] == "l" and label["second"]["level"] == "H":
                raise RuntimeError("Security Error: Cannot assigns a low variable to a high expression")
            return True
        elif label["type"] == "test":
            if label["first"] == "H" or self.monstack[-1] == "H":
                self.monstack = self.monstack + ["H"]
            else:
                self.monstack = self.monstack + ["L"]
            return True
        elif label["type"] == "end":
            self.monstack = self.monstack[:-1] # pop
            return True
        elif label["type"] == "nop":
            return True
        
# the monitor basically checks laels and decides whether should or not block the execution
# we should: implement the Monitor, implement smal_step_eval(), and level() (on all expressions and where needed) methods