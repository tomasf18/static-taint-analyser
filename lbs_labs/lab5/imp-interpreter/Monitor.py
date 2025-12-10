from imp_ast import *

 #SEE SLIDE 62 OF CLASS 5
class Monitor:
    def __init__(self):
        self.monstach = ["L"]
    
    def step(self, label): # given a lablel, decide wheter or not to accept
        top = self.monstach[-1]
        # possible labels: "nop", "branching" (b(t)), "end" (f), "assignment" (x, a)
        if label["type"] == "assign":
            # for every class correspponding to expressios, if we define a def level(self), we can use it here
            if label["level"] == "l" and self.monstach[-1] == "H":
                raise RuntimeError("Security Error: Cannot assigns a low variable to a high context")
            if label["first"] == "l" and çabel["second".level()] == "H":
                raise RuntimeError("Security Error: Cannot assigns a low variable to a high expression")
            return True
        elif label["type"] == "test":
            if label["first"] == "H" or self.monstach[-1] == "H":
                self.monstach = self.monstach.extend("H")
            else:
                self.monstach = self.monstach.extend("L")
            return True
        elif label["type"] == "end":
            self.monstach = self.monstach[:-1] # pop
            return True
        elif label["type"] == "nop":
            return True
        
# the monitor basically checks laels and decides whether should or not block the execution
# we should: implement the Monitor, implement smal_step_eval(), and level() (on all expressions and where needed) methods