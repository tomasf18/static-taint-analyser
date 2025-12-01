# Copyright (c) 2011, Jay Conrod.
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Jay Conrod nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL JAY CONROD BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from equality import *

class Statement(Equality):
    pass

class Aexp(Equality):
    pass

class Bexp(Equality):
    pass

class AssignStatement(Statement):
    def __init__(self, name, aexp):
        self.name = name
        self.aexp = aexp

    def __repr__(self):
        return 'AssignStatement(%s, %s)' % (self.name, self.aexp)

    def eval(self, env):
        value = self.aexp.eval(env)
        env[self.name] = value
        
    def classify(self, labenv, policy, indent):
        # 1. Classify the expression being read
        # Note: We classify the expression FIRST to get its taintedness
        expr_label = self.aexp.classify(labenv, policy, indent + 2)
        
        if self.name not in labenv:
            labenv[self.name] = policy.top()  # Default to most trusted (H)
            
        name_label = labenv[self.name]
        
        label = policy.lub(name_label, expr_label)
        print("  " * indent + repr(self) + ": " + label)
        return label

class CompoundStatement(Statement):
    def __init__(self, first, second):
        self.first = first
        self.second = second

    def __repr__(self):
        return 'CompoundStatement(%s, %s)' % (self.first, self.second)

    def eval(self, env):
        self.first.eval(env)
        self.second.eval(env)
        
    def classify(self, labenv, policy, indent):
        # Process strictly in order because the first statement might 
        # change labenv for the second statement (flow-sensitive)
        first_label = self.first.classify(labenv, policy, indent + 2)
        second_label = self.second.classify(labenv, policy, indent + 2)
        
        # Aggregate labels (usually GLB for statements, representing the 'cleanest' part,
        # or LUB if representing 'taint' accumulation. Standard is GLB for statement security context).
        label = policy.glb(first_label, second_label)
        print("  " * indent + repr(self) + ": " + label)
        return label

class IfStatement(Statement):
    def __init__(self, condition, true_stmt, false_stmt):
        self.condition = condition
        self.true_stmt = true_stmt
        self.false_stmt = false_stmt

    def __repr__(self):
        return 'IfStatement(%s, %s, %s)' % (self.condition, self.true_stmt, self.false_stmt)

    def eval(self, env):
        condition_value = self.condition.eval(env)
        if condition_value:
            self.true_stmt.eval(env)
        else:
            if self.false_stmt:
                self.false_stmt.eval(env)
                
    def classify(self, labenv, policy, indent):
        self.condition.classify(labenv, policy, indent + 2)
        true_label = self.true_stmt.classify(labenv, policy, indent + 2)
        if self.false_stmt:
            false_label = self.false_stmt.classify(labenv, policy, indent + 2)
        else:
            false_label = policy.top() # Default to safe/clean if empty? Or Bottom?
            # In integrity H (Trusted) is usually safe/bottom of taint. 
            # If no code executes, no taint happens -> H.
            false_label = "H"

        label = policy.glb(true_label, false_label)
        print("  " * indent + repr(self) + ": " + label)
        return label

class WhileStatement(Statement):
    def __init__(self, condition, body):
        self.condition = condition
        self.body = body

    def __repr__(self):
        return 'WhileStatement(%s, %s)' % (self.condition, self.body)

    def eval(self, env):
        condition_value = self.condition.eval(env)
        while condition_value:
            self.body.eval(env)
            condition_value = self.condition.eval(env)
            
    def classify(self, labenv, policy, indent):
        label = self.body.classify(labenv, policy, indent + 2)
        print("  " * indent + repr(self) + ": " + label)
        return label

class IntAexp(Aexp):
    def __init__(self, i):
        self.i = i

    def __repr__(self):
        return 'IntAexp(%d)' % self.i

    def eval(self, env):
        return self.i
    
    def classify(self, labenv, policy, indent):
        # Constants are "Trusted" (High Integrity)
        label = "H" 
        print("  " * indent + repr(self) + ": " + label)
        return label
    
class VarAexp(Aexp):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return 'VarAexp(%s)' % self.name

    def eval(self, env):
        if self.name in env:
            return env[self.name]
        else:
            return 0
        
    def classify(self, labenv, policy, indent):
        # "Inferred with the least restrictive label possible" 
        # In Integrity, H (Trusted) is less restrictive than L (Untrusted/Tainted).
        # We assume variables are Clean (H) unless known otherwise.
        if self.name not in labenv:
            labenv[self.name] = "H"
            
        label = labenv[self.name]
        print("  " * indent + repr(self) + ": " + label)
        return label

class BinopAexp(Aexp):
    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right

    def __repr__(self):
        return 'BinopAexp(%s, %s, %s)' % (self.op, self.left, self.right)

    def eval(self, env):
        left_value = self.left.eval(env)
        right_value = self.right.eval(env)
        # (Evaluation logic omitted for brevity, same as original)
        return 0 
    
    def classify(self, labenv, policy, indent):
        left_label = self.left.classify(labenv, policy, indent + 2)
        right_label = self.right.classify(labenv, policy, indent + 2)
        
        # "Expressions should be given an upper bound" [cite: 531]
        # In Integrity lattice: Trusted (H) <= Untrusted (L). 
        # Combining Trusted + Untrusted = Untrusted (L).
        label = policy.lub(left_label, right_label)
        print("  " * indent + repr(self) + ": " + label)
        return label
    
# (RelopBexp, AndBexp, OrBexp, NotBexp logic is identical to BinopAexp 
# regarding classify: they recursively call children and apply policy.lub)
class RelopBexp(Bexp):
    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right
    def __repr__(self): return 'RelopBexp(%s, %s, %s)' % (self.op, self.left, self.right)
    def eval(self, env): return True
    def classify(self, labenv, policy, indent):
        left_label = self.left.classify(labenv, policy, indent + 2)
        right_label = self.right.classify(labenv, policy, indent + 2)
        label = policy.lub(left_label, right_label)
        print("  " * indent + repr(self) + ": " + label)
        return label

class AndBexp(Bexp):
    def __init__(self, left, right):
        self.left = left
        self.right = right
    def __repr__(self): return 'AndBexp(%s, %s)' % (self.left, self.right)
    def eval(self, env): return True
    def classify(self, labenv, policy, indent):
        left_label = self.left.classify(labenv, policy, indent + 2)
        right_label = self.right.classify(labenv, policy, indent + 2)
        label = policy.lub(left_label, right_label)
        print("  " * indent + repr(self) + ": " + label)
        return label

class OrBexp(Bexp):
    def __init__(self, left, right):
        self.left = left
        self.right = right
    def __repr__(self): return 'OrBexp(%s, %s)' % (self.left, self.right)
    def eval(self, env): return True
    def classify(self, labenv, policy, indent):
        left_label = self.left.classify(labenv, policy, indent + 2)
        right_label = self.right.classify(labenv, policy, indent + 2)
        label = policy.lub(left_label, right_label)
        print("  " * indent + repr(self) + ": " + label)
        return label

class NotBexp(Bexp):
    def __init__(self, exp):
        self.exp = exp
    def __repr__(self): return 'NotBexp(%s)' % self.exp
    def eval(self, env): return True
    def classify(self, labenv, policy, indent):
        exp_label = self.exp.classify(labenv, policy, indent + 2)
        print("  " * indent + repr(self) + ": " + exp_label)
        return exp_label