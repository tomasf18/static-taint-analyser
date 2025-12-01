#!/usr/bin/env python

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

import sys
from imp_parser import *
from imp_lexer import *
from HighLowIntegrityPolicy import HighLowIntegrityPolicy

def usage():
    sys.stderr.write('Usage: imp filename\n')
    sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        usage()
    filename = sys.argv[1]
    text = open(filename).read()
    tokens = imp_lex(text)
    parse_result = imp_parse(tokens)
    if not parse_result:
        sys.stderr.write('Parse error!\n')
        sys.exit(1)
    ast = parse_result.value

    # --- Integrity Setup ---
    policy = HighLowIntegrityPolicy()
    labenv = {}
    
    # Pre-scan for "input" variables to mark them as Low Integrity (L)
    # "input variables (those whose name begins with the prefix in)..." 
    for token in tokens:
        if token[1] == 'ID' and token[0].startswith('in'):
            labenv[token[0]] = 'L'
        elif token[1] == 'ID':
            labenv[token[0]] = 'H'  # Default to High Integrity (H)
            
    print("Initial Environment (Inputs identified):", labenv)

    # Run Classification (Inference)
    indent = 0
    ast.classify(labenv, policy, indent)
    
    print("\nFinal Inferred Environment:")
    for name in sorted(labenv):
        print(f"{name}: {labenv[name]}")