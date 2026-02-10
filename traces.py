from tool.multilabel import MultiLabel
from tool.vulnerabilities import Vulnerabilities
from tool.execution_state import ExecutionState


class TracesTraversal:
    """
    Traverses the AST and performs taint analysis, tracking information flows
    through the program and detecting vulnerabilities.
    """
    
    def __init__(self):
        pass
    
    def analyse_program(self, node: dict | list, states: list[ExecutionState], vulnerabilities: Vulnerabilities) -> list[ExecutionState]:
        """
        Main entry point for program analysis.
        Traverses the AST and updates multilabelling and vulnerabilities.
        """
                
        if isinstance(node, list):
            for item in node:
                states = self.analyse_program(item, states, vulnerabilities)
            return states
        
        if not isinstance(node, dict):
            return states
        
        ast_type = node.get('ast_type')
        
        handlers = {
            'Module': self._handle_module,
            'Assign': self._handle_assign,
            'Expr': self._handle_expr,
            'If': self._handle_if,
            'While': self._handle_while,
            'For': self._handle_for,
        }
        
        handler = handlers.get(ast_type)
        if handler:
            return handler(node, states, vulnerabilities)
        
        return states
    
    # ====== Statement Handlers ======
    
    def _handle_module(self, node: dict, states: list[ExecutionState], vulnerabilities: Vulnerabilities) -> list[ExecutionState]:
        """Handle Module node - analyze all statements in body."""
        body = node.get('body', [])
        return self.analyse_program(body, states, vulnerabilities)
    
    def _handle_assign(self, node: dict, states: list[ExecutionState], vulnerabilities: Vulnerabilities) -> list[ExecutionState]:
        """
        Handle assignment statements for ALL execution states.
        Each state is updated independently.
        """
        line_number = node.get('lineno', 0)
        print(80 * '=' + f'\n[DEBUG] Checking assignment in line {line_number}')
        
        # process assignment for each execution state independently
        for state in states:
            print(80 * '-' + f'\n[DEBUG] Processing state:\n{state}\n' + 80 * '-')
            self._process_assign_for_state(node, state, vulnerabilities)
        
        return states

    def _process_assign_for_state(self, node: dict, state: ExecutionState, vulnerabilities: Vulnerabilities) -> tuple[MultiLabel, MultiLabel]:
        """
        Handle assignment statements.
        Assignments might be:
        - Name (a = ...): ['a']
        - Attribute (c.e = ...): ['c', 'e'] (both are updated)
        - Subscript (c[t+f] = ...): ['c'] (only container is updated, but index needs to be evaluated for taint, since it can leak information to the container, i.e., it can taint the container)
        """

        targets = node.get('targets', [])
        line_number = node.get('lineno', 0)

        handlers = {
            'Name': self._handle_assign_name,
            'Attribute': self._handle_assign_attribute,
            'Subscript': self._handle_assign_subscript,
        }

        ml = MultiLabel(state.policy.patterns)

        ml_pc = MultiLabel(state.policy.patterns)

        target_names = []
        for target in targets:
            target_type = target.get('ast_type')
            target_label, target_names = handlers.get(target_type)(target, state, vulnerabilities)
            ml = ml.combine(target_label)

        print(f'[DEBUG] Assignment target names: {target_names}')
        print(f'[DEBUG] Combined target label: {ml}')

        value_node = node.get('value', {})
        # evaluate the right-hand side to get its taint
        value_label = self._evaluate_expression(value_node, state, vulnerabilities)
        ml = ml.combine(value_label)

        value_label_pc = self._evaluate_expression(value_node, state, vulnerabilities, context="pc")
        ml_pc = ml_pc.combine(value_label_pc)

        print(f'[DEBUG] Assignment value label: {value_label}')

        for target_name in target_names:
            # update the target's PC label
            target_label_on_pc = state.pc_multilabelling.get_multilabel(target_name)
            combined_pc = target_label_on_pc.combine(state.current_pc()) if target_label_on_pc else state.current_pc()
            ml_pc = combined_pc.combine(ml_pc)

            # check if target is a sink (e.g., assigning to a sensitive variable)
            explicit_illegal_flows_ml = state.policy.detect_illegal_flows(target_name, ml)
            if explicit_illegal_flows_ml.vulnerabilities: # BEFORE: if illegal.is_tainted(): -> But we want all!
                vulnerabilities.add_vulnerability(target_name, line_number, explicit_illegal_flows_ml, flow_type="explicit")

            implicit_illegal_flows_ml = state.policy.detect_illegal_flows(target_name, ml_pc)
            if implicit_illegal_flows_ml.vulnerabilities:
                vulnerabilities.add_vulnerability(target_name, line_number, implicit_illegal_flows_ml, flow_type="implicit")

            # update the target's label
            state.multilabelling.update_multilabel(target_name, ml)
            state.pc_multilabelling.update_multilabel(target_name, ml_pc)

        return ml, ml_pc
                
    def _handle_assign_name(self, target: dict, state: ExecutionState, vulnerabilities: Vulnerabilities) -> tuple[MultiLabel, list[str]]:
        """Handle assignment to a simple variable (Name)."""
        ml = MultiLabel(state.policy.patterns)
        target_name = target.get('id', '')
        state.initialized_vars.add(target_name)
        return ml, [target_name] # target_names = [name]
    
    def _handle_assign_attribute(self, target: dict, state: ExecutionState, vulnerabilities: Vulnerabilities) -> tuple[MultiLabel, list[str]]:
        """Handle assignment to an attribute (Attribute).
        
        "When we assign, for example, “c.e,” do we have to create an entry in the multilabeling of “c,” “e,” or both?"
        "You can make an approximation and treat c and e independently. So, for both."
        """
        ml = MultiLabel(state.policy.patterns)
        value_node = target.get('value', {})
        attr_name = target.get('attr', '')
        target_names = []
        
        # update both base object and attribute
        if value_node.get('ast_type') == 'Name':
            base_name = value_node.get('id', '')
            target_names.append(base_name)
        
        target_names.append(attr_name)
        state.initialized_vars.add(attr_name) # only attribute is initialized
        
        return ml, target_names # target_names = [base_name, attr_name]
    
    def _handle_assign_subscript(self, target: dict, state: ExecutionState, vulnerabilities: Vulnerabilities) -> tuple[MultiLabel, list[str]]:
        """Handle assignment to a subscript (Subscript).
        
        "When we make an assign for, say, “s[a],” do we have to create an entry in the multilabeling of “s,” “a,” or both?"
        "It is enough to do it for s; a is not being affected."
        """
        ml = MultiLabel(state.policy.patterns)
        value_node = target.get('value', {})
        target_names = []
        
        # evaluate both container and index for taint, and whether the index is tainting the container that might be a sink
        subscript_label = self._evaluate_expression(target, state, vulnerabilities)
        ml = ml.combine(subscript_label)

        # only update the container variable
        if value_node.get('ast_type') == 'Name':
            container_name = value_node.get('id', '')
            target_names.append(container_name)
            state.initialized_vars.add(container_name)
        
        return ml, target_names  # target_names = [container_name]
    
    def _handle_expr(self, node: dict, states: list[ExecutionState], vulnerabilities: Vulnerabilities) -> list[ExecutionState]:
        """
        Handle expression statements.
        Example: e(d) - a function call that's not assigned
        """
        value_node = node.get('value', {})
        
        # evaluate expression for each state independently
        for state in states:
            print(80 * '-' + f'\n[DEBUG] Processing state:\n{state}\n' + 80 * '-')
            self._evaluate_expression(value_node, state, vulnerabilities)
        
        return states

    def _handle_if(self, node: dict, states: list[ExecutionState], vulnerabilities: Vulnerabilities) -> list[ExecutionState]:
        """
        Handle If statements by creating separate execution paths.
        
        For each input state, we create 2 output states:
        1. One that goes through the if-body (True branch)
        2. One that goes through the else-body (False branch)
        """
        test_node = node.get('test', {})
        body_nodes = node.get('body', [])
        orelse_nodes = node.get('orelse', [])
        
        print("-.-" * 10 + '\n[DEBUG] Entering If statement')
        print(f'[DEBUG] Number of input states: {len(states)}')
        
        new_states: list[ExecutionState] = []
        
        # for each existing state, create two branches
        for state in states:
            print(80 * "-" + f'\n[DEBUG] Processing state:\n{state}\n' + 80 * '-')

            # NEW: PC propagation
            cond_label = self._evaluate_expression(test_node, state, vulnerabilities, context="condition")
            cond_pc_label = self._evaluate_expression(test_node, state, vulnerabilities, context="pc")
            new_pc = state.current_pc().combine(cond_pc_label).combine(cond_label)
            state.push_pc(new_pc)

            # branch 1: if-body (True branch)
            if_state = state.copy()
            print('[DEBUG] Analyzing IF branch (True)')
            if_states = self.analyse_program(body_nodes, [if_state], vulnerabilities)
            new_states.extend(if_states)
            
            # branch 2: else-body (False branch)
            else_state = state.copy()
            else_states = self.analyse_program(orelse_nodes, [else_state], vulnerabilities)
            new_states.extend(else_states)

            # POP PC after both branches
            for s in new_states:
                s.pop_pc()
            state.pop_pc()

        print(f'\n[DEBUG] After If: Number of output states: {len(new_states)}')
        return new_states

    def _handle_while(self, node: dict, states: list[ExecutionState], vulnerabilities: Vulnerabilities) -> list[ExecutionState]:
        """
        Handle While statements by generating states for all possible iteration counts.

        For each input state and each iteration count:
        1. Generate all possible execution paths through the loop body for that iteration count
        2. Each path combines the states from sequential body executions
        3. Finally, add the exit state (when condition becomes False)
        """
        body_node = node.get('body', [])
        orelse_node = node.get('orelse', [])
        test_node = node.get('test', {})
        
        print("-.-" * 10 + '\n[DEBUG] Entering While statement')
        print(f'[DEBUG] Number of input states: {len(states)}')
        
        new_states: list[ExecutionState] = []
        
        # for each input state, generate output states for all iteration counts
        for state in states:
            print(80 * '-' + f'\n[DEBUG] Processing input state:\n{state}\n' + 80 * '-')

            entry_state = state.copy()
            seen_states = []
            num_iterations = 0

            # generate paths for each iteration count independently
            while True:
                num_iterations += 1
                print(f'\n{"=" * 15} [OUTPUT DEBUG] num_iterations = {num_iterations} {"=" * 15}')

                # start fresh for this iteration count
                iteration_states = [[entry_state.copy()]]

                # execute the body num_iterations times
                for iteration_num in range(1, num_iterations + 1):
                    print(f'  [OUTPUT DEBUG] Executing iteration {iteration_num}/{num_iterations}')
                    new_iteration_states = []

                    for state_path in iteration_states:
                        current_state = state_path[-1]
                        
                        # evaluate condition with current state (may have sanitized variables from previous iterations)
                        cond_label = self._evaluate_expression(test_node, current_state, vulnerabilities, context="condition")
                        cond_pc_label = self._evaluate_expression(test_node, current_state, vulnerabilities, context="pc")
                        new_pc = current_state.current_pc().combine(cond_pc_label).combine(cond_label)
                        current_state.push_pc(new_pc)
                        
                        # execute the body with the current state -> produces new states (due to branches in body)
                        body_states = self.analyse_program(body_node, [current_state], vulnerabilities)
                        print(f'  [OUTPUT DEBUG] Body execution produced {len(body_states)} state(s)')
                        
                        # for each resulting state, create a new path by appending it
                        for body_state in body_states:
                            body_state.pop_pc()
                            new_path = state_path + [body_state]
                            new_iteration_states.append(new_path)

                        # pop PC from current state
                        current_state.pop_pc()

                    iteration_states = new_iteration_states
                    print(f'  [OUTPUT DEBUG] After iteration {iteration_num}: {len(iteration_states)} path(s)')
                
                # collect final states from this iteration count and check for new ones, if none found, stop while loop
                new_states_found = False
                for state_path in iteration_states:
                    final_state = state_path[-1]
                    new_states.append(final_state)

                    is_new = all(final_state != seen for seen in seen_states)
                    if is_new:
                        seen_states.append(final_state)
                        new_states_found = True

                if not new_states_found:
                    break

                print(f'{"=" * 46}\n')

            # add the exit state (when condition becomes False)
            else_state = entry_state.copy()
            print('[DEBUG] Analyzing WHILE exit branch (False)')
            else_states = self.analyse_program(orelse_node, [else_state], vulnerabilities)
            for else_state in else_states:
                else_state.pop_pc()
            new_states.extend(else_states)

            else_state.pop_pc()

        print(f'\n[DEBUG] After While: Total output states: {len(new_states)}')
        return new_states
    
    def _handle_for(self, node: dict, states: list[ExecutionState], vulnerabilities: Vulnerabilities) -> list[ExecutionState]:
        """
        Handle For statements by generating states for all possible iteration counts.

        For each input state and each iteration count:
        1. Generate all possible execution paths through the loop body for that iteration count
        2. Each path combines the states from sequential body executions
        3. Finally, add the exit state (when loop ends)
        """
        body_node = node.get('body', [])
        orelse_node = node.get('orelse', [])
        target_node = node.get('target', {})
        iter_node = node.get('iter', {})
        
        print("-.-" * 10 + '\n[DEBUG] Entering For statement')
        print(f'[DEBUG] Number of input states: {len(states)}')
        
        new_states: list[ExecutionState] = []
        max_loop = 4  # to prevent infinite loops in case of unbounded loops
        
        # for each input state, generate output states for all iteration counts
        for state in states:
            print(80 * '-' + f'\n[DEBUG] Processing input state:\n{state}\n' + 80 * '-')

            entry_state = state.copy()
            seen_states = []
            num_iterations = 0

            # generate paths for each iteration count independently
            while True:
                num_iterations += 1
                print(f'\n{"=" * 15} [OUTPUT DEBUG] num_iterations = {num_iterations} {"=" * 15}')

                # start fresh for this iteration count
                iteration_states = [[entry_state.copy()]]

                # execute the body num_iterations times
                for iteration_num in range(1, num_iterations + 1):
                    print(f'  [OUTPUT DEBUG] Executing iteration {iteration_num}/{num_iterations}')
                    new_iteration_states = []

                    for state_path in iteration_states:
                        current_state = state_path[-1]
                        
                        # assign the target variable for this iteration
                        iter_assign_label, iter_assign_pc_label = self._process_assign_for_state(
                            {
                                'ast_type': 'Assign',
                                'targets': [target_node],
                                'value': iter_node,
                                'lineno': node.get('lineno', 0)
                            },
                            current_state,
                            vulnerabilities
                        )
                        
                        # evaluate iter expression with current state (may have sanitized variables from previous iterations)
                        new_pc = current_state.current_pc().combine(iter_assign_pc_label).combine(iter_assign_label)
                        
                        print(f'  [OUTPUT DEBUG] Pushing to PC the following context label for iteration {iteration_num}: \n{new_pc}')
                        current_state.push_pc(new_pc)

                        # execute the body with the current state -> produces new states (due to branches in body)
                        body_states = self.analyse_program(body_node, [current_state], vulnerabilities)
                        print(f'  [OUTPUT DEBUG] Body execution produced {len(body_states)} state(s)')
                        
                        # for each resulting state, create a new path by appending it
                        for body_state in body_states:
                            body_state.pop_pc() # we have just exited the body, so pop PC
                            new_path = state_path + [body_state]
                            new_iteration_states.append(new_path)
                            
                        # pop PC from current state
                        current_state.pop_pc()
                        
                    iteration_states = new_iteration_states
                    print(f'  [OUTPUT DEBUG] After iteration {iteration_num}: {len(iteration_states)} path(s)')
                    
                # collect final states from this iteration count and check for new ones, if none found, stop while loop
                new_states_found = False
                for state_path in iteration_states:
                    final_state = state_path[-1]
                    new_states.append(final_state)

                    is_new = all(final_state != seen for seen in seen_states)
                    if is_new:
                        seen_states.append(final_state)
                        new_states_found = True
                        
                if not new_states_found:
                    break
                
                print(f'{"=" * 46}\n')
                
            # add the exit state (when loop ends)
            else_state = entry_state.copy()
            print('[DEBUG] Analyzing FOR exit branch')
            else_states = self.analyse_program(orelse_node, [else_state], vulnerabilities)
            for else_state in else_states:
                else_state.pop_pc()
            new_states.extend(else_states)
            else_state.pop_pc()
            
        print(f'\n[DEBUG] After For: Total output states: {len(new_states)}')
        # print(f"PC for each state after For:")
        # for i, s in enumerate(new_states):
        #     print(f" State {i} PC: {s.pc_multilabelling}")
        return new_states
                        
    # ====== Expression Evaluators ======
    
    def _evaluate_expression(self, node: dict, state: ExecutionState, vulnerabilities: Vulnerabilities, context: str = "value") -> MultiLabel:
        """
        Central dispatcher for expression evaluation.
        Returns the MultiLabel representing the taint of the expression.
        """
        if not isinstance(node, dict):
            return MultiLabel(state.policy.patterns)
        
        ast_type = node.get('ast_type')
        
        # dispatch to appropriate expression handler
        handlers = {
            'Constant': self._eval_constant,
            'Name': self._eval_name,
            'Attribute': self._eval_attribute,
            'Subscript': self._eval_subscript,
            'BinOp': self._eval_binop,
            'Call': self._eval_call,
            'Compare': self._eval_compare,
            'UnaryOp': self._eval_unaryop,
            'BoolOp': self._eval_boolop,
        }
        
        handler = handlers.get(ast_type)
        return handler(node, state, vulnerabilities, context) if handler else MultiLabel(state.policy.patterns)
    
    def _eval_constant(self, node: dict, state: ExecutionState, vulnerabilities: Vulnerabilities, context: str = "value") -> MultiLabel:
        """
        Evaluate a constant value.
        Example: "", 0, "hello"
        Constants have no taint.
        """
        return MultiLabel(state.policy.patterns)
    
    def _eval_name(self, node: dict, state: ExecutionState, vulnerabilities: Vulnerabilities, context: str = "value") -> MultiLabel:
        """
        Evaluate a variable reference.
        Example: a, b
        """
        var_name = node.get('id', '')
        line_number = node.get('lineno', 0)
        
        ml = MultiLabel(state.policy.patterns)
            
        # check if name is initialized in the program so far, else it's a source
        print(f'[DEBUG] Checking if variable "{var_name}" is initialized: {var_name in state.initialized_vars}')
        if var_name not in state.initialized_vars:
            if context == "value":
                # normal variable usage
                state.policy.add_source_to_all_patterns(var_name)
                state.initialized_vars.add(var_name)
            elif context == "condition":
                # variable used in a condition -> implicit flow
                state.policy.add_source_to_all_implicit_patterns(var_name)
            ml.add_source(var_name, line_number)

            return ml
        
        if context == "pc":
            variable_multilabel_in_pc = state.pc_multilabelling.get_multilabel(var_name)
            # print(f'[DEBUG] VARIABLE \'{var_name}\' MULTILABEL IN PC CONTEXT: {variable_multilabel_in_pc}')
            return variable_multilabel_in_pc if variable_multilabel_in_pc else MultiLabel(state.policy.patterns)
        
        # check if the variable name itself is a source
        patterns_with_source = state.policy.get_vulnerabilities_by_source(var_name)
        if patterns_with_source:
            ml.add_source(var_name, line_number)

        # get the current taint of this variable
        if not state.multilabelling.get_multilabel(var_name):
            state.multilabelling.update_multilabel(var_name, MultiLabel(state.policy.patterns))
            
        current_multilabel = state.multilabelling.get_multilabel(var_name)
        if current_multilabel:    
            ml = ml.combine(current_multilabel)
        
        return ml

    def _eval_attribute(self, node: dict, state: ExecutionState, vulnerabilities: Vulnerabilities, context: str = "value") -> MultiLabel:
        """
        Evaluate an attribute access.
        Example: b.m, c.e, request.GET
        
        Both object and their attributes can be affected, and both objects and their methods or attributes can be sources of information
        """
        value_node = node.get('value', {})
        attr_name = node.get('attr', '')
        line_number = node.get('lineno', 0)
        
        ml = MultiLabel(state.policy.patterns)
        
        # evaluate the base object (e.g., 'b' in 'b.m')
        base_label = self._evaluate_expression(value_node, state, vulnerabilities, context)
        ml = ml.combine(base_label)
        
        # Only check attribute itself in "value" context
        if context == "value":
            patterns_with_source = state.policy.get_vulnerabilities_by_source(attr_name)
            if patterns_with_source:
                ml.add_source(attr_name, line_number)
        
            # check if the attribute has a stored label
            attr_label = state.multilabelling.get_multilabel(attr_name)
            if attr_label:
                ml = ml.combine(attr_label)
        
        return ml
    
    def _eval_subscript(self, node: dict, state: ExecutionState, vulnerabilities: Vulnerabilities, context: str = "value") -> MultiLabel:
        """
        Evaluate a subscript operation.
        Example: b[0], s[a], c[e+f]
        
        Both the container and the index of subscripts can be sources of information. Information can leak from the index do the container.
        """
        value_node = node.get('value', {})
        slice_node = node.get('slice', {})
        line_number = node.get('lineno', 0)
        
        ml = MultiLabel(state.policy.patterns)

        # evaluate both the container and the index
        container_label = self._evaluate_expression(value_node, state, vulnerabilities, context)
        ml = ml.combine(container_label)
        print(f'[DEBUG] Subscript container label: {container_label}')
        index_label = self._evaluate_expression(slice_node, state, vulnerabilities, context)
        ml = ml.combine(index_label)
        
        # check if the container itself is a sink
        if context == "value" and value_node.get('ast_type') == 'Name':
            container_name = value_node.get('id', '')
            patterns_with_sink = state.policy.get_vulnerabilities_by_sink(container_name)
            if patterns_with_sink:
                illegal = state.policy.detect_illegal_flows(container_name, ml)
                if illegal.vulnerabilities:
                    vulnerabilities.add_vulnerability(container_name, line_number, illegal)
        
        return ml
    
    def _eval_binop(self, node: dict, state: ExecutionState, 
                    vulnerabilities: Vulnerabilities, context: str = "value") -> MultiLabel:
        """
        Evaluate a binary operation.
        Example: a + b, c + "oi" + d, e * f
        
        Both operands can contribute taint.
        """
        left_node = node.get('left', {})
        right_node = node.get('right', {})
        
        ml = MultiLabel(state.policy.patterns)
        
        # evaluate both operands
        left_label = self._evaluate_expression(left_node, state, vulnerabilities, context)
        ml = ml.combine(left_label)

        right_label = self._evaluate_expression(right_node, state, vulnerabilities, context)
        ml = ml.combine(right_label)
        
        return ml
    
    def _eval_call(self, node: dict, state: ExecutionState, vulnerabilities: Vulnerabilities, context: str = "value") -> MultiLabel:
        """
        Evaluate a function call.
        Example: f(a, b), b.m(), s("ola", a)
        The function can be:
        - A source (introduces taint)
        - A sanitizer (removes taint)
        - A sink (triggers vulnerability check)
        """
        func_node = node.get('func', {})
        args = node.get('args', [])
        line_number = node.get('lineno', 0)
        
        ml = MultiLabel(state.policy.patterns)
        ml_pc = MultiLabel(state.policy.patterns)
                
        # extract the function name
        base_name, func_name = self._extract_function_names(func_node)
        if base_name and (base_name not in state.initialized_vars):
            state.policy.add_source_to_all_patterns(base_name)
            ml.add_source(base_name, line_number)
            state.initialized_vars.add(base_name)
            
        # evaluate all arguments and combine their labels
        for arg in args:
            arg_label = self._evaluate_expression(arg, state, vulnerabilities, context="value")
            ml = ml.combine(arg_label)

            arg_pc_label = self._evaluate_expression(arg, state, vulnerabilities, context="pc")
            ml_pc = ml_pc.combine(arg_pc_label)

        ml_pc = ml_pc.combine(state.current_pc())
        
        # check if the function itself is a source
        patterns_with_source = state.policy.get_vulnerabilities_by_source(func_name)
        if patterns_with_source:
            ml.add_source(func_name, line_number)
            
        # check if the function is a sanitizer
        patterns_with_sanitizer = state.policy.get_vulnerabilities_by_sanitizer(func_name)
        if patterns_with_sanitizer:
            ml.add_sanitizer(func_name, line_number)
            ml_pc.add_sanitizer(func_name, line_number)
        
        # check if the function is a sink
        explicit_illegal = state.policy.detect_illegal_flows(func_name, ml)
        if explicit_illegal.vulnerabilities:
            vulnerabilities.add_vulnerability(func_name, line_number, explicit_illegal, flow_type="explicit")

        implicit_illegal = state.policy.detect_illegal_flows(func_name, ml_pc)
        if implicit_illegal.vulnerabilities:
            vulnerabilities.add_vulnerability(func_name, line_number, implicit_illegal, flow_type="implicit")

        return ml_pc if context == "pc" else ml
    
    def _eval_compare(self, node: dict, state: ExecutionState, vulnerabilities: Vulnerabilities, context: str = "value") -> MultiLabel:
        """
        Evaluate a comparison operation.
        Example: a < b, x == y
        
        All operands can contribute taint.
        """
        left_node = node.get('left', {})
        comparators = node.get('comparators', [])
        
        # evaluate left side
        ml = self._evaluate_expression(left_node, state, vulnerabilities, context)
        
        # evaluate all comparators and combine
        for comp_node in comparators:
            comp_label = self._evaluate_expression(comp_node, state, vulnerabilities, context)
            ml = ml.combine(comp_label)
        
        return ml
    
    def _eval_unaryop(self, node: dict, state: ExecutionState, vulnerabilities: Vulnerabilities, context: str = "value") -> MultiLabel:
        """
        Evaluate a unary operation.
        Example: -a, not b, +x
        
        The operand contributes taint.
        """
        operand_node = node.get('operand', {})
        return self._evaluate_expression(operand_node, state, vulnerabilities, context)
    
    def _eval_boolop(self, node: dict, state: ExecutionState, vulnerabilities: Vulnerabilities, context: str = "value") -> MultiLabel:
        """
        Evaluate a boolean operation.
        Example: a and b, x or y
        
        All operands can contribute taint.
        """
        values = node.get('values', [])
        ml = MultiLabel(state.policy.patterns)
        
        for value in values:
            value_label = self._evaluate_expression(value, state, vulnerabilities, context)
            ml = ml.combine(value_label)
        
        return ml

    # ====== Helper Methods ======
    
    def _extract_function_names(self, func_node: dict) -> tuple[str, str]:
        """
        Extract the function name from a Call's func node.
        
        Returns a tuple of (base_name, func_name):
        - Simple names: f() -> ('', 'f')
        - Attributes: b.m() -> ('b', 'm')
        """
        if not isinstance(func_node, dict):
            return '', ''
        
        func_type = func_node.get('ast_type')
        
        if func_type == 'Name':
            return '', func_node.get('id', '')
        
        elif func_type == 'Attribute':
            value_node = func_node.get('value', {})
            base_name = value_node.get('id', '') if value_node.get('ast_type') == 'Name' else ''
            func_name = func_node.get('attr', '')
            return base_name, func_name
        
        return '', ''