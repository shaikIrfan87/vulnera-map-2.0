import ast
import os

class ASTTaintVisitor(ast.NodeVisitor):
    """
    AST Visitor that tracks untrusted data flow from Sources to Sinks.
    Sources: function parameters, user_input, request args.
    Sinks: eval(), exec(), db.execute(), cursor.execute() using unparameterized string concatenation.
    """
    SINKS = {"eval", "exec", "execute", "raw_sql", "system"}
    SOURCES = {"user_input", "request", "params", "input_data", "payload"}

    def __init__(self, file_path=""):
        self.file_path = file_path
        self.findings = []
        self.tainted_vars = set(self.SOURCES)

    def visit_Assign(self, node):
        # Track assignments from tainted sources
        if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
        elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
            # Check if any side of string concat uses tainted var
            left_tainted = isinstance(node.value.left, ast.Name) and node.value.left.id in self.tainted_vars
            right_tainted = isinstance(node.value.right, ast.Name) and node.value.right.id in self.tainted_vars
            if left_tainted or right_tainted:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in self.SINKS:
            # Check arguments passed to sink
            if len(node.args) > 0:
                arg = node.args[0]
                is_dangerous_concat = False
                
                # Case 1: Direct Binary Op (+) with string & tainted var
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    is_dangerous_concat = True
                # Case 2: Joined Str (f-string)
                elif isinstance(arg, ast.JoinedStr):
                    is_dangerous_concat = True
                # Case 3: Tainted variable that was created via concatenation
                elif isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                    is_dangerous_concat = True
                    
                # Safe Parameterized Check: If second argument is passed (e.g. tuple of params), it's safe!
                has_param_tuple = len(node.args) > 1 and isinstance(node.args[1], (ast.Tuple, ast.List, ast.Dict))
                
                if is_dangerous_concat and not has_param_tuple:
                    self.findings.append({
                        "type": "UNKNOWN_CUSTOM_FLAW",
                        "subtype": "SQL_INJECTION" if func_name == "execute" else "COMMAND_INJECTION",
                        "file": self.file_path,
                        "line": node.lineno,
                        "sink": func_name,
                        "description": f"Untrusted data flow to sink '{func_name}' without parameterization."
                    })
        self.generic_visit(node)

class UnknownVulnerabilityEngine:
    @staticmethod
    def analyze_code(code_string: str, file_path: str = "test.py"):
        try:
            tree = ast.parse(code_string)
            visitor = ASTTaintVisitor(file_path=file_path)
            visitor.visit(tree)
            return visitor.findings
        except Exception as e:
            return []

if __name__ == "__main__":
    engine = UnknownVulnerabilityEngine()
    
    # 1. Dangerous code test
    unsafe_code = 'user_input = get_input()\ndb.execute("SELECT * FROM users WHERE name = " + user_input)\n'
    unsafe_findings = engine.analyze_code(unsafe_code, "unsafe.py")
    print("Unsafe Code Findings:", unsafe_findings)
    
    # 2. Safe parameterized code test
    safe_code = 'user_input = get_input()\ndb.execute("SELECT * FROM users WHERE name = %s", (user_input,))\n'
    safe_findings = engine.analyze_code(safe_code, "safe.py")
    print("Safe Code Findings:", safe_findings)
