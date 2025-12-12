#!/usr/bin/env python3
"""
Input Validation Analyzer
Checks for missing input validation
"""

import ast

class InputValidationAnalyzer:
    """Analyzes input validation in code"""
    
    def __init__(self):
        self.vulnerabilities = []
    
    def analyze(self, code, filename="unknown"):
        """Analyze code for input validation issues"""
        try:
            tree = ast.parse(code)
            self._walk_tree(tree, filename)
        except SyntaxError as e:
            print(f"⚠️  Syntax error in {filename}: {e}")
        
        return self.vulnerabilities
    
    def _walk_tree(self, tree, filename):
        """Walk AST looking for input handling without validation"""
        for node in ast.walk(tree):
            # Check for dangerous functions
            if isinstance(node, ast.Call):
                self._check_dangerous_functions(node, filename)
            
            # Check for input() function
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id == 'input':
                        self._add_vulnerability(
                            filename=filename,
                            line=node.lineno,
                            type="Input Validation",
                            severity="MEDIUM",
                            message="input() function used without validation",
                            recommendation="Validate all user inputs before use"
                        )
    
    def _check_dangerous_functions(self, node, filename):
        """Check for dangerous functions like eval() and exec()"""
        if isinstance(node.func, ast.Name):
            if node.func.id == 'eval':
                self._add_vulnerability(
                    filename=filename,
                    line=node.lineno,
                    type="Dangerous Function",
                    severity="HIGH",
                    message="eval() function used - can execute arbitrary code",
                    recommendation="Avoid eval() with untrusted input"
                )
            elif node.func.id == 'exec':
                self._add_vulnerability(
                    filename=filename,
                    line=node.lineno,
                    type="Dangerous Function",
                    severity="HIGH",
                    message="exec() function used - can execute arbitrary code",
                    recommendation="Avoid exec() with untrusted input"
                )
    
    def _add_vulnerability(self, **kwargs):
        """Add a vulnerability to the list"""
        self.vulnerabilities.append(kwargs)
