#!/usr/bin/env python3
"""
Day 3: SQL Injection Detection Module
Detects potential SQL injection vulnerabilities in Python code
"""

import ast

class SQLInjectionAnalyzer:
    def __init__(self):
        self.vulnerabilities = []
    
    def analyze(self, code, filename="unknown"):
        """Analyze code for SQL injection vulnerabilities"""
        try:
            tree = ast.parse(code)
            self._walk_tree(tree, filename)
        except SyntaxError as e:
            print(f"⚠️  Syntax error in {filename}: {e}")
        
        return self.vulnerabilities
    
    def _walk_tree(self, tree, filename):
        """Walk through AST nodes looking for SQL vulnerabilities"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_sql_call(node, filename)
            elif isinstance(node, ast.Assign):
                self._check_string_concat(node, filename)
    
    def _check_sql_call(self, node, filename):
        """Check if a function call might be vulnerable SQL execution"""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['execute', 'executemany']:
                if node.args and isinstance(node.args[0], ast.BinOp):
                    if isinstance(node.args[0].op, ast.Add):
                        self._add_vulnerability(
                            filename=filename,
                            line=node.lineno,
                            type="SQL Injection",
                            severity="HIGH",
                            message="String concatenation in SQL execute() call",
                            recommendation="Use parameterized queries"
                        )
    
    def _check_string_concat(self, node, filename):
        """Check string concatenation that might be used in SQL"""
        SQL_KEYWORDS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WHERE']
        if isinstance(node.value, ast.BinOp):
            line_code = ast.unparse(node) if hasattr(ast, 'unparse') else str(node)
            if any(keyword in line_code.upper() for keyword in SQL_KEYWORDS):
                if isinstance(node.value.op, ast.Add):
                    self._add_vulnerability(
                        filename=filename,
                        line=node.lineno,
                        type="SQL Injection",
                        severity="MEDIUM",
                        message="String concatenation that might build SQL query",
                        recommendation="Use parameterized queries"
                    )
    
    def _add_vulnerability(self, **kwargs):
        """Add a vulnerability to the list"""
        self.vulnerabilities.append(kwargs)
