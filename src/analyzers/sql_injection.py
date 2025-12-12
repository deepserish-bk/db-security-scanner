#!/usr/bin/env python3
"""
SQL Injection Detection Module
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
            # Check for SQL execute calls with string concatenation
            if isinstance(node, ast.Call):
                self._check_sql_call(node, filename)
            
            # Check for string concatenation in assignments
            elif isinstance(node, ast.Assign):
                self._check_string_concat(node, filename)
    
    def _check_sql_call(self, node, filename):
        """Check if a function call might be vulnerable SQL execution"""
        # Check if it's an execute method call
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['execute', 'executemany']:
                # Check arguments for string concatenation
                for arg in node.args:
                    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                        self._add_vulnerability(
                            filename=filename,
                            line=node.lineno,
                            type="SQL Injection",
                            severity="HIGH",
                            message="String concatenation in SQL execute() call",
                            code=self._get_code_snippet(node),
                            recommendation="Use parameterized queries: cursor.execute('SELECT ... WHERE id = ?', (user_id,))"
                        )
    
    def _check_string_concat(self, node, filename):
        """Check string concatenation that might be used in SQL"""
        SQL_KEYWORDS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WHERE', 'FROM']
        
        if isinstance(node.value, ast.BinOp):
            # Try to get the code as string
            try:
                code_str = ast.unparse(node) if hasattr(ast, 'unparse') else str(node)
            except:
                code_str = str(node)
            
            # Check if this looks like SQL
            if any(keyword in code_str.upper() for keyword in SQL_KEYWORDS):
                if isinstance(node.value.op, ast.Add):
                    self._add_vulnerability(
                        filename=filename,
                        line=node.lineno,
                        type="SQL Injection",
                        severity="MEDIUM",
                        message="String concatenation that might build SQL query",
                        code=code_str[:100],
                        recommendation="Use parameterized queries or stored procedures"
                    )
    
    def _get_code_snippet(self, node):
        """Try to get code snippet for display"""
        try:
            return ast.unparse(node) if hasattr(ast, 'unparse') else str(node)
        except:
            return "Unable to extract code"
    
    def _add_vulnerability(self, **kwargs):
        """Add a vulnerability to the list"""
        self.vulnerabilities.append(kwargs)
