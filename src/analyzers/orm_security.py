#!/usr/bin/env python3
"""
ORM Security Analyzer
Detects security vulnerabilities in Object-Relational Mappers
"""

import ast

class ORMSecurityAnalyzer:
    def __init__(self):
        self.vulnerabilities = []
    
    def analyze(self, code, filename="unknown"):
        """Analyze code for ORM security vulnerabilities"""
        try:
            tree = ast.parse(code)
            self._walk_tree(tree, filename)
        except SyntaxError as e:
            print(f"Syntax error in {filename}: {e}")
        
        return self.vulnerabilities
    
    def _walk_tree(self, tree, filename):
        """Walk through AST looking for ORM vulnerabilities"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_sqlalchemy(node, filename)
                self._check_django_orm(node, filename)
    
    def _check_sqlalchemy(self, node, filename):
        """Check SQLAlchemy security issues"""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'execute':
                for arg in node.args:
                    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                        self._add_vulnerability(
                            filename=filename,
                            line=node.lineno,
                            type="SQLAlchemy Security",
                            severity="HIGH",
                            message="String concatenation in SQLAlchemy execute() call",
                            code=self._get_code_snippet(node),
                            recommendation="Use parameterized queries with session.execute()"
                        )
    
    def _check_django_orm(self, node, filename):
        """Check Django ORM security issues"""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'raw':
                self._add_vulnerability(
                    filename=filename,
                    line=node.lineno,
                    type="Django ORM Security",
                    severity="MEDIUM",
                    message="Django raw() method used - potential SQL injection risk",
                    code=self._get_code_snippet(node),
                    recommendation="Use parameterized queries with Model.objects.raw()"
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
