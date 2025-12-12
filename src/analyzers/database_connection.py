#!/usr/bin/env python3
"""
Database Connection Analyzer
Checks for insecure database configurations
"""

import ast

class DatabaseConnectionAnalyzer:
    """Analyzes database connection security"""
    
    def __init__(self):
        self.vulnerabilities = []
    
    def analyze(self, code, filename="unknown"):
        """Analyze code for database connection issues"""
        try:
            tree = ast.parse(code)
            self._walk_tree(tree, filename)
        except SyntaxError as e:
            print(f"⚠️  Syntax error in {filename}: {e}")
        
        return self.vulnerabilities
    
    def _walk_tree(self, tree, filename):
        """Walk through AST looking for database connection issues"""
        for node in ast.walk(tree):
            # Check for database connection calls
            if isinstance(node, ast.Call):
                self._check_connection_call(node, filename)
            
            # Check for database imports
            elif isinstance(node, ast.Import):
                self._check_database_imports(node, filename)
    
    def _check_connection_call(self, node, filename):
        """Check database connection function calls"""
        if isinstance(node.func, ast.Attribute):
            # Check for sqlite3.connect(), psycopg2.connect(), etc.
            if node.func.attr == 'connect':
                # Check for insecure connection parameters
                if node.args:
                    # Check first argument (database path/URL)
                    db_arg = node.args[0]
                    if isinstance(db_arg, ast.Constant) and isinstance(db_arg.value, str):
                        db_value = db_arg.value
                        
                        # Check for in-memory database
                        if db_value == ':memory:':
                            self._add_vulnerability(
                                filename=filename,
                                line=node.lineno,
                                type="Database Security",
                                severity="LOW",
                                message="SQLite in-memory database used - data not persistent",
                                recommendation="Use file-based database for production"
                            )
    
    def _check_database_imports(self, node, filename):
        """Check which database libraries are imported"""
        db_libraries = ['sqlite3', 'psycopg2', 'mysql.connector', 'pymysql', 'sqlalchemy']
        
        for alias in node.names:
            if alias.name in db_libraries:
                self._add_vulnerability(
                    filename=filename,
                    line=node.lineno,
                    type="Database Import",
                    severity="INFO",
                    message=f"Database library '{alias.name}' imported",
                    recommendation="Ensure secure connection practices are followed"
                )
    
    def _add_vulnerability(self, **kwargs):
        """Add a vulnerability to the list"""
        self.vulnerabilities.append(kwargs)
