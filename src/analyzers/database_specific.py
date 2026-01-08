#!/usr/bin/env python3
"""Database-specific security analyzer - Day 11"""
import ast
import re

class DatabaseSpecificAnalyzer:
    def __init__(self):
        self.vulnerabilities = []
    
    def analyze(self, code, filename="unknown"):
        """Analyze code for database-specific security issues"""
        try:
            tree = ast.parse(code)
            self._walk_tree(tree, filename)
        except SyntaxError as e:
            print(f"⚠️  Syntax error in {filename}: {e}")
        
        return self.vulnerabilities
    
    def _walk_tree(self, tree, filename):
        """Walk through AST looking for database-specific vulnerabilities"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_nosql_injection(node, filename)
                self._check_redis_security(node, filename)
                self._check_sql_server_issues(node, filename)
                self._check_cassandra_issues(node, filename)
    
    def _check_nosql_injection(self, node, filename):
        """Check for NoSQL injection vulnerabilities"""
        # MongoDB specific checks
        if isinstance(node.func, ast.Attribute):
            mongo_methods = ['find', 'find_one', 'aggregate', 'update_one', 
                           'update_many', 'delete_one', 'delete_many', 'insert_one']
            
            if node.func.attr in mongo_methods:
                for arg in node.args:
                    if isinstance(arg, ast.Dict):
                        # Check if user input is directly used in query
                        for key_node in arg.keys:
                            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                                if '$where' in key_node.value or '$expr' in key_node.value:
                                    self._add_vulnerability(
                                        filename=filename,
                                        line=node.lineno,
                                        type="NoSQL Injection",
                                        severity="HIGH",
                                        message=f"MongoDB {node.func.attr}() with potentially dangerous operator: {key_node.value}",
                                        recommendation="Validate and sanitize all query parameters, avoid $where and $expr with user input"
                                    )
    
    def _check_redis_security(self, node, filename):
        """Check Redis security vulnerabilities"""
        if isinstance(node.func, ast.Attribute):
            # Check for dangerous Redis commands
            dangerous_commands = ['EVAL', 'EVALSHA', 'DEBUG', 'CONFIG', 'SHUTDOWN', 'FLUSHALL']
            
            if node.func.attr.upper() in dangerous_commands:
                self._add_vulnerability(
                    filename=filename,
                    line=node.lineno,
                    type="Redis Security",
                    severity="HIGH",
                    message=f"Potentially dangerous Redis command: {node.func.attr}",
                    recommendation="Avoid using dangerous Redis commands in application code, especially with user input"
                )
            
            # Check for KEYS command (can be slow)
            if node.func.attr.upper() == 'KEYS':
                self._add_vulnerability(
                    filename=filename,
                    line=node.lineno,
                    type="Redis Performance",
                    severity="MEDIUM",
                    message="Redis KEYS command used - can block server on large datasets",
                    recommendation="Use SCAN instead of KEYS for production systems"
                )
    
    def _check_sql_server_issues(self, node, filename):
        """Check SQL Server specific issues"""
        if isinstance(node.func, ast.Attribute):
            # Check for xp_cmdshell usage
            sql = ast.unparse(node) if hasattr(ast, 'unparse') else str(node)
            sql_upper = sql.upper()
            
            if 'XP_CMDSHELL' in sql_upper or 'SP_OACREATE' in sql_upper:
                self._add_vulnerability(
                    filename=filename,
                    line=node.lineno,
                    type="SQL Server Security",
                    severity="CRITICAL",
                    message="Dangerous SQL Server extended procedure used",
                    recommendation="Remove xp_cmdshell and sp_OACreate calls from application code"
                )
            
            # Check for dynamic SQL with EXEC/EXECUTE
            if 'EXEC(' in sql_upper or 'EXECUTE(' in sql_upper:
                # Check if there's string concatenation
                for arg in node.args:
                    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                        self._add_vulnerability(
                            filename=filename,
                            line=node.lineno,
                            type="SQL Server Injection",
                            severity="HIGH",
                            message="Dynamic SQL with string concatenation in EXEC statement",
                            recommendation="Use parameterized queries or sp_executesql with parameters"
                        )
    
    def _check_cassandra_issues(self, node, filename):
        """Check Cassandra specific issues"""
        if isinstance(node.func, ast.Attribute):
            # Check for unsafe CQL queries
            if node.func.attr in ['execute', 'execute_async']:
                for arg in node.args:
                    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                        self._add_vulnerability(
                            filename=filename,
                            line=node.lineno,
                            type="CQL Injection",
                            severity="HIGH",
                            message="String concatenation in Cassandra CQL query",
                            recommendation="Use prepared statements with bind variables"
                        )
    
    def _add_vulnerability(self, **kwargs):
        """Add a vulnerability to the list"""
        self.vulnerabilities.append(kwargs)