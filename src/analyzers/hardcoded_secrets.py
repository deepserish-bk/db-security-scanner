
"""
Day 4: Hardcoded Secrets Detection
Detects passwords, API keys, and other secrets in code
"""

import ast
import re

class HardcodedSecretsAnalyzer:
    def __init__(self):
        self.vulnerabilities = []
        self.secret_patterns = {
            'password': r'pass(word|wd|phrase)',
            'api_key': r'api[_-]?key',
            'secret': r'secret[_-]?(key|token)?',
            'token': r'(access[_-]?|refresh[_-]?)token'
        }
    
    def analyze(self, code, filename="unknown"):
        """Analyze code for hardcoded secrets"""
        try:
            tree = ast.parse(code)
            self._walk_tree(tree, filename)
        except SyntaxError as e:
            print(f"⚠️  Syntax error in {filename}: {e}")
        
        return self.vulnerabilities
    
    def _walk_tree(self, tree, filename):
        """Walk AST looking for hardcoded secrets"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                self._check_assignment(node, filename)
    
    def _check_assignment(self, node, filename):
        """Check variable assignments for secrets"""
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
            var_name = ""
            
            if node.targets and isinstance(node.targets[0], ast.Name):
                var_name = node.targets[0].id.lower()
            
            # Check variable name patterns
            for pattern_name, pattern in self.secret_patterns.items():
                if re.search(pattern, var_name, re.IGNORECASE):
                    self._add_vulnerability(
                        filename=filename,
                        line=node.lineno,
                        type="Hardcoded Secret",
                        severity="HIGH",
                        message=f"Hardcoded {pattern_name} found in variable '{var_name}'",
                        recommendation="Use environment variables or secret management"
                    )
            
            # Check if value looks like a secret (long strings)
            if len(value) > 20 and not value.startswith('http'):
                self._add_vulnerability(
                    filename=filename,
                    line=node.lineno,
                    type="Suspicious String",
                    severity="MEDIUM",
                    message="Long string that might be a secret",
                    recommendation="Review if this should be hardcoded"
                )
    
    def _add_vulnerability(self, **kwargs):
        """Add a vulnerability to the list"""
        self.vulnerabilities.append(kwargs)
