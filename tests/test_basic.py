#!/usr/bin/env python3
"""
Basic tests for the security analyzer
"""
import unittest
import tempfile
import os
from src.analyzers.sql_injection import SQLInjectionAnalyzer
from src.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer

class TestSecurityAnalyzers(unittest.TestCase):
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection"""
        code = '''
import sqlite3
def bad():
    cursor.execute("SELECT * FROM users WHERE id = " + user_input)
'''
        analyzer = SQLInjectionAnalyzer()
        results = analyzer.analyze(code, 'test.py')
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]['type'], 'SQL Injection')
    
    def test_hardcoded_secret_detection(self):
        """Test hardcoded secret detection"""
        code = 'PASSWORD = "supersecret123"'
        analyzer = HardcodedSecretsAnalyzer()
        results = analyzer.analyze(code, 'test.py')
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]['type'], 'Hardcoded Secret')

if __name__ == '__main__':
    unittest.main()
