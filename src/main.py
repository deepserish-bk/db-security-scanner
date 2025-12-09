#!/usr/bin/env python3
"""
Day 5: Main Security Analyzer Runner
Orchestrates all security analyzers
"""

import os
import sys
from datetime import datetime

# Import analyzers
from src.analyzers.sql_injection import SQLInjectionAnalyzer
from src.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer

class SecurityAnalyzer:
    """Main security analyzer that runs all checks"""
    
    def __init__(self):
        self.analyzers = [
            ("SQL Injection", SQLInjectionAnalyzer()),
            ("Hardcoded Secrets", HardcodedSecretsAnalyzer())
        ]
        self.results = []
    
    def analyze_file(self, filepath):
        """Analyze a single Python file"""
        print(f"\n🔍 Analyzing: {filepath}")
        print("=" * 60)
        
        try:
            with open(filepath, 'r') as f:
                code = f.read()
        except FileNotFoundError:
            print(f"❌ File not found: {filepath}")
            return
        
        file_results = []
        
        for analyzer_name, analyzer in self.analyzers:
            vulnerabilities = analyzer.analyze(code, filepath)
            for vuln in vulnerabilities:
                file_results.append(vuln)
                # Print findings
                severity_color = {
                    'HIGH': '\033[91m',   # Red
                    'MEDIUM': '\033[93m', # Yellow
                    'LOW': '\033[94m'     # Blue
                }.get(vuln['severity'], '\033[0m')
                
                print(f"{severity_color}⚠️  [{vuln['severity']}] {vuln['type']}")
                print(f"   {filepath}:{vuln['line']} - {vuln['message']}")
                print(f"\033[0m")
        
        if not file_results:
            print("✅ No vulnerabilities found!")
        
        return file_results
    
    def analyze_directory(self, dirpath):
        """Analyze all Python files in a directory"""
        all_results = []
        
        for root, dirs, files in os.walk(dirpath):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    results = self.analyze_file(filepath)
                    if results:
                        all_results.extend(results)
        
        return all_results
    
    def generate_report(self, results):
        """Generate a summary report"""
        print("\n" + "=" * 60)
        print("📊 SECURITY ANALYSIS REPORT")
        print("=" * 60)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total vulnerabilities found: {len(results)}")
        
        # Count by severity
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for result in results:
            severity_counts[result['severity']] = severity_counts.get(result['severity'], 0) + 1
        
        print("\nSeverity Summary:")
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"  {severity}: {count}")
        
        return severity_counts

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python src/main.py <file_or_directory>")
        print("Example: python src/main.py tests/vulnerable_test.py")
        sys.exit(1)
    
    target = sys.argv[1]
    analyzer = SecurityAnalyzer()
    
    print("\n" + "=" * 60)
    print("🔒 DATABASE SECURITY STATIC ANALYZER")
    print("=" * 60)
    
    if os.path.isfile(target):
        results = analyzer.analyze_file(target)
    elif os.path.isdir(target):
        results = analyzer.analyze_directory(target)
    else:
        print(f"❌ Target not found: {target}")
        sys.exit(1)
    
    analyzer.generate_report(results)
    
    # Exit with appropriate code
    if any(r['severity'] == 'HIGH' for r in results):
        print("\n❌ Critical security issues found!")
        sys.exit(1)
    else:
        print("\n✅ Analysis complete!")
        sys.exit(0)

if __name__ == "__main__":
    main()
