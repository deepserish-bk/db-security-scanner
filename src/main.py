
#!/usr/bin/env python3
"""
Main Security Analyzer with Enhanced Reporting
"""

import os
import sys

# Add the parent directory to Python path so we can import from src
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Now we can import from src.analyzers
from src.analyzers.sql_injection import SQLInjectionAnalyzer
from src.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer

# Import enhanced reporter
from src.utils.reporter import ReportGenerator

class SecurityAnalyzer:
    """Main security analyzer with comprehensive reporting"""
    
    def __init__(self):
        self.analyzers = [
            ("SQL Injection", SQLInjectionAnalyzer()),
            ("Hardcoded Secrets", HardcodedSecretsAnalyzer())
        ]
        self.reporter = ReportGenerator()
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
            return []
        except UnicodeDecodeError:
            print(f"❌ Cannot read file (encoding issue): {filepath}")
            return []
        
        file_results = []
        
        for analyzer_name, analyzer in self.analyzers:
            try:
                vulnerabilities = analyzer.analyze(code, filepath)
                for vuln in vulnerabilities:
                    vuln['analyzer'] = analyzer_name
                    file_results.append(vuln)
            except Exception as e:
                print(f"❌ Error in {analyzer_name} analyzer: {e}")
        
        # Display findings
        if file_results:
            for vuln in file_results:
                severity = vuln.get('severity', 'INFO')
                color = {
                    'HIGH': '\033[91m',
                    'MEDIUM': '\033[93m',
                    'LOW': '\033[94m',
                    'INFO': '\033[96m'
                }.get(severity, '\033[0m')
                
                print(f"{color}⚠️  [{severity}] {vuln['type']}")
                print(f"   {filepath}:{vuln['line']} - {vuln['message']}")
                if 'recommendation' in vuln:
                    print(f"   💡 {vuln['recommendation']}")
                print("\033[0m")
        else:
            print("✅ No vulnerabilities found!")
        
        self.results.extend(file_results)
        return file_results
    
    def analyze_directory(self, dirpath):
        """Analyze all Python files in a directory"""
        all_results = []
        
        # Count files first
        python_files = []
        for root, dirs, files in os.walk(dirpath):
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        
        print(f"\n📁 Found {len(python_files)} Python files to analyze")
        
        # Analyze each file
        for i, filepath in enumerate(python_files, 1):
            print(f"\n[{i}/{len(python_files)}] ", end="")
            results = self.analyze_file(filepath)
            if results:
                all_results.extend(results)
        
        return all_results
    
    def generate_report(self, format='text', output_file=None):
        """Generate a comprehensive report"""
        if not self.results:
            print("\n📊 No vulnerabilities found to report.")
            return ""
        
        print(f"\n📊 Generating {format.upper()} report...")
        
        if format == 'json':
            report = self.reporter.generate_json_report(self.results, output_file)
        elif format == 'html':
            report = self.reporter.generate_html_report(self.results, output_file)
        else:
            report = self.reporter.generate_text_report(self.results, output_file)
        
        if not output_file:
            print("\n" + "=" * 60)
            print("📋 REPORT OUTPUT")
            print("=" * 60)
            if format == 'text':
                print(report)
            else:
                print(f"{format.upper()} report generated successfully")
                print("Use --output <filename> to save to a file")
        
        return report
    
    def print_summary(self):
        """Print a summary of findings"""
        if not self.results:
            print("\n🎉 Great! No security vulnerabilities found!")
            return True
        
        print("\n" + "=" * 60)
        print("📈 ANALYSIS SUMMARY")
        print("=" * 60)
        
        # Count by severity
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        analyzer_counts = {}
        
        for result in self.results:
            severity = result.get('severity', 'INFO')
            analyzer = result.get('analyzer', 'Unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            analyzer_counts[analyzer] = analyzer_counts.get(analyzer, 0) + 1
        
        print(f"\n📊 Total vulnerabilities: {len(self.results)}")
        
        print("\n⚠️  Severity Breakdown:")
        for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = {
                    'HIGH': '\033[91m',
                    'MEDIUM': '\033[93m',
                    'LOW': '\033[94m',
                    'INFO': '\033[96m'
                }.get(severity, '\033[0m')
                print(f"  {color}{severity}: {count}\033[0m")
        
        print("\n🔧 Analyzer Breakdown:")
        for analyzer, count in sorted(analyzer_counts.items()):
            print(f"  {analyzer}: {count}")
        
        # Return True if no critical issues
        return severity_counts.get('HIGH', 0) == 0

def main():
    """Main entry point with enhanced CLI"""
    if len(sys.argv) < 2:
        print("""
🔒 Database Security Static Analyzer

Usage: python src/main.py <file_or_directory> [options]

Options:
  --format <text|json|html>  Output format (default: text)
  --output <filename>         Save report to file

Examples:
  python src/main.py tests/vulnerable_test.py
  python src/main.py . --format json
  python src/main.py src/ --output report.html
        """)
        sys.exit(1)
    
    target = sys.argv[1]
    output_format = 'text'
    output_file = None
    
    # Parse optional arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--format' and i + 1 < len(sys.argv):
            output_format = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--output' and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 2
        else:
            i += 1
    
    analyzer = SecurityAnalyzer()
    
    print("\n" + "=" * 60)
    print("🔒 DATABASE SECURITY STATIC ANALYZER")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"Output format: {output_format}")
    if output_file:
        print(f"Output file: {output_file}")
    
    # Check if target exists
    if not os.path.exists(target):
        print(f"\n❌ Error: Target '{target}' not found")
        sys.exit(1)
    
    # Analyze target
    if os.path.isfile(target):
        analyzer.analyze_file(target)
    else:
        analyzer.analyze_directory(target)
    
    # Generate report
    analyzer.generate_report(output_format, output_file)
    
    # Print summary and exit
    if analyzer.print_summary():
        print("\n✅ Analysis completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Critical security issues found!")
        sys.exit(1)

if __name__ == "__main__":
    main()
