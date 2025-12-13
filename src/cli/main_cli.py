#!/usr/bin/env python3
"""
DAY 8: Enhanced CLI with HTML Reports
Learning: Integrating HTML report generation into CLI
"""

import argparse
import sys
import os
import json
from datetime import datetime

# Fix import paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
sys.path.insert(0, project_root)

# Import our analyzers
try:
    from src.analyzers.sql_injection import SQLInjectionAnalyzer
    from src.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer
    from src.analyzers.database_connection import DatabaseConnectionAnalyzer
    from src.analyzers.input_validation import InputValidationAnalyzer
    from src.report.html_generator import HTMLReportGenerator
    
    ANALYZERS_AVAILABLE = True
    HTML_REPORTS_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Some modules not available: {e}")
    ANALYZERS_AVAILABLE = False
    HTML_REPORTS_AVAILABLE = False

class SecurityAnalyzerCLI:
    """Main CLI interface for the security analyzer"""
    
    def __init__(self):
        if not ANALYZERS_AVAILABLE:
            self.analyzers = {}
        else:
            self.analyzers = {
                'sql': SQLInjectionAnalyzer(),
                'secrets': HardcodedSecretsAnalyzer(),
                'db': DatabaseConnectionAnalyzer(),
                'input': InputValidationAnalyzer()
            }
        
        # Initialize HTML reporter if available
        self.html_reporter = HTMLReportGenerator() if HTML_REPORTS_AVAILABLE else None
        
        # Color codes for terminal output
        self.colors = {
            'HIGH': '\033[91m',
            'MEDIUM': '\033[93m',
            'LOW': '\033[94m',
            'INFO': '\033[96m',
            'RESET': '\033[0m',
            'GREEN': '\033[92m',
            'BOLD': '\033[1m',
            'CYAN': '\033[96m'
        }
    
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{self.colors['BOLD']}{self.colors['CYAN']}
╔══════════════════════════════════════════════════════════╗
║          DATABASE SECURITY STATIC ANALYZER               ║
║                   30-Day Learning Project                ║
║                      Day 8: HTML Reports                 ║
╚══════════════════════════════════════════════════════════╝{self.colors['RESET']}
        """
        print(banner)
        
        # Show features
        print(f"\n{self.colors['BOLD']}✨ Features:{self.colors['RESET']}")
        print("-" * 40)
        print(f"  • {self.colors['GREEN']}4 Security Analyzers{self.colors['RESET']}")
        print(f"  • {self.colors['GREEN']}3 Report Formats (Text/JSON/HTML){self.colors['RESET']}")
        print(f"  • {self.colors['GREEN']}Professional HTML Reports{self.colors['RESET']}")
        print(f"  • {self.colors['GREEN']}Color-coded Output{self.colors['RESET']}")
    
    def analyze_file(self, file_path, analyzers=None):
        """Analyze a single file"""
        print(f"\n{self.colors['BOLD']}📁 Analyzing:{self.colors['RESET']} {file_path}")
        print("=" * 60)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            return []
        
        all_vulnerabilities = []
        
        # Run selected analyzers
        if analyzers is None:
            analyzers = self.analyzers.keys()
        
        for analyzer_name in analyzers:
            if analyzer_name in self.analyzers:
                print(f"\n🔍 Running {analyzer_name.upper()} analyzer...")
                analyzer = self.analyzers[analyzer_name]
                vulnerabilities = analyzer.analyze(code, file_path)
                
                for vuln in vulnerabilities:
                    vuln['analyzer'] = analyzer_name.upper()
                    # Add timestamp for HTML report
                    vuln['timestamp'] = datetime.now().strftime('%H:%M:%S')
                    all_vulnerabilities.append(vuln)
                    
                    # Print vulnerability with colors
                    severity = vuln.get('severity', 'INFO')
                    color = self.colors.get(severity, self.colors['RESET'])
                    
                    print(f"{color}⚠️  [{severity}] {vuln['type']}{self.colors['RESET']}")
                    print(f"   📍 {vuln['filename']}:{vuln['line']}")
                    print(f"   📝 {vuln['message']}")
                    if 'code' in vuln and vuln['code']:
                        # Truncate long code snippets
                        code_preview = vuln['code']
                        if len(code_preview) > 100:
                            code_preview = code_preview[:97] + "..."
                        print(f"   📄 {code_preview}")
                    if 'recommendation' in vuln:
                        print(f"   💡 {vuln['recommendation']}")
                    print()
        
        if not all_vulnerabilities:
            print(f"{self.colors['GREEN']}✅ No vulnerabilities found!{self.colors['RESET']}")
        
        return all_vulnerabilities
    
    def analyze_directory(self, directory_path, analyzers=None):
        """Analyze all Python files in a directory"""
        all_vulnerabilities = []
        
        # Find all Python files
        python_files = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        
        print(f"\n📁 Found {len(python_files)} Python files to analyze")
        
        for i, file_path in enumerate(python_files, 1):
            print(f"\n[{i}/{len(python_files)}] ", end="")
            vulns = self.analyze_file(file_path, analyzers)
            all_vulnerabilities.extend(vulns)
        
        return all_vulnerabilities
    
    def generate_report(self, vulnerabilities, output_format='text', output_file=None):
        """Generate a report in specified format"""
        if not vulnerabilities:
            print(f"\n{self.colors['GREEN']}📊 No vulnerabilities to report.{self.colors['RESET']}")
            return ""
        
        print(f"\n{self.colors['BOLD']}📊 Generating {output_format.upper()} report...{self.colors['RESET']}")
        
        if output_format == 'json':
            return self._generate_json_report(vulnerabilities, output_file)
        elif output_format == 'html':
            return self._generate_html_report(vulnerabilities, output_file)
        else:
            return self._generate_text_report(vulnerabilities, output_file)
    
    def _generate_text_report(self, vulnerabilities, output_file=None):
        """Generate text report"""
        report_lines = []
        report_lines.append("\n" + "=" * 70)
        report_lines.append("🔒 SECURITY ANALYSIS REPORT")
        report_lines.append("=" * 70)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total vulnerabilities: {len(vulnerabilities)}")
        
        # Count by severity
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        report_lines.append(f"\n{self.colors['BOLD']}📊 Severity Summary:{self.colors['RESET']}")
        report_lines.append("-" * 40)
        for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = self.colors.get(severity, '')
                report_lines.append(f"{color}  {severity}: {count}{self.colors['RESET']}")
        
        report_text = "\n".join(report_lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"✅ Text report saved: {output_file}")
        
        return report_text
    
    def _generate_json_report(self, vulnerabilities, output_file=None):
        """Generate JSON report"""
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'Database Security Static Analyzer',
                'version': '1.0',
                'total_vulnerabilities': len(vulnerabilities)
            },
            'vulnerabilities': vulnerabilities
        }
        
        json_report = json.dumps(report, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_report)
            print(f"✅ JSON report saved: {output_file}")
        
        return json_report
    
    def _generate_html_report(self, vulnerabilities, output_file=None):
        """Generate HTML report"""
        if not self.html_reporter or not self.html_reporter.available:
            print(f"{self.colors['YELLOW']}⚠️  HTML reports not available. Install Jinja2.{self.colors['RESET']}")
            return ""
        
        if not output_file:
            output_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        result = self.html_reporter.generate(vulnerabilities, output_file)
        if result:
            print(f"✅ HTML report saved: {result}")
            return result
        else:
            return ""

def main():
    """Main CLI entry point"""
    cli = SecurityAnalyzerCLI()
    cli.print_banner()
    
    parser = argparse.ArgumentParser(
        description='Static Analysis Tool for Database Security',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s examples/test_code.py
  %(prog)s . --format html --output report.html
  %(prog)s src/ --analyzers sql,secrets --format json
  %(prog)s test_vuln.py --format html --open
        """
    )
    
    parser.add_argument('path', help='File or directory to analyze')
    parser.add_argument('--analyzers', default='all',
                       help='Comma-separated list of analyzers: sql,secrets,db,input')
    parser.add_argument('--format', default='text', choices=['text', 'json', 'html'],
                       help='Output format')
    parser.add_argument('--output', help='Save report to file')
    parser.add_argument('--open', action='store_true', 
                       help='Open HTML report in browser after generation')
    
    args = parser.parse_args()
    
    # Determine which analyzers to run
    if args.analyzers == 'all':
        analyzers_to_run = None
    else:
        analyzers_to_run = [a.strip() for a in args.analyzers.split(',')]
    
    # Check if we have analyzers
    if not cli.analyzers:
        print("❌ No analyzers available. Please check that all analyzer files exist.")
        sys.exit(1)
    
    # Analyze path
    start_time = datetime.now()
    
    if os.path.isfile(args.path):
        vulnerabilities = cli.analyze_file(args.path, analyzers_to_run)
    elif os.path.isdir(args.path):
        vulnerabilities = cli.analyze_directory(args.path, analyzers_to_run)
    else:
        print(f"❌ Error: Path '{args.path}' not found")
        sys.exit(1)
    
    # Generate report
    report = cli.generate_report(vulnerabilities, args.format, args.output)
    
    # Open HTML report in browser if requested
    if args.format == 'html' and args.open:
        report_file = args.output or f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        try:
            import webbrowser
            webbrowser.open(f'file://{os.path.abspath(report_file)}')
            print(f"🌐 Opened report in browser")
        except:
            print("⚠️  Could not open browser")
    
    # Calculate and display analysis time
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    print(f"\n⏱️  Analysis completed in {duration:.2f} seconds")
    
    # Exit code based on findings
    if any(v['severity'] in ['HIGH', 'MEDIUM'] for v in vulnerabilities):
        print(f"\n{cli.colors['BOLD']}{cli.colors['HIGH']}❌ Security issues found!{cli.colors['RESET']}")
        sys.exit(1)
    else:
        print(f"\n{cli.colors['BOLD']}{cli.colors['GREEN']}✅ No critical issues found!{cli.colors['RESET']}")
        sys.exit(0)

if __name__ == "__main__":
    main()
