import argparse
import sys
import os
from pathlib import Path
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
    
    ANALYZERS_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Some analyzers not available: {e}")
    print("⚠️  Make sure all analyzer files exist in src/analyzers/")
    ANALYZERS_AVAILABLE = False

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
        
        # Color codes for terminal output - FIXED: No 'RED' key
        self.colors = {
            'HIGH': '\033[91m',     # Red
            'MEDIUM': '\033[93m',   # Yellow
            'LOW': '\033[94m',      # Blue
            'INFO': '\033[96m',     # Cyan
            'RESET': '\033[0m',     # Reset
            'GREEN': '\033[92m',    # Green
            'BOLD': '\033[1m'       # Bold
        }
    
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{self.colors['BOLD']}{self.colors['GREEN']}
╔══════════════════════════════════════════════════════════╗
║          DATABASE SECURITY STATIC ANALYZER               ║
║                   30-Day Learning Project                ║
║                        Day 7: CLI Interface              ║
╚══════════════════════════════════════════════════════════╝{self.colors['RESET']}
        """
        print(banner)
        
        # Show available analyzers
        print(f"\n{self.colors['BOLD']}Available Analyzers:{self.colors['RESET']}")
        print("-" * 40)
        for analyzer_name in self.analyzers.keys():
            print(f"  • {analyzer_name.upper()}")
        print()
    
    def analyze_file(self, file_path, analyzers=None):
        """Analyze a single file"""
        print(f"\n{self.colors['BOLD']}📁 Analyzing: {file_path}{self.colors['RESET']}")
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
                    all_vulnerabilities.append(vuln)
                    
                    # Print vulnerability
                    color = self.colors.get(vuln['severity'], self.colors['RESET'])
                    print(f"{color}⚠️  [{vuln['severity']}] {vuln['type']}")
                    print(f"   File: {vuln['filename']}:{vuln['line']}")
                    print(f"   Message: {vuln['message']}")
                    if 'code' in vuln and vuln['code']:
                        print(f"   Code: {vuln['code'][:100]}...")
                    print(f"   Recommendation: {vuln['recommendation']}")
                    print(f"{self.colors['RESET']}")
        
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
        
        print(f"\nFound {len(python_files)} Python files to analyze")
        
        for file_path in python_files:
            vulns = self.analyze_file(file_path, analyzers)
            all_vulnerabilities.extend(vulns)
        
        return all_vulnerabilities
    
    def generate_report(self, vulnerabilities, output_format='text'):
        """Generate a report of vulnerabilities"""
        if output_format == 'json':
            return self._generate_json_report(vulnerabilities)
        else:
            return self._generate_text_report(vulnerabilities)
    
    def _generate_text_report(self, vulnerabilities):
        """Generate text report"""
        report = []
        report.append("\n" + "=" * 60)
        report.append("SECURITY ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total vulnerabilities found: {len(vulnerabilities)}")
        
        if vulnerabilities:
            # Group by severity
            severity_counts = {}
            analyzer_counts = {}
            
            for vuln in vulnerabilities:
                severity = vuln['severity']
                analyzer = vuln.get('analyzer', 'Unknown')
                
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                analyzer_counts[analyzer] = analyzer_counts.get(analyzer, 0) + 1
            
            report.append("\n📊 Severity Summary:")
            for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    color = self.colors.get(severity, '')
                    report.append(f"  {color}{severity}: {count}{self.colors['RESET']}")
            
            report.append("\n🔧 Analyzer Breakdown:")
            for analyzer, count in sorted(analyzer_counts.items()):
                report.append(f"  {analyzer}: {count}")
        else:
            report.append("\n✅ No vulnerabilities found!")
        
        return "\n".join(report)
    
    def _generate_json_report(self, vulnerabilities):
        """Generate JSON report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
        return json.dumps(report, indent=2)

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
  %(prog)s src/ --analyzers sql,secrets
  %(prog)s . --output json > report.json
        """
    )
    
    parser.add_argument('path', help='File or directory to analyze')
    parser.add_argument('--analyzers', default='all',
                       help='Comma-separated list of analyzers: sql,secrets,db,input')
    parser.add_argument('--output', default='text', choices=['text', 'json'],
                       help='Output format')
    
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
    if os.path.isfile(args.path):
        vulnerabilities = cli.analyze_file(args.path, analyzers_to_run)
    elif os.path.isdir(args.path):
        vulnerabilities = cli.analyze_directory(args.path, analyzers_to_run)
    else:
        print(f"❌ Error: Path '{args.path}' not found")
        sys.exit(1)
    
    # Generate report
    report = cli.generate_report(vulnerabilities, args.output)
    print(report)
    
    # Save report to file
    if args.output == 'json':
        report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            f.write(report)
        print(f"\n✅ JSON report saved to: {report_file}")
    else:
        report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write(report)
        print(f"\n✅ Text report saved to: {report_file}")
    
    # Exit code based on findings - FIXED: Use 'HIGH' instead of 'RED'
    if any(v['severity'] in ['HIGH', 'MEDIUM'] for v in vulnerabilities):
        print(f"\n{cli.colors['BOLD']}{cli.colors['HIGH']}❌ Security issues found!{cli.colors['RESET']}")
        sys.exit(1)
    else:
        print(f"\n{cli.colors['BOLD']}{cli.colors['GREEN']}✅ No critical issues found!{cli.colors['RESET']}")
        sys.exit(0)

if __name__ == "__main__":
    main()