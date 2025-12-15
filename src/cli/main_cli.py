#!/usr/bin/env python3
"""
DAY 9: Enhanced CLI with Configuration Support
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

# Import our modules
try:
    from src.analyzers.sql_injection import SQLInjectionAnalyzer
    from src.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer
    from src.analyzers.database_connection import DatabaseConnectionAnalyzer
    from src.analyzers.input_validation import InputValidationAnalyzer
    from src.report.html_generator import HTMLReportGenerator
    from src.config.config_loader import ConfigLoader
    
    ANALYZERS_AVAILABLE = True
    HTML_REPORTS_AVAILABLE = True
    CONFIG_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Some modules not available: {e}")
    ANALYZERS_AVAILABLE = False
    HTML_REPORTS_AVAILABLE = False
    CONFIG_AVAILABLE = False

class SecurityAnalyzerCLI:
    """Main CLI interface with configuration support"""
    
    def __init__(self, config_path=None):
        # Load configuration
        if CONFIG_AVAILABLE:
            self.config = ConfigLoader(config_path)
        else:
            self.config = None
        
        # Initialize analyzers
        if ANALYZERS_AVAILABLE:
            self.analyzers = {
                'sql': SQLInjectionAnalyzer(),
                'secrets': HardcodedSecretsAnalyzer(),
                'db': DatabaseConnectionAnalyzer(),
                'input': InputValidationAnalyzer()
            }
        else:
            self.analyzers = {}
        
        # Initialize HTML reporter
        self.html_reporter = HTMLReportGenerator() if HTML_REPORTS_AVAILABLE else None
        
        # Color codes
        self.colors = {
            'HIGH': '\033[91m', 'MEDIUM': '\033[93m', 'LOW': '\033[94m',
            'INFO': '\033[96m', 'RESET': '\033[0m', 'GREEN': '\033[92m',
            'BOLD': '\033[1m', 'CYAN': '\033[96m', 'YELLOW': '\033[93m'
        }
    
    def print_banner(self):
        """Print tool banner with config info"""
        version = self.config.get('general.version', '1.0') if self.config else '1.0'
        
        banner = f"""
{self.colors['BOLD']}{self.colors['CYAN']}
╔══════════════════════════════════════════════════════════╗
║          DATABASE SECURITY STATIC ANALYZER v{version:<10}   ║
║                   30-Day Learning Project                ║
║                      Day 9: Configuration                ║
╚══════════════════════════════════════════════════════════╝{self.colors['RESET']}
        """
        print(banner)
        
        if self.config:
            self.config.print_summary()
    
    def should_analyze_file(self, file_path):
        """Check if file should be analyzed based on config"""
        if not self.config:
            return True
        
        # Check ignore patterns
        if self.config.should_ignore_file(file_path):
            print(f"⏭️  Skipping ignored file: {file_path}")
            return False
        
        # Check file size
        try:
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            max_size = self.config.get('analysis.max_file_size_mb', 10)
            if file_size_mb > max_size:
                print(f"📦 Skipping large file ({file_size_mb:.1f}MB): {file_path}")
                return False
        except:
            pass
        
        return True
    
    def analyze_file(self, file_path, analyzers=None):
        """Analyze a single file with config checks"""
        if not self.should_analyze_file(file_path):
            return []
        
        print(f"\n{self.colors['BOLD']}📁 Analyzing:{self.colors['RESET']} {file_path}")
        print("=" * 60)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            return []
        
        all_vulnerabilities = []
        
        # Get analyzers to run from config or argument
        if analyzers is None:
            if self.config:
                analyzers = self.config.get_enabled_analyzers()
            else:
                analyzers = self.analyzers.keys()
        
        for analyzer_name in analyzers:
            if analyzer_name in self.analyzers:
                print(f"\n🔍 Running {analyzer_name.upper()} analyzer...")
                analyzer = self.analyzers[analyzer_name]
                vulnerabilities = analyzer.analyze(code, file_path)
                
                # Filter by config if available
                if self.config:
                    analyzer_config = self.config.get(f'analyzers.{analyzer_name}', {})
                    if not analyzer_config.get('enabled', True):
                        continue
                
                for vuln in vulnerabilities:
                    vuln['analyzer'] = analyzer_name.upper()
                    vuln['timestamp'] = datetime.now().strftime('%H:%M:%S')
                    all_vulnerabilities.append(vuln)
                    
                    # Print with colors
                    severity = vuln.get('severity', 'INFO')
                    color = self.colors.get(severity, self.colors['RESET'])
                    
                    print(f"{color}⚠️  [{severity}] {vuln['type']}{self.colors['RESET']}")
                    print(f"   📍 {vuln['filename']}:{vuln['line']}")
                    print(f"   📝 {vuln['message']}")
                    if 'code' in vuln:
                        code_preview = vuln['code'][:100] + "..." if len(vuln['code']) > 100 else vuln['code']
                        print(f"   📄 {code_preview}")
                    if 'recommendation' in vuln:
                        print(f"   💡 {vuln['recommendation']}")
                    print()
        
        if not all_vulnerabilities:
            print(f"{self.colors['GREEN']}✅ No vulnerabilities found!{self.colors['RESET']}")
        
        return all_vulnerabilities
    
    def analyze_directory(self, directory_path, analyzers=None):
        """Analyze directory with config-based filtering"""
        all_vulnerabilities = []
        
        # Get scan settings from config
        scan_hidden = self.config.get('analysis.scan_hidden_files', False) if self.config else False
        follow_symlinks = self.config.get('analysis.follow_symlinks', False) if self.config else False
        
        python_files = []
        for root, dirs, files in os.walk(directory_path):
            # Skip hidden directories if configured
            if not scan_hidden:
                dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                if file.endswith('.py'):
                    full_path = os.path.join(root, file)
                    
                    # Skip hidden files if configured
                    if not scan_hidden and file.startswith('.'):
                        continue
                    
                    # Skip symlinks if not following
                    if not follow_symlinks and os.path.islink(full_path):
                        continue
                    
                    python_files.append(full_path)
        
        print(f"\n📁 Found {len(python_files)} Python files to analyze")
        
        for i, file_path in enumerate(python_files, 1):
            print(f"\n[{i}/{len(python_files)}] ", end="")
            vulns = self.analyze_file(file_path, analyzers)
            all_vulnerabilities.extend(vulns)
        
        return all_vulnerabilities
    
    def check_severity_thresholds(self, vulnerabilities):
        """Check if vulnerabilities exceed config thresholds"""
        if not self.config:
            return True, False  # (has_high, has_medium_warning)
        
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        high_threshold = self.config.get('severity.high_threshold', 3)
        medium_threshold = self.config.get('severity.medium_threshold', 5)
        fail_on_high = self.config.get('severity.fail_on_high', True)
        warn_on_medium = self.config.get('severity.warn_on_medium', True)
        
        has_high = fail_on_high and severity_counts['HIGH'] >= high_threshold
        has_medium_warning = warn_on_medium and severity_counts['MEDIUM'] >= medium_threshold
        
        return has_high, has_medium_warning
    
    def generate_report(self, vulnerabilities, output_format=None, output_file=None):
        """Generate report with config-based defaults"""
        if not vulnerabilities:
            print(f"\n{self.colors['GREEN']}📊 No vulnerabilities to report.{self.colors['RESET']}")
            return ""
        
        # Get format from config or argument
        if output_format is None:
            output_format = self.config.get('reports.default_format', 'html') if self.config else 'text'
        
        print(f"\n{self.colors['BOLD']}📊 Generating {output_format.upper()} report...{self.colors['RESET']}")
        
        # Get output directory from config
        output_dir = None
        if self.config:
            output_dir = self.config.get('reports.output_directory', './reports')
            os.makedirs(output_dir, exist_ok=True)
        
        # Generate filename if not provided
        if not output_file:
            timestamp = datetime.now().strftime(
                self.config.get('reports.timestamp_format', '%Y%m%d_%H%M%S') if self.config else '%Y%m%d_%H%M%S'
            )
            filename = f"security_report_{timestamp}"
            
            if output_format == 'json':
                filename += '.json'
            elif output_format == 'html':
                filename += '.html'
            else:
                filename += '.txt'
            
            if output_dir:
                output_file = os.path.join(output_dir, filename)
            else:
                output_file = filename
        
        # Generate report
        if output_format == 'json':
            return self._generate_json_report(vulnerabilities, output_file)
        elif output_format == 'html':
            return self._generate_html_report(vulnerabilities, output_file)
        else:
            return self._generate_text_report(vulnerabilities, output_file)
    
    def _generate_text_report(self, vulnerabilities, output_file):
        """Generate text report"""
        report_lines = []
        report_lines.append("\n" + "=" * 70)
        report_lines.append("🔒 SECURITY ANALYSIS REPORT")
        report_lines.append("=" * 70)
        
        if self.config:
            project = self.config.get('general.project_name', 'Database Security Static Analyzer')
            report_lines.append(f"Project: {project}")
        
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total vulnerabilities: {len(vulnerabilities)}")
        
        # Severity counts
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        report_lines.append(f"\n{self.colors['BOLD']}📊 Severity Summary:{self.colors['RESET']}")
        for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = self.colors.get(severity, '')
                report_lines.append(f"{color}  {severity}: {count}{self.colors['RESET']}")
        
        # Check thresholds
        if self.config:
            has_high, has_medium = self.check_severity_thresholds(vulnerabilities)
            if has_high:
                report_lines.append(f"\n{self.colors['HIGH']}❌ Exceeds high severity threshold!{self.colors['RESET']}")
            elif has_medium:
                report_lines.append(f"\n{self.colors['MEDIUM']}⚠️  Exceeds medium severity threshold{self.colors['RESET']}")
        
        report_text = "\n".join(report_lines)
        
        with open(output_file, 'w') as f:
            f.write(report_text)
        print(f"✅ Text report saved: {output_file}")
        
        return report_text
    
    def _generate_json_report(self, vulnerabilities, output_file):
        """Generate JSON report"""
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': self.config.get('general.project_name', 'Database Security Static Analyzer') if self.config else 'Database Security Static Analyzer',
                'version': self.config.get('general.version', '1.0') if self.config else '1.0',
                'total_vulnerabilities': len(vulnerabilities)
            },
            'vulnerabilities': vulnerabilities
        }
        
        json_report = json.dumps(report, indent=2)
        
        with open(output_file, 'w') as f:
            f.write(json_report)
        print(f"✅ JSON report saved: {output_file}")
        
        return json_report
    
    def _generate_html_report(self, vulnerabilities, output_file):
        """Generate HTML report"""
        if not self.html_reporter or not self.html_reporter.available:
            print(f"{self.colors['YELLOW']}⚠️  HTML reports not available.{self.colors['RESET']}")
            return ""
        
        result = self.html_reporter.generate(vulnerabilities, output_file)
        if result:
            print(f"✅ HTML report saved: {result}")
            return result
        else:
            return ""

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Database Security Static Analyzer with Configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze with default config
  %(prog)s analyze test_vuln.py
  
  # Create config file
  %(prog)s config create --output security_config.yaml
  
  # Show config
  %(prog)s config show --config security_config.yaml
  
  # Analyze with custom config
  %(prog)s analyze test_vuln.py --config security_config.yaml --format html
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze code for vulnerabilities')
    analyze_parser.add_argument('path', help='File or directory to analyze')
    analyze_parser.add_argument('--config', help='Configuration file path')
    analyze_parser.add_argument('--analyzers', help='Comma-separated list of analyzers to run')
    analyze_parser.add_argument('--format', choices=['text', 'json', 'html'], 
                               help='Output format (default: from config)')
    analyze_parser.add_argument('--output', help='Output file path')
    analyze_parser.add_argument('--open', action='store_true', 
                               help='Open HTML report in browser')
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_subparsers = config_parser.add_subparsers(dest='action', help='Config action')
    
    # Config create
    create_parser = config_subparsers.add_parser('create', help='Create default config')
    create_parser.add_argument('--output', default='security_config.yaml', 
                              help='Output file (default: security_config.yaml)')
    
    # Config show
    show_parser = config_subparsers.add_parser('show', help='Show current config')
    show_parser.add_argument('--config', help='Config file to load')
    
    # Config validate
    validate_parser = config_subparsers.add_parser('validate', help='Validate config')
    validate_parser.add_argument('--config', required=True, help='Config file to validate')
    
    # Version command
    subparsers.add_parser('version', help='Show version information')
    
    args = parser.parse_args()
    
    if args.command == 'analyze':
        cli = SecurityAnalyzerCLI(args.config)
        cli.print_banner()
        
        start_time = datetime.now()
        
        if os.path.isfile(args.path):
            analyzers = args.analyzers.split(',') if args.analyzers else None
            vulnerabilities = cli.analyze_file(args.path, analyzers)
        elif os.path.isdir(args.path):
            analyzers = args.analyzers.split(',') if args.analyzers else None
            vulnerabilities = cli.analyze_directory(args.path, analyzers)
        else:
            print(f"❌ Path not found: {args.path}")
            sys.exit(1)
        
        # Generate report
        cli.generate_report(vulnerabilities, args.format, args.output)
        
        # Open if requested
        if args.format == 'html' and args.open:
            report_file = args.output or f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            try:
                import webbrowser
                webbrowser.open(f'file://{os.path.abspath(report_file)}')
                print(f"🌐 Opened in browser")
            except:
                pass
        
        # Check thresholds
        has_high, has_medium = cli.check_severity_thresholds(vulnerabilities)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        print(f"\n⏱️  Completed in {duration:.2f} seconds")
        
        # Exit based on thresholds
        if has_high:
            print(f"\n{cli.colors['BOLD']}{cli.colors['HIGH']}❌ Security thresholds exceeded!{cli.colors['RESET']}")
            sys.exit(1)
        elif has_medium:
            print(f"\n{cli.colors['BOLD']}{cli.colors['MEDIUM']}⚠️  Warning: Medium severity threshold exceeded{cli.colors['RESET']}")
            sys.exit(0)
        else:
            print(f"\n{cli.colors['BOLD']}{cli.colors['GREEN']}✅ Analysis passed all thresholds!{cli.colors['RESET']}")
            sys.exit(0)
    
    elif args.command == 'config':
        if args.action == 'create':
            if CONFIG_AVAILABLE:
                config = ConfigLoader()
                if config.save_config(args.output):
                    print(f"✅ Created default configuration at {args.output}")
                else:
                    print(f"❌ Failed to create configuration")
            else:
                print("❌ Config module not available")
        
        elif args.action == 'show':
            if CONFIG_AVAILABLE:
                config = ConfigLoader(args.config)
                print("\n📋 CONFIGURATION")
                print("=" * 60)
                if args.config and os.path.exists(args.config):
                    print(f"Source: {args.config}")
                else:
                    print("Source: Default configuration")
                print()
                config.print_summary()
            else:
                print("❌ Config module not available")
        
        elif args.action == 'validate':
            if CONFIG_AVAILABLE:
                if os.path.exists(args.config):
                    config = ConfigLoader(args.config)
                    print(f"✅ Configuration is valid: {args.config}")
                    config.print_summary()
                else:
                    print(f"❌ Configuration file not found: {args.config}")
            else:
                print("❌ Config module not available")
        
        else:
            config_parser.print_help()
    
    elif args.command == 'version':
        print("Database Security Static Analyzer v1.0")
        print("30-Day Learning Project - Day 9: Configuration")
        print("GitHub: https://github.com/deepserish-bk/db-security-scanner")
    
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
