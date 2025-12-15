#!/usr/bin/env python3
"""
DAY 10: Complete Performance Optimized CLI
"""

import argparse
import sys
import os
import json
import time
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
    from src.utils.performance import PerformanceOptimizer, ProgressTracker
    
    ANALYZERS_AVAILABLE = True
    HTML_REPORTS_AVAILABLE = True
    CONFIG_AVAILABLE = True
    PERFORMANCE_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Import error: {e}")
    ANALYZERS_AVAILABLE = False
    HTML_REPORTS_AVAILABLE = False
    CONFIG_AVAILABLE = False
    PERFORMANCE_AVAILABLE = False

class SecurityAnalyzerCLI:
    """Performance-optimized CLI with caching"""
    
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
        
        # Initialize performance optimizer
        if PERFORMANCE_AVAILABLE:
            cache_dir = self.config.get('performance.cache_dir', '.security_cache') if self.config else '.security_cache'
            max_workers = self.config.get('performance.max_workers', 4) if self.config else 4
            self.optimizer = PerformanceOptimizer(cache_dir=cache_dir, max_workers=max_workers)
        else:
            self.optimizer = None
        
        # Color codes
        self.colors = {
            'HIGH': '\033[91m', 'MEDIUM': '\033[93m', 'LOW': '\033[94m',
            'INFO': '\033[96m', 'RESET': '\033[0m', 'GREEN': '\033[92m',
            'BOLD': '\033[1m', 'CYAN': '\033[96m', 'YELLOW': '\033[93m',
            'MAGENTA': '\033[95m'
        }
    
    def print_banner(self):
        """Print tool banner with performance info"""
        version = self.config.get('general.version', '1.0') if self.config else '1.0'
        
        banner = f"""
{self.colors['BOLD']}{self.colors['MAGENTA']}
╔══════════════════════════════════════════════════════════╗
║          DATABASE SECURITY STATIC ANALYZER v{version:<10}   ║
║                   30-Day Learning Project                ║
║                    Day 10: Performance                   ║
╚══════════════════════════════════════════════════════════╝{self.colors['RESET']}
        """
        print(banner)
        
        # Show performance features
        print(f"\n{self.colors['BOLD']}⚡ Performance Features:{self.colors['RESET']}")
        print("-" * 40)
        if self.optimizer:
            print(f"  • {self.colors['GREEN']}Smart Caching{self.colors['RESET']} (24-hour cache)")
            print(f"  • {self.colors['GREEN']}Parallel Processing{self.colors['RESET']} ({self.optimizer.max_workers} workers)")
            print(f"  • {self.colors['GREEN']}Progress Tracking{self.colors['RESET']} with ETA")
        else:
            print(f"  • {self.colors['YELLOW']}Performance features disabled{self.colors['RESET']}")
    
    def analyze_file(self, filepath, analyzer_name, analyzer):
        """Analyze a single file"""
        if not os.path.exists(filepath):
            return []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            print(f"❌ Error reading {filepath}: {e}")
            return []
        
        vulnerabilities = analyzer.analyze(code, filepath)
        
        # Add analyzer name and timestamp
        for vuln in vulnerabilities:
            vuln['analyzer'] = analyzer_name.upper()
            vuln['timestamp'] = datetime.now().strftime('%H:%M:%S')
        
        return vulnerabilities
    
    def analyze_single_file(self, filepath, analyzers=None):
        """Analyze single file with caching"""
        if not analyzers:
            if self.config:
                analyzers = self.config.get_enabled_analyzers()
            else:
                analyzers = self.analyzers.keys()
        
        print(f"\n{self.colors['BOLD']}📁 Analyzing:{self.colors['RESET']} {filepath}")
        print("=" * 60)
        
        all_vulnerabilities = []
        
        for analyzer_name in analyzers:
            if analyzer_name not in self.analyzers:
                continue
            
            print(f"\n🔍 Running {analyzer_name.upper()} analyzer...")
            
            analyzer = self.analyzers[analyzer_name]
            start_time = time.time()
            
            # Use cached analysis if optimizer available
            if self.optimizer:
                analyzer_func = lambda fp: self.analyze_file(fp, analyzer_name, analyzer)
                results = self.optimizer.analyze_file_with_cache(
                    filepath, 
                    analyzer_func, 
                    analyzer_name
                )
            else:
                results = self.analyze_file(filepath, analyzer_name, analyzer)
            
            elapsed = time.time() - start_time
            
            # Display results
            for vuln in results:
                severity = vuln.get('severity', 'INFO')
                color = self.colors.get(severity, self.colors['RESET'])
                
                print(f"{color}⚠️  [{severity}] {vuln['type']}{self.colors['RESET']}")
                print(f"   📍 {vuln['filename']}:{vuln['line']}")
                print(f"   📝 {vuln['message']}")
                if 'code' in vuln and vuln['code']:
                    code_preview = vuln['code'][:100] + "..." if len(vuln['code']) > 100 else vuln['code']
                    print(f"   📄 {code_preview}")
                if 'recommendation' in vuln:
                    print(f"   💡 {vuln['recommendation']}")
                print()
            
            if results:
                print(f"   ⏱️  Found {len(results)} issues in {elapsed:.3f}s")
            else:
                print(f"   ✅ No issues found ({elapsed:.3f}s)")
            
            all_vulnerabilities.extend(results)
        
        return all_vulnerabilities
    
    def analyze_directory_fast(self, directory_path, analyzers=None):
        """Fast directory analysis with parallel processing"""
        if not analyzers:
            if self.config:
                analyzers = self.config.get_enabled_analyzers()
            else:
                analyzers = self.analyzers.keys()
        
        # Collect all Python files
        python_files = []
        scan_hidden = self.config.get('analysis.scan_hidden_files', False) if self.config else False
        
        for root, dirs, files in os.walk(directory_path):
            if not scan_hidden:
                dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                if file.endswith('.py'):
                    if not scan_hidden and file.startswith('.'):
                        continue
                    
                    full_path = os.path.join(root, file)
                    python_files.append(full_path)
        
        print(f"\n📁 Found {len(python_files)} Python files")
        print(f"🔧 Running {len(analyzers)} analyzers")
        
        if not python_files:
            return []
        
        # Initialize progress tracker
        total_operations = len(python_files) * len(analyzers)
        progress = ProgressTracker(total_operations)
        
        all_vulnerabilities = []
        start_time = time.time()
        
        # Process each analyzer
        for analyzer_name in analyzers:
            if analyzer_name not in self.analyzers:
                continue
            
            analyzer = self.analyzers[analyzer_name]
            
            print(f"\n🔍 Starting {analyzer_name.upper()} analyzer...")
            
            # Use optimizer if available
            if self.optimizer:
                # Prepare analyzer function
                analyzer_func = lambda fp: self.analyze_file(fp, analyzer_name, analyzer)
                
                # Run parallel analysis
                results = self.optimizer.analyze_files_parallel(
                    python_files, 
                    analyzer_func, 
                    analyzer_name
                )
                all_vulnerabilities.extend(results)
                
                # Update progress for all files
                progress.update(len(python_files))
            else:
                # Fallback to sequential analysis
                for i, filepath in enumerate(python_files):
                    results = self.analyze_file(filepath, analyzer_name, analyzer)
                    all_vulnerabilities.extend(results)
                    progress.update(1)
        
        progress.finish()
        
        # Show cache statistics if optimizer is used
        if self.optimizer:
            stats = self.optimizer.get_performance_stats()
            print(f"\n📊 Cache Statistics:")
            print(f"   Hits: {stats['cache_hits']} | Misses: {stats['cache_misses']}")
            print(f"   Hit Rate: {stats['cache_hit_rate']:.1%}")
            print(f"   Cache Size: {stats['cache_size']} entries")
        
        return all_vulnerabilities
    
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
    
    def check_severity_thresholds(self, vulnerabilities):
        """Check if vulnerabilities exceed config thresholds"""
        if not self.config:
            return True, False
        
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
    
    def clear_cache(self):
        """Clear analysis cache"""
        if self.optimizer:
            return self.optimizer.clear_cache()
        return False

def main():
    """Main CLI entry point with performance features"""
    parser = argparse.ArgumentParser(
        description='Performance-Optimized Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fast analysis with caching
  %(prog)s analyze src/ --fast --workers 8
  
  # Clear cache
  %(prog)s cache clear
  
  # Show cache stats
  %(prog)s cache stats
  
  # Analyze with config
  %(prog)s analyze test.py --config security_config.yaml --format html
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze code')
    analyze_parser.add_argument('path', help='File or directory to analyze')
    analyze_parser.add_argument('--config', help='Configuration file')
    analyze_parser.add_argument('--analyzers', help='Comma-separated analyzers')
    analyze_parser.add_argument('--format', choices=['text', 'json', 'html'], help='Output format')
    analyze_parser.add_argument('--output', help='Output file')
    analyze_parser.add_argument('--open', action='store_true', help='Open HTML report')
    analyze_parser.add_argument('--fast', action='store_true', help='Use fast parallel mode')
    analyze_parser.add_argument('--workers', type=int, help='Number of parallel workers')
    
    # Cache command
    cache_parser = subparsers.add_parser('cache', help='Cache management')
    cache_subparsers = cache_parser.add_subparsers(dest='cache_action', help='Cache action')
    cache_subparsers.add_parser('clear', help='Clear cache')
    cache_subparsers.add_parser('stats', help='Show cache statistics')
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_subparsers = config_parser.add_subparsers(dest='config_action', help='Config action')
    config_subparsers.add_parser('create', help='Create default config')
    show_parser = config_subparsers.add_parser('show', help='Show config')
    show_parser.add_argument('--config', help='Config file to load')
    validate_parser = config_subparsers.add_parser('validate', help='Validate config')
    validate_parser.add_argument('--config', required=True, help='Config file to validate')
    
    # Version command
    subparsers.add_parser('version', help='Show version')
    
    args = parser.parse_args()
    
    if args.command == 'analyze':
        cli = SecurityAnalyzerCLI(args.config)
        cli.print_banner()
        
        # Override workers if specified
        if args.workers and cli.optimizer:
            cli.optimizer.max_workers = args.workers
            print(f"⚡ Using {args.workers} parallel workers")
        
        start_time = time.time()
        
        if os.path.isfile(args.path):
            analyzers = args.analyzers.split(',') if args.analyzers else None
            vulnerabilities = cli.analyze_single_file(args.path, analyzers)
        elif os.path.isdir(args.path):
            analyzers = args.analyzers.split(',') if args.analyzers else None
            if args.fast:
                print(f"🚀 Starting FAST parallel analysis...")
                vulnerabilities = cli.analyze_directory_fast(args.path, analyzers)
            else:
                print(f"🐌 Starting standard analysis...")
                # Fallback to sequential analysis
                vulnerabilities = []
                for root, dirs, files in os.walk(args.path):
                    for file in files:
                        if file.endswith('.py'):
                            filepath = os.path.join(root, file)
                            print(f"\nAnalyzing {filepath}")
                            vulns = cli.analyze_single_file(filepath, analyzers)
                            vulnerabilities.extend(vulns)
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
        
        end_time = time.time()
        duration = end_time - start_time
        print(f"\n⏱️  Total analysis time: {duration:.2f} seconds")
        
        if has_high:
            print(f"\n{cli.colors['BOLD']}{cli.colors['HIGH']}❌ Security thresholds exceeded!{cli.colors['RESET']}")
            sys.exit(1)
        elif has_medium:
            print(f"\n{cli.colors['BOLD']}{cli.colors['MEDIUM']}⚠️  Warning: Medium severity threshold exceeded{cli.colors['RESET']}")
            sys.exit(0)
        else:
            print(f"\n{cli.colors['BOLD']}{cli.colors['GREEN']}✅ Analysis passed all thresholds!{cli.colors['RESET']}")
            sys.exit(0)
    
    elif args.command == 'cache':
        cli = SecurityAnalyzerCLI()
        
        if args.cache_action == 'clear':
            if cli.clear_cache():
                print("✅ Cache cleared successfully")
            else:
                print("❌ Failed to clear cache")
        
        elif args.cache_action == 'stats':
            if cli.optimizer:
                stats = cli.optimizer.get_performance_stats()
                print("\n📊 CACHE STATISTICS")
                print("=" * 60)
                print(f"Cache Hits: {stats['cache_hits']}")
                print(f"Cache Misses: {stats['cache_misses']}")
                print(f"Cache Hit Rate: {stats['cache_hit_rate']:.1%}")
                print(f"Cache Size: {stats['cache_size']} entries")
                print(f"Cache Directory: {cli.optimizer.cache_dir}")
            else:
                print("❌ Performance optimizer not available")
    
    elif args.command == 'config':
        cli = SecurityAnalyzerCLI()
        
        if args.config_action == 'create':
            if CONFIG_AVAILABLE:
                from src.config.config_loader import ConfigLoader
                config = ConfigLoader()
                if config.save_config('security_config.yaml'):
                    print(f"✅ Created default configuration at security_config.yaml")
                else:
                    print(f"❌ Failed to create configuration")
        
        elif args.config_action == 'show':
            if CONFIG_AVAILABLE:
                from src.config.config_loader import ConfigLoader
                config = ConfigLoader(args.config if hasattr(args, 'config') else None)
                print("\n📋 CONFIGURATION")
                print("=" * 60)
                # Create a simple print method
                enabled = config.get_enabled_analyzers()
                print(f"Enabled Analyzers: {', '.join(enabled)}")
                print(f"Default Report Format: {config.get('reports.default_format', 'html')}")
        
        elif args.config_action == 'validate':
            if CONFIG_AVAILABLE and hasattr(args, 'config'):
                from src.config.config_loader import ConfigLoader
                if os.path.exists(args.config):
                    config = ConfigLoader(args.config)
                    print(f"✅ Configuration is valid: {args.config}")
                    enabled = config.get_enabled_analyzers()
                    print(f"Enabled Analyzers: {', '.join(enabled)}")
                else:
                    print(f"❌ Configuration file not found: {args.config}")
    
    elif args.command == 'version':
        print("Database Security Static Analyzer v1.0")
        print("Day 10: Performance Optimization")
        print("GitHub: https://github.com/deepserish-bk/db-security-scanner")
    
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
