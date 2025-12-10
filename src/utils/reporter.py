#!/usr/bin/env python3
"""
Day 6: Enhanced Report Generator
Generates comprehensive security reports in multiple formats
"""

import json
from datetime import datetime

class ReportGenerator:
    """Generates security reports in text, JSON, and HTML formats"""
    
    def __init__(self):
        self.severity_colors = {
            'HIGH': '\033[91m',    # Red
            'MEDIUM': '\033[93m',  # Yellow
            'LOW': '\033[94m',     # Blue
            'INFO': '\033[96m',    # Cyan
            'RESET': '\033[0m'     # Reset
        }
    
    def generate_text_report(self, vulnerabilities, filename=None):
        """Generate a detailed text report"""
        if not vulnerabilities:
            report = ["No vulnerabilities found. Your code appears to be secure!"]
        else:
            report = []
            report.append("=" * 70)
            report.append("🔒 SECURITY ANALYSIS REPORT")
            report.append("=" * 70)
            report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report.append(f"Total vulnerabilities: {len(vulnerabilities)}")
            
            # Summary statistics
            summary = self._generate_summary(vulnerabilities)
            report.append("\n📊 SUMMARY")
            report.append("-" * 70)
            
            for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
                count = summary['severity_counts'].get(severity, 0)
                if count > 0:
                    color = self.severity_colors.get(severity, '')
                    report.append(f"{color}  {severity}: {count} vulnerabilities{self.severity_colors['RESET']}")
            
            report.append("\n📋 VULNERABILITY TYPES")
            report.append("-" * 70)
            for vuln_type, count in summary['type_counts'].items():
                report.append(f"  {vuln_type}: {count}")
            
            # Detailed findings
            report.append("\n🔍 DETAILED FINDINGS")
            report.append("=" * 70)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get('severity', 'INFO')
                color = self.severity_colors.get(severity, '')
                
                report.append(f"\n{i}. {color}[{severity}] {vuln['type']}{self.severity_colors['RESET']}")
                report.append(f"   📍 Location: {vuln['filename']}:{vuln['line']}")
                report.append(f"   📝 Issue: {vuln['message']}")
                
                if 'code' in vuln and vuln['code']:
                    # Show code snippet (truncated if too long)
                    code = vuln['code'].strip()
                    if len(code) > 100:
                        code = code[:97] + "..."
                    report.append(f"   📄 Code: {code}")
                
                if 'recommendation' in vuln:
                    report.append(f"   💡 Recommendation: {vuln['recommendation']}")
            
            # Recommendations summary
            report.append("\n🎯 RECOMMENDATIONS SUMMARY")
            report.append("=" * 70)
            
            unique_recs = set()
            for vuln in vulnerabilities:
                if 'recommendation' in vuln:
                    unique_recs.add(vuln['recommendation'])
            
            for rec in unique_recs:
                report.append(f"  • {rec}")
        
        report_text = "\n".join(report)
        
        # Save to file if requested
        if filename:
            with open(filename, 'w') as f:
                f.write(report_text)
            print(f"📄 Text report saved to: {filename}")
        
        return report_text
    
    def generate_json_report(self, vulnerabilities, filename=None):
        """Generate a structured JSON report for programmatic use"""
        summary = self._generate_summary(vulnerabilities)
        
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'Database Security Static Analyzer',
                'version': '1.0',
                'analysis_duration': 'N/A'
            },
            'summary': summary,
            'vulnerabilities': vulnerabilities
        }
        
        json_report = json.dumps(report, indent=2, default=str)
        
        if filename:
            with open(filename, 'w') as f:
                f.write(json_report)
            print(f"📄 JSON report saved to: {filename}")
        
        return json_report
    
    def generate_html_report(self, vulnerabilities, filename=None):
        """Generate a basic HTML report (simple version)"""
        summary = self._generate_summary(vulnerabilities)
        
        html = []
        html.append('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #eaeaea;
        }
        
        .summary-cards {
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            flex: 1;
            min-width: 200px;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .card.high { background: #ffe6e6; border-left: 5px solid #dc3545; }
        .card.medium { background: #fff3cd; border-left: 5px solid #ffc107; }
        .card.low { background: #d1ecf1; border-left: 5px solid #17a2b8; }
        .card.info { background: #e2e3e5; border-left: 5px solid #6c757d; }
        
        .card .count {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .card.high .count { color: #dc3545; }
        .card.medium .count { color: #ffc107; }
        .card.low .count { color: #17a2b8; }
        .card.info .count { color: #6c757d; }
        
        .vulnerability {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            transition: transform 0.2s;
        }
        
        .vulnerability:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        
        .vulnerability.high { border-left: 5px solid #dc3545; }
        .vulnerability.medium { border-left: 5px solid #ffc107; }
        .vulnerability.low { border-left: 5px solid #17a2b8; }
        .vulnerability.info { border-left: 5px solid #6c757d; }
        
        .severity {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .severity.high { background: #dc3545; color: white; }
        .severity.medium { background: #ffc107; }
        .severity.low { background: #17a2b8; color: white; }
        .severity.info { background: #6c757d; color: white; }
        
        .vulnerability h3 {
            margin: 10px 0;
            color: #333;
        }
        
        .meta {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        
        .code {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            overflow-x: auto;
        }
        
        .recommendation {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 5px;
            padding: 15px;
            margin-top: 10px;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eaeaea;
            color: #666;
            font-size: 0.9em;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            
            .summary-cards {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Analysis Report</h1>
            <p>Generated: ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
            <p>Tool: Database Security Static Analyzer v1.0</p>
        </div>''')
        
        if vulnerabilities:
            html.append(f'''
        <div class="summary-cards">
            <div class="card high">
                <div class="count">{summary['severity_counts'].get('HIGH', 0)}</div>
                <div>High Severity</div>
            </div>
            <div class="card medium">
                <div class="count">{summary['severity_counts'].get('MEDIUM', 0)}</div>
                <div>Medium Severity</div>
            </div>
            <div class="card low">
                <div class="count">{summary['severity_counts'].get('LOW', 0)}</div>
                <div>Low Severity</div>
            </div>
            <div class="card info">
                <div class="count">{summary['severity_counts'].get('INFO', 0)}</div>
                <div>Info</div>
            </div>
        </div>
        
        <h2>Vulnerabilities Found: {len(vulnerabilities)}</h2>''')
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'INFO').lower()
                html.append(f'''
        <div class="vulnerability {severity}">
            <span class="severity {severity}">{vuln.get('severity', 'INFO')}</span>
            <h3>{vuln['type']}</h3>
            <div class="meta">
                📍 {vuln['filename']}:{vuln['line']}
            </div>
            <p>{vuln['message']}</p>''')
                
                if 'code' in vuln and vuln['code']:
                    html.append(f'''
            <div class="code">
                {vuln['code'][:200]}{'...' if len(vuln['code']) > 200 else ''}
            </div>''')
                
                if 'recommendation' in vuln:
                    html.append(f'''
            <div class="recommendation">
                💡 <strong>Recommendation:</strong> {vuln['recommendation']}
            </div>''')
                
                html.append('''
        </div>''')
        else:
            html.append('''
        <div style="text-align: center; padding: 50px;">
            <h2 style="color: #28a745;">✅ No Vulnerabilities Found!</h2>
            <p>Your code appears to be secure.</p>
        </div>''')
        
        html.append(f'''
        <div class="footer">
            <p>Generated by Database Security Static Analyzer</p>
            <p>This is an automated security report. Please review findings with your security team.</p>
        </div>
    </div>
</body>
</html>''')
        
        html_report = "\n".join(html)
        
        if filename:
            with open(filename, 'w') as f:
                f.write(html_report)
            print(f"📄 HTML report saved to: {filename}")
        
        return html_report
    
    def _generate_summary(self, vulnerabilities):
        """Generate summary statistics from vulnerabilities"""
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        type_counts = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            vuln_type = vuln.get('type', 'Unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_counts,
            'type_counts': type_counts
        }
