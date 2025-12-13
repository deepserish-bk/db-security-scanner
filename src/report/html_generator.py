#!/usr/bin/env python3
"""
DAY 8: HTML Report Generator
Learning: Creating professional HTML reports with Jinja2 templates
"""

import os
import json
from datetime import datetime
from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    print("⚠️  Jinja2 not installed. HTML reports disabled.")
    print("   Install with: pip install Jinja2")

class HTMLReportGenerator:
    """Generates professional HTML security reports"""
    
    def __init__(self):
        if not JINJA2_AVAILABLE:
            self.available = False
            return
        
        self.available = True
        # Set up template environment
        template_dir = Path(__file__).parent.parent / 'templates'
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))
        
    def generate(self, vulnerabilities, output_file="security_report.html"):
        """Generate HTML report from vulnerabilities"""
        if not self.available:
            print("❌ HTML reports not available. Install Jinja2 first.")
            return None
        
        # Calculate statistics
        severity_counts = {
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Add timestamp to each vulnerability if not present
            if 'timestamp' not in vuln:
                vuln['timestamp'] = datetime.now().strftime('%H:%M:%S')
        
        # Prepare template data
        template_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_counts,
            'vulnerabilities': vulnerabilities
        }
        
        try:
            # Load and render template
            template = self.env.get_template('report.html')
            html_content = template.render(**template_data)
            
            # Write to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"✅ HTML report generated: {output_file}")
            return output_file
            
        except Exception as e:
            print(f"❌ Error generating HTML report: {e}")
            return None
    
    def generate_from_json(self, json_file, output_file=None):
        """Generate HTML report from JSON file"""
        if not output_file:
            output_file = json_file.replace('.json', '.html')
        
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, dict) and 'vulnerabilities' in data:
                vulnerabilities = data['vulnerabilities']
            else:
                vulnerabilities = data
            
            return self.generate(vulnerabilities, output_file)
            
        except Exception as e:
            print(f"❌ Error reading JSON file: {e}")
            return None
