#!/usr/bin/env python3
"""
Day 6: Test the reporting system
"""

from src.utils.reporter import ReportGenerator

# Sample vulnerabilities for testing
sample_vulnerabilities = [
    {
        'filename': 'test_app.py',
        'line': 42,
        'type': 'SQL Injection',
        'severity': 'HIGH',
        'message': 'String concatenation in SQL query detected',
        'code': 'cursor.execute("SELECT * FROM users WHERE id = " + user_input)',
        'recommendation': 'Use parameterized queries: cursor.execute("SELECT ... WHERE id = ?", (user_id,))'
    },
    {
        'filename': 'config.py',
        'line': 15,
        'type': 'Hardcoded Secret',
        'severity': 'HIGH',
        'message': 'Database password found in source code',
        'code': 'DB_PASSWORD = "supersecret123"',
        'recommendation': 'Use environment variables for secrets'
    },
    {
        'filename': 'api.py',
        'line': 78,
        'type': 'Input Validation',
        'severity': 'MEDIUM',
        'message': 'Missing input validation on user data',
        'code': 'result = process_data(user_input)',
        'recommendation': 'Validate and sanitize all user inputs'
    },
    {
        'filename': 'utils.py',
        'line': 33,
        'type': 'Database Configuration',
        'severity': 'LOW',
        'message': 'Using default database port',
        'code': 'conn = psycopg2.connect("host=localhost port=5432")',
        'recommendation': 'Change default ports in production'
    }
]

def test_reporting():
    """Test all report formats"""
    reporter = ReportGenerator()
    
    print("🧪 Testing Report Generator...")
    print("=" * 60)
    
    # Test text report
    print("\n1. Testing Text Report:")
    print("-" * 30)
    text_report = reporter.generate_text_report(sample_vulnerabilities, 'test_text_report.txt')
    print("✓ Text report generated successfully")
    
    # Test JSON report
    print("\n2. Testing JSON Report:")
    print("-" * 30)
    json_report = reporter.generate_json_report(sample_vulnerabilities, 'test_json_report.json')
    print("✓ JSON report generated successfully")
    
    # Test HTML report
    print("\n3. Testing HTML Report:")
    print("-" * 30)
    html_report = reporter.generate_html_report(sample_vulnerabilities, 'test_html_report.html')
    print("✓ HTML report generated successfully")
    
    print("\n" + "=" * 60)
    print("✅ All report formats tested successfully!")
    print("\nGenerated files:")
    print("  - test_text_report.txt")
    print("  - test_json_report.json")
    print("  - test_html_report.html")
    
    # Show a preview of each format
    print("\n📋 Report Previews:")
    print("\nText Report (first 5 lines):")
    print("-" * 30)
    print("\n".join(text_report.split('\n')[:5]))
    
    print("\nJSON Report (metadata):")
    print("-" * 30)
    import json
    data = json.loads(json_report)
    print(f"Total vulnerabilities: {data['summary']['total_vulnerabilities']}")
    
    return True

if __name__ == "__main__":
    test_reporting()
