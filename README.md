# Database Security Scanner

A static analysis tool for detecting database security vulnerabilities in Python code.

## Overview

This tool analyzes Python source code to identify security vulnerabilities related to database operations. It includes specialized analyzers for different types of database security issues.

## Security Analyzers

1. **SQL Injection Analyzer**
   - Detects string concatenation in SQL execute() calls
   - Identifies potential SQL injection points

2. **Hardcoded Secrets Analyzer**
   - Finds passwords, API keys, and tokens in source code
   - Uses pattern matching for credential detection

3. **Database Connection Analyzer**
   - Checks for insecure database configurations
   - Identifies weak connection settings

4. **Input Validation Analyzer**
   - Detects missing input validation
   - Identifies dangerous function usage (eval, exec)

5. **Database-Specific Analyzer**
   - PostgreSQL COPY command security
   - MySQL default port and root user checks
   - MongoDB eval() function warnings
   - SQLite temp directory security

6. **ORM Security Analyzer**
   - SQLAlchemy execute() string concatenation detection
   - Django ORM raw() method security analysis

## Installation

```bash
git clone https://github.com/deepserish-bk/db-security-scanner.git
cd db-security-scanner
pip install -r requirements.txt
```

Usage
Basic Analysis
```bash
# Analyze a single file
python dbscan.py analyze file.py

# Analyze a directory
python dbscan.py analyze src/

# Specify output format
python dbscan.py analyze . --format html
python dbscan.py analyze . --format json
python dbscan.py analyze . --format text
```

Using Specific Analyzers
```bash
# Use only SQL injection analyzer
python dbscan.py analyze . --analyzers sql

# Use multiple analyzers
python dbscan.py analyze . --analyzers sql,secrets,orm

# Use all analyzers (default)
python dbscan.py analyze .
```

Configuration
```bash
# Create default configuration
python dbscan.py config create

# Use custom configuration
python dbscan.py analyze . --config security_config.yaml
```

Output Examples
Reports are saved to the reports/ directory by default:
	•	HTML reports: Visual security audit reports
	•	JSON reports: Structured data for CI/CD pipelines
	•	Text reports: Simple console output
Project Structure
```bash
db-security-scanner/
├── dbscan.py              # Main entry point
├── src/                   # Source code
│   ├── analyzers/         # Security analyzers
│   ├── cli/              # Command-line interface
│   ├── config/           # Configuration management
│   ├── report/           # Report generation
│   ├── templates/        # HTML templates
│   └── utils/            # Utility functions
├── examples/             # Test code examples
├── reports/              # Generated reports (not tracked)
├── tests/                # Test suite
└── requirements.txt      # Python dependencies
```


```bash
# Run test suite
python -m pytest tests/
```

Adding New Analyzers
	1	Create analyzer in src/analyzers/
	2	Implement the analyze() method
	3	Add to CLI in src/cli/main_cli.py
	4	Create test cases in examples/
License
MIT License
Contributing
This is a personal learning project. The code is shared as a reference for building security analysis tools.