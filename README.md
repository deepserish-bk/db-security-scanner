# Database Security Static Analyzer

A static analysis tool for detecting database security vulnerabilities in Python code.

## Overview

This tool analyzes Python source code to identify security vulnerabilities related to database operations. It's designed as a 30-day learning project to build a comprehensive security scanning tool.

## Features

### Security Checks
- SQL injection vulnerabilities
- Hardcoded secrets and credentials
- Database connection security issues
- Input validation weaknesses
- Database-specific security patterns (PostgreSQL, MySQL, MongoDB, SQLite)

### Technical Capabilities
- Abstract Syntax Tree (AST) based analysis
- Multiple output formats (HTML, JSON, text)
- Configuration file support (YAML)
- Performance optimization with caching
- Parallel processing for large codebases

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
Configuration

```bash
# Create default configuration
python dbscan.py config create

# Use custom configuration
python dbscan.py analyze . --config security_config.yaml
```
Output Examples

Reports are saved to the reports/ directory by default:

HTML reports: Visual security audit reports
JSON reports: Structured data for CI/CD pipelines
Text reports: Simple console output
```bash
Project Structure

text
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
├── reports/              # Generated reports
├── tests/                # Test suite
└── requirements.txt      # Python dependencies
Security Analyzers
```
SQL Injection Analyzer

Detects string concatenation in SQL execute() calls
Identifies potential SQL injection points
Hardcoded Secrets Analyzer

Finds passwords, API keys, and tokens in source code
Uses pattern matching for credential detection
Database Connection Analyzer

Checks for insecure database configurations
Identifies weak connection settings
Input Validation Analyzer

Detects missing input validation
Identifies dangerous function usage (eval, exec)
Database-Specific Analyzer

PostgreSQL COPY command security
MySQL default port and root user checks
MongoDB eval() function warnings
SQLite temp directory security
Development

This is a 30-day learning project with daily commits tracking feature development.

Running Tests

bash
# Run test suite
python -m pytest tests/
Adding New Analyzers

Create analyzer in src/analyzers/
Implement the analyze() method
Add to CLI in src/cli/main_cli.py
Create test cases in examples/
License

MIT License

Contributing

This is a personal learning project. The code is shared as a reference for building security analysis tools.
