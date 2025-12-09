# Research Notes - Day 1

## Project Idea: Static Analysis Tool for Database Security

## Day 3: SQL Injection Detection

Today I built the first security analyzer module that detects SQL injection vulnerabilities.

Key learnings:
1. Python's AST module makes it easy to parse and analyze code structure
2. SQL injection often happens when string concatenation is used in execute() calls
3. The pattern: cursor.execute("SELECT ..." + user_input) is dangerous
4. Safe alternative: cursor.execute("SELECT ... WHERE id = ?", (user_input,))

The analyzer checks for:
- String concatenation in execute() calls
- SQL keywords in concatenated strings
- Both high and medium severity vulnerabilities

Next steps: Add more analyzers for other vulnerabilities.


## Day 4: Hardcoded Secrets Detection

Today I implemented an analyzer for hardcoded secrets like passwords and API keys.

Key learnings:
1. Secrets in code are a major security risk - they can be easily extracted
2. Common patterns to look for: 'password', 'api_key', 'secret', 'token'
3. Long strings (>20 chars) without http:// might be secrets
4. Regular expressions help identify suspicious variable names

The analyzer detects:
- Variables with names suggesting they contain secrets
- Long string constants that might be credentials
- Different severity levels based on confidence

Best practices:
1. Use environment variables for secrets
2. Use secure secret management services
3. Never commit secrets to version control


## Day 5: Main Analyzer Runner and Integration

Today I created the main orchestrator that runs all security analyzers together.

Key achievements:
1. Built a unified SecurityAnalyzer class that coordinates multiple analyzers
2. Added file and directory scanning capabilities
3. Implemented colored terminal output for better visibility
4. Created a summary report with severity counts
5. Added proper exit codes (0 for success, 1 for vulnerabilities found)

Features:
- Single command to analyze files or directories
- Color-coded output based on severity
- Summary statistics
- Integration of SQL injection and hardcoded secrets analyzers

Usage:
```bash
python src/main.py <file_or_directory>
python src/main.py tests/vulnerable_test.py
python src/main.py .