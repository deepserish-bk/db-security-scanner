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

