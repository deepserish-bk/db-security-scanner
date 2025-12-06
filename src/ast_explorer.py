#!/usr/bin/env python3
"""
Day 2: Learning AST (Abstract Syntax Tree) basics
"""

import ast

print(" Understanding Python's AST")
print("=" * 50)

# a simple Python function
sample_code = '''
def get_user(username):
    """Get user from database"""
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return query
'''

print(" Sample Code to Analyze:")
print(sample_code)

# Parse the code into AST
tree = ast.parse(sample_code)

print("\n🔍 What Python Sees (AST Structure):")
print("=" * 50)

# Walk through all nodes in the tree
for node in ast.walk(tree):
    node_type = type(node).__name__
    
    # Show interesting nodes
    if node_type in ['FunctionDef', 'Assign', 'BinOp', 'Constant', 'Name']:
        # Try to get line number
        try:
            line_no = node.lineno
        except:
            line_no = "unknown"
        
        print(f"{node_type:15} (line {line_no:3})", end="")
        
        # Show additional info for specific node types
        if node_type == 'FunctionDef':
            print(f" → Function name: {node.name}")
        elif node_type == 'Constant':
            print(f" → Value: {repr(node.value)}")
        elif node_type == 'Name':
            print(f" → Variable name: {node.id}")
        elif node_type == 'BinOp':
            print(f" → Operation: {type(node.op).__name__}")
        else:
            print()

print("\n" + "=" * 50)
print(" Key Learning: Python converts code to a tree structure")
print(" Each element (function, variable, operation) is a 'node'")
print(" We can analyze these nodes to find patterns!")

#  see the raw AST
print("\n\n Raw AST Structure:")
print(ast.dump(tree, indent=2)[:500] + "...")  # Show first 500 chars

def analyze_file(filename):
    """Analyze a Python file"""
    print(f"\n\n🔍 Analyzing {filename}:")
    print("=" * 50)
    
    try:
        with open(filename, 'r') as f:
            code = f.read()
        
        tree = ast.parse(code)
        

        function_count = 0
        string_count = 0
        sql_execute_calls = 0
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                function_count += 1
                print(f"📌 Found function: {node.name}")
            
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                string_count += 1
                if len(node.value) > 50:  # Long strings might be SQL
                    print(f"📝 Long string (might be SQL): {node.value[:50]}...")
            
            elif isinstance(node, ast.Call):
                # Check for cursor.execute() calls
                call_str = ast.unparse(node) if hasattr(ast, 'unparse') else str(node)
                if 'execute' in call_str:
                    sql_execute_calls += 1
                    print(f"⚡ Found SQL execute call on line {node.lineno}")
        
        print(f"\n📊 Summary for {filename}:")
        print(f"  Functions: {function_count}")
        print(f"  String constants: {string_count}")
        print(f"  SQL execute calls: {sql_execute_calls}")
        
    except FileNotFoundError:
        print(f"❌ File {filename} not found!")
    except SyntaxError as e:
        print(f"❌ Syntax error: {e}")

# Test it
if __name__ == "__main__":
    # show the basics
    print(" Day 2: Understanding Python's AST")
    print("=" * 50)
    
    # analyze our test file
    analyze_file("examples/test_code.py")