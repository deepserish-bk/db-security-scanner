#!/usr/bin/env python3
# Create test files for performance testing
import os

test_code = '''#!/usr/bin/env python3
# Test file for performance testing

import sqlite3

# Some test code
def test_function():
    password = "test123"
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    
    # Safe query
    cursor.execute("SELECT * FROM users WHERE id = ?", (1,))
    
    return cursor.fetchall()

# Some more code
API_KEY = "test_key_12345"
SECRET_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

if __name__ == "__main__":
    test_function()
'''

os.makedirs("test_performance", exist_ok=True)

# Create 20 test files
for i in range(1, 21):
    filename = f"test_performance/test_{i:02d}.py"
    with open(filename, 'w') as f:
        f.write(test_code)
    
    print(f"Created: {filename}")

print(f"\nCreated 20 test files in test_performance/")
