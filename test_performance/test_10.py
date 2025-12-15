#!/usr/bin/env python3
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
