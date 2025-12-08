# Test file with various vulnerabilities
import sqlite3

# Hardcoded secrets (Day 4 will catch these)
DATABASE_PASSWORD = "mysecretpassword123"
API_KEY = "sk_test_1234567890abcdef"

# SQL injection (Day 3 will catch this)
def unsafe_query(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: String concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchall()

# Safe version for comparison
def safe_query(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SAFE: Parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()

if __name__ == "__main__":
    print("Test code for security analyzer")
