# Simple test code for our AST explorer
import sqlite3

#  a hardcoded password
DATABASE_PASSWORD = "supersecret123"

def unsafe_query(user_input):
    """This function is vulnerable to SQL injection"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # BAD: String concatenation in SQL
    query = "SELECT * FROM users WHERE id = " + user_input
    cursor.execute(query)
    
    return cursor.fetchall()

def safe_query(user_id):
    """This is the safe way to do it"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # GOOD: Parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    
    return cursor.fetchall()

# Test
if __name__ == "__main__":
    print("Test code loaded successfully!")