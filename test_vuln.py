#!/usr/bin/env python3
"""
Test file with clear vulnerabilities
"""

import sqlite3

# Hardcoded secrets - should be caught
DATABASE_PASSWORD = "mysecretpassword123"
API_KEY = "sk_live_abcdef123456"

# SQL injection - should be caught
def unsafe_query(user_input):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Very obvious SQL injection
    query = "SELECT * FROM users WHERE id = " + user_input
    cursor.execute(query)
    
    return cursor.fetchall()

# Safe version for comparison
def safe_query(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Parameterized query - should NOT be caught
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    
    return cursor.fetchall()

# Database connection issue - should be caught
def create_in_memory_db():
    conn = sqlite3.connect(":memory:")  # In-memory DB
    return conn

# Input validation issue - should be caught
def process_input():
    user_input = input("Enter something: ")  # No validation
    return user_input

if __name__ == "__main__":
    print("Test file for security analyzer")
