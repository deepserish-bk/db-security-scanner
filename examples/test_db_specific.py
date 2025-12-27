#!/usr/bin/env python3
"""
Test file for database-specific security checks
Contains various DB vulnerabilities for testing
"""

import sqlite3
import psycopg2
import pymysql
from pymongo import MongoClient

# ===== SQLite issues =====
# SQLite in temp directory (MEDIUM severity)
conn1 = sqlite3.connect('/tmp/test.db')

# SQLite in-memory (LOW severity if in production-like code)
conn2 = sqlite3.connect(':memory:')

# ===== PostgreSQL issues =====
def postgres_test():
    conn = psycopg2.connect("dbname=test user=postgres")
    cursor = conn.cursor()
    
    # COPY FROM STDIN - dangerous! (HIGH severity)
    cursor.copy_from(open('data.csv'), 'my_table')
    
    # Type registration (MEDIUM severity)
    from psycopg2 import extensions
    extensions.register_type(extensions.UNICODE)
    
    return cursor

# ===== MySQL issues =====
def mysql_test():
    # Default port (MEDIUM severity)
    conn = pymysql.connect(host='localhost', port=3306, user='root', password='secret')
    
    # LOAD DATA INFILE - file injection risk (HIGH severity)
    cursor = conn.cursor()
    cursor.execute("LOAD DATA INFILE '/tmp/data.csv' INTO TABLE users")
    
    return conn

# ===== MongoDB issues =====
def mongodb_test():
    client = MongoClient('localhost', 27017)
    db = client.test_database
    
    # eval() - CRITICAL severity!
    result = db.eval('function() { return db.users.find().count(); }')
    
    # $where operator - MEDIUM severity
    users = db.users.find({"$where": "this.age > 18"})
    
    return users

# Safe database usage examples
def safe_examples():
    # Safe SQLite
    conn = sqlite3.connect('./data/production.db')
    
    # Safe PostgreSQL without COPY
    import psycopg2
    safe_conn = psycopg2.connect("dbname=prod user=appuser")
    
    # Safe MySQL with custom port
    import pymysql
    mysql_conn = pymysql.connect(host='localhost', port=3307, user='appuser')
    
    # Safe MongoDB without eval
    from pymongo import MongoClient
    mongo_client = MongoClient('localhost', 27017)
    results = mongo_client.test.users.find({"age": {"$gt": 18}})
    
    return conn, safe_conn, mysql_conn, results

if __name__ == "__main__":
    print("Testing database-specific security checks...")
    postgres_test()
    mysql_test()
    mongodb_test()
    safe_examples()
