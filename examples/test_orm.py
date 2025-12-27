#!/usr/bin/env python3
"""
Test ORM security patterns
"""

# SQLAlchemy unsafe pattern
def unsafe_sqlalchemy():
    from sqlalchemy import text
    
    user_id = "1"
    # UNSAFE - string concatenation
    query = text("SELECT * FROM users WHERE id = " + user_id)
    return query

# Django unsafe pattern  
def unsafe_django():
    # Simulate Django ORM
    class QuerySet:
        def raw(self, sql, params=None):
            return []
    
    users = QuerySet()
    # UNSAFE - raw() usage
    result = users.raw("SELECT * FROM auth_user")
    return result

# Safe patterns
def safe_examples():
    from sqlalchemy import text
    
    # SAFE - parameterized
    safe_query = text("SELECT * FROM users WHERE id = :id")
    
    # Simulate safe Django
    class SafeQuerySet:
        def raw(self, sql, params=None):
            return []
        def filter(self, **kwargs):
            return []
    
    return safe_query
