"""
Intentionally vulnerable code for testing scanner
"""

import os
import sqlite3


# VULNERABLE: Hardcoded token (test fixture - not real)
SECRET_TOKEN = "test-fake-token-xxxxxxxxxxxxx"


def unsafe_query(user_id):
    """SQL Injection vulnerability"""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # VULNERABLE: String concatenation in SQL
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()


def unsafe_command(filename):
    """Command Injection vulnerability"""
    # VULNERABLE: Unsanitized input to shell
    os.system(f"cat {filename}")


def hardcoded_secret():
    """Hardcoded credentials"""
    # VULNERABLE: Hardcoded API key (test fixture - not real)
    API_KEY = "test-fake-key-1234567890abcdef"
    return API_KEY


def path_traversal(user_file):
    """Path traversal vulnerability"""
    # VULNERABLE: No path validation
    with open(f"/uploads/{user_file}", "r") as f:
        return f.read()


def eval_danger(user_input):
    """Code injection via eval"""
    # VULNERABLE: eval with user input
    result = eval(user_input)
    return result
