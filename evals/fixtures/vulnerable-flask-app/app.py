"""Vulnerable Flask application for eval testing.

This application intentionally contains security vulnerabilities
for testing SecureVibes detection capabilities.

DO NOT USE IN PRODUCTION.
"""

from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key-12345"  # CWE-798: Hardcoded credentials


def get_db():
    """Get database connection."""
    conn = sqlite3.connect('users.db')
    return conn


@app.route('/')
def index():
    return "Welcome to the vulnerable app!"


@app.route('/users')
def get_user():
    """VULNERABLE: SQL Injection via string concatenation (CWE-89)."""
    user_id = request.args.get('id', '')
    
    conn = get_db()
    cursor = conn.cursor()
    
    # VULNERABLE: User input directly concatenated into query
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    
    return str(results)


@app.route('/search')
def search():
    """VULNERABLE: Another SQL injection vector."""
    name = request.args.get('name', '')
    
    conn = get_db()
    cursor = conn.cursor()
    
    # VULNERABLE: String concatenation with user input
    query = "SELECT * FROM users WHERE name LIKE '%" + name + "%'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    
    return str(results)


@app.route('/profile')
def profile():
    """VULNERABLE: Reflected XSS (CWE-79)."""
    username = request.args.get('username', 'Guest')
    
    # VULNERABLE: User input rendered without escaping
    html = f"""
    <html>
        <body>
            <h1>Welcome, {username}!</h1>
        </body>
    </html>
    """
    return render_template_string(html)


@app.route('/download')
def download():
    """VULNERABLE: Path traversal (CWE-22)."""
    filename = request.args.get('file', '')
    
    # VULNERABLE: No path validation
    file_path = os.path.join('/uploads', filename)
    
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File not found", 404


@app.route('/exec')
def execute():
    """VULNERABLE: Command injection (CWE-78)."""
    cmd = request.args.get('cmd', 'echo hello')
    
    # VULNERABLE: Direct command execution
    import subprocess
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    return result.stdout


if __name__ == '__main__':
    # Initialize database
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT,
            email TEXT,
            password TEXT
        )
    ''')
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin@test.com', 'password123')"
    )
    conn.commit()
    conn.close()
    
    app.run(debug=True)  # VULNERABLE: Debug mode in production
