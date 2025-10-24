# IDOR Testing Examples

## Example 1: Sequential ID IDOR

**Scenario**: User management API with sequential numeric IDs

**Vulnerability**:
```python
# api/users.py - VULNERABLE
@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())  # No authorization check!
```

**Test**:
1. User1 (ID: 123) authenticates and gets token
2. User1 accesses `/api/users/123` → 200 OK (authorized)
3. User1 accesses `/api/users/456` (User2's ID) → 200 OK (IDOR!)

**Evidence**:
```json
{
  "status": "VALIDATED",
  "baseline": {
    "url": "http://target.com/api/users/123",
    "status": 200,
    "response_snippet": "{\"id\":123,\"email\":\"user1@test.com\"}"
  },
  "test": {
    "url": "http://target.com/api/users/456",
    "status": 200,
    "response_snippet": "{\"id\":456,\"email\":\"user2@test.com\"}"
  },
  "evidence": "User1 accessed User2's profile without authorization"
}
```

---

## Example 2: UUID IDOR

**Scenario**: Document management system using UUIDs

**Vulnerability**:
```python
# api/documents.py - VULNERABLE
@app.route('/api/documents/<uuid:doc_id>')
def get_document(doc_id):
    doc = Document.query.filter_by(id=doc_id).first()
    return jsonify(doc.to_dict())  # No ownership check!
```

**Test**:
1. User1 creates document → Gets UUID: `abc-def-123`
2. User2 creates document → Gets UUID: `xyz-pqr-789`
3. User1 accesses `/api/documents/abc-def-123` → 200 OK
4. User1 accesses `/api/documents/xyz-pqr-789` → 200 OK (IDOR!)

**Evidence**:
```json
{
  "status": "VALIDATED",
  "baseline": {
    "url": "http://target.com/api/documents/abc-def-123",
    "status": 200,
    "response_snippet": "{\"id\":\"abc-def-123\",\"owner\":\"user1\"}"
  },
  "test": {
    "url": "http://target.com/api/documents/xyz-pqr-789",
    "status": 200,
    "response_snippet": "{\"id\":\"xyz-pqr-789\",\"owner\":\"user2\"}"
  },
  "evidence": "User1 accessed User2's private document"
}
```

---

## Example 3: Nested Resource IDOR

**Scenario**: Team management with nested resources

**Vulnerability**:
```python
# api/teams.py - VULNERABLE
@app.route('/api/teams/<int:team_id>/members/<int:member_id>')
def get_team_member(team_id, member_id):
    member = TeamMember.query.filter_by(
        team_id=team_id, 
        id=member_id
    ).first()
    return jsonify(member.to_dict())  # No team membership check!
```

**Test**:
1. User1 belongs to Team 1
2. User1 accesses `/api/teams/1/members/5` (their own) → 200 OK
3. User1 accesses `/api/teams/2/members/10` (Team 2 member) → 200 OK (IDOR!)

---

## Example 4: FALSE_POSITIVE (Properly Secured)

**Scenario**: API with proper authorization

**Secure Implementation**:
```python
# api/users.py - SECURE
@app.route('/api/users/<int:user_id>')
@login_required
def get_user(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        abort(403, "Not authorized")
    
    user = User.query.get(user_id)
    return jsonify(user.to_dict())
```

**Test Result**:
```json
{
  "status": "FALSE_POSITIVE",
  "baseline": {
    "url": "http://target.com/api/users/123",
    "status": 200,
    "response_snippet": "{\"id\":123,\"email\":\"user1@test.com\"}"
  },
  "test": {
    "url": "http://target.com/api/users/456",
    "status": 403,
    "response_snippet": "{\"error\":\"Not authorized\"}"
  },
  "evidence": "Access properly denied with 403"
}
```

---

## Example 5: UNVALIDATED (Cannot Test)

**Scenario**: Endpoint requires complex multi-step authentication

**Test Result**:
```json
{
  "status": "UNVALIDATED",
  "reason": "Endpoint requires OAuth2 + 2FA which cannot be automated",
  "evidence": null
}
```

---

## Common IDOR Patterns to Test

### Pattern 1: Direct Object Reference
```
GET /api/users/{id}
GET /api/documents/{id}
GET /api/orders/{id}
```

### Pattern 2: Nested Resources
```
GET /api/users/{user_id}/documents/{doc_id}
GET /api/teams/{team_id}/members/{member_id}
```

### Pattern 3: Batch Operations
```
POST /api/users/bulk-update
Body: {"user_ids": [123, 456, 789]}
```

### Pattern 4: Query Parameters
```
GET /api/profile?user_id=123
GET /api/export?document_id=456
```

---

## Test Account Setup

**Minimal Setup**:
```json
{
  "regular_users": [
    {
      "email": "user1@test.com",
      "password": "TestPass123!",
      "user_id": "123"
    },
    {
      "email": "user2@test.com",
      "password": "TestPass456!",
      "user_id": "456"
    }
  ]
}
```

**Advanced Setup** (with resources):
```json
{
  "regular_users": [
    {
      "email": "user1@test.com",
      "password": "TestPass123!",
      "user_id": "123",
      "documents": ["doc-abc", "doc-def"],
      "orders": [1001, 1002]
    },
    {
      "email": "user2@test.com",
      "password": "TestPass456!",
      "user_id": "456",
      "documents": ["doc-xyz", "doc-pqr"],
      "orders": [2001, 2002]
    }
  ]
}
```
