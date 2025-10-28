# Authorization Testing Examples

This file contains comprehensive examples of authorization vulnerability testing, organized by vulnerability category.

## Table of Contents
1. [Horizontal Escalation (IDOR)](#horizontal-escalation-idor)
2. [Vertical Privilege Escalation](#vertical-privilege-escalation)
3. [Missing Authorization](#missing-authorization)
4. [Forced Browsing / Direct Request](#forced-browsing--direct-request)
5. [Test Result Types](#test-result-types)
   - FALSE_POSITIVE (Example 9)
   - UNVALIDATED (Example 10)
   - PARTIAL (Example 11)
6. [Common Patterns](#common-patterns)

---

## Horizontal Escalation (IDOR)

### Example 1: Sequential ID IDOR

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

### Example 4: Cross-Account Modification (CWE-639)

**Scenario**: Profile update API missing ownership check

**Vulnerability**:
```python
# api/profiles.py - VULNERABLE
@app.route('/api/profile/<int:user_id>/update', methods=['POST'])
@login_required
def update_profile(user_id):
    profile = Profile.query.filter_by(user_id=user_id).first()
    profile.email = request.json.get('email')
    profile.phone = request.json.get('phone')
    db.session.commit()
    return jsonify({"success": True})  # No ownership check!
```

**Test**:
1. User2 (ID: 456) authenticates
2. User2 POSTs to `/api/profile/1/update` with malicious data
3. Result: 200 OK, User1 (admin) profile modified

**Evidence**:
```json
{
  "status": "VALIDATED",
  "baseline": {
    "url": "http://target.com/api/profile/456/update",
    "status": 200,
    "response_snippet": "{\"success\":true}"
  },
  "test": {
    "url": "http://target.com/api/profile/1/update",
    "method": "POST",
    "payload": "{\"email\":\"attacker@evil.com\",\"phone\":\"555-0000\"}",
    "status": 200,
    "response_snippet": "{\"success\":true}"
  },
  "evidence": "User2 modified User1's (admin) profile - account takeover risk"
}
```

---

## Vertical Privilege Escalation

### Example 5: Role Self-Modification (CWE-269)

**Scenario**: User can escalate own privileges via role update endpoint

**Vulnerability**:
```python
# api/users.py - VULNERABLE
@app.route('/update_role', methods=['POST'])
@login_required
def update_role():
    user_id = request.json.get('user_id')
    new_role = request.json.get('role')
    
    user = User.query.get(user_id)
    user.role = new_role  # No authorization check!
    db.session.commit()
    
    return jsonify({"success": True})
```

**Test**:
1. Regular user (ID: 123, role: user) authenticates
2. User POSTs to `/update_role` with `{"user_id": 123, "role": "admin"}`
3. Result: 200 OK, user's role changed to admin

**Evidence**:
```json
{
  "status": "VALIDATED",
  "baseline": {
    "url": "http://target.com/api/user/123",
    "status": 200,
    "response_snippet": "{\"id\":123,\"role\":\"user\"}"
  },
  "test": {
    "url": "http://target.com/update_role",
    "method": "POST",
    "payload": "{\"user_id\":123,\"role\":\"admin\"}",
    "status": 200,
    "response_snippet": "{\"success\":true}"
  },
  "evidence": "Regular user escalated to admin role - complete system compromise possible"
}
```

### Example 6: Admin Function Access (CWE-285)

**Scenario**: Admin dashboard accessible to non-admin users

**Vulnerability**:
```python
# api/admin.py - VULNERABLE
@app.route('/admin/dashboard')
@login_required  # Only checks authentication, not authorization!
def admin_dashboard():
    users = User.query.all()
    return render_template('admin/dashboard.html', users=users)
```

**Test**:
1. Regular user authenticates
2. User GETs `/admin/dashboard`
3. Result: 200 OK, admin panel HTML returned with sensitive data

**Evidence**:
```json
{
  "status": "VALIDATED",
  "baseline": {
    "url": "http://target.com/dashboard",
    "status": 200,
    "response_snippet": "<html>User Dashboard</html>"
  },
  "test": {
    "url": "http://target.com/admin/dashboard",
    "status": 200,
    "response_snippet": "<html>Admin Dashboard - 1,234 users</html>"
  },
  "evidence": "Regular user accessed admin dashboard - information disclosure, potential further exploitation"
}
```

---

## Missing Authorization

### Example 7: Missing Authorization on Admin Endpoint (CWE-862)

**Scenario**: Admin API endpoint has no authorization check at all

**Vulnerability**:
```python
# api/admin.py - VULNERABLE
@app.route('/api/admin/users')
def get_all_users():  # No @login_required, no role check!
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])
```

**Test**:
1. Unauthenticated request to `/api/admin/users`
2. Result: 200 OK, full user list with emails, phone numbers

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/api/admin/users",
    "method": "GET",
    "authenticated": false,
    "status": 200,
    "response_snippet": "[{\"id\":1,\"email\":\"admin@company.com\"},{\"id\":2,\"email\":\"user@company.com\"}...]"
  },
  "evidence": "Unauthenticated access to admin endpoint - mass information disclosure, user enumeration"
}
```

---

## Forced Browsing / Direct Request

### Example 8: Direct URL Access to Admin Settings (CWE-425)

**Scenario**: Admin settings page accessible by directly navigating to URL

**Vulnerability**:
```python
# routes/admin.py - VULNERABLE
@app.route('/admin/settings')
def admin_settings():
    # Relies on UI hiding the link, but no server-side check!
    return render_template('admin/settings.html')
```

**Test**:
1. Regular user authenticates
2. User directly navigates to `/admin/settings` (bypassing normal navigation)
3. Result: 200 OK, admin settings page displayed

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/admin/settings",
    "method": "GET",
    "user": "regular_user",
    "status": 200,
    "response_snippet": "<html>Admin Settings - API Keys, Database Config</html>"
  },
  "evidence": "Regular user accessed admin settings via direct URL - unauthorized access to administrative functionality"
}
```

---

## Test Result Types

### Example 9: FALSE_POSITIVE (Properly Secured)

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

### Example 10: UNVALIDATED (Cannot Test)

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

### Example 11: PARTIAL (Mixed Results)

**Scenario**: Document API with inconsistent authorization - read succeeds but write/delete are protected

**Vulnerability**:
```python
# api/documents.py - PARTIALLY VULNERABLE
@app.route('/api/documents/<int:doc_id>', methods=['GET'])
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    return jsonify(doc.to_dict())  # No authorization check!

@app.route('/api/documents/<int:doc_id>', methods=['PUT'])
@require_ownership  # This decorator checks ownership
def update_document(doc_id):
    # Properly protected
    pass

@app.route('/api/documents/<int:doc_id>', methods=['DELETE'])
@require_ownership  # This decorator checks ownership
def delete_document(doc_id):
    # Properly protected
    pass
```

**Test**:
1. User1 (owns doc 123) authenticates
2. User1 creates baseline: `GET /api/documents/123` → 200 OK
3. User1 tests User2's document (doc 456):
   - `GET /api/documents/456` → 200 OK (IDOR on read!)
   - `PUT /api/documents/456` → 403 Forbidden (write protected)
   - `DELETE /api/documents/456` → 403 Forbidden (delete protected)

**Evidence**:
```json
{
  "status": "PARTIAL",
  "baseline": {
    "url": "http://target.com/api/documents/123",
    "method": "GET",
    "status": 200,
    "response_snippet": "{\"id\":123,\"title\":\"My Doc\",\"owner\":\"user1\"}",
    "response_hash": "sha256:abc123..."
  },
  "test": {
    "read": {
      "url": "http://target.com/api/documents/456",
      "method": "GET",
      "status": 200,
      "response_snippet": "{\"id\":456,\"title\":\"Private Doc\",\"owner\":\"user2\"}",
      "response_hash": "sha256:def456..."
    },
    "write": {
      "url": "http://target.com/api/documents/456",
      "method": "PUT",
      "status": 403,
      "response_snippet": "{\"error\":\"Not authorized to modify this document\"}",
      "response_hash": "sha256:ghi789..."
    },
    "delete": {
      "url": "http://target.com/api/documents/456",
      "method": "DELETE",
      "status": 403,
      "response_snippet": "{\"error\":\"Not authorized to delete this document\"}",
      "response_hash": "sha256:jkl012..."
    }
  },
  "evidence": "User1 read User2's document (200 OK) but modification/deletion properly blocked (403). Information disclosure via IDOR on read operation.",
  "requires_manual_review": true,
  "risk_assessment": "Medium - Information disclosure but not tampering"
}
```

**Classification Rationale**:
- **Not VALIDATED**: Write and delete operations are properly secured
- **Not FALSE_POSITIVE**: Read operation has IDOR vulnerability
- **PARTIAL**: Mixed results - some operations bypass authorization, others don't
- **Manual Review Needed**: Security team must assess whether read-only IDOR poses acceptable risk

**Real-World Impact**:
- Attacker can read sensitive documents (information disclosure)
- Cannot modify or delete documents (tampering prevented)
- Risk depends on document sensitivity and business context

---

## Common Patterns

### Authorization Bypass Patterns to Test

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
