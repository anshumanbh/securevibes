---
name: sql-injection-testing
description: Validate SQL injection vulnerabilities (including blind SQLi) across time-based, error-based, boolean-based, UNION-based, stacked-query, and out-of-band patterns. Use when testing CWE-89 (SQL Injection), CWE-564 (Hibernate SQL Injection), and related SQL injection classes across MySQL, PostgreSQL, MSSQL, Oracle, and SQLite targets.
allowed-tools: Read, Write, Bash
---

# SQL Injection Testing Skill

## Purpose
Validate SQL injection (including blind SQLi) by injecting SQL syntax into user-controlled inputs and observing:
- **Time-based delays** (blind)
- **Error messages** (error-based)
- **Boolean/content differences** (blind)
- **Data extraction via UNION**
- **Stacked queries** where supported
- **Out-of-band interactions** (DNS/HTTP callbacks) when infra allows

## Vulnerability Types Covered

### 1. Time-Based Blind SQLi (CWE-89)
Inject time-delay functions and detect response latency.

**Detection Methods:** `SLEEP(5)`, `pg_sleep(5)`, `WAITFOR DELAY '0:0:5'`, heavy functions (e.g., `randomblob()` for SQLite).

### 2. Boolean-Based Blind SQLi (CWE-89)
Inject true/false conditions and compare content/length/status.

**Detection Methods:** `' OR '1'='1` vs `' OR '1'='2`, `AND 1=1` vs `AND 1=2`.

### 3. Error-Based SQLi (CWE-89)
Trigger SQL parser errors and observe verbose error responses.

**Detection Methods:** stray quote/backtick, type-cast errors, `extractvalue()/updatexml()` (MySQL), `CAST('a' AS INT)` (PostgreSQL/MSSQL).

### 4. UNION-Based SQLi (CWE-89)
Use UNION to extract data when column counts align.

**Detection Methods:** `UNION SELECT NULL,NULL`, `ORDER BY N` probing for column count.

### 5. Stacked Queries (CWE-89)
Inject additional statements when DB/driver permits (e.g., MSSQL `; WAITFOR`, PostgreSQL `; SELECT pg_sleep(5)`).

### 6. Out-of-Band SQLi (CWE-89)
Detect DNS/HTTP callbacks via `load_file()`, `xp_dirtree`, or UTL_HTTP/UTL_INADDR when response-based detection is blocked (use only if callback infra is authorized).

### 7. ORM/Framework-Specific (CWE-564)
Hibernate/JPA or query-builder misuse leading to SQLi (parameter concatenation, unsafe `createQuery`).

## Database-Specific Notes

| Database | Time-Based | Error-Based | Boolean-Based | UNION | Stacked Queries |
|----------|------------|-------------|---------------|-------|-----------------|
| MySQL/MariaDB | `SLEEP(5)` | ✓ | ✓ | ✓ | Limited |
| PostgreSQL | `pg_sleep(5)` | ✓ | ✓ | ✓ | ✓ (`; SELECT ...`) |
| MSSQL | `WAITFOR DELAY '0:0:5'` | ✓ | ✓ | ✓ | ✓ |
| Oracle | `dbms_pipe.receive_message` | ✓ | ✓ | ✓ | Limited |
| SQLite | No native sleep; use heavy ops (`randomblob`) | ✓ | ✓ | Partial | No |

## Prerequisites
- Target reachable; SQL-backed functionality identified (endpoints, forms, headers, cookies, path params).
- If authentication required: test accounts available (low-priv + optional admin) or mark paths UNVALIDATED.
- Know (or infer) DB type to choose correct payloads; default to generic when unknown.
- VULNERABILITIES.json with suspected SQLi findings if provided.

## Testing Methodology

### Phase 1: Identify Injection Points
- URL params, POST bodies (JSON/form), headers, cookies, path segments.
- Look for string interpolation, query concatenation, ORM custom queries.

### Phase 2: Establish Baseline
- Send a benign request; record status, content length, and response time.
- Note WAF/rate-limit behaviors.

### Phase 3: Execute SQLi Tests

**Time-Based (Blind):**
```python
payload = "123' OR SLEEP(5)--"
resp_time = send(payload)
if resp_time > baseline_time + 4.5:
    status = "VALIDATED"
```

**Boolean-Based (Blind):**
```python
true_p = "123' OR '1'='1"
false_p = "123' OR '1'='2"
len_true = len(send(true_p).text)
len_false = len(send(false_p).text)
if abs(len_true - len_false) >= 50:
    status = "VALIDATED"
```

**Error-Based:**
```python
payload = "123'"
resp = send(payload)
if any(err in resp.text.lower() for err in sql_errors):
    status = "VALIDATED"
```

**UNION/Stacked Probing:**
- `ORDER BY` incrementally to find column count.
- `UNION SELECT NULL,...` until count matches; watch for 200 vs 500.
- For stacked-capable DBs: append `; SELECT pg_sleep(5)` or `; WAITFOR DELAY '0:0:5'`.

**Out-of-Band (only if infra-approved):**
- Use controlled collaborator domain; record DNS/HTTP hits.
- Stop if any unexpected external interaction occurs.

### Phase 4: Classification Logic

| Status | Meaning |
|--------|---------|
| **VALIDATED** | Clear SQLi indicators (delay, error, boolean diff, data via UNION/stacked, OOB hit) |
| **FALSE_POSITIVE** | No indicators; behavior unchanged |
| **PARTIAL** | Mixed/weak signals (small deltas, inconsistent responses) |
| **UNVALIDATED** | Blocked, error, or insufficient evidence |

### Phase 5: Capture Evidence
Capture minimal structured evidence (redact PII/secrets, truncate to 8KB, hash full response). Include:
- `status`, `injection_type`, `cwe`
- Baseline request (url/method/status/time/hash)
- Test request (url/method/status/time/hash, or collaborator hit details)
- Payload used
- Note if truncated and original size

### Phase 6: Safety Rules
- Detection-only payloads; **never** destructive statements (DROP/DELETE/TRUNCATE/UPDATE/INSERT).
- Avoid data exfiltration; prefer boolean/time-based confirmation.
- Do not send OOB callbacks unless explicitly authorized.
- Respect rate limits; add delays between time-based probes.
- Redact credentials, tokens, and personal data in evidence.

## Output Guidelines
- Keep responses concise (1-4 sentences).
- Include endpoint, payload, detection method, and impact.

**Validated examples:**
```
Time-based SQLi on /api/users?id - SLEEP(5) payload caused 5.1s delay (CWE-89). Evidence: path/to/evidence.json
Boolean-based SQLi on /products - response length differs for true vs false condition (CWE-89). Evidence: path/to/evidence.json
Error-based SQLi on /login - SQL syntax error returned to client (CWE-89). Evidence: path/to/evidence.json
```

**Unvalidated example:**
```
SQLi test incomplete on /reports - WAF blocked payloads (403). Evidence: path/to/evidence.json
```

## CWE Mapping

**Primary CWEs (DAST-testable):**
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- **CWE-564:** SQL Injection: Hibernate (ORM-specific variant of CWE-89)

**Parent/Related CWEs (context):**
- **CWE-943:** Improper Neutralization of Special Elements in Data Query Logic (parent class of CWE-89)
- **CWE-74:** Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') (grandparent)
- **CWE-20:** Improper Input Validation (related - root cause)

**Note:** CWE-89 is ranked #2 in MITRE's 2025 CWE Top 25 Most Dangerous Software Weaknesses.

## Notable CVEs (examples)
- **CVE-2023-34362 (MOVEit Transfer):** Pre-auth SQLi leading to mass data exfiltration; exploited by Cl0p ransomware.
- **CVE-2024-27956 (WordPress Automatic Plugin):** Unauthenticated SQLi allowing privilege escalation.
- **CVE-2021-27065 (Microsoft Exchange ProxyLogon chain):** Post-auth SQLi in OWA contributing to RCE chain.
- **CVE-2019-2725 (Oracle WebLogic):** Unauthenticated SQLi leading to RCE.
- **CVE-2017-5638 (Apache Struts):** OGNL injection (related pattern) leading to RCE via Content-Type header.
- **CVE-2014-3704 (Drupal SA-CORE-2014-005):** SQLi via Drupal 7/8 form API ("Drupalgeddon").

## Safety Reminders
- ONLY test against user-approved targets; stop if production protections trigger.
- Do not log or store sensitive data; redact in evidence.
- Prefer parameterized queries and least-privileged DB accounts in mitigations.

## Reference Implementations
- See `reference/sql_payloads.py` for SQLi payloads by DB and detection type.
- See `reference/validate_sqli.py` for a SQLi-focused validation flow (time/error/boolean/UNION/stacked).
- See `examples.md` for concrete SQLi scenarios and evidence formats.
