# NoSQL Injection Reference Implementations

Reference utilities for NoSQL injection testing. These are examples to adapt, not drop-in scripts.

## Files

- `nosql_payloads.py` — NoSQLi payload generation by database type and injection technique
- `validate_nosqli.py` — NoSQLi-focused validator (operator injection, JS injection, boolean-based)

## Usage Examples

### Payloads
```python
from nosql_payloads import (
    get_operator_payloads,
    get_js_payloads,
    get_regex_payloads,
    get_query_string_payloads
)

# MongoDB operator injection payloads
operator_payloads = get_operator_payloads(db_type="mongodb")

# JavaScript injection payloads ($where)
js_payloads = get_js_payloads(detection="time")

# Regex-based extraction payloads
regex_payloads = get_regex_payloads(prefix="admin")
```

### Validator
```bash
python validate_nosqli.py \
  --url "http://target.com/api/login" \
  --method POST \
  --body '{"username":"admin","password":"INJECT"}' \
  --inject-field "password" \
  --types "operator,js,boolean" \
  --db "mongodb" \
  --output nosqli_results.json
```

## Adaptation Notes
- Update endpoints, HTTP methods, and JSON body structure to match the target
- Add authentication headers/cookies with `--header "Authorization: Bearer ..."` if required
- For query string injection (Express.js), use `--query-inject` mode
- Adjust payload sets based on the specific NoSQL database in use

## Safety Reminders
- Detection-only payloads; never use destructive operations (`$out`, `db.dropDatabase()`)
- Redact sensitive data in responses; truncate to 8KB and hash full bodies
- Respect rate limits; introduce delays between requests
- Do not execute arbitrary JavaScript that modifies data

## Database-Specific Notes

### MongoDB
- Most common target; supports operator injection and $where JS
- Disable JS execution in production with `--noscripting`

### CouchDB
- Views and design documents can contain JavaScript
- Selector-based queries support operators

### Redis
- Command injection via unsanitized inputs
- Lua script injection if scripting enabled

### Elasticsearch
- Query DSL manipulation
- Script injection if scripting enabled
