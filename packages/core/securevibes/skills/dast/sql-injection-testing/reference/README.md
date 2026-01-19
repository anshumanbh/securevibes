# SQL Injection Reference Implementations

Reference utilities for SQL injection testing. These are examples to adapt, not drop-in scripts.

## Files

- `sql_payloads.py` — SQLi payload generation by detection type and DB (time/error/boolean/union/stacked).
- `validate_sqli.py` — SQLi-focused validator (time, error, boolean, union probes, stacked where supported).

## Usage Examples

### Payloads
```python
from sql_payloads import get_time_payloads, get_error_payloads, get_boolean_payloads, get_union_payloads

time_payloads = get_time_payloads(db_type="mysql")
error_payloads = get_error_payloads(db_type="postgres")
```

### Validator
```bash
python validate_sqli.py \
  --url "http://target.com/api/users" \
  --param "id" \
  --value "1" \
  --types "time,error,boolean,union" \
  --db "mysql" \
  --output sqli_results.json
```

## Adaptation Notes
- Update endpoints, HTTP methods, and parameters to match the target.
- Add authentication headers/cookies with `--header "Authorization: Bearer ..."` if required.
- For POST/JSON, modify `validate_sqli.py` request bodies accordingly (it defaults to GET + query param).
- Configure out-of-band/collaborator domain only when authorized; otherwise disable OOB tests.

## Safety Reminders
- Detection-only payloads; never use destructive statements.
- Redact sensitive data in responses; truncate to 8KB and hash full bodies.
- Respect rate limits; introduce delays between time-based probes.
