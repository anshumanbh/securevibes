# Authorization Testing Reference Implementations

These files are examples to read and adapt — not runnable drop-in scripts.

## Files

### auth_patterns.py
Reusable authentication helper functions for common auth mechanisms:
- **session_based_auth()**: Session cookie authentication (Flask, Express, Django)
- **jwt_bearer_auth()**: JWT Bearer token authentication (REST APIs)
- **api_key_auth()**: API key header authentication
- **oauth2_token_auth()**: OAuth2 access token authentication
- **basic_auth()**: HTTP Basic authentication
- **auto_auth()**: Automatic authentication detection

Usage:
```python
from auth_patterns import jwt_bearer_auth

headers = jwt_bearer_auth("http://localhost:5000", "user1", "pass123")
response = requests.get(f"{target_url}/api/resource", headers=headers)
```

### validate_idor.py
Complete authorization testing pattern illustrating:
- Authentication and session management
- Baseline vs. test request execution
- Response redaction for sensitive fields
- Response truncation and hashing
- Classification logic (VALIDATED/FALSE_POSITIVE/UNVALIDATED)

Usage guidance:
- Identify the application's auth mechanism and endpoints
- Adapt authentication, headers, payloads, and URLs accordingly
- Capture minimal, redacted evidence and hash full bodies
- Classify based on status codes and expected behavior

## Important

Do not run these files unchanged; each application requires tailored logic. These are reference implementations to guide your testing approach.
