---
name: api-security-threat-modeling
description: Threat model REST and GraphQL APIs using OWASP API Security Top 10. Use when analyzing API backends, microservice endpoints, mobile app backends, or any HTTP/JSON-based service interfaces. Covers BOLA, authentication, authorization, rate limiting, mass assignment, and API-specific attack patterns.
allowed-tools: Read, Grep, Glob, Write
---

# API Security Threat Modeling Skill

## Purpose

Apply specialized threat modeling to API-first applications, covering the OWASP API Security Top 10 (2023). This skill focuses on REST APIs, GraphQL endpoints, webhook receivers, and service-to-service communication patterns.

## When to Use This Skill

Use this skill when the target application includes ANY of:
- REST API endpoints (JSON/XML over HTTP)
- GraphQL APIs
- Mobile application backends
- Single-Page Application (SPA) backends
- Microservice API gateways
- Third-party API integrations
- Webhook receivers
- OAuth/OIDC implementations

## API Security Threat Categories

### 1. BROKEN OBJECT LEVEL AUTHORIZATION - BOLA (API1:2023)

APIs expose endpoints that handle object identifiers, creating attack surface for unauthorized access.

**Horizontal Access**
- Accessing other users' resources by changing IDs
- Enumerable/predictable object identifiers
- Missing ownership verification on CRUD operations

**Patterns to Look For:**
```
GET /api/users/{user_id}
GET /api/orders/{order_id}
PUT /api/documents/{doc_id}
DELETE /api/posts/{post_id}
```

**Indicators:**
- Path parameters used directly in database queries
- No `WHERE user_id = current_user` in queries
- Sequential/predictable IDs (1, 2, 3...)
- UUID used but not verified against session

### 2. BROKEN AUTHENTICATION (API2:2023)

Authentication mechanisms that are weak or improperly implemented.

**Token Vulnerabilities**
- JWT with `alg: none` or weak algorithms
- Tokens that never expire
- Tokens not invalidated on logout
- Sensitive data in JWT payload

**Credential Issues**
- No brute-force protection
- Weak password requirements
- Password in response bodies
- API keys in URLs (logged by proxies)

**Session Problems**
- Session tokens predictable
- Missing token rotation
- Tokens stored insecurely client-side

**Indicators:**
- `jwt.decode(token, verify=False)`
- No rate limiting on `/auth/login`
- Tokens valid for >24h without refresh
- API keys passed in query strings

### 3. BROKEN OBJECT PROPERTY LEVEL AUTHORIZATION (API3:2023)

API returns more data than necessary or allows modification of protected fields.

**Excessive Data Exposure**
- Internal IDs exposed in responses
- Sensitive fields included (password_hash, SSN)
- Debug information in production
- Full objects returned instead of projections

**Mass Assignment**
- User can set `is_admin: true` in request
- Role/permission fields modifiable
- Internal fields bindable from request
- No allowlist for updateable fields

**Indicators:**
- `User.update(request.json)` without filtering
- `return user.to_dict()` (full serialization)
- Response includes fields like `password_hash`, `internal_notes`
- No DTO/serializer layer

### 4. UNRESTRICTED RESOURCE CONSUMPTION (API4:2023)

APIs allow unlimited resource usage leading to DoS or cost attacks.

**Rate Limiting Gaps**
- No request rate limits
- Limits per-IP only (bypassable)
- Missing limits on expensive operations
- File upload size unrestricted

**Query Complexity**
- GraphQL depth unlimited
- Pagination missing/bypassable
- N+1 queries exploitable
- Batch operations unbounded

**Indicators:**
- No `X-RateLimit-*` headers
- GraphQL without depth/complexity limits
- `?limit=999999` accepted
- File uploads to `/tmp` without size check

### 5. BROKEN FUNCTION LEVEL AUTHORIZATION (API5:2023)

Admin endpoints accessible to regular users.

**Missing Role Checks**
- Admin routes without `@admin_required`
- Horizontal access to admin functions
- Role checks only on frontend
- Debug endpoints in production

**API Versioning Issues**
- Old API versions lack security controls
- Shadow APIs without authentication
- Internal APIs exposed externally

**Indicators:**
- `/api/admin/*` without role verification
- `DEBUG_ENDPOINTS` enabled in production
- `/api/v1/` missing controls that `/api/v2/` has
- Internal service ports exposed publicly

### 6. UNRESTRICTED ACCESS TO SENSITIVE BUSINESS FLOWS (API6:2023)

APIs that can be automated to harm the business.

**Abusable Flows**
- Account creation without CAPTCHA
- Coupon/promo code endpoint bruteforceable
- Password reset tokens guessable
- Voting/rating systems gameable

**Resource Exhaustion**
- Free tier abuse
- Trial account farming
- Scraping without limits

**Indicators:**
- No CAPTCHA on registration
- Promo codes without rate limiting
- Email/SMS sending without throttling
- No device fingerprinting

### 7. SERVER SIDE REQUEST FORGERY - SSRF (API7:2023)

API fetches remote resources based on user input.

**URL Injection**
- Webhook URL pointing to internal services
- Image URL fetching internal networks
- Document import from user-supplied URLs
- OAuth callback manipulation

**Cloud Metadata**
- Access to `169.254.169.254` (AWS/GCP/Azure)
- Internal service discovery
- Kubernetes API access

**Indicators:**
- `requests.get(user_url)` without validation
- Webhook registration accepting any URL
- PDF generation from user-supplied HTML/URLs
- No URL allowlist/denylist

### 8. SECURITY MISCONFIGURATION (API8:2023)

API infrastructure and configuration issues.

**CORS Misconfiguration**
- `Access-Control-Allow-Origin: *`
- Credentials allowed with wildcard origin
- Overly permissive headers

**Error Handling**
- Stack traces in responses
- Database errors exposed
- Internal paths revealed

**Missing Headers**
- No `X-Content-Type-Options`
- Missing CSP for API docs
- No HSTS

**Indicators:**
- `CORS(app, origins="*")`
- `DEBUG=True` in production
- `catch(e) { return res.json({error: e.stack}) }`
- Missing security headers in responses

### 9. IMPROPER INVENTORY MANAGEMENT (API9:2023)

Outdated or undocumented APIs that lack security controls.

**Shadow APIs**
- Old versions still running
- Development endpoints in production
- Undocumented admin APIs
- Beta features without auth

**Documentation Gaps**
- OpenAPI spec incomplete
- Endpoints not in API gateway
- Inconsistent versioning

**Indicators:**
- `/api/v1/` and `/api/v2/` both active
- `/__debug__/` or `/test/` endpoints
- APIs not registered in gateway
- Different auth on different versions

### 10. UNSAFE CONSUMPTION OF APIs (API10:2023)

Vulnerabilities from trusting third-party APIs.

**Injection via Upstream**
- Third-party data used in SQL
- Webhook payloads not validated
- OAuth provider data trusted blindly

**Transport Security**
- HTTP to third-party APIs
- No certificate validation
- Secrets in URLs to external services

**Indicators:**
- `requests.get(url, verify=False)`
- External API response used in query
- No schema validation on webhooks
- HTTP URLs for external services

## GraphQL-Specific Threats

### Introspection Enabled
```graphql
{ __schema { types { name fields { name } } } }
```
**Risk:** Full schema disclosure in production

### Nested Query Attack
```graphql
{ user { posts { comments { author { posts { comments ... } } } } } }
```
**Risk:** DoS via exponential query complexity

### Batching Attack
```graphql
[
  { query: "{ user(id:1) { password } }" },
  { query: "{ user(id:2) { password } }" },
  ... (1000 times)
]
```
**Risk:** Bypass rate limiting with single request

## Mapping to STRIDE

| STRIDE Category | API Manifestation |
|-----------------|-------------------|
| **Spoofing** | JWT forgery, API key theft, OAuth hijacking |
| **Tampering** | Mass assignment, request body manipulation |
| **Repudiation** | Missing audit logs, unsigned requests |
| **Info Disclosure** | Excessive data exposure, verbose errors |
| **Denial of Service** | No rate limiting, query complexity attacks |
| **Elevation of Privilege** | BOLA, BFLA, broken auth |

## Threat Identification Workflow

### Phase 1: API Discovery
1. Collect OpenAPI/Swagger specs
2. Map all endpoints from source code
3. Identify authentication mechanisms
4. Document request/response schemas

### Phase 2: Authorization Analysis
1. Map resources to ownership rules
2. Check object-level authorization
3. Verify function-level authorization
4. Test for mass assignment

### Phase 3: Apply OWASP API Top 10
For each endpoint:
- Check against all 10 categories
- Consider authentication context
- Test with different user roles

## Output Format

Generate threats with API-specific fields:

```json
{
  "id": "THREAT-XXX",
  "category": "Elevation of Privilege",
  "title": "BOLA on Order Endpoint",
  "description": "Order endpoint returns any order by ID without ownership check",
  "severity": "high",
  "affected_components": ["/api/orders/{id}", "OrderController"],
  "attack_scenario": "User A accesses User B's order by changing ID",
  "api_category": "API1:2023 BOLA",
  "http_method": "GET",
  "endpoint": "/api/orders/{order_id}",
  "vulnerability_types": ["CWE-639", "CWE-284"],
  "mitigation": "Add ownership check: Order.query.filter_by(id=order_id, user_id=current_user.id)"
}
```

## Examples

### BOLA Example
```
Endpoint: GET /api/invoices/{invoice_id}
Auth: Bearer token for user_123
Request: GET /api/invoices/456  (belongs to user_456)
Response: 200 OK with invoice_456 data
Threat: Any authenticated user can access any invoice
```

### Mass Assignment Example
```
Endpoint: PUT /api/users/{id}
Normal: {"name": "John", "email": "john@example.com"}
Attack: {"name": "John", "email": "john@example.com", "role": "admin"}
Risk: User self-promotes to admin role
```

### Rate Limiting Gap
```
Endpoint: POST /api/auth/login
No rate limiting → Brute force 10000 passwords/minute
Threat: Account takeover via credential stuffing
```

## Safety Notes

When threat modeling APIs:
- Test with minimum privilege tokens first
- Document all authorization boundaries
- Check both REST and GraphQL if both exist
- Verify rate limits with actual requests
- Consider mobile/web/service clients separately

