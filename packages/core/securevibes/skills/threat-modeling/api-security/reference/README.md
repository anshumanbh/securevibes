# API Security Threat Modeling Reference

Reference materials for API security threat modeling.

## OWASP API Security Top 10 (2023)

| Rank | Category | Description |
|------|----------|-------------|
| API1 | Broken Object Level Authorization | Manipulating object IDs to access others' data |
| API2 | Broken Authentication | Weak auth mechanisms allowing impersonation |
| API3 | Broken Object Property Level Authorization | Mass assignment and excessive data exposure |
| API4 | Unrestricted Resource Consumption | Missing rate limits and pagination |
| API5 | Broken Function Level Authorization | Admin functions accessible to users |
| API6 | Unrestricted Access to Sensitive Business Flows | Automatable abuse of business logic |
| API7 | Server Side Request Forgery | Making server request internal resources |
| API8 | Security Misconfiguration | CORS, headers, error handling |
| API9 | Improper Inventory Management | Shadow APIs and outdated versions |
| API10 | Unsafe Consumption of APIs | Trusting third-party API data |

## Common Vulnerable Patterns

### Python/Flask

```python
# BOLA - Missing ownership check
@app.route('/api/orders/<id>')
def get_order(id):
    return Order.query.get(id).to_dict()  # BAD

# Fixed
@app.route('/api/orders/<id>')
def get_order(id):
    order = Order.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    return order.to_dict()
```

### Node.js/Express

```javascript
// Mass assignment
app.put('/api/users/:id', (req, res) => {
  User.findByIdAndUpdate(req.params.id, req.body);  // BAD
});

// Fixed
const allowedFields = ['name', 'email', 'phone'];
app.put('/api/users/:id', (req, res) => {
  const updates = _.pick(req.body, allowedFields);
  User.findByIdAndUpdate(req.params.id, updates);
});
```

## JWT Security Checklist

- [ ] Algorithm explicitly set (no 'none' accepted)
- [ ] Signature verified on every request
- [ ] Short expiration time (15 min access, 7 day refresh)
- [ ] Token blacklist on logout
- [ ] Sensitive data not in payload
- [ ] Secret key is strong (256+ bits)
- [ ] HTTPS only transmission

## GraphQL Security Checklist

- [ ] Introspection disabled in production
- [ ] Query depth limiting (max 10-15)
- [ ] Query complexity analysis
- [ ] Batching limits
- [ ] Rate limiting per operation
- [ ] Authorization on every resolver
- [ ] Input validation on arguments

## Rate Limiting Best Practices

```
# Authentication endpoints (strict)
/api/auth/login: 5/minute per IP, 20/hour per account
/api/auth/register: 3/hour per IP
/api/auth/forgot-password: 3/hour per email

# API endpoints (normal)
/api/*: 100/minute per user, 1000/minute per IP

# Expensive operations
/api/export: 5/hour per user
/api/search: 60/minute per user
```

## CORS Configuration Examples

### Secure Configuration
```python
# Flask
CORS(app, 
     origins=['https://app.company.com', 'https://admin.company.com'],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'PUT', 'DELETE'])
```

```javascript
// Express
app.use(cors({
  origin: ['https://app.company.com'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));
```

### Vulnerable Patterns to Avoid
```python
# NEVER do this
CORS(app, origins="*", supports_credentials=True)

# Or this
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')  # Reflects any origin!
    return response
```

## API Security Headers

```http
# Required headers
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cache-Control: no-store
Content-Type: application/json

# Recommended headers
Strict-Transport-Security: max-age=31536000
X-Request-ID: <unique-id>  # For tracing

# Rate limit headers
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1609459200
```

## Testing Checklist

1. **Authentication**
   - [ ] Test with no token
   - [ ] Test with expired token
   - [ ] Test with modified token
   - [ ] Test token reuse after logout

2. **Authorization**
   - [ ] Access resources of other users
   - [ ] Access admin endpoints as user
   - [ ] Modify protected fields

3. **Input Validation**
   - [ ] SQL injection in all parameters
   - [ ] XSS in stored data
   - [ ] Integer overflow/underflow

4. **Rate Limiting**
   - [ ] Brute force login
   - [ ] API enumeration
   - [ ] Resource exhaustion

