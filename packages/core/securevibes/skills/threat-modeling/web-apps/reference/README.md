# Web Application Threat Modeling Reference

This directory contains reference materials for web application threat modeling.

## Files

- `owasp_mapping.md` - Detailed OWASP Top 10 to CWE mapping
- `attack_patterns.md` - Common attack patterns and payloads

## Quick Reference

### OWASP Top 10 (2021)

| Rank | Category | Common CWEs |
|------|----------|-------------|
| A01 | Broken Access Control | CWE-22, CWE-23, CWE-35, CWE-59, CWE-200, CWE-201, CWE-219, CWE-264, CWE-275, CWE-276, CWE-284, CWE-285, CWE-352, CWE-359, CWE-377, CWE-402, CWE-425, CWE-441, CWE-497, CWE-538, CWE-540, CWE-548, CWE-552, CWE-566, CWE-601, CWE-639, CWE-651, CWE-668, CWE-706, CWE-862, CWE-863, CWE-913, CWE-922, CWE-1275 |
| A02 | Cryptographic Failures | CWE-261, CWE-296, CWE-310, CWE-319, CWE-321, CWE-322, CWE-323, CWE-324, CWE-325, CWE-326, CWE-327, CWE-328, CWE-329, CWE-330, CWE-331, CWE-335, CWE-336, CWE-337, CWE-338, CWE-340, CWE-347, CWE-523, CWE-720, CWE-757, CWE-759, CWE-760, CWE-780, CWE-818, CWE-916 |
| A03 | Injection | CWE-20, CWE-74, CWE-75, CWE-77, CWE-78, CWE-79, CWE-80, CWE-83, CWE-87, CWE-88, CWE-89, CWE-90, CWE-91, CWE-93, CWE-94, CWE-95, CWE-96, CWE-97, CWE-98, CWE-99, CWE-100, CWE-113, CWE-116, CWE-138, CWE-184, CWE-470, CWE-471, CWE-564, CWE-610, CWE-643, CWE-644, CWE-652, CWE-917 |
| A04 | Insecure Design | CWE-73, CWE-183, CWE-209, CWE-213, CWE-235, CWE-256, CWE-257, CWE-266, CWE-269, CWE-280, CWE-311, CWE-312, CWE-313, CWE-316, CWE-419, CWE-430, CWE-434, CWE-444, CWE-451, CWE-472, CWE-501, CWE-522, CWE-525, CWE-539, CWE-579, CWE-598, CWE-602, CWE-642, CWE-646, CWE-650, CWE-653, CWE-656, CWE-657, CWE-799, CWE-807, CWE-840, CWE-841, CWE-927, CWE-1021, CWE-1173 |
| A05 | Security Misconfiguration | CWE-2, CWE-11, CWE-13, CWE-15, CWE-16, CWE-260, CWE-315, CWE-520, CWE-526, CWE-537, CWE-541, CWE-547, CWE-611, CWE-614, CWE-756, CWE-776, CWE-942, CWE-1004, CWE-1032, CWE-1174 |
| A06 | Vulnerable Components | CWE-937, CWE-1035, CWE-1104 |
| A07 | Auth Failures | CWE-255, CWE-259, CWE-287, CWE-288, CWE-290, CWE-294, CWE-295, CWE-297, CWE-300, CWE-302, CWE-304, CWE-306, CWE-307, CWE-346, CWE-384, CWE-521, CWE-613, CWE-620, CWE-640, CWE-798, CWE-940, CWE-1216 |
| A08 | Software/Data Integrity | CWE-345, CWE-353, CWE-426, CWE-494, CWE-502, CWE-565, CWE-784, CWE-829, CWE-830, CWE-915 |
| A09 | Logging Failures | CWE-117, CWE-223, CWE-532, CWE-778 |
| A10 | SSRF | CWE-918 |

### Security Headers Checklist

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### Common Vulnerable Patterns

**Python/Flask:**
```python
# BAD
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
render_template_string(user_input)
pickle.loads(user_data)

# GOOD
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
render_template('template.html', data=user_input)
json.loads(user_data)
```

**JavaScript/Node:**
```javascript
// BAD
eval(userInput)
element.innerHTML = userInput
db.query(`SELECT * FROM users WHERE id = ${userId}`)

// GOOD
JSON.parse(userInput)
element.textContent = userInput
db.query('SELECT * FROM users WHERE id = $1', [userId])
```

## Usage

When threat modeling web applications:

1. **Identify the stack** - What framework, database, auth mechanism?
2. **Map entry points** - All routes, forms, APIs, file uploads
3. **Trace data flows** - Input → processing → storage → output
4. **Check OWASP Top 10** - Systematically verify each category
5. **Consider attack chains** - How can vulns be combined?

