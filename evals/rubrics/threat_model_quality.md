# Threat Model Quality Rubric

Use this rubric to evaluate the quality of STRIDE threat modeling output from SecureVibes.

## Scoring Scale (1-5)

### 5 - Excellent

The threat model demonstrates deep understanding of the application architecture:

- **Architecture-Grounded**: All threats are based on actual components discovered in the codebase
- **STRIDE Coverage**: Appropriate threats for each relevant STRIDE category
- **Realistic Scenarios**: Attack vectors describe plausible attack paths
- **Risk Calibration**: Likelihood and impact assessments are realistic, not all "CRITICAL"
- **Existing Controls**: Documents security controls already in place
- **Specific Mitigations**: Recommendations are specific to this application
- **ASI Coverage** (if agentic): Includes relevant OWASP ASI threats

### 4 - Good

The threat model is comprehensive and useful:

- Threats reference actual application components
- Most STRIDE categories addressed appropriately
- Attack scenarios are realistic
- Risk scoring is mostly reasonable
- Some existing controls noted
- Mitigations are helpful

### 3 - Adequate

The threat model covers the basics:

- Threats are generally relevant to the application type
- STRIDE coverage may be uneven (missing categories)
- Some threats feel generic rather than specific
- Risk scoring may be inconsistent
- Limited documentation of existing controls
- Mitigations are somewhat generic

### 2 - Poor

The threat model has significant gaps:

- Threats feel copy-pasted / not specific to this app
- Missing obvious STRIDE categories
- Attack scenarios are unrealistic or vague
- All threats rated CRITICAL regardless of actual risk
- No mention of existing controls
- Boilerplate mitigations

### 1 - Fail

The threat model is not useful:

- Threats don't match the application architecture
- Generic security checklist disguised as threat model
- Missing most STRIDE categories
- No realistic attack scenarios
- Completely wrong risk assessments

## STRIDE Category Guidance

When evaluating coverage, consider:

| Category | Should Include |
|----------|----------------|
| **Spoofing** | Authentication bypass, session hijacking, identity confusion |
| **Tampering** | Data modification, SQL injection, parameter manipulation |
| **Repudiation** | Missing audit logs, non-attributable actions |
| **Information Disclosure** | Data leaks, verbose errors, path traversal |
| **Denial of Service** | Resource exhaustion, crash vectors, rate limiting gaps |
| **Elevation of Privilege** | Authorization bypass, IDOR, privilege escalation |

## ASI Category Guidance (Agentic Applications)

For agentic applications, also check:

| Category | Should Include |
|----------|----------------|
| **ASI01** | Prompt injection, instruction override |
| **ASI02** | Sensitive data exposure to/from LLM |
| **ASI03** | Improper tool/API invocation |
| **ASI04** | Excessive agency, unauthorized actions |
| **ASI05** | Inadequate sandboxing |

## Common Deductions

- -1 point: Missing obvious STRIDE category
- -1 point: All threats rated same severity
- -1 point: Generic "implement security best practices" mitigations
- -2 points: Threats don't reference actual codebase components
- -2 points: Missing ASI threats for detected agentic application
