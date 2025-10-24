# IDOR Testing Reference Implementations

These files are examples to read and adapt — not runnable drop-in scripts.

- validate_idor.py: Illustrates a simple IDOR testing pattern, including
  authentication, baseline vs. test requests, classification, and redaction.

Usage guidance:
- Identify the application’s auth mechanism and endpoints
- Adapt headers, payloads, and URLs accordingly
- Capture minimal, redacted evidence and hash full bodies
- Classify as VALIDATED, FALSE_POSITIVE, or UNVALIDATED

Do not run these files unchanged; each application requires tailored logic.
