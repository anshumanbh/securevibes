# SSRF Testing Reference Implementations

These files are examples to read and adapt — not runnable drop-in scripts.

## Files

### ssrf_payloads.py
Payload generators for SSRF testing:
- **get_localhost_payloads()**: All localhost/127.0.0.1 bypass variants
- **get_cloud_metadata_payloads(provider)**: AWS, GCP, Azure, DigitalOcean, Alibaba, Oracle
- **get_ip_encoding_payloads(ip)**: Decimal, hex, octal, IPv6 representations
- **get_protocol_payloads()**: file://, gopher://, dict://, ldap://
- **get_dns_rebinding_payloads(target_ip)**: DNS rebinding service URLs
- **get_url_parser_confusion_payloads()**: @, #, \ bypass techniques

Usage:
```python
from ssrf_payloads import get_localhost_payloads, get_cloud_metadata_payloads

for payload in get_localhost_payloads():
    response = requests.post(f"{target}/api/fetch", json={"url": payload})
    
for payload in get_cloud_metadata_payloads("aws"):
    response = requests.post(f"{target}/api/fetch", json={"url": payload})
```

### validate_ssrf.py
Complete SSRF testing pattern illustrating:
- Baseline establishment
- Payload iteration with bypass techniques
- Response analysis for internal content indicators
- Classification logic (VALIDATED/FALSE_POSITIVE/PARTIAL/UNVALIDATED)
- Evidence capture with redaction
- OOB callback integration

Usage guidance:
- Identify the application's URL fetching endpoints
- Adapt payloads for specific injection points
- Set up OOB callback service for blind SSRF detection
- Capture evidence with proper redaction

## Important

Do not run these files unchanged; each application requires tailored logic. These are reference implementations to guide your testing approach.

## Cloud Provider Detection

When testing cloud metadata, check for these indicators in responses:

| Provider | Response Indicators |
|----------|-------------------|
| AWS | `ami-id`, `instance-id`, `AccessKeyId`, `SecretAccessKey` |
| GCP | `access_token`, `service-accounts`, `project-id` |
| Azure | `subscriptionId`, `resourceGroupName`, `vmId` |
| DigitalOcean | `droplet_id`, `hostname`, `region` |

## Safety Reminders

- Always redact credentials in evidence files
- Use INFO/GET commands, never destructive operations
- Respect scope limitations (--target-url only)
- Stop immediately if unintended access occurs

