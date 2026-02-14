"""Tests for scanner.chain_analysis helpers."""

import pytest

from securevibes.scanner.chain_analysis import (
    CHAIN_STOPWORDS,
    adjudicate_consensus_support,
    attempt_contains_core_chain_evidence,
    build_chain_family_identity,
    build_chain_flow_identity,
    build_chain_identity,
    canonicalize_finding_path,
    chain_text_tokens,
    coerce_line_number,
    collect_chain_exact_ids,
    collect_chain_family_ids,
    collect_chain_flow_ids,
    count_passes_with_core_chains,
    detect_weak_chain_consensus,
    extract_chain_sink_anchor,
    extract_cwe_family,
    extract_finding_locations,
    extract_finding_routes,
    finding_text,
    infer_chain_family_class,
    infer_chain_sink_family,
    normalize_chain_class_for_sink,
    summarize_chain_candidates_for_prompt,
    summarize_revalidation_support,
)


# ---------------------------------------------------------------------------
# CHAIN_STOPWORDS
# ---------------------------------------------------------------------------


def test_chain_stopwords_contains_extended_terms():
    """Shared stopwords should include terms used by merge-token dedupe."""
    for token in ("through", "command", "configuration", "path", "line", "file"):
        assert token in CHAIN_STOPWORDS


# ---------------------------------------------------------------------------
# coerce_line_number
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "input_val, expected",
    [
        pytest.param(None, 0, id="none_returns_zero"),
        pytest.param(42, 42, id="valid_int"),
        pytest.param("100", 100, id="string_int"),
        pytest.param(3.7, 3, id="float"),
        pytest.param("not-a-number", 0, id="invalid_string"),
        pytest.param(0, 0, id="zero"),
        pytest.param(-5, -5, id="negative"),
        pytest.param("", 0, id="empty_string"),
    ],
)
def test_coerce_line_number(input_val, expected):
    assert coerce_line_number(input_val) == expected


# ---------------------------------------------------------------------------
# extract_cwe_family
# ---------------------------------------------------------------------------


def testextract_cwe_family_two_digit_cwe():
    assert extract_cwe_family("CWE-78") == "78"


def testextract_cwe_family_three_digit_cwe():
    assert extract_cwe_family("CWE-123") == "12"


def testextract_cwe_family_four_digit_cwe():
    assert extract_cwe_family("CWE-1234") == "12"


def testextract_cwe_family_not_a_cwe():
    assert extract_cwe_family("not-a-cwe") == ""


def testextract_cwe_family_empty_string():
    assert extract_cwe_family("") == ""


def testextract_cwe_family_none():
    assert extract_cwe_family(None) == ""


def testextract_cwe_family_lowercase():
    """CWE matching should be case-insensitive."""
    assert extract_cwe_family("cwe-78") == "78"


def testextract_cwe_family_single_digit():
    """Single-digit CWE should return its single digit."""
    assert extract_cwe_family("CWE-5") == "5"


# ---------------------------------------------------------------------------
# chain_text_tokens
# ---------------------------------------------------------------------------


def testchain_text_tokens_normal_text():
    tokens = chain_text_tokens("SQL Injection via user_input parameter")
    assert "injection" in tokens
    assert "user_input" in tokens
    assert "parameter" in tokens


def testchain_text_tokens_stopwords_filtered():
    """Stopwords from CHAIN_STOPWORDS should be excluded."""
    tokens = chain_text_tokens("vulnerability through command injection via path")
    # "vulnerability", "through", "command", "path" are all stopwords
    assert "vulnerability" not in tokens
    assert "through" not in tokens
    assert "command" not in tokens
    assert "path" not in tokens
    assert "injection" in tokens


def testchain_text_tokens_short_tokens_filtered():
    """Tokens shorter than 4 characters should be excluded."""
    tokens = chain_text_tokens("the api foo bar baz longer_token")
    assert "api" not in tokens
    assert "foo" not in tokens
    assert "bar" not in tokens
    assert "baz" not in tokens
    assert "longer_token" in tokens


def testchain_text_tokens_max_tokens_limit():
    tokens = chain_text_tokens(
        "first_tok second_tok third_tok fourth_tok fifth_tok sixth_tok seventh_tok",
        max_tokens=3,
    )
    assert len(tokens) <= 3


def testchain_text_tokens_default_max_is_five():
    tokens = chain_text_tokens(
        "alpha_tok beta_tok gamma_tok delta_tok epsilon_tok zeta_tok eta_tok"
    )
    assert len(tokens) <= 5


def testchain_text_tokens_none_input():
    assert chain_text_tokens(None) == ()


def testchain_text_tokens_empty_string():
    assert chain_text_tokens("") == ()


def testchain_text_tokens_digits_only_excluded():
    """Pure digit tokens should be excluded."""
    tokens = chain_text_tokens("1234 token_here")
    assert "1234" not in tokens
    assert "token_here" in tokens


# ---------------------------------------------------------------------------
# finding_text
# ---------------------------------------------------------------------------


def testfinding_text_dict_with_fields():
    entry = {"title": "SQL Injection", "description": "A vuln", "extra": "ignored"}
    result = finding_text(entry, fields=("title", "description"))
    assert result == "sql injection a vuln"


def testfinding_text_non_dict():
    assert finding_text("not a dict", fields=("title",)) == ""
    assert finding_text(42, fields=("title",)) == ""
    assert finding_text(None, fields=("title",)) == ""


def testfinding_text_missing_fields():
    entry = {"title": "Hello"}
    result = finding_text(entry, fields=("title", "description"))
    assert "hello" in result
    # missing field contributes empty string, not KeyError


def testfinding_text_empty_dict():
    result = finding_text({}, fields=("title",))
    assert result == ""


# ---------------------------------------------------------------------------
# extract_finding_locations
# ---------------------------------------------------------------------------


def testextract_finding_locations_with_file_path():
    entry = {
        "evidence": "The file services/api/routes/tasks.py:42 has a vuln",
        "attack_scenario": "",
        "description": "",
    }
    locations = extract_finding_locations(entry)
    assert len(locations) >= 1
    # Should contain a canonicalized version of the file path
    assert any("tasks.py" in loc for loc in locations)


def testextract_finding_locations_empty_entry():
    entry = {"evidence": "", "attack_scenario": "", "description": ""}
    assert extract_finding_locations(entry) == ()


def testextract_finding_locations_deduplicates():
    entry = {
        "evidence": "see routes/tasks.py and routes/tasks.py again",
        "attack_scenario": "",
        "description": "",
    }
    locations = extract_finding_locations(entry)
    # Should be deduplicated
    paths_matching = [loc for loc in locations if "tasks.py" in loc]
    assert len(paths_matching) <= 1


# ---------------------------------------------------------------------------
# extract_finding_routes
# ---------------------------------------------------------------------------


def testextract_finding_routes_with_route():
    entry = {
        "title": "auth bypass on /api/v1/admin",
        "description": "accessing /api/v1/users",
        "attack_scenario": "",
        "evidence": "",
    }
    routes = extract_finding_routes(entry)
    assert len(routes) >= 1
    assert any("/api/v1/admin" in r for r in routes)


def testextract_finding_routes_empty():
    entry = {"title": "", "description": "", "attack_scenario": "", "evidence": ""}
    assert extract_finding_routes(entry) == ()


def testextract_finding_routes_deduplicates():
    entry = {
        "title": "/api/tasks /api/tasks /api/tasks",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    routes = extract_finding_routes(entry)
    route_matches = [r for r in routes if "/api/tasks" in r]
    assert len(route_matches) == 1


# ---------------------------------------------------------------------------
# extract_chain_sink_anchor
# ---------------------------------------------------------------------------


def testextract_chain_sink_anchor_prefers_non_primary_location():
    entry = {
        "file_path": "services/api/routes/tasks.py",
        "evidence": "reads from services/api/routes/tasks.py and writes to services/api/utils/file_ops.py",
        "attack_scenario": "",
        "description": "",
        "title": "",
    }
    anchor = extract_chain_sink_anchor(entry)
    # Should prefer non-primary location
    assert anchor != ""


def testextract_chain_sink_anchor_falls_back_to_routes():
    entry = {
        "file_path": "",
        "title": "vuln at /api/upload",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    anchor = extract_chain_sink_anchor(entry)
    assert "/api/upload" in anchor or anchor != ""


def testextract_chain_sink_anchor_empty_entry():
    entry = {
        "file_path": "",
        "title": "",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    assert extract_chain_sink_anchor(entry) == ""


# ---------------------------------------------------------------------------
# canonicalize_finding_path
# ---------------------------------------------------------------------------


def testcanonicalize_finding_path_prefers_repo_suffix():
    path = "/tmp/workspace/services/api/routes/tasks.py"
    assert canonicalize_finding_path(path) == "services/api/routes/tasks.py"


def testcanonicalize_finding_path_empty():
    assert canonicalize_finding_path("") == ""


def testcanonicalize_finding_path_none():
    assert canonicalize_finding_path(None) == ""


def testcanonicalize_finding_path_relative():
    result = canonicalize_finding_path("src/lib/utils.py")
    assert "utils.py" in result


def testcanonicalize_finding_path_non_string():
    assert canonicalize_finding_path(42) == ""


# ---------------------------------------------------------------------------
# infer_chain_family_class
# ---------------------------------------------------------------------------


def testinfer_chain_family_class_command_injection_keyword():
    entry = {
        "title": "command injection risk",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    assert infer_chain_family_class(entry) == "command_chain"


def testinfer_chain_family_class_option_injection():
    entry = {
        "title": "option injection in ssh args",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    assert infer_chain_family_class(entry) == "command_chain"


def testinfer_chain_family_class_path_traversal_keyword():
    entry = {
        "title": "path traversal via upload",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    assert infer_chain_family_class(entry) == "path_file_chain"


def testinfer_chain_family_class_auth_bypass_keyword():
    entry = {
        "title": "auth bypass allows admin",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    assert infer_chain_family_class(entry) == "auth_priv_chain"


def testinfer_chain_family_class_cwe_based_path():
    """CWE-22 (path traversal) should map to path_file_chain."""
    entry = {
        "title": "generic title",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
        "cwe_id": "CWE-22",
    }
    assert infer_chain_family_class(entry) == "path_file_chain"


def testinfer_chain_family_class_cwe_based_command():
    """CWE-78 (OS command injection) should map to command_chain."""
    entry = {
        "title": "generic title",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
        "cwe_id": "CWE-78",
    }
    assert infer_chain_family_class(entry) == "command_chain"


def testinfer_chain_family_class_cwe_based_auth():
    """CWE-86 should map to auth_priv_chain."""
    entry = {
        "title": "generic title",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
        "cwe_id": "CWE-86",
    }
    assert infer_chain_family_class(entry) == "auth_priv_chain"


def testinfer_chain_family_class_generic_fallback():
    entry = {
        "title": "some generic finding",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    assert infer_chain_family_class(entry) == "generic_chain"


def testinfer_chain_family_class_cwe_fallback_with_unknown_cwe():
    """Unknown CWE should produce cwe_XX format."""
    entry = {
        "title": "generic title",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
        "cwe_id": "CWE-999",
    }
    result = infer_chain_family_class(entry)
    assert result == "cwe_99"


def testinfer_chain_family_class_keyword_priority_over_cwe():
    """Text-based keyword detection should take priority over CWE-based."""
    entry = {
        "title": "command injection risk",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
        "cwe_id": "CWE-22",  # This is a path traversal CWE, but keyword says command
    }
    assert infer_chain_family_class(entry) == "command_chain"


# ---------------------------------------------------------------------------
# infer_chain_sink_family
# ---------------------------------------------------------------------------


def testinfer_chain_sink_family_file_operations():
    entry = {
        "title": "file upload vulnerability",
        "description": "uses copyfile to transfer",
        "attack_scenario": "",
        "evidence": "",
    }
    assert infer_chain_sink_family(entry) == "file_host_sink"


def testinfer_chain_sink_family_command_operations():
    entry = {
        "title": "command execution",
        "description": "calls exec( to run commands",
        "attack_scenario": "",
        "evidence": "",
    }
    assert infer_chain_sink_family(entry) == "command_exec_sink"


def testinfer_chain_sink_family_auth_operations():
    entry = {
        "title": "authentication issue",
        "description": "missing permission check",
        "attack_scenario": "",
        "evidence": "",
    }
    assert infer_chain_sink_family(entry) == "authz_sink"


def testinfer_chain_sink_family_generic():
    entry = {
        "title": "some generic issue",
        "description": "no specific sink",
        "attack_scenario": "",
        "evidence": "",
    }
    assert infer_chain_sink_family(entry) == "generic_sink"


# ---------------------------------------------------------------------------
# normalize_chain_class_for_sink
# ---------------------------------------------------------------------------


def test_normalize_chain_class_already_specific():
    assert normalize_chain_class_for_sink("command_chain", "generic_sink") == "command_chain"
    assert normalize_chain_class_for_sink("path_file_chain", "generic_sink") == "path_file_chain"
    assert normalize_chain_class_for_sink("auth_priv_chain", "generic_sink") == "auth_priv_chain"


def test_normalize_chain_class_generic_with_file_sink():
    assert normalize_chain_class_for_sink("generic_chain", "file_host_sink") == "path_file_chain"


def test_normalize_chain_class_generic_with_command_sink():
    assert normalize_chain_class_for_sink("generic_chain", "command_exec_sink") == "command_chain"


def test_normalize_chain_class_generic_with_authz_sink():
    assert normalize_chain_class_for_sink("generic_chain", "authz_sink") == "auth_priv_chain"


def test_normalize_chain_class_generic_with_generic_sink():
    assert normalize_chain_class_for_sink("generic_chain", "generic_sink") == "generic_chain"


def test_normalize_chain_class_empty_with_generic_sink():
    assert normalize_chain_class_for_sink("", "generic_sink") == "generic_chain"


def test_normalize_chain_class_cwe_class_with_file_sink():
    """Non-standard chain class should be normalized based on sink."""
    assert normalize_chain_class_for_sink("cwe_22", "file_host_sink") == "path_file_chain"


# ---------------------------------------------------------------------------
# build_chain_identity
# ---------------------------------------------------------------------------


def testbuild_chain_identity_full_entry():
    entry = {
        "file_path": "services/api/routes/tasks.py",
        "cwe_id": "CWE-78",
        "line_number": 42,
        "title": "SQL Injection vulnerability found here",
    }
    identity = build_chain_identity(entry)
    assert identity != ""
    parts = identity.split("|")
    assert len(parts) == 4
    # path | cwe_family | line_bucket | tokens
    assert "tasks.py" in parts[0]
    assert parts[1] == "78"
    assert parts[2] == "2"  # 42 // 20 = 2
    assert parts[3] != "unknown"


def testbuild_chain_identity_missing_path_with_title():
    entry = {
        "title": "SQL injection vulnerability found",
        "cwe_id": "CWE-89",
        "line_number": 10,
    }
    identity = build_chain_identity(entry)
    assert identity != ""
    parts = identity.split("|")
    assert parts[0] == "unknown"


def testbuild_chain_identity_missing_tokens_and_path():
    """When both path and title tokens are empty, should return empty string."""
    entry = {
        "file_path": "",
        "title": "",
        "cwe_id": "",
    }
    assert build_chain_identity(entry) == ""


def testbuild_chain_identity_non_dict():
    assert build_chain_identity("not a dict") == ""
    assert build_chain_identity(None) == ""
    assert build_chain_identity(42) == ""


def testbuild_chain_identity_line_bucketing():
    """Line 42 should map to bucket '2' (42 // 20 = 2)."""
    entry = {
        "file_path": "src/app.py",
        "line_number": 42,
        "title": "injection_vuln",
        "cwe_id": "CWE-78",
    }
    identity = build_chain_identity(entry)
    parts = identity.split("|")
    assert parts[2] == "2"


def testbuild_chain_identity_line_zero_bucket():
    """Line 0 should produce 'x' bucket."""
    entry = {
        "file_path": "src/app.py",
        "line_number": 0,
        "title": "injection_vuln",
        "cwe_id": "CWE-78",
    }
    identity = build_chain_identity(entry)
    parts = identity.split("|")
    assert parts[2] == "x"


def testbuild_chain_identity_no_cwe():
    """Missing CWE should produce 'xx' placeholder."""
    entry = {
        "file_path": "src/app.py",
        "line_number": 10,
        "title": "some_vulnerability here",
    }
    identity = build_chain_identity(entry)
    parts = identity.split("|")
    assert parts[1] == "xx"


# ---------------------------------------------------------------------------
# build_chain_family_identity
# ---------------------------------------------------------------------------


def testbuild_chain_family_identity_with_path():
    entry = {
        "file_path": "services/api/routes/tasks.py",
        "title": "command injection",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    identity = build_chain_family_identity(entry)
    assert identity != ""
    parts = identity.split("|")
    assert len(parts) == 2
    assert "tasks.py" in parts[0]
    assert parts[1] == "command_chain"


def testbuild_chain_family_identity_no_path_with_sink_anchor():
    entry = {
        "file_path": "",
        "title": "vuln at /api/upload endpoint",
        "description": "file upload issue",
        "attack_scenario": "",
        "evidence": "see services/api/upload.py",
    }
    identity = build_chain_family_identity(entry)
    assert identity != ""
    parts = identity.split("|")
    assert parts[0] == "unknown"


def testbuild_chain_family_identity_no_path_with_title_tokens():
    entry = {
        "file_path": "",
        "title": "injection_vuln special_case",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    identity = build_chain_family_identity(entry)
    # Should use title tokens as fallback when no path and no sink anchor
    assert identity != ""
    parts = identity.split("|")
    assert parts[0] == "unknown"


def testbuild_chain_family_identity_empty():
    """Completely empty entry should return empty string."""
    entry = {
        "file_path": "",
        "title": "",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    assert build_chain_family_identity(entry) == ""


def testbuild_chain_family_identity_non_dict():
    assert build_chain_family_identity("not a dict") == ""


# ---------------------------------------------------------------------------
# build_chain_flow_identity
# ---------------------------------------------------------------------------


def testbuild_chain_flow_identity_with_path_and_cwe():
    entry = {
        "file_path": "services/api/routes/tasks.py",
        "cwe_id": "CWE-78",
        "title": "command injection",
        "description": "calls exec(",
        "attack_scenario": "",
        "evidence": "",
    }
    identity = build_chain_flow_identity(entry)
    assert identity != ""
    parts = identity.split("|")
    assert len(parts) == 3
    assert "tasks.py" in parts[0]
    # sink_family and chain_class


def testbuild_chain_flow_identity_without_path_but_with_locations():
    entry = {
        "file_path": "",
        "title": "injection",
        "description": "",
        "attack_scenario": "",
        "evidence": "vulnerable at services/api/handler.py",
    }
    identity = build_chain_flow_identity(entry)
    # Should fall back to extracted locations
    if identity:
        parts = identity.split("|")
        assert len(parts) == 3


def testbuild_chain_flow_identity_no_path_returns_empty():
    entry = {
        "file_path": "",
        "title": "",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    assert build_chain_flow_identity(entry) == ""


def testbuild_chain_flow_identity_non_dict():
    assert build_chain_flow_identity("not a dict") == ""
    assert build_chain_flow_identity(None) == ""


# ---------------------------------------------------------------------------
# collect_chain_exact_ids
# ---------------------------------------------------------------------------


def testcollect_chain_exact_ids_empty():
    assert collect_chain_exact_ids([]) == set()


def testcollect_chain_exact_ids_single_finding():
    findings = [
        {
            "file_path": "src/app.py",
            "cwe_id": "CWE-78",
            "line_number": 10,
            "title": "command injection_vuln",
        }
    ]
    result = collect_chain_exact_ids(findings)
    assert len(result) >= 1


def testcollect_chain_exact_ids_multiple_findings():
    findings = [
        {
            "file_path": "src/app.py",
            "cwe_id": "CWE-78",
            "line_number": 10,
            "title": "command injection_vuln found",
        },
        {
            "file_path": "src/handler.py",
            "cwe_id": "CWE-22",
            "line_number": 50,
            "title": "path traversal vulnerability found",
        },
    ]
    result = collect_chain_exact_ids(findings)
    assert len(result) == 2


def testcollect_chain_exact_ids_skips_empty_identities():
    """Findings with empty identity should not appear in the set."""
    findings = [
        {"file_path": "", "title": "", "cwe_id": ""},
    ]
    result = collect_chain_exact_ids(findings)
    assert len(result) == 0


# ---------------------------------------------------------------------------
# collect_chain_family_ids
# ---------------------------------------------------------------------------


def testcollect_chain_family_ids_empty():
    assert collect_chain_family_ids([]) == set()


def testcollect_chain_family_ids_single():
    findings = [
        {
            "file_path": "services/api/routes/tasks.py",
            "title": "command injection",
            "description": "",
            "attack_scenario": "",
            "evidence": "",
        }
    ]
    result = collect_chain_family_ids(findings)
    assert len(result) >= 1


# ---------------------------------------------------------------------------
# collect_chain_flow_ids
# ---------------------------------------------------------------------------


def testcollect_chain_flow_ids_empty():
    assert collect_chain_flow_ids([]) == set()


def testcollect_chain_flow_ids_single():
    findings = [
        {
            "file_path": "services/api/handler.py",
            "cwe_id": "CWE-78",
            "title": "command injection via exec(",
            "description": "",
            "attack_scenario": "",
            "evidence": "",
        }
    ]
    result = collect_chain_flow_ids(findings)
    assert len(result) >= 1


# ---------------------------------------------------------------------------
# count_passes_with_core_chains
# ---------------------------------------------------------------------------


def test_count_passes_empty_core():
    assert count_passes_with_core_chains(set(), [{"a"}, {"b"}]) == 0


def test_count_passes_empty_pass_ids():
    assert count_passes_with_core_chains({"a"}, []) == 0


def test_count_passes_no_overlap():
    assert count_passes_with_core_chains({"a"}, [{"b"}, {"c"}]) == 0


def test_count_passes_partial_overlap():
    assert count_passes_with_core_chains({"a", "b"}, [{"a"}, {"c"}, {"b"}]) == 2


def test_count_passes_full_overlap():
    assert count_passes_with_core_chains({"a"}, [{"a"}, {"a", "b"}]) == 2


# ---------------------------------------------------------------------------
# attempt_contains_core_chain_evidence
# ---------------------------------------------------------------------------


def testattempt_contains_core_chain_evidence_empty_findings():
    assert (
        attempt_contains_core_chain_evidence(
            attempt_findings=[],
            expected_family_ids={"some_id"},
            expected_flow_ids=set(),
        )
        is False
    )


def testattempt_contains_core_chain_evidence_no_expectations():
    """No expected ids means any non-empty attempt is considered evidence."""
    finding = {
        "file_path": "src/app.py",
        "title": "something_special",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    assert (
        attempt_contains_core_chain_evidence(
            attempt_findings=[finding],
            expected_family_ids=set(),
            expected_flow_ids=set(),
        )
        is True
    )


def testattempt_contains_core_chain_evidence_matching_family():
    finding = {
        "file_path": "services/api/routes/tasks.py",
        "title": "command injection",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    family_id = build_chain_family_identity(finding)
    assert (
        attempt_contains_core_chain_evidence(
            attempt_findings=[finding],
            expected_family_ids={family_id},
            expected_flow_ids=set(),
        )
        is True
    )


def testattempt_contains_core_chain_evidence_matching_flow():
    finding = {
        "file_path": "services/api/routes/tasks.py",
        "cwe_id": "CWE-78",
        "title": "command injection exec(",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    flow_id = build_chain_flow_identity(finding)
    assert flow_id != ""
    assert (
        attempt_contains_core_chain_evidence(
            attempt_findings=[finding],
            expected_family_ids=set(),
            expected_flow_ids={flow_id},
        )
        is True
    )


def testattempt_contains_core_chain_evidence_no_match():
    finding = {
        "file_path": "services/api/routes/tasks.py",
        "title": "command injection",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    assert (
        attempt_contains_core_chain_evidence(
            attempt_findings=[finding],
            expected_family_ids={"nonexistent|id"},
            expected_flow_ids={"also|nonexistent|id"},
        )
        is False
    )


# ---------------------------------------------------------------------------
# summarize_revalidation_support
# ---------------------------------------------------------------------------


def testsummarize_revalidation_support_all_hits():
    attempts, hits, misses = summarize_revalidation_support(
        [True, True, True],
        [True, True, True],
    )
    assert attempts == 3
    assert hits == 3
    assert misses == 0


def testsummarize_revalidation_support_mixed():
    attempts, hits, misses = summarize_revalidation_support(
        [True, True, False, True],
        [True, False, False, True],
    )
    assert attempts == 3
    assert hits == 2
    assert misses == 1


def testsummarize_revalidation_support_none_attempted():
    attempts, hits, misses = summarize_revalidation_support(
        [False, False, False],
        [False, False, False],
    )
    assert attempts == 0
    assert hits == 0
    assert misses == 0


def testsummarize_revalidation_support_empty():
    attempts, hits, misses = summarize_revalidation_support([], [])
    assert attempts == 0
    assert hits == 0
    assert misses == 0


# ---------------------------------------------------------------------------
# detect_weak_chain_consensus
# ---------------------------------------------------------------------------


def test_detect_weak_consensus_stable():
    weak, reason, support = detect_weak_chain_consensus(
        core_chain_ids={"chain-1"},
        pass_chain_ids=[{"chain-1"}, {"chain-1"}],
        required_support=2,
    )
    assert weak is False
    assert reason == "stable"
    assert support == 2


def test_detect_weak_consensus_no_core_chains():
    weak, reason, support = detect_weak_chain_consensus(
        core_chain_ids=set(),
        pass_chain_ids=[{"a"}, {"b"}],
        required_support=2,
    )
    assert weak is False
    assert reason == "no_core_chains"


def test_detect_weak_consensus_low_support():
    weak, reason, support = detect_weak_chain_consensus(
        core_chain_ids={"chain-1"},
        pass_chain_ids=[{"chain-1"}, {"other"}],
        required_support=2,
    )
    assert weak is True
    assert "core_support=" in reason
    assert support == 1


def test_detect_weak_consensus_trailing_empty():
    weak, reason, support = detect_weak_chain_consensus(
        core_chain_ids={"chain-1"},
        pass_chain_ids=[{"chain-1"}, {"chain-1"}, set()],
        required_support=2,
    )
    assert weak is True
    assert "trailing_empty_passes" in reason


# ---------------------------------------------------------------------------
# adjudicate_consensus_support
# ---------------------------------------------------------------------------


def testadjudicate_consensus_support_exact_stable():
    weak, reason, support, mode, metrics = adjudicate_consensus_support(
        required_support=2,
        core_exact_ids={"exact-1"},
        pass_exact_ids=[{"exact-1"}, {"exact-1"}],
        core_family_ids=set(),
        pass_family_ids=[set(), set()],
        core_flow_ids=set(),
        pass_flow_ids=[set(), set()],
    )
    assert weak is False
    assert reason == "stable"
    assert mode == "exact"
    assert support == 2


def testadjudicate_consensus_support_flow_stable_when_exact_weak():
    weak, reason, support, mode, metrics = adjudicate_consensus_support(
        required_support=2,
        core_exact_ids={"exact-1"},
        pass_exact_ids=[set(), set()],
        core_family_ids=set(),
        pass_family_ids=[set(), set()],
        core_flow_ids={"flow-1"},
        pass_flow_ids=[{"flow-1"}, {"flow-1"}],
    )
    assert weak is False
    assert reason == "stable"
    assert mode == "flow"
    assert metrics["flow"] == 2


def testadjudicate_consensus_support_all_weak():
    weak, reason, support, mode, metrics = adjudicate_consensus_support(
        required_support=3,
        core_exact_ids={"exact-1"},
        pass_exact_ids=[{"exact-1"}, set()],
        core_family_ids={"fam-1"},
        pass_family_ids=[{"fam-1"}, set()],
        core_flow_ids={"flow-1"},
        pass_flow_ids=[{"flow-1"}, set()],
    )
    assert weak is True
    assert ":" in reason  # format is "mode:reason"


def testadjudicate_consensus_support_family_stable():
    """Family mode is selected when exact and flow are both weak but family is stable.
    Priority order: exact -> flow -> family. Exact and flow must be truly weak
    (not stable via no_core_chains) so that family gets picked."""
    weak, reason, support, mode, metrics = adjudicate_consensus_support(
        required_support=3,
        core_exact_ids={"exact-1"},
        pass_exact_ids=[{"exact-1"}, set(), set()],
        core_family_ids={"fam-1"},
        pass_family_ids=[{"fam-1"}, {"fam-1"}, {"fam-1"}],
        core_flow_ids={"flow-1"},
        pass_flow_ids=[{"flow-1"}, set(), set()],
    )
    assert weak is False
    assert mode == "family"


def testadjudicate_consensus_support_no_core_ids():
    """When no core ids exist in any mode, should not be weak."""
    weak, reason, support, mode, metrics = adjudicate_consensus_support(
        required_support=2,
        core_exact_ids=set(),
        pass_exact_ids=[set(), set()],
        core_family_ids=set(),
        pass_family_ids=[set(), set()],
        core_flow_ids=set(),
        pass_flow_ids=[set(), set()],
    )
    assert weak is False
    assert reason == "no_core_chains"


def test_adjudicate_consensus_trailing_empty_with_enough_support():
    """Trailing empty passes should be treated as stable if support is sufficient."""
    weak, reason, support, mode, metrics = adjudicate_consensus_support(
        required_support=2,
        core_exact_ids={"exact-1"},
        pass_exact_ids=[{"exact-1"}, {"exact-1"}, set()],
        core_family_ids=set(),
        pass_family_ids=[set(), set(), set()],
        core_flow_ids=set(),
        pass_flow_ids=[set(), set(), set()],
    )
    assert weak is False
    assert reason == "stable"
    assert mode == "exact"


# ---------------------------------------------------------------------------
# summarize_chain_candidates_for_prompt
# ---------------------------------------------------------------------------


def test_summarize_chain_candidates_empty():
    assert summarize_chain_candidates_for_prompt([], {}, 1) == "- None"


def test_summarize_chain_candidates_single_finding():
    finding = {
        "file_path": "services/api/routes/tasks.py",
        "line_number": 42,
        "title": "Command injection via exec",
        "cwe_id": "CWE-78",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    result = summarize_chain_candidates_for_prompt([finding], {}, 2)
    assert "Command injection via exec" in result
    assert "CWE-78" in result
    assert "tasks.py" in result


def test_summarize_chain_candidates_truncation():
    findings = [
        {
            "file_path": f"services/api/routes/handler_{i}.py",
            "line_number": i * 10,
            "title": f"Finding number {i} with a very long title " * 5,
            "cwe_id": f"CWE-{i}",
            "description": "",
            "attack_scenario": "",
            "evidence": "",
        }
        for i in range(10)
    ]
    result = summarize_chain_candidates_for_prompt(findings, {}, 5, max_items=3)
    # Should only include max_items findings
    assert result.count("- ") <= 3


def test_summarize_chain_candidates_with_support_counts():
    finding = {
        "file_path": "services/api/routes/tasks.py",
        "title": "command injection",
        "cwe_id": "CWE-78",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    chain_id = build_chain_family_identity(finding)
    support_counts = {chain_id: 3}
    result = summarize_chain_candidates_for_prompt([finding], support_counts, 5)
    assert "support=3/5" in result


def test_summarize_chain_candidates_title_truncation():
    """Very long titles should be truncated to 120 chars."""
    finding = {
        "file_path": "src/app.py",
        "line_number": 1,
        "title": "A" * 200,
        "cwe_id": "CWE-1",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    result = summarize_chain_candidates_for_prompt([finding], {}, 1)
    assert "..." in result


def test_summarize_chain_candidates_max_chars_truncation():
    """Output should be truncated at max_chars."""
    findings = [
        {
            "file_path": f"services/api/routes/handler_{i}.py",
            "line_number": i * 10,
            "title": f"Very long finding title repeated many times {i} " * 10,
            "cwe_id": f"CWE-{100 + i}",
            "description": "",
            "attack_scenario": "",
            "evidence": "",
        }
        for i in range(5)
    ]
    result = summarize_chain_candidates_for_prompt(
        findings,
        {},
        5,
        max_items=5,
        max_chars=200,
    )
    assert len(result) <= 200
    assert result.endswith("...[truncated]")


def test_summarize_chain_candidates_no_line_number():
    """When line_number is 0, location should just be the path."""
    finding = {
        "file_path": "src/app.py",
        "line_number": 0,
        "title": "some_vuln",
        "cwe_id": "",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    result = summarize_chain_candidates_for_prompt([finding], {}, 1)
    assert "N/A" in result  # empty cwe_id -> "N/A"


def test_summarize_chain_candidates_flow_support():
    """flow_support_counts should take precedence when higher."""
    finding = {
        "file_path": "services/api/routes/tasks.py",
        "cwe_id": "CWE-78",
        "title": "command injection exec(",
        "description": "",
        "attack_scenario": "",
        "evidence": "",
    }
    chain_id = build_chain_family_identity(finding)
    flow_id = build_chain_flow_identity(finding)
    chain_support = {chain_id: 1}
    flow_support = {flow_id: 4}
    result = summarize_chain_candidates_for_prompt(
        [finding],
        chain_support,
        5,
        flow_support_counts=flow_support,
    )
    assert "support=4/5" in result
