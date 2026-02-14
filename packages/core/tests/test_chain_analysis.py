"""Tests for scanner.chain_analysis helpers."""

from securevibes.scanner.chain_analysis import (
    CHAIN_STOPWORDS,
    _adjudicate_consensus_support,
    _canonicalize_finding_path,
)


def test_chain_stopwords_contains_extended_terms():
    """Shared stopwords should include terms used by merge-token dedupe."""
    for token in ("through", "command", "configuration", "path", "line", "file"):
        assert token in CHAIN_STOPWORDS


def test_canonicalize_finding_path_prefers_repo_suffix():
    """Absolute paths should be normalized to repo-style suffixes."""
    path = "/tmp/workspace/services/api/routes/tasks.py"
    assert _canonicalize_finding_path(path) == "services/api/routes/tasks.py"


def test_adjudicate_consensus_support_uses_flow_mode_when_exact_is_weak():
    """Flow support should stabilize consensus when exact support is absent."""
    weak, reason, support, mode, metrics = _adjudicate_consensus_support(
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
    assert support == 2
    assert mode == "flow"
    assert metrics["flow"] == 2
