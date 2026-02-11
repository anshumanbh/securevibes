"""Tests for prompt quality and false positive prevention guidance."""

import pytest
from pathlib import Path
from securevibes.prompts.loader import load_prompt, load_shared_rules


class TestSharedRulesInjection:
    """Test that shared rules are properly loaded and injected."""

    def test_shared_rules_file_exists(self):
        """Test _shared/security_rules.txt exists."""
        shared_file = (
            Path(__file__).parent.parent
            / "securevibes"
            / "prompts"
            / "agents"
            / "_shared"
            / "security_rules.txt"
        )
        assert shared_file.exists(), "Missing shared security_rules.txt"

    def test_shared_rules_has_critical_rules(self):
        """Test shared rules has critical_rules section."""
        content = load_shared_rules()
        assert content is not None, "Failed to load shared rules"
        assert "<critical_rules>" in content, "Missing critical_rules section"
        assert "</critical_rules>" in content, "Missing closing tag"

    def test_shared_rules_has_false_positive_prevention(self):
        """Test shared rules has false_positive_prevention section."""
        content = load_shared_rules()
        assert content is not None, "Failed to load shared rules"
        assert "<false_positive_prevention>" in content, "Missing false_positive_prevention section"
        assert "</false_positive_prevention>" in content, "Missing closing tag"

    def test_threat_modeling_gets_shared_rules_injected(self):
        """Test threat_modeling prompt gets shared rules injected."""
        content = load_prompt("threat_modeling", category="agents")
        assert "<critical_rules>" in content, "Shared rules not injected into threat_modeling"
        assert "<false_positive_prevention>" in content, "False positive prevention not injected"

    def test_code_review_gets_shared_rules_injected(self):
        """Test code_review prompt gets shared rules injected."""
        content = load_prompt("code_review", category="agents")
        assert "<critical_rules>" in content, "Shared rules not injected into code_review"
        assert "<false_positive_prevention>" in content, "False positive prevention not injected"

    def test_non_security_agents_dont_get_injection(self):
        """Test non-security agents don't get shared rules injected."""
        content = load_prompt("assessment", category="agents")
        assert (
            "<false_positive_prevention>" not in content
        ), "Assessment should not have FP prevention"

    def test_can_disable_injection(self):
        """Test injection can be disabled via parameter."""
        content = load_prompt("threat_modeling", category="agents", inject_shared=False)
        assert "<false_positive_prevention>" not in content
        # The raw file should NOT have false_positive_prevention (it's in shared)
        raw_file = (
            Path(__file__).parent.parent
            / "securevibes"
            / "prompts"
            / "agents"
            / "threat_modeling.txt"
        )
        raw_content = raw_file.read_text()
        assert (
            "<false_positive_prevention>" not in raw_content
        ), "Raw file should not have FP section"

    def test_injection_preserves_role_line(self):
        """Test that shared rules are injected AFTER the role line."""
        content = load_prompt("threat_modeling", category="agents")
        lines = content.split("\n")
        # First line should be the role definition
        assert lines[0].startswith("You are a threat modeling expert"), "Role line should be first"
        # Shared rules should come after
        critical_rules_line = next(i for i, line in enumerate(lines) if "<critical_rules>" in line)
        assert critical_rules_line > 0, "Shared rules should be after role line"

    def test_load_all_agent_prompts_includes_injected_content(self):
        """Test load_all_agent_prompts() returns prompts with shared rules injected."""
        from securevibes.prompts.loader import load_all_agent_prompts

        prompts = load_all_agent_prompts()

        # Security agents should have shared false_positive_prevention (unique to shared rules)
        assert (
            "<false_positive_prevention>" in prompts["threat_modeling"]
        ), "threat_modeling should have injected false_positive_prevention"
        assert (
            "<false_positive_prevention>" in prompts["code_review"]
        ), "code_review should have injected false_positive_prevention"

        # Non-security agents should NOT have false_positive_prevention
        assert (
            "<false_positive_prevention>" not in prompts["assessment"]
        ), "assessment should not have injected false_positive_prevention"
        assert (
            "<false_positive_prevention>" not in prompts["report_generator"]
        ), "report_generator should not have injected false_positive_prevention"


class TestFalsePositivePreventionGuidance:
    """Test that prompts include false positive prevention guidance (via injection)."""

    def test_threat_modeling_has_false_positive_prevention(self):
        """Test threat_modeling prompt has false positive prevention section (injected)."""
        content = load_prompt("threat_modeling", category="agents")

        # Check section exists (injected from shared)
        assert "<false_positive_prevention>" in content, "Missing false_positive_prevention section"
        assert "</false_positive_prevention>" in content, "Missing closing tag"

    def test_threat_modeling_has_trust_boundary_analysis(self):
        """Test threat_modeling prompt includes trust boundary analysis guidance."""
        content = load_prompt("threat_modeling", category="agents")

        # Check trust levels are defined (from shared rules)
        assert "UNTRUSTED" in content, "Missing UNTRUSTED trust level"
        assert "SEMI-TRUSTED" in content, "Missing SEMI-TRUSTED trust level"
        assert "TRUSTED" in content, "Missing TRUSTED trust level"

        # Check guidance about admin config
        assert "admin" in content.lower(), "Missing admin configuration guidance"

    def test_threat_modeling_has_auth_prerequisite_guidance(self):
        """Test threat_modeling prompt includes authentication prerequisite guidance."""
        content = load_prompt("threat_modeling", category="agents")

        # Check prerequisite analysis
        assert "prerequisite" in content.lower(), "Missing prerequisite analysis"
        assert "authentication" in content.lower(), "Missing authentication prerequisite"

        # Check severity adjustment guidance
        assert "severity" in content.lower(), "Missing severity adjustment guidance"

    def test_threat_modeling_has_intentional_design_detection(self):
        """Test threat_modeling prompt includes intentional design detection."""
        content = load_prompt("threat_modeling", category="agents")

        # Check intentional design guidance
        assert (
            "intentional" in content.lower() or "by-design" in content.lower()
        ), "Missing intentional design detection"
        assert "configuration" in content.lower(), "Missing configuration guidance"

    def test_code_review_has_false_positive_prevention(self):
        """Test code_review prompt has false positive prevention section (injected)."""
        content = load_prompt("code_review", category="agents")

        # Check section exists (injected from shared)
        assert "<false_positive_prevention>" in content, "Missing false_positive_prevention section"
        assert "</false_positive_prevention>" in content, "Missing closing tag"

    def test_code_review_has_data_flow_tracing(self):
        """Test code_review prompt includes data flow tracing guidance."""
        content = load_prompt("code_review", category="agents")

        # Check trust levels (from shared rules)
        assert "UNTRUSTED" in content, "Missing UNTRUSTED trust level"
        assert "TRUSTED" in content, "Missing TRUSTED trust level"

    def test_code_review_has_auth_prerequisite_guidance(self):
        """Test code_review prompt includes authentication prerequisite guidance."""
        content = load_prompt("code_review", category="agents")

        # Check prerequisite guidance (from shared rules)
        assert "prerequisite" in content.lower(), "Missing prerequisite guidance"
        assert "severity" in content.lower(), "Missing severity adjustment guidance"

    def test_code_review_has_evidence_requirements(self):
        """Test code_review prompt includes evidence requirements."""
        content = load_prompt("code_review", category="agents")

        # Check evidence requirements
        assert "evidence" in content.lower(), "Missing evidence requirements"


class TestRiskAssessmentSchema:
    """Test that threat_modeling prompt includes risk assessment fields."""

    def test_threat_modeling_has_existing_controls_field(self):
        """Test threat_modeling.txt includes existing_controls field in schema."""
        prompt_file = (
            Path(__file__).parent.parent
            / "securevibes"
            / "prompts"
            / "agents"
            / "threat_modeling.txt"
        )
        content = prompt_file.read_text()

        assert "existing_controls" in content, "Missing existing_controls field in schema"
        assert "control_effectiveness" in content, "Missing control_effectiveness field"

    def test_threat_modeling_has_risk_scoring_fields(self):
        """Test threat_modeling.txt includes risk scoring fields."""
        prompt_file = (
            Path(__file__).parent.parent
            / "securevibes"
            / "prompts"
            / "agents"
            / "threat_modeling.txt"
        )
        content = prompt_file.read_text()

        assert "attack_complexity" in content, "Missing attack_complexity field"
        assert "likelihood" in content, "Missing likelihood field"
        assert "impact" in content, "Missing impact field"
        assert "risk_score" in content, "Missing risk_score field"
        assert "residual_risk" in content, "Missing residual_risk field"

    def test_threat_modeling_has_risk_matrix(self):
        """Test threat_modeling.txt includes risk scoring matrix."""
        prompt_file = (
            Path(__file__).parent.parent
            / "securevibes"
            / "prompts"
            / "agents"
            / "threat_modeling.txt"
        )
        content = prompt_file.read_text()

        assert "<risk_scoring_matrix>" in content, "Missing risk_scoring_matrix section"
        assert "LIKELIHOOD" in content, "Missing LIKELIHOOD factors"
        assert "IMPACT" in content, "Missing IMPACT factors"

    def test_threat_modeling_has_existing_controls_detection(self):
        """Test threat_modeling.txt includes existing controls detection guidance."""
        prompt_file = (
            Path(__file__).parent.parent
            / "securevibes"
            / "prompts"
            / "agents"
            / "threat_modeling.txt"
        )
        content = prompt_file.read_text()

        assert (
            "<existing_controls_detection>" in content
        ), "Missing existing_controls_detection section"
        # Check for common control patterns
        assert (
            "rateLimit" in content or "rate limiting" in content.lower()
        ), "Missing rate limiting patterns"
        assert "sandbox" in content.lower(), "Missing sandboxing patterns"

    def test_threat_modeling_has_control_effectiveness_values(self):
        """Test threat_modeling.txt defines control effectiveness values."""
        prompt_file = (
            Path(__file__).parent.parent
            / "securevibes"
            / "prompts"
            / "agents"
            / "threat_modeling.txt"
        )
        content = prompt_file.read_text()

        # Check for effectiveness levels
        assert "none" in content.lower(), "Missing 'none' effectiveness level"
        assert "partial" in content.lower(), "Missing 'partial' effectiveness level"
        assert "substantial" in content.lower(), "Missing 'substantial' effectiveness level"


class TestPromptConsistency:
    """Test that threat_modeling and code_review prompts have consistent guidance."""

    def test_both_prompts_have_trust_levels(self):
        """Test both prompts define the same trust levels (via shared injection)."""
        tm_content = load_prompt("threat_modeling", category="agents")
        cr_content = load_prompt("code_review", category="agents")

        trust_levels = ["UNTRUSTED", "SEMI-TRUSTED", "TRUSTED", "SYSTEM"]

        for level in trust_levels:
            assert level in tm_content, f"threat_modeling missing {level}"
            assert level in cr_content, f"code_review missing {level}"

    def test_both_prompts_have_severity_adjustment(self):
        """Test both prompts include severity adjustment guidance."""
        tm_content = load_prompt("threat_modeling", category="agents")
        cr_content = load_prompt("code_review", category="agents")

        # Both should mention reducing severity for auth-required issues (from shared rules)
        assert (
            "reduce" in tm_content.lower() or "adjust" in tm_content.lower()
        ), "threat_modeling missing severity adjustment"
        assert (
            "reduce" in cr_content.lower() or "adjust" in cr_content.lower()
        ), "code_review missing severity adjustment"

    def test_shared_rules_ensure_consistency(self):
        """Test that shared rules file ensures both prompts have identical FP prevention."""
        shared_rules = load_shared_rules()
        tm_content = load_prompt("threat_modeling", category="agents")
        cr_content = load_prompt("code_review", category="agents")

        # Both should contain the same shared rules
        assert shared_rules in tm_content, "threat_modeling missing shared rules content"
        assert shared_rules in cr_content, "code_review missing shared rules content"


class TestPrCodeReviewAttackPatterns:
    """PR code review prompt should include critical attack pattern detection."""

    @pytest.fixture
    def prompt_content(self):
        raw_path = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "pr_code_review.txt"
        return raw_path.read_text()

    def test_has_attack_patterns_section(self, prompt_content):
        assert "## CRITICAL ATTACK PATTERNS" in prompt_content

    def test_has_credential_exposure_subsection(self, prompt_content):
        assert "### Credential Exposure" in prompt_content

    def test_has_sandbox_bypass_subsection(self, prompt_content):
        assert "### Sandbox" in prompt_content or "### Safety Bypass" in prompt_content

    def test_has_ssrf_rce_subsection(self, prompt_content):
        assert "### Localhost Bypass" in prompt_content or "### SSRF" in prompt_content

    def test_has_multi_stage_chain_subsection(self, prompt_content):
        assert "### Multi-Stage" in prompt_content or "### Exploit Chain" in prompt_content

    def test_has_cwe_references(self, prompt_content):
        """Each subsection should reference specific CWE IDs."""
        assert prompt_content.count("CWE-") >= 4
