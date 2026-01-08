"""Tests for prompt quality and false positive prevention guidance."""

from pathlib import Path


class TestFalsePositivePreventionGuidance:
    """Test that prompts include false positive prevention guidance."""

    def test_threat_modeling_has_false_positive_prevention(self):
        """Test threat_modeling.txt has false positive prevention section."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "threat_modeling.txt"
        content = prompt_file.read_text()
        
        # Check section exists
        assert "<false_positive_prevention>" in content, "Missing false_positive_prevention section"
        assert "</false_positive_prevention>" in content, "Missing closing tag"

    def test_threat_modeling_has_trust_boundary_analysis(self):
        """Test threat_modeling.txt includes trust boundary analysis guidance."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "threat_modeling.txt"
        content = prompt_file.read_text()
        
        # Check trust levels are defined
        assert "UNTRUSTED" in content, "Missing UNTRUSTED trust level"
        assert "SEMI-TRUSTED" in content, "Missing SEMI-TRUSTED trust level"
        assert "TRUSTED" in content, "Missing TRUSTED trust level"
        
        # Check guidance about admin config
        assert "admin" in content.lower(), "Missing admin configuration guidance"

    def test_threat_modeling_has_auth_prerequisite_guidance(self):
        """Test threat_modeling.txt includes authentication prerequisite guidance."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "threat_modeling.txt"
        content = prompt_file.read_text()
        
        # Check prerequisite analysis
        assert "prerequisite" in content.lower(), "Missing prerequisite analysis"
        assert "authentication" in content.lower(), "Missing authentication prerequisite"
        
        # Check severity adjustment guidance
        assert "severity" in content.lower(), "Missing severity adjustment guidance"

    def test_threat_modeling_has_intentional_design_detection(self):
        """Test threat_modeling.txt includes intentional design detection."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "threat_modeling.txt"
        content = prompt_file.read_text()
        
        # Check intentional design guidance
        assert "intentional" in content.lower() or "by-design" in content.lower(), \
            "Missing intentional design detection"
        assert "configuration" in content.lower(), "Missing configuration guidance"

    def test_code_review_has_false_positive_prevention(self):
        """Test code_review.txt has false positive prevention section."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "code_review.txt"
        content = prompt_file.read_text()
        
        # Check section exists
        assert "<false_positive_prevention>" in content, "Missing false_positive_prevention section"
        assert "</false_positive_prevention>" in content, "Missing closing tag"

    def test_code_review_has_data_flow_tracing(self):
        """Test code_review.txt includes data flow tracing guidance."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "code_review.txt"
        content = prompt_file.read_text()
        
        # Check trust levels
        assert "UNTRUSTED" in content, "Missing UNTRUSTED trust level"
        assert "TRUSTED" in content, "Missing TRUSTED trust level"
        
        # Check data flow guidance
        assert "data flow" in content.lower() or "dataflow" in content.lower(), \
            "Missing data flow tracing guidance"

    def test_code_review_has_auth_prerequisite_guidance(self):
        """Test code_review.txt includes authentication prerequisite guidance."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "code_review.txt"
        content = prompt_file.read_text()
        
        # Check prerequisite guidance
        assert "prerequisite" in content.lower(), "Missing prerequisite guidance"
        assert "severity" in content.lower(), "Missing severity adjustment guidance"

    def test_code_review_has_evidence_requirements(self):
        """Test code_review.txt includes evidence requirements."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "code_review.txt"
        content = prompt_file.read_text()
        
        # Check evidence requirements
        assert "evidence" in content.lower(), "Missing evidence requirements"


class TestRiskAssessmentSchema:
    """Test that threat_modeling prompt includes risk assessment fields."""

    def test_threat_modeling_has_existing_controls_field(self):
        """Test threat_modeling.txt includes existing_controls field in schema."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "threat_modeling.txt"
        content = prompt_file.read_text()
        
        assert "existing_controls" in content, "Missing existing_controls field in schema"
        assert "control_effectiveness" in content, "Missing control_effectiveness field"

    def test_threat_modeling_has_risk_scoring_fields(self):
        """Test threat_modeling.txt includes risk scoring fields."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "threat_modeling.txt"
        content = prompt_file.read_text()
        
        assert "attack_complexity" in content, "Missing attack_complexity field"
        assert "likelihood" in content, "Missing likelihood field"
        assert "impact" in content, "Missing impact field"
        assert "risk_score" in content, "Missing risk_score field"
        assert "residual_risk" in content, "Missing residual_risk field"

    def test_threat_modeling_has_risk_matrix(self):
        """Test threat_modeling.txt includes risk scoring matrix."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "threat_modeling.txt"
        content = prompt_file.read_text()
        
        assert "<risk_scoring_matrix>" in content, "Missing risk_scoring_matrix section"
        assert "LIKELIHOOD" in content, "Missing LIKELIHOOD factors"
        assert "IMPACT" in content, "Missing IMPACT factors"

    def test_threat_modeling_has_existing_controls_detection(self):
        """Test threat_modeling.txt includes existing controls detection guidance."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "threat_modeling.txt"
        content = prompt_file.read_text()
        
        assert "<existing_controls_detection>" in content, "Missing existing_controls_detection section"
        # Check for common control patterns
        assert "rateLimit" in content or "rate limiting" in content.lower(), "Missing rate limiting patterns"
        assert "sandbox" in content.lower(), "Missing sandboxing patterns"

    def test_threat_modeling_has_control_effectiveness_values(self):
        """Test threat_modeling.txt defines control effectiveness values."""
        prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "threat_modeling.txt"
        content = prompt_file.read_text()
        
        # Check for effectiveness levels
        assert "none" in content.lower(), "Missing 'none' effectiveness level"
        assert "partial" in content.lower(), "Missing 'partial' effectiveness level"
        assert "substantial" in content.lower(), "Missing 'substantial' effectiveness level"


class TestPromptConsistency:
    """Test that threat_modeling and code_review prompts have consistent guidance."""

    def test_both_prompts_have_trust_levels(self):
        """Test both prompts define the same trust levels."""
        tm_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "threat_modeling.txt"
        cr_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "code_review.txt"
        
        tm_content = tm_file.read_text()
        cr_content = cr_file.read_text()
        
        trust_levels = ["UNTRUSTED", "SEMI-TRUSTED", "TRUSTED", "SYSTEM"]
        
        for level in trust_levels:
            assert level in tm_content, f"threat_modeling.txt missing {level}"
            assert level in cr_content, f"code_review.txt missing {level}"

    def test_both_prompts_have_severity_adjustment(self):
        """Test both prompts include severity adjustment guidance."""
        tm_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "threat_modeling.txt"
        cr_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "code_review.txt"
        
        tm_content = tm_file.read_text()
        cr_content = cr_file.read_text()
        
        # Both should mention reducing severity for auth-required issues
        assert "reduce" in tm_content.lower() or "adjust" in tm_content.lower(), \
            "threat_modeling.txt missing severity adjustment"
        assert "reduce" in cr_content.lower() or "adjust" in cr_content.lower(), \
            "code_review.txt missing severity adjustment"
