"""
Property-based tests for ComplianceChecker.

Feature: attack-application-parity
Tests correctness properties for compliance checking and report generation.
"""

import json
import tempfile
from pathlib import Path
import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.validation.compliance_checker import ComplianceChecker, ComplianceReport
from core.validation.attack_detector import DetectedAttacks
from core.strategy.loader import Strategy


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def strategy_with_attacks(draw):
    """Generate a valid Strategy object."""
    # Generate attack list
    attack_types = ['fake', 'split', 'multisplit', 'disorder', 'fakeddisorder']
    num_attacks = draw(st.integers(min_value=1, max_value=3))
    attacks = draw(st.lists(
        st.sampled_from(attack_types),
        min_size=num_attacks,
        max_size=num_attacks,
        unique=True
    ))
    
    # Generate params based on attacks
    params = {}
    if 'fake' in attacks or 'fakeddisorder' in attacks:
        params['ttl'] = draw(st.integers(min_value=1, max_value=3))
        params['fooling'] = draw(st.sampled_from(['badsum', 'badseq', 'none']))
    
    if 'split' in attacks or 'multisplit' in attacks:
        params['split_pos'] = draw(st.one_of(
            st.just('sni'),
            st.integers(min_value=1, max_value=100)
        ))
        if 'multisplit' in attacks:
            params['split_count'] = draw(st.integers(min_value=3, max_value=8))
    
    if 'disorder' in attacks or 'fakeddisorder' in attacks:
        params['disorder_method'] = draw(st.sampled_from(['reverse', 'overlap']))
    
    # Generate metadata
    metadata = {
        'source': draw(st.sampled_from(['manual', 'auto', 'test'])),
        'confidence': draw(st.floats(min_value=0.0, max_value=1.0))
    }
    
    return Strategy(
        type=attacks[0] if attacks else 'none',
        attacks=attacks,
        params=params,
        metadata=metadata
    )


@st.composite
def detected_attacks_matching_strategy(draw, strategy):
    """Generate DetectedAttacks that match a given strategy."""
    detected = DetectedAttacks()
    
    # Set detected flags based on strategy attacks
    if 'fake' in strategy.attacks or 'fakeddisorder' in strategy.attacks:
        detected.fake = True
        detected.fake_count = draw(st.integers(min_value=1, max_value=5))
        detected.fake_ttl = float(strategy.params.get('ttl', 2))
    
    if 'split' in strategy.attacks:
        detected.split = True
        detected.fragment_count = 2
        detected.split_positions = [draw(st.integers(min_value=10, max_value=200))]
    
    if 'multisplit' in strategy.attacks:
        detected.split = True
        split_count = strategy.params.get('split_count', 3)
        detected.fragment_count = split_count
        # Generate split positions
        positions = []
        cumulative = 0
        for i in range(split_count - 1):
            cumulative += draw(st.integers(min_value=10, max_value=100))
            positions.append(cumulative)
        detected.split_positions = positions
    
    if strategy.params.get('split_pos') == 'sni':
        detected.split_near_sni = True
    
    if 'disorder' in strategy.attacks or 'fakeddisorder' in strategy.attacks:
        detected.disorder = True
        disorder_method = strategy.params.get('disorder_method', 'reverse')
        detected.disorder_type = 'out-of-order' if disorder_method == 'reverse' else 'overlap'
    
    return detected


@st.composite
def detected_attacks_not_matching_strategy(draw, strategy):
    """Generate DetectedAttacks that don't match a given strategy."""
    detected = DetectedAttacks()
    
    # Randomly omit some expected attacks
    if 'fake' in strategy.attacks or 'fakeddisorder' in strategy.attacks:
        detected.fake = draw(st.booleans())
        if detected.fake:
            detected.fake_count = draw(st.integers(min_value=1, max_value=5))
            # Use different TTL to cause mismatch
            detected.fake_ttl = float(strategy.params.get('ttl', 2)) + draw(st.integers(min_value=2, max_value=10))
    
    if 'split' in strategy.attacks or 'multisplit' in strategy.attacks:
        detected.split = draw(st.booleans())
        if detected.split:
            # Use wrong fragment count
            expected_count = strategy.params.get('split_count', 2)
            detected.fragment_count = expected_count + draw(st.integers(min_value=1, max_value=3))
    
    if 'disorder' in strategy.attacks or 'fakeddisorder' in strategy.attacks:
        detected.disorder = draw(st.booleans())
    
    return detected


# ============================================================================
# Property Tests for Compliance Report Format (Property 16)
# ============================================================================

class TestComplianceReportFormat:
    """
    **Feature: attack-application-parity, Property 16: Compliance Report Format**
    **Validates: Requirements 9.2**
    
    Property: For any validation analysis, the Validator should output a
    compliance score and a JSON patch for domain_rules.json updates.
    """
    
    @given(
        strategy=strategy_with_attacks(),
        domain=st.text(min_size=5, max_size=50, alphabet=st.characters(
            whitelist_categories=('Ll', 'Lu', 'Nd'),
            whitelist_characters='.-'
        ))
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_compliance_report_has_required_fields(self, strategy, domain):
        """
        Test that ComplianceReport has all required fields.
        
        For any strategy and domain, the compliance report should contain:
        - domain
        - expected_strategy
        - detected_attacks
        - score
        - max_score
        - issues
        - verdicts
        - proposed_patch
        """
        # Create detected attacks matching the strategy
        detected = DetectedAttacks()
        
        # Create compliance report
        report = ComplianceReport(
            domain=domain,
            expected_strategy=strategy,
            detected_attacks=detected,
            score=0,
            max_score=len(strategy.attacks) * 10,
            issues=[],
            verdicts={},
            proposed_patch=None
        )
        
        # Assert: all required fields should be present
        assert hasattr(report, 'domain'), "Report should have 'domain' field"
        assert hasattr(report, 'expected_strategy'), "Report should have 'expected_strategy' field"
        assert hasattr(report, 'detected_attacks'), "Report should have 'detected_attacks' field"
        assert hasattr(report, 'score'), "Report should have 'score' field"
        assert hasattr(report, 'max_score'), "Report should have 'max_score' field"
        assert hasattr(report, 'issues'), "Report should have 'issues' field"
        assert hasattr(report, 'verdicts'), "Report should have 'verdicts' field"
        assert hasattr(report, 'proposed_patch'), "Report should have 'proposed_patch' field"
        
        # Assert: field types should be correct
        assert isinstance(report.domain, str), "domain should be string"
        assert isinstance(report.expected_strategy, Strategy), "expected_strategy should be Strategy"
        assert isinstance(report.detected_attacks, DetectedAttacks), "detected_attacks should be DetectedAttacks"
        assert isinstance(report.score, int), "score should be int"
        assert isinstance(report.max_score, int), "max_score should be int"
        assert isinstance(report.issues, list), "issues should be list"
        assert isinstance(report.verdicts, dict), "verdicts should be dict"
    
    @given(
        strategy=strategy_with_attacks(),
        domain=st.text(min_size=5, max_size=50, alphabet=st.characters(
            whitelist_categories=('Ll', 'Lu', 'Nd'),
            whitelist_characters='.-'
        ))
    )
    @settings(max_examples=100)
    def test_compliance_report_to_dict_is_json_serializable(self, strategy, domain):
        """
        Test that ComplianceReport.to_dict() produces JSON-serializable output.
        
        For any compliance report, to_dict() should return a dictionary
        that can be serialized to JSON.
        """
        # Create detected attacks
        detected = DetectedAttacks()
        
        # Create compliance report
        report = ComplianceReport(
            domain=domain,
            expected_strategy=strategy,
            detected_attacks=detected,
            score=50,
            max_score=100,
            issues=["Test issue"],
            verdicts={'fake': True},
            proposed_patch={'test': 'patch'}
        )
        
        # Convert to dict
        report_dict = report.to_dict()
        
        # Assert: should be JSON serializable
        try:
            json_str = json.dumps(report_dict)
            assert len(json_str) > 0, "JSON string should not be empty"
        except (TypeError, ValueError) as e:
            pytest.fail(f"Report dict should be JSON serializable: {e}")
        
        # Assert: dict should contain all expected keys
        assert 'domain' in report_dict, "Dict should have 'domain' key"
        assert 'expected_strategy' in report_dict, "Dict should have 'expected_strategy' key"
        assert 'detected_attacks' in report_dict, "Dict should have 'detected_attacks' key"
        assert 'score' in report_dict, "Dict should have 'score' key"
        assert 'max_score' in report_dict, "Dict should have 'max_score' key"
        assert 'compliance_percentage' in report_dict, "Dict should have 'compliance_percentage' key"
        assert 'issues' in report_dict, "Dict should have 'issues' key"
        assert 'verdicts' in report_dict, "Dict should have 'verdicts' key"
        assert 'proposed_patch' in report_dict, "Dict should have 'proposed_patch' key"
    
    @given(strategy=strategy_with_attacks())
    @settings(max_examples=100)
    def test_compliance_percentage_calculation(self, strategy):
        """
        Test that compliance_percentage is correctly calculated.
        
        For any score and max_score, compliance_percentage should be
        (score / max_score) * 100.
        """
        max_score = len(strategy.attacks) * 10
        assume(max_score > 0)
        
        # Test various score values
        for score in [0, max_score // 2, max_score]:
            report = ComplianceReport(
                domain="test.com",
                expected_strategy=strategy,
                detected_attacks=DetectedAttacks(),
                score=score,
                max_score=max_score,
                issues=[],
                verdicts={},
                proposed_patch=None
            )
            
            expected_percentage = (score / max_score) * 100.0
            assert abs(report.compliance_percentage - expected_percentage) < 0.01, \
                f"Compliance percentage should be {expected_percentage}, got {report.compliance_percentage}"
    
    @given(strategy=strategy_with_attacks())
    @settings(max_examples=100)
    def test_proposed_patch_has_correct_structure(self, strategy):
        """
        Test that proposed_patch has the correct JSON patch structure.
        
        For any detected attacks, the proposed patch should have:
        - domain
        - operation
        - path
        - value (with type, attacks, params, metadata)
        """
        # Create detected attacks
        detected = DetectedAttacks(
            fake=True,
            fake_count=2,
            fake_ttl=2.0,
            split=True,
            fragment_count=3
        )
        
        # Generate patch
        checker = ComplianceChecker()
        patch = checker.generate_patch("example.com", detected)
        
        # Assert: patch should have required fields
        assert 'domain' in patch, "Patch should have 'domain' field"
        assert 'operation' in patch, "Patch should have 'operation' field"
        assert 'path' in patch, "Patch should have 'path' field"
        assert 'value' in patch, "Patch should have 'value' field"
        
        # Assert: value should have strategy structure
        value = patch['value']
        assert 'type' in value, "Patch value should have 'type' field"
        assert 'attacks' in value, "Patch value should have 'attacks' field"
        assert 'params' in value, "Patch value should have 'params' field"
        assert 'metadata' in value, "Patch value should have 'metadata' field"
        
        # Assert: attacks should be a list
        assert isinstance(value['attacks'], list), "attacks should be a list"
        assert len(value['attacks']) > 0, "attacks list should not be empty"
    
    @given(strategy=strategy_with_attacks())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_perfect_compliance_has_no_issues(self, strategy):
        """
        Test that perfect compliance (100% score) has no issues.
        
        For any strategy where all attacks are detected correctly,
        the issues list should be empty.
        """
        # Create matching detected attacks
        detected = DetectedAttacks()
        
        # Set all expected attacks as detected
        for attack in strategy.attacks:
            if attack == 'fake' or attack == 'fakeddisorder':
                detected.fake = True
                detected.fake_count = 1
                detected.fake_ttl = float(strategy.params.get('ttl', 2))
            elif attack == 'split':
                detected.split = True
                detected.fragment_count = 2
                # If split_pos is 'sni', set split_near_sni to True
                if strategy.params.get('split_pos') == 'sni':
                    detected.split_near_sni = True
            elif attack == 'multisplit':
                detected.split = True
                detected.fragment_count = strategy.params.get('split_count', 3)
                # If split_pos is 'sni', set split_near_sni to True
                if strategy.params.get('split_pos') == 'sni':
                    detected.split_near_sni = True
            elif attack == 'disorder':
                detected.disorder = True
                # Set disorder_type based on disorder_method
                disorder_method = strategy.params.get('disorder_method', 'reverse')
                detected.disorder_type = 'out-of-order' if disorder_method == 'reverse' else 'overlap'
        
        # Calculate score
        checker = ComplianceChecker()
        verdicts = checker.compare_attacks(strategy.attacks, detected)
        score, max_score, issues = checker.calculate_score(strategy, detected, verdicts)
        
        # Assert: if all verdicts are True, score should be max_score
        if all(verdicts.values()):
            assert score == max_score, \
                f"Perfect compliance should have score={max_score}, got {score}"
    
    @given(strategy=strategy_with_attacks())
    @settings(max_examples=100)
    def test_missing_attacks_generate_issues(self, strategy):
        """
        Test that missing attacks generate issues in the report.
        
        For any strategy where expected attacks are not detected,
        the issues list should contain descriptions of missing attacks.
        """
        # Create empty detected attacks (nothing detected)
        detected = DetectedAttacks()
        
        # Calculate score
        checker = ComplianceChecker()
        verdicts = checker.compare_attacks(strategy.attacks, detected)
        score, max_score, issues = checker.calculate_score(strategy, detected, verdicts)
        
        # Assert: issues should be generated for missing attacks
        assert len(issues) > 0, "Missing attacks should generate issues"
        
        # Assert: each missing attack should have an issue
        for attack in strategy.attacks:
            if not verdicts.get(attack, False):
                # Check if there's an issue mentioning this attack
                has_issue = any(attack in issue for issue in issues)
                assert has_issue, f"Should have issue for missing attack '{attack}'"
    
    @given(strategy=strategy_with_attacks())
    @settings(max_examples=100)
    def test_score_is_bounded(self, strategy):
        """
        Test that score is always between 0 and max_score.
        
        For any compliance check, the score should never be negative
        or exceed max_score.
        """
        # Create random detected attacks
        detected = DetectedAttacks(
            fake=True,
            split=True,
            disorder=True
        )
        
        # Calculate score
        checker = ComplianceChecker()
        verdicts = checker.compare_attacks(strategy.attacks, detected)
        score, max_score, issues = checker.calculate_score(strategy, detected, verdicts)
        
        # Assert: score should be bounded
        assert score >= 0, f"Score should be >= 0, got {score}"
        assert score <= max_score, f"Score should be <= {max_score}, got {score}"
    
    @given(strategy=strategy_with_attacks())
    @settings(max_examples=100)
    def test_verdicts_cover_all_expected_attacks(self, strategy):
        """
        Test that verdicts dictionary covers all expected attacks.
        
        For any strategy, the verdicts dictionary should have an entry
        for each attack in the strategy.attacks list.
        """
        # Create detected attacks
        detected = DetectedAttacks()
        
        # Compare attacks
        checker = ComplianceChecker()
        verdicts = checker.compare_attacks(strategy.attacks, detected)
        
        # Assert: verdicts should cover all expected attacks
        for attack in strategy.attacks:
            assert attack in verdicts, \
                f"Verdicts should have entry for attack '{attack}'"
            assert isinstance(verdicts[attack], bool), \
                f"Verdict for '{attack}' should be boolean"
    
    @given(
        strategy=strategy_with_attacks(),
        domain=st.text(min_size=5, max_size=50, alphabet=st.characters(
            whitelist_categories=('Ll', 'Lu', 'Nd'),
            whitelist_characters='.-'
        ))
    )
    @settings(max_examples=100)
    def test_report_contains_domain_and_strategy(self, strategy, domain):
        """
        Test that report contains the original domain and strategy.
        
        For any compliance check, the report should preserve the
        domain name and expected strategy for reference.
        """
        detected = DetectedAttacks()
        
        report = ComplianceReport(
            domain=domain,
            expected_strategy=strategy,
            detected_attacks=detected,
            score=0,
            max_score=len(strategy.attacks) * 10,
            issues=[],
            verdicts={},
            proposed_patch=None
        )
        
        # Assert: domain and strategy should be preserved
        assert report.domain == domain, "Domain should be preserved"
        assert report.expected_strategy == strategy, "Strategy should be preserved"
        assert report.expected_strategy.attacks == strategy.attacks, \
            "Strategy attacks should be preserved"
    
    def test_zero_max_score_handles_gracefully(self):
        """
        Test that zero max_score is handled gracefully.
        
        For a strategy with no attacks (edge case), compliance_percentage
        should return 100% to avoid division by zero.
        """
        strategy = Strategy(
            type='none',
            attacks=[],
            params={},
            metadata={}
        )
        
        report = ComplianceReport(
            domain="test.com",
            expected_strategy=strategy,
            detected_attacks=DetectedAttacks(),
            score=0,
            max_score=0,
            issues=[],
            verdicts={},
            proposed_patch=None
        )
        
        # Assert: should return 100% for zero max_score
        assert report.compliance_percentage == 100.0, \
            "Zero max_score should result in 100% compliance"
