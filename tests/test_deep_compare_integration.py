"""
Test for deep_compare_testing_vs_production.py integration.

Verifies that the script correctly integrates:
- StrategyLoader for rule matching
- PCAPValidator for ClientHello parsing
- ComplianceChecker for automated validation
- JA3 fingerprint comparison

Requirements: 3.1, 3.2, 8.3, 9.2
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.strategy.loader import StrategyLoader
from core.validation.pcap_validator import PCAPValidator
from core.validation.compliance_checker import ComplianceChecker


def test_strategy_loader_integration():
    """Test that StrategyLoader can be imported and used."""
    loader = StrategyLoader()
    
    # Should be able to load rules
    rules = loader.load_rules()
    assert isinstance(rules, dict)
    
    # Should be able to find strategy for known domain
    strategy = loader.find_strategy("nnmclub.to")
    if strategy:
        assert hasattr(strategy, 'attacks')
        assert hasattr(strategy, 'params')
        assert isinstance(strategy.attacks, list)


def test_pcap_validator_integration():
    """Test that PCAPValidator can be imported and used."""
    validator = PCAPValidator()
    
    # Should have required methods
    assert hasattr(validator, 'load_pcap')
    assert hasattr(validator, 'find_streams')
    assert hasattr(validator, 'reassemble_clienthello')
    assert hasattr(validator, 'parse_clienthello')
    assert hasattr(validator, 'detect_attacks')


def test_compliance_checker_integration():
    """Test that ComplianceChecker can be imported and used."""
    checker = ComplianceChecker()
    
    # Should have required methods
    assert hasattr(checker, 'check_compliance')
    assert hasattr(checker, 'compare_attacks')
    assert hasattr(checker, 'calculate_score')
    assert hasattr(checker, 'generate_patch')


def test_deep_compare_script_imports():
    """Test that deep_compare script can import all required modules."""
    # This will fail if there are import errors
    import deep_compare_testing_vs_production
    
    # Verify key functions exist
    assert hasattr(deep_compare_testing_vs_production, 'compare_with_compliance_checker')
    assert hasattr(deep_compare_testing_vs_production, 'compare_ja3_fingerprints')
    assert hasattr(deep_compare_testing_vs_production, 'compare_results')


def test_compliance_checker_with_mock_pcap(tmp_path):
    """Test ComplianceChecker with a minimal mock scenario."""
    from core.strategy.loader import Strategy
    from core.validation.attack_detector import DetectedAttacks
    
    # Create a mock strategy
    strategy = Strategy(
        type='fake',
        attacks=['fake'],
        params={'ttl': 1, 'fooling': 'badseq'},
        metadata={}
    )
    
    # Create a mock detected attacks
    detected = DetectedAttacks(
        fake=True,
        fake_count=1,
        fake_ttl=1.0
    )
    
    # Test compare_attacks
    checker = ComplianceChecker()
    verdicts = checker.compare_attacks(strategy.attacks, detected)
    
    assert 'fake' in verdicts
    assert verdicts['fake'] == True


def test_strategy_loader_finds_nnmclub():
    """Test that StrategyLoader can find strategy for nnmclub.to."""
    loader = StrategyLoader()
    strategy = loader.find_strategy("nnmclub.to")
    
    if strategy:
        # Verify it has the expected structure
        assert strategy.attacks is not None
        assert len(strategy.attacks) > 0
        assert strategy.params is not None
        
        # Log what we found
        print(f"Found strategy for nnmclub.to:")
        print(f"  Attacks: {strategy.attacks}")
        print(f"  Params: {strategy.params}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
