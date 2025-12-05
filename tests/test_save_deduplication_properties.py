"""
Property-based tests for save deduplication logic.

Feature: strategy-testing-production-parity, Property 7: Strategies are saved exactly once
Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5

For any successful test, the strategy must be saved to each storage location
(adaptive_knowledge.json, domain_rules.json, domain_strategies.json) exactly once,
with deduplication of multiple save attempts.
"""

import time
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock
import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.validation.strategy_saver import StrategySaver
from core.test_result_models import TestVerdict, SaveResult


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def valid_domain(draw):
    """Generate valid domain names."""
    tld = draw(st.sampled_from(['com', 'org', 'net', 'io', 'ru']))
    domain_name = draw(st.text(
        alphabet='abcdefghijklmnopqrstuvwxyz0123456789-',
        min_size=3,
        max_size=20
    ).filter(lambda x: not x.startswith('-') and not x.endswith('-')))
    
    return f"{domain_name}.{tld}"


@st.composite
def valid_strategy_name(draw):
    """Generate valid strategy names."""
    return draw(st.text(
        alphabet='abcdefghijklmnopqrstuvwxyz_',
        min_size=3,
        max_size=30
    ))


@st.composite
def valid_parameters(draw):
    """Generate valid strategy parameters."""
    params = {}
    
    # Randomly include common parameters
    if draw(st.booleans()):
        params['split_pos'] = draw(st.integers(min_value=1, max_value=10))
    
    if draw(st.booleans()):
        params['split_count'] = draw(st.integers(min_value=2, max_value=10))
    
    if draw(st.booleans()):
        params['ttl'] = draw(st.integers(min_value=1, max_value=64))
    
    if draw(st.booleans()):
        params['fooling'] = draw(st.sampled_from(['badseq', 'badsum', 'none']))
    
    if draw(st.booleans()):
        params['disorder_method'] = draw(st.sampled_from(['reverse', 'shuffle']))
    
    return params


@st.composite
def valid_attacks(draw):
    """Generate valid attack lists."""
    attack_names = ['split', 'fake', 'disorder', 'multisplit']
    num_attacks = draw(st.integers(min_value=1, max_value=4))
    return draw(st.lists(
        st.sampled_from(attack_names),
        min_size=num_attacks,
        max_size=num_attacks,
        unique=True
    ))


# ============================================================================
# Property Tests for Save Deduplication
# ============================================================================

class TestSaveDeduplicationProperty:
    """
    **Feature: strategy-testing-production-parity, Property 7: Strategies are saved exactly once**
    **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5**
    
    Property: For any successful test, the strategy must be saved to each storage location
    exactly once, with deduplication of multiple save attempts.
    """
    
    @given(
        domain=valid_domain(),
        strategy_name=valid_strategy_name(),
        parameters=valid_parameters(),
        attacks=valid_attacks(),
        num_save_attempts=st.integers(min_value=2, max_value=5)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_multiple_save_attempts_are_deduplicated(
        self,
        domain,
        strategy_name,
        parameters,
        attacks,
        num_save_attempts
    ):
        """
        Test that multiple save attempts for the same domain+strategy are deduplicated.
        
        For any successful test, if save_strategy() is called multiple times (2-5 times)
        with the same domain and strategy_name, only the first call should actually save,
        and subsequent calls should be marked as duplicates.
        
        Validates: Requirements 5.4, 5.5
        """
        # Create temporary directory for test files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create StrategySaver with temporary paths
            saver = StrategySaver(
                adaptive_knowledge_path=str(tmpdir_path / "adaptive_knowledge.json"),
                domain_rules_path=str(tmpdir_path / "domain_rules.json"),
                domain_strategies_path=str(tmpdir_path / "domain_strategies.json")
            )
            
            # Attempt to save multiple times
            results = []
            for i in range(num_save_attempts):
                result = saver.save_strategy(
                    domain=domain,
                    strategy_name=strategy_name,
                    parameters=parameters,
                    verdict=TestVerdict.SUCCESS,
                    attacks=attacks,
                    success_rate=1.0,
                    verified=True
                )
                results.append(result)
            
            # First save should succeed and not be a duplicate
            assert results[0].success, \
                f"First save attempt should succeed"
            assert not results[0].was_duplicate, \
                f"First save attempt should not be marked as duplicate"
            assert len(results[0].files_updated) > 0, \
                f"First save should update files"
            
            # Subsequent saves should be marked as duplicates
            for i in range(1, num_save_attempts):
                assert results[i].success, \
                    f"Save attempt {i+1} should succeed (but be deduplicated)"
                assert results[i].was_duplicate, \
                    f"Save attempt {i+1} should be marked as duplicate"
                assert len(results[i].files_updated) == 0, \
                    f"Save attempt {i+1} should not update any files (deduplicated)"
    
    @given(
        domain=valid_domain(),
        strategy_name=valid_strategy_name(),
        parameters=valid_parameters(),
        attacks=valid_attacks()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_strategy_saved_to_all_three_files(
        self,
        domain,
        strategy_name,
        parameters,
        attacks
    ):
        """
        Test that a successful strategy is saved to all three storage locations.
        
        For any successful test, save_strategy() should update all three files:
        - adaptive_knowledge.json
        - domain_rules.json
        - domain_strategies.json
        
        Validates: Requirements 5.1, 5.2, 5.3
        """
        # Create temporary directory for test files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create StrategySaver with temporary paths
            saver = StrategySaver(
                adaptive_knowledge_path=str(tmpdir_path / "adaptive_knowledge.json"),
                domain_rules_path=str(tmpdir_path / "domain_rules.json"),
                domain_strategies_path=str(tmpdir_path / "domain_strategies.json")
            )
            
            # Save strategy
            result = saver.save_strategy(
                domain=domain,
                strategy_name=strategy_name,
                parameters=parameters,
                verdict=TestVerdict.SUCCESS,
                attacks=attacks,
                success_rate=1.0,
                verified=True
            )
            
            # Check that all three files were updated
            assert result.success, \
                f"Save should succeed"
            assert len(result.files_updated) == 3, \
                f"Should update exactly 3 files, but updated {len(result.files_updated)}"
            
            # Check that all three files exist
            assert (tmpdir_path / "adaptive_knowledge.json").exists(), \
                f"adaptive_knowledge.json should exist"
            assert (tmpdir_path / "domain_rules.json").exists(), \
                f"domain_rules.json should exist"
            assert (tmpdir_path / "domain_strategies.json").exists(), \
                f"domain_strategies.json should exist"
    
    @given(
        domain=valid_domain(),
        strategy_name=valid_strategy_name(),
        parameters=valid_parameters(),
        attacks=valid_attacks()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_saved_data_is_valid_json(
        self,
        domain,
        strategy_name,
        parameters,
        attacks
    ):
        """
        Test that saved data is valid JSON and can be loaded.
        
        For any successful save, all three storage files should contain valid JSON
        that can be loaded without errors.
        
        Validates: Requirements 5.1, 5.2, 5.3
        """
        # Create temporary directory for test files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create StrategySaver with temporary paths
            saver = StrategySaver(
                adaptive_knowledge_path=str(tmpdir_path / "adaptive_knowledge.json"),
                domain_rules_path=str(tmpdir_path / "domain_rules.json"),
                domain_strategies_path=str(tmpdir_path / "domain_strategies.json")
            )
            
            # Save strategy
            result = saver.save_strategy(
                domain=domain,
                strategy_name=strategy_name,
                parameters=parameters,
                verdict=TestVerdict.SUCCESS,
                attacks=attacks,
                success_rate=1.0,
                verified=True
            )
            
            assert result.success, f"Save should succeed"
            
            # Try to load all three files as JSON
            try:
                with open(tmpdir_path / "adaptive_knowledge.json", 'r') as f:
                    adaptive_data = json.load(f)
                assert isinstance(adaptive_data, dict), \
                    f"adaptive_knowledge.json should contain a dict"
                
                with open(tmpdir_path / "domain_rules.json", 'r') as f:
                    rules_data = json.load(f)
                assert isinstance(rules_data, dict), \
                    f"domain_rules.json should contain a dict"
                
                with open(tmpdir_path / "domain_strategies.json", 'r') as f:
                    strategies_data = json.load(f)
                assert isinstance(strategies_data, dict), \
                    f"domain_strategies.json should contain a dict"
                
            except json.JSONDecodeError as e:
                pytest.fail(f"Saved JSON is invalid: {e}")
    
    @given(
        domain=valid_domain(),
        strategy_name=valid_strategy_name(),
        parameters=valid_parameters(),
        attacks=valid_attacks()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_saved_data_contains_domain_and_strategy(
        self,
        domain,
        strategy_name,
        parameters,
        attacks
    ):
        """
        Test that saved data contains the domain and strategy information.
        
        For any successful save, the saved data should contain the domain
        and strategy_name that were saved.
        
        Validates: Requirements 5.1, 5.2, 5.3
        """
        # Create temporary directory for test files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create StrategySaver with temporary paths
            saver = StrategySaver(
                adaptive_knowledge_path=str(tmpdir_path / "adaptive_knowledge.json"),
                domain_rules_path=str(tmpdir_path / "domain_rules.json"),
                domain_strategies_path=str(tmpdir_path / "domain_strategies.json")
            )
            
            # Save strategy
            result = saver.save_strategy(
                domain=domain,
                strategy_name=strategy_name,
                parameters=parameters,
                verdict=TestVerdict.SUCCESS,
                attacks=attacks,
                success_rate=1.0,
                verified=True
            )
            
            assert result.success, f"Save should succeed"
            
            # Load and check adaptive_knowledge.json
            with open(tmpdir_path / "adaptive_knowledge.json", 'r') as f:
                adaptive_data = json.load(f)
            assert domain in adaptive_data, \
                f"Domain {domain} should be in adaptive_knowledge.json"
            
            # Load and check domain_rules.json
            with open(tmpdir_path / "domain_rules.json", 'r') as f:
                rules_data = json.load(f)
            assert domain in rules_data.get("domain_rules", {}), \
                f"Domain {domain} should be in domain_rules.json"
            
            # Load and check domain_strategies.json
            with open(tmpdir_path / "domain_strategies.json", 'r') as f:
                strategies_data = json.load(f)
            assert domain in strategies_data.get("domain_strategies", {}), \
                f"Domain {domain} should be in domain_strategies.json"
    
    @given(
        domain=valid_domain(),
        strategy_name=valid_strategy_name(),
        parameters=valid_parameters(),
        attacks=valid_attacks(),
        verdict=st.sampled_from([
            TestVerdict.FAIL,
            TestVerdict.PARTIAL_SUCCESS,
            TestVerdict.MISMATCH,
            TestVerdict.INCONCLUSIVE
        ])
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_non_success_verdicts_are_not_saved(
        self,
        domain,
        strategy_name,
        parameters,
        attacks,
        verdict
    ):
        """
        Test that non-SUCCESS verdicts are not saved.
        
        For any test with verdict != SUCCESS, save_strategy() should not
        save to any files and should return success=False.
        
        Validates: Requirements 1.4, 1.5, 9.4
        """
        # Ensure verdict is not SUCCESS
        assume(verdict != TestVerdict.SUCCESS)
        
        # Create temporary directory for test files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create StrategySaver with temporary paths
            saver = StrategySaver(
                adaptive_knowledge_path=str(tmpdir_path / "adaptive_knowledge.json"),
                domain_rules_path=str(tmpdir_path / "domain_rules.json"),
                domain_strategies_path=str(tmpdir_path / "domain_strategies.json")
            )
            
            # Attempt to save with non-SUCCESS verdict
            result = saver.save_strategy(
                domain=domain,
                strategy_name=strategy_name,
                parameters=parameters,
                verdict=verdict,
                attacks=attacks,
                success_rate=1.0,
                verified=True
            )
            
            # Save should fail
            assert not result.success, \
                f"Save with verdict {verdict} should fail"
            assert len(result.files_updated) == 0, \
                f"No files should be updated for non-SUCCESS verdict"
            assert result.error is not None, \
                f"Error message should be provided for non-SUCCESS verdict"
            
            # Check that no files were created
            assert not (tmpdir_path / "adaptive_knowledge.json").exists(), \
                f"adaptive_knowledge.json should not exist for non-SUCCESS verdict"
            assert not (tmpdir_path / "domain_rules.json").exists(), \
                f"domain_rules.json should not exist for non-SUCCESS verdict"
            assert not (tmpdir_path / "domain_strategies.json").exists(), \
                f"domain_strategies.json should not exist for non-SUCCESS verdict"
    
    @given(
        domain=valid_domain(),
        strategy_name=valid_strategy_name(),
        parameters=valid_parameters(),
        attacks=valid_attacks()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_atomic_save_creates_no_temp_files(
        self,
        domain,
        strategy_name,
        parameters,
        attacks
    ):
        """
        Test that atomic save operations don't leave temporary files.
        
        For any successful save, no .tmp files should remain after the operation.
        
        Validates: Requirement 5.2 (atomic save operations)
        """
        # Create temporary directory for test files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create StrategySaver with temporary paths
            saver = StrategySaver(
                adaptive_knowledge_path=str(tmpdir_path / "adaptive_knowledge.json"),
                domain_rules_path=str(tmpdir_path / "domain_rules.json"),
                domain_strategies_path=str(tmpdir_path / "domain_strategies.json")
            )
            
            # Save strategy
            result = saver.save_strategy(
                domain=domain,
                strategy_name=strategy_name,
                parameters=parameters,
                verdict=TestVerdict.SUCCESS,
                attacks=attacks,
                success_rate=1.0,
                verified=True
            )
            
            assert result.success, f"Save should succeed"
            
            # Check that no .tmp files exist
            tmp_files = list(tmpdir_path.glob("*.tmp"))
            assert len(tmp_files) == 0, \
                f"No .tmp files should remain after save, but found: {tmp_files}"
    
    @given(
        domain=valid_domain(),
        strategy_name=valid_strategy_name(),
        parameters=valid_parameters(),
        attacks=valid_attacks()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_save_result_contains_correct_metadata(
        self,
        domain,
        strategy_name,
        parameters,
        attacks
    ):
        """
        Test that SaveResult contains correct metadata.
        
        For any successful save, the SaveResult should contain:
        - success=True
        - files_updated (list of 3 files)
        - was_duplicate=False (for first save)
        - domain and strategy_name
        - timestamp
        
        Validates: Requirements 5.1, 5.2, 5.3
        """
        # Create temporary directory for test files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create StrategySaver with temporary paths
            saver = StrategySaver(
                adaptive_knowledge_path=str(tmpdir_path / "adaptive_knowledge.json"),
                domain_rules_path=str(tmpdir_path / "domain_rules.json"),
                domain_strategies_path=str(tmpdir_path / "domain_strategies.json")
            )
            
            # Save strategy
            result = saver.save_strategy(
                domain=domain,
                strategy_name=strategy_name,
                parameters=parameters,
                verdict=TestVerdict.SUCCESS,
                attacks=attacks,
                success_rate=1.0,
                verified=True
            )
            
            # Check SaveResult metadata
            assert result.success, f"success should be True"
            assert len(result.files_updated) == 3, f"Should update 3 files"
            assert not result.was_duplicate, f"First save should not be duplicate"
            assert result.domain == domain, f"Domain should match"
            assert result.strategy_name == strategy_name, f"Strategy name should match"
            assert result.timestamp > 0, f"Timestamp should be set"
            assert result.error is None, f"Error should be None for successful save"
    
    @given(
        domain1=valid_domain(),
        domain2=valid_domain(),
        strategy_name=valid_strategy_name(),
        parameters=valid_parameters(),
        attacks=valid_attacks()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_different_domains_are_not_deduplicated(
        self,
        domain1,
        domain2,
        strategy_name,
        parameters,
        attacks
    ):
        """
        Test that saves for different domains are not deduplicated.
        
        For any two different domains with the same strategy, both saves
        should succeed and neither should be marked as duplicate.
        
        Validates: Requirement 5.4, 5.5
        """
        # Ensure domains are different
        assume(domain1 != domain2)
        
        # Create temporary directory for test files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create StrategySaver with temporary paths
            saver = StrategySaver(
                adaptive_knowledge_path=str(tmpdir_path / "adaptive_knowledge.json"),
                domain_rules_path=str(tmpdir_path / "domain_rules.json"),
                domain_strategies_path=str(tmpdir_path / "domain_strategies.json")
            )
            
            # Save for domain1
            result1 = saver.save_strategy(
                domain=domain1,
                strategy_name=strategy_name,
                parameters=parameters,
                verdict=TestVerdict.SUCCESS,
                attacks=attacks,
                success_rate=1.0,
                verified=True
            )
            
            # Save for domain2
            result2 = saver.save_strategy(
                domain=domain2,
                strategy_name=strategy_name,
                parameters=parameters,
                verdict=TestVerdict.SUCCESS,
                attacks=attacks,
                success_rate=1.0,
                verified=True
            )
            
            # Both saves should succeed and not be duplicates
            assert result1.success, f"First save should succeed"
            assert not result1.was_duplicate, f"First save should not be duplicate"
            assert len(result1.files_updated) == 3, f"First save should update 3 files"
            
            assert result2.success, f"Second save should succeed"
            assert not result2.was_duplicate, f"Second save should not be duplicate"
            assert len(result2.files_updated) == 3, f"Second save should update 3 files"
    
    @given(
        domain=valid_domain(),
        strategy1=valid_strategy_name(),
        strategy2=valid_strategy_name(),
        parameters=valid_parameters(),
        attacks=valid_attacks()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_different_strategies_are_not_deduplicated(
        self,
        domain,
        strategy1,
        strategy2,
        parameters,
        attacks
    ):
        """
        Test that saves for different strategies are not deduplicated.
        
        For any domain with two different strategies, both saves
        should succeed and neither should be marked as duplicate.
        
        Validates: Requirement 5.4, 5.5
        """
        # Ensure strategies are different
        assume(strategy1 != strategy2)
        
        # Create temporary directory for test files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create StrategySaver with temporary paths
            saver = StrategySaver(
                adaptive_knowledge_path=str(tmpdir_path / "adaptive_knowledge.json"),
                domain_rules_path=str(tmpdir_path / "domain_rules.json"),
                domain_strategies_path=str(tmpdir_path / "domain_strategies.json")
            )
            
            # Save strategy1
            result1 = saver.save_strategy(
                domain=domain,
                strategy_name=strategy1,
                parameters=parameters,
                verdict=TestVerdict.SUCCESS,
                attacks=attacks,
                success_rate=1.0,
                verified=True
            )
            
            # Save strategy2
            result2 = saver.save_strategy(
                domain=domain,
                strategy_name=strategy2,
                parameters=parameters,
                verdict=TestVerdict.SUCCESS,
                attacks=attacks,
                success_rate=1.0,
                verified=True
            )
            
            # Both saves should succeed and not be duplicates
            assert result1.success, f"First save should succeed"
            assert not result1.was_duplicate, f"First save should not be duplicate"
            assert len(result1.files_updated) == 3, f"First save should update 3 files"
            
            assert result2.success, f"Second save should succeed"
            assert not result2.was_duplicate, f"Second save should not be duplicate"
            assert len(result2.files_updated) == 3, f"Second save should update 3 files"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])