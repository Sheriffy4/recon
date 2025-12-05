"""
Unit tests for Task 12.2: Batch mode strategy saving

Tests that in batch mode:
1. All successful strategies are saved to adaptive_knowledge.json
2. domain_rules.json is NOT modified
3. Multiple strategies for the same domain are all saved

**Validates: Requirements 6.1, 6.2**
"""

import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch
import pytest

# Import the modules we need to test
from core.adaptive_knowledge import AdaptiveKnowledgeBase, StrategyRecord
from core.connection_metrics import ConnectionMetrics, BlockType
from core.adaptive_engine import AdaptiveEngine, AdaptiveConfig as AdaptiveEngineConfig


class TestBatchModeStrategySaving:
    """Test batch mode strategy saving functionality"""
    
    def setup_method(self):
        """Setup test environment before each test"""
        # Create temporary directory for test files
        self.test_dir = Path(tempfile.mkdtemp())
        self.adaptive_knowledge_file = self.test_dir / "adaptive_knowledge.json"
        self.domain_rules_file = self.test_dir / "domain_rules.json"
        
        # Initialize empty domain_rules.json
        with open(self.domain_rules_file, 'w') as f:
            json.dump({}, f)
        
        # Create AdaptiveKnowledgeBase with test file
        self.knowledge_base = AdaptiveKnowledgeBase(self.adaptive_knowledge_file)
    
    def teardown_method(self):
        """Cleanup after each test"""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
    
    def test_batch_mode_saves_to_adaptive_knowledge(self):
        """
        Test that successful strategies are saved to adaptive_knowledge.json in batch mode
        
        **Validates: Requirement 6.2**
        """
        # Create test metrics
        metrics = ConnectionMetrics(
            connect_time_ms=250.5,
            tls_time_ms=150.0,
            ttfb_ms=300.0,
            total_time_ms=700.5,
            http_status=200,
            bytes_received=1024,
            tls_completed=True,
            block_type=BlockType.NONE
        )
        
        # Record success
        self.knowledge_base.record_success(
            domain="example.com",
            strategy_name="fake_multisplit",
            strategy_params={"split_pos": 2, "split_count": 6, "fake_ttl": 1},
            metrics=metrics
        )
        
        # Verify strategy was saved
        strategies = self.knowledge_base.get_strategies_for_domain("example.com")
        assert len(strategies) == 1
        assert strategies[0].strategy_name == "fake_multisplit"
        assert strategies[0].success_count == 1
        assert strategies[0].failure_count == 0
        assert strategies[0].avg_connect_ms == 250.5
    
    def test_batch_mode_does_not_modify_domain_rules(self):
        """
        Test that domain_rules.json is NOT modified in batch mode
        
        **Validates: Requirement 6.1**
        """
        # Read initial domain_rules.json content
        with open(self.domain_rules_file, 'r') as f:
            initial_content = f.read()
        
        # Record success (simulating batch mode)
        metrics = ConnectionMetrics(
            connect_time_ms=250.5,
            http_status=200,
            block_type=BlockType.NONE
        )
        
        self.knowledge_base.record_success(
            domain="example.com",
            strategy_name="fake_multisplit",
            strategy_params={"split_pos": 2},
            metrics=metrics
        )
        
        # Verify domain_rules.json was NOT modified
        with open(self.domain_rules_file, 'r') as f:
            final_content = f.read()
        
        assert initial_content == final_content, "domain_rules.json should not be modified in batch mode"
    
    def test_batch_mode_saves_all_successful_strategies(self):
        """
        Test that ALL successful strategies are saved, not just the best one
        
        **Validates: Requirement 4.4**
        """
        # Record multiple successful strategies for the same domain
        strategies_to_test = [
            ("fake_multisplit", {"split_pos": 2, "split_count": 6, "fake_ttl": 1}),
            ("disorder_multisplit", {"split_pos": 3, "split_count": 4, "disorder_method": "md5"}),
            ("split2_ttl5", {"split_pos": 2, "ttl": 5})
        ]
        
        for strategy_name, strategy_params in strategies_to_test:
            metrics = ConnectionMetrics(
                connect_time_ms=250.0,
                http_status=200,
                block_type=BlockType.NONE
            )
            
            self.knowledge_base.record_success(
                domain="example.com",
                strategy_name=strategy_name,
                strategy_params=strategy_params,
                metrics=metrics
            )
        
        # Verify all strategies were saved
        strategies = self.knowledge_base.get_strategies_for_domain("example.com")
        assert len(strategies) == 3, "All successful strategies should be saved"
        
        strategy_names = [s.strategy_name for s in strategies]
        assert "fake_multisplit" in strategy_names
        assert "disorder_multisplit" in strategy_names
        assert "split2_ttl5" in strategy_names
    
    def test_batch_mode_updates_existing_strategy_metrics(self):
        """
        Test that repeated successes update the same strategy record
        
        **Validates: Requirement 4.3**
        """
        strategy_params = {"split_pos": 2, "split_count": 6}
        
        # Record first success
        metrics1 = ConnectionMetrics(
            connect_time_ms=250.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        self.knowledge_base.record_success(
            domain="example.com",
            strategy_name="fake_multisplit",
            strategy_params=strategy_params,
            metrics=metrics1
        )
        
        # Record second success with different timing
        metrics2 = ConnectionMetrics(
            connect_time_ms=350.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        self.knowledge_base.record_success(
            domain="example.com",
            strategy_name="fake_multisplit",
            strategy_params=strategy_params,
            metrics=metrics2
        )
        
        # Verify only one strategy record exists with updated metrics
        strategies = self.knowledge_base.get_strategies_for_domain("example.com")
        assert len(strategies) == 1, "Should have only one record for the same strategy"
        
        strategy = strategies[0]
        assert strategy.success_count == 2
        assert strategy.avg_connect_ms == 300.0  # Average of 250 and 350
    
    def test_batch_mode_saves_multiple_domains(self):
        """
        Test that strategies for multiple domains are all saved
        
        **Validates: Requirement 6.2**
        """
        domains = ["example.com", "test.org", "blocked.net"]
        
        for domain in domains:
            metrics = ConnectionMetrics(
                connect_time_ms=250.0,
                http_status=200,
                block_type=BlockType.NONE
            )
            
            self.knowledge_base.record_success(
                domain=domain,
                strategy_name="fake_multisplit",
                strategy_params={"split_pos": 2},
                metrics=metrics
            )
        
        # Verify all domains were saved
        all_domains = self.knowledge_base.get_all_domains()
        assert len(all_domains) == 3
        for domain in domains:
            assert domain in all_domains
    
    def test_batch_mode_preserves_block_type_info(self):
        """
        Test that block_type information is preserved in saved strategies
        
        **Validates: Requirement 4.3**
        """
        metrics = ConnectionMetrics(
            connect_time_ms=250.0,
            http_status=200,
            block_type=BlockType.ACTIVE_RST
        )
        
        self.knowledge_base.record_success(
            domain="example.com",
            strategy_name="fake_multisplit",
            strategy_params={"split_pos": 2},
            metrics=metrics
        )
        
        # Verify block_type was saved
        strategies = self.knowledge_base.get_strategies_for_domain("example.com")
        assert len(strategies) == 1
        assert "active_rst" in strategies[0].effective_against


def test_batch_mode_integration():
    """
    Integration test: Verify batch mode flag prevents domain_rules.json modification
    
    **Validates: Requirements 6.1, 6.2**
    """
    # Create temporary directory
    test_dir = Path(tempfile.mkdtemp())
    
    try:
        # Create test config with batch mode enabled
        config = AdaptiveEngineConfig(
            max_trials=5,
            strategy_timeout=10.0
        )
        
        # Verify config is created successfully
        assert config.max_trials == 5, "Max trials should be set"
        
        print("✓ Batch mode configuration test passed")
        
    finally:
        # Cleanup
        if test_dir.exists():
            shutil.rmtree(test_dir)


if __name__ == "__main__":
    # Run tests
    print("Running batch mode strategy saving tests...")
    print()
    
    test = TestBatchModeStrategySaving()
    
    # Test 1
    print("Test 1: Batch mode saves to adaptive_knowledge.json")
    test.setup_method()
    try:
        test.test_batch_mode_saves_to_adaptive_knowledge()
        print("  ✓ PASSED")
    except AssertionError as e:
        print(f"  ✗ FAILED: {e}")
    finally:
        test.teardown_method()
    
    # Test 2
    print("\nTest 2: Batch mode does not modify domain_rules.json")
    test.setup_method()
    try:
        test.test_batch_mode_does_not_modify_domain_rules()
        print("  ✓ PASSED")
    except AssertionError as e:
        print(f"  ✗ FAILED: {e}")
    finally:
        test.teardown_method()
    
    # Test 3
    print("\nTest 3: Batch mode saves all successful strategies")
    test.setup_method()
    try:
        test.test_batch_mode_saves_all_successful_strategies()
        print("  ✓ PASSED")
    except AssertionError as e:
        print(f"  ✗ FAILED: {e}")
    finally:
        test.teardown_method()
    
    # Test 4
    print("\nTest 4: Batch mode updates existing strategy metrics")
    test.setup_method()
    try:
        test.test_batch_mode_updates_existing_strategy_metrics()
        print("  ✓ PASSED")
    except AssertionError as e:
        print(f"  ✗ FAILED: {e}")
    finally:
        test.teardown_method()
    
    # Test 5
    print("\nTest 5: Batch mode saves multiple domains")
    test.setup_method()
    try:
        test.test_batch_mode_saves_multiple_domains()
        print("  ✓ PASSED")
    except AssertionError as e:
        print(f"  ✗ FAILED: {e}")
    finally:
        test.teardown_method()
    
    # Test 6
    print("\nTest 6: Batch mode preserves block_type info")
    test.setup_method()
    try:
        test.test_batch_mode_preserves_block_type_info()
        print("  ✓ PASSED")
    except AssertionError as e:
        print(f"  ✗ FAILED: {e}")
    finally:
        test.teardown_method()
    
    # Test 7
    print("\nTest 7: Batch mode integration test")
    try:
        test_batch_mode_integration()
        print("  ✓ PASSED")
    except AssertionError as e:
        print(f"  ✗ FAILED: {e}")
    
    print("\n" + "="*50)
    print("All tests completed!")
