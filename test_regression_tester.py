#!/usr/bin/env python3
"""
Test script for RegressionTester class.

This script tests the regression testing and monitoring functionality
for automated fix validation.
"""

import asyncio
import json
import logging
import os
import tempfile
import time
from pathlib import Path

from core.pcap_analysis.regression_tester import (
    RegressionTester, RegressionTest, PerformanceMetrics, RollbackInfo
)
from core.pcap_analysis.fix_generator import CodeFix, FixType, RiskLevel
from core.pcap_analysis.strategy_config import StrategyConfig


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_test_fix() -> CodeFix:
    """Create a test fix for testing purposes."""
    return CodeFix(
        fix_id="test_fix_001",
        fix_type=FixType.TTL_FIX,
        description="Fix TTL parameter for fake packets",
        file_path="core/bypass/attacks/tcp/fake_disorder_attack.py",
        function_name="send_fake_packet",
        old_code="ttl = 64",
        new_code="ttl = 3",
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        test_cases=["test_ttl_fix", "test_fake_packet_generation"],
        dependencies=["core/packet/packet_builder.py"]
    )


def test_test_case_generation():
    """Test regression test case generation."""
    logger.info("Testing regression test case generation...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Initialize regression tester
        tester = RegressionTester(
            test_data_dir=os.path.join(temp_dir, "tests"),
            backup_dir=os.path.join(temp_dir, "backups")
        )
        
        # Create test fix
        test_fix = create_test_fix()
        
        # Generate test cases
        tests = tester.generate_test_cases(test_fix)
        
        logger.info(f"Generated {len(tests)} test cases:")
        for test in tests:
            logger.info(f"  - {test.name} ({test.test_type})")
            logger.info(f"    Domains: {test.test_domains}")
            logger.info(f"    Expected success rate: {test.expected_success_rate}")
        
        # Verify test generation
        assert len(tests) > 0, "Should generate at least one test"
        
        # Check that functional test was generated
        functional_tests = [t for t in tests if t.test_type == "functional"]
        assert len(functional_tests) > 0, "Should generate functional test"
        
        # Verify test is registered
        assert test_fix.fix_id in [t.fix_id for t in tests], "Test should reference the fix"
        
        logger.info("✓ Test case generation successful")


def test_rollback_mechanism():
    """Test rollback mechanism."""
    logger.info("Testing rollback mechanism...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Initialize regression tester
        tester = RegressionTester(
            test_data_dir=os.path.join(temp_dir, "tests"),
            backup_dir=os.path.join(temp_dir, "backups")
        )
        
        # Create test file
        test_file = os.path.join(temp_dir, "test_file.py")
        original_content = "# Original content\nttl = 64\n"
        
        with open(test_file, 'w') as f:
            f.write(original_content)
        
        # Create test fix
        test_fix = create_test_fix()
        test_fix.file_path = test_file
        
        # Create rollback point
        rollback_info = tester.create_rollback_point(test_fix)
        
        logger.info(f"Created rollback point: {rollback_info.backup_path}")
        
        # Verify rollback info
        assert rollback_info.fix_id == test_fix.fix_id
        assert test_file in rollback_info.original_files
        assert rollback_info.original_files[test_file] == original_content
        
        # Simulate applying fix (modify file)
        modified_content = "# Modified content\nttl = 3\n"
        with open(test_file, 'w') as f:
            f.write(modified_content)
        
        # Verify file was modified
        with open(test_file, 'r') as f:
            assert f.read() == modified_content
        
        # Rollback the fix
        success = tester.rollback_fix(test_fix.fix_id)
        assert success, "Rollback should succeed"
        
        # Verify file was restored
        with open(test_file, 'r') as f:
            restored_content = f.read()
            assert restored_content == original_content, f"Expected '{original_content}', got '{restored_content}'"
        
        logger.info("✓ Rollback mechanism successful")


def test_performance_monitoring():
    """Test performance monitoring functionality."""
    logger.info("Testing performance monitoring...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Initialize regression tester
        tester = RegressionTester(
            test_data_dir=os.path.join(temp_dir, "tests"),
            backup_dir=os.path.join(temp_dir, "backups")
        )
        
        # Add some test performance metrics
        strategy_id = "test_strategy"
        current_time = time.time()
        
        # Add metrics for the last 24 hours
        successful_count = 0
        for i in range(10):
            success = i % 3 != 0  # 2/3 success rate
            if success:
                successful_count += 1
            
            metrics = PerformanceMetrics(
                timestamp=current_time - (i * 3600),  # Every hour
                strategy_id=strategy_id,
                domain="x.com",
                success=success,
                response_time=1.0 + (i * 0.1),
                packet_count=10 + i,
                bytes_sent=1000 + (i * 100),
                bytes_received=2000 + (i * 200),
                connection_time=0.5 + (i * 0.05)
            )
            tester.performance_history.append(metrics)
        
        # Monitor performance
        analysis = tester.monitor_performance(strategy_id, time_window_hours=24)
        
        logger.info(f"Performance analysis: {json.dumps(analysis, indent=2)}")
        
        # Verify analysis
        assert analysis['strategy_id'] == strategy_id
        assert analysis['total_tests'] == 10
        assert analysis['successful_tests'] == successful_count  # Use actual count
        expected_rate = successful_count / 10
        assert abs(analysis['success_rate'] - expected_rate) < 0.01
        assert analysis['trend'] in ['improving', 'degrading', 'stable']
        
        logger.info("✓ Performance monitoring successful")


async def test_regression_test_execution():
    """Test regression test execution."""
    logger.info("Testing regression test execution...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Initialize regression tester
        tester = RegressionTester(
            test_data_dir=os.path.join(temp_dir, "tests"),
            backup_dir=os.path.join(temp_dir, "backups")
        )
        
        # Create test fix and generate tests
        test_fix = create_test_fix()
        tests = tester.generate_test_cases(test_fix)
        
        # Note: We can't actually run the tests without a full recon environment,
        # so we'll test the test execution framework structure
        
        logger.info(f"Would run {len(tests)} regression tests")
        
        # Test the test filtering logic
        functional_tests = [t for t in tests if t.test_type == "functional"]
        performance_tests = [t for t in tests if t.test_type == "performance"]
        
        logger.info(f"Functional tests: {len(functional_tests)}")
        logger.info(f"Performance tests: {len(performance_tests)}")
        
        # Verify test structure
        for test in tests:
            assert test.test_id is not None
            assert test.fix_id == test_fix.fix_id
            assert len(test.test_domains) > 0
            assert 0.0 <= test.expected_success_rate <= 1.0
        
        logger.info("✓ Regression test execution framework verified")


def test_data_persistence():
    """Test data persistence functionality."""
    logger.info("Testing data persistence...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Initialize regression tester
        tester1 = RegressionTester(
            test_data_dir=os.path.join(temp_dir, "tests"),
            backup_dir=os.path.join(temp_dir, "backups")
        )
        
        # Create test data
        test_fix = create_test_fix()
        tests = tester1.generate_test_cases(test_fix)
        rollback_info = tester1.create_rollback_point(test_fix)
        
        # Add performance metrics
        metrics = PerformanceMetrics(
            timestamp=time.time(),
            strategy_id="test_strategy",
            domain="x.com",
            success=True,
            response_time=1.5,
            packet_count=15,
            bytes_sent=1500,
            bytes_received=3000,
            connection_time=0.8
        )
        tester1.performance_history.append(metrics)
        tester1._save_performance_history()
        
        # Create new instance (should load persisted data)
        tester2 = RegressionTester(
            test_data_dir=os.path.join(temp_dir, "tests"),
            backup_dir=os.path.join(temp_dir, "backups")
        )
        
        # Verify data was loaded
        assert len(tester2.regression_tests) == len(tests)
        assert test_fix.fix_id in tester2.rollback_info
        assert len(tester2.performance_history) >= 1
        
        # Verify test data integrity
        for test_id, original_test in tester1.regression_tests.items():
            loaded_test = tester2.regression_tests[test_id]
            assert loaded_test.test_id == original_test.test_id
            assert loaded_test.fix_id == original_test.fix_id
            assert loaded_test.test_type == original_test.test_type
        
        logger.info("✓ Data persistence successful")


def test_cleanup_functionality():
    """Test cleanup functionality."""
    logger.info("Testing cleanup functionality...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Initialize regression tester
        tester = RegressionTester(
            test_data_dir=os.path.join(temp_dir, "tests"),
            backup_dir=os.path.join(temp_dir, "backups")
        )
        
        # Add old performance metrics (older than 30 days)
        old_time = time.time() - (35 * 24 * 3600)  # 35 days ago
        recent_time = time.time() - (10 * 24 * 3600)  # 10 days ago
        
        old_metrics = PerformanceMetrics(
            timestamp=old_time,
            strategy_id="old_strategy",
            domain="old.com",
            success=True,
            response_time=1.0,
            packet_count=10,
            bytes_sent=1000,
            bytes_received=2000,
            connection_time=0.5
        )
        
        recent_metrics = PerformanceMetrics(
            timestamp=recent_time,
            strategy_id="recent_strategy",
            domain="recent.com",
            success=True,
            response_time=1.2,
            packet_count=12,
            bytes_sent=1200,
            bytes_received=2400,
            connection_time=0.6
        )
        
        tester.performance_history.extend([old_metrics, recent_metrics])
        
        # Create old rollback info
        old_rollback = RollbackInfo(
            fix_id="old_fix",
            backup_path=os.path.join(temp_dir, "old_backup"),
            original_files={},
            rollback_commands=[],
            dependencies=[],
            created_at=old_time
        )
        
        recent_rollback = RollbackInfo(
            fix_id="recent_fix",
            backup_path=os.path.join(temp_dir, "recent_backup"),
            original_files={},
            rollback_commands=[],
            dependencies=[],
            created_at=recent_time
        )
        
        tester.rollback_info["old_fix"] = old_rollback
        tester.rollback_info["recent_fix"] = recent_rollback
        
        # Run cleanup
        tester.cleanup_old_data(days_to_keep=30)
        
        # Verify old data was removed
        assert len(tester.performance_history) == 1
        assert tester.performance_history[0].strategy_id == "recent_strategy"
        
        assert "old_fix" not in tester.rollback_info
        assert "recent_fix" in tester.rollback_info
        
        logger.info("✓ Cleanup functionality successful")


def test_summary_generation():
    """Test summary generation."""
    logger.info("Testing summary generation...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Initialize regression tester
        tester = RegressionTester(
            test_data_dir=os.path.join(temp_dir, "tests"),
            backup_dir=os.path.join(temp_dir, "backups")
        )
        
        # Create test fixes and generate tests
        for i in range(3):
            test_fix = create_test_fix()
            test_fix.fix_id = f"test_fix_{i:03d}"
            tests = tester.generate_test_cases(test_fix)
            
            # Simulate some test runs
            for test in tests:
                test.run_count = 5
                test.success_count = 3 + i  # Varying success rates
        
        # Generate summary
        summary = tester.get_test_summary()
        
        logger.info(f"Test summary: {json.dumps(summary, indent=2)}")
        
        # Verify summary
        assert summary['total_tests'] > 0
        assert 'test_types' in summary
        assert 'overall_success_rate' in summary
        
        logger.info("✓ Summary generation successful")


async def main():
    """Run all tests."""
    logger.info("Starting RegressionTester tests...")
    
    try:
        # Run tests
        test_test_case_generation()
        test_rollback_mechanism()
        test_performance_monitoring()
        await test_regression_test_execution()
        test_data_persistence()
        test_cleanup_functionality()
        test_summary_generation()
        
        logger.info("✅ All RegressionTester tests passed!")
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())