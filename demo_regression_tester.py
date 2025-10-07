#!/usr/bin/env python3
"""
Demo script for RegressionTester class.

This script demonstrates how to use the regression testing and monitoring
functionality for automated fix validation.
"""

import asyncio
import json
import logging
import os
import tempfile
import time
from pathlib import Path

from core.pcap_analysis.regression_tester import RegressionTester
from core.pcap_analysis.fix_generator import CodeFix, FixType, RiskLevel
from core.pcap_analysis.strategy_config import StrategyConfig


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_sample_fixes() -> list[CodeFix]:
    """Create sample fixes for demonstration."""
    fixes = []
    
    # TTL Fix
    ttl_fix = CodeFix(
        fix_id="ttl_fix_001",
        fix_type=FixType.TTL_FIX,
        description="Fix TTL parameter for fake packets in fakeddisorder attack",
        file_path="core/bypass/attacks/tcp/fake_disorder_attack.py",
        function_name="send_fake_packet",
        old_code="ttl = 64  # Default TTL",
        new_code="ttl = 3   # Low TTL for fake packets",
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        impact_assessment="Critical fix for x.com domain bypass",
        test_cases=["test_ttl_fake_packet", "test_x_com_bypass"],
        validation_requirements=["Verify TTL=3 in fake packets", "Test x.com accessibility"],
        dependencies=["core/packet/packet_builder.py"]
    )
    fixes.append(ttl_fix)
    
    # Split Position Fix
    split_fix = CodeFix(
        fix_id="split_pos_fix_001",
        fix_type=FixType.SPLIT_POSITION_FIX,
        description="Fix split position calculation for fakeddisorder",
        file_path="core/bypass/attacks/tcp/fake_disorder_attack.py",
        function_name="calculate_split_position",
        old_code="split_pos = len(payload) // 2",
        new_code="split_pos = min(3, len(payload) - 1)",
        risk_level=RiskLevel.MEDIUM,
        confidence=0.85,
        impact_assessment="Improves split position accuracy for TLS ClientHello",
        test_cases=["test_split_position_calculation", "test_tls_clienthello_split"],
        validation_requirements=["Verify split_pos=3 for TLS", "Test packet sequence order"]
    )
    fixes.append(split_fix)
    
    # Checksum Fix
    checksum_fix = CodeFix(
        fix_id="checksum_fix_001",
        fix_type=FixType.CHECKSUM_FIX,
        description="Implement proper checksum corruption for fake packets",
        file_path="core/packet/packet_builder.py",
        function_name="corrupt_checksum",
        old_code="# TODO: Implement checksum corruption",
        new_code="""def corrupt_checksum(packet):
    # Corrupt TCP checksum for fake packets
    packet[TCP].chksum = 0xFFFF
    return packet""",
        risk_level=RiskLevel.LOW,
        confidence=0.90,
        impact_assessment="Ensures fake packets are properly corrupted",
        test_cases=["test_checksum_corruption", "test_fake_packet_detection"],
        validation_requirements=["Verify corrupted checksum in fake packets"]
    )
    fixes.append(checksum_fix)
    
    return fixes


async def demo_basic_usage():
    """Demonstrate basic RegressionTester usage."""
    logger.info("=== Demo: Basic RegressionTester Usage ===")
    
    # Initialize regression tester
    tester = RegressionTester(
        test_data_dir="demo_regression_tests",
        backup_dir="demo_fix_backups"
    )
    
    # Create sample fixes
    fixes = create_sample_fixes()
    
    logger.info(f"Created {len(fixes)} sample fixes:")
    for fix in fixes:
        logger.info(f"  - {fix.fix_id}: {fix.description}")
    
    # Generate regression tests for each fix
    all_tests = []
    for fix in fixes:
        logger.info(f"\nGenerating tests for {fix.fix_id}...")
        tests = tester.generate_test_cases(fix)
        all_tests.extend(tests)
        
        for test in tests:
            logger.info(f"  Generated: {test.name} ({test.test_type})")
            logger.info(f"    Domains: {', '.join(test.test_domains)}")
            logger.info(f"    Expected success rate: {test.expected_success_rate:.1%}")
    
    logger.info(f"\nTotal tests generated: {len(all_tests)}")


async def demo_rollback_mechanism():
    """Demonstrate rollback mechanism."""
    logger.info("\n=== Demo: Rollback Mechanism ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Initialize regression tester
        tester = RegressionTester(
            test_data_dir=os.path.join(temp_dir, "tests"),
            backup_dir=os.path.join(temp_dir, "backups")
        )
        
        # Create a test file to demonstrate rollback
        test_file = os.path.join(temp_dir, "sample_code.py")
        original_content = '''"""Sample code file for rollback demo."""

def send_fake_packet():
    ttl = 64  # Original TTL value
    return create_packet(ttl=ttl)
'''
        
        with open(test_file, 'w') as f:
            f.write(original_content)
        
        logger.info(f"Created test file: {test_file}")
        logger.info("Original content:")
        logger.info(original_content)
        
        # Create a fix that modifies this file
        fix = CodeFix(
            fix_id="demo_rollback_fix",
            fix_type=FixType.TTL_FIX,
            description="Demo fix for rollback testing",
            file_path=test_file,
            function_name="send_fake_packet",
            old_code="ttl = 64  # Original TTL value",
            new_code="ttl = 3   # Fixed TTL value",
            risk_level=RiskLevel.LOW,
            confidence=0.9
        )
        
        # Create rollback point
        logger.info("\nCreating rollback point...")
        rollback_info = tester.create_rollback_point(fix)
        logger.info(f"Rollback point created at: {rollback_info.backup_path}")
        
        # Simulate applying the fix
        logger.info("\nSimulating fix application...")
        modified_content = original_content.replace("ttl = 64  # Original TTL value", "ttl = 3   # Fixed TTL value")
        with open(test_file, 'w') as f:
            f.write(modified_content)
        
        logger.info("Modified content:")
        with open(test_file, 'r') as f:
            logger.info(f.read())
        
        # Simulate fix failure and rollback
        logger.info("\nSimulating fix failure - rolling back...")
        success = tester.rollback_fix(fix.fix_id)
        
        if success:
            logger.info("Rollback successful!")
            logger.info("Restored content:")
            with open(test_file, 'r') as f:
                restored_content = f.read()
                logger.info(restored_content)
                
            # Verify rollback worked
            if restored_content == original_content:
                logger.info("✅ Rollback verification: Content successfully restored")
            else:
                logger.error("❌ Rollback verification: Content not properly restored")
        else:
            logger.error("❌ Rollback failed")


async def demo_performance_monitoring():
    """Demonstrate performance monitoring."""
    logger.info("\n=== Demo: Performance Monitoring ===")
    
    tester = RegressionTester(
        test_data_dir="demo_regression_tests",
        backup_dir="demo_fix_backups"
    )
    
    # Simulate performance data for different strategies
    strategies = ["ttl_fix_strategy", "split_pos_strategy", "checksum_strategy"]
    domains = ["x.com", "youtube.com", "discord.com", "github.com"]
    
    logger.info("Simulating performance data collection...")
    
    current_time = time.time()
    for strategy in strategies:
        logger.info(f"\nGenerating metrics for {strategy}:")
        
        # Generate 24 hours of hourly metrics
        for hour in range(24):
            timestamp = current_time - (hour * 3600)
            
            for domain in domains:
                # Simulate varying success rates and performance
                success_rate = 0.7 + (0.3 * (1 - hour / 24))  # Degrading over time
                success = hash(f"{strategy}_{domain}_{hour}") % 100 < (success_rate * 100)
                
                from core.pcap_analysis.regression_tester import PerformanceMetrics
                metrics = PerformanceMetrics(
                    timestamp=timestamp,
                    strategy_id=strategy,
                    domain=domain,
                    success=success,
                    response_time=1.0 + (hour * 0.05),  # Increasing response time
                    packet_count=10 + (hour % 5),
                    bytes_sent=1000 + (hour * 50),
                    bytes_received=2000 + (hour * 100),
                    connection_time=0.5 + (hour * 0.02)
                )
                tester.performance_history.append(metrics)
        
        # Analyze performance for this strategy
        analysis = tester.monitor_performance(strategy, time_window_hours=24)
        
        logger.info(f"Performance analysis for {strategy}:")
        logger.info(f"  Total tests: {analysis['total_tests']}")
        logger.info(f"  Success rate: {analysis['success_rate']:.1%}")
        logger.info(f"  Average response time: {analysis['avg_response_time']:.2f}s")
        logger.info(f"  Trend: {analysis['trend']}")
        
        if analysis['problematic_domains']:
            logger.info(f"  Problematic domains: {', '.join(analysis['problematic_domains'])}")


async def demo_test_execution_simulation():
    """Demonstrate test execution simulation."""
    logger.info("\n=== Demo: Test Execution Simulation ===")
    
    tester = RegressionTester(
        test_data_dir="demo_regression_tests",
        backup_dir="demo_fix_backups"
    )
    
    # Create sample fixes and tests
    fixes = create_sample_fixes()
    all_tests = []
    
    for fix in fixes:
        tests = tester.generate_test_cases(fix)
        all_tests.extend(tests)
    
    logger.info(f"Simulating execution of {len(all_tests)} regression tests...")
    
    # Simulate test results (we can't actually run tests without full recon environment)
    simulated_results = {}
    for test in all_tests:
        # Simulate test success based on test type and expected success rate
        success_probability = test.expected_success_rate
        if test.test_type == "performance":
            success_probability *= 0.9  # Performance tests are slightly harder
        elif test.test_type == "compatibility":
            success_probability *= 0.8  # Compatibility tests are harder
        
        success = hash(test.test_id) % 100 < (success_probability * 100)
        simulated_results[test.test_id] = success
        
        # Update test statistics
        test.run_count += 1
        test.last_run = time.time()
        test.last_result = success
        if success:
            test.success_count += 1
        
        logger.info(f"  {test.name}: {'PASSED' if success else 'FAILED'}")
    
    # Generate test summary
    summary = tester.get_test_summary()
    
    logger.info("\nTest Execution Summary:")
    logger.info(f"  Total tests: {summary['total_tests']}")
    logger.info(f"  Tests run: {summary['tests_run']}")
    logger.info(f"  Overall success rate: {summary['overall_success_rate']:.1%}")
    
    logger.info("\nBy test type:")
    for test_type, stats in summary['test_types'].items():
        logger.info(f"  {test_type}: {stats['count']} tests, {stats['success_rate']:.1%} success rate")
    
    if summary['recent_failures']:
        logger.info(f"\nRecent failures: {len(summary['recent_failures'])}")
        for failure in summary['recent_failures'][:3]:  # Show first 3
            logger.info(f"  - {failure['name']} (success rate: {failure['success_rate']:.1%})")


async def demo_data_persistence():
    """Demonstrate data persistence."""
    logger.info("\n=== Demo: Data Persistence ===")
    
    # Create first instance and add data
    logger.info("Creating first RegressionTester instance...")
    tester1 = RegressionTester(
        test_data_dir="demo_regression_tests",
        backup_dir="demo_fix_backups"
    )
    
    # Add some data
    fixes = create_sample_fixes()[:1]  # Just one fix for demo
    tests = tester1.generate_test_cases(fixes[0])
    
    logger.info(f"Added {len(tests)} tests to first instance")
    
    # Create second instance (should load persisted data)
    logger.info("\nCreating second RegressionTester instance...")
    tester2 = RegressionTester(
        test_data_dir="demo_regression_tests",
        backup_dir="demo_fix_backups"
    )
    
    logger.info(f"Second instance loaded {len(tester2.regression_tests)} tests")
    
    # Verify data integrity
    for test_id in tester1.regression_tests:
        if test_id in tester2.regression_tests:
            original = tester1.regression_tests[test_id]
            loaded = tester2.regression_tests[test_id]
            
            if (original.test_id == loaded.test_id and 
                original.fix_id == loaded.fix_id and
                original.test_type == loaded.test_type):
                logger.info(f"✅ Test {test_id} loaded correctly")
            else:
                logger.error(f"❌ Test {test_id} data mismatch")
        else:
            logger.error(f"❌ Test {test_id} not found in loaded data")


async def demo_cleanup():
    """Demonstrate cleanup functionality."""
    logger.info("\n=== Demo: Cleanup Functionality ===")
    
    tester = RegressionTester(
        test_data_dir="demo_regression_tests",
        backup_dir="demo_fix_backups"
    )
    
    # Show current data
    logger.info(f"Before cleanup:")
    logger.info(f"  Performance metrics: {len(tester.performance_history)}")
    logger.info(f"  Rollback info entries: {len(tester.rollback_info)}")
    
    # Run cleanup (keep only 1 day for demo)
    logger.info("\nRunning cleanup (keeping only 1 day of data)...")
    tester.cleanup_old_data(days_to_keep=1)
    
    logger.info(f"After cleanup:")
    logger.info(f"  Performance metrics: {len(tester.performance_history)}")
    logger.info(f"  Rollback info entries: {len(tester.rollback_info)}")


async def main():
    """Run all demos."""
    logger.info("🚀 Starting RegressionTester Demo")
    logger.info("=" * 50)
    
    try:
        await demo_basic_usage()
        await demo_rollback_mechanism()
        await demo_performance_monitoring()
        await demo_test_execution_simulation()
        await demo_data_persistence()
        await demo_cleanup()
        
        logger.info("\n" + "=" * 50)
        logger.info("✅ All RegressionTester demos completed successfully!")
        logger.info("\nThe RegressionTester provides:")
        logger.info("  • Automated test case generation for fixes")
        logger.info("  • Rollback mechanism for failed fixes")
        logger.info("  • Performance monitoring over time")
        logger.info("  • Data persistence and cleanup")
        logger.info("  • Comprehensive test execution framework")
        
    except Exception as e:
        logger.error(f"❌ Demo failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())