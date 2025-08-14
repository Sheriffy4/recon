#!/usr/bin/env python3
"""
Simple test runner for metrics collector tests
"""

import sys
import os
import unittest
import asyncio

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import test classes
from core.fingerprint.test_metrics_collector import (
    TestTimingMetrics,
    TestNetworkMetrics,
    TestProtocolMetrics,
    TestComprehensiveMetrics,
    TestBaseMetricsCollector,
    TestTimingMetricsCollector,
    TestNetworkMetricsCollector,
    TestProtocolMetricsCollector,
    TestMetricsCollector,
    TestMetricsCollectorIntegration
)

def run_async_tests():
    """Run async tests with proper event loop handling"""
    
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add synchronous tests first
    sync_test_classes = [
        TestTimingMetrics,
        TestNetworkMetrics,
        TestProtocolMetrics,
        TestComprehensiveMetrics,
        TestBaseMetricsCollector,
    ]
    
    for test_class in sync_test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run synchronous tests
    print("Running synchronous tests...")
    runner = unittest.TextTestRunner(verbosity=2)
    sync_result = runner.run(suite)
    
    # Run async tests manually
    print("\nRunning asynchronous tests...")
    
    async_test_classes = [
        TestTimingMetricsCollector,
        TestNetworkMetricsCollector,
        TestProtocolMetricsCollector,
        TestMetricsCollector,
        TestMetricsCollectorIntegration
    ]
    
    async_passed = 0
    async_failed = 0
    
    for test_class in async_test_classes:
        print(f"\nTesting {test_class.__name__}...")
        test_instance = test_class()
        
        # Get all test methods
        test_methods = [method for method in dir(test_instance) 
                       if method.startswith('test_') and callable(getattr(test_instance, method))]
        
        for method_name in test_methods:
            method = getattr(test_instance, method_name)
            
            try:
                # Set up test
                if hasattr(test_instance, 'setUp'):
                    test_instance.setUp()
                
                # Run test
                if asyncio.iscoroutinefunction(method):
                    # Async test
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        loop.run_until_complete(method())
                        print(f"  ✓ {method_name}")
                        async_passed += 1
                    except Exception as e:
                        print(f"  ✗ {method_name}: {e}")
                        async_failed += 1
                    finally:
                        loop.close()
                else:
                    # Sync test
                    method()
                    print(f"  ✓ {method_name}")
                    async_passed += 1
                
                # Tear down test
                if hasattr(test_instance, 'tearDown'):
                    test_instance.tearDown()
                    
            except Exception as e:
                print(f"  ✗ {method_name}: {e}")
                async_failed += 1
    
    print(f"\nAsync tests: {async_passed} passed, {async_failed} failed")
    print(f"Sync tests: {sync_result.testsRun - sync_result.failures - sync_result.errors} passed, "
          f"{sync_result.failures + sync_result.errors} failed")
    
    total_passed = (sync_result.testsRun - sync_result.failures - sync_result.errors) + async_passed
    total_failed = (sync_result.failures + sync_result.errors) + async_failed
    
    print(f"\nTotal: {total_passed} passed, {total_failed} failed")
    
    return total_failed == 0

if __name__ == '__main__':
    success = run_async_tests()
    sys.exit(0 if success else 1)