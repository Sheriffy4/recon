"""
Test script to verify baseline manager integration with AttackTestOrchestrator.

This script tests:
1. Baseline saving
2. Baseline loading
3. Baseline comparison
4. Regression detection
5. Improvement detection
"""

import sys
import logging
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from test_all_attacks import (
    AttackTestOrchestrator,
    TestResult,
    TestStatus
)
from core.baseline_manager import BaselineManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_baseline_save_load():
    """Test baseline save and load functionality."""
    print("\n" + "="*80)
    print("TEST 1: Baseline Save and Load")
    print("="*80)
    
    output_dir = Path("test_results_baseline_integration")
    output_dir.mkdir(exist_ok=True)
    
    orchestrator = AttackTestOrchestrator(output_dir=output_dir)
    
    # Add mock results
    orchestrator.report.add_result(TestResult(
        attack_name='fake',
        params={'ttl': 1, 'fooling': ['badsum']},
        status=TestStatus.PASSED,
        duration=0.5
    ))
    
    orchestrator.report.add_result(TestResult(
        attack_name='split',
        params={'split_pos': 2},
        status=TestStatus.PASSED,
        duration=0.3
    ))
    
    # Save baseline
    print("\n✓ Saving baseline...")
    baseline_file = orchestrator.save_baseline("test_baseline_v1")
    print(f"  Baseline saved to: {baseline_file}")
    
    # Load baseline
    print("\n✓ Loading baseline...")
    loaded = orchestrator.load_baseline("test_baseline_v1")
    print(f"  Baseline loaded: {loaded.name}")
    print(f"  Timestamp: {loaded.timestamp}")
    print(f"  Total tests: {loaded.total_tests}")
    print(f"  Passed tests: {loaded.passed_tests}")
    print(f"  Results count: {len(loaded.results)}")
    
    return True

def test_baseline_comparison():
    """Test baseline comparison functionality."""
    print("\n" + "="*80)
    print("TEST 2: Baseline Comparison")
    print("="*80)
    
    output_dir = Path("test_results_baseline_integration")
    orchestrator = AttackTestOrchestrator(output_dir=output_dir)
    
    # Create baseline with passing tests
    orchestrator.report.add_result(TestResult(
        attack_name='fake',
        params={'ttl': 1, 'fooling': ['badsum']},
        status=TestStatus.PASSED,
        duration=0.5
    ))
    
    orchestrator.report.add_result(TestResult(
        attack_name='split',
        params={'split_pos': 2},
        status=TestStatus.PASSED,
        duration=0.3
    ))
    
    baseline_file = orchestrator.save_baseline("test_baseline_v2")
    print(f"\n✓ Baseline saved: {baseline_file}")
    
    # Create new orchestrator with different results (regression)
    orchestrator2 = AttackTestOrchestrator(output_dir=output_dir)
    
    # Add results with one regression
    orchestrator2.report.add_result(TestResult(
        attack_name='fake',
        params={'ttl': 1, 'fooling': ['badsum']},
        status=TestStatus.FAILED,  # Regression!
        duration=0.5
    ))
    
    orchestrator2.report.add_result(TestResult(
        attack_name='split',
        params={'split_pos': 2},
        status=TestStatus.PASSED,
        duration=0.3
    ))
    
    # Compare with baseline
    print("\n✓ Comparing with baseline...")
    comparison = orchestrator2.compare_with_baseline("test_baseline_v2")
    
    if comparison:
        print(f"\n  Comparison Results:")
        print(f"  - Total tests: {comparison.total_tests}")
        print(f"  - Regressions: {len(comparison.regressions)}")
        print(f"  - Improvements: {len(comparison.improvements)}")
        print(f"  - Unchanged: {comparison.unchanged}")
        
        if comparison.regressions:
            print(f"\n  Detected Regressions:")
            for reg in comparison.regressions:
                print(f"    [{reg.severity.value}] {reg.attack_name}: {reg.description}")
        
        return len(comparison.regressions) > 0  # Should detect regression
    
    return False

def test_regression_detection():
    """Test regression detection with various scenarios."""
    print("\n" + "="*80)
    print("TEST 3: Regression Detection Scenarios")
    print("="*80)
    
    output_dir = Path("test_results_baseline_integration")
    
    # Scenario 1: Pass -> Fail (Critical regression)
    print("\n✓ Scenario 1: Pass -> Fail (Critical)")
    orchestrator = AttackTestOrchestrator(output_dir=output_dir)
    orchestrator.report.add_result(TestResult(
        attack_name='disorder',
        params={'split_pos': 1},
        status=TestStatus.PASSED,
        duration=0.4
    ))
    orchestrator.save_baseline("test_scenario1")
    
    orchestrator2 = AttackTestOrchestrator(output_dir=output_dir)
    orchestrator2.report.add_result(TestResult(
        attack_name='disorder',
        params={'split_pos': 1},
        status=TestStatus.FAILED,
        duration=0.4
    ))
    
    comparison = orchestrator2.compare_with_baseline("test_scenario1")
    if comparison and comparison.regressions:
        reg = comparison.regressions[0]
        print(f"  ✓ Detected: [{reg.severity.value}] {reg.description}")
    
    # Scenario 2: Fail -> Pass (Improvement)
    print("\n✓ Scenario 2: Fail -> Pass (Improvement)")
    orchestrator3 = AttackTestOrchestrator(output_dir=output_dir)
    orchestrator3.report.add_result(TestResult(
        attack_name='multisplit',
        params={'split_count': 3},
        status=TestStatus.FAILED,
        duration=0.6
    ))
    orchestrator3.save_baseline("test_scenario2")
    
    orchestrator4 = AttackTestOrchestrator(output_dir=output_dir)
    orchestrator4.report.add_result(TestResult(
        attack_name='multisplit',
        params={'split_count': 3},
        status=TestStatus.PASSED,
        duration=0.6
    ))
    
    comparison2 = orchestrator4.compare_with_baseline("test_scenario2")
    if comparison2 and comparison2.improvements:
        imp = comparison2.improvements[0]
        print(f"  ✓ Detected: [IMPROVEMENT] {imp.description}")
    
    return True

def test_baseline_list_and_archive():
    """Test baseline listing and archiving."""
    print("\n" + "="*80)
    print("TEST 4: Baseline List and Archive")
    print("="*80)
    
    output_dir = Path("test_results_baseline_integration")
    orchestrator = AttackTestOrchestrator(output_dir=output_dir)
    
    # List baselines
    print("\n✓ Listing baselines...")
    baselines = orchestrator.list_baselines()
    print(f"  Found {len(baselines)} baselines:")
    for baseline in baselines[:5]:  # Show first 5
        print(f"    - {baseline}")
    
    # Archive a baseline
    if baselines:
        baseline_to_archive = baselines[0]
        print(f"\n✓ Archiving baseline: {baseline_to_archive}")
        success = orchestrator.archive_baseline(baseline_to_archive)
        if success:
            print(f"  ✓ Successfully archived")
        else:
            print(f"  ✗ Failed to archive")
        
        # List again to verify
        baselines_after = orchestrator.list_baselines()
        print(f"\n  Baselines after archiving: {len(baselines_after)}")
    
    return True

def test_regression_report_generation():
    """Test regression report generation."""
    print("\n" + "="*80)
    print("TEST 5: Regression Report Generation")
    print("="*80)
    
    output_dir = Path("test_results_baseline_integration")
    
    # Create baseline
    orchestrator = AttackTestOrchestrator(output_dir=output_dir)
    orchestrator.report.add_result(TestResult(
        attack_name='fakeddisorder',
        params={'split_pos': 2, 'ttl': 1},
        status=TestStatus.PASSED,
        duration=0.7
    ))
    orchestrator.save_baseline("test_report_baseline")
    
    # Create new results with regression
    orchestrator2 = AttackTestOrchestrator(output_dir=output_dir)
    orchestrator2.report.add_result(TestResult(
        attack_name='fakeddisorder',
        params={'split_pos': 2, 'ttl': 1},
        status=TestStatus.FAILED,
        duration=0.7
    ))
    
    # Compare and generate report
    print("\n✓ Comparing with baseline...")
    comparison = orchestrator2.compare_with_baseline("test_report_baseline")
    
    if comparison:
        print("\n✓ Generating regression report...")
        report_file = orchestrator2.generate_regression_report()
        
        if report_file:
            print(f"  Report saved to: {report_file}")
            print(f"  Summary saved to: {report_file.with_suffix('.txt')}")
            
            # Read and display summary
            summary_file = report_file.with_suffix('.txt')
            if summary_file.exists():
                print(f"\n  Summary:")
                print("  " + "-"*76)
                summary = summary_file.read_text()
                for line in summary.split('\n')[:10]:  # Show first 10 lines
                    print(f"  {line}")
                print("  " + "-"*76)
            
            return True
    
    return False

def main():
    """Run all baseline integration tests."""
    print("\n" + "="*80)
    print("BASELINE MANAGER INTEGRATION TESTS")
    print("="*80)
    
    tests = [
        ("Baseline Save/Load", test_baseline_save_load),
        ("Baseline Comparison", test_baseline_comparison),
        ("Regression Detection", test_regression_detection),
        ("List and Archive", test_baseline_list_and_archive),
        ("Regression Report", test_regression_report_generation),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success, None))
        except Exception as e:
            results.append((test_name, False, str(e)))
            print(f"\n✗ Test failed: {e}")
            import traceback
            traceback.print_exc()
    
    # Print summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    
    for test_name, success, error in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status} - {test_name}")
        if error:
            print(f"       Error: {error}")
    
    print(f"\n{passed}/{total} tests passed")
    print("="*80 + "\n")
    
    return 0 if passed == total else 1

if __name__ == '__main__':
    exit(main())
