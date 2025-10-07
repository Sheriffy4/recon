"""
Demo: CLI Baseline Comparison Integration

This script demonstrates the baseline comparison feature integrated into the CLI workflow.
It shows how to:
1. Save a baseline
2. Compare with a baseline
3. Detect regressions
4. Detect improvements

Part of Task 6.4: Integrate baseline comparison into CLI workflow
"""

import sys
import os
import json
import tempfile
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.baseline_manager import (
    BaselineManager,
    BaselineReport,
    BaselineResult,
    RegressionSeverity
)
from core.cli_validation_orchestrator import CLIValidationOrchestrator


def print_section(title):
    """Print a section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def demo_save_baseline():
    """Demonstrate saving a baseline."""
    print_section("DEMO 1: Save Baseline")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        orchestrator = CLIValidationOrchestrator(baselines_dir=Path(tmpdir) / "baselines")
        
        # Simulate test results from a CLI run
        test_results = [
            {
                'attack_name': 'fake_disorder',
                'passed': True,
                'packet_count': 10,
                'validation_passed': True,
                'validation_issues': [],
                'execution_time': 0.5,
                'metadata': {'domain': 'example.com', 'success_rate': 1.0}
            },
            {
                'attack_name': 'multisplit',
                'passed': True,
                'packet_count': 15,
                'validation_passed': True,
                'validation_issues': [],
                'execution_time': 0.7,
                'metadata': {'domain': 'example.com', 'success_rate': 1.0}
            },
            {
                'attack_name': 'sequence_overlap',
                'passed': True,
                'packet_count': 12,
                'validation_passed': True,
                'validation_issues': [],
                'execution_time': 0.6,
                'metadata': {'domain': 'example.com', 'success_rate': 1.0}
            }
        ]
        
        print("\n📊 Test Results:")
        for result in test_results:
            status = "✓ PASS" if result['passed'] else "✗ FAIL"
            print(f"  {status} - {result['attack_name']} ({result['packet_count']} packets)")
        
        # Save baseline
        print("\n💾 Saving baseline as 'production_baseline'...")
        baseline_file = orchestrator.save_baseline(test_results, name="production_baseline")
        
        print(f"✓ Baseline saved to: {baseline_file}")
        print(f"✓ Contains {len(test_results)} test results")
        
        # Show baseline content
        with open(baseline_file, 'r') as f:
            baseline_data = json.load(f)
        
        print("\n📄 Baseline Summary:")
        print(f"  Name: {baseline_data['name']}")
        print(f"  Timestamp: {baseline_data['timestamp']}")
        print(f"  Total Tests: {baseline_data['total_tests']}")
        print(f"  Passed: {baseline_data['passed_tests']}")
        print(f"  Failed: {baseline_data['failed_tests']}")


def demo_compare_with_regression():
    """Demonstrate comparing with baseline and detecting regressions."""
    print_section("DEMO 2: Compare with Baseline (Regression Detected)")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        orchestrator = CLIValidationOrchestrator(baselines_dir=Path(tmpdir) / "baselines")
        
        # Save baseline with all passing tests
        baseline_results = [
            {
                'attack_name': 'fake_disorder',
                'passed': True,
                'packet_count': 10,
                'validation_passed': True,
                'validation_issues': [],
                'execution_time': 0.5,
                'metadata': {'domain': 'example.com'}
            },
            {
                'attack_name': 'multisplit',
                'passed': True,
                'packet_count': 15,
                'validation_passed': True,
                'validation_issues': [],
                'execution_time': 0.7,
                'metadata': {'domain': 'example.com'}
            }
        ]
        
        print("\n📊 Baseline Results (saved earlier):")
        for result in baseline_results:
            print(f"  ✓ PASS - {result['attack_name']} ({result['packet_count']} packets)")
        
        orchestrator.save_baseline(baseline_results, name="baseline")
        
        # Simulate new test run with regression
        current_results = [
            {
                'attack_name': 'fake_disorder',
                'passed': False,  # REGRESSION!
                'packet_count': 0,
                'validation_passed': False,
                'validation_issues': ['Attack failed to execute'],
                'execution_time': 0.3,
                'metadata': {'domain': 'example.com'}
            },
            {
                'attack_name': 'multisplit',
                'passed': True,
                'packet_count': 15,
                'validation_passed': True,
                'validation_issues': [],
                'execution_time': 0.7,
                'metadata': {'domain': 'example.com'}
            }
        ]
        
        print("\n📊 Current Results (new test run):")
        for result in current_results:
            status = "✓ PASS" if result['passed'] else "✗ FAIL"
            print(f"  {status} - {result['attack_name']} ({result['packet_count']} packets)")
        
        # Compare with baseline
        print("\n🔍 Comparing with baseline...")
        comparison = orchestrator.compare_with_baseline(current_results, baseline_name="baseline")
        
        print("\n" + "=" * 70)
        print("BASELINE COMPARISON RESULTS")
        print("=" * 70)
        print(f"Baseline: {comparison.baseline_name}")
        print(f"Total Tests: {comparison.total_tests}")
        print(f"Regressions: {len(comparison.regressions)}")
        print(f"Improvements: {len(comparison.improvements)}")
        print(f"Unchanged: {comparison.unchanged}")
        
        if comparison.regressions:
            print("\n⚠️  REGRESSIONS DETECTED:")
            for reg in comparison.regressions:
                print(f"  [{reg.severity.value.upper()}] {reg.attack_name}")
                print(f"    {reg.description}")
                print(f"    Baseline: {reg.baseline_status} → Current: {reg.current_status}")
        
        print("=" * 70)


def demo_compare_with_improvement():
    """Demonstrate comparing with baseline and detecting improvements."""
    print_section("DEMO 3: Compare with Baseline (Improvement Detected)")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        orchestrator = CLIValidationOrchestrator(baselines_dir=Path(tmpdir) / "baselines")
        
        # Save baseline with failing test
        baseline_results = [
            {
                'attack_name': 'fake_disorder',
                'passed': False,
                'packet_count': 0,
                'validation_passed': False,
                'validation_issues': ['Attack failed'],
                'execution_time': 0.3,
                'metadata': {'domain': 'example.com'}
            },
            {
                'attack_name': 'multisplit',
                'passed': True,
                'packet_count': 15,
                'validation_passed': True,
                'validation_issues': [],
                'execution_time': 0.7,
                'metadata': {'domain': 'example.com'}
            }
        ]
        
        print("\n📊 Baseline Results (saved earlier):")
        for result in baseline_results:
            status = "✓ PASS" if result['passed'] else "✗ FAIL"
            print(f"  {status} - {result['attack_name']} ({result['packet_count']} packets)")
        
        orchestrator.save_baseline(baseline_results, name="baseline")
        
        # Simulate new test run with improvement
        current_results = [
            {
                'attack_name': 'fake_disorder',
                'passed': True,  # IMPROVEMENT!
                'packet_count': 10,
                'validation_passed': True,
                'validation_issues': [],
                'execution_time': 0.5,
                'metadata': {'domain': 'example.com'}
            },
            {
                'attack_name': 'multisplit',
                'passed': True,
                'packet_count': 15,
                'validation_passed': True,
                'validation_issues': [],
                'execution_time': 0.7,
                'metadata': {'domain': 'example.com'}
            }
        ]
        
        print("\n📊 Current Results (new test run):")
        for result in current_results:
            status = "✓ PASS" if result['passed'] else "✗ FAIL"
            print(f"  {status} - {result['attack_name']} ({result['packet_count']} packets)")
        
        # Compare with baseline
        print("\n🔍 Comparing with baseline...")
        comparison = orchestrator.compare_with_baseline(current_results, baseline_name="baseline")
        
        print("\n" + "=" * 70)
        print("BASELINE COMPARISON RESULTS")
        print("=" * 70)
        print(f"Baseline: {comparison.baseline_name}")
        print(f"Total Tests: {comparison.total_tests}")
        print(f"Regressions: {len(comparison.regressions)}")
        print(f"Improvements: {len(comparison.improvements)}")
        print(f"Unchanged: {comparison.unchanged}")
        
        if comparison.improvements:
            print("\n✓ IMPROVEMENTS:")
            for imp in comparison.improvements:
                print(f"  [IMPROVEMENT] {imp.attack_name}")
                print(f"    {imp.description}")
                print(f"    Baseline: {imp.baseline_status} → Current: {imp.current_status}")
        
        print("=" * 70)


def demo_cli_usage():
    """Show CLI usage examples."""
    print_section("DEMO 4: CLI Usage Examples")
    
    print("\n📝 How to use baseline comparison in CLI:")
    print("\n1. Save a baseline:")
    print("   $ python cli.py example.com --validate --save-baseline my_baseline")
    
    print("\n2. Compare with baseline:")
    print("   $ python cli.py example.com --validate --validate-baseline my_baseline")
    
    print("\n3. Compare and save new baseline:")
    print("   $ python cli.py example.com --validate \\")
    print("       --validate-baseline old_baseline \\")
    print("       --save-baseline new_baseline")
    
    print("\n4. Test multiple domains:")
    print("   $ python cli.py -d sites.txt --validate \\")
    print("       --validate-baseline production \\")
    print("       --save-baseline daily_$(date +%Y%m%d)")
    
    print("\n📁 Baselines are stored in:")
    print("   baselines/")
    print("   ├── my_baseline.json")
    print("   ├── production.json")
    print("   ├── daily_20251006.json")
    print("   └── current_baseline.json -> my_baseline.json")


def main():
    """Run all demos."""
    print("\n" + "=" * 70)
    print("  CLI BASELINE COMPARISON - INTERACTIVE DEMO")
    print("  Task 6.4: Integrate baseline comparison into CLI workflow")
    print("=" * 70)
    
    try:
        demo_save_baseline()
        input("\nPress Enter to continue to next demo...")
        
        demo_compare_with_regression()
        input("\nPress Enter to continue to next demo...")
        
        demo_compare_with_improvement()
        input("\nPress Enter to continue to next demo...")
        
        demo_cli_usage()
        
        print("\n" + "=" * 70)
        print("  ✓ DEMO COMPLETE")
        print("=" * 70)
        print("\n🎉 Baseline comparison is successfully integrated into CLI workflow!")
        print("\n📚 For more information:")
        print("  - Full documentation: docs/CLI_BASELINE_COMPARISON.md")
        print("  - Quick start: CLI_BASELINE_COMPARISON_QUICK_START.md")
        print("  - Run tests: python test_cli_baseline_integration.py")
        
        return 0
        
    except Exception as e:
        print(f"\n✗ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
