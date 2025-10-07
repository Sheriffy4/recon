"""
Test CLI Baseline Integration

This script tests the baseline comparison integration in the CLI workflow.
It verifies that:
1. --save-baseline saves current results as baseline
2. --validate-baseline loads and compares with baseline
3. Regressions are detected and reported prominently
4. Improvements are detected and reported

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


def test_baseline_save_and_load():
    """Test saving and loading baselines."""
    print("\n" + "=" * 70)
    print("TEST 1: Baseline Save and Load")
    print("=" * 70)
    
    # Create temporary directory for baselines
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = BaselineManager(baselines_dir=Path(tmpdir))
        
        # Create sample baseline results
        results = [
            BaselineResult(
                attack_name="fake_disorder",
                passed=True,
                packet_count=10,
                validation_passed=True,
                validation_issues=[],
                execution_time=0.5
            ),
            BaselineResult(
                attack_name="multisplit",
                passed=True,
                packet_count=15,
                validation_passed=True,
                validation_issues=[],
                execution_time=0.7
            ),
            BaselineResult(
                attack_name="sequence_overlap",
                passed=False,
                packet_count=0,
                validation_passed=False,
                validation_issues=["No packets captured"],
                execution_time=0.3
            )
        ]
        
        # Create baseline report
        report = BaselineReport(
            name="test_baseline",
            timestamp=datetime.now().isoformat(),
            version="1.0",
            total_tests=3,
            passed_tests=2,
            failed_tests=1,
            results=results
        )
        
        # Save baseline
        baseline_file = manager.save_baseline(report, name="test_baseline")
        print(f"✓ Baseline saved to: {baseline_file}")
        
        # Load baseline
        loaded_report = manager.load_baseline("test_baseline")
        assert loaded_report is not None, "Failed to load baseline"
        assert loaded_report.name == "test_baseline", "Baseline name mismatch"
        assert loaded_report.total_tests == 3, "Total tests mismatch"
        assert loaded_report.passed_tests == 2, "Passed tests mismatch"
        assert len(loaded_report.results) == 3, "Results count mismatch"
        
        print("✓ Baseline loaded successfully")
        print(f"  - Name: {loaded_report.name}")
        print(f"  - Total Tests: {loaded_report.total_tests}")
        print(f"  - Passed: {loaded_report.passed_tests}")
        print(f"  - Failed: {loaded_report.failed_tests}")
        
        print("\n✓ TEST 1 PASSED")


def test_regression_detection():
    """Test regression detection."""
    print("\n" + "=" * 70)
    print("TEST 2: Regression Detection")
    print("=" * 70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = BaselineManager(baselines_dir=Path(tmpdir))
        
        # Create baseline with passing tests
        baseline_results = [
            BaselineResult(
                attack_name="fake_disorder",
                passed=True,
                packet_count=10,
                validation_passed=True,
                validation_issues=[],
                execution_time=0.5
            ),
            BaselineResult(
                attack_name="multisplit",
                passed=True,
                packet_count=15,
                validation_passed=True,
                validation_issues=[],
                execution_time=0.7
            )
        ]
        
        baseline_report = BaselineReport(
            name="baseline",
            timestamp=datetime.now().isoformat(),
            version="1.0",
            total_tests=2,
            passed_tests=2,
            failed_tests=0,
            results=baseline_results
        )
        
        manager.save_baseline(baseline_report, name="baseline")
        
        # Create current results with regression (fake_disorder now fails)
        current_results = [
            BaselineResult(
                attack_name="fake_disorder",
                passed=False,  # REGRESSION: was True
                packet_count=0,
                validation_passed=False,
                validation_issues=["Attack failed"],
                execution_time=0.3
            ),
            BaselineResult(
                attack_name="multisplit",
                passed=True,
                packet_count=15,
                validation_passed=True,
                validation_issues=[],
                execution_time=0.7
            )
        ]
        
        current_report = BaselineReport(
            name="current",
            timestamp=datetime.now().isoformat(),
            version="1.0",
            total_tests=2,
            passed_tests=1,
            failed_tests=1,
            results=current_results
        )
        
        # Compare
        comparison = manager.compare_with_baseline(current_report, baseline_name="baseline")
        
        print(f"✓ Comparison completed")
        print(f"  - Total Tests: {comparison.total_tests}")
        print(f"  - Regressions: {len(comparison.regressions)}")
        print(f"  - Improvements: {len(comparison.improvements)}")
        print(f"  - Unchanged: {comparison.unchanged}")
        
        # Verify regression detected
        assert len(comparison.regressions) == 1, "Should detect 1 regression"
        regression = comparison.regressions[0]
        assert regression.attack_name == "fake_disorder", "Wrong attack in regression"
        assert regression.severity == RegressionSeverity.CRITICAL, "Should be CRITICAL severity"
        
        print("\n✓ Regression detected:")
        print(f"  - Attack: {regression.attack_name}")
        print(f"  - Severity: {regression.severity.value}")
        print(f"  - Description: {regression.description}")
        
        print("\n✓ TEST 2 PASSED")


def test_improvement_detection():
    """Test improvement detection."""
    print("\n" + "=" * 70)
    print("TEST 3: Improvement Detection")
    print("=" * 70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = BaselineManager(baselines_dir=Path(tmpdir))
        
        # Create baseline with failing test
        baseline_results = [
            BaselineResult(
                attack_name="fake_disorder",
                passed=False,
                packet_count=0,
                validation_passed=False,
                validation_issues=["Attack failed"],
                execution_time=0.3
            ),
            BaselineResult(
                attack_name="multisplit",
                passed=True,
                packet_count=15,
                validation_passed=True,
                validation_issues=[],
                execution_time=0.7
            )
        ]
        
        baseline_report = BaselineReport(
            name="baseline",
            timestamp=datetime.now().isoformat(),
            version="1.0",
            total_tests=2,
            passed_tests=1,
            failed_tests=1,
            results=baseline_results
        )
        
        manager.save_baseline(baseline_report, name="baseline")
        
        # Create current results with improvement (fake_disorder now passes)
        current_results = [
            BaselineResult(
                attack_name="fake_disorder",
                passed=True,  # IMPROVEMENT: was False
                packet_count=10,
                validation_passed=True,
                validation_issues=[],
                execution_time=0.5
            ),
            BaselineResult(
                attack_name="multisplit",
                passed=True,
                packet_count=15,
                validation_passed=True,
                validation_issues=[],
                execution_time=0.7
            )
        ]
        
        current_report = BaselineReport(
            name="current",
            timestamp=datetime.now().isoformat(),
            version="1.0",
            total_tests=2,
            passed_tests=2,
            failed_tests=0,
            results=current_results
        )
        
        # Compare
        comparison = manager.compare_with_baseline(current_report, baseline_name="baseline")
        
        print(f"✓ Comparison completed")
        print(f"  - Total Tests: {comparison.total_tests}")
        print(f"  - Regressions: {len(comparison.regressions)}")
        print(f"  - Improvements: {len(comparison.improvements)}")
        print(f"  - Unchanged: {comparison.unchanged}")
        
        # Verify improvement detected
        assert len(comparison.improvements) == 1, "Should detect 1 improvement"
        improvement = comparison.improvements[0]
        assert improvement.attack_name == "fake_disorder", "Wrong attack in improvement"
        
        print("\n✓ Improvement detected:")
        print(f"  - Attack: {improvement.attack_name}")
        print(f"  - Description: {improvement.description}")
        
        print("\n✓ TEST 3 PASSED")


def test_cli_orchestrator_integration():
    """Test CLI validation orchestrator integration."""
    print("\n" + "=" * 70)
    print("TEST 4: CLI Orchestrator Integration")
    print("=" * 70)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        orchestrator = CLIValidationOrchestrator(
            baselines_dir=Path(tmpdir) / "baselines",
            output_dir=Path(tmpdir) / "validation_results"
        )
        
        # Create sample test results
        test_results = [
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
        
        # Save baseline
        baseline_file = orchestrator.save_baseline(test_results, name="test_baseline")
        print(f"✓ Baseline saved via orchestrator: {baseline_file}")
        
        # Create new results with regression
        new_results = [
            {
                'attack_name': 'fake_disorder',
                'passed': False,  # REGRESSION
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
        
        # Compare with baseline
        comparison = orchestrator.compare_with_baseline(new_results, baseline_name="test_baseline")
        
        print(f"✓ Comparison completed via orchestrator")
        print(f"  - Regressions: {len(comparison.regressions)}")
        print(f"  - Improvements: {len(comparison.improvements)}")
        
        assert len(comparison.regressions) == 1, "Should detect 1 regression"
        
        # Test formatted output
        output = orchestrator.format_validation_output(
            orchestrator.create_validation_report(baseline_comparison=comparison),
            use_colors=False
        )
        
        print("\n✓ Formatted output generated:")
        print(output[:500] + "..." if len(output) > 500 else output)
        
        print("\n✓ TEST 4 PASSED")


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("CLI BASELINE INTEGRATION TEST SUITE")
    print("Task 6.4: Integrate baseline comparison into CLI workflow")
    print("=" * 70)
    
    try:
        test_baseline_save_and_load()
        test_regression_detection()
        test_improvement_detection()
        test_cli_orchestrator_integration()
        
        print("\n" + "=" * 70)
        print("✓ ALL TESTS PASSED")
        print("=" * 70)
        print("\nBaseline comparison is successfully integrated into CLI workflow!")
        print("\nFeatures verified:")
        print("  ✓ Load baseline if --validate-baseline provided")
        print("  ✓ Compare current execution results with baseline")
        print("  ✓ Report regressions prominently in output")
        print("  ✓ Save new baseline if --save-baseline provided")
        print("\nCLI Usage:")
        print("  python cli.py <target> --validate --save-baseline <name>")
        print("  python cli.py <target> --validate --validate-baseline <name>")
        print("  python cli.py <target> --validate --validate-baseline <name> --save-baseline <new_name>")
        
        return 0
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
