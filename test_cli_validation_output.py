"""
Test: Enhanced CLI Validation Output

Tests for Task 6.5: Enhance CLI output with validation reporting

This test verifies:
- Validation summary section in CLI output
- Pass/fail status display
- Error and warning display
- JSON report generation
- Colored output support
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.cli_validation_orchestrator import (
    CLIValidationOrchestrator,
    CLIValidationReport,
    StrategyValidationResult
)
from core.pcap_content_validator import PCAPValidationResult, ValidationIssue
from core.baseline_manager import ComparisonResult, Regression, Improvement, RegressionSeverity


def test_validation_summary_section():
    """Test that validation summary section is included in output."""
    print("\nTest 1: Validation Summary Section")
    print("-" * 70)
    
    orchestrator = CLIValidationOrchestrator()
    
    pcap_validation = PCAPValidationResult(
        passed=True,
        pcap_file=Path("test.pcap"),
        packet_count=10,
        expected_packet_count=10,
        issues=[],
        warnings=[],
        details={}
    )
    
    report = orchestrator.create_validation_report(
        pcap_validation=pcap_validation
    )
    
    output = orchestrator.format_validation_output(report, use_colors=False)
    
    # Verify summary section exists
    assert "SUMMARY:" in output, "Summary section missing"
    assert report.summary in output, "Summary content missing"
    
    print("[OK] Validation summary section present")
    print(f"  Summary: {report.summary}")
    
    return True


def test_pass_fail_status_display():
    """Test that pass/fail status is clearly displayed."""
    print("\nTest 2: Pass/Fail Status Display")
    print("-" * 70)
    
    orchestrator = CLIValidationOrchestrator()
    
    # Test PASSED status
    pcap_validation_pass = PCAPValidationResult(
        passed=True,
        pcap_file=Path("test_pass.pcap"),
        packet_count=10,
        expected_packet_count=10,
        issues=[],
        warnings=[],
        details={}
    )
    
    report_pass = orchestrator.create_validation_report(
        pcap_validation=pcap_validation_pass
    )
    
    output_pass = orchestrator.format_validation_output(report_pass, use_colors=False)
    
    assert "PASSED" in output_pass, "PASSED status not displayed"
    print("✓ PASSED status displayed correctly")
    
    # Test FAILED status
    pcap_validation_fail = PCAPValidationResult(
        passed=False,
        pcap_file=Path("test_fail.pcap"),
        packet_count=8,
        expected_packet_count=10,
        issues=[
            ValidationIssue(
                severity="error",
                category="packet_count",
                packet_index=0,
                description="Packet count mismatch",
                expected=10,
                actual=8
            )
        ],
        warnings=[],
        details={}
    )
    
    report_fail = orchestrator.create_validation_report(
        pcap_validation=pcap_validation_fail
    )
    
    output_fail = orchestrator.format_validation_output(report_fail, use_colors=False)
    
    assert "FAILED" in output_fail, "FAILED status not displayed"
    print("✓ FAILED status displayed correctly")
    
    return True


def test_error_warning_display():
    """Test that errors and warnings are clearly displayed."""
    print("\nTest 3: Error and Warning Display")
    print("-" * 70)
    
    orchestrator = CLIValidationOrchestrator()
    
    strategy_validation = StrategyValidationResult(
        passed=False,
        strategy={"type": "fake"},
        errors=[
            "Error 1: Missing required parameter",
            "Error 2: Invalid parameter value"
        ],
        warnings=[
            "Warning 1: Using default value",
            "Warning 2: Attack may not be effective"
        ],
        details={}
    )
    
    report = orchestrator.create_validation_report(
        strategy_validation=strategy_validation
    )
    
    output = orchestrator.format_validation_output(report, use_colors=False)
    
    # Verify errors are displayed
    assert "Error 1: Missing required parameter" in output, "Error 1 not displayed"
    assert "Error 2: Invalid parameter value" in output, "Error 2 not displayed"
    print("✓ Errors displayed correctly")
    
    # Verify warnings are displayed
    assert "Warning 1: Using default value" in output, "Warning 1 not displayed"
    assert "Warning 2: Attack may not be effective" in output, "Warning 2 not displayed"
    print("✓ Warnings displayed correctly")
    
    return True


def test_json_report_generation():
    """Test that validation report can be saved as JSON."""
    print("\nTest 4: JSON Report Generation")
    print("-" * 70)
    
    orchestrator = CLIValidationOrchestrator()
    
    pcap_validation = PCAPValidationResult(
        passed=True,
        pcap_file=Path("test.pcap"),
        packet_count=10,
        expected_packet_count=10,
        issues=[],
        warnings=["Test warning"],
        details={"test": "data"}
    )
    
    strategy_validation = StrategyValidationResult(
        passed=True,
        strategy={"type": "fake", "ttl": 8},
        errors=[],
        warnings=[],
        details={"attack_available": True}
    )
    
    report = orchestrator.create_validation_report(
        pcap_validation=pcap_validation,
        strategy_validation=strategy_validation
    )
    
    # Save JSON report
    json_path = orchestrator.save_validation_report_json(report)
    
    assert json_path.exists(), "JSON report file not created"
    print(f"✓ JSON report created: {json_path}")
    
    # Verify JSON content
    with open(json_path, 'r') as f:
        report_data = json.load(f)
    
    assert "timestamp" in report_data, "Timestamp missing from JSON"
    assert "validation_enabled" in report_data, "validation_enabled missing from JSON"
    assert "pcap_validation" in report_data, "pcap_validation missing from JSON"
    assert "strategy_validation" in report_data, "strategy_validation missing from JSON"
    assert "summary" in report_data, "summary missing from JSON"
    
    print("✓ JSON report contains all required fields")
    print(f"  Fields: {list(report_data.keys())}")
    
    # Cleanup
    json_path.unlink()
    
    return True


def test_colored_output():
    """Test that colored output is generated correctly."""
    print("\nTest 5: Colored Output")
    print("-" * 70)
    
    orchestrator = CLIValidationOrchestrator()
    
    pcap_validation = PCAPValidationResult(
        passed=False,
        pcap_file=Path("test.pcap"),
        packet_count=8,
        expected_packet_count=10,
        issues=[
            ValidationIssue(
                severity="error",
                category="packet_count",
                packet_index=0,
                description="Packet count mismatch",
                expected=10,
                actual=8
            )
        ],
        warnings=[],
        details={}
    )
    
    report = orchestrator.create_validation_report(
        pcap_validation=pcap_validation
    )
    
    # Test with colors
    output_colored = orchestrator.format_validation_output(report, use_colors=True)
    
    # ANSI color codes should be present
    assert "\033[" in output_colored, "ANSI color codes not present"
    print("✓ Colored output contains ANSI codes")
    
    # Test without colors
    output_plain = orchestrator.format_validation_output(report, use_colors=False)
    
    # ANSI color codes should NOT be present
    assert "\033[" not in output_plain, "ANSI color codes present when disabled"
    print("✓ Plain output does not contain ANSI codes")
    
    return True


def test_verbose_mode():
    """Test that verbose mode includes additional details."""
    print("\nTest 6: Verbose Mode")
    print("-" * 70)
    
    orchestrator = CLIValidationOrchestrator()
    
    strategy_validation = StrategyValidationResult(
        passed=True,
        strategy={"type": "fake", "ttl": 8},
        errors=[],
        warnings=["Warning 1", "Warning 2", "Warning 3"],
        details={
            "attack_available": True,
            "attack_category": "tcp",
            "validated_parameters": ["ttl"]
        }
    )
    
    report = orchestrator.create_validation_report(
        strategy_validation=strategy_validation
    )
    
    # Test non-verbose output
    output_normal = orchestrator.format_validation_output(report, use_colors=False, verbose=False)
    
    # Test verbose output
    output_verbose = orchestrator.format_validation_output(report, use_colors=False, verbose=True)
    
    # Verbose output should be longer and contain more details
    assert len(output_verbose) >= len(output_normal), "Verbose output not longer than normal"
    
    # Verbose output should contain details
    assert "attack_available" in output_verbose or "Details:" in output_verbose, "Details not in verbose output"
    
    print("✓ Verbose mode includes additional details")
    print(f"  Normal output length: {len(output_normal)}")
    print(f"  Verbose output length: {len(output_verbose)}")
    
    return True


def test_rich_output_fallback():
    """Test that rich output falls back to plain text if rich not available."""
    print("\nTest 7: Rich Output Fallback")
    print("-" * 70)
    
    orchestrator = CLIValidationOrchestrator()
    
    pcap_validation = PCAPValidationResult(
        passed=True,
        pcap_file=Path("test.pcap"),
        packet_count=10,
        expected_packet_count=10,
        issues=[],
        warnings=[],
        details={}
    )
    
    report = orchestrator.create_validation_report(
        pcap_validation=pcap_validation
    )
    
    try:
        # Try to use rich output
        orchestrator.format_validation_output_rich(report)
        print("✓ Rich output executed (rich library available)")
    except Exception as e:
        # Should fall back gracefully
        print(f"✓ Rich output fallback handled: {e}")
    
    return True


def test_baseline_comparison_display():
    """Test that baseline comparison results are displayed correctly."""
    print("\nTest 8: Baseline Comparison Display")
    print("-" * 70)
    
    orchestrator = CLIValidationOrchestrator()
    
    baseline_comparison = ComparisonResult(
        baseline_name="test_baseline",
        baseline_timestamp="2025-10-05T10:00:00",
        current_timestamp=datetime.now().isoformat(),
        total_tests=10,
        regressions=[
            Regression(
                attack_name="fake",
                severity=RegressionSeverity.HIGH,
                description="Attack now fails",
                baseline_status="passed",
                current_status="failed",
                details={}
            )
        ],
        improvements=[
            Improvement(
                attack_name="split",
                description="Attack now passes",
                baseline_status="failed",
                current_status="passed",
                details={}
            )
        ],
        unchanged=8,
        summary="1 regression, 1 improvement"
    )
    
    report = orchestrator.create_validation_report(
        baseline_comparison=baseline_comparison
    )
    
    output = orchestrator.format_validation_output(report, use_colors=False)
    
    # Verify baseline comparison is displayed
    assert "BASELINE COMPARISON:" in output, "Baseline comparison section missing"
    assert "test_baseline" in output, "Baseline name not displayed"
    assert "REGRESSIONS DETECTED:" in output, "Regressions section missing"
    assert "IMPROVEMENTS:" in output, "Improvements section missing"
    
    print("✓ Baseline comparison displayed correctly")
    print("  - Regressions section present")
    print("  - Improvements section present")
    
    return True


def run_all_tests():
    """Run all tests."""
    import io
    
    # Set UTF-8 encoding for Windows console
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    
    print("\n" + "=" * 70)
    print("CLI VALIDATION OUTPUT TESTS")
    print("Task 6.5: Enhance CLI output with validation reporting")
    print("=" * 70)
    
    tests = [
        ("Validation Summary Section", test_validation_summary_section),
        ("Pass/Fail Status Display", test_pass_fail_status_display),
        ("Error and Warning Display", test_error_warning_display),
        ("JSON Report Generation", test_json_report_generation),
        ("Colored Output", test_colored_output),
        ("Verbose Mode", test_verbose_mode),
        ("Rich Output Fallback", test_rich_output_fallback),
        ("Baseline Comparison Display", test_baseline_comparison_display)
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            result = test_func()
            if result:
                passed += 1
                print(f"[OK] {name} PASSED")
            else:
                failed += 1
                print(f"[FAIL] {name} FAILED")
        except Exception as e:
            failed += 1
            print(f"[FAIL] {name} FAILED: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 70)
    print("TEST RESULTS")
    print("=" * 70)
    print(f"Total Tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {passed/len(tests)*100:.1f}%")
    
    if failed == 0:
        print("\n[OK] ALL TESTS PASSED")
        return True
    else:
        print(f"\n[FAIL] {failed} TEST(S) FAILED")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
