"""
Demo: Enhanced CLI Validation Output

This script demonstrates the enhanced CLI validation reporting features:
- Colored output with clear status indicators
- Validation summary section
- Error and warning display
- JSON report generation
- Rich library integration (if available)

Part of Task 6.5: Enhance CLI output with validation reporting
"""

import sys
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


def create_sample_pcap_validation() -> PCAPValidationResult:
    """Create sample PCAP validation result."""
    return PCAPValidationResult(
        passed=False,
        pcap_file=Path("test.pcap"),
        packet_count=10,
        expected_packet_count=12,
        issues=[
            ValidationIssue(
                severity="error",
                category="packet_count",
                packet_index=0,
                description="Expected 12 packets but found 10",
                expected=12,
                actual=10
            ),
            ValidationIssue(
                severity="warning",
                category="checksum",
                packet_index=3,
                description="Checksum validation failed",
                expected="good",
                actual="bad"
            ),
            ValidationIssue(
                severity="error",
                category="ttl",
                packet_index=5,
                description="TTL value incorrect",
                expected=64,
                actual=128
            )
        ],
        warnings=[
            "Packet 7: Sequence number gap detected",
            "Packet 9: TCP flags unusual combination"
        ],
        details={
            "capture_duration": 2.5,
            "protocol_distribution": {"TCP": 8, "UDP": 2}
        }
    )


def create_sample_strategy_validation() -> StrategyValidationResult:
    """Create sample strategy validation result."""
    return StrategyValidationResult(
        passed=False,
        strategy={
            "type": "multisplit",
            "split_count": 3,
            "split_position": "middle"
        },
        errors=[
            "Parameter 'split_count' exceeds maximum value of 2",
            "Attack type 'multisplit' requires parameter 'disorder' which is missing"
        ],
        warnings=[
            "Parameter 'split_position' using default value",
            "Attack may not be effective against modern DPI systems"
        ],
        details={
            "attack_available": True,
            "attack_category": "tcp",
            "validated_parameters": ["split_count", "split_position"]
        }
    )


def create_sample_baseline_comparison() -> ComparisonResult:
    """Create sample baseline comparison result."""
    return ComparisonResult(
        baseline_name="baseline_20251005_v1",
        baseline_timestamp="2025-10-05T10:00:00",
        current_timestamp=datetime.now().isoformat(),
        total_tests=20,
        regressions=[
            Regression(
                attack_name="fake",
                severity=RegressionSeverity.HIGH,
                description="Attack now fails (was passing in baseline)",
                baseline_status="passed",
                current_status="failed",
                details={"error": "Connection timeout"}
            ),
            Regression(
                attack_name="disorder",
                severity=RegressionSeverity.MEDIUM,
                description="Packet count decreased from 5 to 3",
                baseline_status="passed",
                current_status="passed",
                details={"baseline_packets": 5, "current_packets": 3}
            )
        ],
        improvements=[
            Improvement(
                attack_name="split",
                description="Attack now passes (was failing in baseline)",
                baseline_status="failed",
                current_status="passed",
                details={"fix": "TTL parameter corrected"}
            ),
            Improvement(
                attack_name="multidisorder",
                description="Execution time improved from 2.5s to 1.2s",
                baseline_status="passed",
                current_status="passed",
                details={"baseline_time": 2.5, "current_time": 1.2}
            )
        ],
        unchanged=16,
        summary="2 regressions detected, 2 improvements found"
    )


def demo_plain_text_output():
    """Demonstrate plain text output with colors."""
    print("\n" + "=" * 70)
    print("DEMO 1: Plain Text Output (with colors)")
    print("=" * 70 + "\n")
    
    orchestrator = CLIValidationOrchestrator()
    
    # Create sample validation results
    pcap_validation = create_sample_pcap_validation()
    strategy_validation = create_sample_strategy_validation()
    baseline_comparison = create_sample_baseline_comparison()
    
    # Create validation report
    report = orchestrator.create_validation_report(
        pcap_validation=pcap_validation,
        strategy_validation=strategy_validation,
        baseline_comparison=baseline_comparison,
        baseline_saved="baseline_20251006_v2"
    )
    
    # Format and display output
    output = orchestrator.format_validation_output(
        report,
        use_colors=True,
        verbose=False
    )
    print(output)


def demo_verbose_output():
    """Demonstrate verbose output."""
    print("\n" + "=" * 70)
    print("DEMO 2: Verbose Output")
    print("=" * 70 + "\n")
    
    orchestrator = CLIValidationOrchestrator()
    
    # Create sample validation results
    pcap_validation = create_sample_pcap_validation()
    strategy_validation = create_sample_strategy_validation()
    
    # Create validation report
    report = orchestrator.create_validation_report(
        pcap_validation=pcap_validation,
        strategy_validation=strategy_validation
    )
    
    # Format and display verbose output
    output = orchestrator.format_validation_output(
        report,
        use_colors=True,
        verbose=True
    )
    print(output)


def demo_json_report():
    """Demonstrate JSON report generation."""
    print("\n" + "=" * 70)
    print("DEMO 3: JSON Report Generation")
    print("=" * 70 + "\n")
    
    orchestrator = CLIValidationOrchestrator()
    
    # Create sample validation results
    pcap_validation = create_sample_pcap_validation()
    strategy_validation = create_sample_strategy_validation()
    baseline_comparison = create_sample_baseline_comparison()
    
    # Create validation report
    report = orchestrator.create_validation_report(
        pcap_validation=pcap_validation,
        strategy_validation=strategy_validation,
        baseline_comparison=baseline_comparison
    )
    
    # Save JSON report
    json_path = orchestrator.save_validation_report_json(report)
    
    print(f"✓ JSON report saved to: {json_path}")
    print(f"\nReport contents preview:")
    print("-" * 70)
    
    import json
    with open(json_path, 'r') as f:
        report_data = json.load(f)
        print(json.dumps(report_data, indent=2)[:1000] + "...")


def demo_rich_output():
    """Demonstrate rich library output."""
    print("\n" + "=" * 70)
    print("DEMO 4: Rich Library Output")
    print("=" * 70 + "\n")
    
    try:
        from rich.console import Console
        
        orchestrator = CLIValidationOrchestrator()
        console = Console()
        
        # Create sample validation results
        pcap_validation = create_sample_pcap_validation()
        strategy_validation = create_sample_strategy_validation()
        baseline_comparison = create_sample_baseline_comparison()
        
        # Create validation report
        report = orchestrator.create_validation_report(
            pcap_validation=pcap_validation,
            strategy_validation=strategy_validation,
            baseline_comparison=baseline_comparison
        )
        
        # Display using rich
        orchestrator.format_validation_output_rich(report, console)
        
    except ImportError:
        print("⚠ Rich library not available. Install with: pip install rich")
        print("Falling back to plain text output...")
        demo_plain_text_output()


def demo_no_colors():
    """Demonstrate output without colors (for CI/CD)."""
    print("\n" + "=" * 70)
    print("DEMO 5: Output Without Colors (CI/CD mode)")
    print("=" * 70 + "\n")
    
    orchestrator = CLIValidationOrchestrator()
    
    # Create sample validation results
    pcap_validation = create_sample_pcap_validation()
    strategy_validation = create_sample_strategy_validation()
    
    # Create validation report
    report = orchestrator.create_validation_report(
        pcap_validation=pcap_validation,
        strategy_validation=strategy_validation
    )
    
    # Format and display output without colors
    output = orchestrator.format_validation_output(
        report,
        use_colors=False,
        verbose=False
    )
    print(output)


def demo_success_case():
    """Demonstrate successful validation output."""
    print("\n" + "=" * 70)
    print("DEMO 6: Successful Validation (All Passed)")
    print("=" * 70 + "\n")
    
    orchestrator = CLIValidationOrchestrator()
    
    # Create successful validation results
    pcap_validation = PCAPValidationResult(
        passed=True,
        pcap_file=Path("test_success.pcap"),
        packet_count=10,
        expected_packet_count=10,
        issues=[],
        warnings=[],
        details={"all_checks_passed": True}
    )
    
    strategy_validation = StrategyValidationResult(
        passed=True,
        strategy={"type": "fake", "ttl": 8},
        errors=[],
        warnings=[],
        details={"attack_available": True}
    )
    
    # Create validation report
    report = orchestrator.create_validation_report(
        pcap_validation=pcap_validation,
        strategy_validation=strategy_validation
    )
    
    # Format and display output
    output = orchestrator.format_validation_output(
        report,
        use_colors=True,
        verbose=False
    )
    print(output)


def main():
    """Run all demos."""
    import sys
    import io
    
    # Set UTF-8 encoding for Windows console
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    
    print("\n" + "=" * 70)
    print("CLI VALIDATION OUTPUT ENHANCEMENT DEMO")
    print("Task 6.5: Enhance CLI output with validation reporting")
    print("=" * 70)
    
    demos = [
        ("Plain Text Output (with colors)", demo_plain_text_output),
        ("Verbose Output", demo_verbose_output),
        ("JSON Report Generation", demo_json_report),
        ("Rich Library Output", demo_rich_output),
        ("Output Without Colors", demo_no_colors),
        ("Successful Validation", demo_success_case)
    ]
    
    for i, (name, demo_func) in enumerate(demos, 1):
        try:
            demo_func()
            print(f"\n[OK] Demo {i} completed successfully\n")
        except Exception as e:
            print(f"\n[FAIL] Demo {i} failed: {e}\n")
            import traceback
            traceback.print_exc()
        
        if i < len(demos):
            input("\nPress Enter to continue to next demo...")
    
    print("\n" + "=" * 70)
    print("ALL DEMOS COMPLETED")
    print("=" * 70 + "\n")
    
    print("Summary of features demonstrated:")
    print("  [OK] Colored output with status indicators")
    print("  [OK] Clear error and warning display")
    print("  [OK] Validation summary section")
    print("  [OK] JSON report generation")
    print("  [OK] Rich library integration (if available)")
    print("  [OK] Verbose mode for detailed information")
    print("  [OK] CI/CD mode without colors")
    print("  [OK] Success and failure cases")


if __name__ == "__main__":
    main()
