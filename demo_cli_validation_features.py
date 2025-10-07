"""
Demo: CLI Validation Features

This script demonstrates the validation features integrated into the CLI.

Usage:
    python demo_cli_validation_features.py

Part of Phase 6: CLI Integration for Attack Validation Production Readiness
"""

import sys
import subprocess
from pathlib import Path
from datetime import datetime


def print_section(title):
    """Print a section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70 + "\n")


def run_command(cmd, description):
    """Run a command and display output."""
    print(f"Command: {' '.join(cmd)}")
    print(f"Description: {description}\n")
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    
    print("Output:")
    print(result.stdout)
    
    if result.stderr:
        print("Errors:")
        print(result.stderr)
    
    print(f"\nExit Code: {result.returncode}")
    
    return result.returncode == 0


def demo_help():
    """Demo: Show validation flags in help."""
    print_section("DEMO 1: Validation Flags in CLI Help")
    
    cmd = [sys.executable, "cli.py", "--help"]
    run_command(cmd, "Display CLI help showing validation flags")
    
    print("\nValidation flags available:")
    print("  --validate              Enable validation mode")
    print("  --validate-baseline     Compare with baseline")
    print("  --save-baseline         Save results as baseline")
    print("  --validate-pcap         Validate PCAP file")


def demo_validate_flag():
    """Demo: Using --validate flag."""
    print_section("DEMO 2: Using --validate Flag")
    
    print("The --validate flag enables validation during execution:")
    print("  - Validates generated strategies")
    print("  - Validates captured PCAP files")
    print("  - Adds validation results to report")
    print("\nExample command:")
    print("  python cli.py -t example.com --validate")
    print("\nNote: This demo doesn't run the actual command to avoid network calls.")


def demo_validate_pcap():
    """Demo: Using --validate-pcap flag."""
    print_section("DEMO 3: Using --validate-pcap Flag")
    
    print("The --validate-pcap flag validates a PCAP file and exits:")
    print("  - Validates packet structure")
    print("  - Checks sequence numbers, checksums, TTL, TCP flags")
    print("  - Displays detailed validation report")
    print("  - Exits with code 0 (pass) or 1 (fail)")
    print("\nExample command:")
    print("  python cli.py --validate-pcap output.pcap")
    print("\nNote: Requires a valid PCAP file to demonstrate.")


def demo_baseline_workflow():
    """Demo: Baseline workflow."""
    print_section("DEMO 4: Baseline Workflow")
    
    print("Complete baseline workflow:")
    print("\n1. Save initial baseline:")
    print("   python cli.py -t example.com --validate --save-baseline initial")
    print("\n2. Make changes to code/config")
    print("\n3. Compare with baseline:")
    print("   python cli.py -t example.com --validate --validate-baseline initial")
    print("\n4. If tests pass, save new baseline:")
    print("   python cli.py -t example.com --validate --save-baseline updated")
    print("\nBenefits:")
    print("  - Detect regressions automatically")
    print("  - Track improvements over time")
    print("  - Ensure consistent results")


def demo_validation_orchestrator():
    """Demo: CLIValidationOrchestrator."""
    print_section("DEMO 5: CLIValidationOrchestrator")
    
    try:
        from core.cli_validation_orchestrator import CLIValidationOrchestrator
        
        print("Creating CLIValidationOrchestrator instance...")
        orchestrator = CLIValidationOrchestrator()
        print("✓ CLIValidationOrchestrator created successfully")
        
        print("\nAvailable methods:")
        methods = [
            'validate_pcap',
            'validate_strategy',
            'compare_with_baseline',
            'save_baseline',
            'create_validation_report',
            'format_validation_output'
        ]
        
        for method in methods:
            if hasattr(orchestrator, method):
                print(f"  ✓ {method}()")
            else:
                print(f"  ✗ {method}() - NOT FOUND")
        
        print("\nThe orchestrator provides a unified interface for:")
        print("  - PCAP content validation")
        print("  - Strategy syntax validation")
        print("  - Baseline comparison")
        print("  - Validation result formatting")
        
    except ImportError as e:
        print(f"✗ Failed to import CLIValidationOrchestrator: {e}")
    except Exception as e:
        print(f"✗ Error: {e}")


def demo_strategy_validation():
    """Demo: Strategy validation."""
    print_section("DEMO 6: Strategy Validation")
    
    try:
        from core.cli_validation_orchestrator import CLIValidationOrchestrator
        
        orchestrator = CLIValidationOrchestrator()
        
        # Example strategies
        strategies = [
            {
                'type': 'fake_disorder',
                'ttl': 3,
                'split_pos': 3
            },
            {
                'type': 'multisplit',
                'ttl': 5,
                'split_count': 4,
                'split_seqovl': 10
            },
            {
                'type': 'invalid_attack',  # This should fail
                'param': 'value'
            }
        ]
        
        print("Validating example strategies...\n")
        
        for i, strategy in enumerate(strategies, 1):
            print(f"Strategy {i}: {strategy.get('type', 'unknown')}")
            
            try:
                result = orchestrator.validate_strategy(
                    strategy,
                    check_attack_availability=True
                )
                
                if result.passed:
                    print(f"  ✓ Validation PASSED")
                else:
                    print(f"  ✗ Validation FAILED")
                    for err in result.errors:
                        print(f"    - {err}")
                
                if result.warnings:
                    print(f"  Warnings:")
                    for warn in result.warnings:
                        print(f"    - {warn}")
                
            except Exception as e:
                print(f"  ✗ Error: {e}")
            
            print()
        
    except ImportError as e:
        print(f"✗ Failed to import required modules: {e}")
    except Exception as e:
        print(f"✗ Error: {e}")


def demo_validation_output():
    """Demo: Validation output formatting."""
    print_section("DEMO 7: Validation Output Formatting")
    
    print("Validation output features:")
    print("\n1. Colored Output:")
    print("   - Green: Pass/Success")
    print("   - Red: Fail/Error")
    print("   - Yellow: Warning")
    print("\n2. ASCII-Safe Symbols:")
    print("   - [OK] for success")
    print("   - [X] for failure")
    print("   - [!] for warning")
    print("\n3. Detailed Reports:")
    print("   - Strategy validation summary")
    print("   - PCAP validation results")
    print("   - Baseline comparison")
    print("   - JSON reports saved to files")
    print("\n4. Progress Indicators:")
    print("   - Validation in progress messages")
    print("   - Completion confirmations")
    print("   - Error/warning counts")


def demo_integration_points():
    """Demo: Integration points in CLI."""
    print_section("DEMO 8: CLI Integration Points")
    
    print("Validation is integrated at multiple points in the CLI:")
    print("\n1. Strategy Generation Phase (line ~1777):")
    print("   - Validates generated strategies")
    print("   - Filters out invalid strategies")
    print("   - Displays validation summary")
    print("\n2. Test Execution Phase (line ~1935):")
    print("   - Validates captured PCAP files")
    print("   - Checks packet structure")
    print("   - Adds results to report")
    print("\n3. Results Reporting Phase (line ~2200):")
    print("   - Compares with baseline")
    print("   - Detects regressions")
    print("   - Saves new baseline")
    print("\n4. Standalone Validation Mode (line ~3391):")
    print("   - Validates PCAP and exits")
    print("   - Displays detailed report")
    print("   - Returns exit code")


def main():
    """Run all demos."""
    print("\n" + "=" * 70)
    print("  CLI VALIDATION FEATURES DEMONSTRATION")
    print("=" * 70)
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    demos = [
        ("Validation Flags in Help", demo_help),
        ("Using --validate Flag", demo_validate_flag),
        ("Using --validate-pcap Flag", demo_validate_pcap),
        ("Baseline Workflow", demo_baseline_workflow),
        ("CLIValidationOrchestrator", demo_validation_orchestrator),
        ("Strategy Validation", demo_strategy_validation),
        ("Validation Output Formatting", demo_validation_output),
        ("CLI Integration Points", demo_integration_points),
    ]
    
    for demo_name, demo_func in demos:
        try:
            demo_func()
        except Exception as e:
            print(f"\n✗ Demo '{demo_name}' failed: {e}")
            import traceback
            traceback.print_exc()
    
    print_section("SUMMARY")
    
    print("CLI Validation Features:")
    print("  ✓ --validate flag for validation mode")
    print("  ✓ --validate-baseline for baseline comparison")
    print("  ✓ --save-baseline for saving baselines")
    print("  ✓ --validate-pcap for PCAP validation")
    print("  ✓ Strategy validation integrated")
    print("  ✓ PCAP validation integrated")
    print("  ✓ Baseline comparison integrated")
    print("  ✓ Enhanced validation output")
    print("\nFor more information:")
    print("  - See CLI_VALIDATION_QUICK_START.md")
    print("  - Run: python cli.py --help")
    print("  - Check: TASK6_CLI_VALIDATION_INTEGRATION_COMPLETE.md")
    
    print("\n" + "=" * 70)
    print("  Demo complete!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
