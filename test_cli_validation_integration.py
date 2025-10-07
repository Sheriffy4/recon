"""
Test CLI Validation Integration

This script tests the integration of validation features into the CLI,
including --validate, --validate-baseline, --save-baseline, and --validate-pcap flags.

Part of Task 6: CLI Integration for Attack Validation Production Readiness
"""

import sys
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))


def test_validate_flag():
    """Test --validate flag integration."""
    print("\n" + "=" * 70)
    print("TEST 1: --validate flag")
    print("=" * 70)
    
    # Test that --validate flag is recognized
    result = subprocess.run(
        [sys.executable, "cli.py", "--help"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    
    if "--validate" in result.stdout:
        print("✓ --validate flag is present in CLI help")
    else:
        print("✗ --validate flag NOT found in CLI help")
        return False
    
    if "Enable validation mode" in result.stdout:
        print("✓ --validate flag has proper description")
    else:
        print("✗ --validate flag description missing")
        return False
    
    return True


def test_validate_baseline_flag():
    """Test --validate-baseline flag integration."""
    print("\n" + "=" * 70)
    print("TEST 2: --validate-baseline flag")
    print("=" * 70)
    
    result = subprocess.run(
        [sys.executable, "cli.py", "--help"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    
    if "--validate-baseline" in result.stdout:
        print("✓ --validate-baseline flag is present in CLI help")
    else:
        print("✗ --validate-baseline flag NOT found in CLI help")
        return False
    
    if "Compare current execution results" in result.stdout or "baseline" in result.stdout.lower():
        print("✓ --validate-baseline flag has proper description")
    else:
        print("✗ --validate-baseline flag description missing")
        return False
    
    return True


def test_save_baseline_flag():
    """Test --save-baseline flag integration."""
    print("\n" + "=" * 70)
    print("TEST 3: --save-baseline flag")
    print("=" * 70)
    
    result = subprocess.run(
        [sys.executable, "cli.py", "--help"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    
    if "--save-baseline" in result.stdout:
        print("✓ --save-baseline flag is present in CLI help")
    else:
        print("✗ --save-baseline flag NOT found in CLI help")
        return False
    
    if "Save current execution results" in result.stdout or "baseline" in result.stdout.lower():
        print("✓ --save-baseline flag has proper description")
    else:
        print("✗ --save-baseline flag description missing")
        return False
    
    return True


def test_validate_pcap_flag():
    """Test --validate-pcap flag integration."""
    print("\n" + "=" * 70)
    print("TEST 4: --validate-pcap flag")
    print("=" * 70)
    
    result = subprocess.run(
        [sys.executable, "cli.py", "--help"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent
    )
    
    if "--validate-pcap" in result.stdout:
        print("✓ --validate-pcap flag is present in CLI help")
    else:
        print("✗ --validate-pcap flag NOT found in CLI help")
        return False
    
    return True


def test_validation_orchestrator_import():
    """Test that CLIValidationOrchestrator can be imported."""
    print("\n" + "=" * 70)
    print("TEST 5: CLIValidationOrchestrator import")
    print("=" * 70)
    
    try:
        from core.cli_validation_orchestrator import CLIValidationOrchestrator
        print("✓ CLIValidationOrchestrator imported successfully")
        
        # Test instantiation
        orchestrator = CLIValidationOrchestrator()
        print("✓ CLIValidationOrchestrator instantiated successfully")
        
        # Check methods exist
        required_methods = [
            'validate_pcap',
            'validate_strategy',
            'compare_with_baseline',
            'save_baseline',
            'create_validation_report',
            'format_validation_output'
        ]
        
        for method in required_methods:
            if hasattr(orchestrator, method):
                print(f"✓ Method '{method}' exists")
            else:
                print(f"✗ Method '{method}' NOT found")
                return False
        
        return True
        
    except ImportError as e:
        print(f"✗ Failed to import CLIValidationOrchestrator: {e}")
        return False
    except Exception as e:
        print(f"✗ Error testing CLIValidationOrchestrator: {e}")
        return False


def test_strategy_validation_integration():
    """Test that strategy validation is integrated into CLI."""
    print("\n" + "=" * 70)
    print("TEST 6: Strategy validation integration")
    print("=" * 70)
    
    # Check if validation code is present in cli.py
    cli_path = Path(__file__).parent / "cli.py"
    
    if not cli_path.exists():
        print("✗ cli.py not found")
        return False
    
    with open(cli_path, 'r', encoding='utf-8') as f:
        cli_content = f.read()
    
    # Check for strategy validation code
    if "validate_strategy" in cli_content:
        print("✓ Strategy validation code found in cli.py")
    else:
        print("✗ Strategy validation code NOT found in cli.py")
        return False
    
    if "args.validate" in cli_content:
        print("✓ args.validate check found in cli.py")
    else:
        print("✗ args.validate check NOT found in cli.py")
        return False
    
    return True


def test_pcap_validation_integration():
    """Test that PCAP validation is integrated into CLI."""
    print("\n" + "=" * 70)
    print("TEST 7: PCAP validation integration")
    print("=" * 70)
    
    cli_path = Path(__file__).parent / "cli.py"
    
    with open(cli_path, 'r', encoding='utf-8') as f:
        cli_content = f.read()
    
    # Check for PCAP validation code
    if "validate_pcap" in cli_content:
        print("✓ PCAP validation code found in cli.py")
    else:
        print("✗ PCAP validation code NOT found in cli.py")
        return False
    
    if "pcap_validation_result" in cli_content:
        print("✓ PCAP validation result handling found in cli.py")
    else:
        print("✗ PCAP validation result handling NOT found in cli.py")
        return False
    
    return True


def test_baseline_comparison_integration():
    """Test that baseline comparison is integrated into CLI."""
    print("\n" + "=" * 70)
    print("TEST 8: Baseline comparison integration")
    print("=" * 70)
    
    cli_path = Path(__file__).parent / "cli.py"
    
    with open(cli_path, 'r', encoding='utf-8') as f:
        cli_content = f.read()
    
    # Check for baseline comparison code
    if "compare_with_baseline" in cli_content:
        print("✓ Baseline comparison code found in cli.py")
    else:
        print("✗ Baseline comparison code NOT found in cli.py")
        return False
    
    if "args.validate_baseline" in cli_content:
        print("✓ args.validate_baseline check found in cli.py")
    else:
        print("✗ args.validate_baseline check NOT found in cli.py")
        return False
    
    if "args.save_baseline" in cli_content:
        print("✓ args.save_baseline check found in cli.py")
    else:
        print("✗ args.save_baseline check NOT found in cli.py")
        return False
    
    return True


def test_validation_output_integration():
    """Test that validation output is integrated into CLI."""
    print("\n" + "=" * 70)
    print("TEST 9: Validation output integration")
    print("=" * 70)
    
    cli_path = Path(__file__).parent / "cli.py"
    
    with open(cli_path, 'r', encoding='utf-8') as f:
        cli_content = f.read()
    
    # Check for validation output code
    if "VALIDATION" in cli_content:
        print("✓ Validation output markers found in cli.py")
    else:
        print("✗ Validation output markers NOT found in cli.py")
        return False
    
    if "baseline_comparison" in cli_content:
        print("✓ Baseline comparison output found in cli.py")
    else:
        print("✗ Baseline comparison output NOT found in cli.py")
        return False
    
    return True


def main():
    """Run all CLI validation integration tests."""
    print("\n" + "=" * 70)
    print("CLI VALIDATION INTEGRATION TEST SUITE")
    print("=" * 70)
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    tests = [
        ("Validate Flag", test_validate_flag),
        ("Validate Baseline Flag", test_validate_baseline_flag),
        ("Save Baseline Flag", test_save_baseline_flag),
        ("Validate PCAP Flag", test_validate_pcap_flag),
        ("Validation Orchestrator Import", test_validation_orchestrator_import),
        ("Strategy Validation Integration", test_strategy_validation_integration),
        ("PCAP Validation Integration", test_pcap_validation_integration),
        ("Baseline Comparison Integration", test_baseline_comparison_integration),
        ("Validation Output Integration", test_validation_output_integration),
    ]
    
    results = {}
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results[test_name] = result
            if result:
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"\n✗ Test '{test_name}' raised exception: {e}")
            import traceback
            traceback.print_exc()
            results[test_name] = False
            failed += 1
    
    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success rate: {(passed / len(tests) * 100):.1f}%")
    
    print("\nDetailed Results:")
    for test_name, result in results.items():
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"  {status}: {test_name}")
    
    print("\n" + "=" * 70)
    
    if failed == 0:
        print("✓ ALL TESTS PASSED - CLI validation integration is complete!")
        return 0
    else:
        print(f"✗ {failed} TEST(S) FAILED - CLI validation integration needs fixes")
        return 1


if __name__ == "__main__":
    sys.exit(main())
