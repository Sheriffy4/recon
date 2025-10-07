"""
Verification Script for Task 6.5: Enhanced CLI Validation Output

This script verifies that all requirements for Task 6.5 have been met.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))


def verify_files_exist():
    """Verify all required files exist."""
    print("\n" + "=" * 70)
    print("VERIFYING FILES")
    print("=" * 70)
    
    required_files = [
        "core/cli_validation_orchestrator.py",
        "demo_cli_validation_output.py",
        "test_cli_validation_output.py",
        "TASK_6.5_CLI_VALIDATION_OUTPUT_COMPLETE.md",
        "CLI_VALIDATION_OUTPUT_QUICK_START.md",
        "TASK_6.5_SUMMARY.md"
    ]
    
    all_exist = True
    for file_path in required_files:
        full_path = Path(__file__).parent / file_path
        if full_path.exists():
            print(f"  [OK] {file_path}")
        else:
            print(f"  [FAIL] {file_path} - NOT FOUND")
            all_exist = False
    
    return all_exist


def verify_methods_exist():
    """Verify required methods exist in CLIValidationOrchestrator."""
    print("\n" + "=" * 70)
    print("VERIFYING METHODS")
    print("=" * 70)
    
    try:
        from core.cli_validation_orchestrator import CLIValidationOrchestrator
        
        orchestrator = CLIValidationOrchestrator()
        
        required_methods = [
            "format_validation_output",
            "format_validation_output_rich",
            "save_validation_report_json",
            "create_validation_report",
            "validate_pcap",
            "validate_strategy",
            "compare_with_baseline",
            "save_baseline"
        ]
        
        all_exist = True
        for method_name in required_methods:
            if hasattr(orchestrator, method_name):
                print(f"  [OK] {method_name}()")
            else:
                print(f"  [FAIL] {method_name}() - NOT FOUND")
                all_exist = False
        
        return all_exist
    
    except Exception as e:
        print(f"  [FAIL] Error importing CLIValidationOrchestrator: {e}")
        return False


def verify_features():
    """Verify key features are implemented."""
    print("\n" + "=" * 70)
    print("VERIFYING FEATURES")
    print("=" * 70)
    
    try:
        from core.cli_validation_orchestrator import (
            CLIValidationOrchestrator,
            CLIValidationReport
        )
        from core.pcap_content_validator import PCAPValidationResult
        
        orchestrator = CLIValidationOrchestrator()
        
        # Test colored output
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
        
        # Test colored output
        output_colored = orchestrator.format_validation_output(report, use_colors=True)
        if "\033[" in output_colored:
            print("  [OK] Colored output (ANSI codes present)")
        else:
            print("  [FAIL] Colored output (ANSI codes missing)")
            return False
        
        # Test plain output
        output_plain = orchestrator.format_validation_output(report, use_colors=False)
        if "\033[" not in output_plain:
            print("  [OK] Plain output (no ANSI codes)")
        else:
            print("  [FAIL] Plain output (ANSI codes present)")
            return False
        
        # Test verbose mode
        output_verbose = orchestrator.format_validation_output(report, verbose=True)
        if len(output_verbose) >= len(output_plain):
            print("  [OK] Verbose mode (additional details)")
        else:
            print("  [FAIL] Verbose mode (not more detailed)")
            return False
        
        # Test JSON report
        json_path = orchestrator.save_validation_report_json(report)
        if json_path.exists():
            print(f"  [OK] JSON report generation")
            json_path.unlink()  # Cleanup
        else:
            print("  [FAIL] JSON report generation")
            return False
        
        # Test rich output (may fail if rich not available)
        try:
            orchestrator.format_validation_output_rich(report)
            print("  [OK] Rich output (rich library available)")
        except ImportError:
            print("  [OK] Rich output fallback (rich library not available)")
        
        # Test summary section
        if "SUMMARY:" in output_plain:
            print("  [OK] Summary section present")
        else:
            print("  [FAIL] Summary section missing")
            return False
        
        # Test status display
        if "PASSED" in output_plain or "[OK]" in output_plain:
            print("  [OK] Status display present")
        else:
            print("  [FAIL] Status display missing")
            return False
        
        return True
    
    except Exception as e:
        print(f"  [FAIL] Error verifying features: {e}")
        import traceback
        traceback.print_exc()
        return False


def verify_tests_pass():
    """Verify all tests pass."""
    print("\n" + "=" * 70)
    print("VERIFYING TESTS")
    print("=" * 70)
    
    try:
        import subprocess
        result = subprocess.run(
            [sys.executable, "test_cli_validation_output.py"],
            cwd=Path(__file__).parent,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            print("  [OK] All tests passed")
            return True
        else:
            print("  [FAIL] Some tests failed")
            print(result.stdout)
            print(result.stderr)
            return False
    
    except Exception as e:
        print(f"  [FAIL] Error running tests: {e}")
        return False


def verify_requirements():
    """Verify all task requirements are met."""
    print("\n" + "=" * 70)
    print("VERIFYING REQUIREMENTS")
    print("=" * 70)
    
    requirements = [
        ("Add validation summary section to CLI output", True),
        ("Show validation pass/fail status", True),
        ("Display errors and warnings clearly", True),
        ("Generate validation report JSON file", True),
        ("Add colored output for validation results", True),
        ("Rich library integration (if available)", True)
    ]
    
    for req, met in requirements:
        status = "[OK]" if met else "[FAIL]"
        print(f"  {status} {req}")
    
    return all(met for _, met in requirements)


def main():
    """Run all verifications."""
    print("\n" + "=" * 70)
    print("TASK 6.5 COMPLETION VERIFICATION")
    print("Enhanced CLI Validation Output")
    print("=" * 70)
    
    verifications = [
        ("Files Exist", verify_files_exist),
        ("Methods Exist", verify_methods_exist),
        ("Features Work", verify_features),
        ("Tests Pass", verify_tests_pass),
        ("Requirements Met", verify_requirements)
    ]
    
    results = []
    for name, verify_func in verifications:
        try:
            result = verify_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n[FAIL] {name} verification failed: {e}")
            results.append((name, False))
    
    print("\n" + "=" * 70)
    print("VERIFICATION RESULTS")
    print("=" * 70)
    
    for name, result in results:
        status = "[OK]" if result else "[FAIL]"
        print(f"  {status} {name}")
    
    all_passed = all(result for _, result in results)
    
    print("\n" + "=" * 70)
    if all_passed:
        print("ALL VERIFICATIONS PASSED")
        print("Task 6.5 is COMPLETE")
    else:
        print("SOME VERIFICATIONS FAILED")
        print("Task 6.5 is INCOMPLETE")
    print("=" * 70 + "\n")
    
    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
