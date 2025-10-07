"""
Test CLI --validate-pcap Integration

This script tests the --validate-pcap flag integration in the CLI.
"""

import sys
import subprocess
from pathlib import Path

def test_validate_pcap_help():
    """Test that --validate-pcap appears in help."""
    print("Testing --validate-pcap in CLI help...")
    
    result = subprocess.run(
        [sys.executable, "cli.py", "--help"],
        capture_output=True,
        text=True,
        cwd="."
    )
    
    if "--validate-pcap" in result.stdout:
        print("✓ --validate-pcap flag found in help")
        return True
    else:
        print("✗ --validate-pcap flag NOT found in help")
        print("Help output:")
        print(result.stdout)
        return False


def test_validate_flag_help():
    """Test that --validate appears in help."""
    print("\nTesting --validate in CLI help...")
    
    result = subprocess.run(
        [sys.executable, "cli.py", "--help"],
        capture_output=True,
        text=True,
        cwd="."
    )
    
    if "--validate" in result.stdout:
        print("✓ --validate flag found in help")
        return True
    else:
        print("✗ --validate flag NOT found in help")
        return False


def test_validate_pcap_with_sample():
    """Test --validate-pcap with a sample PCAP file."""
    print("\nTesting --validate-pcap with sample PCAP...")
    
    # Find a sample PCAP
    pcap_files = list(Path('.').glob('*.pcap'))
    
    if not pcap_files:
        print("  No PCAP files found, skipping")
        return True
    
    sample_pcap = pcap_files[0]
    print(f"  Using sample PCAP: {sample_pcap}")
    
    result = subprocess.run(
        [sys.executable, "cli.py", "--validate-pcap", str(sample_pcap)],
        capture_output=True,
        text=True,
        cwd=".",
        timeout=30
    )
    
    # Check output
    if "VALIDATION" in result.stdout or "PCAP Validation" in result.stdout:
        print("✓ Validation output detected")
        print(f"  Exit code: {result.returncode}")
        
        # Show summary
        lines = result.stdout.split('\n')
        for line in lines:
            if 'PASSED' in line or 'FAILED' in line or 'Packets:' in line:
                print(f"  {line.strip()}")
        
        return True
    else:
        print("✗ No validation output detected")
        print("STDOUT:")
        print(result.stdout)
        print("STDERR:")
        print(result.stderr)
        return False


def test_validate_pcap_nonexistent():
    """Test --validate-pcap with nonexistent file."""
    print("\nTesting --validate-pcap with nonexistent file...")
    
    result = subprocess.run(
        [sys.executable, "cli.py", "--validate-pcap", "nonexistent.pcap"],
        capture_output=True,
        text=True,
        cwd=".",
        timeout=10
    )
    
    # Should show error
    if "not found" in result.stdout.lower() or "error" in result.stdout.lower():
        print("✓ Error message displayed for nonexistent file")
        return True
    else:
        print("✗ No error message for nonexistent file")
        print("Output:", result.stdout)
        return False


def main():
    """Run all tests."""
    print("=" * 70)
    print("CLI --validate-pcap Integration Tests")
    print("=" * 70)
    
    results = []
    
    # Run tests
    results.append(("--validate-pcap in help", test_validate_pcap_help()))
    results.append(("--validate in help", test_validate_flag_help()))
    results.append(("Validate sample PCAP", test_validate_pcap_with_sample()))
    results.append(("Validate nonexistent PCAP", test_validate_pcap_nonexistent()))
    
    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
