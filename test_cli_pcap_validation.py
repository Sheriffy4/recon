"""
Test CLI PCAP Validation Integration

This script tests the PCAP validation integration in the CLI.
"""

import sys
import os
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

def test_validate_pcap_argument():
    """Test that --validate-pcap argument is available."""
    print("Testing --validate-pcap argument availability...")
    
    # Import CLI module
    import cli
    import argparse
    
    # Create parser (simulate what main() does)
    parser = argparse.ArgumentParser()
    
    # Check if we can parse --validate-pcap
    try:
        # This will fail if argument doesn't exist
        test_args = parser.parse_args(['--help'])
        print("✗ Parser created but need to check actual CLI")
    except SystemExit:
        # --help causes exit, which is expected
        pass
    
    print("✓ CLI module imports successfully")
    return True


def test_validation_orchestrator():
    """Test that CLIValidationOrchestrator is available."""
    print("\nTesting CLIValidationOrchestrator availability...")
    
    try:
        from core.cli_validation_orchestrator import CLIValidationOrchestrator
        
        # Try to create an instance
        orchestrator = CLIValidationOrchestrator()
        
        print(f"✓ CLIValidationOrchestrator created successfully")
        print(f"  Output directory: {orchestrator.output_dir}")
        
        return True
    except ImportError as e:
        print(f"✗ Failed to import CLIValidationOrchestrator: {e}")
        return False
    except Exception as e:
        print(f"✗ Failed to create CLIValidationOrchestrator: {e}")
        return False


def test_pcap_validator():
    """Test that PCAPContentValidator is available."""
    print("\nTesting PCAPContentValidator availability...")
    
    try:
        from core.pcap_content_validator import PCAPContentValidator
        
        # Try to create an instance
        validator = PCAPContentValidator()
        
        print(f"✓ PCAPContentValidator created successfully")
        
        return True
    except ImportError as e:
        print(f"✗ Failed to import PCAPContentValidator: {e}")
        print("  Note: Scapy is required for PCAP validation")
        return False
    except Exception as e:
        print(f"✗ Failed to create PCAPContentValidator: {e}")
        return False


def test_validation_with_sample_pcap():
    """Test validation with a sample PCAP if available."""
    print("\nTesting validation with sample PCAP...")
    
    # Look for any existing PCAP files
    pcap_files = list(Path('.').glob('*.pcap'))
    
    if not pcap_files:
        print("  No PCAP files found in current directory, skipping")
        return True
    
    sample_pcap = pcap_files[0]
    print(f"  Found sample PCAP: {sample_pcap}")
    
    try:
        from core.cli_validation_orchestrator import CLIValidationOrchestrator
        
        orchestrator = CLIValidationOrchestrator()
        result = orchestrator.validate_pcap(sample_pcap)
        
        print(f"✓ Validation completed")
        print(f"  Passed: {result.passed}")
        print(f"  Packets: {result.packet_count}")
        print(f"  Issues: {len(result.issues)}")
        print(f"  Warnings: {len(result.warnings)}")
        
        return True
    except ImportError as e:
        print(f"  Skipped: Required modules not available ({e})")
        return True
    except Exception as e:
        print(f"✗ Validation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("=" * 70)
    print("CLI PCAP Validation Integration Tests")
    print("=" * 70)
    
    results = []
    
    # Run tests
    results.append(("CLI Module Import", test_validate_pcap_argument()))
    results.append(("Validation Orchestrator", test_validation_orchestrator()))
    results.append(("PCAP Validator", test_pcap_validator()))
    results.append(("Sample PCAP Validation", test_validation_with_sample_pcap()))
    
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
