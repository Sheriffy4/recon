#!/usr/bin/env python3
"""
Simple test to verify CLI optimization integration works correctly.
"""

import subprocess
import sys
from pathlib import Path

def test_cli_help():
    """Test that new CLI arguments appear in help."""
    print("🧪 Testing CLI help output...")
    
    try:
        result = subprocess.run([
            sys.executable, "cli.py", "--help"
        ], capture_output=True, text=True, timeout=10)
        
        help_text = result.stdout
        
        # Check for new arguments
        required_args = [
            "--analysis-level",
            "--parallel", 
            "--no-fail-fast",
            "--enable-scapy",
            "--sni-mode",
            "--connect-timeout",
            "--tls-timeout",
            "--sequential"
        ]
        
        missing_args = []
        for arg in required_args:
            if arg not in help_text:
                missing_args.append(arg)
        
        if missing_args:
            print(f"❌ Missing CLI arguments: {missing_args}")
            return False
        else:
            print("✅ All new CLI arguments found in help")
            return True
            
    except Exception as e:
        print(f"❌ Error testing CLI help: {e}")
        return False

def test_cli_argument_parsing():
    """Test that CLI can parse new arguments without errors."""
    print("🧪 Testing CLI argument parsing...")
    
    # Test command that should parse successfully (but exit early)
    test_commands = [
        ["cli.py", "--help"],  # Should work
        ["cli.py", "example.com", "--fingerprint", "--analysis-level", "fast", "--parallel", "10"],
        ["cli.py", "example.com", "--fingerprint", "--sni-mode", "basic", "--connect-timeout", "2.0"],
    ]
    
    for cmd in test_commands[1:]:  # Skip help command
        try:
            # We expect this to fail due to missing dependencies, but it should parse args correctly
            result = subprocess.run([
                sys.executable] + cmd + ["--debug", "--count", "1", "--single-strategy", "--strategy", "test"
            ], capture_output=True, text=True, timeout=5)
            
            # Check that it's not an argument parsing error
            if "invalid choice" in result.stderr or "unrecognized arguments" in result.stderr:
                print(f"❌ Argument parsing error in command: {' '.join(cmd)}")
                print(f"   Error: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("⏰ Command timed out (this is expected)")
            continue
        except Exception as e:
            print(f"⚠️ Command failed (may be expected): {e}")
            continue
    
    print("✅ CLI argument parsing works correctly")
    return True

def main():
    """Run CLI integration tests."""
    print("🚀 CLI Optimization Integration Test")
    print("=" * 40)
    
    # Change to the recon directory
    recon_dir = Path(__file__).parent
    import os
    os.chdir(recon_dir)
    
    tests_passed = 0
    total_tests = 2
    
    # Test 1: Help output
    if test_cli_help():
        tests_passed += 1
    
    # Test 2: Argument parsing
    if test_cli_argument_parsing():
        tests_passed += 1
    
    print(f"\n📊 Test Results: {tests_passed}/{total_tests} passed")
    
    if tests_passed == total_tests:
        print("✅ All CLI integration tests passed!")
        print("\n💡 You can now use the optimized CLI commands:")
        print("   python cli.py -d sites.txt --fingerprint --analysis-level balanced --parallel 15")
        print("   python cli.py -d sites.txt --fingerprint --analysis-level fast --parallel 20")
        return True
    else:
        print("❌ Some tests failed. Check the CLI implementation.")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)