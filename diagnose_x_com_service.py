#!/usr/bin/env python3
"""
X.com Service Diagnostic Tool
Diagnoses why x.com subdomains are not working with bypass service.
"""

import sys
import os
import json
import socket
import subprocess
import time
from pathlib import Path

# Add recon to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_strategies_config():
    """Check if strategies.json has correct x.com configuration"""
    print("🔧 Checking strategies.json configuration...")
    
    strategies_file = Path('strategies.json')
    if not strategies_file.exists():
        print("  ❌ strategies.json not found!")
        return False
    
    try:
        with open(strategies_file, 'r', encoding='utf-8') as f:
            strategies = json.load(f)
        
        x_com_domains = ['x.com', 'www.x.com', 'api.x.com', 'mobile.x.com']
        configured_domains = []
        
        for domain in x_com_domains:
            if domain in strategies:
                strategy = strategies[domain]
                print(f"  ✅ {domain}: {strategy}")
                configured_domains.append(domain)
            else:
                print(f"  ❌ {domain}: NOT CONFIGURED")
        
        print(f"\n  📊 Configured: {len(configured_domains)}/{len(x_com_domains)} domains")
        
        if configured_domains:
            # Check if strategy looks correct
            sample_strategy = strategies[configured_domains[0]]
            if 'multidisorder' in sample_strategy and 'autottl' in sample_strategy:
                print("  ✅ Strategy appears to be correct multidisorder with autottl")
                return True
            else:
                print("  ⚠️  Strategy may not be the correct router-tested strategy")
                return False
        else:
            return False
            
    except Exception as e:
        print(f"  ❌ Error reading strategies.json: {e}")
        return False

def check_service_processes():
    """Check what Python processes are running"""
    print("\n🔍 Checking running Python processes...")
    
    try:
        # Get detailed process list
        result = subprocess.run(
            ['wmic', 'process', 'where', 'name="python.exe"', 'get', 'ProcessId,CommandLine'],
            capture_output=True, text=True, shell=True, timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            python_processes = []
            
            for line in lines[1:]:  # Skip header
                if line.strip() and 'python.exe' in line:
                    python_processes.append(line.strip())
            
            if python_processes:
                print(f"  ✅ Found {len(python_processes)} Python processes:")
                for i, process in enumerate(python_processes, 1):
                    print(f"     {i}. {process}")
                
                # Check if any look like recon service
                recon_processes = [p for p in python_processes if 'recon' in p.lower() or 'setup.py' in p]
                if recon_processes:
                    print(f"  ✅ Found {len(recon_processes)} recon-related processes")
                    return True
                else:
                    print("  ⚠️  No recon-related processes found")
                    return False
            else:
                print("  ❌ No Python processes found")
                return False
        else:
            print("  ❌ Could not get process list")
            return False
            
    except Exception as e:
        print(f"  ❌ Error checking processes: {e}")
        return False

def test_direct_connection():
    """Test direct connection without bypass to see if it's blocked"""
    print("\n🌐 Testing direct connection (without bypass)...")
    
    try:
        # Try to connect to x.com port 443 directly
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        print("  📍 Connecting to x.com:443...")
        start_time = time.time()
        result = sock.connect_ex(('x.com', 443))
        connect_time = time.time() - start_time
        
        sock.close()
        
        if result == 0:
            print(f"  ✅ Direct connection successful ({connect_time:.2f}s)")
            print("     This suggests x.com is not blocked at network level")
            return True
        else:
            print(f"  ❌ Direct connection failed (error {result})")
            print("     This suggests x.com is blocked at network level")
            return False
            
    except Exception as e:
        print(f"  ❌ Connection test failed: {e}")
        return False

def check_windivert_driver():
    """Check if WinDivert driver is available"""
    print("\n🚗 Checking WinDivert driver...")
    
    windivert_files = ['WinDivert.dll', 'WinDivert64.sys']
    found_files = []
    
    for filename in windivert_files:
        if Path(filename).exists():
            found_files.append(filename)
            print(f"  ✅ {filename} found")
        else:
            print(f"  ❌ {filename} not found")
    
    if len(found_files) == len(windivert_files):
        print("  ✅ All WinDivert files present")
        return True
    else:
        print("  ❌ Missing WinDivert files - bypass cannot work")
        return False

def check_admin_privileges():
    """Check if running with admin privileges"""
    print("\n👑 Checking admin privileges...")
    
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        
        if is_admin:
            print("  ✅ Running with administrator privileges")
            return True
        else:
            print("  ❌ NOT running with administrator privileges")
            print("     WinDivert requires admin rights to work")
            return False
            
    except Exception as e:
        print(f"  ❌ Could not check admin privileges: {e}")
        return False

def suggest_fixes():
    """Suggest potential fixes based on diagnosis"""
    print("\n💡 SUGGESTED FIXES:")
    print("=" * 50)
    
    print("1. 🔄 Restart bypass service:")
    print("   - Stop current service (Ctrl+C if running)")
    print("   - Run: python setup.py")
    print("   - Select [2] Start bypass service")
    print("   - Make sure it starts without errors")
    
    print("\n2. ✅ Verify service is working:")
    print("   - Check service logs for errors")
    print("   - Look for 'Mapped IP ... (x.com) -> multidisorder' messages")
    print("   - Verify no 'Failed to apply bypass' errors")
    
    print("\n3. 🔧 Check configuration:")
    print("   - Ensure strategies.json has correct x.com entries")
    print("   - Verify strategy uses multidisorder with autottl=2")
    print("   - Check all x.com subdomains are configured")
    
    print("\n4. 👑 Run as administrator:")
    print("   - Close current terminal")
    print("   - Right-click Command Prompt -> 'Run as administrator'")
    print("   - Navigate to recon folder and restart service")
    
    print("\n5. 🚗 Check WinDivert:")
    print("   - Ensure WinDivert.dll and WinDivert64.sys are present")
    print("   - Try reinstalling WinDivert if needed")

def main():
    """Main diagnostic function"""
    print("🔍 X.com Service Diagnostic Tool")
    print("=" * 50)
    print("Diagnosing why x.com subdomains are not working...")
    
    issues_found = []
    
    # Run all diagnostic checks
    if not check_strategies_config():
        issues_found.append("strategies.json configuration")
    
    if not check_service_processes():
        issues_found.append("bypass service not running")
    
    if not test_direct_connection():
        issues_found.append("direct connection blocked")
    
    if not check_windivert_driver():
        issues_found.append("WinDivert driver missing")
    
    if not check_admin_privileges():
        issues_found.append("not running as administrator")
    
    # Summary
    print("\n" + "=" * 50)
    print("🎯 DIAGNOSTIC SUMMARY")
    print("=" * 50)
    
    if not issues_found:
        print("✅ No obvious issues found")
        print("   The service should be working. Try testing again.")
    else:
        print(f"❌ Found {len(issues_found)} potential issues:")
        for i, issue in enumerate(issues_found, 1):
            print(f"   {i}. {issue}")
    
    suggest_fixes()
    
    return len(issues_found)

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⏹️  Diagnostic interrupted")
        sys.exit(130)