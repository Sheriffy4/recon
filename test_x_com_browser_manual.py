#!/usr/bin/env python3
"""
Manual X.com Browser Test
Opens x.com in default browser to test if bypass is working.
"""

import sys
import os
import time
import webbrowser
import subprocess
from datetime import datetime

def check_service_running():
    """Check if bypass service is running"""
    try:
        result = subprocess.run(
            ['tasklist', '/FI', 'IMAGENAME eq python.exe'],
            capture_output=True, text=True, shell=True, timeout=5
        )
        
        if 'python.exe' in result.stdout:
            print("✅ Python processes detected - bypass service likely running")
            return True
        else:
            print("❌ No Python processes found - bypass service may not be running")
            return False
    except:
        print("⚠️  Could not check service status")
        return None

def main():
    """Main test function"""
    print("🌐 Manual X.com Browser Test")
    print("=" * 50)
    print("This test will open x.com subdomains in your default browser")
    print("You should manually verify if they load correctly")
    
    # Check service status
    service_status = check_service_running()
    
    if not service_status:
        print("\n⚠️  WARNING: Bypass service may not be running!")
        print("Consider starting the service first:")
        print("   python recon_service.py")
        
        response = input("\nContinue anyway? (y/N): ").lower()
        if response != 'y':
            print("Test cancelled")
            return 1
    
    # Subdomains to test
    subdomains = [
        'https://x.com',
        'https://www.x.com', 
        'https://api.x.com',
        'https://mobile.x.com'
    ]
    
    print(f"\n📋 Opening {len(subdomains)} x.com subdomains in browser:")
    
    for i, url in enumerate(subdomains, 1):
        print(f"\n{i}. Opening {url}...")
        
        try:
            webbrowser.open(url)
            print(f"   ✅ Browser opened for {url}")
            
            # Wait a bit between opens
            if i < len(subdomains):
                print("   ⏱️  Waiting 3 seconds before next...")
                time.sleep(3)
                
        except Exception as e:
            print(f"   ❌ Failed to open {url}: {e}")
    
    print(f"\n" + "=" * 50)
    print("📋 MANUAL VERIFICATION REQUIRED")
    print("=" * 50)
    print("Please check each browser tab and verify:")
    print("1. ✅ Page loads successfully (not timeout/error)")
    print("2. ✅ Content is displayed properly") 
    print("3. ✅ No connection errors or blocks")
    print("4. ✅ Images and resources load")
    
    print(f"\n🎯 EXPECTED RESULTS:")
    print("If bypass is working correctly:")
    print("- All x.com subdomains should load")
    print("- No 'This site can't be reached' errors")
    print("- No timeout errors")
    print("- Normal X.com content should display")
    
    print(f"\n📊 TEST COMPLETION:")
    print("- Check all browser tabs")
    print("- Note which subdomains work/fail")
    print("- Report results for Requirement 6.6")
    
    # Ask for user feedback
    print(f"\n" + "=" * 50)
    working_count = 0
    
    for url in subdomains:
        domain = url.replace('https://', '')
        response = input(f"Did {domain} load successfully? (y/N): ").lower()
        if response == 'y':
            working_count += 1
            print(f"   ✅ {domain}: WORKING")
        else:
            print(f"   ❌ {domain}: FAILED")
    
    total = len(subdomains)
    success_rate = (working_count / total) * 100
    
    print(f"\n📊 FINAL RESULTS:")
    print(f"Total subdomains: {total}")
    print(f"Working: {working_count}")
    print(f"Failed: {total - working_count}")
    print(f"Success rate: {success_rate:.1f}%")
    
    print(f"\n🎯 REQUIREMENT 6.6 ASSESSMENT:")
    if working_count == total:
        print("✅ PASS - All x.com subdomains working")
        return 0
    elif working_count > 0:
        print("⚠️  PARTIAL - Some x.com subdomains working")
        return 1
    else:
        print("❌ FAIL - No x.com subdomains working")
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⏹️  Test interrupted")
        sys.exit(130)