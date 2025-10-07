#!/usr/bin/env python3
"""
X.com Browser Access Test Guide
Task 10.2: Test x.com access in browser

This script provides step-by-step guidance for manual browser testing
and validates the service is ready for testing.

Requirements: 6.1, 6.2
"""

import sys
import json
import time
import subprocess
import logging
from pathlib import Path
from datetime import datetime

class BrowserAccessTestGuide:
    """Provides guidance for manual x.com browser testing."""
    
    def __init__(self):
        self.logger = self.setup_logging()
        
    def setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)-7s] %(message)s',
            datefmt='%H:%M:%S'
        )
        return logging.getLogger('BrowserTest')
        
    def check_prerequisites(self) -> bool:
        """Check if prerequisites for browser testing are met."""
        print("=" * 80)
        print("🔍 CHECKING PREREQUISITES FOR BROWSER TESTING")
        print("=" * 80)
        
        success = True
        
        # 1. Check strategies.json has x.com
        strategies_file = Path("strategies.json")
        if strategies_file.exists():
            try:
                with open(strategies_file, 'r', encoding='utf-8') as f:
                    strategies = json.load(f)
                    
                if 'x.com' in strategies:
                    strategy = strategies['x.com']
                    print(f"✅ x.com strategy configured: {strategy}")
                    
                    # Check for router-tested parameters
                    if all(param in strategy for param in ['multidisorder', 'autottl=2', 'badseq', 'split-pos=46']):
                        print("✅ Router-tested strategy parameters detected")
                    else:
                        print("⚠️ Strategy may not be optimal")
                else:
                    print("❌ x.com strategy not found in strategies.json")
                    success = False
                    
            except Exception as e:
                print(f"❌ Error reading strategies.json: {e}")
                success = False
        else:
            print("❌ strategies.json not found")
            success = False
            
        # 2. Check WinDivert files
        if Path("WinDivert.dll").exists() and Path("WinDivert64.sys").exists():
            print("✅ WinDivert files present")
        else:
            print("❌ WinDivert files missing")
            success = False
            
        # 3. Check administrator privileges
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                print("✅ Running with Administrator privileges")
            else:
                print("❌ Administrator privileges required")
                success = False
        except:
            print("⚠️ Could not check administrator privileges")
            
        return success
        
    def show_service_startup_guide(self):
        """Show how to start the bypass service."""
        print("\n" + "=" * 80)
        print("🚀 STEP 1: START THE BYPASS SERVICE")
        print("=" * 80)
        
        print("""
1. Open a NEW Administrator Command Prompt:
   - Press Win+X, select "Windows Terminal (Admin)" or "Command Prompt (Admin)"
   - If prompted by UAC, click "Yes"

2. Navigate to the recon directory:
   cd path\\to\\your\\recon

3. Start the bypass service:
   python recon_service.py

4. Wait for these success messages:
   ✅ Loaded X domain-specific strategies
   ✅ Loaded X domains from sites.txt  
   ✅ Mapped IP 172.66.0.227 (x.com) -> multidisorder
   ✅ Mapped IP 162.159.140.229 (x.com) -> multidisorder
   ✅ DPI Bypass Engine started successfully
   ✅ Service Started Successfully

5. KEEP THIS WINDOW OPEN during browser testing!

IMPORTANT: If you see any errors, fix them before proceeding to browser testing.
""")
        
    def show_browser_testing_steps(self):
        """Show detailed browser testing steps."""
        print("\n" + "=" * 80)
        print("🌐 STEP 2: BROWSER TESTING PROCEDURE")
        print("=" * 80)
        
        print("""
REQUIREMENT 6.1: Verify page loads successfully
REQUIREMENT 6.2: Check for no connection errors

Test Procedure:

1. OPEN YOUR BROWSER:
   - Use Chrome, Firefox, or Edge
   - Open a new tab or window

2. TEST MAIN X.COM DOMAIN:
   
   a) Navigate to: https://x.com
   
   b) Expected Results:
      ✅ Page loads within 10-15 seconds
      ✅ No "This site can't be reached" error
      ✅ No "ERR_CONNECTION_RESET" error  
      ✅ No "ERR_TIMED_OUT" error
      ✅ Login page or main feed appears
      ✅ Browser shows secure connection (lock icon)
   
   c) If page doesn't load:
      ❌ Check service console for errors
      ❌ Look for "RST packet" messages
      ❌ Verify service is still running

3. TEST X.COM SUBDOMAINS:
   
   a) Navigate to: https://www.x.com
      Expected: Redirects to x.com or loads properly
   
   b) Navigate to: https://mobile.x.com  
      Expected: Loads mobile version or redirects
   
   c) All should work without connection errors

4. TEST RESOURCE LOADING:
   
   a) On x.com page, open Developer Tools (F12)
   
   b) Go to Network tab
   
   c) Refresh the page (Ctrl+F5)
   
   d) Check for failed requests:
      ✅ No red/failed requests to twimg.com domains
      ✅ Images load properly (pbs.twimg.com, abs.twimg.com)
      ✅ CSS and JavaScript files load
      ✅ No timeout errors in network tab
   
   e) Verify images and resources load:
      ✅ Profile pictures display
      ✅ Tweet images show properly
      ✅ Video thumbnails appear
      ✅ Icons and UI elements render correctly

5. TEST INTERACTIVE FEATURES:
   
   a) Try scrolling the page
      Expected: Smooth scrolling, new content loads
   
   b) Click on tweets/posts (if visible)
      Expected: Links work, no connection errors
   
   c) Try search (if available)
      Expected: Search suggestions appear
""")
        
    def show_success_indicators(self):
        """Show what indicates successful bypass."""
        print("\n" + "=" * 80)
        print("✅ SUCCESS INDICATORS")
        print("=" * 80)
        
        print("""
BROWSER SUCCESS SIGNS:
✅ x.com loads completely within 10-15 seconds
✅ No connection error messages
✅ Images and media display correctly
✅ Page layout appears normal (not broken)
✅ Browser shows secure HTTPS connection
✅ No timeout errors in Developer Tools
✅ All twimg.com resources load successfully

SERVICE LOG SUCCESS SIGNS:
✅ "Mapped IP 172.66.0.227 (x.com) -> multidisorder"
✅ "AutoTTL: N hops + 2 offset = TTL M" 
✅ "Applying bypass for ... -> Type: multidisorder"
✅ No "RST packet detected" messages
✅ No "Connection reset by peer" errors
""")
        
    def show_failure_indicators(self):
        """Show what indicates bypass failure."""
        print("\n" + "=" * 80)
        print("❌ FAILURE INDICATORS")
        print("=" * 80)
        
        print("""
BROWSER FAILURE SIGNS:
❌ "This site can't be reached"
❌ "ERR_CONNECTION_RESET"
❌ "ERR_TIMED_OUT" 
❌ "ERR_CONNECTION_REFUSED"
❌ Page loads but images don't display
❌ Blank or broken page layout
❌ Connection timeout after 30+ seconds

SERVICE LOG FAILURE SIGNS:
❌ "RST packet detected from DPI"
❌ "Connection reset by peer"
❌ "Failed to apply bypass"
❌ "No strategy found for IP"
❌ "Falling back to default strategy" (for x.com)

TROUBLESHOOTING STEPS:
1. Check service is still running
2. Restart service if needed
3. Verify Administrator privileges
4. Check Windows Firewall settings
5. Try different browser
6. Check service logs for specific errors
""")
        
    def show_completion_checklist(self):
        """Show completion checklist for task 10.2."""
        print("\n" + "=" * 80)
        print("📋 TASK 10.2 COMPLETION CHECKLIST")
        print("=" * 80)
        
        print("""
Mark each item as completed:

□ Service started successfully with x.com strategies loaded
□ Opened https://x.com in browser  
□ Page loaded successfully without connection errors
□ No "This site can't be reached" or timeout errors
□ Images and resources loaded properly
□ Tested www.x.com subdomain access
□ Tested mobile.x.com subdomain access  
□ Verified no failed requests in Developer Tools
□ Confirmed secure HTTPS connection established
□ Service logs show successful bypass application

REQUIREMENTS VERIFICATION:
□ Requirement 6.1: Page loads successfully ✓
□ Requirement 6.2: No connection errors ✓

When all items are checked, Task 10.2 is COMPLETE!
""")
        
    def run_guide(self):
        """Run the complete browser testing guide."""
        print("🛡️ X.COM BROWSER ACCESS TESTING GUIDE")
        print(f"Task 10.2 - Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Check prerequisites
        if not self.check_prerequisites():
            print("\n❌ Prerequisites not met. Please fix issues before proceeding.")
            return False
            
        # Show step-by-step guide
        self.show_service_startup_guide()
        
        input("\nPress ENTER when service is started and ready...")
        
        self.show_browser_testing_steps()
        self.show_success_indicators()
        self.show_failure_indicators()
        
        input("\nPress ENTER when browser testing is complete...")
        
        self.show_completion_checklist()
        
        print("\n🎉 Browser testing guide completed!")
        print("Follow the checklist to verify Task 10.2 requirements are met.")
        
        return True


def main():
    """Main function."""
    guide = BrowserAccessTestGuide()
    
    try:
        guide.run_guide()
        return 0
    except KeyboardInterrupt:
        print("\n⚠️ Guide interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())