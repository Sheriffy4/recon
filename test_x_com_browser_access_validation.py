#!/usr/bin/env python3
"""
X.com Browser Access Validation Script
Task 10.2: Test x.com access in browser

This script validates that the bypass service is properly configured for x.com
and provides guidance for manual browser testing.

Requirements: 6.1, 6.2
- Verify page loads successfully
- Check for no connection errors  
- Verify images and resources load
"""

import sys
import json
import time
import socket
import ssl
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests
from datetime import datetime

# Add project root to path
if __name__ == "__main__" and __package__ is None:
    recon_dir = Path(__file__).parent
    project_root = recon_dir.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

class XComBrowserAccessValidator:
    """Validates x.com browser access and bypass service configuration."""
    
    def __init__(self):
        self.logger = self.setup_logging()
        self.x_com_domains = [
            'x.com',
            'www.x.com', 
            'api.x.com',
            'mobile.x.com'
        ]
        self.x_com_resources = [
            'pbs.twimg.com',
            'abs.twimg.com', 
            'abs-0.twimg.com',
            'video.twimg.com',
            'ton.twimg.com'
        ]
        
    def setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        return logging.getLogger('XComValidator')
        
    def validate_service_configuration(self) -> bool:
        """Validate that the bypass service is properly configured for x.com."""
        self.logger.info("=" * 70)
        self.logger.info("VALIDATING X.COM SERVICE CONFIGURATION")
        self.logger.info("=" * 70)
        
        success = True
        
        # 1. Check strategies.json exists and has x.com entries
        strategies_file = Path("strategies.json")
        if not strategies_file.exists():
            self.logger.error("❌ strategies.json file not found!")
            return False
            
        try:
            with open(strategies_file, 'r', encoding='utf-8') as f:
                strategies = json.load(f)
                
            self.logger.info("✅ strategies.json loaded successfully")
            
            # Check x.com domains have strategies
            missing_domains = []
            for domain in self.x_com_domains:
                if domain not in strategies:
                    missing_domains.append(domain)
                else:
                    strategy = strategies[domain]
                    self.logger.info(f"✅ {domain}: {strategy}")
                    
                    # Validate it's the router-tested strategy
                    if 'multidisorder' in strategy and 'autottl=2' in strategy:
                        self.logger.info(f"✅ {domain} has correct router-tested strategy")
                    else:
                        self.logger.warning(f"⚠️ {domain} strategy may not be optimal")
                        
            if missing_domains:
                self.logger.error(f"❌ Missing strategies for: {missing_domains}")
                success = False
                
        except Exception as e:
            self.logger.error(f"❌ Failed to load strategies.json: {e}")
            return False
            
        # 2. Check sites.txt includes x.com domains
        sites_file = Path("sites.txt")
        if sites_file.exists():
            try:
                with open(sites_file, 'r', encoding='utf-8') as f:
                    sites_content = f.read().lower()
                    
                missing_sites = []
                for domain in self.x_com_domains:
                    if domain not in sites_content:
                        missing_sites.append(domain)
                    else:
                        self.logger.info(f"✅ {domain} found in sites.txt")
                        
                if missing_sites:
                    self.logger.warning(f"⚠️ Missing from sites.txt: {missing_sites}")
                    
            except Exception as e:
                self.logger.warning(f"⚠️ Could not read sites.txt: {e}")
        else:
            self.logger.warning("⚠️ sites.txt not found - service will use strategy domains")
            
        return success
        
    def check_dns_resolution(self) -> Dict[str, List[str]]:
        """Check DNS resolution for x.com domains."""
        self.logger.info("=" * 70)
        self.logger.info("CHECKING DNS RESOLUTION")
        self.logger.info("=" * 70)
        
        domain_ips = {}
        
        for domain in self.x_com_domains + self.x_com_resources:
            try:
                # Resolve domain to IP addresses
                addr_info = socket.getaddrinfo(domain, 443, socket.AF_INET)
                ips = list(set([addr[4][0] for addr in addr_info]))
                domain_ips[domain] = ips
                
                self.logger.info(f"✅ {domain} -> {', '.join(ips)}")
                
            except Exception as e:
                self.logger.error(f"❌ Failed to resolve {domain}: {e}")
                domain_ips[domain] = []
                
        return domain_ips
        
    def test_basic_connectivity(self, domain_ips: Dict[str, List[str]]) -> Dict[str, bool]:
        """Test basic TCP connectivity to x.com domains."""
        self.logger.info("=" * 70)
        self.logger.info("TESTING BASIC CONNECTIVITY")
        self.logger.info("=" * 70)
        
        connectivity_results = {}
        
        for domain in self.x_com_domains:
            ips = domain_ips.get(domain, [])
            if not ips:
                connectivity_results[domain] = False
                continue
                
            # Test connectivity to first IP
            ip = ips[0]
            try:
                with socket.create_connection((ip, 443), timeout=10) as sock:
                    self.logger.info(f"✅ {domain} ({ip}):443 - TCP connection successful")
                    connectivity_results[domain] = True
                    
            except Exception as e:
                self.logger.error(f"❌ {domain} ({ip}):443 - TCP connection failed: {e}")
                connectivity_results[domain] = False
                
        return connectivity_results
        
    def test_tls_handshake(self, domain_ips: Dict[str, List[str]]) -> Dict[str, bool]:
        """Test TLS handshake with x.com domains."""
        self.logger.info("=" * 70)
        self.logger.info("TESTING TLS HANDSHAKE")
        self.logger.info("=" * 70)
        
        tls_results = {}
        
        for domain in self.x_com_domains:
            ips = domain_ips.get(domain, [])
            if not ips:
                tls_results[domain] = False
                continue
                
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=15) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        self.logger.info(f"✅ {domain} - TLS handshake successful")
                        self.logger.info(f"   Certificate subject: {cert.get('subject', 'Unknown')}")
                        tls_results[domain] = True
                        
            except Exception as e:
                self.logger.error(f"❌ {domain} - TLS handshake failed: {e}")
                tls_results[domain] = False
                
        return tls_results
        
    def test_http_requests(self) -> Dict[str, bool]:
        """Test HTTP requests to x.com domains."""
        self.logger.info("=" * 70)
        self.logger.info("TESTING HTTP REQUESTS")
        self.logger.info("=" * 70)
        
        http_results = {}
        
        # Configure requests session
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        for domain in ['x.com', 'www.x.com']:  # Test main domains
            url = f"https://{domain}"
            try:
                self.logger.info(f"Testing HTTP request to {url}...")
                response = session.get(url, timeout=30, allow_redirects=True)
                
                if response.status_code == 200:
                    self.logger.info(f"✅ {domain} - HTTP 200 OK")
                    self.logger.info(f"   Content-Length: {len(response.content)} bytes")
                    self.logger.info(f"   Content-Type: {response.headers.get('content-type', 'Unknown')}")
                    http_results[domain] = True
                else:
                    self.logger.warning(f"⚠️ {domain} - HTTP {response.status_code}")
                    http_results[domain] = False
                    
            except requests.exceptions.Timeout:
                self.logger.error(f"❌ {domain} - Request timeout")
                http_results[domain] = False
            except requests.exceptions.ConnectionError as e:
                self.logger.error(f"❌ {domain} - Connection error: {e}")
                http_results[domain] = False
            except Exception as e:
                self.logger.error(f"❌ {domain} - Request failed: {e}")
                http_results[domain] = False
                
        return http_results
        
    def check_service_status(self) -> bool:
        """Check if the bypass service is running."""
        self.logger.info("=" * 70)
        self.logger.info("CHECKING SERVICE STATUS")
        self.logger.info("=" * 70)
        
        try:
            # Check for WinDivert files (indicates service capability)
            windivert_dll = Path("WinDivert.dll")
            windivert_sys = Path("WinDivert64.sys")
            
            if windivert_dll.exists() and windivert_sys.exists():
                self.logger.info("✅ WinDivert files found - service can run")
            else:
                self.logger.error("❌ WinDivert files missing - service cannot run")
                return False
                
            # Check if running as administrator
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                self.logger.info("✅ Running with Administrator privileges")
            else:
                self.logger.error("❌ Not running as Administrator - service requires elevated privileges")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Service status check failed: {e}")
            return False
            
    def generate_browser_test_guide(self) -> str:
        """Generate manual browser testing guide."""
        guide = """
=" * 70
MANUAL BROWSER TESTING GUIDE
=" * 70

Follow these steps to manually test x.com access in your browser:

1. ENSURE SERVICE IS RUNNING:
   - Open Administrator Command Prompt
   - Navigate to the recon directory
   - Run: python recon_service.py
   - Wait for "✅ Service Started Successfully" message
   - Keep this window open during testing

2. BROWSER TESTING STEPS:

   Step 1: Test Main x.com Domain
   - Open your browser (Chrome, Firefox, Edge)
   - Navigate to: https://x.com
   - Expected: Page should load without connection errors
   - Check: Login page or main feed should appear
   - Verify: No "This site can't be reached" errors

   Step 2: Test x.com Subdomains
   - Navigate to: https://www.x.com
   - Navigate to: https://mobile.x.com
   - Expected: All should redirect or load properly
   - Check: No connection timeouts or errors

   Step 3: Test Resource Loading
   - On x.com, check that images load properly
   - Open browser Developer Tools (F12)
   - Go to Network tab
   - Refresh the page
   - Check: No failed requests to twimg.com domains
   - Verify: Images, CSS, and JS resources load successfully

   Step 4: Test Interactive Features
   - Try scrolling the timeline (if logged in)
   - Try clicking on tweets/posts
   - Check: Page interactions work smoothly
   - Verify: No network errors in console

3. WHAT TO LOOK FOR:

   ✅ SUCCESS INDICATORS:
   - Page loads within 10 seconds
   - Images and media display correctly
   - No "connection timed out" errors
   - No "ERR_CONNECTION_RESET" errors
   - Browser shows secure connection (lock icon)

   ❌ FAILURE INDICATORS:
   - "This site can't be reached"
   - "ERR_CONNECTION_RESET" 
   - "ERR_TIMED_OUT"
   - Images fail to load
   - Blank or broken page layout

4. TROUBLESHOOTING:

   If x.com doesn't load:
   - Check service logs for errors
   - Verify service shows "Mapped IP ... (x.com) -> multidisorder"
   - Try restarting the service
   - Check Windows Firewall isn't blocking

   If images don't load:
   - Check twimg.com domains in service logs
   - Verify *.twimg.com strategies are configured
   - Check browser console for specific errors

5. LOGGING VERIFICATION:

   In the service console, look for these log messages:
   ✅ "Mapped IP 172.66.0.227 (x.com) -> multidisorder"
   ✅ "Mapped IP 162.159.140.229 (x.com) -> multidisorder"  
   ✅ "AutoTTL: N hops + 2 offset = TTL M"
   ✅ "Applying bypass for ... -> Type: multidisorder"

   If you see these, the bypass is working correctly.

=" * 70
"""
        return guide
        
    def run_validation(self) -> bool:
        """Run complete validation suite."""
        self.logger.info("🛡️ X.COM BROWSER ACCESS VALIDATION")
        self.logger.info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        overall_success = True
        
        # 1. Validate service configuration
        if not self.validate_service_configuration():
            self.logger.error("❌ Service configuration validation failed")
            overall_success = False
            
        # 2. Check DNS resolution
        domain_ips = self.check_dns_resolution()
        if not any(domain_ips.values()):
            self.logger.error("❌ DNS resolution failed for all domains")
            overall_success = False
            
        # 3. Check service status
        if not self.check_service_status():
            self.logger.error("❌ Service status check failed")
            overall_success = False
            
        # 4. Test basic connectivity
        connectivity_results = self.test_basic_connectivity(domain_ips)
        if not any(connectivity_results.values()):
            self.logger.error("❌ Basic connectivity failed for all domains")
            overall_success = False
            
        # 5. Test TLS handshake
        tls_results = self.test_tls_handshake(domain_ips)
        if not any(tls_results.values()):
            self.logger.error("❌ TLS handshake failed for all domains")
            overall_success = False
            
        # 6. Test HTTP requests
        http_results = self.test_http_requests()
        if not any(http_results.values()):
            self.logger.error("❌ HTTP requests failed for all domains")
            overall_success = False
            
        # Generate summary
        self.logger.info("=" * 70)
        self.logger.info("VALIDATION SUMMARY")
        self.logger.info("=" * 70)
        
        if overall_success:
            self.logger.info("✅ X.com bypass validation PASSED")
            self.logger.info("✅ Service is properly configured for x.com")
            self.logger.info("✅ Ready for manual browser testing")
        else:
            self.logger.error("❌ X.com bypass validation FAILED")
            self.logger.error("❌ Fix configuration issues before browser testing")
            
        # Always show browser testing guide
        print(self.generate_browser_test_guide())
        
        return overall_success


def main():
    """Main function."""
    validator = XComBrowserAccessValidator()
    
    try:
        success = validator.run_validation()
        
        if success:
            print("\n🎉 VALIDATION COMPLETED SUCCESSFULLY!")
            print("You can now proceed with manual browser testing.")
            print("Follow the guide above to test x.com access in your browser.")
        else:
            print("\n❌ VALIDATION FAILED!")
            print("Please fix the configuration issues before testing in browser.")
            
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n⚠️ Validation interrupted by user")
        return 1
    except Exception as e:
        validator.logger.error(f"❌ Validation failed with error: {e}")
        import traceback
        validator.logger.error(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())