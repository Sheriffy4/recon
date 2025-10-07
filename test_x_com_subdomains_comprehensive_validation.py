#!/usr/bin/env python3
"""
Comprehensive X.com Subdomains Testing Script
Tests all x.com subdomains to verify bypass functionality works correctly.

This script validates:
- www.x.com
- api.x.com (if accessible)
- mobile.x.com
- All use correct strategy and work properly

Requirements: 6.6
"""

import sys
import os
import time
import json
import socket
import requests
import subprocess
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse

# Add recon to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class XComSubdomainTester:
    """Comprehensive tester for all x.com subdomains"""
    
    def __init__(self):
        self.results = {
            'test_timestamp': datetime.now().isoformat(),
            'subdomains_tested': [],
            'successful_subdomains': [],
            'failed_subdomains': [],
            'detailed_results': {},
            'service_status': 'unknown',
            'strategy_verification': {}
        }
        
        # X.com subdomains to test
        self.subdomains = [
            'x.com',
            'www.x.com', 
            'api.x.com',
            'mobile.x.com'
        ]
        
        # Expected strategy for all x.com subdomains
        self.expected_strategy = {
            'desync_method': 'multidisorder',
            'autottl': 2,
            'fooling': ['badseq'],
            'repeats': 2,
            'split_pos': 46,
            'overlap_size': 1
        }
        
        self.session = requests.Session()
        # Set aggressive timeouts to prevent hanging
        self.session.timeout = (5, 10)  # (connect_timeout, read_timeout)
        
    def check_service_status(self) -> bool:
        """Check if bypass service is running"""
        try:
            # Check if recon service process is running
            result = subprocess.run(
                ['tasklist', '/FI', 'IMAGENAME eq python.exe'],
                capture_output=True, text=True, shell=True
            )
            
            if 'python.exe' in result.stdout:
                print("✅ Python processes found - service likely running")
                self.results['service_status'] = 'running'
                return True
            else:
                print("❌ No Python processes found - service may not be running")
                self.results['service_status'] = 'not_running'
                return False
                
        except Exception as e:
            print(f"⚠️  Could not check service status: {e}")
            self.results['service_status'] = 'unknown'
            return True  # Assume running and continue tests
    
    def resolve_subdomain(self, subdomain: str) -> List[str]:
        """Resolve subdomain to IP addresses"""
        try:
            ips = []
            result = socket.getaddrinfo(subdomain, None)
            for item in result:
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)
            return ips
        except Exception as e:
            print(f"❌ Failed to resolve {subdomain}: {e}")
            return []
    
    def check_strategy_config(self, subdomain: str) -> Dict:
        """Check if subdomain has correct strategy in config"""
        try:
            strategies_file = 'strategies.json'
            if os.path.exists(strategies_file):
                with open(strategies_file, 'r', encoding='utf-8') as f:
                    strategies = json.load(f)
                
                if subdomain in strategies:
                    strategy_str = strategies[subdomain]
                    print(f"✅ {subdomain} found in strategies.json: {strategy_str}")
                    
                    # Parse strategy string to verify parameters
                    parsed = self.parse_strategy_string(strategy_str)
                    return {
                        'configured': True,
                        'strategy_string': strategy_str,
                        'parsed_params': parsed,
                        'matches_expected': self.verify_strategy_params(parsed)
                    }
                else:
                    print(f"❌ {subdomain} not found in strategies.json")
                    return {'configured': False}
            else:
                print(f"❌ strategies.json not found")
                return {'configured': False, 'error': 'strategies.json not found'}
                
        except Exception as e:
            print(f"❌ Error checking strategy config for {subdomain}: {e}")
            return {'configured': False, 'error': str(e)}
    
    def parse_strategy_string(self, strategy_str: str) -> Dict:
        """Parse zapret-style strategy string"""
        params = {}
        
        if '--dpi-desync=multidisorder' in strategy_str:
            params['desync_method'] = 'multidisorder'
        elif '--dpi-desync=fakeddisorder' in strategy_str:
            params['desync_method'] = 'fakeddisorder'
            
        if '--dpi-desync-autottl=' in strategy_str:
            try:
                start = strategy_str.find('--dpi-desync-autottl=') + len('--dpi-desync-autottl=')
                end = strategy_str.find(' ', start)
                if end == -1:
                    end = len(strategy_str)
                params['autottl'] = int(strategy_str[start:end])
            except:
                pass
                
        if '--dpi-desync-fooling=' in strategy_str:
            try:
                start = strategy_str.find('--dpi-desync-fooling=') + len('--dpi-desync-fooling=')
                end = strategy_str.find(' ', start)
                if end == -1:
                    end = len(strategy_str)
                fooling_str = strategy_str[start:end]
                params['fooling'] = fooling_str.split(',')
            except:
                pass
                
        if '--dpi-desync-repeats=' in strategy_str:
            try:
                start = strategy_str.find('--dpi-desync-repeats=') + len('--dpi-desync-repeats=')
                end = strategy_str.find(' ', start)
                if end == -1:
                    end = len(strategy_str)
                params['repeats'] = int(strategy_str[start:end])
            except:
                pass
                
        if '--dpi-desync-split-pos=' in strategy_str:
            try:
                start = strategy_str.find('--dpi-desync-split-pos=') + len('--dpi-desync-split-pos=')
                end = strategy_str.find(' ', start)
                if end == -1:
                    end = len(strategy_str)
                params['split_pos'] = int(strategy_str[start:end])
            except:
                pass
                
        if '--dpi-desync-split-seqovl=' in strategy_str:
            try:
                start = strategy_str.find('--dpi-desync-split-seqovl=') + len('--dpi-desync-split-seqovl=')
                end = strategy_str.find(' ', start)
                if end == -1:
                    end = len(strategy_str)
                params['overlap_size'] = int(strategy_str[start:end])
            except:
                pass
        
        return params
    
    def verify_strategy_params(self, parsed_params: Dict) -> bool:
        """Verify parsed parameters match expected strategy"""
        for key, expected_value in self.expected_strategy.items():
            if key not in parsed_params:
                print(f"❌ Missing parameter: {key}")
                return False
            if parsed_params[key] != expected_value:
                print(f"❌ Parameter mismatch: {key} = {parsed_params[key]}, expected {expected_value}")
                return False
        
        print("✅ All strategy parameters match expected values")
        return True
    
    def test_subdomain_connectivity(self, subdomain: str) -> Dict:
        """Test if subdomain is accessible via HTTPS"""
        print(f"\n🔍 Testing {subdomain}...")
        
        result = {
            'subdomain': subdomain,
            'accessible': False,
            'response_code': None,
            'response_time_ms': None,
            'error': None,
            'resolved_ips': [],
            'strategy_config': {},
            'tls_handshake': False,
            'content_loaded': False
        }
        
        # Resolve IPs
        result['resolved_ips'] = self.resolve_subdomain(subdomain)
        if not result['resolved_ips']:
            result['error'] = 'DNS resolution failed'
            return result
        
        print(f"  📍 Resolved to IPs: {result['resolved_ips']}")
        
        # Check strategy configuration
        result['strategy_config'] = self.check_strategy_config(subdomain)
        
        # Test HTTPS connectivity
        try:
            url = f"https://{subdomain}"
            print(f"  🌐 Testing HTTPS connection to {url}")
            print(f"     Using timeout: connect=5s, read=10s")
            
            start_time = time.time()
            
            # Make request with custom headers to look like real browser
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            print(f"     Initiating request...")
            response = self.session.get(
                url, 
                headers=headers, 
                verify=True, 
                allow_redirects=True,
                timeout=(5, 10)  # Explicit timeout per request
            )
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            result['response_code'] = response.status_code
            result['response_time_ms'] = round(response_time, 2)
            result['tls_handshake'] = True
            
            if response.status_code == 200:
                result['accessible'] = True
                result['content_loaded'] = len(response.content) > 0
                print(f"  ✅ SUCCESS: {subdomain} accessible (HTTP {response.status_code}, {response_time:.1f}ms)")
                print(f"     Content length: {len(response.content)} bytes")
                
                # Check if we got actual content (not just error page)
                if len(response.content) > 1000:  # Reasonable threshold for real content
                    print(f"     ✅ Substantial content received - bypass working correctly")
                else:
                    print(f"     ⚠️  Limited content received - may be error page")
                    
            elif 300 <= response.status_code < 400:
                result['accessible'] = True
                print(f"  ✅ REDIRECT: {subdomain} redirected (HTTP {response.status_code})")
            else:
                result['error'] = f'HTTP {response.status_code}'
                print(f"  ❌ HTTP Error: {response.status_code}")
                
        except requests.exceptions.SSLError as e:
            result['error'] = f'SSL/TLS Error: {str(e)}'
            print(f"  ❌ SSL/TLS Error: {e}")
        except requests.exceptions.ConnectionError as e:
            result['error'] = f'Connection Error: {str(e)}'
            print(f"  ❌ Connection Error: {e}")
        except requests.exceptions.Timeout as e:
            result['error'] = f'Timeout: {str(e)}'
            print(f"  ❌ Timeout: {e}")
        except Exception as e:
            result['error'] = f'Unexpected Error: {str(e)}'
            print(f"  ❌ Unexpected Error: {e}")
        
        return result
    
    def run_comprehensive_test(self) -> Dict:
        """Run comprehensive test of all x.com subdomains"""
        print("🚀 Starting comprehensive x.com subdomains test...")
        print("=" * 60)
        
        # Check service status first
        service_running = self.check_service_status()
        if not service_running:
            print("\n⚠️  Warning: Bypass service may not be running!")
            print("   Consider starting the service first for accurate results.")
        
        print(f"\n📋 Testing {len(self.subdomains)} subdomains:")
        for subdomain in self.subdomains:
            print(f"   - {subdomain}")
        
        # Test each subdomain
        for subdomain in self.subdomains:
            self.results['subdomains_tested'].append(subdomain)
            
            result = self.test_subdomain_connectivity(subdomain)
            self.results['detailed_results'][subdomain] = result
            
            if result['accessible']:
                self.results['successful_subdomains'].append(subdomain)
            else:
                self.results['failed_subdomains'].append(subdomain)
            
            # Store strategy verification results
            if result['strategy_config'].get('configured'):
                self.results['strategy_verification'][subdomain] = result['strategy_config']
        
        return self.results
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        
        total = len(self.results['subdomains_tested'])
        successful = len(self.results['successful_subdomains'])
        failed = len(self.results['failed_subdomains'])
        
        print(f"Total subdomains tested: {total}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Success rate: {(successful/total*100):.1f}%")
        
        if self.results['successful_subdomains']:
            print(f"\n✅ WORKING SUBDOMAINS:")
            for subdomain in self.results['successful_subdomains']:
                result = self.results['detailed_results'][subdomain]
                print(f"   - {subdomain} (HTTP {result['response_code']}, {result['response_time_ms']}ms)")
        
        if self.results['failed_subdomains']:
            print(f"\n❌ FAILED SUBDOMAINS:")
            for subdomain in self.results['failed_subdomains']:
                result = self.results['detailed_results'][subdomain]
                print(f"   - {subdomain}: {result['error']}")
        
        # Strategy configuration summary
        print(f"\n🔧 STRATEGY CONFIGURATION:")
        configured_count = 0
        for subdomain, config in self.results['strategy_verification'].items():
            if config.get('configured'):
                configured_count += 1
                matches = "✅" if config.get('matches_expected') else "❌"
                print(f"   {matches} {subdomain}: configured")
            else:
                print(f"   ❌ {subdomain}: not configured")
        
        print(f"\nConfigured subdomains: {configured_count}/{total}")
        
        # Overall assessment
        print(f"\n🎯 OVERALL ASSESSMENT:")
        if successful == total and configured_count == total:
            print("   ✅ ALL TESTS PASSED - X.com bypass working correctly for all subdomains")
        elif successful > 0:
            print("   ⚠️  PARTIAL SUCCESS - Some subdomains working, others need attention")
        else:
            print("   ❌ ALL TESTS FAILED - X.com bypass not working")
        
        # Requirements verification
        print(f"\n📋 REQUIREMENTS VERIFICATION:")
        print(f"   Requirement 6.6 (All x.com subdomains work): {'✅ PASS' if successful == total else '❌ FAIL'}")
    
    def save_results(self, filename: str = None):
        """Save detailed results to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"x_com_subdomains_test_results_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"\n💾 Detailed results saved to: {filename}")
        except Exception as e:
            print(f"\n❌ Failed to save results: {e}")

def main():
    """Main test execution"""
    print("X.com Subdomains Comprehensive Test")
    print("Testing all x.com subdomains for bypass functionality")
    print("Requirements: 6.6")
    
    tester = XComSubdomainTester()
    
    try:
        # Run comprehensive test
        results = tester.run_comprehensive_test()
        
        # Print summary
        tester.print_summary()
        
        # Save results
        tester.save_results()
        
        # Return appropriate exit code
        total_tested = len(results['subdomains_tested'])
        successful = len(results['successful_subdomains'])
        
        if successful == total_tested:
            print(f"\n🎉 All {total_tested} subdomains working correctly!")
            return 0
        else:
            print(f"\n⚠️  Only {successful}/{total_tested} subdomains working")
            return 1
            
    except KeyboardInterrupt:
        print("\n\n⏹️  Test interrupted by user")
        return 130
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)