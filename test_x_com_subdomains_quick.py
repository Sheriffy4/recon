#!/usr/bin/env python3
"""
Quick X.com Subdomains Test
Fast test to check if x.com subdomains are accessible with bypass service.
"""

import sys
import os
import time
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import requests

# Add recon to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_single_subdomain(subdomain, timeout=8):
    """Test a single subdomain with strict timeout"""
    print(f"\n🔍 Testing {subdomain}...")
    
    result = {
        'subdomain': subdomain,
        'accessible': False,
        'error': None,
        'response_time': None,
        'status_code': None
    }
    
    try:
        # First check DNS resolution
        print(f"  📍 Resolving DNS...")
        start_dns = time.time()
        ips = socket.getaddrinfo(subdomain, 443)
        dns_time = time.time() - start_dns
        ip_list = [ip[4][0] for ip in ips]
        print(f"     Resolved to: {ip_list} ({dns_time:.2f}s)")
        
        # Test HTTPS connection with aggressive timeout
        url = f"https://{subdomain}"
        print(f"  🌐 Testing HTTPS connection...")
        
        session = requests.Session()
        session.timeout = (3, timeout)  # 3s connect, 8s read
        
        start_time = time.time()
        
        response = session.get(
            url,
            timeout=(3, timeout),
            verify=False,  # Skip SSL verification for speed
            allow_redirects=False,  # Don't follow redirects
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        
        response_time = time.time() - start_time
        
        result['accessible'] = True
        result['response_time'] = round(response_time, 2)
        result['status_code'] = response.status_code
        
        print(f"  ✅ SUCCESS: HTTP {response.status_code} in {response_time:.2f}s")
        
    except requests.exceptions.Timeout:
        result['error'] = f'Timeout after {timeout}s'
        print(f"  ❌ TIMEOUT: No response after {timeout}s")
    except requests.exceptions.ConnectionError as e:
        result['error'] = f'Connection failed: {str(e)[:100]}'
        print(f"  ❌ CONNECTION ERROR: {str(e)[:100]}")
    except Exception as e:
        result['error'] = f'Error: {str(e)[:100]}'
        print(f"  ❌ ERROR: {str(e)[:100]}")
    
    return result

def check_bypass_service():
    """Quick check if bypass service is running"""
    try:
        # Check for python processes
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
    print("🚀 Quick X.com Subdomains Test")
    print("=" * 50)
    
    # Check service status
    service_status = check_bypass_service()
    
    # Subdomains to test
    subdomains = ['x.com', 'www.x.com', 'api.x.com', 'mobile.x.com']
    
    print(f"\n📋 Testing {len(subdomains)} subdomains with 8s timeout each:")
    
    results = []
    successful = 0
    
    # Test each subdomain sequentially to avoid overwhelming
    for subdomain in subdomains:
        try:
            result = test_single_subdomain(subdomain, timeout=8)
            results.append(result)
            
            if result['accessible']:
                successful += 1
                
        except KeyboardInterrupt:
            print(f"\n⏹️  Test interrupted by user")
            break
        except Exception as e:
            print(f"\n❌ Unexpected error testing {subdomain}: {e}")
            results.append({
                'subdomain': subdomain,
                'accessible': False,
                'error': f'Test error: {e}'
            })
    
    # Print summary
    print("\n" + "=" * 50)
    print("📊 QUICK TEST SUMMARY")
    print("=" * 50)
    
    total_tested = len(results)
    print(f"Total tested: {total_tested}")
    print(f"Successful: {successful}")
    print(f"Failed: {total_tested - successful}")
    print(f"Success rate: {(successful/total_tested*100):.1f}%")
    
    print(f"\n📋 DETAILED RESULTS:")
    for result in results:
        subdomain = result['subdomain']
        if result['accessible']:
            print(f"  ✅ {subdomain}: HTTP {result['status_code']} ({result['response_time']}s)")
        else:
            print(f"  ❌ {subdomain}: {result['error']}")
    
    # Assessment
    print(f"\n🎯 ASSESSMENT:")
    if successful == len(subdomains):
        print("  ✅ ALL SUBDOMAINS WORKING - X.com bypass successful!")
        print("  ✅ Requirement 6.6: PASS")
    elif successful > 0:
        print("  ⚠️  PARTIAL SUCCESS - Some subdomains working")
        print("  ❌ Requirement 6.6: PARTIAL")
    else:
        print("  ❌ NO SUBDOMAINS WORKING - Bypass not functioning")
        print("  ❌ Requirement 6.6: FAIL")
        
        if not service_status:
            print("\n💡 SUGGESTION: Start the bypass service first:")
            print("   python setup.py")
            print("   Select option [2] Start bypass service")
    
    return 0 if successful == len(subdomains) else 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⏹️  Test interrupted")
        sys.exit(130)