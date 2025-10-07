#!/usr/bin/env python3
"""
Simple X.com Connectivity Test

This script performs basic connectivity tests to x.com to validate if the
router-tested strategy parameters are effective without complex TLS testing.
"""

import socket
import time
import sys
import os
import json
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def test_basic_connectivity(domain="x.com", port=443, timeout=10):
    """Test basic TCP connectivity to domain"""
    try:
        # Resolve domain
        ip = socket.gethostbyname(domain)
        print(f"Resolved {domain} to {ip}")
        
        # Test TCP connection
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        result = sock.connect_ex((ip, port))
        latency = (time.time() - start_time) * 1000
        
        sock.close()
        
        if result == 0:
            print(f"✓ TCP connection to {domain}:{port} successful ({latency:.1f}ms)")
            return True, latency, ip
        else:
            print(f"✗ TCP connection to {domain}:{port} failed (error {result})")
            return False, latency, ip
            
    except Exception as e:
        print(f"✗ Connection test failed: {e}")
        return False, 0, None

def test_http_request(domain="x.com", timeout=15):
    """Test HTTP request to domain"""
    try:
        import urllib.request
        import urllib.error
        import ssl
        
        # Create SSL context that's more permissive
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        url = f"https://{domain}/"
        
        start_time = time.time()
        
        # Create request with proper headers
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
        req.add_header('Accept-Language', 'en-US,en;q=0.5')
        req.add_header('Accept-Encoding', 'gzip, deflate')
        req.add_header('Connection', 'keep-alive')
        
        # Make request
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            latency = (time.time() - start_time) * 1000
            status_code = response.getcode()
            content_length = len(response.read())
            
            print(f"✓ HTTPS request to {domain} successful")
            print(f"  Status: {status_code}, Content: {content_length} bytes, Latency: {latency:.1f}ms")
            return True, latency, status_code, content_length
            
    except urllib.error.HTTPError as e:
        latency = (time.time() - start_time) * 1000
        print(f"✗ HTTP error {e.code}: {e.reason} ({latency:.1f}ms)")
        return False, latency, e.code, 0
    except urllib.error.URLError as e:
        latency = (time.time() - start_time) * 1000
        print(f"✗ URL error: {e.reason} ({latency:.1f}ms)")
        return False, latency, 0, 0
    except Exception as e:
        latency = (time.time() - start_time) * 1000
        print(f"✗ Request failed: {e} ({latency:.1f}ms)")
        return False, latency, 0, 0

def test_multiple_subdomains():
    """Test connectivity to multiple x.com subdomains"""
    subdomains = ["x.com", "www.x.com", "api.x.com", "mobile.x.com"]
    results = {}
    
    print("Testing connectivity to x.com subdomains...")
    print("=" * 60)
    
    for subdomain in subdomains:
        print(f"\nTesting {subdomain}:")
        
        # Test TCP connectivity
        tcp_success, tcp_latency, ip = test_basic_connectivity(subdomain)
        
        # Test HTTPS request
        if tcp_success:
            https_success, https_latency, status_code, content_length = test_http_request(subdomain)
        else:
            https_success, https_latency, status_code, content_length = False, 0, 0, 0
        
        results[subdomain] = {
            'ip': ip,
            'tcp_success': tcp_success,
            'tcp_latency_ms': tcp_latency,
            'https_success': https_success,
            'https_latency_ms': https_latency,
            'status_code': status_code,
            'content_length': content_length,
            'timestamp': datetime.now().isoformat()
        }
    
    return results

def analyze_connectivity_results(results):
    """Analyze connectivity test results"""
    print("\n" + "=" * 60)
    print("CONNECTIVITY ANALYSIS SUMMARY")
    print("=" * 60)
    
    total_domains = len(results)
    tcp_success_count = sum(1 for r in results.values() if r['tcp_success'])
    https_success_count = sum(1 for r in results.values() if r['https_success'])
    
    print(f"Total domains tested: {total_domains}")
    print(f"TCP connectivity success: {tcp_success_count}/{total_domains} ({tcp_success_count/total_domains:.1%})")
    print(f"HTTPS request success: {https_success_count}/{total_domains} ({https_success_count/total_domains:.1%})")
    
    if tcp_success_count > 0:
        avg_tcp_latency = sum(r['tcp_latency_ms'] for r in results.values() if r['tcp_success']) / tcp_success_count
        print(f"Average TCP latency: {avg_tcp_latency:.1f}ms")
    
    if https_success_count > 0:
        avg_https_latency = sum(r['https_latency_ms'] for r in results.values() if r['https_success']) / https_success_count
        print(f"Average HTTPS latency: {avg_https_latency:.1f}ms")
    
    print("\nDetailed Results:")
    for domain, result in results.items():
        tcp_status = "✓" if result['tcp_success'] else "✗"
        https_status = "✓" if result['https_success'] else "✗"
        print(f"  {domain} ({result['ip']}): TCP {tcp_status} HTTPS {https_status}")
        if result['https_success']:
            print(f"    Status: {result['status_code']}, Size: {result['content_length']} bytes")
    
    # Generate recommendations
    recommendations = []
    
    if https_success_count == total_domains:
        recommendations.append({
            'priority': 'HIGH',
            'title': 'All X.com Domains Accessible ✓',
            'description': f'All {total_domains} x.com subdomains are successfully accessible',
            'action': 'Current bypass configuration appears to be working correctly'
        })
    elif https_success_count > 0:
        recommendations.append({
            'priority': 'MEDIUM',
            'title': 'Partial X.com Access',
            'description': f'{https_success_count}/{total_domains} x.com subdomains are accessible',
            'action': 'Investigate failed domains and verify bypass configuration'
        })
    else:
        recommendations.append({
            'priority': 'CRITICAL',
            'title': 'No X.com Access ✗',
            'description': 'All x.com subdomains are inaccessible',
            'action': 'Check bypass service status and network configuration'
        })
    
    if tcp_success_count == total_domains and https_success_count == 0:
        recommendations.append({
            'priority': 'HIGH',
            'title': 'TCP Success but HTTPS Failure',
            'description': 'TCP connections succeed but HTTPS requests fail',
            'action': 'This may indicate DPI is blocking TLS handshakes - verify bypass is active'
        })
    
    return {
        'summary': {
            'total_domains': total_domains,
            'tcp_success_count': tcp_success_count,
            'https_success_count': https_success_count,
            'tcp_success_rate': tcp_success_count / total_domains,
            'https_success_rate': https_success_count / total_domains,
            'avg_tcp_latency_ms': sum(r['tcp_latency_ms'] for r in results.values() if r['tcp_success']) / tcp_success_count if tcp_success_count > 0 else 0,
            'avg_https_latency_ms': sum(r['https_latency_ms'] for r in results.values() if r['https_success']) / https_success_count if https_success_count > 0 else 0
        },
        'results': results,
        'recommendations': recommendations,
        'timestamp': datetime.now().isoformat()
    }

def main():
    """Main function"""
    print("X.com Simple Connectivity Test")
    print("=" * 60)
    print("This test validates basic connectivity to x.com without bypass engine integration.")
    print("It helps determine if the network path to x.com is working correctly.\n")
    
    try:
        # Test connectivity to all x.com subdomains
        results = test_multiple_subdomains()
        
        # Analyze results
        analysis = analyze_connectivity_results(results)
        
        # Save results
        output_file = "x_com_connectivity_test.json"
        with open(output_file, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        
        print(f"\nRecommendations:")
        for rec in analysis['recommendations']:
            print(f"  [{rec['priority']}] {rec['title']}")
            print(f"      {rec['description']}")
            print(f"      Action: {rec['action']}")
        
        print(f"\nResults saved to: {output_file}")
        
        # Return appropriate exit code
        if analysis['summary']['https_success_count'] > 0:
            print("\n✓ At least some x.com domains are accessible")
            return 0
        else:
            print("\n✗ No x.com domains are accessible")
            return 1
            
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        return 1
    except Exception as e:
        print(f"\nTest failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())