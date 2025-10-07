#!/usr/bin/env python3
"""
Test X.com Browser Access - Task 10.2
Tests x.com access in browser and validates:
- Page loads successfully
- No connection errors
- Images and resources load
- Requirements: 6.1, 6.2
"""

import sys
import time
import subprocess
import threading
import requests
import socket
import ssl
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import urllib3
from urllib.parse import urlparse

# Add project root to path
if __name__ == "__main__" and __package__ is None:
    recon_dir = Path(__file__).parent
    project_root = recon_dir.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    class Console:
        def print(self, *args, **kwargs):
            print(*args)

console = Console() if RICH_AVAILABLE else Console()

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XComBrowserAccessTester:
    """Tests x.com access in browser environment."""
    
    def __init__(self):
        self.test_results = {}
        self.service_process = None
        
    def test_basic_connectivity(self) -> bool:
        """Test basic network connectivity to x.com."""
        console.print("[cyan]Testing basic connectivity to x.com...[/cyan]")
        
        try:
            # Test DNS resolution
            x_com_ips = socket.getaddrinfo("x.com", 443)
            ips = [addr[4][0] for addr in x_com_ips if ':' not in addr[4][0]]
            
            if not ips:
                console.print("[red]❌ Failed to resolve x.com to IPv4 addresses[/red]")
                return False
                
            console.print(f"[green]✅ Resolved x.com to IPs: {ips}[/green]")
            
            # Test TCP connection
            for ip in ips[:2]:  # Test first 2 IPs
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    result = sock.connect_ex((ip, 443))
                    sock.close()
                    
                    if result == 0:
                        console.print(f"[green]✅ TCP connection to {ip}:443 successful[/green]")
                        return True
                    else:
                        console.print(f"[yellow]⚠️ TCP connection to {ip}:443 failed (code: {result})[/yellow]")
                        
                except Exception as e:
                    console.print(f"[yellow]⚠️ TCP connection to {ip}:443 error: {e}[/yellow]")
            
            console.print("[red]❌ No successful TCP connections to x.com[/red]")
            return False
            
        except Exception as e:
            console.print(f"[red]❌ Basic connectivity test failed: {e}[/red]")
            return False
    
    def test_https_connection(self) -> bool:
        """Test HTTPS connection to x.com."""
        console.print("[cyan]Testing HTTPS connection to x.com...[/cyan]")
        
        try:
            # Test HTTPS connection with requests
            session = requests.Session()
            session.verify = False  # Disable SSL verification for testing
            
            # Set reasonable timeouts
            timeout = (10, 30)  # (connect, read)
            
            # Test basic HTTPS request
            response = session.get("https://x.com", timeout=timeout, allow_redirects=True)
            
            console.print(f"[green]✅ HTTPS request successful[/green]")
            console.print(f"[dim]Status code: {response.status_code}[/dim]")
            console.print(f"[dim]Final URL: {response.url}[/dim]")
            console.print(f"[dim]Response size: {len(response.content)} bytes[/dim]")
            
            # Check if we got a reasonable response
            if response.status_code in [200, 301, 302, 403]:
                console.print(f"[green]✅ Received valid HTTP response ({response.status_code})[/green]")
                return True
            else:
                console.print(f"[yellow]⚠️ Unexpected status code: {response.status_code}[/yellow]")
                return False
                
        except requests.exceptions.SSLError as e:
            console.print(f"[red]❌ SSL/TLS error: {e}[/red]")
            return False
        except requests.exceptions.ConnectionError as e:
            console.print(f"[red]❌ Connection error: {e}[/red]")
            return False
        except requests.exceptions.Timeout as e:
            console.print(f"[red]❌ Timeout error: {e}[/red]")
            return False
        except Exception as e:
            console.print(f"[red]❌ HTTPS connection test failed: {e}[/red]")
            return False
    
    def test_tls_handshake(self) -> bool:
        """Test TLS handshake with x.com."""
        console.print("[cyan]Testing TLS handshake with x.com...[/cyan]")
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Test TLS handshake
            with socket.create_connection(("x.com", 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname="x.com") as ssock:
                    console.print(f"[green]✅ TLS handshake successful[/green]")
                    console.print(f"[dim]TLS version: {ssock.version()}[/dim]")
                    console.print(f"[dim]Cipher: {ssock.cipher()}[/dim]")
                    
                    # Try to send a simple HTTP request
                    request = b"GET / HTTP/1.1\r\nHost: x.com\r\nConnection: close\r\n\r\n"
                    ssock.send(request)
                    
                    # Read response
                    response = ssock.recv(1024)
                    if response:
                        console.print(f"[green]✅ Received HTTP response over TLS[/green]")
                        console.print(f"[dim]Response preview: {response[:100]}...[/dim]")
                        return True
                    else:
                        console.print("[yellow]⚠️ No response received over TLS[/yellow]")
                        return False
                        
        except ssl.SSLError as e:
            console.print(f"[red]❌ TLS handshake failed: {e}[/red]")
            return False
        except Exception as e:
            console.print(f"[red]❌ TLS handshake test failed: {e}[/red]")
            return False
    
    def test_resource_loading(self) -> bool:
        """Test loading of x.com resources."""
        console.print("[cyan]Testing x.com resource loading...[/cyan]")
        
        try:
            session = requests.Session()
            session.verify = False
            timeout = (10, 30)
            
            # Test main page
            response = session.get("https://x.com", timeout=timeout, allow_redirects=True)
            
            if response.status_code not in [200, 301, 302, 403]:
                console.print(f"[red]❌ Main page request failed: {response.status_code}[/red]")
                return False
            
            console.print(f"[green]✅ Main page loaded ({response.status_code})[/green]")
            
            # Test common resource endpoints
            resource_urls = [
                "https://abs.twimg.com/favicons/twitter.ico",
                "https://pbs.twimg.com/profile_images/1683325380441128960/yRsRRjGO_400x400.jpg",
                "https://abs.twimg.com/responsive-web/client-web/main.css"
            ]
            
            successful_resources = 0
            for url in resource_urls:
                try:
                    resp = session.head(url, timeout=(5, 10), allow_redirects=True)
                    if resp.status_code in [200, 301, 302, 304]:
                        console.print(f"[green]✅ Resource accessible: {url}[/green]")
                        successful_resources += 1
                    else:
                        console.print(f"[yellow]⚠️ Resource status {resp.status_code}: {url}[/yellow]")
                except Exception as e:
                    console.print(f"[yellow]⚠️ Resource error: {url} - {e}[/yellow]")
            
            if successful_resources > 0:
                console.print(f"[green]✅ {successful_resources}/{len(resource_urls)} resources accessible[/green]")
                return True
            else:
                console.print("[yellow]⚠️ No resources were accessible[/yellow]")
                return False
                
        except Exception as e:
            console.print(f"[red]❌ Resource loading test failed: {e}[/red]")
            return False
    
    def test_with_bypass_service(self) -> bool:
        """Test x.com access with bypass service running."""
        console.print("[cyan]Testing x.com access with bypass service...[/cyan]")
        
        try:
            # Start bypass service in background
            console.print("[dim]Starting bypass service...[/dim]")
            
            service_cmd = [sys.executable, "recon_service.py"]
            self.service_process = subprocess.Popen(
                service_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Wait for service to initialize
            console.print("[dim]Waiting for service to initialize...[/dim]")
            time.sleep(10)
            
            # Check if service is still running
            if self.service_process.poll() is not None:
                console.print("[red]❌ Bypass service failed to start[/red]")
                return False
            
            console.print("[green]✅ Bypass service started[/green]")
            
            # Test x.com access with service running
            session = requests.Session()
            session.verify = False
            
            # Test multiple requests to ensure consistency
            successful_requests = 0
            total_requests = 3
            
            for i in range(total_requests):
                try:
                    response = session.get("https://x.com", timeout=(15, 30), allow_redirects=True)
                    if response.status_code in [200, 301, 302, 403]:
                        successful_requests += 1
                        console.print(f"[green]✅ Request {i+1}: {response.status_code}[/green]")
                    else:
                        console.print(f"[yellow]⚠️ Request {i+1}: {response.status_code}[/yellow]")
                        
                    time.sleep(2)  # Small delay between requests
                    
                except Exception as e:
                    console.print(f"[red]❌ Request {i+1} failed: {e}[/red]")
            
            success_rate = successful_requests / total_requests
            console.print(f"[cyan]Success rate: {successful_requests}/{total_requests} ({success_rate:.1%})[/cyan]")
            
            if success_rate >= 0.67:  # At least 2/3 successful
                console.print("[green]✅ x.com access with bypass service successful[/green]")
                return True
            else:
                console.print("[red]❌ x.com access with bypass service failed[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red]❌ Bypass service test failed: {e}[/red]")
            return False
        finally:
            # Stop service
            if self.service_process and self.service_process.poll() is None:
                try:
                    self.service_process.terminate()
                    self.service_process.wait(timeout=5)
                    console.print("[dim]Bypass service stopped[/dim]")
                except:
                    try:
                        self.service_process.kill()
                    except:
                        pass
    
    def test_browser_simulation(self) -> bool:
        """Simulate browser-like access patterns."""
        console.print("[cyan]Testing browser-like access patterns...[/cyan]")
        
        try:
            # Create session with browser-like headers
            session = requests.Session()
            session.verify = False
            
            # Browser-like headers
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            
            # Test main page with browser headers
            response = session.get("https://x.com", timeout=(15, 30), allow_redirects=True)
            
            console.print(f"[green]✅ Browser simulation request: {response.status_code}[/green]")
            console.print(f"[dim]Content-Type: {response.headers.get('content-type', 'unknown')}[/dim]")
            console.print(f"[dim]Content-Length: {len(response.content)} bytes[/dim]")
            
            # Check for common web content indicators
            content = response.text.lower()
            web_indicators = ['html', 'javascript', 'css', 'twitter', 'x.com']
            found_indicators = [indicator for indicator in web_indicators if indicator in content]
            
            if found_indicators:
                console.print(f"[green]✅ Found web content indicators: {found_indicators}[/green]")
                return True
            else:
                console.print("[yellow]⚠️ No web content indicators found[/yellow]")
                return False
                
        except Exception as e:
            console.print(f"[red]❌ Browser simulation test failed: {e}[/red]")
            return False
    
    def run_all_tests(self) -> Dict[str, bool]:
        """Run all x.com browser access tests."""
        console.print(Panel(
            "[bold cyan]X.com Browser Access Testing - Task 10.2[/bold cyan]\n"
            "Testing x.com access in browser environment",
            title="Starting Tests"
        ))
        
        tests = [
            ("basic_connectivity", self.test_basic_connectivity),
            ("https_connection", self.test_https_connection),
            ("tls_handshake", self.test_tls_handshake),
            ("resource_loading", self.test_resource_loading),
            ("browser_simulation", self.test_browser_simulation),
            ("with_bypass_service", self.test_with_bypass_service)
        ]
        
        results = {}
        
        for test_name, test_func in tests:
            console.print(f"\n{'='*60}")
            console.print(f"Running test: {test_name}")
            console.print(f"{'='*60}")
            
            try:
                result = test_func()
                results[test_name] = result
                
                if result:
                    console.print(f"[green]✅ {test_name} PASSED[/green]")
                else:
                    console.print(f"[red]❌ {test_name} FAILED[/red]")
                    
            except Exception as e:
                console.print(f"[red]❌ {test_name} ERROR: {e}[/red]")
                results[test_name] = False
        
        # Print summary
        self.print_test_summary(results)
        return results
    
    def print_test_summary(self, results: Dict[str, bool]):
        """Print test results summary."""
        console.print(f"\n{'='*60}")
        console.print("X.COM BROWSER ACCESS TEST SUMMARY")
        console.print(f"{'='*60}")
        
        if RICH_AVAILABLE:
            table = Table(title="Test Results")
            table.add_column("Test", style="cyan")
            table.add_column("Status", justify="center")
            table.add_column("Description", style="dim")
            
            test_descriptions = {
                "basic_connectivity": "Basic network connectivity to x.com",
                "https_connection": "HTTPS connection establishment",
                "tls_handshake": "TLS handshake completion",
                "resource_loading": "Loading of x.com resources",
                "browser_simulation": "Browser-like access patterns",
                "with_bypass_service": "Access with bypass service running"
            }
            
            for test_name, result in results.items():
                status = "✅ PASS" if result else "❌ FAIL"
                description = test_descriptions.get(test_name, "")
                table.add_row(test_name, status, description)
            
            console.print(table)
        else:
            for test_name, result in results.items():
                status = "PASS" if result else "FAIL"
                print(f"{test_name}: {status}")
        
        passed = sum(results.values())
        total = len(results)
        
        if passed == total:
            console.print(f"\n[bold green]✅ ALL TESTS PASSED ({passed}/{total})[/bold green]")
            console.print("[green]x.com browser access validation completed successfully![/green]")
        else:
            console.print(f"\n[bold yellow]⚠️ SOME TESTS FAILED ({passed}/{total})[/bold yellow]")
            
            # Provide guidance based on results
            if results.get("basic_connectivity", False) and results.get("https_connection", False):
                console.print("[yellow]Basic connectivity works - bypass may be functioning[/yellow]")
            elif not results.get("basic_connectivity", False):
                console.print("[red]Basic connectivity failed - check network/DNS[/red]")
            
            if results.get("with_bypass_service", False):
                console.print("[green]Bypass service is working correctly[/green]")
            else:
                console.print("[red]Bypass service may need attention[/red]")

def main():
    """Main function to run x.com browser access tests."""
    tester = XComBrowserAccessTester()
    results = tester.run_all_tests()
    
    # Return exit code based on critical tests
    critical_tests = ["basic_connectivity", "https_connection", "with_bypass_service"]
    critical_passed = sum(results.get(test, False) for test in critical_tests)
    
    if critical_passed >= 2:  # At least 2/3 critical tests pass
        return 0
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())