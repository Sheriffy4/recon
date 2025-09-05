#!/usr/bin/env python3
"""
Simple test script to validate improvements
"""

import asyncio
import ssl
import socket
import time
from typing import Dict, List

async def test_domain_connection(domain: str, port: int = 443) -> Dict:
    """Test connection to a domain."""
    domain_clean = domain.replace("https://", "").replace("http://", "")
    
    result = {
        "domain": domain,
        "success": False,
        "error": None,
        "connect_time": 0,
        "resolved_ip": None
    }
    
    start_time = time.time()
    
    try:
        # Resolve domain
        ip = socket.gethostbyname(domain_clean)
        result["resolved_ip"] = ip
        
        # Create SSL context with minimal verification
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Try connection with timeout
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context, server_hostname=domain_clean),
            timeout=15.0
        )
        
        result["success"] = True
        result["connect_time"] = time.time() - start_time
        
        writer.close()
        await writer.wait_closed()
        
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
    except asyncio.TimeoutError:
        result["error"] = "Connection timeout"
    except ssl.SSLError as e:
        result["error"] = f"SSL/TLS error: {e}"
    except Exception as e:
        result["error"] = f"Connection error: {e}"
    
    return result

async def test_improvements():
    """Test connection improvements."""
    
    # Test domains from sites.txt
    test_domains = [
        "x.com",
        "instagram.com",
        "youtube.com",
        "facebook.com",
        "pbs.twimg.com",
        "abs.twimg.com",
        "static.cdninstagram.com"
    ]
    
    print(f"Testing {len(test_domains)} domains...")
    print("="*60)
    
    results = []
    for domain in test_domains:
        result = await test_domain_connection(domain)
        results.append(result)
        
        status = "✅ SUCCESS" if result["success"] else "❌ FAILED"
        time_str = f"({result['connect_time']:.2f}s)" if result["success"] else ""
        print(f"{domain}: {status} {time_str}")
        
        if not result["success"]:
            print(f"  Error: {result['error']}")
    
    # Summary
    success_count = sum(1 for r in results if r["success"])
    print("="*60)
    print(f"Results: {success_count}/{len(results)} domains successful ({success_count/len(results):.1%})")
    
    if success_count > 0:
        avg_time = sum(r["connect_time"] for r in results if r["success"]) / success_count
        print(f"Average connection time: {avg_time:.2f}s")

if __name__ == "__main__":
    asyncio.run(test_improvements())
