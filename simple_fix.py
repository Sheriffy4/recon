#!/usr/bin/env python3
"""
Simple but effective fix for the main issues identified in the analysis.
"""

import json
import logging
import os
import shutil
from typing import List

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
LOG = logging.getLogger(__name__)

def fix_sites_file():
    """Fix the corrupted sites.txt file."""
    LOG.info("Fixing sites.txt file...")
    
    # Create backup
    if os.path.exists("sites.txt"):
        shutil.copy2("sites.txt", "sites.txt.corrupted_backup")
    
    # Create clean domains list based on the analysis
    clean_domains = [
        "https://x.com",
        "https://instagram.com", 
        "https://nnmclub.to",
        "https://rutracker.org",
        "https://youtube.com",
        "https://facebook.com",
        "https://telegram.org",
        "https://www.x.com",
        "https://api.x.com",
        "https://mobile.x.com",
        "https://www.youtube.com",
        "https://www.facebook.com",
        # Expanded wildcard domains
        "https://pbs.twimg.com",
        "https://abs.twimg.com",
        "https://abs-0.twimg.com",
        "https://video.twimg.com",
        "https://ton.twimg.com",
        "https://static.cdninstagram.com",
        "https://scontent-arn2-1.cdninstagram.com",
        "https://edge-chat.instagram.com",
        "https://static.xx.fbcdn.net",
        "https://external.xx.fbcdn.net",
        "https://youtubei.googleapis.com",
        "https://i.ytimg.com",
        "https://i1.ytimg.com",
        "https://i2.ytimg.com",
        "https://lh3.ggpht.com",
        "https://lh4.ggpht.com",
        "https://cdnjs.cloudflare.net",
        "https://www.fastly.com",
        "https://api.fastly.com"
    ]
    
    with open("sites.txt", "w", encoding="utf-8") as f:
        for domain in clean_domains:
            f.write(domain + "\n")
    
    LOG.info(f"Fixed sites.txt with {len(clean_domains)} clean domains")
    return True

def create_improved_configs():
    """Create improved configuration files."""
    LOG.info("Creating improved configuration files...")
    
    # 1. Enhanced timeout configuration
    timeout_config = {
        "connection_timeouts": {
            "tcp_connect": 15.0,  # Increased from default
            "tls_handshake": 20.0,  # Increased for slow handshakes
            "http_request": 25.0,
            "total_request": 40.0
        },
        "retry_policy": {
            "max_retries": 5,  # More retries for blocked domains
            "retry_delay": 2.0,  # Longer delays between retries
            "backoff_multiplier": 1.5,
            "retry_on_timeout": True,
            "retry_on_handshake_failure": True,
            "retry_on_connection_reset": True
        },
        "tls_options": {
            "verify_ssl": False,  # Disable SSL verification
            "check_hostname": False,  # Disable hostname checking  
            "use_sni": True,
            "fallback_no_sni": True,  # Try without SNI if with SNI fails
            "protocols": ["TLSv1.2", "TLSv1.3"],
            "alpn_protocols": ["h2", "http/1.1"]
        }
    }
    
    with open("improved_timeout_config.json", "w", encoding="utf-8") as f:
        json.dump(timeout_config, f, indent=2)
    
    # 2. Better strategy configuration
    strategy_config = {
        "default_strategy": "multisplit(ttl=4, split_count=5)",
        "domain_specific": {
            "x.com": "seqovl(positions=[1,3,7], split_pos=2, overlap_size=15)",
            "instagram.com": "multisplit(ttl=3, split_count=7) + disorder(ttl=2)",
            "youtube.com": "syndata_fake(flags=0x18, split_pos=3)",
            "facebook.com": "seqovl(positions=[1,5,10], split_pos=3, overlap_size=20)",
            "pbs.twimg.com": "multisplit(ttl=4, split_count=6)",
            "abs.twimg.com": "disorder(ttl=3) + multisplit(ttl=2, split_count=5)",
            "static.cdninstagram.com": "badsum_race(ttl=3) + disorder(ttl=2)"
        },
        "fallback_strategies": [
            "multisplit(ttl=3, split_count=5)",
            "seqovl(positions=[1,4,8], split_pos=2, overlap_size=10)",
            "disorder(ttl=4)",
            "syndata_fake(flags=0x18, split_pos=2)",
            "badsum_race(ttl=3)"
        ]
    }
    
    with open("improved_strategies.json", "w", encoding="utf-8") as f:
        json.dump(strategy_config, f, indent=2)
    
    # 3. DNS resolution configuration
    dns_config = {
        "doh_enabled": True,
        "doh_providers": [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/resolve", 
            "https://9.9.9.9/dns-query"
        ],
        "fallback_to_system": True,
        "cache_ttl": 300,
        "resolve_timeout": 10,
        "max_retries": 3,
        "wildcard_expansion": {
            "*.twimg.com": ["pbs", "abs", "abs-0", "video", "ton"],
            "*.cdninstagram.com": ["static", "scontent-arn2-1"],
            "*.fbcdn.net": ["static.xx", "external.xx"],
            "*.ytimg.com": ["i", "i1", "i2", "i3"],
            "*.ggpht.com": ["lh3", "lh4", "lh5"]
        }
    }
    
    with open("improved_dns_config.json", "w", encoding="utf-8") as f:
        json.dump(dns_config, f, indent=2)
    
    LOG.info("Created improved configuration files")
    return True

def create_test_script():
    """Create a simple test script."""
    test_script = '''#!/usr/bin/env python3
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
'''
    
    with open("test_improvements.py", "w", encoding="utf-8") as f:
        f.write(test_script)
    
    LOG.info("Created test script")
    return True

def main():
    """Apply simple but effective fixes."""
    
    print("🔧 Applying simple fixes for recon system...")
    
    try:
        # Fix the corrupted sites file
        fix_sites_file()
        
        # Create improved configurations
        create_improved_configs()
        
        # Create test script
        create_test_script()
        
        print("\n✅ Simple fixes applied successfully!")
        
        print("\n📋 Files created/modified:")
        print("  • sites.txt - Fixed with clean domain list")
        print("  • improved_timeout_config.json - Better timeout handling")
        print("  • improved_strategies.json - Enhanced bypass strategies")
        print("  • improved_dns_config.json - Better DNS resolution")
        print("  • test_improvements.py - Validation test script")
        
        print("\n🧪 Next steps:")
        print("  1. Run 'python test_improvements.py' to test connections")
        print("  2. Use improved_timeout_config.json in your bypass engine")
        print("  3. Update strategy selection to use improved_strategies.json")
        print("  4. Implement DNS config from improved_dns_config.json")
        
        print("\n💡 Key improvements:")
        print("  • Expanded wildcard domains to specific subdomains")
        print("  • Increased timeouts for slow/blocked connections")
        print("  • Added retry mechanisms for failed connections")
        print("  • Disabled SSL verification to avoid certificate blocks")
        print("  • Added fallback strategies for better coverage")
        
        return True
        
    except Exception as e:
        LOG.error(f"Error applying fixes: {e}")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)