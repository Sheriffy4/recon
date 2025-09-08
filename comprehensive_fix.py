#!/usr/bin/env python3
"""
Comprehensive fix for all identified issues in the recon system.
This script addresses:
1. DNS resolution issues for wildcard domains
2. Timeout and TLS handshake failures
3. Poor strategy selection
4. Packet fragmentation improvements
"""

import asyncio
import json
import logging
import sys
import os
from pathlib import Path
from typing import Dict, List, Any
import traceback

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger(__name__)

class ComprehensiveFix:
    """Comprehensive fix for all recon system issues."""
    
    def __init__(self):
        self.fixes_applied = []
        self.backup_files = []
        
    def backup_file(self, file_path: str) -> str:
        """Create backup of file before modification."""
        if not os.path.exists(file_path):
            return None
            
        backup_path = f"{file_path}.backup"
        try:
            import shutil
            shutil.copy2(file_path, backup_path)
            self.backup_files.append(backup_path)
            LOG.info(f"Created backup: {backup_path}")
            return backup_path
        except Exception as e:
            LOG.error(f"Failed to create backup for {file_path}: {e}")
            return None
    
    def fix_dns_resolution_issues(self):
        """Fix DNS resolution issues for wildcard domains."""
        LOG.info("Applying DNS resolution fixes...")
        
        fixes = []
        
        # 1. Update sites.txt to expand wildcard domains
        sites_file = "sites.txt"
        if os.path.exists(sites_file):
            self.backup_file(sites_file)
            
            # Try different encodings to handle corrupted files
            lines = []
            for encoding in ['utf-8', 'utf-16', 'cp1252', 'latin1']:
                try:
                    with open(sites_file, 'r', encoding=encoding) as f:
                        lines = f.readlines()
                    break
                except UnicodeDecodeError:
                    continue
            
            if not lines:
                LOG.warning(f"Could not read {sites_file} with any encoding, creating new file")
                lines = []
            
            # Clean and normalize the lines
            clean_lines = []
            for line in lines:
                # Remove null bytes and strange characters
                line = line.replace('\x00', '').replace('\uffff', '').strip()
                # Remove spaces between characters (encoding artifact)
                line = ''.join(line.split())
                if line and not line.startswith('#'):
                    if not line.startswith('http'):
                        line = 'https://' + line
                    clean_lines.append(line)
            
            expanded_lines = []
            for line in clean_lines:
                if line.startswith("https://*."):
                    # Expand wildcard domains
                    domain = line.replace("https://", "").replace("*.", "")
                    if domain == "twimg.com":
                        expanded_lines.extend([
                            "https://pbs.twimg.com",
                            "https://abs.twimg.com", 
                            "https://abs-0.twimg.com",
                            "https://video.twimg.com",
                            "https://ton.twimg.com"
                        ])
                    elif domain == "cdninstagram.com":
                        expanded_lines.extend([
                            "https://static.cdninstagram.com",
                            "https://scontent-arn2-1.cdninstagram.com"
                        ])
                    elif domain == "fbcdn.net":
                        expanded_lines.extend([
                            "https://static.xx.fbcdn.net",
                            "https://external.xx.fbcdn.net"
                        ])
                    elif domain == "ytimg.com":
                        expanded_lines.extend([
                            "https://i.ytimg.com",
                            "https://i1.ytimg.com",
                            "https://i2.ytimg.com"
                        ])
                    elif domain == "googleapis.com":
                        expanded_lines.extend([
                            "https://youtubei.googleapis.com",
                            "https://www.googleapis.com"
                        ])
                    elif domain == "ggpht.com":
                        expanded_lines.extend([
                            "https://lh3.ggpht.com",
                            "https://lh4.ggpht.com"
                        ])
                    elif domain == "cloudflare.net":
                        expanded_lines.extend([
                            "https://cdnjs.cloudflare.net",
                            "https://www.cloudflare.net"
                        ])
                    elif domain == "fastly.com":
                        expanded_lines.extend([
                            "https://www.fastly.com",
                            "https://api.fastly.com"
                        ])
                    elif domain == "fastly.net":
                        expanded_lines.extend([
                            "https://www.fastly.net",
                            "https://api.fastly.net"
                        ])
                    else:
                        # Keep original wildcard for unknown domains
                        expanded_lines.append(line)
                else:
                    expanded_lines.append(line)
            
            with open(sites_file, 'w', encoding='utf-8') as f:
                for line in expanded_lines:
                    f.write(line + '\n')
            
            fixes.append("Expanded wildcard domains in sites.txt")
        
        # 2. Update engine configuration for better DNS handling
        engine_config_file = "config/engine_config.json"
        if os.path.exists(engine_config_file):
            self.backup_file(engine_config_file)
            
            with open(engine_config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Add DNS configuration
            if "dns" not in config:
                config["dns"] = {}
            
            config["dns"].update({
                "use_doh": True,
                "doh_providers": ["cloudflare", "google", "quad9"],
                "fallback_to_system": True,
                "cache_ttl": 600,
                "resolve_timeout": 5,
                "max_retries": 3
            })
            
            # Update timeout settings
            if "timeouts" not in config:
                config["timeouts"] = {}
            
            config["timeouts"].update({
                "connection_timeout": 10,
                "handshake_timeout": 15,
                "read_timeout": 20,
                "max_retries": 3
            })
            
            with open(engine_config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            
            fixes.append("Updated engine configuration for better DNS and timeouts")
        
        self.fixes_applied.extend(fixes)
        return fixes
    
    def fix_timeout_issues(self):
        """Fix timeout and TLS handshake issues."""
        LOG.info("Applying timeout and TLS fixes...")
        
        fixes = []
        
        # 1. Create improved timeout configuration
        timeout_config = {
            "connection_timeouts": {
                "tcp_connect": 10.0,
                "tls_handshake": 15.0,
                "http_request": 20.0,
                "total_request": 30.0
            },
            "retry_policy": {
                "max_retries": 3,
                "retry_delay": 1.0,
                "backoff_multiplier": 2.0,
                "retry_on_timeout": True,
                "retry_on_handshake_failure": True
            },
            "tls_options": {
                "verify_ssl": False,
                "check_hostname": False,
                "use_sni": True,
                "fallback_no_sni": True,
                "cipher_suites": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!eNULL",
                "protocols": ["TLSv1.2", "TLSv1.3"],
                "alpn_protocols": ["h2", "http/1.1"]
            }
        }
        
        with open("timeout_config.json", 'w', encoding='utf-8') as f:
            json.dump(timeout_config, f, indent=2)
        
        fixes.append("Created improved timeout configuration")
        
        # 2. Update monitoring configuration to track timeouts
        monitoring_config_file = "monitoring_config.json"
        if os.path.exists(monitoring_config_file):
            self.backup_file(monitoring_config_file)
            
            with open(monitoring_config_file, 'r', encoding='utf-8') as f:
                monitoring_config = json.load(f)
            
            # Add timeout monitoring
            monitoring_config["metrics"]["timeouts"] = {
                "connection_timeouts": {"threshold": 0.1, "alert": True},
                "handshake_timeouts": {"threshold": 0.15, "alert": True},
                "total_timeouts": {"threshold": 0.2, "alert": True}
            }
            
            with open(monitoring_config_file, 'w', encoding='utf-8') as f:
                json.dump(monitoring_config, f, indent=2)
            
            fixes.append("Updated monitoring configuration for timeout tracking")
        
        self.fixes_applied.extend(fixes)
        return fixes
    
    def improve_strategy_selection(self):
        """Improve strategy selection algorithm."""
        LOG.info("Improving strategy selection...")
        
        fixes = []
        
        # 1. Update strategies.json with better configurations
        strategies_file = "strategies.json"
        if os.path.exists(strategies_file):
            self.backup_file(strategies_file)
            
            with open(strategies_file, 'r', encoding='utf-8') as f:
                strategies = json.load(f)
            
            # Add improved strategies for problematic domains
            improved_strategies = {
                "x.com": "multisplit(ttl=3, split_count=5) + disorder(ttl=2)",
                "instagram.com": "seqovl(positions=[1,3,7], split_pos=2, overlap_size=10)",
                "youtube.com": "syndata_fake(flags=0x18, split_pos=3)",
                "facebook.com": "multisplit(ttl=4, split_count=7) + badsum_race(ttl=3)",
                "pbs.twimg.com": "disorder(ttl=4) + multisplit(ttl=3, split_count=5)",
                "abs.twimg.com": "multisplit(ttl=4, split_count=7)",
                "abs-0.twimg.com": "multisplit(ttl=4, split_count=7)",
                "video.twimg.com": "seqovl(positions=[1,5,10], split_pos=3, overlap_size=20)",
                "static.cdninstagram.com": "disorder(ttl=3) + badsum_race(ttl=2)",
                "scontent-arn2-1.cdninstagram.com": "multisplit(ttl=5, split_count=6)",
                "www.youtube.com": "syndata_fake(flags=0x18, split_pos=4)",
                "www.facebook.com": "seqovl(positions=[1,4,8], split_pos=2, overlap_size=15)"
            }
            
            strategies.update(improved_strategies)
            
            with open(strategies_file, 'w', encoding='utf-8') as f:
                json.dump(strategies, f, indent=2)
            
            fixes.append("Updated strategy configurations for better bypass rates")
        
        # 2. Create strategy priority configuration
        strategy_priority = {
            "high_success_strategies": [
                "multisplit",
                "seqovl", 
                "disorder",
                "syndata_fake"
            ],
            "fallback_strategies": [
                "badsum_race",
                "fakedisorder",
                "fakedata"
            ],
            "domain_specific_overrides": {
                "social_media": ["multisplit", "seqovl"],
                "cdn_domains": ["disorder", "syndata_fake"], 
                "api_endpoints": ["badsum_race", "multisplit"]
            },
            "strategy_weights": {
                "multisplit": 0.9,
                "seqovl": 0.85,
                "disorder": 0.8,
                "syndata_fake": 0.75,
                "badsum_race": 0.6,
                "fakedisorder": 0.5,
                "fakedata": 0.4
            }
        }
        
        with open("strategy_priority.json", 'w', encoding='utf-8') as f:
            json.dump(strategy_priority, f, indent=2)
        
        fixes.append("Created strategy priority configuration")
        
        self.fixes_applied.extend(fixes)
        return fixes
    
    def enhance_fragmentation(self):
        """Enhance packet fragmentation strategies."""
        LOG.info("Enhancing fragmentation strategies...")
        
        fixes = []
        
        # Create fragmentation configuration
        fragmentation_config = {
            "ip_fragmentation": {
                "enabled": True,
                "fragment_sizes": [8, 16, 32, 64],
                "overlap_bytes": [0, 4, 8],
                "out_of_order": True,
                "duplicate_fragments": False
            },
            "tcp_fragmentation": {
                "enabled": True,
                "segment_sizes": [1, 4, 8, 16],
                "segment_timing": [0, 10, 50, 100],  # ms delays
                "out_of_order_segments": True,
                "partial_segments": True
            },
            "tls_fragmentation": {
                "enabled": True,
                "handshake_fragmentation": True,
                "record_fragmentation": True,
                "fragment_sizes": [1, 8, 16, 32],
                "inter_fragment_delay": [0, 5, 10]
            },
            "http_fragmentation": {
                "enabled": True,
                "header_fragmentation": True,
                "body_fragmentation": True,
                "fragment_boundaries": ["random", "field", "word"],
                "case_variations": True
            }
        }
        
        with open("fragmentation_config.json", 'w', encoding='utf-8') as f:
            json.dump(fragmentation_config, f, indent=2)
        
        fixes.append("Created enhanced fragmentation configuration")
        
        self.fixes_applied.extend(fixes)
        return fixes
    
    def create_fixed_test_script(self):
        """Create a test script to validate fixes."""
        test_script = '''#!/usr/bin/env python3
"""
Test script to validate comprehensive fixes.
"""

import asyncio
import json
import logging
from improved_timeout_handler import ImprovedTimeoutHandler, test_domain_connections
from domain_manager_fixed import DomainManagerFixed

LOG = logging.getLogger(__name__)

async def test_fixes():
    """Test all applied fixes."""
    print("🔧 Testing comprehensive fixes...")
    
    # Test domains from the original failure report
    test_domains = [
        'x.com',
        'instagram.com', 
        'youtube.com',
        'facebook.com',
        'pbs.twimg.com',
        'abs.twimg.com',
        'static.cdninstagram.com'
    ]
    
    print(f"\\n📋 Testing {len(test_domains)} domains...")
    
    # Test improved timeout handling
    results = await test_domain_connections(test_domains)
    
    success_count = sum(1 for r in results.values() if r.get('success', False))
    total_count = len(results)
    
    print(f"\\n📊 Results:")
    print(f"  Successful connections: {success_count}/{total_count} ({success_count/total_count:.1%})")
    
    for domain, result in results.items():
        status = "✅ SUCCESS" if result.get('success', False) else "❌ FAILED"
        print(f"  {domain}: {status}")
        if not result.get('success', False) and result.get('error'):
            print(f"    Error: {result['error']}")
            if result.get('recommendations'):
                print(f"    Recommendations: {', '.join(result['recommendations'])}")
    
    # Test DNS resolution with new domain manager
    print(f"\\n🔍 Testing improved DNS resolution...")
    
    domain_manager = DomainManagerFixed(default_domains=test_domains)
    dns_stats = domain_manager.get_resolution_stats()
    
    print(f"  DNS resolution stats: {dns_stats}")
    
    return success_count / total_count

if __name__ == "__main__":
    asyncio.run(test_fixes())
'''
        
        with open("test_comprehensive_fixes.py", 'w', encoding='utf-8') as f:
            f.write(test_script)
        
        self.fixes_applied.append("Created validation test script")
    
    def generate_summary_report(self):
        """Generate a summary report of all fixes applied."""
        
        report = {
            "timestamp": str(asyncio.get_event_loop().time()),
            "fixes_applied": self.fixes_applied,
            "backup_files": self.backup_files,
            "summary": {
                "total_fixes": len(self.fixes_applied),
                "dns_fixes": len([f for f in self.fixes_applied if "DNS" in f or "dns" in f]),
                "timeout_fixes": len([f for f in self.fixes_applied if "timeout" in f or "TLS" in f]),
                "strategy_fixes": len([f for f in self.fixes_applied if "strategy" in f]),
                "fragmentation_fixes": len([f for f in self.fixes_applied if "fragmentation" in f])
            },
            "recommendations": [
                "Run test_comprehensive_fixes.py to validate improvements",
                "Monitor success rates using monitoring_config.json",
                "Adjust strategy_priority.json based on observed effectiveness",
                "Use fragmentation_config.json for advanced DPI evasion",
                "Restore from backup files if issues occur"
            ]
        }
        
        with open("comprehensive_fixes_report.json", 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    async def apply_all_fixes(self):
        """Apply all identified fixes."""
        
        LOG.info("🚀 Starting comprehensive fix application...")
        
        try:
            # Apply all fixes
            dns_fixes = self.fix_dns_resolution_issues()
            timeout_fixes = self.fix_timeout_issues()
            strategy_fixes = self.improve_strategy_selection()
            fragmentation_fixes = self.enhance_fragmentation()
            
            # Create test script
            self.create_fixed_test_script()
            
            # Generate summary
            report = self.generate_summary_report()
            
            LOG.info(f"✅ Applied {len(self.fixes_applied)} fixes successfully")
            
            print("\\n" + "="*60)
            print("COMPREHENSIVE FIXES APPLIED")
            print("="*60)
            
            print(f"\\n📊 SUMMARY:")
            print(f"  Total fixes applied: {report['summary']['total_fixes']}")
            print(f"  DNS resolution fixes: {report['summary']['dns_fixes']}")
            print(f"  Timeout/TLS fixes: {report['summary']['timeout_fixes']}")
            print(f"  Strategy improvements: {report['summary']['strategy_fixes']}")
            print(f"  Fragmentation enhancements: {report['summary']['fragmentation_fixes']}")
            
            print(f"\\n🔧 FIXES APPLIED:")
            for i, fix in enumerate(self.fixes_applied, 1):
                print(f"  {i}. {fix}")
            
            print(f"\\n💾 BACKUP FILES:")
            for backup in self.backup_files:
                print(f"  {backup}")
            
            print(f"\\n🧪 NEXT STEPS:")
            for rec in report["recommendations"]:
                print(f"  • {rec}")
            
            print(f"\\n📄 Full report saved to: comprehensive_fixes_report.json")
            
            return True
            
        except Exception as e:
            LOG.error(f"Error applying fixes: {e}")
            traceback.print_exc()
            return False


async def main():
    fixer = ComprehensiveFix()
    success = await fixer.apply_all_fixes()
    
    if success:
        print("\\n✅ All fixes applied successfully!")
        print("Run 'python test_comprehensive_fixes.py' to validate improvements.")
    else:
        print("\\n❌ Some fixes failed. Check logs for details.")

if __name__ == "__main__":
    asyncio.run(main())