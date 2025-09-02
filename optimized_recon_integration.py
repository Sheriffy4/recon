#!/usr/bin/env python3
"""
Optimized Fingerprinting Integration Script

This script demonstrates how to integrate the parallel fingerprinting optimizations
into your existing recon system workflow.
"""

import asyncio
import json
import time
import logging
from pathlib import Path
from typing import List, Dict, Any

# Setup paths
import sys
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
LOG = logging.getLogger(__name__)

class OptimizedReconEngine:
    """Optimized recon engine with parallel fingerprinting"""
    
    def __init__(self, config_preset: str = "balanced_quality"):
        self.config_preset = config_preset
        self.fingerprinter = None
        self.stats = {
            "domains_processed": 0,
            "successful_fingerprints": 0,
            "total_time": 0.0,
            "average_time_per_domain": 0.0,
            "success_rate": 0.0
        }
        
    async def initialize(self):
        """Initialize the optimized fingerprinting engine"""
        
        # Load optimized configuration
        config_path = current_dir / "optimized_fingerprinting_config.json"
        if config_path.exists():
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            
            preset_config = config_data["optimized_fingerprinting_configs"][self.config_preset]["config"]
            
            # Create fingerprinting configuration
            self.config = FingerprintingConfig(
                analysis_level=preset_config["analysis_level"],
                enable_fail_fast=preset_config["enable_fail_fast"],
                enable_scapy_probes=preset_config["enable_scapy_probes"],
                sni_probe_mode=preset_config["sni_probe_mode"],
                max_parallel_targets=preset_config["max_parallel_targets"],
                connect_timeout=preset_config["connect_timeout"],
                tls_timeout=preset_config["tls_timeout"],
                udp_timeout=preset_config["udp_timeout"],
                dns_timeout=preset_config["dns_timeout"],
                enable_behavioral_probes=preset_config["enable_behavioral_probes"],
                enable_extended_metrics=preset_config["enable_extended_metrics"],
                retry_attempts=preset_config["retry_attempts"],
                cache_ttl=preset_config["cache_ttl"]
            )
        else:
            # Fallback to default optimized configuration
            self.config = FingerprintingConfig(
                analysis_level="balanced",
                enable_fail_fast=True,
                enable_scapy_probes=False,
                sni_probe_mode="basic",
                max_parallel_targets=15,
                connect_timeout=1.5,
                tls_timeout=2.0,
                udp_timeout=0.3
            )
        
        self.fingerprinter = AdvancedFingerprinter(config=self.config)
        LOG.info(f"Initialized optimized recon engine with preset: {self.config_preset}")
    
    async def process_sites_file(self, sites_file: str = "sites.txt") -> Dict[str, Any]:
        """Process sites.txt file with optimized parallel fingerprinting"""
        
        if not self.fingerprinter:
            await self.initialize()
        
        # Read domains from sites.txt
        sites_path = Path(sites_file)
        if not sites_path.exists():
            LOG.error(f"Sites file not found: {sites_file}")
            return {}
        
        domains = []
        with open(sites_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Clean up domain format
                    if line.startswith('http://') or line.startswith('https://'):
                        domain = line.replace('https://', '').replace('http://', '')
                    else:
                        domain = line
                    domains.append(domain)
        
        LOG.info(f"Found {len(domains)} domains in {sites_file}")
        
        # Create targets list
        targets = [(domain, 443) for domain in domains]
        
        # Process with parallel fingerprinting
        LOG.info(f"Starting parallel fingerprinting with concurrency={self.config.max_parallel_targets}")
        start_time = time.time()
        
        fingerprints = await self.fingerprinter.fingerprint_many(
            targets, 
            concurrency=self.config.max_parallel_targets
        )
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        successful_count = sum(1 for fp in fingerprints if fp is not None)
        self.stats.update({
            "domains_processed": len(domains),
            "successful_fingerprints": successful_count,
            "total_time": total_time,
            "average_time_per_domain": total_time / len(domains),
            "success_rate": successful_count / len(domains)
        })
        
        # Create results summary
        results = {
            "timestamp": time.time(),
            "config_preset": self.config_preset,
            "statistics": self.stats,
            "fingerprints": {}
        }
        
        # Process fingerprint results
        for i, (domain, port) in enumerate(targets):
            fp = fingerprints[i]
            if fp:
                results["fingerprints"][domain] = {
                    "dpi_type": fp.dpi_type.value if fp.dpi_type else "unknown",
                    "confidence": fp.confidence,
                    "reliability_score": fp.reliability_score,
                    "analysis_duration": fp.analysis_duration,
                    "block_type": fp.block_type,
                    "recommended_attacks": getattr(fp, 'recommended_attacks', []),
                    "predicted_weaknesses": getattr(fp, 'predicted_weaknesses', [])
                }
            else:
                results["fingerprints"][domain] = {
                    "dpi_type": "unknown",
                    "confidence": 0.0,
                    "error": "fingerprinting_failed"
                }
        
        return results
    
    async def generate_optimized_report(self, results: Dict[str, Any], output_file: str = None):
        """Generate optimized fingerprinting report"""
        
        if not output_file:
            timestamp = int(time.time())
            output_file = f"optimized_recon_report_{timestamp}.json"
        
        # Enhanced report with performance metrics
        report = {
            "metadata": {
                "version": "optimized_v1.0",
                "timestamp": results["timestamp"],
                "config_preset": results["config_preset"],
                "optimization_enabled": True
            },
            "performance_metrics": results["statistics"],
            "fingerprinting_results": results["fingerprints"],
            "summary": {
                "total_domains": results["statistics"]["domains_processed"],
                "successful_fingerprints": results["statistics"]["successful_fingerprints"],
                "success_rate_percent": round(results["statistics"]["success_rate"] * 100, 1),
                "total_analysis_time_seconds": round(results["statistics"]["total_time"], 2),
                "average_time_per_domain": round(results["statistics"]["average_time_per_domain"], 2),
                "estimated_speedup": f"{30 // results['statistics']['average_time_per_domain']:.1f}x vs sequential"
            }
        }
        
        # Analyze results by DPI type
        dpi_distribution = {}
        blocked_domains = []
        accessible_domains = []
        
        for domain, data in results["fingerprints"].items():
            dpi_type = data.get("dpi_type", "unknown")
            dpi_distribution[dpi_type] = dpi_distribution.get(dpi_type, 0) + 1
            
            if data.get("block_type") in ["none", "unknown"] and data.get("confidence", 0) > 0.5:
                accessible_domains.append(domain)
            else:
                blocked_domains.append(domain)
        
        report["analysis_summary"] = {
            "dpi_type_distribution": dpi_distribution,
            "blocked_domains_count": len(blocked_domains),
            "accessible_domains_count": len(accessible_domains),
            "blocked_domains": blocked_domains,
            "accessible_domains": accessible_domains
        }
        
        # Save report
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        LOG.info(f"Optimized report saved to: {output_file}")
        
        # Print summary
        print(f"\n{'='*60}")
        print("OPTIMIZED FINGERPRINTING RESULTS")
        print(f"{'='*60}")
        print(f"📊 Performance Metrics:")
        print(f"  Domains processed: {report['summary']['total_domains']}")
        print(f"  Success rate: {report['summary']['success_rate_percent']}%")
        print(f"  Total time: {report['summary']['total_analysis_time_seconds']}s")
        print(f"  Average per domain: {report['summary']['average_time_per_domain']}s")
        print(f"  Estimated speedup: {report['summary']['estimated_speedup']}")
        
        print(f"\n🔍 Analysis Summary:")
        print(f"  Blocked domains: {report['analysis_summary']['blocked_domains_count']}")
        print(f"  Accessible domains: {report['analysis_summary']['accessible_domains_count']}")
        
        if dpi_distribution:
            print(f"\n🛡️  DPI Type Distribution:")
            for dpi_type, count in sorted(dpi_distribution.items(), key=lambda x: x[1], reverse=True):
                print(f"  {dpi_type}: {count} domains")
        
        return output_file
    
    async def close(self):
        """Clean up resources"""
        if self.fingerprinter:
            await self.fingerprinter.close()


async def main():
    """Main integration example"""
    
    print("🚀 Optimized Recon Engine - Integration Example")
    print("="*60)
    
    # Test different presets
    presets = ["fast_production", "balanced_quality", "ci_testing"]
    
    for preset in presets:
        print(f"\n🧪 Testing preset: {preset}")
        
        engine = OptimizedReconEngine(config_preset=preset)
        
        try:
            # Process sites.txt file
            results = await engine.process_sites_file("sites.txt")
            
            if results:
                # Generate report
                report_file = await engine.generate_optimized_report(
                    results, 
                    f"recon_report_{preset}_{int(time.time())}.json"
                )
                
                print(f"✅ Report generated: {report_file}")
            else:
                print("❌ No results generated")
        
        except Exception as e:
            LOG.error(f"Error with preset {preset}: {e}")
        
        finally:
            await engine.close()
    
    print(f"\n{'='*60}")
    print("INTEGRATION COMPLETE")
    print(f"{'='*60}")
    print("📋 Next Steps:")
    print("1. Review generated reports to choose optimal preset")
    print("2. Integrate chosen preset into your main recon workflow")
    print("3. Monitor performance and adjust concurrency as needed")
    print("4. Use caching to avoid re-analyzing same domains")


if __name__ == "__main__":
    asyncio.run(main())