#!/usr/bin/env python3
"""
Parallel Fingerprinting Optimization Demo

This script demonstrates the performance improvements achieved through parallel processing
and fail-fast optimizations in the DPI fingerprinting system.
"""

import asyncio
import time
import logging
from typing import List, Tuple
from pathlib import Path

# Setup paths
import sys
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
from core.fingerprint.config import PerformanceConfig

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger(__name__)

# Test domains based on your sites.txt
TEST_DOMAINS = [
    "x.com",
    "instagram.com", 
    "youtube.com",
    "facebook.com",
    "pbs.twimg.com",
    "abs.twimg.com",
    "static.cdninstagram.com",
    "www.youtube.com",
    "www.facebook.com",
    "youtubei.googleapis.com",
    "i.ytimg.com",
    "lh3.ggpht.com",
    "cdnjs.cloudflare.net",
    "api.fastly.com",
    "rutracker.org",
    "nnmclub.to",
    "telegram.org",
    "api.x.com",
    "mobile.x.com",
    "video.twimg.com",
    "ton.twimg.com",
    "scontent-arn2-1.cdninstagram.com",
    "edge-chat.instagram.com",
    "static.xx.fbcdn.net",
    "external.xx.fbcdn.net",
    "i1.ytimg.com",
    "i2.ytimg.com",
    "lh4.ggpht.com",
    "www.fastly.com",
    "www.cloudflare.net"
]

class PerformanceBenchmark:
    """Performance benchmarking for fingerprinting optimizations"""
    
    def __init__(self):
        self.results = {}
    
    async def benchmark_sequential_vs_parallel(self, domains: List[str]):
        """Compare sequential vs parallel processing performance"""
        
        targets = [(domain, 443) for domain in domains[:10]]  # Test with first 10 domains
        
        print(f"\n{'='*60}")
        print("PERFORMANCE BENCHMARK: Sequential vs Parallel")
        print(f"{'='*60}")
        print(f"Testing {len(targets)} domains...")
        
        # Test 1: Sequential (traditional approach)
        await self._test_sequential_processing(targets)
        
        # Test 2: Parallel with different concurrency levels
        for concurrency in [5, 10, 15]:
            await self._test_parallel_processing(targets, concurrency)
        
        # Test 3: Fast mode vs Full mode
        await self._test_analysis_levels(targets[:5])  # Use fewer domains for this test
        
        self._print_performance_summary()
    
    async def _test_sequential_processing(self, targets: List[Tuple[str, int]]):
        """Test traditional sequential processing"""
        
        config = FingerprintingConfig(
            analysis_level="balanced",
            enable_fail_fast=False,
            enable_scapy_probes=False,
            sni_probe_mode="basic"
        )
        
        fingerprinter = AdvancedFingerprinter(config=config)
        
        print(f"\n🔄 Testing Sequential Processing...")
        start_time = time.time()
        
        fingerprints = []
        for domain, port in targets:
            try:
                fp = await fingerprinter.fingerprint_target(domain, port)
                fingerprints.append(fp)
            except Exception as e:
                LOG.warning(f"Sequential test failed for {domain}: {e}")
                fingerprints.append(None)
        
        total_time = time.time() - start_time
        success_count = sum(1 for fp in fingerprints if fp is not None)
        
        self.results['sequential'] = {
            'total_time': total_time,
            'success_count': success_count,
            'total_domains': len(targets),
            'avg_time_per_domain': total_time / len(targets),
            'success_rate': success_count / len(targets)
        }
        
        print(f"  ✓ Completed in {total_time:.2f}s")
        print(f"  ✓ Success rate: {success_count}/{len(targets)} ({success_count/len(targets):.1%})")
        print(f"  ✓ Average time per domain: {total_time/len(targets):.2f}s")
        
        await fingerprinter.close()
    
    async def _test_parallel_processing(self, targets: List[Tuple[str, int]], concurrency: int):
        """Test parallel processing with specified concurrency"""
        
        config = FingerprintingConfig(
            analysis_level="balanced",
            enable_fail_fast=True,
            enable_scapy_probes=False,
            sni_probe_mode="basic",
            max_parallel_targets=concurrency
        )
        
        fingerprinter = AdvancedFingerprinter(config=config)
        
        print(f"\n⚡ Testing Parallel Processing (concurrency={concurrency})...")
        start_time = time.time()
        
        # Use the new fingerprint_many method
        fingerprints = await fingerprinter.fingerprint_many(
            targets, 
            concurrency=concurrency
        )
        
        total_time = time.time() - start_time
        success_count = sum(1 for fp in fingerprints if fp is not None)
        
        # Calculate speedup compared to sequential
        sequential_time = self.results.get('sequential', {}).get('total_time', total_time)
        speedup = sequential_time / total_time if total_time > 0 else 1.0
        
        self.results[f'parallel_{concurrency}'] = {
            'total_time': total_time,
            'success_count': success_count,
            'total_domains': len(targets),
            'avg_time_per_domain': total_time / len(targets),
            'success_rate': success_count / len(targets),
            'speedup': speedup,
            'concurrency': concurrency
        }
        
        print(f"  ✓ Completed in {total_time:.2f}s")
        print(f"  ✓ Success rate: {success_count}/{len(targets)} ({success_count/len(targets):.1%})")
        print(f"  ✓ Average time per domain: {total_time/len(targets):.2f}s")
        print(f"  ✓ Speedup vs sequential: {speedup:.1f}x")
        
        await fingerprinter.close()
    
    async def _test_analysis_levels(self, targets: List[Tuple[str, int]]):
        """Test different analysis levels (fast vs balanced vs full)"""
        
        print(f"\n🎯 Testing Analysis Levels...")
        
        for level in ["fast", "balanced", "full"]:
            config = FingerprintingConfig(
                analysis_level=level,
                enable_fail_fast=True,
                enable_scapy_probes=(level == "full"),  # Only enable scapy probes in full mode
                sni_probe_mode="basic" if level == "fast" else "detailed",
                enable_behavioral_probes=(level in ["balanced", "full"]),
                max_parallel_targets=10
            )
            
            fingerprinter = AdvancedFingerprinter(config=config)
            
            print(f"  Testing {level} mode...")
            start_time = time.time()
            
            fingerprints = await fingerprinter.fingerprint_many(targets, concurrency=10)
            
            total_time = time.time() - start_time
            success_count = sum(1 for fp in fingerprints if fp is not None)
            avg_confidence = sum(fp.confidence for fp in fingerprints if fp is not None) / success_count if success_count > 0 else 0
            
            self.results[f'analysis_{level}'] = {
                'total_time': total_time,
                'success_count': success_count,
                'total_domains': len(targets),
                'avg_time_per_domain': total_time / len(targets),
                'success_rate': success_count / len(targets),
                'avg_confidence': avg_confidence,
                'analysis_level': level
            }
            
            print(f"    ✓ {level} mode: {total_time:.2f}s, confidence: {avg_confidence:.2f}")
            
            await fingerprinter.close()
    
    def _print_performance_summary(self):
        """Print comprehensive performance summary"""
        
        print(f"\n{'='*60}")
        print("PERFORMANCE SUMMARY")
        print(f"{'='*60}")
        
        # Sequential vs Parallel comparison
        if 'sequential' in self.results:
            seq = self.results['sequential']
            print(f"\n📊 Processing Mode Comparison:")
            print(f"  Sequential:          {seq['total_time']:.2f}s ({seq['avg_time_per_domain']:.2f}s/domain)")
            
            for key, result in self.results.items():
                if key.startswith('parallel_'):
                    print(f"  Parallel (n={result['concurrency']:2d}):      {result['total_time']:.2f}s "
                          f"({result['avg_time_per_domain']:.2f}s/domain) - {result['speedup']:.1f}x faster")
        
        # Analysis level comparison
        analysis_results = {k: v for k, v in self.results.items() if k.startswith('analysis_')}
        if analysis_results:
            print(f"\n🎯 Analysis Level Comparison:")
            for key, result in analysis_results.items():
                level = result['analysis_level']
                print(f"  {level.capitalize():>9} mode:      {result['total_time']:.2f}s "
                      f"(confidence: {result['avg_confidence']:.2f})")
        
        # Best configuration recommendation
        parallel_results = {k: v for k, v in self.results.items() if k.startswith('parallel_')}
        if parallel_results:
            best_parallel = min(parallel_results.values(), key=lambda x: x['total_time'])
            print(f"\n💡 Recommended Configuration:")
            print(f"  Best parallel setting: concurrency={best_parallel['concurrency']} "
                  f"({best_parallel['speedup']:.1f}x speedup)")
            print(f"  For production: analysis_level='fast' or 'balanced'")
            print(f"  For maximum speed: enable_fail_fast=True, enable_scapy_probes=False")


async def create_optimized_config_examples():
    """Create example configurations for different use cases"""
    
    print(f"\n{'='*60}")
    print("OPTIMIZED CONFIGURATION EXAMPLES")
    print(f"{'='*60}")
    
    configs = {
        "Fast Production": FingerprintingConfig(
            analysis_level="fast",
            enable_fail_fast=True,
            enable_scapy_probes=False,
            sni_probe_mode="basic",
            max_parallel_targets=15,
            connect_timeout=1.0,
            tls_timeout=1.5,
            udp_timeout=0.2,
            enable_behavioral_probes=False
        ),
        
        "Balanced Quality": FingerprintingConfig(
            analysis_level="balanced",
            enable_fail_fast=True,
            enable_scapy_probes=False,
            sni_probe_mode="basic",
            max_parallel_targets=10,
            connect_timeout=1.5,
            tls_timeout=2.0,
            udp_timeout=0.3,
            enable_behavioral_probes=True
        ),
        
        "Maximum Analysis": FingerprintingConfig(
            analysis_level="full",
            enable_fail_fast=False,
            enable_scapy_probes=True,
            sni_probe_mode="detailed",
            max_parallel_targets=5,
            connect_timeout=3.0,
            tls_timeout=5.0,
            udp_timeout=1.0,
            enable_behavioral_probes=True
        ),
        
        "CI/Testing": FingerprintingConfig(
            analysis_level="fast",
            enable_fail_fast=True,
            enable_scapy_probes=False,
            sni_probe_mode="off",
            max_parallel_targets=20,
            connect_timeout=0.5,
            tls_timeout=1.0,
            udp_timeout=0.1,
            enable_behavioral_probes=False
        )
    }
    
    for name, config in configs.items():
        print(f"\n📋 {name} Configuration:")
        print(f"  analysis_level: {config.analysis_level}")
        print(f"  max_parallel_targets: {config.max_parallel_targets}")
        print(f"  enable_fail_fast: {config.enable_fail_fast}")
        print(f"  enable_scapy_probes: {config.enable_scapy_probes}")
        print(f"  timeouts: connect={config.connect_timeout}s, tls={config.tls_timeout}s, udp={config.udp_timeout}s")
        
        # Estimate processing time for 30 domains
        estimated_time_per_domain = {
            "fast": 0.5, "balanced": 1.2, "full": 3.0
        }.get(config.analysis_level, 1.0)
        
        sequential_time = 30 * estimated_time_per_domain
        parallel_time = sequential_time / config.max_parallel_targets
        
        print(f"  Estimated time for 30 domains: {parallel_time:.1f}s (vs {sequential_time:.1f}s sequential)")


async def main():
    """Main demo function"""
    
    print("🚀 Parallel DPI Fingerprinting Optimization Demo")
    print("="*60)
    print("This demo shows performance improvements from parallel processing")
    print("and intelligent analysis level selection.")
    
    # Create performance benchmark
    benchmark = PerformanceBenchmark()
    
    # Test with a subset of domains (adjust based on your needs)
    test_domains = TEST_DOMAINS[:15]  # Use first 15 domains for demo
    
    try:
        # Run performance benchmark
        await benchmark.benchmark_sequential_vs_parallel(test_domains)
        
        # Show configuration examples
        await create_optimized_config_examples()
        
        print(f"\n{'='*60}")
        print("PRACTICAL USAGE EXAMPLE")
        print(f"{'='*60}")
        
        # Demonstrate practical usage
        config = FingerprintingConfig(
            analysis_level="balanced",
            enable_fail_fast=True,
            enable_scapy_probes=False,
            sni_probe_mode="basic",
            max_parallel_targets=15
        )
        
        fingerprinter = AdvancedFingerprinter(config=config)
        
        print(f"\n⚡ Processing {len(TEST_DOMAINS)} domains in parallel...")
        start_time = time.time()
        
        targets = [(domain, 443) for domain in TEST_DOMAINS]
        fingerprints = await fingerprinter.fingerprint_many(targets, concurrency=15)
        
        total_time = time.time() - start_time
        success_count = sum(1 for fp in fingerprints if fp is not None)
        
        print(f"\n✅ Results:")
        print(f"  Processed {len(TEST_DOMAINS)} domains in {total_time:.2f}s")
        print(f"  Success rate: {success_count}/{len(TEST_DOMAINS)} ({success_count/len(TEST_DOMAINS):.1%})")
        print(f"  Average time per domain: {total_time/len(TEST_DOMAINS):.2f}s")
        print(f"  Estimated speedup: ~{len(TEST_DOMAINS)*1.5/total_time:.1f}x vs sequential")
        
        await fingerprinter.close()
        
    except Exception as e:
        LOG.error(f"Demo failed: {e}")
        import traceback
        traceback.print_exc()
    
    print(f"\n{'='*60}")
    print("OPTIMIZATION RECOMMENDATIONS")
    print(f"{'='*60}")
    print("1. Use max_parallel_targets=15 for ~30 domains")
    print("2. Enable fail_fast=True to skip heavy probes on blocked domains")
    print("3. Set analysis_level='fast' for CI/bulk testing")
    print("4. Set analysis_level='balanced' for production")
    print("5. Disable enable_scapy_probes=False on Windows for better performance")
    print("6. Use shorter timeouts (connect=1.5s, tls=2.0s) for faster detection")
    print("7. Expected time reduction: from 34+ minutes to 2-3 minutes for 30 domains")


if __name__ == "__main__":
    asyncio.run(main())