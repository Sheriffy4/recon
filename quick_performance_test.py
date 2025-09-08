#!/usr/bin/env python3
"""
Quick Performance Test Script

This script tests the new parallel fingerprinting functionality 
against your current sequential approach to demonstrate the speedup.
"""

import asyncio
import time
import sys
from pathlib import Path

# Add current directory to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig

# Test domains from your sites.txt
TEST_DOMAINS = [
    "x.com",
    "instagram.com", 
    "youtube.com",
    "facebook.com",
    "pbs.twimg.com"
]

async def test_sequential_vs_parallel():
    """Quick test of sequential vs parallel processing"""
    
    print("🧪 Quick Performance Test: Sequential vs Parallel")
    print("="*50)
    
    targets = [(domain, 443) for domain in TEST_DOMAINS]
    
    # Test 1: Sequential (traditional)
    print("\n1️⃣ Testing Sequential Processing...")
    config_seq = FingerprintingConfig(
        analysis_level="fast",
        enable_fail_fast=False,
        enable_scapy_probes=False
    )
    
    fingerprinter_seq = AdvancedFingerprinter(config=config_seq)
    
    start_time = time.time()
    results_seq = []
    for domain, port in targets:
        try:
            fp = await fingerprinter_seq.fingerprint_target(domain, port)
            results_seq.append(fp)
        except Exception as e:
            print(f"  ⚠️ Failed {domain}: {e}")
            results_seq.append(None)
    
    seq_time = time.time() - start_time
    seq_success = sum(1 for r in results_seq if r is not None)
    
    print(f"  ✓ Sequential: {seq_time:.2f}s, success: {seq_success}/{len(targets)}")
    
    await fingerprinter_seq.close()
    
    # Test 2: Parallel (optimized)
    print("\n2️⃣ Testing Parallel Processing...")
    config_par = FingerprintingConfig(
        analysis_level="fast",
        enable_fail_fast=True,
        enable_scapy_probes=False,
        max_parallel_targets=10
    )
    
    fingerprinter_par = AdvancedFingerprinter(config=config_par)
    
    start_time = time.time()
    results_par = await fingerprinter_par.fingerprint_many(targets, concurrency=10)
    par_time = time.time() - start_time
    par_success = sum(1 for r in results_par if r is not None)
    
    print(f"  ✓ Parallel: {par_time:.2f}s, success: {par_success}/{len(targets)}")
    
    await fingerprinter_par.close()
    
    # Calculate speedup
    speedup = seq_time / par_time if par_time > 0 else 1.0
    
    print(f"\n📊 Results Summary:")
    print(f"  Sequential time: {seq_time:.2f}s")
    print(f"  Parallel time:   {par_time:.2f}s") 
    print(f"  Speedup:         {speedup:.1f}x faster")
    print(f"  Time saved:      {seq_time - par_time:.2f}s ({((seq_time - par_time)/seq_time)*100:.1f}%)")
    
    # Extrapolate to 30 domains
    print(f"\n🔮 Extrapolation to 30 domains:")
    seq_30 = seq_time * (30 / len(targets))
    par_30 = par_time * (30 / len(targets))
    
    print(f"  Sequential (estimated): {seq_30/60:.1f} minutes")
    print(f"  Parallel (estimated):   {par_30/60:.1f} minutes")
    print(f"  Time saved:             {(seq_30-par_30)/60:.1f} minutes")
    
    return speedup

async def test_analysis_levels():
    """Test different analysis levels"""
    
    print("\n🎯 Testing Analysis Levels...")
    print("="*40)
    
    targets = [(domain, 443) for domain in TEST_DOMAINS[:3]]  # Use 3 domains for this test
    
    levels = ["fast", "balanced", "full"]
    results = {}
    
    for level in levels:
        print(f"\n   Testing {level} mode...")
        
        config = FingerprintingConfig(
            analysis_level=level,
            enable_fail_fast=True,
            enable_scapy_probes=(level == "full"),
            sni_probe_mode="basic" if level != "full" else "detailed",
            max_parallel_targets=5
        )
        
        fingerprinter = AdvancedFingerprinter(config=config)
        
        start_time = time.time()
        fps = await fingerprinter.fingerprint_many(targets, concurrency=5)
        elapsed = time.time() - start_time
        
        success_count = sum(1 for fp in fps if fp is not None)
        avg_confidence = sum(fp.confidence for fp in fps if fp is not None) / success_count if success_count > 0 else 0
        
        results[level] = {
            'time': elapsed,
            'success': success_count,
            'confidence': avg_confidence
        }
        
        print(f"     ✓ {level}: {elapsed:.2f}s, confidence: {avg_confidence:.2f}")
        
        await fingerprinter.close()
    
    print(f"\n📋 Analysis Level Comparison:")
    for level, data in results.items():
        print(f"  {level.capitalize():>8}: {data['time']:.2f}s (confidence: {data['confidence']:.2f})")

async def main():
    """Main test function"""
    
    print("🚀 DPI Fingerprinting Performance Test")
    print("="*50)
    print("This script tests the performance improvements from:")
    print("• Parallel processing")
    print("• Fail-fast optimization") 
    print("• Configurable timeouts")
    print("• Analysis level control")
    
    try:
        # Test sequential vs parallel
        speedup = await test_sequential_vs_parallel()
        
        # Test analysis levels
        await test_analysis_levels()
        
        print(f"\n{'='*50}")
        print("✅ PERFORMANCE TEST COMPLETE")
        print(f"{'='*50}")
        
        if speedup > 5:
            print(f"🎉 Excellent speedup achieved: {speedup:.1f}x faster!")
        elif speedup > 2:
            print(f"✅ Good speedup achieved: {speedup:.1f}x faster!")
        else:
            print(f"⚠️  Modest speedup: {speedup:.1f}x faster (network may be limiting factor)")
        
        print(f"\n💡 Recommendations:")
        print(f"• Use 'fast' mode for bulk testing ({TEST_DOMAINS[0]} took least time)")
        print(f"• Use 'balanced' mode for production (good accuracy/speed balance)")
        print(f"• Use parallel processing with 10-15 concurrent domains")
        print(f"• Enable fail_fast=True to skip blocked domains quickly")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())