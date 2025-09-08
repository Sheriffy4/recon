#!/usr/bin/env python3
"""
Test script to validate the fixed fingerprinting functionality
"""

import asyncio
import json
import sys
import os
from datetime import datetime

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_fingerprinting():
    """Test the fixed fingerprinting functionality"""
    
    print("🔍 Testing Fixed Fingerprinting Functionality")
    print("=" * 60)
    
    try:
        from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
        from core.fingerprint.advanced_models import DPIType
        
        # Test configuration
        config = FingerprintingConfig(
            timeout=10.0,
            enable_ml=False,  # Disable ML to test heuristic classification
            enable_cache=False,  # Disable cache for clean testing
            enable_tcp_analysis=True,
            enable_http_analysis=False,  # Disable to avoid dependency issues
            enable_dns_analysis=False,  # Disable to avoid dependency issues
        )
        
        fingerprinter = AdvancedFingerprinter(config=config)
        
        print("✅ AdvancedFingerprinter initialized successfully")
        
        # Test domains that are likely blocked
        test_domains = [
            "x.com",
            "instagram.com", 
            "youtube.com",
            "facebook.com"
        ]
        
        results = {}
        
        for domain in test_domains:
            print(f"\n🔎 Testing fingerprinting for {domain}...")
            
            try:
                # Test fingerprinting
                fingerprint = await fingerprinter.fingerprint_target(domain, port=443)
                
                result = {
                    "domain": domain,
                    "dpi_type": str(fingerprint.dpi_type),
                    "confidence": fingerprint.confidence,
                    "reliability_score": fingerprint.reliability_score,
                    "analysis_methods": fingerprint.analysis_methods_used,
                    "rst_injection_detected": fingerprint.rst_injection_detected,
                    "analysis_duration": fingerprint.analysis_duration
                }
                
                results[domain] = result
                
                print(f"  ✅ DPI Type: {fingerprint.dpi_type}")
                print(f"  ✅ Confidence: {fingerprint.confidence:.2f}")
                print(f"  ✅ Reliability: {fingerprint.reliability_score:.2f}")
                print(f"  ✅ Methods: {fingerprint.analysis_methods_used}")
                print(f"  ✅ RST Injection: {fingerprint.rst_injection_detected}")
                print(f"  ✅ Duration: {fingerprint.analysis_duration:.2f}s")
                
            except Exception as e:
                print(f"  ❌ Error fingerprinting {domain}: {e}")
                results[domain] = {"error": str(e)}
        
        # Get and display stats
        stats = fingerprinter.get_stats()
        print(f"\n📊 Fingerprinting Statistics:")
        print(f"  Fingerprints Created: {stats.get('fingerprints_created', 0)}")
        print(f"  Fallback Classifications: {stats.get('fallback_classifications', 0)}")
        print(f"  Total Analysis Time: {stats.get('total_analysis_time', 0):.2f}s")
        print(f"  Average Analysis Time: {stats.get('avg_analysis_time', 0):.2f}s")
        print(f"  Errors: {stats.get('errors', 0)}")
        
        # Save results
        output_file = f"fingerprinting_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump({
                "test_timestamp": datetime.now().isoformat(),
                "results": results,
                "stats": stats
            }, f, indent=2, default=str)
        
        print(f"\n💾 Results saved to: {output_file}")
        
        # Check if classification is working
        successful_classifications = sum(1 for r in results.values() 
                                       if isinstance(r, dict) and 
                                          r.get('dpi_type') != 'DPIType.UNKNOWN' and
                                          r.get('confidence', 0) > 0)
        
        total_tests = len([r for r in results.values() if not r.get('error')])
        
        print(f"\n🎯 Classification Success Rate: {successful_classifications}/{total_tests}")
        
        if successful_classifications > 0:
            print("✅ Fingerprinting fix appears to be working!")
        else:
            print("⚠️  Fingerprinting still needs improvement")
            
        await fingerprinter.close()
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("Make sure all dependencies are available")
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("Starting fingerprinting test...")
    asyncio.run(test_fingerprinting())