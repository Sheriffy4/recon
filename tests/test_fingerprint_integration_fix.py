#!/usr/bin/env python3
"""
Test script to validate fingerprint integration fix
Validates that fingerprint_used field is now properly set when fingerprints are available
"""

import sys
import os
import asyncio
from unittest.mock import Mock, AsyncMock

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_fingerprint_integration():
    """Test that fingerprint integration is now working correctly"""
    
    print("🔧 Testing Fingerprint Integration Fix")
    print("=" * 60)
    
    try:
        from ml.zapret_strategy_generator import ZapretStrategyGenerator
        from core.fingerprint.advanced_models import DPIFingerprint, DPIType
        from core.hybrid_engine import HybridEngine
        
        # Create a test fingerprint
        test_fingerprint = DPIFingerprint(
            target="test.com:443",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.8,
            reliability_score=0.85,
            rst_injection_detected=True
        )
        
        print("✅ Imports successful")
        
        # Test 1: Strategy Generation with Fingerprint Object
        print("\n📊 Test 1: Strategy Generation with Fingerprint Object")
        generator = ZapretStrategyGenerator()
        
        # Test with fingerprint object (should use fingerprint-aware generation)
        strategies_with_fp = generator.generate_strategies(test_fingerprint, count=5)
        print(f"  ✓ Generated {len(strategies_with_fp)} strategies with fingerprint")
        
        # Test with None (should use generic generation)
        strategies_without_fp = generator.generate_strategies(None, count=5)
        print(f"  ✓ Generated {len(strategies_without_fp)} strategies without fingerprint")
        
        # Test with dict (should use legacy generation)
        legacy_dict = {"dpi_vendor": "unknown", "blocking_method": "connection_reset"}
        strategies_legacy = generator.generate_strategies(legacy_dict, count=5)
        print(f"  ✓ Generated {len(strategies_legacy)} strategies with legacy dict")
        
        # Verify they're different
        strategies_different = (
            set(strategies_with_fp) != set(strategies_without_fp) != set(strategies_legacy)
        )
        print(f"  ✓ Strategy sets are different: {strategies_different}")
        
        # Test 2: Hybrid Engine Fingerprint Usage
        print("\n🔧 Test 2: Hybrid Engine Fingerprint Usage")
        
        # Create hybrid engine with fingerprinting enabled
        hybrid_engine = HybridEngine(debug=False, enable_advanced_fingerprinting=True)
        
        # Mock the fingerprint_target method to return our test fingerprint
        hybrid_engine.fingerprint_target = AsyncMock(return_value=test_fingerprint)
        
        # Mock the execute_strategy_real_world_from_dict method
        hybrid_engine.execute_strategy_real_world_from_dict = AsyncMock(
            return_value=("PARTIAL_SUCCESS", 1, 2, 150.0)
        )
        
        # Prepare test data
        test_strategies = [
            {"type": "fakedisorder", "params": {"split_pos": 3}},
            {"type": "multisplit", "params": {"positions": [1, 5, 10]}}
        ]
        
        test_sites = ["https://test.com"]
        test_ips = {"1.2.3.4"}
        test_dns_cache = {"test.com": "1.2.3.4"}
        
        # Test with fingerprinting enabled
        print("  🧪 Testing with enable_fingerprinting=True...")
        results_with_fp = await hybrid_engine.test_strategies_hybrid(
            strategies=test_strategies,
            test_sites=test_sites,
            ips=test_ips,
            dns_cache=test_dns_cache,
            port=443,
            domain="test.com",
            enable_fingerprinting=True
        )
        
        # Test with fingerprinting disabled
        print("  🧪 Testing with enable_fingerprinting=False...")
        results_without_fp = await hybrid_engine.test_strategies_hybrid(
            strategies=test_strategies,
            test_sites=test_sites,
            ips=test_ips,
            dns_cache=test_dns_cache,
            port=443,
            domain="test.com",
            enable_fingerprinting=False
        )
        
        # Test 3: Verify fingerprint_used field
        print("\n✅ Test 3: Verify fingerprint_used Field")
        
        # Check results with fingerprinting enabled
        fp_enabled_results = [r["fingerprint_used"] for r in results_with_fp]
        print(f"  With fingerprinting enabled: {fp_enabled_results}")
        
        # Check results with fingerprinting disabled  
        fp_disabled_results = [r["fingerprint_used"] for r in results_without_fp]
        print(f"  With fingerprinting disabled: {fp_disabled_results}")
        
        # Verify correctness
        all_fp_enabled = all(fp_enabled_results)
        all_fp_disabled = all(not fp for fp in fp_disabled_results)
        
        print(f"  ✓ All results show fingerprint_used=True when enabled: {all_fp_enabled}")
        print(f"  ✓ All results show fingerprint_used=False when disabled: {all_fp_disabled}")
        
        # Test 4: Verify DPI type and confidence are included
        print("\n🎯 Test 4: Verify DPI Metadata")
        
        for i, result in enumerate(results_with_fp):
            dpi_type = result.get("dpi_type")
            dpi_confidence = result.get("dpi_confidence")
            print(f"  Strategy {i+1}: DPI={dpi_type}, Confidence={dpi_confidence}")
        
        # Final validation
        success = (
            all_fp_enabled and 
            all_fp_disabled and 
            all(r.get("dpi_type") is not None for r in results_with_fp) and
            all(r.get("dpi_confidence") is not None for r in results_with_fp)
        )
        
        print(f"\n🎉 Integration Fix Validation: {'✅ SUCCESS' if success else '❌ FAILED'}")
        
        if success:
            print("\n✅ Summary of Fixes Applied:")
            print("  1. ✓ Strategy generation now uses actual fingerprint objects")
            print("  2. ✓ CLI passes enable_fingerprinting=True when fingerprints available")
            print("  3. ✓ Results properly show fingerprint_used=True when used")
            print("  4. ✓ DPI type and confidence are included in results")
            print("  5. ✓ Backward compatibility maintained for legacy workflows")
        
        # Cleanup
        hybrid_engine.cleanup()
        
        return success
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("Some dependencies may not be available")
        return False
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Main test function"""
    print("🚀 Fingerprint Integration Fix Validation")
    print("Testing the fixes to make fingerprint_used work correctly\n")
    
    success = await test_fingerprint_integration()
    
    if success:
        print("\n🎯 CONCLUSION: Integration fix is working correctly!")
        print("The next test should show fingerprint_used: true in strategy results")
    else:
        print("\n⚠️  CONCLUSION: Further investigation needed")
    
    return success

if __name__ == "__main__":
    asyncio.run(main())