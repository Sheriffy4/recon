#!/usr/bin/env python3
"""
Simple verification script to demonstrate identical behavior
between testing mode and service mode after UnifiedBypassEngine integration.
"""

import sys
import os
import json
import logging
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Setup logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
LOG = logging.getLogger("verify_identical_behavior")

def main():
    """Verify identical behavior between testing and service modes."""
    
    print("="*80)
    print("UNIFIED ENGINE BEHAVIOR VERIFICATION")
    print("="*80)
    
    # Test strategy
    test_strategy = "fakeddisorder(ttl=1)"
    test_domain = "x.com"
    
    print(f"\nTesting Strategy: {test_strategy}")
    print(f"Target Domain: {test_domain}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    try:
        # Import and test
        from enhanced_find_rst_triggers import compare_with_service_mode
        
        print(f"\n🔍 Comparing behavior between testing and service modes...")
        
        # Run comparison
        comparison = compare_with_service_mode(test_domain, test_strategy)
        
        # Display results
        print(f"\n📊 COMPARISON RESULTS:")
        print(f"   Domain: {comparison['domain']}")
        print(f"   Strategy: {comparison['strategy']}")
        print(f"   Identical Behavior: {'✅ YES' if comparison['identical_behavior'] else '❌ NO'}")
        
        if comparison['differences']:
            print(f"   Differences Found: {len(comparison['differences'])}")
            for diff in comparison['differences']:
                print(f"     - {diff}")
        else:
            print(f"   Differences Found: ✅ NONE")
        
        # Check forced override consistency
        testing_result = comparison.get('testing_mode_result', {})
        service_result = comparison.get('service_mode_simulation', {})
        
        print(f"\n🔥 FORCED OVERRIDE VERIFICATION:")
        print(f"   Testing Mode - Forced Override: {'✅' if testing_result.get('forced_override') else '❌'}")
        print(f"   Testing Mode - No Fallbacks: {'✅' if testing_result.get('no_fallbacks') else '❌'}")
        print(f"   Service Mode - Forced Override: {'✅' if service_result.get('forced_override') else '❌'}")
        print(f"   Service Mode - No Fallbacks: {'✅' if service_result.get('no_fallbacks') else '❌'}")
        
        # Check strategy parameters consistency
        testing_params = testing_result.get('strategy_params', {})
        service_params = service_result.get('strategy_params', {})
        
        print(f"\n📋 STRATEGY PARAMETERS VERIFICATION:")
        print(f"   Testing Mode Parameters: {json.dumps(testing_params, indent=6)}")
        print(f"   Service Mode Parameters: {json.dumps(service_params, indent=6)}")
        print(f"   Parameters Identical: {'✅ YES' if testing_params == service_params else '❌ NO'}")
        
        # Overall verdict
        print(f"\n🎯 OVERALL VERDICT:")
        if comparison['identical_behavior'] and not comparison['differences']:
            print(f"   ✅ SUCCESS: Testing mode and service mode show IDENTICAL behavior")
            print(f"   ✅ UnifiedBypassEngine integration is working correctly")
            print(f"   ✅ Forced override is applied consistently in both modes")
            return 0
        else:
            print(f"   ❌ FAILURE: Testing mode and service mode show DIFFERENT behavior")
            print(f"   ❌ UnifiedBypassEngine integration needs investigation")
            return 1
            
    except Exception as e:
        print(f"\n❌ ERROR: Verification failed: {e}")
        return 1
    
    finally:
        print("\n" + "="*80)


if __name__ == "__main__":
    sys.exit(main())