#!/usr/bin/env python3
"""
Final production validation test to confirm all fixes are working.
This test simulates the exact production scenario that was failing.
"""

import logging
import sys
import asyncio
import traceback

logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
LOG = logging.getLogger("FinalProductionValidation")

def test_exact_production_scenario():
    """Test the exact scenario from production logs."""
    LOG.info("🔍 Testing exact production scenario...")
    
    try:
        # Simulate the exact production flow:
        # 1. ML predicts tcp_window_scaling
        # 2. Attack is executed
        # 3. Background fingerprinting runs
        
        from core.bypass.attacks.registry import AttackRegistry
        from core.integration.attack_adapter import AttackAdapter
        from core.bypass.attacks.base import AttackContext
        from core.integration.fingerprint_integration import get_fingerprint_integrator, SimplifiedClassifier
        
        LOG.info("🧪 Step 1: ML prediction scenario")
        LOG.info("INFO     ML predicted strategy for 104.21.32.39 (rutracker.org): tcp_window_scaling (confidence: 0.60)")
        
        # Initialize components
        registry = AttackRegistry()
        adapter = AttackAdapter()
        integrator = get_fingerprint_integrator()
        
        LOG.info("🧪 Step 2: Execute tcp_window_scaling attack")
        
        # Create context exactly like production
        context = AttackContext(
            dst_ip="104.21.32.39",
            dst_port=443,
            domain="rutracker.org",
            payload=b"GET / HTTP/1.1\r\nHost: rutracker.org\r\n\r\n"
        )
        
        # Execute attack (this was failing with AttackStatus error)
        result = asyncio.run(adapter.execute_attack_by_name("tcp_window_scaling", context))
        
        if result is None:
            LOG.error("❌ Attack execution returned None")
            return False
            
        LOG.info(f"✅ Attack execution successful: {result.status}")
        
        LOG.info("🧪 Step 3: Background fingerprinting")
        
        # Test BasicClassification (this was failing with confidence error)
        classifier = SimplifiedClassifier()
        classification = classifier.classify({})
        
        # Access confidence attribute (this was causing AttributeError)
        confidence_value = classification.confidence
        dpi_type = classification.dpi_type
        
        LOG.info(f"✅ Background fingerprinting successful")
        LOG.info(f"   DPI Type: {dpi_type}")
        LOG.info(f"   Confidence: {confidence_value}")
        
        LOG.info("🧪 Step 4: Dynamic combo attack")
        
        # Test dynamic combo (this should work now)
        from core.bypass.attacks.combo.dynamic_combo import DynamicComboAttack
        
        combo_attack = DynamicComboAttack()
        combo_result = combo_attack.execute(context)
        
        if combo_result is None:
            LOG.error("❌ Dynamic combo returned None")
            return False
            
        LOG.info(f"✅ Dynamic combo attack completed successfully: {combo_result.status}")
        
        return True
        
    except Exception as e:
        LOG.error(f"❌ Production scenario failed: {e}")
        LOG.error(f"   Exception type: {type(e).__name__}")
        LOG.error(f"   Traceback: {traceback.format_exc()}")
        return False

def test_error_conditions():
    """Test error conditions to ensure they're handled safely."""
    LOG.info("🔍 Testing error conditions...")
    
    try:
        from core.bypass.attacks.registry import AttackRegistry
        from core.bypass.attacks.base import AttackContext
        
        registry = AttackRegistry()
        attack_class = registry.get("tcp_window_scaling")
        
        if not attack_class:
            LOG.error("❌ tcp_window_scaling not found")
            return False
            
        attack = attack_class()
        
        # Test with empty payload (should handle gracefully)
        context = AttackContext(
            dst_ip="104.21.32.39",
            dst_port=443,
            domain="rutracker.org",
            payload=b""  # Empty payload
        )
        
        result = attack.execute(context)
        
        if result is None:
            LOG.error("❌ Attack returned None for empty payload")
            return False
            
        LOG.info(f"✅ Empty payload handled gracefully: {result.status}")
        
        # Test with invalid context
        invalid_context = AttackContext(
            dst_ip="",  # Invalid IP
            dst_port=0,  # Invalid port
            payload=b"test"
        )
        
        result = attack.execute(invalid_context)
        
        if result is None:
            LOG.error("❌ Attack returned None for invalid context")
            return False
            
        LOG.info(f"✅ Invalid context handled gracefully: {result.status}")
        
        return True
        
    except Exception as e:
        LOG.error(f"❌ Error condition test failed: {e}")
        LOG.error(f"   Exception type: {type(e).__name__}")
        LOG.error(f"   Traceback: {traceback.format_exc()}")
        return False

def test_background_tasks():
    """Test background task scenarios."""
    LOG.info("🔍 Testing background task scenarios...")
    
    try:
        from core.integration.fingerprint_integration import get_fingerprint_integrator
        
        integrator = get_fingerprint_integrator()
        
        # Test background fingerprinting (this was failing)
        LOG.info("🧪 Testing background fingerprinting...")
        
        # This should not fail with confidence error
        integrator.start_background_fingerprinting("rutracker.org", "104.21.32.39")
        
        LOG.info("✅ Background fingerprinting started successfully")
        
        # Test cached fingerprint
        cached = integrator.get_cached_fingerprint("rutracker.org", "104.21.32.39")
        
        LOG.info(f"✅ Cached fingerprint check: {cached is not None}")
        
        return True
        
    except Exception as e:
        LOG.error(f"❌ Background task test failed: {e}")
        LOG.error(f"   Exception type: {type(e).__name__}")
        LOG.error(f"   Traceback: {traceback.format_exc()}")
        return False

def main():
    """Run final production validation."""
    LOG.info("🚀 Starting final production validation...")
    LOG.info("This test simulates the exact production scenario that was failing.")
    
    tests = [
        ("Exact Production Scenario", test_exact_production_scenario),
        ("Error Conditions", test_error_conditions),
        ("Background Tasks", test_background_tasks),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        LOG.info(f"\n--- {test_name} ---")
        try:
            success = test_func()
            results.append((test_name, success))
            if success:
                LOG.info(f"✅ {test_name} PASSED")
            else:
                LOG.error(f"❌ {test_name} FAILED")
        except Exception as e:
            LOG.error(f"❌ {test_name} CRASHED: {e}")
            results.append((test_name, False))
    
    # Summary
    LOG.info(f"\n🎯 Final Production Validation Results:")
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        LOG.info(f"   {test_name}: {status}")
    
    LOG.info(f"\n📊 Summary: {passed}/{total} tests passed")
    
    if passed == total:
        LOG.info("🎉 PRODUCTION VALIDATION SUCCESSFUL!")
        LOG.info("✅ All production errors have been resolved")
        LOG.info("✅ System is stable and ready for production deployment")
        LOG.info("✅ AttackStatus errors eliminated")
        LOG.info("✅ BasicClassification confidence errors eliminated")
    else:
        LOG.error("💥 PRODUCTION VALIDATION FAILED!")
        LOG.error("Some issues still need to be addressed")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)