#!/usr/bin/env python3
"""
Test script to verify UnifiedBypassEngine integration in recon_service.py

This script tests that the service can:
1. Import unified components correctly
2. Initialize UnifiedBypassEngine with forced override
3. Load strategies using UnifiedStrategyLoader
4. Create forced override configurations
"""

import sys
import logging
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

def test_service_imports():
    """Test that service can import unified components."""
    print("🧪 Testing service imports...")
    
    try:
        # Test importing the service
        from recon.recon_service import DPIBypassService
        print("✅ Successfully imported DPIBypassService")
        
        # Test that unified components can be imported
        from recon.core.unified_bypass_engine import UnifiedBypassEngine, UnifiedEngineConfig
        from recon.core.unified_strategy_loader import UnifiedStrategyLoader
        print("✅ Successfully imported unified components")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

def test_service_initialization():
    """Test that service can initialize with unified components."""
    print("\n🧪 Testing service initialization...")
    
    try:
        from recon.recon_service import DPIBypassService
        
        # Create service instance
        service = DPIBypassService()
        print("✅ Successfully created DPIBypassService instance")
        
        # Test that service has the expected attributes
        assert hasattr(service, 'domain_strategies'), "Service missing domain_strategies"
        assert hasattr(service, 'monitored_domains'), "Service missing monitored_domains"
        assert hasattr(service, 'bypass_engine'), "Service missing bypass_engine"
        print("✅ Service has expected attributes")
        
        return True
        
    except Exception as e:
        print(f"❌ Service initialization failed: {e}")
        return False

def test_unified_components():
    """Test unified components directly."""
    print("\n🧪 Testing unified components...")
    
    try:
        from recon.core.unified_bypass_engine import UnifiedBypassEngine, UnifiedEngineConfig
        from recon.core.unified_strategy_loader import UnifiedStrategyLoader
        
        # Test UnifiedEngineConfig
        config = UnifiedEngineConfig(
            debug=True,
            force_override=True,
            enable_diagnostics=True
        )
        print("✅ Successfully created UnifiedEngineConfig")
        
        # Test UnifiedBypassEngine
        engine = UnifiedBypassEngine(config=config)
        print("✅ Successfully created UnifiedBypassEngine")
        
        # Test UnifiedStrategyLoader
        loader = UnifiedStrategyLoader(debug=True)
        print("✅ Successfully created UnifiedStrategyLoader")
        
        # Test strategy loading
        test_strategy = "fakeddisorder(ttl=1, split_pos=3, fooling=badsum)"
        normalized = loader.load_strategy(test_strategy)
        print(f"✅ Successfully loaded strategy: {normalized.type}")
        
        # Test forced override creation
        forced = loader.create_forced_override(normalized)
        assert forced.get('no_fallbacks') == True, "Forced override missing no_fallbacks=True"
        assert forced.get('forced') == True, "Forced override missing forced=True"
        print("✅ Successfully created forced override")
        
        return True
        
    except Exception as e:
        print(f"❌ Unified components test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_strategy_loading_integration():
    """Test strategy loading with various formats."""
    print("\n🧪 Testing strategy loading integration...")
    
    try:
        from recon.core.unified_strategy_loader import UnifiedStrategyLoader
        
        loader = UnifiedStrategyLoader(debug=True)
        
        # Test different strategy formats
        test_strategies = [
            "fakeddisorder(ttl=1, split_pos=3, fooling=badsum)",
            "--dpi-desync=fakeddisorder --dpi-desync-ttl=1 --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum",
            {
                "type": "fakeddisorder",
                "params": {
                    "ttl": 1,
                    "split_pos": 3,
                    "fooling": "badsum"
                }
            }
        ]
        
        for i, strategy in enumerate(test_strategies):
            try:
                normalized = loader.load_strategy(strategy)
                forced = loader.create_forced_override(normalized)
                
                # Verify forced override properties
                assert forced.get('no_fallbacks') == True, f"Strategy {i} missing no_fallbacks=True"
                assert forced.get('forced') == True, f"Strategy {i} missing forced=True"
                assert forced.get('type') == 'fakeddisorder', f"Strategy {i} wrong type"
                
                print(f"✅ Strategy format {i+1} loaded successfully: {normalized.source_format}")
                
            except Exception as e:
                print(f"❌ Strategy format {i+1} failed: {e}")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ Strategy loading integration test failed: {e}")
        return False

def main():
    """Run all integration tests."""
    print("🚀 Running UnifiedBypassEngine Service Integration Tests")
    print("=" * 60)
    
    # Configure logging
    logging.basicConfig(level=logging.WARNING)  # Reduce noise
    
    tests = [
        test_service_imports,
        test_service_initialization,
        test_unified_components,
        test_strategy_loading_integration
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"❌ Test {test.__name__} failed")
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All integration tests passed!")
        print("✅ UnifiedBypassEngine is successfully integrated into recon_service.py")
        return True
    else:
        print("❌ Some integration tests failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)