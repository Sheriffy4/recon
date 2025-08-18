#!/usr/bin/env python3
"""
Simple test for bypass web integration functionality.
"""

import sys
import os

# Add the recon directory to the path
recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, recon_dir)

try:
    # Test basic imports
    print("Testing imports...")
    
    # Test if aiohttp is available
    try:
        import aiohttp
        print("✅ aiohttp available")
    except ImportError:
        print("❌ aiohttp not available - web interface will not work")
        sys.exit(1)
    
    # Test core components
    from core.bypass.strategies.pool_management import StrategyPoolManager, BypassStrategy
    from core.bypass.attacks.modern_registry import ModernAttackRegistry
    print("✅ Core bypass components imported")
    
    # Test web components
    from web.bypass_api import BypassEngineAPI
    from web.bypass_dashboard import BypassDashboard
    from web.bypass_integration import BypassWebIntegration, create_bypass_integration
    print("✅ Web integration components imported")
    
except ImportError as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)

def test_integration_creation():
    """Test creating bypass integration."""
    print("Testing integration creation...")
    
    try:
        # Create integration
        integration = create_bypass_integration()
        print("✅ Integration created successfully")
        
        # Test component access
        pool_manager = integration.get_pool_manager()
        attack_registry = integration.get_attack_registry()
        api = integration.get_api()
        dashboard = integration.get_dashboard()
        
        print("✅ All components accessible")
        
        # Test pool creation
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_pos": 3}
        )
        
        pool = pool_manager.create_pool("Test Pool", strategy)
        pool.add_domain("example.com")
        
        print(f"✅ Created test pool: {pool.name} with {len(pool.domains)} domains")
        
        # Test configuration export
        config = api._export_pools_config()
        print(f"✅ Configuration exported: {len(config['pools'])} pools")
        
        # Test configuration import
        result = api._import_pools_config(config)
        print(f"✅ Configuration import result: {result['success']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def test_api_functionality():
    """Test API functionality."""
    print("Testing API functionality...")
    
    try:
        integration = BypassWebIntegration()
        api = integration.get_api()
        
        # Test WebSocket management
        print(f"✅ WebSocket connections: {len(api.websockets)}")
        
        # Test active tests management
        print(f"✅ Active tests: {len(api.active_tests)}")
        
        return True
        
    except Exception as e:
        print(f"❌ API test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🧪 Running bypass web integration tests...")
    
    tests = [
        test_integration_creation,
        test_api_functionality
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())