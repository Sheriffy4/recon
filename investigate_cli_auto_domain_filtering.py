#!/usr/bin/env python3
"""
Investigation script to understand why domain filtering is not working in CLI auto mode.
"""

import logging
import asyncio
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)

async def investigate_cli_auto_mode():
    """Investigate the CLI auto mode domain filtering integration."""
    
    print("🔍 Investigating CLI Auto Mode Domain Filtering")
    print("=" * 60)
    
    # Test 1: Check if discovery system components are available
    print("\n1. Checking discovery system availability...")
    
    try:
        from core.discovery_controller import DiscoveryController, DiscoveryConfig, DiscoveryStatus
        from core.cli_payload.adaptive_cli_wrapper import create_cli_wrapper_from_args
        print("   ✅ Discovery system components imported successfully")
        DISCOVERY_AVAILABLE = True
    except ImportError as e:
        print(f"   ❌ Discovery system not available: {e}")
        DISCOVERY_AVAILABLE = False
        return
    
    # Test 2: Check if adaptive engine has discovery mode integration
    print("\n2. Checking adaptive engine discovery integration...")
    
    try:
        from core.adaptive_refactored.facade import AdaptiveEngine
        
        engine = AdaptiveEngine()
        has_set_discovery_mode = hasattr(engine, 'set_discovery_mode')
        print(f"   - AdaptiveEngine has set_discovery_mode: {has_set_discovery_mode}")
        
        if has_set_discovery_mode:
            print("   ✅ AdaptiveEngine has discovery mode integration")
        else:
            print("   ❌ AdaptiveEngine missing set_discovery_mode method")
            
    except Exception as e:
        print(f"   ❌ Error checking AdaptiveEngine: {e}")
        return
    
    # Test 3: Create a discovery session and check domain filter setup
    print("\n3. Testing discovery session creation...")
    
    try:
        from core.discovery_config import DiscoveryConfig, StrategyConfig, PCAPConfig, IntegrationConfig
        
        # Create discovery controller
        discovery_controller = DiscoveryController()
        print("   ✅ DiscoveryController created")
        
        # Create discovery config
        target_domain = "www.googlevideo.com"
        discovery_config = DiscoveryConfig(
            target_domain=target_domain,
            strategy=StrategyConfig(
                max_strategies=5,
                max_duration_seconds=60
            ),
            pcap=PCAPConfig(enabled=False),
            integration=IntegrationConfig(
                override_domain_rules=True,
                restore_rules_on_completion=True
            )
        )
        print(f"   ✅ DiscoveryConfig created for {target_domain}")
        
        # Start discovery session
        session_id = discovery_controller.start_discovery(discovery_config)
        print(f"   ✅ Discovery session started: {session_id}")
        
        # Check if session has domain filter
        session = discovery_controller.active_sessions.get(session_id)
        if session and session.domain_filter:
            print(f"   ✅ Session has domain filter")
            print(f"   - Filter mode: {session.domain_filter.get_mode()}")
            print(f"   - Target domain: {session.domain_filter.get_current_target()}")
            print(f"   - Discovery mode: {session.domain_filter.is_discovery_mode()}")
        else:
            print(f"   ❌ Session missing domain filter")
            
        # Test 4: Check adaptive engine integration with discovery session
        print("\n4. Testing adaptive engine integration with discovery session...")
        
        try:
            # Create adaptive engine and set discovery mode
            adaptive_engine = AdaptiveEngine()
            adaptive_engine.set_discovery_mode(True, discovery_controller)
            print("   ✅ AdaptiveEngine discovery mode enabled")
            
            # Check if bypass engines have domain filter set
            if hasattr(adaptive_engine, 'bypass_engine') and adaptive_engine.bypass_engine:
                if hasattr(adaptive_engine.bypass_engine, '_domain_filter'):
                    domain_filter = adaptive_engine.bypass_engine._domain_filter
                    if domain_filter:
                        print(f"   ✅ Bypass engine has domain filter")
                        print(f"   - Filter mode: {domain_filter.get_mode()}")
                        print(f"   - Target domain: {domain_filter.get_current_target()}")
                    else:
                        print(f"   ❌ Bypass engine domain filter is None")
                else:
                    print(f"   ❌ Bypass engine missing _domain_filter attribute")
            else:
                print(f"   ⚠️ AdaptiveEngine has no bypass_engine")
            
            # Check packet processing engine
            if hasattr(adaptive_engine, 'packet_processing_engine') and adaptive_engine.packet_processing_engine:
                if hasattr(adaptive_engine.packet_processing_engine, '_domain_filter'):
                    domain_filter = adaptive_engine.packet_processing_engine._domain_filter
                    if domain_filter:
                        print(f"   ✅ Packet processing engine has domain filter")
                        print(f"   - Filter mode: {domain_filter.get_mode()}")
                        print(f"   - Target domain: {domain_filter.get_current_target()}")
                    else:
                        print(f"   ❌ Packet processing engine domain filter is None")
                else:
                    print(f"   ❌ Packet processing engine missing _domain_filter attribute")
            else:
                print(f"   ⚠️ AdaptiveEngine has no packet_processing_engine")
                
        except Exception as e:
            print(f"   ❌ Error testing adaptive engine integration: {e}")
            import traceback
            traceback.print_exc()
        
        # Test 5: Check CLI wrapper integration
        print("\n5. Testing CLI wrapper integration...")
        
        try:
            # Create a mock args object
            class MockArgs:
                def __init__(self):
                    self.target = target_domain
                    self.mode = "comprehensive"
                    self.timeout = 300
                    self.max_trials = 10
                    self.debug = True
                    self.quiet = False
                    self.pcap = None
                    self.domains_file = False
                    
            mock_args = MockArgs()
            
            # Create CLI wrapper
            cli_wrapper = create_cli_wrapper_from_args(mock_args)
            print("   ✅ CLI wrapper created")
            
            # Set discovery controller
            if hasattr(cli_wrapper, 'set_discovery_controller'):
                cli_wrapper.set_discovery_controller(discovery_controller)
                print("   ✅ Discovery controller set on CLI wrapper")
            else:
                print("   ❌ CLI wrapper missing set_discovery_controller method")
            
            # Check if CLI wrapper has discovery controller
            if hasattr(cli_wrapper, '_discovery_controller'):
                if cli_wrapper._discovery_controller:
                    print("   ✅ CLI wrapper has discovery controller")
                else:
                    print("   ❌ CLI wrapper discovery controller is None")
            else:
                print("   ❌ CLI wrapper missing _discovery_controller attribute")
                
        except Exception as e:
            print(f"   ❌ Error testing CLI wrapper integration: {e}")
            import traceback
            traceback.print_exc()
        
        # Clean up
        try:
            discovery_controller.stop_discovery(session_id, "Investigation complete")
            print(f"\n   🧹 Discovery session {session_id} stopped")
        except Exception as e:
            print(f"   ⚠️ Error stopping discovery session: {e}")
            
    except Exception as e:
        print(f"   ❌ Error in discovery session testing: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("🔍 Investigation complete!")

def main():
    """Main function to run the investigation."""
    asyncio.run(investigate_cli_auto_mode())

if __name__ == "__main__":
    main()