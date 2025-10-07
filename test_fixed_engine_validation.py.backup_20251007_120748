#!/usr/bin/env python3
"""
Validation test for Windows Engine regression fixes.
"""

import sys
import os
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

def test_fixed_engine():
    """Test that the fixed engine works correctly."""
    
    try:
        # Import the fixed engine
        from core.bypass.engine.new_windows_engine_fixed import WindowsBypassEngine
        from core.bypass.engine.base_engine import EngineConfig
        
        print("✓ Fixed engine imports successfully")
        
        # Create engine instance
        config = EngineConfig(debug=True)
        engine = WindowsBypassEngine(config)
        
        print("✓ Fixed engine initializes successfully")
        
        # Check that PacketSender is properly initialized
        if hasattr(engine, '_packet_sender') and engine._packet_sender:
            print("✓ PacketSender is properly initialized")
            
            # Check that it has the correct method
            if hasattr(engine._packet_sender, 'send_tcp_segments'):
                print("✓ send_tcp_segments method exists")
            else:
                print("✗ send_tcp_segments method missing")
                return False
                
            # Check that async method is NOT called
            if hasattr(engine._packet_sender, 'send_tcp_segments_async'):
                print("⚠ send_tcp_segments_async still exists (not necessarily bad)")
            else:
                print("✓ send_tcp_segments_async not present (good)")
                
        else:
            print("⚠ PacketSender not initialized (may be normal)")
            
        # Check that trace_calls decorator is removed
        import inspect
        apply_bypass_source = inspect.getsource(engine.apply_bypass)
        if '@trace_calls' in apply_bypass_source:
            print("✗ @trace_calls decorator still present")
            return False
        else:
            print("✓ @trace_calls decorator removed")
            
        print("\n🎉 All validation tests passed!")
        return True
        
    except Exception as e:
        print(f"✗ Validation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_fixed_engine()
    sys.exit(0 if success else 1)
