#!/usr/bin/env python3

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    print("Attempting to import pool_management...")
    import pool_management
    print("Import successful!")
    
    print("Module attributes:")
    attrs = [x for x in dir(pool_management) if not x.startswith('_')]
    print(attrs)
    
    if hasattr(pool_management, 'BypassStrategy'):
        print("BypassStrategy found!")
        strategy = pool_management.BypassStrategy(
            id="test",
            name="Test",
            attacks=["tcp_fragmentation"]
        )
        print(f"Created strategy: {strategy.name}")
    else:
        print("BypassStrategy NOT found!")
        
    if hasattr(pool_management, 'StrategyPoolManager'):
        print("StrategyPoolManager found!")
        manager = pool_management.StrategyPoolManager()
        print("Created manager successfully!")
    else:
        print("StrategyPoolManager NOT found!")
        
except Exception as e:
    print(f"Import failed: {e}")
    import traceback
    traceback.print_exc()