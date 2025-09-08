#!/usr/bin/env python3

import sys
import os

# Add the parent directories to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
tests_dir = os.path.dirname(current_dir)
recon_dir = os.path.dirname(tests_dir)
sys.path.insert(0, recon_dir)


# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    print("Attempting to from core.bypass.strategies import pool_management...")
    from core.bypass.strategies import pool_management

    print("Import successful!")

    print("Module attributes:")
    attrs = [x for x in dir(pool_management) if not x.startswith("_")]
    print(attrs)

    if hasattr(pool_management, "BypassStrategy"):
        print("BypassStrategy found!")
        strategy = pool_management.BypassStrategy(
            id="test", name="Test", attacks=["tcp_fragmentation"]
        )
        print(f"Created strategy: {strategy.name}")
    else:
        print("BypassStrategy NOT found!")

    if hasattr(pool_management, "StrategyPoolManager"):
        print("StrategyPoolManager found!")
        manager = pool_management.StrategyPoolManager()
        print("Created manager successfully!")
    else:
        print("StrategyPoolManager NOT found!")

except Exception as e:
    print(f"Import failed: {e}")
    import traceback

    traceback.print_exc()
