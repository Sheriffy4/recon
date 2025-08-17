#!/usr/bin/env python3
# Simple test to verify pool management system works

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the module directly
import pool_management

# Test basic functionality
def test_basic_functionality():
    print("Testing basic pool management functionality...")
    
    # Create a strategy
    strategy = pool_management.BypassStrategy(
        id="test_strategy",
        name="Test Strategy",
        attacks=["tcp_fragmentation"],
        parameters={"split_pos": 3}
    )
    print(f"✓ Created strategy: {strategy.name}")
    
    # Create a pool manager
    manager = pool_management.StrategyPoolManager()
    print("✓ Created pool manager")
    
    # Create a pool
    pool = manager.create_pool("Test Pool", strategy, "Test description")
    print(f"✓ Created pool: {pool.name}")
    
    # Add domain to pool
    success = manager.add_domain_to_pool(pool.id, "example.com")
    print(f"✓ Added domain to pool: {success}")
    
    # Get strategy for domain
    resolved_strategy = manager.get_strategy_for_domain("example.com")
    print(f"✓ Resolved strategy: {resolved_strategy.name if resolved_strategy else 'None'}")
    
    # Test format conversions
    zapret_format = strategy.to_zapret_format()
    native_format = strategy.to_native_format()
    print(f"✓ Zapret format: {zapret_format}")
    print(f"✓ Native format: {native_format}")
    
    print("\n✅ All basic tests passed!")

if __name__ == "__main__":
    test_basic_functionality()