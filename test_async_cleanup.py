#!/usr/bin/env python3
"""
Test script to verify async cleanup fixes work properly.
"""

import asyncio
import aiohttp
import time
import sys
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, FingerprintingConfig as UnifiedFPConfig


async def test_cleanup():
    """Test that async cleanup works properly without warnings."""
    print("🧪 Testing async cleanup fixes...")
    
    # Test 1: Basic aiohttp session cleanup
    print("1. Testing basic aiohttp session cleanup...")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get('https://httpbin.org/get', timeout=aiohttp.ClientTimeout(total=5)) as response:
                print(f"   ✓ HTTP request successful: {response.status}")
        except Exception as e:
            print(f"   ⚠ HTTP request failed: {e}")
    
    # Test 2: UnifiedFingerprinter cleanup
    print("2. Testing UnifiedFingerprinter cleanup...")
    try:
        config = UnifiedFPConfig(timeout=2.0, enable_cache=False, analysis_level="basic")
        fingerprinter = UnifiedFingerprinter(config=config)
        
        # Test cleanup without actual fingerprinting to avoid network issues
        print("   ✓ UnifiedFingerprinter created successfully")
        
        # Test cleanup
        await fingerprinter.close()
        print("   ✓ UnifiedFingerprinter closed successfully")
        
    except Exception as e:
        print(f"   ❌ UnifiedFingerprinter test failed: {e}")
    
    # Test 3: Task cancellation handling
    print("3. Testing task cancellation handling...")
    
    async def long_running_task():
        try:
            await asyncio.sleep(10)  # Long sleep
        except asyncio.CancelledError:
            print("   ✓ Task cancelled gracefully")
            raise  # Re-raise to allow proper cleanup
    
    task = asyncio.create_task(long_running_task())
    await asyncio.sleep(0.1)  # Let task start
    task.cancel()
    
    try:
        await task
    except asyncio.CancelledError:
        print("   ✓ CancelledError handled properly")
    
    print("🎉 All cleanup tests completed!")


async def main():
    """Main test function."""
    try:
        await test_cleanup()
    except KeyboardInterrupt:
        print("\n⚠ Test interrupted by user")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("Starting async cleanup test...")
    asyncio.run(main())
    print("Test completed. Check for any asyncio warnings above.")