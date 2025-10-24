#!/usr/bin/env python3
"""
Расширенный тест для проверки fingerprinting с правильной очисткой ресурсов.
"""

import asyncio
import sys
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, FingerprintingConfig as UnifiedFPConfig


async def test_fingerprinting_with_timeout():
    """Тест fingerprinting с таймаутом и правильной очисткой."""
    print("🔍 Testing fingerprinting with proper cleanup...")
    
    config = UnifiedFPConfig(
        timeout=3.0, 
        enable_cache=False, 
        analysis_level="basic"
    )
    fingerprinter = UnifiedFingerprinter(config=config)
    
    try:
        # Тест с коротким таймаутом
        print("   Attempting fingerprinting with short timeout...")
        
        # Используем asyncio.wait_for для контроля времени выполнения
        try:
            result = await asyncio.wait_for(
                fingerprinter.fingerprint_target(
                    target="httpbin.org",
                    port=443,
                    force_refresh=True
                ),
                timeout=5.0  # Общий таймаут для всего процесса
            )
            
            if result:
                print(f"   ✓ Fingerprinting completed: {result.dpi_type}")
                print(f"   ✓ Target: {result.target}:{result.port}")
                print(f"   ✓ Reliability: {result.reliability_score:.2f}")
            else:
                print("   ⚠ Fingerprinting returned None")
                
        except asyncio.TimeoutError:
            print("   ⚠ Fingerprinting timed out (expected for network issues)")
        except asyncio.CancelledError:
            print("   ⚠ Fingerprinting was cancelled")
            raise  # Re-raise to test proper cleanup
        except Exception as e:
            print(f"   ⚠ Fingerprinting failed: {type(e).__name__}: {e}")
    
    finally:
        # Всегда выполняем очистку
        print("   Cleaning up fingerprinter...")
        try:
            await fingerprinter.close()
            print("   ✓ Fingerprinter cleanup completed")
        except Exception as e:
            print(f"   ❌ Cleanup failed: {e}")


async def test_cancellation_during_fingerprinting():
    """Тест отмены во время fingerprinting."""
    print("🚫 Testing cancellation during fingerprinting...")
    
    config = UnifiedFPConfig(timeout=10.0, enable_cache=False)
    fingerprinter = UnifiedFingerprinter(config=config)
    
    async def fingerprint_task():
        try:
            return await fingerprinter.fingerprint_target(
                target="httpbin.org",
                port=443,
                force_refresh=True
            )
        finally:
            await fingerprinter.close()
    
    # Запускаем задачу и отменяем её через короткое время
    task = asyncio.create_task(fingerprint_task())
    
    try:
        # Ждём немного, затем отменяем
        await asyncio.sleep(0.5)
        task.cancel()
        
        # Ждём завершения задачи
        await task
        print("   ⚠ Task completed unexpectedly")
        
    except asyncio.CancelledError:
        print("   ✓ Task cancelled gracefully")
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")


async def main():
    """Главная функция тестирования."""
    print("🧪 Starting extended fingerprinting cleanup tests...\n")
    
    try:
        await test_fingerprinting_with_timeout()
        print()
        await test_cancellation_during_fingerprinting()
        print()
        print("🎉 All extended tests completed!")
        
    except KeyboardInterrupt:
        print("\n⚠ Tests interrupted by user")
    except Exception as e:
        print(f"❌ Tests failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("Starting extended fingerprinting cleanup tests...")
    asyncio.run(main())
    print("Extended tests completed. Check for any asyncio warnings above.")