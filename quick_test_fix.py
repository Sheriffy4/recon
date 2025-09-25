#!/usr/bin/env python3
"""
Быстрый тест исправлений TTL и checksum.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def quick_test():
    """Быстрый тест исправлений."""
    print("⚡ БЫСТРЫЙ ТЕСТ ИСПРАВЛЕНИЙ")
    print("=" * 30)
    
    try:
        # Проверяем что файл изменен
        with open("core/bypass/engine/windows_engine.py", "r", encoding="utf-8") as f:
            content = f.read()
        
        # Проверяем ключевые исправления
        checks = [
            ("fake_ttl = 1", "TTL=1 для fake пакетов"),
            ("real_ttl = 3", "TTL=3 для real сегментов"),
            ("time.sleep(0.001)", "Задержка 1ms"),
            ("corrupt_checksum = False", "Правильная checksum для real"),
        ]
        
        print("🔍 ПРОВЕРКА ИСПРАВЛЕНИЙ В КОДЕ:")
        all_good = True
        
        for check, description in checks:
            if check in content:
                print(f"✅ {description}")
            else:
                print(f"❌ {description} - НЕ НАЙДЕНО")
                all_good = False
        
        if all_good:
            print("\n🎯 ВСЕ ИСПРАВЛЕНИЯ ПРИМЕНЕНЫ!")
            print("📊 Ожидаемая последовательность:")
            print("  1. fake ClientHello (TTL=1, badsum)")
            print("  2. [задержка 1ms]")
            print("  3. real segment 1 (TTL=3, good checksum)")
            print("  4. real segment 2 (TTL=3, good checksum)")
            print("\n🚀 ГОТОВО К ТЕСТИРОВАНИЮ!")
            return True
        else:
            print("\n❌ НЕ ВСЕ ИСПРАВЛЕНИЯ ПРИМЕНЕНЫ")
            return False
        
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        return False

if __name__ == "__main__":
    success = quick_test()
    sys.exit(0 if success else 1)