#!/usr/bin/env python3
"""
Тест исправления badsum для fake пакетов.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_badsum_fix():
    """Тестирует исправление badsum."""
    print("🔧 ТЕСТ ИСПРАВЛЕНИЯ BADSUM ДЛЯ FAKE ПАКЕТОВ")
    print("=" * 45)
    
    try:
        # Проверяем что исправление применилось
        with open("core/bypass/engine/windows_engine.py", "r", encoding="utf-8") as f:
            content = f.read()
        
        # Ищем наше исправление
        if "opts.get(\"is_fake\")" in content:
            print("✅ Исправление badsum применено")
        else:
            print("❌ Исправление badsum НЕ НАЙДЕНО")
            return False
        
        if "Corrupted checksum for fake packet" in content:
            print("✅ Отладочное сообщение добавлено")
        else:
            print("❌ Отладочное сообщение НЕ НАЙДЕНО")
            return False
        
        # Проверяем что движок загружается
        from core.bypass.engine.windows_engine import WindowsBypassEngine
        from core.bypass.engine.base_engine import EngineConfig
        
        config = EngineConfig(debug=True)
        engine = WindowsBypassEngine(config)
        
        print("✅ Движок с исправлением загружен")
        
        print("\n🎯 ОЖИДАЕМОЕ ПОВЕДЕНИЕ:")
        print("1. Fake пакеты (is_fake=True) будут иметь испорченную checksum")
        print("2. Real пакеты будут иметь правильную checksum")
        print("3. В логах появится сообщение 'Corrupted checksum for fake packet'")
        
        print("\n📊 ОЖИДАЕМЫЙ РЕЗУЛЬТАТ В PCAP:")
        print('  "csum_fake_bad": true  ✅ (вместо false)')
        
        return True
        
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_badsum_fix()
    if success:
        print("\n✅ ТЕСТ BADSUM ИСПРАВЛЕНИЯ ПРОЙДЕН!")
        print("🚀 Готово к тестированию")
    else:
        print("\n❌ ПРОБЛЕМЫ С ИСПРАВЛЕНИЕМ!")
    sys.exit(0 if success else 1)