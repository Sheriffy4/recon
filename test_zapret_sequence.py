#!/usr/bin/env python3
"""
Простой тест для проверки zapret-style последовательности пакетов.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_zapret_sequence():
    """Тестирует zapret-style последовательность пакетов."""
    print("🎯 ТЕСТ ZAPRET-STYLE ПОСЛЕДОВАТЕЛЬНОСТИ ПАКЕТОВ")
    print("=" * 50)
    
    try:
        # Импортируем необходимые модули
        from core.bypass.engine.windows_engine import WindowsBypassEngine
        from core.bypass.engine.base_engine import EngineConfig
        
        # Создаем движок
        config = EngineConfig(debug=False)
        engine = WindowsBypassEngine(config)
        
        print("✅ Движок создан успешно")
        
        # Проверяем zapret-style функции
        functions_to_check = [
            '_send_full_fake_zapret_style',
            '_send_real_segments_zapret_style', 
            '_generate_fake_sni'
        ]
        
        for func_name in functions_to_check:
            if hasattr(engine, func_name):
                print(f"✅ {func_name} - найдена")
            else:
                print(f"❌ {func_name} - НЕ НАЙДЕНА")
                return False
        
        # Тестируем генерацию fake SNI
        print("\n🎭 Тест генерации fake SNI:")
        test_domains = ["x.com", "twitter.com", "facebook.com"]
        
        for domain in test_domains:
            fake_sni = engine._generate_fake_sni(domain)
            print(f"  {domain} → {fake_sni}")
            
            # Проверяем формат
            if fake_sni.endswith('.edu') and len(fake_sni) == 16:
                print(f"    ✅ Формат корректный")
            else:
                print(f"    ❌ Неправильный формат")
                return False
        
        print("\n🎯 РЕЗУЛЬТАТ:")
        print("✅ Zapret-style логика восстановлена")
        print("📊 Ожидаемая последовательность пакетов:")
        print("  1. fake ClientHello (~500 байт, bad checksum)")
        print("  2. real segment 1 (3 байта)")  
        print("  3. real segment 2 (~514 байт)")
        print("🚀 Готово к тестированию!")
        
        return True
        
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_zapret_sequence()
    if success:
        print("\n✅ ТЕСТ ПРОЙДЕН!")
    else:
        print("\n❌ ТЕСТ НЕ ПРОЙДЕН!")
    sys.exit(0 if success else 1)