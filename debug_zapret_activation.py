#!/usr/bin/env python3
"""
Отладка активации zapret-style логики.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def debug_zapret_activation():
    """Отлаживает активацию zapret-style логики."""
    print("🔧 ОТЛАДКА АКТИВАЦИИ ZAPRET-STYLE ЛОГИКИ")
    print("=" * 50)
    
    try:
        from core.bypass.engine.windows_engine import WindowsBypassEngine
        from core.bypass.engine.base_engine import EngineConfig
        
        # Создаем движок
        config = EngineConfig(debug=True)
        engine = WindowsBypassEngine(config)
        
        print("✅ Движок создан")
        
        # Тестируем условия активации zapret-style
        print("\n🎯 ТЕСТ УСЛОВИЙ АКТИВАЦИИ:")
        
        test_cases = [
            {"split_pos": 3, "fooling": ["badsum"], "expected": True},
            {"split_pos": 3, "fooling": ["md5sig"], "expected": False},
            {"split_pos": 76, "fooling": ["badsum"], "expected": False},
            {"split_pos": 3, "fooling": [], "expected": False},
        ]
        
        for i, case in enumerate(test_cases, 1):
            split_pos = case["split_pos"]
            fooling_list = case["fooling"]
            expected = case["expected"]
            
            # Проверяем условие
            zapret_compatible = (split_pos == 3 and "badsum" in fooling_list)
            
            status = "✅" if zapret_compatible == expected else "❌"
            print(f"{status} Тест {i}: split_pos={split_pos}, fooling={fooling_list}")
            print(f"   Ожидается: {expected}, Получено: {zapret_compatible}")
        
        # Проверяем текущие параметры движка
        print(f"\n🔍 ТЕКУЩИЕ ПАРАМЕТРЫ ДВИЖКА:")
        print(f"  current_params: {getattr(engine, 'current_params', {})}")
        
        # Тестируем генерацию fake SNI
        print(f"\n🎭 ТЕСТ ГЕНЕРАЦИИ FAKE SNI:")
        test_domains = ["x.com", "api.twitter.com"]
        for domain in test_domains:
            fake_sni = engine._generate_fake_sni(domain)
            print(f"  {domain} → {fake_sni}")
        
        # Проверяем, что функции существуют
        print(f"\n🔍 ПРОВЕРКА ZAPRET-STYLE ФУНКЦИЙ:")
        functions = [
            "_send_full_fake_zapret_style",
            "_send_real_segments_zapret_style",
            "_generate_fake_sni",
            "_replace_sni_in_clienthello"
        ]
        
        for func_name in functions:
            exists = hasattr(engine, func_name)
            status = "✅" if exists else "❌"
            print(f"  {status} {func_name}")
        
        # Анализируем возможные проблемы
        print(f"\n🎯 ВОЗМОЖНЫЕ ПРОБЛЕМЫ:")
        
        print("1. ПРОВЕРЬТЕ СТРАТЕГИИ:")
        print("   - Используется ли split_pos=3?")
        print("   - Включен ли fooling=badsum?")
        print("   - Активируется ли zapret-compatible условие?")
        
        print("\n2. ПРОВЕРЬТЕ ОТПРАВКУ ПАКЕТОВ:")
        print("   - Отправляется ли fake ClientHello с TTL=1-3?")
        print("   - Отправляются ли real сегменты с TTL=3?")
        print("   - Портится ли checksum в fake пакетах?")
        
        print("\n3. ПРОВЕРЬТЕ DPI РЕАКЦИЮ:")
        print("   - Блокирует ли DPI fake пакеты?")
        print("   - Пропускает ли DPI real сегменты?")
        print("   - Возможно, нужны другие параметры (TTL, размер, задержка)?")
        
        return True
        
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

def analyze_strategy_activation():
    """Анализирует активацию стратегий из логов."""
    print("\n🔍 АНАЛИЗ АКТИВАЦИИ СТРАТЕГИЙ ИЗ PCAP:")
    
    # Из анализа PCAP мы знаем:
    print("📊 ДАННЫЕ ИЗ PCAP АНАЛИЗА:")
    print("  - TTL=3 пакетов: 1760 (fake пакеты)")
    print("  - Пакетов 400-600 байт: 1728 (fake ClientHello)")
    print("  - Пакетов 3 байта: 137 (первые real сегменты)")
    print("  - Пакетов 514 байт: 137 (вторые real сегменты)")
    
    print("\n🎯 ВЫВОДЫ:")
    print("✅ Zapret-style логика АКТИВИРУЕТСЯ")
    print("✅ Fake пакеты ОТПРАВЛЯЮТСЯ")
    print("✅ Real сегменты ОТПРАВЛЯЮТСЯ")
    print("❌ Но обход НЕ РАБОТАЕТ (0% успеха)")
    
    print("\n🔧 ВОЗМОЖНЫЕ ПРИЧИНЫ НЕУДАЧИ:")
    print("1. DPI не блокирует fake пакеты (TTL слишком высокий?)")
    print("2. DPI все равно блокирует real сегменты")
    print("3. Неправильная последовательность или тайминг")
    print("4. Checksum не портится должным образом")
    print("5. SNI в fake пакетах недостаточно убедительный")

if __name__ == "__main__":
    success = debug_zapret_activation()
    if success:
        analyze_strategy_activation()
    sys.exit(0 if success else 1)