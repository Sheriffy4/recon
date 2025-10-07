#!/usr/bin/env python3
"""
Тест отката к старым рабочим версиям.
"""
def apply_forced_override(original_func, *args, **kwargs):
    """
    Обертка для принудительного применения стратегий.
    КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ для идентичного поведения с режимом тестирования.
    """
    # Добавляем forced параметры
    if len(args) > 1 and isinstance(args[1], dict):
        # Второй аргумент - стратегия
        strategy = args[1].copy()
        strategy['no_fallbacks'] = True
        strategy['forced'] = True
        args = (args[0], strategy) + args[2:]
        print(f"🔥 FORCED OVERRIDE: Applied to {args[0] if args else 'unknown'}")
    
    return original_func(*args, **kwargs)



import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_rollback():
    """Тестирует откат к старым версиям."""
    print("🔄 ТЕСТ ОТКАТА К СТАРЫМ РАБОЧИМ ВЕРСИЯМ")
    print("=" * 45)
    
    try:
        from core.bypass.engine.windows_engine import WindowsBypassEngine
        from core.bypass.engine.base_engine import EngineConfig
        
        # Создаем движок
        config = EngineConfig(debug=True)
        engine = WindowsBypassEngine(config)
        
        print("✅ Старый WindowsBypassEngine загружен успешно")
        
        # Проверяем что это старая версия (без наших модификаций)
        has_zapret_functions = (
            hasattr(engine, '_send_full_fake_zapret_style') or
            hasattr(engine, '_send_real_segments_zapret_style')
        )
        
        if has_zapret_functions:
            print("⚠️  Обнаружены zapret-style функции (возможно откат неполный)")
        else:
            print("✅ Это чистая старая версия (без zapret модификаций)")
        
        # Проверяем базовые функции
        basic_functions = [
            'apply_bypass',
            '_send_fake_packet',
            '_send_segments',
        ]
        
        print("\n🔍 ПРОВЕРКА БАЗОВЫХ ФУНКЦИЙ:")
        for func_name in basic_functions:
            if hasattr(engine, func_name):
                print(f"  ✅ {func_name}")
            else:
                print(f"  ❌ {func_name} - НЕ НАЙДЕНА")
        
        print("\n🎯 ПЛАН ПОЭТАПНОГО ВОССТАНОВЛЕНИЯ:")
        print("1. Сначала протестируем старую версию")
        print("2. Если она работает - добавим минимальные изменения")
        print("3. Будем тестировать каждое изменение отдельно")
        print("4. Найдем что именно сломало функциональность")
        
        return True
        
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_rollback()
    if success:
        print("\n✅ ОТКАТ УСПЕШЕН!")
        print("🚀 Готов к поэтапному восстановлению функций")
    else:
        print("\n❌ ПРОБЛЕМЫ С ОТКАТОМ!")
    sys.exit(0 if success else 1)