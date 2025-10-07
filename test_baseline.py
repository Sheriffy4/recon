#!/usr/bin/env python3
"""
Быстрый тест baseline функциональности старой версии.
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

def test_baseline():
    """Тестирует baseline функциональность."""
    print("📊 ТЕСТ BASELINE ФУНКЦИОНАЛЬНОСТИ")
    print("=" * 40)
    
    try:
        from core.bypass.engine.windows_engine import WindowsBypassEngine
        from core.bypass.engine.base_engine import EngineConfig
        
        # Создаем движок
        config = EngineConfig(debug=False)  # Без отладки для чистоты
        engine = WindowsBypassEngine(config)
        
        print("✅ Движок создан")
        
        # Проверяем ключевые методы
        print("\n🔍 ПРОВЕРКА КЛЮЧЕВЫХ МЕТОДОВ:")
        
        methods_to_check = [
            ('apply_bypass', 'Основной метод обхода'),
            ('_send_fake_packet', 'Отправка fake пакетов'),
            ('_send_segments', 'Отправка сегментов'),
            ('_tcp_checksum', 'Расчет TCP checksum'),
            ('_ip_header_checksum', 'Расчет IP checksum'),
        ]
        
        for method_name, description in methods_to_check:
            if hasattr(engine, method_name):
                print(f"  ✅ {method_name} - {description}")
            else:
                print(f"  ❌ {method_name} - НЕ НАЙДЕН")
        
        # Проверяем что нет наших модификаций
        print("\n🔍 ПРОВЕРКА ОТСУТСТВИЯ МОДИФИКАЦИЙ:")
        
        modifications = [
            ('_send_full_fake_zapret_style', 'Zapret-style fake'),
            ('_send_real_segments_zapret_style', 'Zapret-style real'),
            ('force_zapret', 'Принудительная активация'),
        ]
        
        has_modifications = False
        for mod_name, description in modifications:
            if hasattr(engine, mod_name) or 'force_zapret' in str(engine.__class__):
                print(f"  ⚠️  {mod_name} - НАЙДЕНА (возможно откат неполный)")
                has_modifications = True
            else:
                print(f"  ✅ {mod_name} - отсутствует")
        
        if not has_modifications:
            print("\n✅ ЧИСТАЯ СТАРАЯ ВЕРСИЯ ВОССТАНОВЛЕНА")
            print("🎯 Готова к baseline тестированию")
        else:
            print("\n⚠️  ВОЗМОЖНО ОТКАТ НЕПОЛНЫЙ")
            print("🔧 Может потребоваться дополнительная очистка")
        
        print("\n📋 СЛЕДУЮЩИЕ ШАГИ:")
        print("1. Запустить полный тест со старой версией")
        print("2. Зафиксировать baseline результаты")
        print("3. Начать поэтапное добавление улучшений")
        
        return True
        
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_baseline()
    if success:
        print("\n✅ BASELINE ТЕСТ ПРОЙДЕН!")
    else:
        print("\n❌ ПРОБЛЕМЫ С BASELINE!")
    sys.exit(0 if success else 1)