#!/usr/bin/env python3
"""
Тест forced override на уровне bypass engine.
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
from pathlib import Path

# Добавляем путь к проекту
recon_dir = Path(__file__).parent
if str(recon_dir) not in sys.path:
    sys.path.insert(0, str(recon_dir))

def test_engine_forced_override():
    """Тестирует forced override в bypass engine."""
    
    print("🧪 ТЕСТИРОВАНИЕ ENGINE FORCED OVERRIDE")
    print("=" * 50)
    
    try:
        # Пытаемся импортировать bypass engine
        possible_imports = [
            'core.bypass.engine.base_engine',
            'core.bypass_engine',
            'core.bypass.engine'
        ]
        
        engine_class = None
        
        for import_path in possible_imports:
            try:
                module = __import__(import_path, fromlist=[''])
                
                # Ищем класс engine
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and 
                        'engine' in attr_name.lower() and 
                        hasattr(attr, '__init__')):
                        engine_class = attr
                        print(f"✅ Найден engine класс: {attr_name} из {import_path}")
                        break
                
                if engine_class:
                    break
                    
            except ImportError as e:
                print(f"⚠️ Не удалось импортировать {import_path}: {e}")
                continue
        
        if not engine_class:
            print("❌ Bypass engine класс не найден!")
            return False
        
        # Создаем экземпляр engine
        try:
            engine = engine_class()
            print(f"✅ Создан экземпляр engine: {type(engine).__name__}")
        except Exception as e:
            print(f"❌ Ошибка создания engine: {e}")
            return False
        
        # Проверяем наличие методов forced override
        methods_to_check = [
            'set_forced_strategy',
            'apply_bypass_with_forced_override'
        ]
        
        methods_found = 0
        for method_name in methods_to_check:
            if hasattr(engine, method_name):
                print(f"✅ Метод {method_name} найден")
                methods_found += 1
            else:
                print(f"❌ Метод {method_name} НЕ найден")
        
        if methods_found == len(methods_to_check):
            print(f"\n🎉 ВСЕ МЕТОДЫ FORCED OVERRIDE НАЙДЕНЫ!")
            
            # Тестируем установку forced strategy
            try:
                test_strategy = {
                    'type': 'fakeddisorder',
                    'params': {'ttl': 4, 'split_pos': 3},
                    'no_fallbacks': True,
                    'forced': True
                }
                
                engine.set_forced_strategy(test_strategy)
                print(f"✅ Forced strategy установлена успешно")
                
                if hasattr(engine, 'forced_strategy'):
                    print(f"✅ Forced strategy сохранена в engine")
                    return True
                else:
                    print(f"❌ Forced strategy НЕ сохранена")
                    return False
                    
            except Exception as e:
                print(f"❌ Ошибка установки forced strategy: {e}")
                return False
        else:
            print(f"\n❌ НЕ ВСЕ МЕТОДЫ НАЙДЕНЫ ({methods_found}/{len(methods_to_check)})")
            return False
            
    except Exception as e:
        print(f"❌ Общая ошибка тестирования: {e}")
        return False

if __name__ == "__main__":
    success = test_engine_forced_override()
    
    if success:
        print(f"\n🎉 ТЕСТ ПРОЙДЕН!")
        print("✅ Engine forced override работает")
        print("🚀 Можно перезапускать службу")
    else:
        print(f"\n❌ ТЕСТ НЕ ПРОЙДЕН!")
        print("🔧 Нужны дополнительные исправления")
