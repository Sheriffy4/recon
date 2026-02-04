#!/usr/bin/env python3
"""
Скрипт для отладки проблемы с AttackResult.segments.

Воспроизводит и исправляет проблему с присваиванием property объекта полю segments.
"""

import sys
import logging
from pathlib import Path

# Добавляем корневую директорию в путь
sys.path.insert(0, str(Path(__file__).parent))

# Настройка логирования для отладки
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_attack_result_segments():
    """Тестирует различные сценарии присваивания segments."""
    print("🔍 ОТЛАДКА ПРОБЛЕМЫ С AttackResult.segments")
    print("=" * 45)
    print()
    
    try:
        from core.bypass.attacks.base import AttackResult, AttackStatus
        
        print("✅ Успешно импортирован AttackResult")
        
        # Тест 1: Нормальное создание
        print("\n1️⃣ Тест нормального создания AttackResult:")
        result1 = AttackResult(status=AttackStatus.SUCCESS)
        print(f"   Создан: {type(result1)}")
        print(f"   segments: {result1.segments}")
        print(f"   Тип segments: {type(result1.segments)}")
        
        # Тест 2: Присваивание правильного списка
        print("\n2️⃣ Тест присваивания правильного списка:")
        test_segments = [(b"test", 0, {})]
        result1.segments = test_segments
        print(f"   Присвоен список: {test_segments}")
        print(f"   segments: {result1.segments}")
        print(f"   Тип segments: {type(result1.segments)}")
        
        # Тест 3: Присваивание None
        print("\n3️⃣ Тест присваивания None:")
        result1.segments = None
        print(f"   Присвоен None")
        print(f"   segments: {result1.segments}")
        print(f"   Тип segments: {type(result1.segments)}")
        
        # Тест 4: Присваивание неправильного типа (воспроизводим проблему)
        print("\n4️⃣ Тест присваивания неправильного типа:")
        
        # Создаем property объект для тестирования
        class TestClass:
            @property
            def test_property(self):
                return "I am a property"
        
        test_obj = TestClass()
        
        print(f"   Пытаемся присвоить property: {type(test_obj.test_property)}")
        result1.segments = test_obj.test_property  # Это должно вызвать предупреждение
        print(f"   segments после присваивания: {result1.segments}")
        print(f"   Тип segments: {type(result1.segments)}")
        
        # Тест 5: Присваивание другого AttackResult (возможная причина проблемы)
        print("\n5️⃣ Тест присваивания другого AttackResult:")
        result2 = AttackResult(status=AttackStatus.SUCCESS)
        result2.segments = [(b"test2", 1, {"ttl": 64})]
        
        print(f"   result2.segments: {result2.segments}")
        print(f"   Тип result2.segments: {type(result2.segments)}")
        
        # Попытка присвоить result2 как segments (неправильно)
        print(f"   Пытаемся присвоить result2: {type(result2)}")
        result1.segments = result2  # Это должно вызвать предупреждение
        print(f"   segments после присваивания: {result1.segments}")
        
        # Тест 6: Присваивание property от AttackResult
        print("\n6️⃣ Тест присваивания property от AttackResult:")
        result3 = AttackResult(status=AttackStatus.SUCCESS)
        result3.segments = [(b"test3", 2, {})]
        
        # Получаем property объект
        segments_property = result3.__class__.segments
        print(f"   Property объект: {type(segments_property)}")
        
        # Пытаемся присвоить property (это может быть источником проблемы)
        result1.segments = segments_property  # Это должно вызвать предупреждение
        print(f"   segments после присваивания property: {result1.segments}")
        
        print("\n✅ Все тесты завершены")
        
    except Exception as e:
        logger.error(f"Ошибка во время тестирования: {e}", exc_info=True)
        print(f"\n❌ Ошибка: {e}")
        return False
    
    return True


def find_potential_issues():
    """Ищет потенциальные источники проблемы в коде."""
    print("\n🔎 ПОИСК ПОТЕНЦИАЛЬНЫХ ПРОБЛЕМ")
    print("=" * 35)
    
    try:
        from core.bypass.attacks.base import AttackResult, AttackStatus
        
        # Проверяем, есть ли проблемы с определением класса
        print(f"AttackResult класс: {AttackResult}")
        print(f"AttackResult.__dict__: {list(AttackResult.__dict__.keys())}")
        
        # Проверяем property segments
        segments_attr = getattr(AttackResult, 'segments', None)
        print(f"segments атрибут: {segments_attr}")
        print(f"Тип segments атрибута: {type(segments_attr)}")
        
        if hasattr(segments_attr, 'fget'):
            print(f"segments.fget: {segments_attr.fget}")
        if hasattr(segments_attr, 'fset'):
            print(f"segments.fset: {segments_attr.fset}")
        
        # Создаем экземпляр и проверяем
        instance = AttackResult(status=AttackStatus.SUCCESS)
        print(f"Экземпляр создан: {type(instance)}")
        print(f"instance.segments: {instance.segments}")
        print(f"Тип instance.segments: {type(instance.segments)}")
        
        # Проверяем metadata
        print(f"instance.metadata: {instance.metadata}")
        print(f"Тип instance.metadata: {type(instance.metadata)}")
        
    except Exception as e:
        logger.error(f"Ошибка при анализе: {e}", exc_info=True)
        print(f"❌ Ошибка при анализе: {e}")


def suggest_fixes():
    """Предлагает исправления для проблемы."""
    print("\n🔧 ПРЕДЛАГАЕМЫЕ ИСПРАВЛЕНИЯ")
    print("=" * 30)
    
    print("1. Проверить все места, где присваивается segments:")
    print("   - Убедиться, что присваивается список кортежей")
    print("   - Не присваивать другие AttackResult объекты")
    print("   - Не присваивать property объекты")
    
    print("\n2. Добавить валидацию в setter:")
    print("   - Проверять тип значения перед присваиванием")
    print("   - Логировать подробную информацию об ошибках")
    print("   - Преобразовывать неправильные типы в пустой список")
    
    print("\n3. Проверить импорты:")
    print("   - Убедиться, что используется правильный AttackResult")
    print("   - Избегать циклических импортов")
    print("   - Использовать абсолютные импорты")
    
    print("\n4. Добавить типизацию:")
    print("   - Использовать type hints для segments")
    print("   - Добавить runtime проверки типов")
    print("   - Использовать mypy для статической проверки")


def main():
    """Основная функция."""
    try:
        success = test_attack_result_segments()
        
        if success:
            find_potential_issues()
            suggest_fixes()
        
        print("\n🎉 Отладка завершена!")
        return 0
        
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}", exc_info=True)
        print(f"\n❌ Критическая ошибка: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())