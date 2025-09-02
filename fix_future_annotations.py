#!/usr/bin/env python3
"""
Исправление проблемы с future annotations
"""

import sys
import os
from pathlib import Path

def fix_future_imports():
    """Исправляет проблемы с future imports в проекте."""
    print("🔧 Исправление future annotations в проекте")
    print("=" * 50)
    
    # Файлы, которые могут использовать future annotations
    files_to_check = []
    
    # Сканируем все Python файлы в core/
    for root, dirs, files in os.walk("core"):
        for file in files:
            if file.endswith(".py"):
                files_to_check.append(os.path.join(root, file))
    
    fixed_count = 0
    
    for file_path in files_to_check:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Проверяем, есть ли проблемные импорты
            if "from future import annotations" in content:
                print(f"🔍 Исправление {file_path}...")
                
                # Заменяем проблемный импорт
                content = content.replace("from future import annotations", "# from future import annotations  # Disabled due to compatibility issues")
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                print(f"  ✅ Исправлено")
                fixed_count += 1
            
            # Также проверяем другие варианты
            if "from __future__ import annotations" in content and "# Disabled" not in content:
                # Этот импорт нормальный, но проверим контекст
                lines = content.split('\n')
                first_import_line = -1
                
                for i, line in enumerate(lines):
                    if line.strip().startswith("from __future__ import annotations"):
                        first_import_line = i
                        break
                
                # Если импорт не в начале файла, исправляем
                if first_import_line > 10:  # Если не в первых 10 строках
                    print(f"🔍 Перемещение импорта в {file_path}...")
                    
                    # Удаляем старый импорт
                    lines = [line for line in lines if not line.strip().startswith("from __future__ import annotations")]
                    
                    # Добавляем в начало (после docstring если есть)
                    insert_pos = 0
                    if lines and lines[0].strip().startswith('"""'):
                        # Ищем конец docstring
                        for i in range(1, len(lines)):
                            if lines[i].strip().endswith('"""'):
                                insert_pos = i + 1
                                break
                    
                    lines.insert(insert_pos, "from __future__ import annotations")
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(lines))
                    
                    print(f"  ✅ Импорт перемещен в начало файла")
                    fixed_count += 1
                    
        except Exception as e:
            print(f"❌ Ошибка обработки {file_path}: {e}")
    
    print(f"\n📊 Исправлено файлов: {fixed_count}")
    return fixed_count > 0

def create_compatibility_module():
    """Создает модуль совместимости для future annotations."""
    print("\n🔧 Создание модуля совместимости")
    print("=" * 40)
    
    compat_content = '''"""
Модуль совместимости для future annotations
"""

import sys

# Проверяем версию Python
if sys.version_info >= (3, 7):
    # В Python 3.7+ annotations доступны
    try:
        from __future__ import annotations
        ANNOTATIONS_AVAILABLE = True
    except ImportError:
        ANNOTATIONS_AVAILABLE = False
else:
    ANNOTATIONS_AVAILABLE = False

def get_type_hints(obj):
    """Безопасное получение type hints."""
    try:
        import typing
        return typing.get_type_hints(obj)
    except (ImportError, AttributeError, NameError):
        return {}

def safe_annotations(func):
    """Декоратор для безопасной работы с annotations."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (ImportError, AttributeError, NameError):
            # Если annotations не работают, возвращаем пустой результат
            return {}
    return wrapper
'''
    
    try:
        with open("core/compat.py", 'w', encoding='utf-8') as f:
            f.write(compat_content)
        
        print("✅ Создан модуль совместимости: core/compat.py")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка создания модуля: {e}")
        return False

def main():
    """Главная функция."""
    print("🚀 Исправление проблем с future annotations")
    print("=" * 60)
    
    success1 = fix_future_imports()
    success2 = create_compatibility_module()
    
    if success1 or success2:
        print("\n🎉 Проблемы с future annotations исправлены!")
        print("   Перезапустите скрипты для применения изменений")
    else:
        print("\n⚠️  Проблемы не найдены или не удалось исправить")
    
    return success1 or success2

if __name__ == "__main__":
    main()