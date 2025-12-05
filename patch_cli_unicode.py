#!/usr/bin/env python3
"""
Патч для автоматической настройки UTF-8 в cli.py
"""

import os
import sys
import re

def create_utf8_setup_code():
    """Создает код для автоматической настройки UTF-8"""
    return '''
# === AUTO UTF-8 SETUP FOR WINDOWS ===
import os
import sys
import locale

def setup_utf8_console():
    """Автоматическая настройка UTF-8 консоли для Windows"""
    try:
        # Устанавливаем UTF-8 кодировку
        if os.name == 'nt':  # Windows
            os.environ['PYTHONIOENCODING'] = 'utf-8'
            os.environ['PYTHONUTF8'] = '1'
            
            # Пытаемся установить кодовую страницу UTF-8
            try:
                import subprocess
                subprocess.run(['chcp', '65001'], shell=True, capture_output=True, check=False)
            except:
                pass
            
            # Настраиваем stdout/stderr для UTF-8
            if hasattr(sys.stdout, 'reconfigure'):
                try:
                    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
                    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
                except:
                    pass
        
        # Устанавливаем локаль
        try:
            locale.setlocale(locale.LC_ALL, '')
        except:
            pass
            
    except Exception:
        # Если что-то пошло не так, просто продолжаем
        pass

# Вызываем настройку UTF-8 сразу при импорте
setup_utf8_console()
# === END UTF-8 SETUP ===

'''

def patch_cli_file():
    """Патчит cli.py для автоматической настройки UTF-8"""
    
    cli_file = 'cli.py'
    
    if not os.path.exists(cli_file):
        print(f"❌ Файл {cli_file} не найден")
        return False
    
    # Читаем содержимое файла
    try:
        with open(cli_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"❌ Ошибка чтения {cli_file}: {e}")
        return False
    
    # Проверяем, не был ли файл уже пропатчен
    if 'AUTO UTF-8 SETUP FOR WINDOWS' in content:
        print("✅ Файл cli.py уже содержит UTF-8 патч")
        return True
    
    # Создаем резервную копию
    backup_file = cli_file + '.backup'
    try:
        with open(backup_file, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"📁 Создана резервная копия: {backup_file}")
    except Exception as e:
        print(f"⚠️ Не удалось создать резервную копию: {e}")
    
    # Находим место для вставки (после shebang и docstring, но перед импортами)
    lines = content.split('\n')
    insert_position = 0
    
    # Пропускаем shebang
    if lines and lines[0].startswith('#!'):
        insert_position = 1
    
    # Пропускаем docstring в начале файла
    in_docstring = False
    docstring_quotes = None
    
    for i in range(insert_position, len(lines)):
        line = lines[i].strip()
        
        if not line or line.startswith('#'):
            continue
            
        # Проверяем начало docstring
        if not in_docstring and (line.startswith('"""') or line.startswith("'''")):
            docstring_quotes = line[:3]
            in_docstring = True
            if line.count(docstring_quotes) >= 2:  # Однострочный docstring
                in_docstring = False
                insert_position = i + 1
            continue
        
        # Проверяем конец docstring
        if in_docstring and docstring_quotes and line.endswith(docstring_quotes):
            in_docstring = False
            insert_position = i + 1
            continue
        
        # Если не в docstring и это не комментарий, то это место для вставки
        if not in_docstring:
            insert_position = i
            break
    
    # Вставляем код настройки UTF-8
    utf8_code = create_utf8_setup_code()
    utf8_lines = utf8_code.strip().split('\n')
    
    # Вставляем код
    new_lines = lines[:insert_position] + utf8_lines + lines[insert_position:]
    new_content = '\n'.join(new_lines)
    
    # Сохраняем пропатченный файл
    try:
        with open(cli_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"✅ Файл {cli_file} успешно пропатчен")
        return True
    except Exception as e:
        print(f"❌ Ошибка записи {cli_file}: {e}")
        return False

def replace_unicode_symbols():
    """Заменяет проблемные Unicode символы на ASCII аналоги"""
    
    # Карта замены Unicode символов
    replacements = {
        '✅': '[OK]',
        '❌': '[FAIL]',
        '⚠️': '[WARN]',
        '🎯': '[TARGET]',
        '🔧': '[CONFIG]',
        '📊': '[STATS]',
        '💡': '[TIP]',
        '🟡': '[PARTIAL]',
        '🔍': '[SEARCH]',
        '🚫': '[BLOCKED]',
        '🎉': '[SUCCESS]',
        '🔄': '[PROCESS]',
        '⏰': '[TIMEOUT]',
        '💥': '[ERROR]',
        '🛠️': '[TOOLS]',
        '📋': '[INFO]',
        '🧪': '[TEST]',
        '🚀': '[START]',
        '📁': '[FILES]',
        '🐍': '[PYTHON]',
        '⚖️': '[COMPARE]',
        '🔬': '[ANALYZE]'
    }
    
    files_to_patch = [
        'cli.py',
        'core/adaptive_engine.py',
        'core/cli/adaptive_cli_wrapper.py'
    ]
    
    patched_files = []
    
    for file_path in files_to_patch:
        if not os.path.exists(file_path):
            print(f"⚠️ Файл не найден: {file_path}")
            continue
        
        try:
            # Читаем файл
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            # Применяем замены
            for unicode_char, ascii_replacement in replacements.items():
                content = content.replace(unicode_char, ascii_replacement)
            
            # Если были изменения, сохраняем файл
            if content != original_content:
                # Создаем резервную копию
                backup_path = file_path + '.unicode_backup'
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(original_content)
                
                # Сохраняем исправленную версию
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                patched_files.append(file_path)
                print(f"✅ Исправлен: {file_path}")
            else:
                print(f"ℹ️ Не требует исправления: {file_path}")
                
        except Exception as e:
            print(f"❌ Ошибка обработки {file_path}: {e}")
    
    return patched_files

def test_patched_cli():
    """Тестирует пропатченный CLI"""
    print("\n🧪 Тестирование пропатченного CLI...")
    
    try:
        import subprocess
        result = subprocess.run(
            ['python', 'cli.py', '--help'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print("✅ CLI запускается успешно")
            return True
        else:
            print(f"❌ CLI завершился с ошибкой: {result.returncode}")
            if result.stderr:
                print(f"Ошибка: {result.stderr[:200]}")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка тестирования: {e}")
        return False

def main():
    print("🔧 Патч CLI для автоматической настройки UTF-8")
    print("=" * 60)
    
    # Шаг 1: Патчим cli.py для автоматической настройки UTF-8
    print("\n1️⃣ Добавление автоматической настройки UTF-8 в cli.py...")
    cli_patched = patch_cli_file()
    
    # Шаг 2: Заменяем проблемные Unicode символы
    print("\n2️⃣ Замена Unicode символов на ASCII аналоги...")
    patched_files = replace_unicode_symbols()
    
    # Шаг 3: Тестируем результат
    print("\n3️⃣ Тестирование результата...")
    test_success = test_patched_cli()
    
    # Итоги
    print(f"\n📊 РЕЗУЛЬТАТЫ ПАТЧА:")
    print(f"   CLI пропатчен: {'✅' if cli_patched else '❌'}")
    print(f"   Unicode исправлен в {len(patched_files)} файлах")
    print(f"   Тестирование: {'✅ Успешно' if test_success else '❌ Неудача'}")
    
    if cli_patched and test_success:
        print(f"\n🎉 ПАТЧ ПРИМЕНЕН УСПЕШНО!")
        print(f"   Теперь можно запускать:")
        print(f"   python cli.py auto x.com")
        print(f"   python cli.py --help")
        print(f"   python cli.py auto google.com --mode comprehensive")
        
        # Тестируем auto режим
        print(f"\n🧪 Быстрый тест auto режима...")
        try:
            import subprocess
            result = subprocess.run(
                ['python', 'cli.py', 'auto', 'google.com', '--max-trials', '2'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print("✅ Auto режим работает!")
            else:
                print(f"⚠️ Auto режим завершился с кодом {result.returncode}")
                
        except subprocess.TimeoutExpired:
            print("⏰ Auto режим запустился (таймаут - это нормально)")
        except Exception as e:
            print(f"❌ Ошибка тестирования auto режима: {e}")
    
    else:
        print(f"\n❌ ПАТЧ НЕ ПРИМЕНЕН")
        print(f"   Проверьте ошибки выше и попробуйте снова")
        
        if not cli_patched:
            print(f"   Проблема с патчем cli.py")
        if not test_success:
            print(f"   Проблема с тестированием CLI")
    
    print(f"\n💡 ПРИМЕЧАНИЯ:")
    print(f"   - Резервные копии созданы с расширением .backup и .unicode_backup")
    print(f"   - Для отката изменений переименуйте .backup файлы обратно")
    print(f"   - Патч добавляет автоматическую настройку UTF-8 при запуске")

if __name__ == "__main__":
    main()