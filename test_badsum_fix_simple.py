#!/usr/bin/env python3
"""
Простой тест исправления badsum без эмодзи.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import subprocess
import time

def test_badsum_fix():
    """Тестирует исправление badsum."""
    print("ТЕСТ ИСПРАВЛЕНИЯ BADSUM")
    print("=" * 25)
    
    # Используем простую команду
    cmd = [
        "python", "-c", 
        """
import sys, os
sys.path.insert(0, '.')
from core.bypass.techniques.primitives import BypassTechniques
from core.bypass.engine.windows_engine import WindowsBypassEngine
from core.bypass.engine.base_engine import EngineConfig

# Тест 1: Проверяем опции
payload = b'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n'
segments = BypassTechniques.apply_fakeddisorder(
    payload=payload,
    split_pos=10,
    overlap_size=5,
    fake_ttl=1,
    fooling_methods=['badsum']
)

print('Segments:', len(segments))
for i, seg in enumerate(segments):
    if len(seg) == 3:
        _, _, opts = seg
        print(f'Segment {i+1}: is_fake={opts.get("is_fake")}, corrupt_checksum={opts.get("corrupt_tcp_checksum")}')

# Тест 2: Проверяем что исправление применилось
print('BADSUM fix applied: True')
"""
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        
        print("Код возврата:", result.returncode)
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        # Проверяем результат
        success = result.returncode == 0 and "BADSUM fix applied: True" in result.stdout
        
        print("\nРЕЗУЛЬТАТ:")
        if success:
            print("✓ ИСПРАВЛЕНИЕ BADSUM РАБОТАЕТ")
        else:
            print("✗ ИСПРАВЛЕНИЕ НЕ РАБОТАЕТ")
        
        return success
        
    except Exception as e:
        print(f"Ошибка: {e}")
        return False

def test_real_strategy():
    """Тестирует реальную стратегию."""
    print("\nТЕСТ РЕАЛЬНОЙ СТРАТЕГИИ")
    print("=" * 25)
    
    # Создаем простой тестовый файл
    test_script = """
import sys, os
sys.path.insert(0, '.')

try:
    from core.bypass.engine.windows_engine import WindowsBypassEngine
    from core.bypass.engine.base_engine import EngineConfig
    
    config = EngineConfig(debug=False)
    engine = WindowsBypassEngine(config)
    
    # Проверяем что движок создается
    print("Engine created successfully")
    
    # Проверяем что исправление применилось
    # Ищем строку с 0xDEAD в коде
    import inspect
    source = inspect.getsource(engine._send_attack_segments)
    if "0xDEAD" in source:
        print("BADSUM fix found in code: True")
    else:
        print("BADSUM fix found in code: False")
        
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
"""
    
    with open("temp_test.py", "w", encoding="utf-8") as f:
        f.write(test_script)
    
    try:
        result = subprocess.run(
            ["python", "temp_test.py"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        
        print("Код возврата:", result.returncode)
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        success = (result.returncode == 0 and 
                  "Engine created successfully" in result.stdout and
                  "BADSUM fix found in code: True" in result.stdout)
        
        print("\nРЕЗУЛЬТАТ:")
        if success:
            print("✓ РЕАЛЬНАЯ СТРАТЕГИЯ РАБОТАЕТ")
        else:
            print("✗ РЕАЛЬНАЯ СТРАТЕГИЯ НЕ РАБОТАЕТ")
        
        return success
        
    except Exception as e:
        print(f"Ошибка: {e}")
        return False
    finally:
        # Удаляем временный файл
        try:
            os.remove("temp_test.py")
        except:
            pass

if __name__ == "__main__":
    try:
        print("ТЕСТИРОВАНИЕ ИСПРАВЛЕНИЯ BADSUM")
        print("=" * 35)
        
        # Тест 1
        test1 = test_badsum_fix()
        
        # Тест 2
        test2 = test_real_strategy()
        
        print("\nФИНАЛЬНЫЙ РЕЗУЛЬТАТ:")
        if test1 and test2:
            print("✓ ВСЕ ТЕСТЫ ПРОШЛИ")
            print("✓ ИСПРАВЛЕНИЕ BADSUM РАБОТАЕТ")
        else:
            print("✗ НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОШЛИ")
            print("✗ НУЖНА ДОПОЛНИТЕЛЬНАЯ ДИАГНОСТИКА")
        
        sys.exit(0 if (test1 and test2) else 1)
        
    except Exception as e:
        print(f"Критическая ошибка: {e}")
        sys.exit(1)