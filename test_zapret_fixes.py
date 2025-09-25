#!/usr/bin/env python3
"""
Быстрый тест исправлений zapret совместимости
"""
import subprocess
import sys
import time

def run_test():
    """Запускает быстрый тест с одной стратегией."""
    print("🧪 Тестируем исправления zapret совместимости...")
    print("=" * 60)
    
    # Создаем файл с одним доменом для быстрого теста
    with open("test_site.txt", "w") as f:
        f.write("x.com\n")
    
    # Запускаем тест с одной стратегией
    cmd = [
        sys.executable, "smart_bypass_cli.py",
        "test-file",
        "test_site.txt"
    ]
    
    print(f"Команда: {' '.join(cmd)}")
    print("-" * 60)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)
            
        print(f"\nReturn code: {result.returncode}")
        
        # Ищем ключевые индикаторы в выводе
        output = result.stdout + result.stderr
        
        print("\n" + "=" * 60)
        print("🔍 АНАЛИЗ РЕЗУЛЬТАТОВ:")
        
        if "ZAPRET-COMPATIBLE CONDITIONS DETECTED" in output:
            print("✅ Zapret-совместимые условия обнаружены")
        else:
            print("❌ Zapret-совместимые условия НЕ обнаружены")
            
        if "ZAPRET-STYLE ACTIVATED" in output:
            print("✅ Zapret-style режим активирован")
        else:
            print("❌ Zapret-style режим НЕ активирован")
            
        if "Sending FULL fake with corrupted checksum" in output:
            print("✅ Отправка полного fake с испорченной checksum")
        else:
            print("❌ НЕ отправляется полный fake с испорченной checksum")
            
        if "CHECKSUM DEBUG" in output:
            print("✅ Отладка checksum работает")
        else:
            print("❌ Отладка checksum НЕ работает")
            
        if "REAL segment" in output and "PSH|ACK" in output:
            print("✅ Реальные сегменты с PSH|ACK флагами")
        else:
            print("❌ Реальные сегменты БЕЗ PSH|ACK флагов")
            
        # Проверяем наличие fake SNI
        if ".edu" in output:
            print("✅ Fake SNI с .edu доменом")
        else:
            print("❌ НЕ используется fake SNI с .edu доменом")
            
    except subprocess.TimeoutExpired:
        print("❌ Тест превысил время ожидания")
    except Exception as e:
        print(f"❌ Ошибка выполнения теста: {e}")

if __name__ == "__main__":
    run_test()