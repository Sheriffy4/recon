#!/usr/bin/env python3
"""
Тест реального исправления badsum.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import subprocess
import time
import json

def test_badsum_fix():
    """Тестирует исправление badsum в реальных условиях."""
    print("🔧 ТЕСТ ИСПРАВЛЕНИЯ BADSUM")
    print("=" * 30)
    
    # Тестируем стратегию с badsum
    strategy = "fakeddisorder,split_pos:10,overlap_size:5,fake_ttl:1,fooling:badsum"
    
    print(f"📋 Тестируемая стратегия: {strategy}")
    
    # Запускаем тест
    cmd = [
        "python", "simple_bypass_test.py",
        "--strategy", strategy,
        "--target", "api.x.com",
        "--timeout", "10"
    ]
    
    print(f"🚀 Запуск: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        
        print(f"📊 Код возврата: {result.returncode}")
        print(f"📤 STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print(f"📥 STDERR:")
            print(result.stderr)
        
        # Анализируем результат
        success = result.returncode == 0
        has_badsum = "csum_fake_bad" in result.stdout
        
        print(f"\n🎯 АНАЛИЗ РЕЗУЛЬТАТА:")
        print(f"  Успешное выполнение: {success} {'✅' if success else '❌'}")
        print(f"  Упоминание badsum: {has_badsum} {'✅' if has_badsum else '❌'}")
        
        # Ищем информацию о badsum в выводе
        if "csum_fake_bad" in result.stdout:
            lines = result.stdout.split('\n')
            for line in lines:
                if "csum_fake_bad" in line:
                    print(f"  Строка с badsum: {line.strip()}")
                    if "true" in line.lower():
                        print("  ✅ BADSUM РАБОТАЕТ!")
                        return True
                    else:
                        print("  ❌ BADSUM НЕ РАБОТАЕТ")
        
        return False
        
    except subprocess.TimeoutExpired:
        print("⏰ Тест превысил время ожидания")
        return False
    except Exception as e:
        print(f"❌ Ошибка выполнения: {e}")
        return False

def test_multiple_strategies():
    """Тестирует несколько стратегий с badsum."""
    print(f"\n🧪 ТЕСТ МНОЖЕСТВЕННЫХ СТРАТЕГИЙ")
    print("=" * 35)
    
    strategies = [
        "fakeddisorder,split_pos:10,fooling:badsum",
        "fakeddisorder,split_pos:76,overlap_size:336,fooling:badsum",
        "fakeddisorder,split_pos:5,overlap_size:10,fake_ttl:1,fooling:badsum,md5sig"
    ]
    
    results = []
    
    for i, strategy in enumerate(strategies, 1):
        print(f"\n📋 Стратегия {i}: {strategy}")
        
        cmd = [
            "python", "simple_bypass_test.py",
            "--strategy", strategy,
            "--target", "api.x.com",
            "--timeout", "8"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=12,
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            
            success = result.returncode == 0
            has_badsum = "csum_fake_bad" in result.stdout and "true" in result.stdout.lower()
            
            results.append({
                "strategy": strategy,
                "success": success,
                "badsum_works": has_badsum
            })
            
            print(f"  Результат: {'✅' if success else '❌'}")
            print(f"  Badsum: {'✅' if has_badsum else '❌'}")
            
        except Exception as e:
            print(f"  ❌ Ошибка: {e}")
            results.append({
                "strategy": strategy,
                "success": False,
                "badsum_works": False
            })
    
    print(f"\n📊 СВОДКА РЕЗУЛЬТАТОВ:")
    working_badsum = 0
    for result in results:
        status = "✅" if result["badsum_works"] else "❌"
        print(f"  {status} {result['strategy'][:50]}...")
        if result["badsum_works"]:
            working_badsum += 1
    
    print(f"\n🎯 ИТОГО:")
    print(f"  Стратегий с работающим badsum: {working_badsum}/{len(strategies)}")
    
    return working_badsum > 0

if __name__ == "__main__":
    try:
        print("🔍 ТЕСТИРОВАНИЕ ИСПРАВЛЕНИЯ BADSUM")
        print("=" * 40)
        
        # Основной тест
        main_result = test_badsum_fix()
        
        # Дополнительные тесты
        multi_result = test_multiple_strategies()
        
        print(f"\n🏁 ФИНАЛЬНЫЙ РЕЗУЛЬТАТ:")
        if main_result or multi_result:
            print("✅ ИСПРАВЛЕНИЕ BADSUM РАБОТАЕТ!")
            print("✅ Проблема решена")
        else:
            print("❌ ИСПРАВЛЕНИЕ НЕ РАБОТАЕТ")
            print("❌ Нужна дополнительная диагностика")
        
        sys.exit(0 if (main_result or multi_result) else 1)
        
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)