#!/usr/bin/env python3
"""
Тест исправления парсера стратегий
Проверяет что split и disorder теперь работают
"""
import subprocess
import sys

def run_test(strategy, pcap_name):
    """Запускает тест стратегии"""
    print(f"\n{'='*80}")
    print(f"🧪 ТЕСТ: {strategy}")
    print(f"{'='*80}\n")
    
    cmd = [
        sys.executable,
        "cli.py",
        "x.com",
        "--strategy",
        strategy,
        "--pcap",
        pcap_name
    ]
    
    print(f"Команда: {' '.join(cmd)}\n")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        output = result.stdout + result.stderr
        
        # Проверяем результаты
        checks = {
            "Парсинг успешен": "[OK] Parsed strategy:" in output,
            "Bypass активирован": "APPLY_BYPASS CALLED" in output,
            "Пакеты отправлены": "📤 REAL" in output or "REAL [" in output,
            "НЕТ ошибки 'Неизвестный тип'": "Неизвестный или неподдерживаемый тип" not in output,
            "НЕТ ошибки парсинга": "No valid DPI methods found" not in output
        }
        
        print("📊 РЕЗУЛЬТАТЫ ПРОВЕРОК:")
        print("-" * 80)
        all_passed = True
        for check, passed in checks.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"{status} - {check}")
            if not passed:
                all_passed = False
        
        print("-" * 80)
        
        if all_passed:
            print(f"\n✅ ТЕСТ ПРОЙДЕН: {strategy}")
        else:
            print(f"\n❌ ТЕСТ ПРОВАЛЕН: {strategy}")
            print("\n📝 ВЫВОД:")
            print(output[:2000])  # Первые 2000 символов
        
        return all_passed
        
    except subprocess.TimeoutExpired:
        print(f"❌ TIMEOUT: Тест превысил 60 секунд")
        return False
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        return False

def main():
    """Запускает все тесты"""
    print("="*80)
    print("🚀 ТЕСТИРОВАНИЕ ИСПРАВЛЕНИЯ ПАРСЕРА СТРАТЕГИЙ")
    print("="*80)
    
    tests = [
        ("--dpi-desync=split --dpi-desync-split-pos=3", "test_split_3_fixed.pcap"),
        ("--dpi-desync=split --dpi-desync-split-pos=5", "test_split_5_fixed.pcap"),
        ("--dpi-desync=disorder --dpi-desync-split-pos=3", "test_disorder_3_fixed.pcap"),
        ("--dpi-desync=disorder --dpi-desync-split-pos=5", "test_disorder_5_fixed.pcap"),
    ]
    
    results = []
    for strategy, pcap in tests:
        passed = run_test(strategy, pcap)
        results.append((strategy, passed))
    
    # Итоговый отчет
    print("\n" + "="*80)
    print("📊 ИТОГОВЫЙ ОТЧЕТ")
    print("="*80)
    
    passed_count = sum(1 for _, passed in results if passed)
    total_count = len(results)
    
    for strategy, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {strategy}")
    
    print("-" * 80)
    print(f"Пройдено: {passed_count}/{total_count}")
    
    if passed_count == total_count:
        print("\n🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
        print("✅ Исправление парсера работает!")
        return 0
    else:
        print(f"\n❌ ПРОВАЛЕНО {total_count - passed_count} ТЕСТОВ")
        print("⚠️ Исправление парсера НЕ работает полностью")
        return 1

if __name__ == "__main__":
    sys.exit(main())
