#!/usr/bin/env python3
"""
Финальный тест всех исправлений zapret совместимости
"""
import subprocess
import sys
import time
import json

def run_final_test():
    """Запускает финальный тест с анализом результатов."""
    print("🎯 ФИНАЛЬНЫЙ ТЕСТ ZAPRET СОВМЕСТИМОСТИ")
    print("=" * 60)
    
    # Создаем файл с тестовым доменом
    with open("final_test.txt", "w") as f:
        f.write("x.com\n")
    
    print("🚀 Запуск теста...")
    print("-" * 40)
    
    # Запускаем тест
    cmd = [
        sys.executable, "smart_bypass_cli.py",
        "test-file",
        "final_test.txt"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        print("📋 РЕЗУЛЬТАТ ТЕСТА:")
        print(result.stdout)
        
        if result.stderr:
            print("\n🔍 ОТЛАДОЧНАЯ ИНФОРМАЦИЯ:")
            print(result.stderr)
        
        # Анализируем результат
        output = result.stdout + result.stderr
        
        print("\n" + "=" * 60)
        print("📊 АНАЛИЗ ИСПРАВЛЕНИЙ:")
        
        # Проверяем наличие отладочных сообщений
        debug_indicators = [
            ("ZAPRET-COMPATIBLE CONDITIONS DETECTED", "🎯 Zapret-совместимые условия обнаружены"),
            ("ZAPRET-STYLE ACTIVATED", "🚀 Zapret-style режим активирован"),
            ("Sending FULL fake with corrupted checksum", "🎭 Отправка полного fake с испорченной checksum"),
            ("CHECKSUM DEBUG", "🔧 Отладка checksum"),
            ("Created FULL fake ClientHello", "📦 Создание полного ClientHello"),
            ("REAL segment", "🚩 Реальные сегменты"),
            ("PSH|ACK", "✅ PSH|ACK флаги"),
            (".edu", "🎭 Fake SNI с .edu доменом")
        ]
        
        found_count = 0
        for indicator, description in debug_indicators:
            if indicator in output:
                print(f"  ✅ {description}")
                found_count += 1
            else:
                print(f"  ❌ {description}")
        
        print(f"\n📈 Найдено индикаторов: {found_count}/{len(debug_indicators)}")
        
        # Ищем PCAP данные в выводе
        if "metrics" in output:
            print("\n🔍 ПОИСК PCAP МЕТРИК...")
            lines = output.split('\n')
            for line in lines:
                if '"metrics"' in line and '"fake"' in line:
                    try:
                        # Пытаемся извлечь JSON
                        start = line.find('{"flow"')
                        if start != -1:
                            json_str = line[start:]
                            data = json.loads(json_str)
                            analyze_pcap_metrics(data)
                            break
                    except:
                        continue
        
        # Итоговая оценка
        print("\n" + "=" * 60)
        if found_count >= 6:
            print("🎉 ОТЛИЧНО! Большинство исправлений работают")
        elif found_count >= 4:
            print("👍 ХОРОШО! Многие исправления работают")
        elif found_count >= 2:
            print("⚠️  ЧАСТИЧНО! Некоторые исправления работают")
        else:
            print("❌ ПЛОХО! Исправления не работают")
            
    except subprocess.TimeoutExpired:
        print("❌ Тест превысил время ожидания")
    except Exception as e:
        print(f"❌ Ошибка выполнения теста: {e}")

def analyze_pcap_metrics(data):
    """Анализирует метрики из PCAP."""
    print("\n📊 АНАЛИЗ PCAP МЕТРИК:")
    
    metrics = data.get("metrics", {})
    sni = data.get("sni", "")
    
    # Проверяем исправления
    checks = [
        ("SNI fake", sni.endswith(".edu"), f"SNI: {sni}"),
        ("Checksum испорчен", metrics.get("csum_fake_bad", False), f"csum_fake_bad: {metrics.get('csum_fake_bad')}"),
        ("PSH флаги", metrics.get("flags_real_psh", False), f"flags_real_psh: {metrics.get('flags_real_psh')}"),
        ("Быстрый timing", metrics.get("pair_dt_ms", 999) < 1.0, f"timing: {metrics.get('pair_dt_ms', 'N/A')}ms"),
        ("Большой fake пакет", metrics.get("fake", {}).get("len", 0) > 200, f"fake size: {metrics.get('fake', {}).get('len', 'N/A')} bytes"),
        ("Правильный TTL", metrics.get("fake", {}).get("ttl") == 3, f"fake TTL: {metrics.get('fake', {}).get('ttl', 'N/A')}")
    ]
    
    fixed_count = 0
    for name, condition, details in checks:
        if condition:
            print(f"  ✅ {name}: {details}")
            fixed_count += 1
        else:
            print(f"  ❌ {name}: {details}")
    
    print(f"\n📈 Исправлено проблем: {fixed_count}/{len(checks)}")
    
    if fixed_count == len(checks):
        print("🎉 ВСЕ ПРОБЛЕМЫ ИСПРАВЛЕНЫ!")
    elif fixed_count >= 4:
        print("👍 БОЛЬШИНСТВО ПРОБЛЕМ ИСПРАВЛЕНО!")
    else:
        print("⚠️  ТРЕБУЮТСЯ ДОПОЛНИТЕЛЬНЫЕ ИСПРАВЛЕНИЯ")

if __name__ == "__main__":
    run_final_test()