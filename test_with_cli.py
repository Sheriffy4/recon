#!/usr/bin/env python3
"""
Тест с правильным CLI (cli.py)
"""
import subprocess
import sys
import time
import json

def run_test_with_cli():
    """Запускает тест с cli.py."""
    print("🎯 ТЕСТ С ПРАВИЛЬНЫМ CLI (cli.py)")
    print("=" * 50)
    
    # Создаем файл с заблокированным доменом
    with open("x_com_test.txt", "w") as f:
        f.write("x.com\n")
    
    print("🚀 Запуск теста с cli.py...")
    print("-" * 40)
    
    # Запускаем тест с cli.py (используем флаг -d для файла с доменами)
    cmd = [sys.executable, "cli.py", "-d", "x_com_test.txt"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        
        print("📋 РЕЗУЛЬТАТ ТЕСТА:")
        print(result.stdout)
        
        if result.stderr:
            print("\n🔍 ОТЛАДОЧНАЯ ИНФОРМАЦИЯ:")
            print(result.stderr)
        
        # Анализируем результат
        output = result.stdout + result.stderr
        
        print("\n" + "=" * 50)
        print("📊 АНАЛИЗ ZAPRET ИСПРАВЛЕНИЙ:")
        
        # Проверяем наличие отладочных сообщений
        zapret_indicators = [
            ("ZAPRET-COMPATIBLE CONDITIONS DETECTED", "🎯 Zapret-совместимые условия"),
            ("ZAPRET-STYLE ACTIVATED", "🚀 Zapret-style режим"),
            ("Sending FULL fake with corrupted checksum", "🎭 Полный fake с испорченной checksum"),
            ("CHECKSUM DEBUG", "🔧 Отладка checksum"),
            ("Created FULL fake ClientHello", "📦 Полный ClientHello"),
            ("REAL segment", "🚩 Реальные сегменты"),
            ("PSH|ACK", "✅ PSH|ACK флаги"),
            (".edu", "🎭 Fake SNI с .edu")
        ]
        
        found_count = 0
        for indicator, description in zapret_indicators:
            if indicator in output:
                print(f"  ✅ {description}")
                found_count += 1
            else:
                print(f"  ❌ {description}")
        
        print(f"\n📈 Найдено zapret индикаторов: {found_count}/{len(zapret_indicators)}")
        
        # Ищем PCAP данные
        if "flow" in output and "metrics" in output:
            print("\n🔍 ПОИСК PCAP МЕТРИК...")
            lines = output.split('\n')
            for line in lines:
                if '"flow"' in line and '"metrics"' in line:
                    try:
                        # Пытаемся найти JSON
                        start = line.find('{"flow"')
                        if start != -1:
                            json_str = line[start:]
                            # Убираем лишнее после JSON
                            end = json_str.find('}\n')
                            if end == -1:
                                end = json_str.rfind('}')
                            if end != -1:
                                json_str = json_str[:end+1]
                            data = json.loads(json_str)
                            analyze_pcap_metrics(data)
                            break
                    except Exception as e:
                        print(f"Ошибка парсинга JSON: {e}")
                        continue
        
        # Итоговая оценка
        print("\n" + "=" * 50)
        if found_count >= 6:
            print("🎉 ОТЛИЧНО! Большинство zapret исправлений работают")
        elif found_count >= 4:
            print("👍 ХОРОШО! Многие zapret исправления работают")
        elif found_count >= 2:
            print("⚠️  ЧАСТИЧНО! Некоторые zapret исправления работают")
        else:
            print("❌ ПЛОХО! Zapret исправления не работают")
            
        return found_count
            
    except subprocess.TimeoutExpired:
        print("❌ Тест превысил время ожидания")
        return 0
    except Exception as e:
        print(f"❌ Ошибка выполнения теста: {e}")
        return 0

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
    
    print(f"\n📈 Исправлено PCAP проблем: {fixed_count}/{len(checks)}")
    
    if fixed_count == len(checks):
        print("🎉 ВСЕ PCAP ПРОБЛЕМЫ ИСПРАВЛЕНЫ!")
    elif fixed_count >= 4:
        print("👍 БОЛЬШИНСТВО PCAP ПРОБЛЕМ ИСПРАВЛЕНО!")
    else:
        print("⚠️  ТРЕБУЮТСЯ ДОПОЛНИТЕЛЬНЫЕ ИСПРАВЛЕНИЯ")

if __name__ == "__main__":
    run_test_with_cli()