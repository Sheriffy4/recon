#!/usr/bin/env python3
"""
Тест критических исправлений
"""
import subprocess
import sys
import time
import json

def run_critical_test():
    """Запускает тест критических исправлений."""
    print("🚨 ТЕСТ КРИТИЧЕСКИХ ИСПРАВЛЕНИЙ")
    print("=" * 50)
    
    # Создаем файл с одним заблокированным доменом
    with open("critical_test.txt", "w") as f:
        f.write("x.com\n")
    
    print("🚀 Запуск теста с исправлениями...")
    print("-" * 40)
    
    # Запускаем тест с ограниченным временем
    cmd = [sys.executable, "cli.py", "-d", "critical_test.txt", "-c", "1"]
    
    try:
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        end_time = time.time()
        
        print(f"⏱️  Время выполнения: {end_time - start_time:.1f}s")
        
        # Анализируем результат
        output = result.stdout + result.stderr
        
        print("\n📊 АНАЛИЗ КРИТИЧЕСКИХ ИСПРАВЛЕНИЙ:")
        
        # Проверяем checksum исправления
        checksum_indicators = [
            ("recalculate_checksum=False", "🔧 Попытка отключить пересчет checksum"),
            ("RAW SEND SUCCESS", "🎯 Успешная raw отправка"),
            ("SENT with recalculate_checksum=False", "✅ Отправка без пересчета checksum"),
            ("FINAL FALLBACK", "❌ Fallback отправка (плохо)")
        ]
        
        checksum_fixed = False
        for indicator, description in checksum_indicators:
            if indicator in output:
                print(f"  {description}")
                if "SUCCESS" in indicator or "recalculate_checksum=False" in indicator:
                    checksum_fixed = True
        
        # Проверяем timing
        timing_lines = []
        for line in output.split('\n'):
            if "pair_dt_ms" in line:
                timing_lines.append(line)
        
        if timing_lines:
            print(f"\n⏱️  TIMING АНАЛИЗ:")
            for line in timing_lines[-3:]:  # Последние 3 записи
                if "pair_dt_ms" in line:
                    try:
                        start = line.find('"pair_dt_ms":') + 13
                        end = line.find(',', start)
                        if end == -1:
                            end = line.find('}', start)
                        timing_str = line[start:end].strip()
                        timing = float(timing_str)
                        
                        if timing < 0.5:
                            print(f"  ✅ Хороший timing: {timing:.2f}ms")
                        elif timing < 1.0:
                            print(f"  ⚠️  Средний timing: {timing:.2f}ms")
                        else:
                            print(f"  ❌ Медленный timing: {timing:.2f}ms")
                    except:
                        print(f"  📊 Timing данные: {line}")
        
        # Проверяем успешность обхода
        success_indicators = [
            ("работают", "Количество работающих сайтов"),
            ("Success rate", "Процент успеха"),
            ("NO_SITES_WORKING", "❌ Ни один сайт не работает")
        ]
        
        sites_working = False
        for indicator, description in success_indicators:
            if indicator in output:
                if "NO_SITES_WORKING" in indicator:
                    print(f"  ❌ {description}")
                else:
                    # Ищем количество работающих сайтов
                    lines = output.split('\n')
                    for line in lines:
                        if "работают" in line:
                            if "0/" not in line:
                                sites_working = True
                                print(f"  ✅ {line.strip()}")
                            else:
                                print(f"  ❌ {line.strip()}")
        
        # Ищем PCAP данные
        pcap_found = False
        if '"csum_fake_bad"' in output:
            pcap_found = True
            print(f"\n📊 PCAP АНАЛИЗ:")
            lines = output.split('\n')
            for line in lines:
                if '"csum_fake_bad"' in line:
                    try:
                        start = line.find('{"flow"')
                        if start != -1:
                            json_str = line[start:]
                            end = json_str.rfind('}')
                            if end != -1:
                                json_str = json_str[:end+1]
                            data = json.loads(json_str)
                            
                            csum_bad = data.get("metrics", {}).get("csum_fake_bad", False)
                            timing = data.get("metrics", {}).get("pair_dt_ms", 999)
                            sni = data.get("sni", "")
                            
                            print(f"  Checksum испорчен: {'✅' if csum_bad else '❌'} {csum_bad}")
                            print(f"  Timing: {'✅' if timing < 0.5 else '❌'} {timing:.2f}ms")
                            print(f"  Fake SNI: {'✅' if sni.endswith('.edu') else '❌'} {sni}")
                            break
                    except Exception as e:
                        print(f"  Ошибка парсинга PCAP: {e}")
        
        # Итоговая оценка
        print("\n" + "=" * 50)
        print("🎯 ИТОГОВАЯ ОЦЕНКА:")
        
        if checksum_fixed:
            print("✅ Checksum исправления применены")
        else:
            print("❌ Checksum исправления не работают")
            
        if sites_working:
            print("🎉 УСПЕХ: Сайты открываются!")
        else:
            print("❌ ПРОВАЛ: Сайты не открываются")
            
        if pcap_found:
            print("📊 PCAP данные найдены для анализа")
        else:
            print("❌ PCAP данные не найдены")
            
    except subprocess.TimeoutExpired:
        print("❌ Тест превысил время ожидания")
    except Exception as e:
        print(f"❌ Ошибка выполнения теста: {e}")

if __name__ == "__main__":
    run_critical_test()