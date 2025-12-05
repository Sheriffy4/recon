#!/usr/bin/env python3
"""
Улучшенный генератор стратегий на основе анализа неудач
"""

import json
import sys
import os
from pathlib import Path

# Добавляем путь к core модулям
sys.path.insert(0, str(Path(__file__).parent / "core"))

def analyze_failure_patterns():
    """Анализ паттернов неудач из предыдущих тестов"""
    try:
        with open("strategy_failure_analysis.json", "r", encoding="utf-8") as f:
            analysis = json.load(f)
        
        patterns = {
            'rst_detected': analysis.get('total_rst_packets', 0) > 0,
            'tls_handshake_issues': False,
            'connection_drops': analysis.get('problematic_flows', 0) > 0,
            'aggressive_dpi': analysis.get('diagnosis') == 'DPI_BLOCKING_DETECTED'
        }
        
        # Анализ TLS handshake проблем
        for flow_name, flow_analysis in analysis.get('connection_analysis', {}).items():
            if flow_analysis.get('client_hello') and not flow_analysis.get('server_hello'):
                patterns['tls_handshake_issues'] = True
        
        return patterns
    except FileNotFoundError:
        return {
            'rst_detected': False,
            'tls_handshake_issues': False, 
            'connection_drops': False,
            'aggressive_dpi': False
        }

def generate_anti_rst_strategies():
    """Генерация стратегий против RST атак"""
    strategies = [
        # Агрессивная фрагментация
        "--dpi-desync=split --dpi-desync-split-pos=1 --dpi-desync-ttl=1",
        "--dpi-desync=split --dpi-desync-split-pos=2 --dpi-desync-ttl=2", 
        "--dpi-desync=split --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
        
        # Множественная фрагментация
        "--dpi-desync=multisplit --dpi-desync-split-pos=1,2 --dpi-desync-ttl=1",
        "--dpi-desync=multisplit --dpi-desync-split-pos=2,3 --dpi-desync-ttl=2",
        
        # Fake пакеты с низким TTL
        "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fake-tls=0x16030100",
        "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fake-tls=0x16030300",
        
        # Комбинированные атаки
        "--dpi-desync=fake,split --dpi-desync-ttl=1 --dpi-desync-split-pos=1",
        "--dpi-desync=fake,multisplit --dpi-desync-ttl=2 --dpi-desync-split-pos=1,2",
        
        # Disorder атаки
        "--dpi-desync=disorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1",
        "--dpi-desync=disorder2 --dpi-desync-split-pos=2 --dpi-desync-ttl=2",
        
        # Продвинутые техники
        "--dpi-desync=seqovl --dpi-desync-split-pos=1 --dpi-desync-ttl=1",
        "--dpi-desync=fakeddisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1",
        
        # Экстремальные стратегии
        "--dpi-desync=split --dpi-desync-split-pos=1 --dpi-desync-ttl=0",
        "--dpi-desync=fake,split,disorder --dpi-desync-ttl=1 --dpi-desync-split-pos=1"
    ]
    
    return strategies

def generate_tls_obfuscation_strategies():
    """Генерация стратегий обфускации TLS"""
    strategies = [
        # TLS record фрагментация
        "--dpi-desync=split --dpi-desync-split-pos=5 --dpi-desync-ttl=4",
        "--dpi-desync=split --dpi-desync-split-pos=6 --dpi-desync-ttl=4",
        
        # SNI обфускация
        "--dpi-desync=split --dpi-desync-split-pos=sni --dpi-desync-ttl=4",
        "--dpi-desync=fake --dpi-desync-fake-tls=sni --dpi-desync-ttl=3",
        
        # Handshake манипуляции
        "--dpi-desync=multisplit --dpi-desync-split-pos=5,10 --dpi-desync-ttl=4",
        "--dpi-desync=fake,split --dpi-desync-split-pos=5 --dpi-desync-ttl=3",
        
        # Продвинутая обфускация
        "--dpi-desync=disorder --dpi-desync-split-pos=sni --dpi-desync-ttl=4",
        "--dpi-desync=fakeddisorder --dpi-desync-split-pos=5 --dpi-desync-ttl=3"
    ]
    
    return strategies

def generate_timing_strategies():
    """Генерация стратегий с тайминг атаками"""
    strategies = [
        # Различные задержки
        "--dpi-desync=split --dpi-desync-split-pos=1 --dpi-desync-ttl=4 --dpi-desync-fooling=md5sig",
        "--dpi-desync=fake --dpi-desync-ttl=3 --dpi-desync-fooling=ts",
        "--dpi-desync=multisplit --dpi-desync-split-pos=1,2 --dpi-desync-fooling=badsum",
        
        # Комбинации с fooling
        "--dpi-desync=fake,split --dpi-desync-ttl=2 --dpi-desync-fooling=badseq",
        "--dpi-desync=disorder --dpi-desync-split-pos=2 --dpi-desync-fooling=md5sig"
    ]
    
    return strategies

def generate_experimental_strategies():
    """Экспериментальные стратегии"""
    strategies = [
        # Экстремально низкие TTL
        "--dpi-desync=split --dpi-desync-split-pos=1 --dpi-desync-ttl=0",
        "--dpi-desync=fake --dpi-desync-ttl=0 --dpi-desync-fake-tls=0x160301",
        
        # Множественные fake пакеты
        "--dpi-desync=fake,fake --dpi-desync-ttl=1,2 --dpi-desync-fake-tls=0x16030100",
        
        # Комплексные комбинации
        "--dpi-desync=fake,split,disorder,multisplit --dpi-desync-ttl=1 --dpi-desync-split-pos=1,2",
        
        # Нестандартные позиции
        "--dpi-desync=split --dpi-desync-split-pos=0 --dpi-desync-ttl=1",
        "--dpi-desync=multisplit --dpi-desync-split-pos=0,1,2 --dpi-desync-ttl=1"
    ]
    
    return strategies

def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "x.com"
    
    print(f"🔧 Генерация улучшенных стратегий для {domain}")
    print("=" * 60)
    
    # Анализ паттернов неудач
    patterns = analyze_failure_patterns()
    
    print("📊 Анализ предыдущих неудач:")
    for pattern, detected in patterns.items():
        status = "✅ Обнаружено" if detected else "❌ Не обнаружено"
        print(f"   {pattern}: {status}")
    
    # Генерация стратегий на основе анализа
    all_strategies = []
    
    if patterns['rst_detected'] or patterns['aggressive_dpi']:
        print("\n🚫 Генерация анти-RST стратегий...")
        anti_rst = generate_anti_rst_strategies()
        all_strategies.extend(anti_rst)
        print(f"   Сгенерировано: {len(anti_rst)} стратегий")
    
    if patterns['tls_handshake_issues']:
        print("\n🔒 Генерация TLS обфускации...")
        tls_obf = generate_tls_obfuscation_strategies()
        all_strategies.extend(tls_obf)
        print(f"   Сгенерировано: {len(tls_obf)} стратегий")
    
    print("\n⏱️ Генерация тайминг стратегий...")
    timing = generate_timing_strategies()
    all_strategies.extend(timing)
    print(f"   Сгенерировано: {len(timing)} стратегий")
    
    print("\n🧪 Генерация экспериментальных стратегий...")
    experimental = generate_experimental_strategies()
    all_strategies.extend(experimental)
    print(f"   Сгенерировано: {len(experimental)} стратегий")
    
    # Удаление дубликатов
    unique_strategies = list(set(all_strategies))
    
    print(f"\n📋 Итого уникальных стратегий: {len(unique_strategies)}")
    
    # Сохранение стратегий
    enhanced_strategies = {
        'domain': domain,
        'generation_timestamp': json.dumps(datetime.now(), default=str),
        'failure_patterns': patterns,
        'strategies': unique_strategies,
        'strategy_count': len(unique_strategies),
        'categories': {
            'anti_rst': len(anti_rst) if patterns['rst_detected'] else 0,
            'tls_obfuscation': len(tls_obf) if patterns['tls_handshake_issues'] else 0,
            'timing': len(timing),
            'experimental': len(experimental)
        }
    }
    
    with open(f"enhanced_strategies_{domain.replace('.', '_')}.json", "w", encoding="utf-8") as f:
        json.dump(enhanced_strategies, f, indent=2, ensure_ascii=False)
    
    print(f"💾 Стратегии сохранены в enhanced_strategies_{domain.replace('.', '_')}.json")
    
    # Создание тестового скрипта
    test_script = f"""#!/usr/bin/env python3
# Автоматический тест улучшенных стратегий для {domain}

import subprocess
import time
import json

strategies = {unique_strategies}

print("🧪 Тестирование {len(unique_strategies)} улучшенных стратегий для {domain}")
print("=" * 60)

results = []

for i, strategy in enumerate(strategies, 1):
    print(f"\\n🔄 Тест {{i}}/{{len(strategies)}}: {{strategy}}")
    
    try:
        # Запуск CLI с стратегией
        cmd = ["python", "cli.py", "--auto", "{domain}"] + strategy.split()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        success = result.returncode == 0 and "SUCCESS" in result.stdout
        
        results.append({{
            'strategy': strategy,
            'success': success,
            'returncode': result.returncode,
            'stdout': result.stdout[:200] if result.stdout else "",
            'stderr': result.stderr[:200] if result.stderr else ""
        }})
        
        status = "✅ УСПЕХ" if success else "❌ НЕУДАЧА"
        print(f"   Результат: {{status}}")
        
        if success:
            print(f"   🎉 НАЙДЕНА РАБОЧАЯ СТРАТЕГИЯ: {{strategy}}")
            break
            
    except subprocess.TimeoutExpired:
        print(f"   ⏰ ТАЙМАУТ")
        results.append({{
            'strategy': strategy,
            'success': False,
            'error': 'timeout'
        }})
    except Exception as e:
        print(f"   ❌ ОШИБКА: {{e}}")
        results.append({{
            'strategy': strategy,
            'success': False,
            'error': str(e)
        }})
    
    time.sleep(2)  # Пауза между тестами

# Сохранение результатов
with open("enhanced_strategy_test_results.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

successful = [r for r in results if r.get('success')]
print(f"\\n📊 Результаты тестирования:")
print(f"   Протестировано: {{len(results)}}")
print(f"   Успешных: {{len(successful)}}")
print(f"   Неудачных: {{len(results) - len(successful)}}")

if successful:
    print(f"\\n🎉 РАБОЧИЕ СТРАТЕГИИ:")
    for result in successful:
        print(f"   ✅ {{result['strategy']}}")
else:
    print(f"\\n😞 Рабочих стратегий не найдено")
"""
    
    with open(f"test_enhanced_strategies_{domain.replace('.', '_')}.py", "w", encoding="utf-8") as f:
        f.write(test_script)
    
    print(f"🧪 Тестовый скрипт создан: test_enhanced_strategies_{domain.replace('.', '_')}.py")
    
    print(f"\n🚀 Для запуска тестирования выполните:")
    print(f"   python test_enhanced_strategies_{domain.replace('.', '_')}.py")

if __name__ == "__main__":
    from datetime import datetime
    main()