#!/usr/bin/env python3
"""
Агрессивный тестер стратегий с экстремальными параметрами
"""

import subprocess
import time
import json
import sys
from pathlib import Path

def generate_aggressive_strategies():
    """Генерация экстремально агрессивных стратегий"""
    strategies = [
        # Экстремально низкие TTL
        "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fake-tls=0x16030100",
        "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fake-tls=0x16030300", 
        "--dpi-desync=fake --dpi-desync-ttl=0 --dpi-desync-fake-tls=0x16030100",
        
        # Агрессивная фрагментация
        "--dpi-desync=split --dpi-desync-split-pos=1 --dpi-desync-ttl=1",
        "--dpi-desync=split --dpi-desync-split-pos=2 --dpi-desync-ttl=1",
        "--dpi-desync=split --dpi-desync-split-pos=3 --dpi-desync-ttl=1",
        
        # Множественная фрагментация с низким TTL
        "--dpi-desync=multisplit --dpi-desync-split-pos=1,2,3 --dpi-desync-ttl=1",
        "--dpi-desync=multisplit --dpi-desync-split-pos=1,2 --dpi-desync-ttl=0",
        
        # Комбинированные атаки с экстремальными параметрами
        "--dpi-desync=fake,split --dpi-desync-ttl=1 --dpi-desync-split-pos=1",
        "--dpi-desync=fake,multisplit --dpi-desync-ttl=1 --dpi-desync-split-pos=1,2",
        "--dpi-desync=fake,disorder --dpi-desync-ttl=1 --dpi-desync-split-pos=1",
        
        # Disorder с низким TTL
        "--dpi-desync=disorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1",
        "--dpi-desync=disorder2 --dpi-desync-split-pos=1 --dpi-desync-ttl=1",
        "--dpi-desync=fakeddisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1",
        
        # Продвинутые техники
        "--dpi-desync=seqovl --dpi-desync-split-pos=1 --dpi-desync-ttl=1",
        "--dpi-desync=seqovl --dpi-desync-split-pos=2 --dpi-desync-ttl=0",
        
        # Экспериментальные комбинации
        "--dpi-desync=fake,split,disorder --dpi-desync-ttl=1 --dpi-desync-split-pos=1",
        "--dpi-desync=fake,multisplit,disorder --dpi-desync-ttl=1 --dpi-desync-split-pos=1,2",
        
        # Специальные позиции фрагментации
        "--dpi-desync=split --dpi-desync-split-pos=sni --dpi-desync-ttl=1",
        "--dpi-desync=multisplit --dpi-desync-split-pos=sni,5 --dpi-desync-ttl=1",
        
        # Fooling техники с низким TTL
        "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
        "--dpi-desync=split --dpi-desync-split-pos=1 --dpi-desync-ttl=1 --dpi-desync-fooling=md5sig",
        "--dpi-desync=multisplit --dpi-desync-split-pos=1,2 --dpi-desync-ttl=1 --dpi-desync-fooling=ts",
        
        # Экстремальные стратегии
        "--dpi-desync=fake,fake,fake --dpi-desync-ttl=1,2,3 --dpi-desync-fake-tls=0x16030100",
        "--dpi-desync=split,split --dpi-desync-split-pos=1,2 --dpi-desync-ttl=1",
    ]
    
    return strategies

def test_single_strategy(strategy, domain, timeout=15):
    """Тест одной стратегии с детальным логированием"""
    print(f"🧪 Тестирование: {strategy}")
    
    try:
        # Запуск CLI с стратегией
        cmd = ["python", "cli.py", "--auto", domain] + strategy.split()
        
        print(f"   Команда: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout,
            cwd="."
        )
        
        # Анализ результата
        success = result.returncode == 0
        
        # Поиск индикаторов успеха в выводе
        stdout_lower = result.stdout.lower() if result.stdout else ""
        stderr_lower = result.stderr.lower() if result.stderr else ""
        
        success_indicators = [
            "success", "successful", "работает", "найдена", 
            "effective", "bypass", "обход"
        ]
        
        failure_indicators = [
            "failed", "error", "неудача", "блокировка", 
            "timeout", "connection refused", "rst"
        ]
        
        has_success_indicator = any(indicator in stdout_lower for indicator in success_indicators)
        has_failure_indicator = any(indicator in stderr_lower or indicator in stdout_lower for indicator in failure_indicators)
        
        # Финальная оценка
        if success and has_success_indicator and not has_failure_indicator:
            final_result = "SUCCESS"
        elif success and not has_failure_indicator:
            final_result = "PARTIAL_SUCCESS"
        else:
            final_result = "FAILURE"
        
        print(f"   Код возврата: {result.returncode}")
        print(f"   Результат: {final_result}")
        
        if result.stdout:
            stdout_preview = result.stdout[:200].replace('\n', ' ')
            print(f"   Stdout: {stdout_preview}...")
        
        if result.stderr:
            stderr_preview = result.stderr[:200].replace('\n', ' ')
            print(f"   Stderr: {stderr_preview}...")
        
        return {
            'strategy': strategy,
            'result': final_result,
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'success_indicators': has_success_indicator,
            'failure_indicators': has_failure_indicator
        }
        
    except subprocess.TimeoutExpired:
        print(f"   ⏰ ТАЙМАУТ ({timeout}s)")
        return {
            'strategy': strategy,
            'result': 'TIMEOUT',
            'error': f'timeout after {timeout}s'
        }
    except Exception as e:
        print(f"   ❌ ОШИБКА: {e}")
        return {
            'strategy': strategy,
            'result': 'ERROR',
            'error': str(e)
        }

def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "x.com"
    
    print(f"🚀 Агрессивное тестирование стратегий для {domain}")
    print("=" * 60)
    
    strategies = generate_aggressive_strategies()
    
    print(f"📋 Будет протестировано {len(strategies)} агрессивных стратегий")
    print(f"⏱️  Таймаут на стратегию: 15 секунд")
    print(f"🎯 Цель: найти хотя бы одну рабочую стратегию")
    
    results = []
    successful_strategies = []
    
    for i, strategy in enumerate(strategies, 1):
        print(f"\n🔄 Тест {i}/{len(strategies)}")
        
        result = test_single_strategy(strategy, domain)
        results.append(result)
        
        if result['result'] in ['SUCCESS', 'PARTIAL_SUCCESS']:
            successful_strategies.append(result)
            print(f"   🎉 НАЙДЕНА РАБОЧАЯ СТРАТЕГИЯ!")
            
            # Если нашли полностью успешную стратегию, можно остановиться
            if result['result'] == 'SUCCESS':
                print(f"   ✅ Полный успех! Останавливаем тестирование.")
                break
        
        # Пауза между тестами
        time.sleep(1)
    
    # Анализ результатов
    print(f"\n📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ:")
    print(f"   Протестировано: {len(results)}")
    
    success_count = len([r for r in results if r['result'] == 'SUCCESS'])
    partial_count = len([r for r in results if r['result'] == 'PARTIAL_SUCCESS'])
    failure_count = len([r for r in results if r['result'] == 'FAILURE'])
    timeout_count = len([r for r in results if r['result'] == 'TIMEOUT'])
    error_count = len([r for r in results if r['result'] == 'ERROR'])
    
    print(f"   ✅ Успешных: {success_count}")
    print(f"   🟡 Частично успешных: {partial_count}")
    print(f"   ❌ Неудачных: {failure_count}")
    print(f"   ⏰ Таймаутов: {timeout_count}")
    print(f"   💥 Ошибок: {error_count}")
    
    if successful_strategies:
        print(f"\n🎉 НАЙДЕННЫЕ РАБОЧИЕ СТРАТЕГИИ:")
        for i, strategy in enumerate(successful_strategies, 1):
            result_icon = "✅" if strategy['result'] == 'SUCCESS' else "🟡"
            print(f"   {result_icon} {i}. {strategy['strategy']}")
            print(f"      Результат: {strategy['result']}")
    else:
        print(f"\n😞 Рабочих стратегий не найдено")
        
        print(f"\n🔍 АНАЛИЗ НЕУДАЧ:")
        
        # Анализ частых ошибок
        error_patterns = {}
        for result in results:
            if result['result'] in ['FAILURE', 'ERROR']:
                stderr = result.get('stderr', '')
                stdout = result.get('stdout', '')
                
                # Поиск паттернов ошибок
                if 'connection refused' in stderr.lower() or 'connection refused' in stdout.lower():
                    error_patterns['connection_refused'] = error_patterns.get('connection_refused', 0) + 1
                elif 'timeout' in stderr.lower() or 'timeout' in stdout.lower():
                    error_patterns['timeout'] = error_patterns.get('timeout', 0) + 1
                elif 'rst' in stderr.lower() or 'rst' in stdout.lower():
                    error_patterns['rst_detected'] = error_patterns.get('rst_detected', 0) + 1
                elif 'blocked' in stderr.lower() or 'blocked' in stdout.lower():
                    error_patterns['blocked'] = error_patterns.get('blocked', 0) + 1
                else:
                    error_patterns['other'] = error_patterns.get('other', 0) + 1
        
        print(f"   Паттерны ошибок:")
        for pattern, count in error_patterns.items():
            print(f"     {pattern}: {count} раз")
    
    # Рекомендации
    print(f"\n💡 РЕКОМЕНДАЦИИ:")
    
    if successful_strategies:
        print(f"   ✅ Используйте найденные рабочие стратегии")
        print(f"   🔧 Можно оптимизировать параметры успешных стратегий")
    else:
        print(f"   🔧 Попробуйте:")
        print(f"     1. Еще более низкие TTL (0)")
        print(f"     2. Другие домены для тестирования")
        print(f"     3. Проверить работу WinDivert")
        print(f"     4. Использовать туннелирование")
        print(f"     5. Проверить, не блокируется ли весь HTTPS трафик")
    
    # Сохранение результатов
    final_results = {
        'domain': domain,
        'total_tested': len(results),
        'successful_count': len(successful_strategies),
        'results': results,
        'successful_strategies': successful_strategies,
        'statistics': {
            'success': success_count,
            'partial_success': partial_count,
            'failure': failure_count,
            'timeout': timeout_count,
            'error': error_count
        }
    }
    
    output_file = f"aggressive_test_results_{domain.replace('.', '_')}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(final_results, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 Результаты сохранены в {output_file}")
    
    # Создание скрипта для применения успешной стратегии
    if successful_strategies:
        best_strategy = successful_strategies[0]  # Берем первую успешную
        
        apply_script = f"""#!/usr/bin/env python3
# Применение найденной рабочей стратегии для {domain}

import subprocess
import sys

WORKING_STRATEGY = "{best_strategy['strategy']}"
DOMAIN = "{domain}"

def apply_strategy():
    print(f"🚀 Применение рабочей стратегии для {{DOMAIN}}")
    print(f"📋 Стратегия: {{WORKING_STRATEGY}}")
    
    cmd = ["python", "cli.py", "--auto", DOMAIN] + WORKING_STRATEGY.split()
    
    try:
        result = subprocess.run(cmd, check=True)
        print("✅ Стратегия применена успешно!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Ошибка применения: {{e}}")
    except KeyboardInterrupt:
        print("\\n⏹️  Остановлено пользователем")

if __name__ == "__main__":
    apply_strategy()
"""
        
        script_file = f"apply_working_strategy_{domain.replace('.', '_')}.py"
        with open(script_file, "w", encoding="utf-8") as f:
            f.write(apply_script)
        
        print(f"🎯 Создан скрипт применения: {script_file}")
        print(f"   Запустите: python {script_file}")

if __name__ == "__main__":
    main()