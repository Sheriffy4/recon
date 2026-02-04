#!/usr/bin/env python3
"""
Автоматизированная проверка корректности атак для списка доменов
Адаптирована под реальные CLI и simple_service.py
"""

import subprocess
import json
import time
import os
from pathlib import Path
from datetime import datetime

def create_directories():
    """Создаем необходимые директории"""
    dirs = ['logs', 'reports', 'temp']
    for dir_name in dirs:
        Path(dir_name).mkdir(exist_ok=True)

def test_domain_with_discovery(domain, timeout=120):
    """
    Тестирует домен через discovery mode (auto)
    """
    print(f"  🔍 Discovery mode для {domain}...")
    
    log_file = f"logs/{domain}_discovery.log"
    
    try:
        with open(log_file, 'w', encoding='utf-8') as f:
            process = subprocess.Popen([
                'python', 'cli.py', 'auto', domain
            ], stdout=f, stderr=subprocess.STDOUT, text=True)
            
            try:
                process.wait(timeout=timeout)
                success = process.returncode == 0
            except subprocess.TimeoutExpired:
                process.kill()
                success = False
                print(f"    ⚠️  Таймаут {timeout}с")
        
        # Проверяем размер лога
        log_size = os.path.getsize(log_file) if os.path.exists(log_file) else 0
        
        return {
            'success': success and log_size > 100,
            'log_file': log_file,
            'log_size': log_size
        }
        
    except Exception as e:
        print(f"    ❌ Ошибка: {e}")
        return {'success': False, 'error': str(e)}

def test_domain_with_service(domain, timeout=60):
    """
    Тестирует домен через service mode
    """
    print(f"  🔧 Service mode для {domain}...")
    
    log_file = f"logs/{domain}_service.log"
    
    try:
        # Запускаем service в фоне
        with open(log_file, 'w', encoding='utf-8') as f:
            service_process = subprocess.Popen([
                'python', 'simple_service.py'
            ], stdout=f, stderr=subprocess.STDOUT, text=True)
        
        # Даем время на запуск
        time.sleep(3)
        
        # Тестируем подключение к домену
        test_success = False
        try:
            test_result = subprocess.run([
                'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                '--connect-timeout', '10',
                '--max-time', str(timeout),
                f'https://{domain}'
            ], capture_output=True, text=True, timeout=timeout)
            
            test_success = test_result.returncode == 0
            
        except:
            test_success = False
        
        # Останавливаем service
        try:
            service_process.terminate()
            service_process.wait(timeout=5)
        except:
            service_process.kill()
        
        # Проверяем размер лога
        log_size = os.path.getsize(log_file) if os.path.exists(log_file) else 0
        
        return {
            'success': test_success and log_size > 50,
            'log_file': log_file,
            'log_size': log_size
        }
        
    except Exception as e:
        print(f"    ❌ Ошибка: {e}")
        return {'success': False, 'error': str(e)}

def analyze_domain_logs(domain, discovery_result, service_result):
    """
    Анализирует логи домена с помощью attack parity CLI
    """
    print(f"  📊 Анализ логов для {domain}...")
    
    analysis_results = {}
    
    # Анализ discovery логов
    if discovery_result.get('success') and 'log_file' in discovery_result:
        try:
            result = subprocess.run([
                'python', '-m', 'core.attack_parity.cli', 'correlate',
                '--log', discovery_result['log_file'],
                '--mode', 'discovery',
                '--output', f'reports/{domain}_discovery_analysis.json'
            ], capture_output=True, text=True, timeout=60)
            
            analysis_results['discovery_analysis'] = result.returncode == 0
            
        except Exception as e:
            analysis_results['discovery_analysis'] = False
            analysis_results['discovery_error'] = str(e)
    
    # Анализ service логов
    if service_result.get('success') and 'log_file' in service_result:
        try:
            result = subprocess.run([
                'python', '-m', 'core.attack_parity.cli', 'correlate',
                '--log', service_result['log_file'],
                '--mode', 'service', 
                '--output', f'reports/{domain}_service_analysis.json'
            ], capture_output=True, text=True, timeout=60)
            
            analysis_results['service_analysis'] = result.returncode == 0
            
        except Exception as e:
            analysis_results['service_analysis'] = False
            analysis_results['service_error'] = str(e)
    
    return analysis_results

def run_comprehensive_validation(domains_list):
    """
    Комплексная проверка списка доменов
    """
    print(f"\n🚀 Автоматизированная проверка {len(domains_list)} доменов")
    print("=" * 60)
    
    create_directories()
    results = {}
    
    for i, domain in enumerate(domains_list, 1):
        print(f"\n[{i}/{len(domains_list)}] Проверка {domain}")
        print("-" * 40)
        
        domain_result = {
            'timestamp': datetime.now().isoformat(),
            'domain': domain
        }
        
        try:
            # Тестируем discovery mode
            discovery_result = test_domain_with_discovery(domain)
            domain_result['discovery'] = discovery_result
            
            # Тестируем service mode
            service_result = test_domain_with_service(domain)
            domain_result['service'] = service_result
            
            # Анализируем логи
            analysis_result = analyze_domain_logs(domain, discovery_result, service_result)
            domain_result['analysis'] = analysis_result
            
            # Определяем общий статус
            discovery_ok = discovery_result.get('success', False)
            service_ok = service_result.get('success', False)
            analysis_ok = any(analysis_result.values()) if analysis_result else False
            
            if discovery_ok and service_ok:
                status = "SUCCESS"
                print(f"  ✅ Полный успех")
            elif discovery_ok or service_ok:
                status = "PARTIAL"
                print(f"  ⚠️  Частичный успех")
            else:
                status = "FAILED"
                print(f"  ❌ Неудача")
            
            domain_result['status'] = status
            results[domain] = domain_result
            
        except Exception as e:
            domain_result['status'] = "ERROR"
            domain_result['error'] = str(e)
            results[domain] = domain_result
            print(f"  ❌ Критическая ошибка: {e}")
    
    # Сохраняем детальный отчет
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    detailed_report_path = f"reports/detailed_validation_{timestamp}.json"
    
    with open(detailed_report_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Создаем краткую сводку
    summary = {
        'timestamp': timestamp,
        'total_domains': len(domains_list),
        'results_summary': {},
        'detailed_report': detailed_report_path
    }
    
    for domain, result in results.items():
        status = result.get('status', 'UNKNOWN')
        if status not in summary['results_summary']:
            summary['results_summary'][status] = []
        summary['results_summary'][status].append(domain)
    
    summary_report_path = f"reports/validation_summary_{timestamp}.json"
    with open(summary_report_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    # Выводим итоговую статистику
    print(f"\n📊 ИТОГОВАЯ СТАТИСТИКА")
    print("=" * 60)
    
    for status, domains in summary['results_summary'].items():
        count = len(domains)
        percentage = count / len(domains_list) * 100
        print(f"{status:>8}: {count:>2}/{len(domains_list)} ({percentage:>5.1f}%)")
    
    print(f"\n📄 Отчеты сохранены:")
    print(f"  Детальный: {detailed_report_path}")
    print(f"  Краткий:   {summary_report_path}")
    
    return results

def main():
    """Основная функция"""
    
    print("🔍 Автоматизированная система проверки атак")
    print("Версия: Адаптированная под реальные CLI")
    
    # Список доменов для проверки
    test_domains = [
        "youtube.com",
        "googlevideo.com", 
        "nnmclub.to",
        "rutracker.org",
        "twitter.com"
    ]
    
    try:
        results = run_comprehensive_validation(test_domains)
        
        # Подсчитываем успешные результаты
        success_count = sum(1 for r in results.values() 
                          if r.get('status') in ['SUCCESS', 'PARTIAL'])
        
        if success_count > 0:
            print(f"\n🎉 {success_count} доменов показали положительные результаты!")
        else:
            print(f"\n⚠️  Все домены требуют дополнительной настройки")
            
        print(f"\n💡 Для полного анализа паритета нужны PCAP файлы")
        print(f"   Текущая версия работает только с логами")
            
    except KeyboardInterrupt:
        print(f"\n⏹️  Проверка прервана пользователем")
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")

if __name__ == "__main__":
    main()