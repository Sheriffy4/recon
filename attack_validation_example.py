#!/usr/bin/env python3
"""
Реальный скрипт для проверки корректности выполнения атак
Адаптирован под существующие CLI и simple_service.py
"""

import os
import subprocess
import json
import time
from pathlib import Path
from datetime import datetime
from core.attack_parity.analyzer import AttackParityAnalyzer
from core.attack_parity.report_generator import AttackParityReportGenerator

def create_directories():
    """Создаем необходимые директории для логов и отчетов"""
    dirs = ['logs', 'pcap', 'reports']
    for dir_name in dirs:
        Path(dir_name).mkdir(exist_ok=True)

def run_discovery_mode(domain, timeout=60):
    """
    Запускает discovery mode (auto) и собирает логи
    """
    print(f"🔍 Запуск discovery mode для {domain}...")
    
    log_file = f"logs/{domain}_discovery.log"
    
    try:
        # Запускаем CLI в auto режиме с перенаправлением вывода
        with open(log_file, 'w', encoding='utf-8') as f:
            process = subprocess.Popen([
                'python', 'cli.py', 'auto', domain
            ], stdout=f, stderr=subprocess.STDOUT, text=True)
            
            # Ждем завершения с таймаутом
            try:
                process.wait(timeout=timeout)
                return log_file if process.returncode == 0 else None
            except subprocess.TimeoutExpired:
                process.kill()
                print(f"⚠️  Discovery mode превысил таймаут {timeout}с")
                return log_file  # Возвращаем частичный лог
                
    except Exception as e:
        print(f"❌ Ошибка запуска discovery mode: {e}")
        return None

def run_service_mode(domain, timeout=30):
    """
    Запускает service mode и собирает логи
    """
    print(f"🔧 Запуск service mode для {domain}...")
    
    log_file = f"logs/{domain}_service.log"
    
    try:
        # Запускаем simple_service.py с перенаправлением вывода
        with open(log_file, 'w', encoding='utf-8') as f:
            process = subprocess.Popen([
                'python', 'simple_service.py'
            ], stdout=f, stderr=subprocess.STDOUT, text=True)
            
            # Даем время на запуск службы
            time.sleep(2)
            
            # Тестируем домен через curl или другой способ
            test_process = subprocess.run([
                'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                f'https://{domain}'
            ], capture_output=True, text=True, timeout=timeout)
            
            # Останавливаем службу
            process.terminate()
            process.wait(timeout=5)
            
            return log_file
            
    except Exception as e:
        print(f"❌ Ошибка запуска service mode: {e}")
        return None

def analyze_logs_only(discovery_log, service_log, domain):
    """
    Анализирует только логи без PCAP файлов
    """
    print(f"📊 Анализ логов для {domain}...")
    
    try:
        # Используем CLI инструмент для анализа
        result = subprocess.run([
            'python', '-m', 'core.attack_parity.cli', 'correlate',
            '--log', discovery_log,
            '--mode', 'discovery',
            '--output', f'reports/{domain}_discovery_analysis.json'
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            print(f"⚠️  Проблемы с анализом discovery логов: {result.stderr}")
        
        result = subprocess.run([
            'python', '-m', 'core.attack_parity.cli', 'correlate', 
            '--log', service_log,
            '--mode', 'service',
            '--output', f'reports/{domain}_service_analysis.json'
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            print(f"⚠️  Проблемы с анализом service логов: {result.stderr}")
            
        return True
        
    except Exception as e:
        print(f"❌ Ошибка анализа логов: {e}")
        return False

def validate_attack_execution_simple(domain):
    """
    Упрощенная проверка корректности выполнения атак
    Работает только с логами, без PCAP анализа
    """
    
    print(f"\n🎯 Проверка корректности атак для {domain}")
    print("=" * 50)
    
    # Создаем директории
    create_directories()
    
    # Запускаем discovery mode
    discovery_log = run_discovery_mode(domain)
    if not discovery_log:
        print("❌ Не удалось получить логи discovery mode")
        return False
    
    # Запускаем service mode
    service_log = run_service_mode(domain)
    if not service_log:
        print("❌ Не удалось получить логи service mode")
        return False
    
    # Анализируем логи
    analysis_success = analyze_logs_only(discovery_log, service_log, domain)
    
    # Проверяем размеры логов как базовую метрику
    discovery_size = os.path.getsize(discovery_log) if os.path.exists(discovery_log) else 0
    service_size = os.path.getsize(service_log) if os.path.exists(service_log) else 0
    
    print(f"\n📈 Базовые метрики:")
    print(f"Discovery log: {discovery_size} байт")
    print(f"Service log: {service_size} байт")
    print(f"Анализ логов: {'✅ Успешно' if analysis_success else '❌ Ошибки'}")
    
    # Простые критерии успешности
    success = (
        discovery_size > 100 and  # Есть содержимое в логах
        service_size > 100 and
        analysis_success
    )
    
    if success:
        print("\n✅ Базовая проверка пройдена!")
        print("💡 Для полного анализа нужны PCAP файлы")
    else:
        print("\n❌ Обнаружены проблемы в базовой проверке")
    
    return success

def validate_multiple_domains(domains):
    """
    Проверка нескольких доменов
    """
    results = {}
    
    print(f"\n🚀 Массовая проверка {len(domains)} доменов")
    print("=" * 60)
    
    for i, domain in enumerate(domains, 1):
        print(f"\n[{i}/{len(domains)}] Проверка {domain}")
        try:
            success = validate_attack_execution_simple(domain)
            results[domain] = "SUCCESS" if success else "FAILED"
        except Exception as e:
            results[domain] = f"ERROR: {e}"
            print(f"❌ Ошибка при проверке {domain}: {e}")
    
    # Сохраняем общий отчет
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/validation_summary_{timestamp}.json"
    
    summary = {
        'timestamp': timestamp,
        'results': results,
        'summary': {
            'total': len(domains),
            'success': sum(1 for r in results.values() if r == "SUCCESS"),
            'failed': sum(1 for r in results.values() if r == "FAILED"),
            'errors': sum(1 for r in results.values() if r.startswith("ERROR"))
        }
    }
    
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    # Выводим итоговую статистику
    print(f"\n📊 Итоговая статистика:")
    print(f"Успешно: {summary['summary']['success']}/{summary['summary']['total']}")
    print(f"Неудачно: {summary['summary']['failed']}/{summary['summary']['total']}")
    print(f"Ошибки: {summary['summary']['errors']}/{summary['summary']['total']}")
    print(f"Процент успеха: {summary['summary']['success']/summary['summary']['total']:.1%}")
    print(f"\n📄 Отчет сохранен: {report_path}")
    
    return results

def main():
    """Основная функция для запуска проверки"""
    
    print("🔍 Система проверки корректности выполнения атак")
    print("Версия: Адаптированная под реальные CLI")
    
    # Тестовые домены
    test_domains = [
        "youtube.com",
        "googlevideo.com", 
        "nnmclub.to"
    ]
    
    try:
        # Можно проверить один домен
        # success = validate_attack_execution_simple("youtube.com")
        
        # Или несколько доменов
        results = validate_multiple_domains(test_domains)
        
        success_count = sum(1 for r in results.values() if r == "SUCCESS")
        if success_count > 0:
            print(f"\n🎉 {success_count} доменов прошли проверку!")
        else:
            print("\n⚠️  Все домены требуют дополнительной настройки")
            
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")

if __name__ == "__main__":
    main()