#!/usr/bin/env python3
"""
Улучшенная система проверки атак с диагностикой проблем
"""

import os
import subprocess
import json
import time
import threading
import sys
from pathlib import Path
from datetime import datetime
import requests

class ImprovedAttackValidator:
    """Улучшенный валидатор атак с диагностикой"""
    
    def __init__(self):
        self.tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
        self.create_directories()
        self.check_system_requirements()
    
    def create_directories(self):
        """Создает необходимые директории"""
        dirs = ['logs', 'pcap', 'reports', 'temp']
        for dir_name in dirs:
            Path(dir_name).mkdir(exist_ok=True)
    
    def check_system_requirements(self):
        """Проверяет системные требования"""
        print("🔍 Проверка системных требований...")
        
        # Проверяем tshark
        if os.path.exists(self.tshark_path):
            print("✅ tshark найден")
        else:
            print("❌ tshark не найден - PCAP анализ недоступен")
            self.tshark_path = None
        
        # Проверяем права администратора (нужны для захвата пакетов)
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                print("✅ Права администратора есть")
            else:
                print("⚠️  Нет прав администратора - захват пакетов может не работать")
        except:
            print("⚠️  Не удалось проверить права администратора")
    
    def test_site_accessibility_detailed(self, domain):
        """Детальная проверка доступности сайта"""
        print(f"🌐 Детальная проверка доступности {domain}...")
        
        results = {
            'domain': domain,
            'tests': {},
            'overall_accessible': False
        }
        
        # Тест 1: Прямое HTTPS подключение
        try:
            response = requests.get(
                f"https://{domain}", 
                timeout=10, 
                allow_redirects=True,
                verify=False
            )
            
            results['tests']['https_direct'] = {
                'success': response.status_code < 400,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'final_url': response.url
            }
            
            print(f"   HTTPS: {response.status_code} ({response.elapsed.total_seconds():.2f}s)")
            
        except Exception as e:
            results['tests']['https_direct'] = {
                'success': False,
                'error': str(e)
            }
            print(f"   HTTPS: ❌ {e}")
        
        # Тест 2: HTTP подключение
        try:
            response = requests.get(
                f"http://{domain}", 
                timeout=10, 
                allow_redirects=True
            )
            
            results['tests']['http_direct'] = {
                'success': response.status_code < 400,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds()
            }
            
            print(f"   HTTP:  {response.status_code} ({response.elapsed.total_seconds():.2f}s)")
            
        except Exception as e:
            results['tests']['http_direct'] = {
                'success': False,
                'error': str(e)
            }
            print(f"   HTTP:  ❌ {e}")
        
        # Тест 3: DNS резолюция
        try:
            import socket
            ip = socket.gethostbyname(domain)
            results['tests']['dns_resolution'] = {
                'success': True,
                'ip': ip
            }
            print(f"   DNS:   ✅ {ip}")
            
        except Exception as e:
            results['tests']['dns_resolution'] = {
                'success': False,
                'error': str(e)
            }
            print(f"   DNS:   ❌ {e}")
        
        # Тест 4: Ping тест
        try:
            ping_result = subprocess.run([
                'ping', '-n', '1', domain
            ], capture_output=True, text=True, timeout=10)
            
            results['tests']['ping'] = {
                'success': ping_result.returncode == 0,
                'output': ping_result.stdout
            }
            
            if ping_result.returncode == 0:
                print(f"   PING:  ✅ Доступен")
            else:
                print(f"   PING:  ❌ Недоступен")
                
        except Exception as e:
            results['tests']['ping'] = {
                'success': False,
                'error': str(e)
            }
            print(f"   PING:  ❌ {e}")
        
        # Определяем общую доступность
        results['overall_accessible'] = any(
            test.get('success', False) 
            for test in results['tests'].values()
        )
        
        return results
    
    def run_discovery_with_monitoring(self, domain, timeout=60):
        """Запускает discovery mode с мониторингом"""
        print(f"🔍 Discovery mode для {domain} с мониторингом...")
        
        log_file = f"logs/{domain}_discovery_improved.log"
        
        try:
            # Запускаем discovery mode
            with open(log_file, 'w', encoding='utf-8') as f:
                process = subprocess.Popen([
                    'python', 'cli.py', 'auto', domain
                ], stdout=f, stderr=subprocess.STDOUT, text=True)
                
                # Мониторим процесс
                start_time = time.time()
                while process.poll() is None:
                    elapsed = time.time() - start_time
                    if elapsed > timeout:
                        print(f"   ⚠️  Принудительная остановка после {timeout}с")
                        process.kill()
                        break
                    
                    # Проверяем размер лога каждые 5 секунд
                    if elapsed % 5 == 0:
                        if os.path.exists(log_file):
                            size = os.path.getsize(log_file)
                            print(f"   📊 {elapsed:.0f}с: лог {size} байт")
                    
                    time.sleep(1)
                
                success = process.returncode == 0 if process.poll() is not None else False
        
        except Exception as e:
            print(f"   ❌ Ошибка запуска: {e}")
            success = False
        
        # Анализируем лог
        log_analysis = self.analyze_log_content(log_file)
        
        return {
            'success': success,
            'log_file': log_file,
            'log_analysis': log_analysis
        }
    
    def analyze_log_content(self, log_file):
        """Анализирует содержимое лога"""
        if not os.path.exists(log_file):
            return {'error': 'Лог файл не найден'}
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            analysis = {
                'size': len(content),
                'lines': len(content.split('\n')),
                'attacks_mentioned': [],
                'errors': [],
                'warnings': [],
                'success_indicators': []
            }
            
            # Ищем упоминания атак
            attack_types = ['split', 'multisplit', 'disorder', 'fake', 'badsum', 'badseq']
            for attack in attack_types:
                if attack.lower() in content.lower():
                    analysis['attacks_mentioned'].append(attack)
            
            # Ищем ошибки
            lines = content.split('\n')
            for line in lines:
                line_lower = line.lower()
                if 'error' in line_lower or 'exception' in line_lower:
                    analysis['errors'].append(line.strip())
                elif 'warning' in line_lower:
                    analysis['warnings'].append(line.strip())
                elif any(word in line_lower for word in ['success', 'found', 'working']):
                    analysis['success_indicators'].append(line.strip())
            
            return analysis
            
        except Exception as e:
            return {'error': f'Ошибка анализа лога: {e}'}
    
    def run_service_with_monitoring(self, domain, timeout=30):
        """Запускает service mode с мониторингом"""
        print(f"🔧 Service mode для {domain} с мониторингом...")
        
        log_file = f"logs/{domain}_service_improved.log"
        
        service_process = None
        try:
            # Запускаем service в фоне
            with open(log_file, 'w', encoding='utf-8') as f:
                service_process = subprocess.Popen([
                    'python', 'simple_service.py'
                ], stdout=f, stderr=subprocess.STDOUT, text=True)
            
            print(f"   🚀 Service запущен (PID: {service_process.pid})")
            
            # Даем время на запуск
            time.sleep(5)
            
            # Тестируем подключение
            print(f"   🌐 Тестирование через service...")
            accessibility = self.test_site_accessibility_detailed(domain)
            
            # Даем время на обработку
            time.sleep(3)
            
        finally:
            # Останавливаем service
            if service_process:
                try:
                    service_process.terminate()
                    service_process.wait(timeout=5)
                    print(f"   ⏹️  Service остановлен")
                except:
                    service_process.kill()
                    print(f"   💀 Service принудительно завершен")
        
        # Анализируем лог
        log_analysis = self.analyze_log_content(log_file)
        
        return {
            'success': accessibility['overall_accessible'],
            'log_file': log_file,
            'log_analysis': log_analysis,
            'accessibility': accessibility
        }
    
    def validate_domain_improved(self, domain):
        """Улучшенная валидация домена"""
        print(f"\n🎯 УЛУЧШЕННАЯ ПРОВЕРКА: {domain}")
        print("=" * 60)
        
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'phases': {}
        }
        
        # Фаза 1: Детальная проверка доступности
        print("1️⃣ Детальная проверка доступности...")
        baseline = self.test_site_accessibility_detailed(domain)
        result['phases']['baseline'] = baseline
        
        # Фаза 2: Discovery mode с мониторингом
        print("\n2️⃣ Discovery Mode с мониторингом...")
        discovery = self.run_discovery_with_monitoring(domain)
        result['phases']['discovery'] = discovery
        
        if discovery['log_analysis'].get('attacks_mentioned'):
            print(f"   ⚔️  Найденные атаки: {', '.join(discovery['log_analysis']['attacks_mentioned'])}")
        
        if discovery['log_analysis'].get('errors'):
            print(f"   ❌ Ошибки: {len(discovery['log_analysis']['errors'])}")
            for error in discovery['log_analysis']['errors'][:3]:
                print(f"      {error}")
        
        # Фаза 3: Service mode с мониторингом
        print("\n3️⃣ Service Mode с мониторингом...")
        service = self.run_service_with_monitoring(domain)
        result['phases']['service'] = service
        
        # Фаза 4: Анализ результатов
        print("\n4️⃣ Анализ результатов...")
        analysis = self.analyze_results(result)
        result['analysis'] = analysis
        
        # Итоговая оценка
        print(f"\n📊 РЕЗУЛЬТАТЫ:")
        print(f"Базовая доступность: {'✅' if baseline['overall_accessible'] else '❌'}")
        print(f"Discovery работает: {'✅' if discovery['success'] else '❌'}")
        print(f"Service работает: {'✅' if service['success'] else '❌'}")
        print(f"Найдено атак: {len(discovery['log_analysis'].get('attacks_mentioned', []))}")
        print(f"Общая оценка: {analysis['score']:.2f}/1.00")
        print(f"Статус: {analysis['status']}")
        
        return result
    
    def analyze_results(self, result):
        """Анализирует результаты проверки"""
        score = 0.0
        
        # Базовая доступность (30%)
        if result['phases']['baseline']['overall_accessible']:
            score += 0.3
        
        # Discovery работает (35%)
        discovery = result['phases']['discovery']
        if discovery['success']:
            score += 0.2
        if discovery['log_analysis'].get('attacks_mentioned'):
            score += 0.15  # Есть упоминания атак
        
        # Service работает (35%)
        service = result['phases']['service']
        if service['success']:
            score += 0.2
        if service['accessibility']['overall_accessible']:
            score += 0.15
        
        # Определяем статус
        if score >= 0.8:
            status = "ОТЛИЧНО - Система работает корректно"
        elif score >= 0.6:
            status = "ХОРОШО - Незначительные проблемы"
        elif score >= 0.4:
            status = "УДОВЛЕТВОРИТЕЛЬНО - Требуется настройка"
        else:
            status = "НЕУДОВЛЕТВОРИТЕЛЬНО - Серьезные проблемы"
        
        return {
            'score': score,
            'status': status
        }

def main():
    """Основная функция"""
    
    print("🔍 УЛУЧШЕННАЯ СИСТЕМА ПРОВЕРКИ АТАК")
    print("Версия: С детальной диагностикой")
    print("=" * 60)
    
    validator = ImprovedAttackValidator()
    
    # Тестовые домены
    domains = ["youtube.com", "nnmclub.to", "googlevideo.com"]
    
    if len(sys.argv) > 1:
        # Проверка конкретного домена
        domain = sys.argv[1]
        result = validator.validate_domain_improved(domain)
        
        # Сохраняем результат
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/improved_validation_{domain}_{timestamp}.json"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Отчет сохранен: {report_file}")
        
    else:
        # Проверка всех доменов
        results = {}
        
        for i, domain in enumerate(domains, 1):
            print(f"\n{'='*20} [{i}/{len(domains)}] {'='*20}")
            result = validator.validate_domain_improved(domain)
            results[domain] = result
        
        # Сохраняем общий отчет
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/improved_batch_validation_{timestamp}.json"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        # Итоговая статистика
        print(f"\n{'='*60}")
        print("📊 ИТОГОВАЯ СТАТИСТИКА")
        print(f"{'='*60}")
        
        for domain, result in results.items():
            score = result['analysis']['score']
            status = result['analysis']['status'].split(' - ')[0]
            print(f"{domain:20} | {score:.2f} | {status}")
        
        avg_score = sum(r['analysis']['score'] for r in results.values()) / len(results)
        print(f"\nСредний балл: {avg_score:.2f}")
        print(f"Отчет сохранен: {report_file}")

if __name__ == "__main__":
    main()