#!/usr/bin/env python3
"""
Полноценная система проверки корректности выполнения атак
С захватом PCAP и реальной валидацией доступности
"""

import os
import subprocess
import json
import time
import threading
import signal
import sys
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import requests

class PCAPCapture:
    """Класс для захвата PCAP данных"""
    
    def __init__(self, output_file, interface="any"):
        self.output_file = output_file
        self.interface = interface
        self.process = None
        self.tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    
    def start_capture(self, filter_expr=None):
        """Запускает захват пакетов"""
        try:
            cmd = [self.tshark_path, "-i", self.interface, "-w", self.output_file]
            if filter_expr:
                cmd.extend(["-f", filter_expr])
            
            self.process = subprocess.Popen(
                cmd, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            print(f"   📡 Захват PCAP запущен: {self.output_file}")
            return True
            
        except Exception as e:
            print(f"   ❌ Ошибка запуска захвата: {e}")
            return False
    
    def stop_capture(self):
        """Останавливает захват пакетов"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                print(f"   ⏹️  Захват PCAP остановлен")
                return True
            except:
                try:
                    self.process.kill()
                    return True
                except:
                    return False
        return True

class RealAttackValidator:
    """Основной класс для валидации атак"""
    
    def __init__(self):
        self.tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
        self.create_directories()
    
    def create_directories(self):
        """Создает необходимые директории"""
        dirs = ['logs', 'pcap', 'reports', 'temp']
        for dir_name in dirs:
            Path(dir_name).mkdir(exist_ok=True)
    
    def check_site_accessibility(self, domain, timeout=10):
        """Проверяет реальную доступность сайта"""
        try:
            # Проверяем HTTPS
            response = requests.get(
                f"https://{domain}", 
                timeout=timeout, 
                allow_redirects=True,
                verify=False  # Игнорируем SSL ошибки для заблокированных сайтов
            )
            
            return {
                'accessible': response.status_code < 400,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'final_url': response.url
            }
            
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e),
                'status_code': 0,
                'response_time': timeout
            }
    
    def run_discovery_with_pcap(self, domain, timeout=120):
        """Запускает discovery mode с захватом PCAP"""
        print(f"🔍 Discovery mode для {domain} с захватом PCAP...")
        
        log_file = f"logs/{domain}_discovery.log"
        pcap_file = f"pcap/{domain}_discovery.pcap"
        
        # Запускаем захват PCAP
        pcap_capture = PCAPCapture(pcap_file)
        if not pcap_capture.start_capture(f"host {domain}"):
            return None
        
        try:
            # Даем время на запуск захвата
            time.sleep(2)
            
            # Запускаем discovery mode
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
                    print(f"   ⚠️  Таймаут {timeout}с")
            
            # Даем время на завершение записи пакетов
            time.sleep(2)
            
        finally:
            # Останавливаем захват
            pcap_capture.stop_capture()
        
        # Проверяем результаты
        log_size = os.path.getsize(log_file) if os.path.exists(log_file) else 0
        pcap_size = os.path.getsize(pcap_file) if os.path.exists(pcap_file) else 0
        
        return {
            'success': success and log_size > 100,
            'log_file': log_file,
            'pcap_file': pcap_file,
            'log_size': log_size,
            'pcap_size': pcap_size
        }
    
    def run_service_with_pcap(self, domain, timeout=60):
        """Запускает service mode с захватом PCAP"""
        print(f"🔧 Service mode для {domain} с захватом PCAP...")
        
        log_file = f"logs/{domain}_service.log"
        pcap_file = f"pcap/{domain}_service.pcap"
        
        # Запускаем захват PCAP
        pcap_capture = PCAPCapture(pcap_file)
        if not pcap_capture.start_capture(f"host {domain}"):
            return None
        
        service_process = None
        try:
            # Даем время на запуск захвата
            time.sleep(2)
            
            # Запускаем service в фоне
            with open(log_file, 'w', encoding='utf-8') as f:
                service_process = subprocess.Popen([
                    'python', 'simple_service.py'
                ], stdout=f, stderr=subprocess.STDOUT, text=True)
            
            # Даем время на запуск службы
            time.sleep(5)
            
            # Тестируем подключение к домену
            print(f"   🌐 Тестирование доступности {domain}...")
            accessibility = self.check_site_accessibility(domain, timeout)
            
            # Даем время на обработку трафика
            time.sleep(3)
            
        finally:
            # Останавливаем service
            if service_process:
                try:
                    service_process.terminate()
                    service_process.wait(timeout=5)
                except:
                    service_process.kill()
            
            # Останавливаем захват
            pcap_capture.stop_capture()
        
        # Проверяем результаты
        log_size = os.path.getsize(log_file) if os.path.exists(log_file) else 0
        pcap_size = os.path.getsize(pcap_file) if os.path.exists(pcap_file) else 0
        
        return {
            'success': accessibility['accessible'] and log_size > 50,
            'log_file': log_file,
            'pcap_file': pcap_file,
            'log_size': log_size,
            'pcap_size': pcap_size,
            'accessibility': accessibility
        }
    
    def analyze_pcap_with_tshark(self, pcap_file, domain):
        """Анализирует PCAP файл с помощью tshark"""
        if not os.path.exists(pcap_file) or os.path.getsize(pcap_file) == 0:
            return {'error': 'PCAP файл пуст или не существует'}
        
        try:
            # Базовая статистика пакетов
            stats_cmd = [
                self.tshark_path, "-r", pcap_file, 
                "-q", "-z", "conv,tcp"
            ]
            
            stats_result = subprocess.run(
                stats_cmd, capture_output=True, text=True, timeout=30
            )
            
            # Анализ HTTP/HTTPS трафика
            http_cmd = [
                self.tshark_path, "-r", pcap_file,
                "-Y", f"http.host == \"{domain}\" or tls.handshake.extensions_server_name == \"{domain}\"",
                "-T", "fields",
                "-e", "frame.number",
                "-e", "ip.src", 
                "-e", "ip.dst",
                "-e", "tcp.srcport",
                "-e", "tcp.dstport",
                "-e", "http.request.method",
                "-e", "tls.handshake.extensions_server_name"
            ]
            
            http_result = subprocess.run(
                http_cmd, capture_output=True, text=True, timeout=30
            )
            
            # Подсчет пакетов
            count_cmd = [
                self.tshark_path, "-r", pcap_file,
                "-Y", f"ip.addr == {domain} or http.host == \"{domain}\" or tls.handshake.extensions_server_name == \"{domain}\"",
                "-T", "fields", "-e", "frame.number"
            ]
            
            count_result = subprocess.run(
                count_cmd, capture_output=True, text=True, timeout=30
            )
            
            packet_count = len([line for line in count_result.stdout.strip().split('\n') if line])
            
            return {
                'packet_count': packet_count,
                'has_http_traffic': bool(http_result.stdout.strip()),
                'tcp_conversations': stats_result.stdout,
                'http_details': http_result.stdout.strip().split('\n') if http_result.stdout.strip() else []
            }
            
        except Exception as e:
            return {'error': f'Ошибка анализа PCAP: {e}'}
    
    def correlate_log_pcap(self, log_file, pcap_file, domain, mode):
        """Корреляция логов и PCAP данных"""
        print(f"   📊 Корреляция {mode} логов и PCAP...")
        
        # Анализируем PCAP
        pcap_analysis = self.analyze_pcap_with_tshark(pcap_file, domain)
        
        # Читаем лог
        log_content = ""
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    log_content = f.read()
            except:
                pass
        
        # Ищем упоминания атак в логах
        attack_mentions = []
        attack_types = ['split', 'multisplit', 'disorder', 'fake', 'badsum', 'badseq']
        
        for attack in attack_types:
            if attack.lower() in log_content.lower():
                attack_mentions.append(attack)
        
        # Корреляционный анализ
        correlation = {
            'log_size': len(log_content),
            'pcap_analysis': pcap_analysis,
            'attack_mentions': attack_mentions,
            'has_traffic': pcap_analysis.get('packet_count', 0) > 0,
            'correlation_score': 0.0
        }
        
        # Вычисляем простой скор корреляции
        score = 0.0
        if correlation['log_size'] > 100:
            score += 0.3
        if correlation['has_traffic']:
            score += 0.4
        if correlation['attack_mentions']:
            score += 0.3
        
        correlation['correlation_score'] = score
        
        return correlation
    
    def validate_domain_comprehensive(self, domain):
        """Комплексная валидация домена"""
        print(f"\n🎯 ПОЛНАЯ ПРОВЕРКА ДОМЕНА: {domain}")
        print("=" * 60)
        
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'phases': {}
        }
        
        # Фаза 1: Проверка базовой доступности
        print("1️⃣ Проверка базовой доступности...")
        baseline_access = self.check_site_accessibility(domain)
        result['phases']['baseline'] = baseline_access
        
        if baseline_access['accessible']:
            print(f"   ✅ Сайт доступен (код: {baseline_access['status_code']})")
        else:
            print(f"   ❌ Сайт заблокирован или недоступен")
        
        # Фаза 2: Discovery mode с PCAP
        print("\n2️⃣ Discovery Mode с захватом PCAP...")
        discovery_result = self.run_discovery_with_pcap(domain)
        if discovery_result:
            result['phases']['discovery'] = discovery_result
            
            # Корреляция discovery
            discovery_correlation = self.correlate_log_pcap(
                discovery_result['log_file'],
                discovery_result['pcap_file'],
                domain,
                'discovery'
            )
            result['phases']['discovery']['correlation'] = discovery_correlation
            
            print(f"   📊 Discovery корреляция: {discovery_correlation['correlation_score']:.2f}")
            print(f"   📦 Пакетов в PCAP: {discovery_correlation['pcap_analysis'].get('packet_count', 0)}")
            print(f"   ⚔️  Атаки в логах: {', '.join(discovery_correlation['attack_mentions']) or 'Не найдены'}")
        
        # Фаза 3: Service mode с PCAP
        print("\n3️⃣ Service Mode с захватом PCAP...")
        service_result = self.run_service_with_pcap(domain)
        if service_result:
            result['phases']['service'] = service_result
            
            # Корреляция service
            service_correlation = self.correlate_log_pcap(
                service_result['log_file'],
                service_result['pcap_file'],
                domain,
                'service'
            )
            result['phases']['service']['correlation'] = service_correlation
            
            print(f"   📊 Service корреляция: {service_correlation['correlation_score']:.2f}")
            print(f"   📦 Пакетов в PCAP: {service_correlation['pcap_analysis'].get('packet_count', 0)}")
            print(f"   🌐 Доступность: {'✅' if service_result['accessibility']['accessible'] else '❌'}")
        
        # Фаза 4: Анализ паритета
        print("\n4️⃣ Анализ паритета между режимами...")
        parity_analysis = self.analyze_parity(result)
        result['parity'] = parity_analysis
        
        # Итоговая оценка
        overall_score = self.calculate_overall_score(result)
        result['overall_score'] = overall_score
        
        print(f"\n📊 ИТОГОВАЯ ОЦЕНКА: {overall_score['score']:.2f}/1.00")
        print(f"🎯 Статус: {overall_score['status']}")
        
        return result
    
    def analyze_parity(self, result):
        """Анализ паритета между режимами"""
        discovery = result['phases'].get('discovery', {})
        service = result['phases'].get('service', {})
        
        parity = {
            'log_size_ratio': 0.0,
            'pcap_size_ratio': 0.0,
            'correlation_diff': 0.0,
            'attack_consistency': False,
            'parity_score': 0.0
        }
        
        # Сравнение размеров логов
        if discovery.get('log_size', 0) > 0 and service.get('log_size', 0) > 0:
            ratio = min(discovery['log_size'], service['log_size']) / max(discovery['log_size'], service['log_size'])
            parity['log_size_ratio'] = ratio
        
        # Сравнение размеров PCAP
        if discovery.get('pcap_size', 0) > 0 and service.get('pcap_size', 0) > 0:
            ratio = min(discovery['pcap_size'], service['pcap_size']) / max(discovery['pcap_size'], service['pcap_size'])
            parity['pcap_size_ratio'] = ratio
        
        # Сравнение корреляций
        disc_corr = discovery.get('correlation', {}).get('correlation_score', 0)
        serv_corr = service.get('correlation', {}).get('correlation_score', 0)
        parity['correlation_diff'] = abs(disc_corr - serv_corr)
        
        # Консистентность атак
        disc_attacks = set(discovery.get('correlation', {}).get('attack_mentions', []))
        serv_attacks = set(service.get('correlation', {}).get('attack_mentions', []))
        if disc_attacks and serv_attacks:
            parity['attack_consistency'] = len(disc_attacks & serv_attacks) > 0
        
        # Общий скор паритета
        score = 0.0
        score += parity['log_size_ratio'] * 0.25
        score += parity['pcap_size_ratio'] * 0.25
        score += (1.0 - parity['correlation_diff']) * 0.25
        score += (1.0 if parity['attack_consistency'] else 0.0) * 0.25
        
        parity['parity_score'] = score
        
        return parity
    
    def calculate_overall_score(self, result):
        """Вычисляет общую оценку"""
        score = 0.0
        max_score = 1.0
        
        # Базовая доступность (20%)
        baseline = result['phases'].get('baseline', {})
        if baseline.get('accessible'):
            score += 0.2
        
        # Discovery корреляция (30%)
        discovery_corr = result['phases'].get('discovery', {}).get('correlation', {}).get('correlation_score', 0)
        score += discovery_corr * 0.3
        
        # Service корреляция (30%)
        service_corr = result['phases'].get('service', {}).get('correlation', {}).get('correlation_score', 0)
        score += service_corr * 0.3
        
        # Паритет (20%)
        parity_score = result.get('parity', {}).get('parity_score', 0)
        score += parity_score * 0.2
        
        # Определяем статус
        if score >= 0.9:
            status = "ОТЛИЧНО - Все системы работают корректно"
        elif score >= 0.7:
            status = "ХОРОШО - Незначительные расхождения"
        elif score >= 0.5:
            status = "УДОВЛЕТВОРИТЕЛЬНО - Требуется настройка"
        else:
            status = "НЕУДОВЛЕТВОРИТЕЛЬНО - Серьезные проблемы"
        
        return {
            'score': score,
            'max_score': max_score,
            'percentage': score / max_score * 100,
            'status': status
        }

def main():
    """Основная функция"""
    
    print("🔍 ПОЛНОЦЕННАЯ СИСТЕМА ПРОВЕРКИ АТАК")
    print("Версия: С захватом PCAP и реальной валидацией")
    print("=" * 60)
    
    # Проверяем наличие tshark
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    if not os.path.exists(tshark_path):
        print(f"❌ tshark не найден по пути: {tshark_path}")
        print("Установите Wireshark или укажите правильный путь")
        return
    
    validator = RealAttackValidator()
    
    # Тестовые домены с известным статусом
    test_domains = [
        "youtube.com",      # Должен быть доступен
        "nnmclub.to",       # Заблокирован в РФ
        "googlevideo.com"   # Поддомены заблокированы
    ]
    
    results = {}
    
    try:
        for i, domain in enumerate(test_domains, 1):
            print(f"\n{'='*20} [{i}/{len(test_domains)}] {'='*20}")
            
            result = validator.validate_domain_comprehensive(domain)
            results[domain] = result
            
            # Сохраняем промежуточный результат
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"reports/comprehensive_validation_{timestamp}.json"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        
        # Итоговая статистика
        print(f"\n{'='*60}")
        print("📊 ИТОГОВАЯ СТАТИСТИКА")
        print(f"{'='*60}")
        
        for domain, result in results.items():
            score = result['overall_score']['score']
            status = result['overall_score']['status'].split(' - ')[0]
            print(f"{domain:20} | {score:.2f} | {status}")
        
        avg_score = sum(r['overall_score']['score'] for r in results.values()) / len(results)
        print(f"\nСредний балл: {avg_score:.2f}")
        print(f"Отчет сохранен: {report_file}")
        
    except KeyboardInterrupt:
        print(f"\n⏹️  Проверка прервана пользователем")
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")

if __name__ == "__main__":
    main()