#!/usr/bin/env python3
"""
Глубокий анализ параметров атак и модификаций пакетов
"""

import re
import json
import subprocess
import time
import requests
from datetime import datetime
from pathlib import Path
from collections import defaultdict

class DeepAttackAnalyzer:
    """Глубокий анализатор атак и их параметров"""
    
    def __init__(self):
        self.tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
        self.test_domains = [
            "nnmclub.to",
            "rutracker.org", 
            "kinozal.tv",
            "youtube.com"
        ]
    
    def analyze_attack_parameters(self, log_file):
        """Анализирует параметры атак в логах"""
        print(f"🔍 Анализ параметров атак в {log_file}...")
        
        # Try different encodings
        encodings = ['utf-8', 'cp1251', 'latin-1']
        content = None
        
        for encoding in encodings:
            try:
                with open(log_file, 'r', encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
        
        if content is None:
            print("   ❌ Не удалось прочитать файл")
            return {}
        
        parameters = defaultdict(list)
        strategies = []
        
        lines = content.split('\n')
        for i, line in enumerate(lines):
            # Ищем параметры атак
            param_patterns = [
                r"'split_pos':\s*(\d+)",
                r"'split_count':\s*(\d+)", 
                r"'ttl':\s*(\d+)",
                r"'fooling':\s*'([^']+)'",
                r"params:\s*({[^}]+})",
                r"Strategy:\s*([^,\s]+(?:,[^,\s]+)*)"
            ]
            
            for pattern in param_patterns:
                matches = re.findall(pattern, line)
                if matches:
                    param_name = pattern.split("'")[1] if "'" in pattern else "other"
                    for match in matches:
                        parameters[param_name].append({
                            'line': i+1,
                            'value': match,
                            'context': line.strip()[:100]
                        })
            
            # Ищем стратегии с параметрами
            if 'strategy:' in line.lower() and any(param in line.lower() for param in ['split_pos', 'ttl', 'fooling']):
                strategies.append({
                    'line': i+1,
                    'text': line.strip()
                })
        
        print(f"   📊 Найдено параметров:")
        for param, values in parameters.items():
            unique_values = set(v['value'] for v in values)
            print(f"      {param}: {len(values)} упоминаний, значения: {list(unique_values)[:5]}")
        
        print(f"   🎯 Найдено стратегий с параметрами: {len(strategies)}")
        
        return {
            'parameters': dict(parameters),
            'strategies': strategies,
            'total_lines': len(lines)
        }
    
    def analyze_packet_modifications(self, pcap_file):
        """Анализирует модификации пакетов в PCAP"""
        print(f"📡 Анализ модификаций пакетов в {pcap_file}...")
        
        if not Path(pcap_file).exists():
            print("   ❌ PCAP файл не найден")
            return {}
        
        try:
            # Получаем детальную информацию о пакетах
            result = subprocess.run([
                self.tshark_path,
                "-r", pcap_file,
                "-T", "fields",
                "-e", "frame.number",
                "-e", "frame.time_relative", 
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "ip.ttl",
                "-e", "tcp.flags",
                "-e", "tcp.len",
                "-e", "tcp.seq",
                "-e", "tls.handshake.type"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                print(f"   ❌ Ошибка tshark: {result.stderr}")
                return {}
            
            packets = []
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                if line.strip():
                    fields = line.split('\t')
                    if len(fields) >= 8:
                        packets.append({
                            'number': fields[0],
                            'time': fields[1],
                            'src_ip': fields[2],
                            'dst_ip': fields[3], 
                            'ttl': fields[4],
                            'tcp_flags': fields[5],
                            'tcp_len': fields[6],
                            'tcp_seq': fields[7],
                            'tls_handshake': fields[8] if len(fields) > 8 else ''
                        })
            
            # Анализируем модификации
            modifications = self._detect_modifications(packets)
            
            print(f"   📊 Всего пакетов: {len(packets)}")
            print(f"   🔧 Обнаружено модификаций: {len(modifications)}")
            
            return {
                'total_packets': len(packets),
                'packets': packets[:10],  # Первые 10 для анализа
                'modifications': modifications
            }
            
        except Exception as e:
            print(f"   ❌ Ошибка анализа PCAP: {e}")
            return {}
    
    def _detect_modifications(self, packets):
        """Обнаруживает модификации в пакетах"""
        modifications = []
        
        for i, packet in enumerate(packets):
            # Проверяем TTL модификации
            if packet['ttl'] and packet['ttl'] != '':
                ttl_value = int(packet['ttl']) if packet['ttl'].isdigit() else 0
                if ttl_value < 10:  # Подозрительно низкий TTL
                    modifications.append({
                        'type': 'low_ttl',
                        'packet': i+1,
                        'value': ttl_value,
                        'description': f"Низкий TTL: {ttl_value}"
                    })
            
            # Проверяем TCP флаги
            if packet['tcp_flags'] and packet['tcp_flags'] != '':
                flags = packet['tcp_flags']
                if flags in ['0x0002', '0x0012', '0x0018']:  # SYN, SYN-ACK, PSH-ACK
                    modifications.append({
                        'type': 'tcp_flags',
                        'packet': i+1,
                        'value': flags,
                        'description': f"TCP флаги: {flags}"
                    })
            
            # Проверяем размер TCP сегментов
            if packet['tcp_len'] and packet['tcp_len'] != '':
                tcp_len = int(packet['tcp_len']) if packet['tcp_len'].isdigit() else 0
                if tcp_len > 0 and tcp_len < 100:  # Маленькие сегменты
                    modifications.append({
                        'type': 'small_segment',
                        'packet': i+1,
                        'value': tcp_len,
                        'description': f"Маленький TCP сегмент: {tcp_len} байт"
                    })
        
        return modifications
    
    def test_multiple_domains(self):
        """Тестирует несколько заблокированных доменов"""
        print(f"🌐 Тестирование множественных доменов...")
        
        results = {}
        
        for domain in self.test_domains:
            print(f"   🎯 Тестирование {domain}...")
            
            # Прямой тест
            direct_result = self._test_domain_direct(domain)
            
            # Тест через service (быстрый)
            service_result = self._test_domain_with_service(domain)
            
            results[domain] = {
                'direct': direct_result,
                'service': service_result,
                'blocked': direct_result.get('blocked', True),
                'bypass_works': service_result.get('success', False)
            }
            
            status = "✅ Работает" if service_result.get('success') else "❌ Заблокирован"
            print(f"      Результат: {status}")
        
        return results
    
    def _test_domain_direct(self, domain):
        """Тестирует прямой доступ к домену"""
        try:
            response = requests.get(f"https://{domain}", timeout=5, verify=False)
            return {
                'success': response.status_code < 400,
                'status_code': response.status_code,
                'blocked': False
            }
        except requests.exceptions.Timeout:
            return {'success': False, 'blocked': True, 'error': 'timeout'}
        except Exception as e:
            return {'success': False, 'blocked': True, 'error': str(e)}
    
    def _test_domain_with_service(self, domain):
        """Тестирует доступ через service (быстрый тест)"""
        service_process = None
        try:
            # Запускаем service
            service_process = subprocess.Popen([
                'python', 'simple_service.py'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            time.sleep(3)  # Короткое ожидание
            
            # Быстрый тест
            response = requests.get(f"https://{domain}", timeout=8, verify=False)
            return {
                'success': response.status_code < 400,
                'status_code': response.status_code
            }
            
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            if service_process:
                service_process.terminate()
                service_process.wait(timeout=3)
    
    def investigate_timeout_causes(self, domain="nnmclub.to"):
        """Исследует причины timeout даже с bypass"""
        print(f"🔍 Исследование причин timeout для {domain}...")
        
        investigations = {}
        
        # 1. DNS резолюция
        print("   🌐 Проверка DNS...")
        try:
            import socket
            ip = socket.gethostbyname(domain)
            investigations['dns'] = {'success': True, 'ip': ip}
            print(f"      DNS: ✅ {ip}")
        except Exception as e:
            investigations['dns'] = {'success': False, 'error': str(e)}
            print(f"      DNS: ❌ {e}")
        
        # 2. Ping тест
        print("   📡 Проверка ping...")
        try:
            result = subprocess.run([
                'ping', '-n', '1', domain
            ], capture_output=True, text=True, timeout=10)
            
            investigations['ping'] = {
                'success': result.returncode == 0,
                'output': result.stdout[:200]
            }
            
            status = "✅" if result.returncode == 0 else "❌"
            print(f"      Ping: {status}")
            
        except Exception as e:
            investigations['ping'] = {'success': False, 'error': str(e)}
            print(f"      Ping: ❌ {e}")
        
        # 3. Traceroute (упрощенный)
        print("   🛣️  Проверка маршрута...")
        try:
            result = subprocess.run([
                'tracert', '-h', '5', domain
            ], capture_output=True, text=True, timeout=15)
            
            investigations['traceroute'] = {
                'success': result.returncode == 0,
                'output': result.stdout[:300]
            }
            
            print(f"      Traceroute: ✅ Выполнен")
            
        except Exception as e:
            investigations['traceroute'] = {'success': False, 'error': str(e)}
            print(f"      Traceroute: ❌ {e}")
        
        # 4. Проверка портов
        print("   🔌 Проверка портов...")
        ports_to_check = [80, 443]
        port_results = {}
        
        for port in ports_to_check:
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((investigations['dns']['ip'], port))
                sock.close()
                
                port_results[port] = result == 0
                status = "✅" if result == 0 else "❌"
                print(f"      Порт {port}: {status}")
                
            except Exception as e:
                port_results[port] = False
                print(f"      Порт {port}: ❌ {e}")
        
        investigations['ports'] = port_results
        
        return investigations
    
    def generate_comprehensive_report(self, discovery_params, service_params, 
                                    discovery_pcap, service_pcap, 
                                    domain_tests, timeout_investigation):
        """Генерирует комплексный отчет"""
        print(f"📋 Генерация комплексного отчета...")
        
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'analysis_type': 'deep_attack_analysis',
            'parameters_analysis': {
                'discovery_mode': discovery_params,
                'service_mode': service_params
            },
            'packet_modifications': {
                'discovery_pcap': discovery_pcap,
                'service_pcap': service_pcap
            },
            'domain_testing': domain_tests,
            'timeout_investigation': timeout_investigation,
            'conclusions': self._generate_conclusions(
                discovery_params, service_params, 
                discovery_pcap, service_pcap,
                domain_tests, timeout_investigation
            )
        }
        
        # Сохраняем отчет
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/deep_attack_analysis_{timestamp}.json"
        Path("reports").mkdir(exist_ok=True)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"   💾 Отчет сохранен: {report_file}")
        return report_file, report
    
    def _generate_conclusions(self, discovery_params, service_params, 
                            discovery_pcap, service_pcap,
                            domain_tests, timeout_investigation):
        """Генерирует выводы анализа"""
        conclusions = []
        
        # Анализ параметров
        discovery_param_count = sum(len(v) for v in discovery_params.get('parameters', {}).values())
        service_param_count = sum(len(v) for v in service_params.get('parameters', {}).values())
        
        if discovery_param_count > 0 and service_param_count > 0:
            conclusions.append("✅ Параметры атак найдены в обоих режимах")
        else:
            conclusions.append("❌ Недостаточно параметров атак в логах")
        
        # Анализ PCAP
        discovery_mods = len(discovery_pcap.get('modifications', []))
        service_mods = len(service_pcap.get('modifications', []))
        
        if discovery_mods > 0 or service_mods > 0:
            conclusions.append(f"✅ Обнаружены модификации пакетов: Discovery={discovery_mods}, Service={service_mods}")
        else:
            conclusions.append("❌ Модификации пакетов не обнаружены")
        
        # Анализ доменов
        working_domains = sum(1 for d in domain_tests.values() if d.get('bypass_works', False))
        total_domains = len(domain_tests)
        
        if working_domains > 0:
            conclusions.append(f"✅ Bypass работает для {working_domains}/{total_domains} доменов")
        else:
            conclusions.append("❌ Bypass не работает ни для одного домена")
        
        # Анализ timeout
        dns_works = timeout_investigation.get('dns', {}).get('success', False)
        ping_works = timeout_investigation.get('ping', {}).get('success', False)
        
        if dns_works and ping_works:
            conclusions.append("✅ DNS и ping работают - проблема в DPI блокировке")
        elif dns_works:
            conclusions.append("⚠️ DNS работает, но ping не проходит - возможна блокировка ICMP")
        else:
            conclusions.append("❌ DNS не работает - возможна полная блокировка")
        
        return conclusions

def main():
    """Основная функция"""
    print("🎯 ГЛУБОКИЙ АНАЛИЗ АТАК И МОДИФИКАЦИЙ")
    print("=" * 60)
    
    analyzer = DeepAttackAnalyzer()
    
    # Файлы для анализа
    discovery_log = "logs/nnmclub.to_discovery_20251217_154756.log"
    service_log = "logs/nnmclub.to_service_20251217_154828.log"
    discovery_pcap = "pcap/nnmclub.to_discovery_20251217_154756.pcap"
    service_pcap = "pcap/nnmclub.to_service_20251217_154828.pcap"
    
    # 1. Анализ параметров атак
    print("\n1️⃣ АНАЛИЗ ПАРАМЕТРОВ АТАК")
    discovery_params = analyzer.analyze_attack_parameters(discovery_log)
    service_params = analyzer.analyze_attack_parameters(service_log)
    
    # 2. Анализ модификаций пакетов
    print("\n2️⃣ АНАЛИЗ МОДИФИКАЦИЙ ПАКЕТОВ")
    discovery_pcap_analysis = analyzer.analyze_packet_modifications(discovery_pcap)
    service_pcap_analysis = analyzer.analyze_packet_modifications(service_pcap)
    
    # 3. Тестирование множественных доменов
    print("\n3️⃣ ТЕСТИРОВАНИЕ МНОЖЕСТВЕННЫХ ДОМЕНОВ")
    domain_tests = analyzer.test_multiple_domains()
    
    # 4. Исследование причин timeout
    print("\n4️⃣ ИССЛЕДОВАНИЕ ПРИЧИН TIMEOUT")
    timeout_investigation = analyzer.investigate_timeout_causes()
    
    # 5. Генерация отчета
    print("\n5️⃣ ГЕНЕРАЦИЯ ОТЧЕТА")
    report_file, report = analyzer.generate_comprehensive_report(
        discovery_params, service_params,
        discovery_pcap_analysis, service_pcap_analysis,
        domain_tests, timeout_investigation
    )
    
    # Выводим основные выводы
    print(f"\n📊 ОСНОВНЫЕ ВЫВОДЫ:")
    for conclusion in report['conclusions']:
        print(f"   {conclusion}")
    
    print(f"\n💾 Полный отчет: {report_file}")

if __name__ == "__main__":
    main()