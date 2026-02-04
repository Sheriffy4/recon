#!/usr/bin/env python3
"""
Исследователь проблем с bypass системой
"""

import subprocess
import time
import requests
import json
from datetime import datetime
from pathlib import Path

class BypassProblemInvestigator:
    """Исследует конкретные проблемы с bypass"""
    
    def __init__(self):
        self.tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    
    def test_attack_effectiveness(self, domain="nnmclub.to"):
        """Тестирует эффективность конкретных атак"""
        print(f"🎯 Тестирование эффективности атак для {domain}...")
        
        # Тестируем разные стратегии
        strategies_to_test = [
            "split",
            "multisplit", 
            "disorder",
            "fake",
            "smart_combo_disorder_multisplit"
        ]
        
        results = {}
        
        for strategy in strategies_to_test:
            print(f"   🔧 Тестирование стратегии: {strategy}")
            result = self._test_single_strategy(domain, strategy)
            results[strategy] = result
            
            status = "✅" if result.get('success') else "❌"
            print(f"      Результат: {status}")
        
        return results
    
    def _test_single_strategy(self, domain, strategy):
        """Тестирует одну конкретную стратегию"""
        service_process = None
        try:
            # Создаем временный конфиг для конкретной стратегии
            config = {
                "domains": {
                    domain: {
                        "attacks": [strategy],
                        "params": self._get_strategy_params(strategy)
                    }
                }
            }
            
            # Сохраняем временный конфиг
            with open("temp_strategy_config.json", "w") as f:
                json.dump(config, f, indent=2)
            
            # Запускаем service с конкретной стратегией
            service_process = subprocess.Popen([
                'python', 'simple_service.py', '--config', 'temp_strategy_config.json'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            time.sleep(4)  # Даем время на запуск
            
            # Тестируем подключение
            start_time = time.time()
            try:
                response = requests.get(f"https://{domain}", timeout=10, verify=False)
                duration = time.time() - start_time
                
                return {
                    'success': response.status_code < 400,
                    'status_code': response.status_code,
                    'duration': duration,
                    'strategy': strategy
                }
            except requests.exceptions.Timeout:
                return {
                    'success': False,
                    'error': 'timeout',
                    'strategy': strategy
                }
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e),
                    'strategy': strategy
                }
                
        finally:
            if service_process:
                service_process.terminate()
                service_process.wait(timeout=3)
            
            # Удаляем временный конфиг
            if Path("temp_strategy_config.json").exists():
                Path("temp_strategy_config.json").unlink()
    
    def _get_strategy_params(self, strategy):
        """Возвращает оптимальные параметры для стратегии"""
        params_map = {
            "split": {"split_pos": 3},
            "multisplit": {"split_pos": 3, "split_count": 8},
            "disorder": {"split_pos": 3, "disorder_method": "reverse"},
            "fake": {"ttl": 1},
            "smart_combo_disorder_multisplit": {
                "split_pos": 3,
                "split_count": 8,
                "disorder_method": "reverse"
            }
        }
        return params_map.get(strategy, {})
    
    def analyze_dpi_behavior(self, domain="nnmclub.to"):
        """Анализирует поведение DPI системы"""
        print(f"🔍 Анализ поведения DPI для {domain}...")
        
        dpi_tests = {}
        
        # 1. Тест обычного подключения
        print("   🌐 Тест обычного подключения...")
        dpi_tests['normal_connection'] = self._test_normal_connection(domain)
        
        # 2. Тест с разными User-Agent
        print("   🤖 Тест с разными User-Agent...")
        dpi_tests['user_agent_test'] = self._test_user_agents(domain)
        
        # 3. Тест с разными портами
        print("   🔌 Тест с разными портами...")
        dpi_tests['port_test'] = self._test_different_ports(domain)
        
        # 4. Тест фрагментации
        print("   🧩 Тест фрагментации...")
        dpi_tests['fragmentation_test'] = self._test_fragmentation(domain)
        
        return dpi_tests
    
    def _test_normal_connection(self, domain):
        """Тестирует обычное подключение"""
        try:
            response = requests.get(f"https://{domain}", timeout=5, verify=False)
            return {
                'success': True,
                'status_code': response.status_code,
                'headers': dict(response.headers)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _test_user_agents(self, domain):
        """Тестирует разные User-Agent"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "curl/7.68.0",
            "Python-requests/2.25.1"
        ]
        
        results = {}
        for ua in user_agents:
            try:
                headers = {'User-Agent': ua}
                response = requests.get(f"https://{domain}", 
                                      headers=headers, timeout=5, verify=False)
                results[ua] = {
                    'success': True,
                    'status_code': response.status_code
                }
            except Exception as e:
                results[ua] = {
                    'success': False,
                    'error': str(e)
                }
        
        return results
    
    def _test_different_ports(self, domain):
        """Тестирует разные порты"""
        ports_to_test = [80, 443, 8080, 8443]
        results = {}
        
        for port in ports_to_test:
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((domain, port))
                sock.close()
                
                results[port] = {
                    'success': result == 0,
                    'connection_result': result
                }
            except Exception as e:
                results[port] = {
                    'success': False,
                    'error': str(e)
                }
        
        return results
    
    def _test_fragmentation(self, domain):
        """Тестирует фрагментацию пакетов"""
        # Простой тест - пытаемся подключиться с маленьким MSS
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 536)  # Маленький MSS
            sock.settimeout(5)
            
            result = sock.connect_ex((domain, 443))
            sock.close()
            
            return {
                'success': result == 0,
                'connection_result': result,
                'method': 'small_mss'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def investigate_packet_timing(self, pcap_file):
        """Исследует тайминги пакетов"""
        print(f"⏱️ Анализ таймингов пакетов в {pcap_file}...")
        
        if not Path(pcap_file).exists():
            print("   ❌ PCAP файл не найден")
            return {}
        
        try:
            # Получаем тайминги пакетов
            result = subprocess.run([
                self.tshark_path,
                "-r", pcap_file,
                "-T", "fields",
                "-e", "frame.number",
                "-e", "frame.time_relative",
                "-e", "tcp.flags",
                "-e", "tcp.len"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return {'error': result.stderr}
            
            packets = []
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                if line.strip():
                    fields = line.split('\t')
                    if len(fields) >= 4:
                        packets.append({
                            'number': int(fields[0]) if fields[0].isdigit() else 0,
                            'time': float(fields[1]) if fields[1] else 0.0,
                            'tcp_flags': fields[2],
                            'tcp_len': int(fields[3]) if fields[3].isdigit() else 0
                        })
            
            # Анализируем тайминги
            timing_analysis = self._analyze_packet_timings(packets)
            
            print(f"   📊 Проанализировано пакетов: {len(packets)}")
            print(f"   ⏱️ Средний интервал: {timing_analysis.get('avg_interval', 0):.3f}с")
            
            return {
                'total_packets': len(packets),
                'timing_analysis': timing_analysis,
                'packets_sample': packets[:5]
            }
            
        except Exception as e:
            print(f"   ❌ Ошибка анализа: {e}")
            return {'error': str(e)}
    
    def _analyze_packet_timings(self, packets):
        """Анализирует тайминги между пакетами"""
        if len(packets) < 2:
            return {}
        
        intervals = []
        for i in range(1, len(packets)):
            interval = packets[i]['time'] - packets[i-1]['time']
            intervals.append(interval)
        
        avg_interval = sum(intervals) / len(intervals)
        max_interval = max(intervals)
        min_interval = min(intervals)
        
        # Ищем подозрительные задержки
        suspicious_delays = [i for i in intervals if i > 0.1]  # Больше 100мс
        
        return {
            'avg_interval': avg_interval,
            'max_interval': max_interval,
            'min_interval': min_interval,
            'suspicious_delays': len(suspicious_delays),
            'total_intervals': len(intervals)
        }
    
    def generate_investigation_report(self, attack_results, dpi_analysis, 
                                    discovery_timing, service_timing):
        """Генерирует отчет исследования"""
        print(f"📋 Генерация отчета исследования...")
        
        report = {
            'investigation_timestamp': datetime.now().isoformat(),
            'investigation_type': 'bypass_problem_analysis',
            'attack_effectiveness': attack_results,
            'dpi_behavior_analysis': dpi_analysis,
            'packet_timing_analysis': {
                'discovery_mode': discovery_timing,
                'service_mode': service_timing
            },
            'recommendations': self._generate_recommendations(
                attack_results, dpi_analysis, discovery_timing, service_timing
            )
        }
        
        # Сохраняем отчет
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/bypass_investigation_{timestamp}.json"
        Path("reports").mkdir(exist_ok=True)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"   💾 Отчет сохранен: {report_file}")
        return report_file, report
    
    def _generate_recommendations(self, attack_results, dpi_analysis, 
                                discovery_timing, service_timing):
        """Генерирует рекомендации по улучшению bypass"""
        recommendations = []
        
        # Анализ эффективности атак
        working_attacks = [k for k, v in attack_results.items() if v.get('success')]
        if not working_attacks:
            recommendations.append("❌ Ни одна атака не работает - проверить параметры и реализацию")
        else:
            recommendations.append(f"✅ Работающие атаки: {', '.join(working_attacks)}")
        
        # Анализ DPI поведения
        if dpi_analysis.get('normal_connection', {}).get('success'):
            recommendations.append("⚠️ Обычное подключение работает - возможно нет блокировки")
        else:
            recommendations.append("✅ Подтверждена блокировка DPI")
        
        # Анализ портов
        port_results = dpi_analysis.get('port_test', {})
        working_ports = [str(p) for p, r in port_results.items() if r.get('success')]
        if working_ports:
            recommendations.append(f"✅ Открытые порты: {', '.join(working_ports)}")
        
        # Анализ таймингов
        discovery_delays = discovery_timing.get('timing_analysis', {}).get('suspicious_delays', 0)
        service_delays = service_timing.get('timing_analysis', {}).get('suspicious_delays', 0)
        
        if discovery_delays > 0 or service_delays > 0:
            recommendations.append(f"⚠️ Обнаружены подозрительные задержки: Discovery={discovery_delays}, Service={service_delays}")
        
        return recommendations

def main():
    """Основная функция"""
    print("🔍 ИССЛЕДОВАНИЕ ПРОБЛЕМ С BYPASS СИСТЕМОЙ")
    print("=" * 60)
    
    investigator = BypassProblemInvestigator()
    domain = "nnmclub.to"
    
    # 1. Тестирование эффективности атак
    print("\n1️⃣ ТЕСТИРОВАНИЕ ЭФФЕКТИВНОСТИ АТАК")
    attack_results = investigator.test_attack_effectiveness(domain)
    
    # 2. Анализ поведения DPI
    print("\n2️⃣ АНАЛИЗ ПОВЕДЕНИЯ DPI")
    dpi_analysis = investigator.analyze_dpi_behavior(domain)
    
    # 3. Исследование таймингов пакетов
    print("\n3️⃣ ИССЛЕДОВАНИЕ ТАЙМИНГОВ ПАКЕТОВ")
    discovery_pcap = "pcap/nnmclub.to_discovery_20251217_154756.pcap"
    service_pcap = "pcap/nnmclub.to_service_20251217_154828.pcap"
    
    discovery_timing = investigator.investigate_packet_timing(discovery_pcap)
    service_timing = investigator.investigate_packet_timing(service_pcap)
    
    # 4. Генерация отчета
    print("\n4️⃣ ГЕНЕРАЦИЯ ОТЧЕТА")
    report_file, report = investigator.generate_investigation_report(
        attack_results, dpi_analysis, discovery_timing, service_timing
    )
    
    # Выводим рекомендации
    print(f"\n📊 РЕКОМЕНДАЦИИ:")
    for rec in report['recommendations']:
        print(f"   {rec}")
    
    print(f"\n💾 Полный отчет: {report_file}")

if __name__ == "__main__":
    main()