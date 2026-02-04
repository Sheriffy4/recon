#!/usr/bin/env python3
"""
Верификация применения DPI-атак: сопоставление стратегий из лога с пакетами в PCAP
"""

import re
import json
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

try:
    from scapy.all import rdpcap, IP, TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy не установлен. Установите: pip install scapy")

@dataclass
class StrategyTest:
    """Тест стратегии из лога."""
    test_number: int
    strategy_name: str
    session_id: str
    attacks: List[str]
    params: Dict[str, Any]
    start_time: Optional[str] = None
    result: str = "UNKNOWN"

@dataclass
class AttackFlow:
    """Поток пакетов для одной атаки."""
    session_id: str
    packets: List[Any]  # Scapy packets
    start_time: float
    end_time: float
    attack_indicators: Dict[str, Any]

class DPIAttackVerifier:
    """Верификатор применения DPI-атак."""
    
    def __init__(self):
        self.target_ip = "142.250.74.100"  # googlevideo.com
        self.target_domain = "www.googlevideo.com"
        
    def parse_strategy_tests(self, log_file: str) -> List[StrategyTest]:
        """Парсит тесты стратегий из лога."""
        strategies = []
        
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Ищем начало каждого теста
        test_pattern = r'🧪 Testing strategy (\d+)/\d+: ([^\n]+)'
        session_pattern = r'🚀 Starting test: \[([^\]]+)\] for \[([^\]]+)\] \(session: ([^)]+)\)'
        convert_pattern = r'\[CONVERT\] Конвертация стратегии: attacks=\[([^\]]+)\], params=({[^}]+})'
        recipe_pattern = r'📋 Creating recipe with (\d+) attacks'
        attack_detail_pattern = r'➤ Attack: (\w+) \(order=\d+\)\s+Params: ({[^}]+})'
        result_pattern = r'❌ Test FAIL: ([^\n]+)|✅ Test SUCCESS: ([^\n]+)'
        
        # Находим все тесты
        test_matches = re.findall(test_pattern, content)
        session_matches = re.findall(session_pattern, content)
        
        print(f"Найдено {len(test_matches)} тестов стратегий")
        print(f"Найдено {len(session_matches)} сессий")
        
        # Разбиваем лог на секции по тестам
        test_sections = re.split(r'🧪 Testing strategy \d+/\d+:', content)[1:]  # Убираем первую пустую секцию
        
        for i, (test_num, strategy_name) in enumerate(test_matches):
            if i >= len(test_sections):
                break
                
            section = test_sections[i]
            
            # Ищем session_id в секции
            session_match = re.search(r'session: ([^)]+)\)', section)
            session_id = session_match.group(1) if session_match else f"unknown_{i}"
            
            # Извлекаем параметры атак
            attacks = []
            params = {}
            
            # Ищем конвертацию стратегии
            convert_match = re.search(convert_pattern, section)
            if convert_match:
                attacks_str = convert_match.group(1)
                params_str = convert_match.group(2)
                
                # Парсим атаки
                attacks = [a.strip().strip("'\"") for a in attacks_str.split(',')]
                
                # Парсим параметры
                try:
                    params = eval(params_str)  # Осторожно, но для отладки подойдет
                except:
                    params = {}
            
            # Ищем детали рецепта атак
            recipe_attacks = re.findall(attack_detail_pattern, section)
            attack_details = {}
            for attack_name, attack_params in recipe_attacks:
                try:
                    attack_details[attack_name] = eval(attack_params)
                except:
                    attack_details[attack_name] = {}
            
            # Определяем результат
            result = "FAIL"  # По умолчанию, так как все тесты в логе неудачны
            
            strategy_test = StrategyTest(
                test_number=int(test_num),
                strategy_name=strategy_name,
                session_id=session_id,
                attacks=attacks,
                params=params,
                result=result
            )
            
            # Добавляем детали атак
            if attack_details:
                strategy_test.params['attack_details'] = attack_details
            
            strategies.append(strategy_test)
        
        return strategies
    
    def group_packets_by_flows(self, pcap_file: str) -> Dict[str, List[Any]]:
        """Группирует пакеты по потокам (по времени и характеристикам)."""
        if not SCAPY_AVAILABLE:
            return {}
        
        try:
            packets = rdpcap(pcap_file)
            googlevideo_packets = []
            
            # Фильтруем пакеты к googlevideo.com
            for pkt in packets:
                if IP in pkt and TCP in pkt and pkt[IP].dst == self.target_ip:
                    googlevideo_packets.append(pkt)
            
            print(f"Найдено {len(googlevideo_packets)} пакетов к {self.target_ip}")
            
            if not googlevideo_packets:
                return {}
            
            # Группируем по временным окнам (предполагаем, что каждый тест ~10-15 секунд)
            flows = {}
            current_flow = []
            flow_id = 1
            
            for i, pkt in enumerate(googlevideo_packets):
                if i == 0:
                    current_flow = [pkt]
                    continue
                
                # Если пауза больше 10 секунд - новый поток
                time_diff = float(pkt.time) - float(googlevideo_packets[i-1].time)
                if time_diff > 10.0:
                    if current_flow:
                        flows[f"flow_{flow_id}"] = current_flow
                        flow_id += 1
                    current_flow = [pkt]
                else:
                    current_flow.append(pkt)
            
            # Добавляем последний поток
            if current_flow:
                flows[f"flow_{flow_id}"] = current_flow
            
            print(f"Сгруппировано в {len(flows)} потоков")
            return flows
            
        except Exception as e:
            print(f"Ошибка чтения PCAP: {e}")
            return {}
    
    def analyze_attack_indicators(self, packets: List[Any], expected_attacks: List[str], 
                                 params: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует индикаторы атак в пакетах."""
        indicators = {
            'total_packets': len(packets),
            'attack_evidence': {},
            'packet_analysis': {},
            'verdict': 'NO_ATTACK_DETECTED'
        }
        
        if not packets:
            return indicators
        
        # Анализируем каждый тип атаки
        for attack in expected_attacks:
            attack_clean = attack.replace('attacktype.', '').replace("'", "")
            indicators['attack_evidence'][attack_clean] = self._analyze_specific_attack(
                packets, attack_clean, params
            )
        
        # Общий анализ пакетов
        indicators['packet_analysis'] = {
            'ttl_values': list(set(pkt[IP].ttl for pkt in packets if IP in pkt)),
            'tcp_flags': list(set(pkt[TCP].flags for pkt in packets if TCP in pkt)),
            'packet_sizes': [len(pkt) for pkt in packets],
            'payload_sizes': [len(pkt[TCP].payload) if TCP in pkt and pkt[TCP].payload else 0 for pkt in packets],
            'sequence_numbers': [pkt[TCP].seq for pkt in packets if TCP in pkt],
            'time_intervals': self._calculate_time_intervals(packets)
        }
        
        # Определяем общий вердикт
        attack_detected = any(
            evidence.get('detected', False) 
            for evidence in indicators['attack_evidence'].values()
        )
        
        indicators['verdict'] = 'ATTACK_DETECTED' if attack_detected else 'NO_ATTACK_DETECTED'
        
        return indicators
    
    def _analyze_specific_attack(self, packets: List[Any], attack_type: str, 
                                params: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует конкретный тип атаки."""
        evidence = {
            'detected': False,
            'confidence': 0.0,
            'details': {},
            'expected_vs_actual': {}
        }
        
        if attack_type == 'disorder':
            evidence = self._analyze_disorder_attack(packets, params)
        elif attack_type == 'multidisorder':
            evidence = self._analyze_multidisorder_attack(packets, params)
        elif attack_type == 'ttl':
            evidence = self._analyze_ttl_attack(packets, params)
        elif attack_type == 'split' or attack_type == 'multisplit':
            evidence = self._analyze_split_attack(packets, params)
        elif attack_type == 'fake':
            evidence = self._analyze_fake_attack(packets, params)
        elif attack_type == 'seqovl':
            evidence = self._analyze_seqovl_attack(packets, params)
        else:
            evidence['details'] = f"Анализ для {attack_type} не реализован"
        
        return evidence
    
    def _analyze_disorder_attack(self, packets: List[Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует атаку disorder (переупорядочивание пакетов)."""
        evidence = {
            'detected': False,
            'confidence': 0.0,
            'details': {},
            'expected_vs_actual': {}
        }
        
        if len(packets) < 2:
            evidence['details'] = "Недостаточно пакетов для анализа disorder"
            return evidence
        
        # Ожидаемые параметры
        expected_method = params.get('attack_details', {}).get('disorder', {}).get('disorder_method', 'reverse')
        expected_count = params.get('disorder_count', 1)
        
        # Анализируем последовательность пакетов
        tcp_packets = [pkt for pkt in packets if TCP in pkt and pkt[TCP].payload]
        
        if len(tcp_packets) < 2:
            evidence['details'] = "Нет TCP пакетов с payload для анализа"
            return evidence
        
        # Проверяем порядок sequence numbers
        seq_numbers = [pkt[TCP].seq for pkt in tcp_packets]
        is_ordered = all(seq_numbers[i] <= seq_numbers[i+1] for i in range(len(seq_numbers)-1))
        
        evidence['expected_vs_actual'] = {
            'expected_method': expected_method,
            'expected_count': expected_count,
            'actual_packets': len(tcp_packets),
            'sequence_ordered': is_ordered,
            'sequence_numbers': seq_numbers[:5]  # Первые 5 для примера
        }
        
        # Disorder должен нарушать порядок
        if not is_ordered:
            evidence['detected'] = True
            evidence['confidence'] = 0.8
            evidence['details'] = f"Обнаружено нарушение порядка пакетов (метод: {expected_method})"
        else:
            evidence['detected'] = False
            evidence['confidence'] = 0.0
            evidence['details'] = "Пакеты идут в правильном порядке - disorder не применен"
        
        return evidence
    
    def _analyze_multidisorder_attack(self, packets: List[Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует атаку multidisorder."""
        evidence = {
            'detected': False,
            'confidence': 0.0,
            'details': {},
            'expected_vs_actual': {}
        }
        
        # Multidisorder - множественное переупорядочивание
        tcp_packets = [pkt for pkt in packets if TCP in pkt and pkt[TCP].payload]
        
        if len(tcp_packets) < 3:
            evidence['details'] = "Недостаточно пакетов для multidisorder"
            return evidence
        
        expected_count = params.get('disorder_count', 1)
        
        # Ищем признаки множественного переупорядочивания
        seq_numbers = [pkt[TCP].seq for pkt in tcp_packets]
        
        # Подсчитываем "скачки" в последовательности
        jumps = 0
        for i in range(1, len(seq_numbers)):
            if seq_numbers[i] < seq_numbers[i-1]:
                jumps += 1
        
        evidence['expected_vs_actual'] = {
            'expected_disorder_count': expected_count,
            'actual_sequence_jumps': jumps,
            'total_tcp_packets': len(tcp_packets)
        }
        
        if jumps > 0:
            evidence['detected'] = True
            evidence['confidence'] = min(0.9, jumps * 0.3)
            evidence['details'] = f"Обнаружено {jumps} нарушений порядка последовательности"
        else:
            evidence['details'] = "Нарушений порядка не обнаружено"
        
        return evidence
    
    def _analyze_ttl_attack(self, packets: List[Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует TTL атаку."""
        evidence = {
            'detected': False,
            'confidence': 0.0,
            'details': {},
            'expected_vs_actual': {}
        }
        
        ip_packets = [pkt for pkt in packets if IP in pkt]
        if not ip_packets:
            evidence['details'] = "Нет IP пакетов для анализа TTL"
            return evidence
        
        ttl_values = [pkt[IP].ttl for pkt in ip_packets]
        unique_ttls = list(set(ttl_values))
        min_ttl = min(ttl_values)
        
        # TTL атака должна использовать низкие значения (1-4)
        expected_low_ttl = any(ttl <= 4 for ttl in ttl_values)
        
        evidence['expected_vs_actual'] = {
            'expected_low_ttl': "1-4",
            'actual_ttl_values': unique_ttls,
            'min_ttl': min_ttl,
            'all_ttl_values': ttl_values[:10]  # Первые 10
        }
        
        if expected_low_ttl:
            evidence['detected'] = True
            evidence['confidence'] = 0.9
            evidence['details'] = f"Обнаружены низкие TTL значения: {unique_ttls}"
        else:
            evidence['detected'] = False
            evidence['details'] = f"TTL атака не обнаружена. Все TTL >= 5: {unique_ttls}"
        
        return evidence
    
    def _analyze_split_attack(self, packets: List[Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует split/multisplit атаку."""
        evidence = {
            'detected': False,
            'confidence': 0.0,
            'details': {},
            'expected_vs_actual': {}
        }
        
        tcp_packets = [pkt for pkt in packets if TCP in pkt and pkt[TCP].payload]
        
        if not tcp_packets:
            evidence['details'] = "Нет TCP пакетов с payload"
            return evidence
        
        payload_sizes = [len(pkt[TCP].payload) for pkt in tcp_packets]
        avg_payload_size = sum(payload_sizes) / len(payload_sizes)
        small_packets = [size for size in payload_sizes if size < 100]
        
        split_pos = params.get('split_pos', 1)
        
        evidence['expected_vs_actual'] = {
            'expected_split_pos': split_pos,
            'actual_avg_payload_size': avg_payload_size,
            'small_packets_count': len(small_packets),
            'total_packets': len(tcp_packets),
            'payload_sizes': payload_sizes[:10]
        }
        
        # Split должен создавать много мелких пакетов
        if len(small_packets) > len(tcp_packets) * 0.5:
            evidence['detected'] = True
            evidence['confidence'] = 0.7
            evidence['details'] = f"Обнаружена фрагментация: {len(small_packets)} мелких пакетов из {len(tcp_packets)}"
        else:
            evidence['details'] = f"Фрагментация не обнаружена. Средний размер payload: {avg_payload_size:.1f}"
        
        return evidence
    
    def _analyze_fake_attack(self, packets: List[Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует fake атаку."""
        evidence = {
            'detected': False,
            'confidence': 0.0,
            'details': {},
            'expected_vs_actual': {}
        }
        
        # Fake атака должна создавать дополнительные пакеты
        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        
        # Ищем дублированные или подозрительные пакеты
        seq_numbers = [pkt[TCP].seq for pkt in tcp_packets]
        duplicate_seqs = len(seq_numbers) - len(set(seq_numbers))
        
        evidence['expected_vs_actual'] = {
            'total_packets': len(tcp_packets),
            'duplicate_sequences': duplicate_seqs,
            'unique_sequences': len(set(seq_numbers))
        }
        
        if duplicate_seqs > 0:
            evidence['detected'] = True
            evidence['confidence'] = 0.6
            evidence['details'] = f"Обнаружены дублированные sequence numbers: {duplicate_seqs}"
        else:
            evidence['details'] = "Дублированных пакетов не обнаружено"
        
        return evidence
    
    def _analyze_seqovl_attack(self, packets: List[Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует seqovl атаку (перекрывающиеся последовательности)."""
        evidence = {
            'detected': False,
            'confidence': 0.0,
            'details': {},
            'expected_vs_actual': {}
        }
        
        tcp_packets = [pkt for pkt in packets if TCP in pkt and pkt[TCP].payload]
        
        if len(tcp_packets) < 2:
            evidence['details'] = "Недостаточно пакетов для анализа seqovl"
            return evidence
        
        # Ищем перекрывающиеся последовательности
        overlaps = 0
        for i in range(len(tcp_packets) - 1):
            seq1 = tcp_packets[i][TCP].seq
            len1 = len(tcp_packets[i][TCP].payload)
            seq2 = tcp_packets[i + 1][TCP].seq
            
            # Проверяем перекрытие
            if seq2 < seq1 + len1:
                overlaps += 1
        
        evidence['expected_vs_actual'] = {
            'total_packets': len(tcp_packets),
            'overlapping_sequences': overlaps
        }
        
        if overlaps > 0:
            evidence['detected'] = True
            evidence['confidence'] = 0.8
            evidence['details'] = f"Обнаружено {overlaps} перекрывающихся последовательностей"
        else:
            evidence['details'] = "Перекрывающихся последовательностей не обнаружено"
        
        return evidence
    
    def _calculate_time_intervals(self, packets: List[Any]) -> List[float]:
        """Вычисляет интервалы между пакетами."""
        if len(packets) < 2:
            return []
        
        intervals = []
        for i in range(1, len(packets)):
            interval = float(packets[i].time) - float(packets[i-1].time)
            intervals.append(interval)
        
        return intervals
    
    def generate_verification_report(self, strategies: List[StrategyTest], 
                                   flows: Dict[str, List[Any]]) -> str:
        """Генерирует отчет верификации."""
        report = []
        report.append("# Верификация применения DPI-атак")
        report.append(f"Домен: {self.target_domain}")
        report.append(f"Целевой IP: {self.target_ip}")
        report.append(f"Время анализа: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        report.append("## Общая статистика")
        report.append(f"- Протестировано стратегий: {len(strategies)}")
        report.append(f"- Потоков в PCAP: {len(flows)}")
        report.append("")
        
        # Анализируем каждую стратегию
        attacks_detected = 0
        attacks_failed = 0
        
        for i, strategy in enumerate(strategies):
            flow_key = f"flow_{i+1}" if f"flow_{i+1}" in flows else list(flows.keys())[i] if i < len(flows) else None
            
            report.append(f"## Стратегия {strategy.test_number}: {strategy.strategy_name}")
            report.append(f"- **Session ID**: {strategy.session_id}")
            report.append(f"- **Атаки**: {', '.join(strategy.attacks)}")
            report.append(f"- **Параметры**: {strategy.params}")
            
            if flow_key and flow_key in flows:
                flow_packets = flows[flow_key]
                indicators = self.analyze_attack_indicators(flow_packets, strategy.attacks, strategy.params)
                
                report.append(f"- **Пакетов в потоке**: {indicators['total_packets']}")
                report.append(f"- **Вердикт**: {indicators['verdict']}")
                
                if indicators['verdict'] == 'ATTACK_DETECTED':
                    attacks_detected += 1
                    report.append("  ✅ **АТАКА ПРИМЕНЕНА**")
                else:
                    attacks_failed += 1
                    report.append("  ❌ **АТАКА НЕ ПРИМЕНЕНА**")
                
                # Детали по каждой атаке
                for attack, evidence in indicators['attack_evidence'].items():
                    report.append(f"  - **{attack}**: {evidence['details']}")
                    if evidence.get('expected_vs_actual'):
                        report.append(f"    - Ожидалось vs Фактически: {evidence['expected_vs_actual']}")
                
                # Анализ пакетов
                packet_analysis = indicators['packet_analysis']
                report.append(f"  - **TTL значения**: {packet_analysis['ttl_values']}")
                report.append(f"  - **Размеры payload**: мин={min(packet_analysis['payload_sizes']) if packet_analysis['payload_sizes'] else 0}, макс={max(packet_analysis['payload_sizes']) if packet_analysis['payload_sizes'] else 0}")
                
            else:
                attacks_failed += 1
                report.append("  ❌ **ПОТОК НЕ НАЙДЕН В PCAP**")
            
            report.append("")
        
        # Итоговая статистика
        report.append("## Итоговая статистика")
        report.append(f"- ✅ **Атаки применены**: {attacks_detected}/{len(strategies)} ({attacks_detected/len(strategies)*100:.1f}%)")
        report.append(f"- ❌ **Атаки не применены**: {attacks_failed}/{len(strategies)} ({attacks_failed/len(strategies)*100:.1f}%)")
        report.append("")
        
        if attacks_detected == 0:
            report.append("## 🚨 КРИТИЧЕСКАЯ ПРОБЛЕМА")
            report.append("**НИ ОДНА АТАКА НЕ ПРИМЕНИЛАСЬ КОРРЕКТНО**")
            report.append("")
            report.append("Возможные причины:")
            report.append("1. Проблемы с WinDivert или правами администратора")
            report.append("2. Ошибки в коде применения атак после модернизации")
            report.append("3. Проблемы с фильтрацией пакетов")
            report.append("4. Discovery mode переопределяет стратегии")
            report.append("")
        elif attacks_detected < len(strategies) * 0.5:
            report.append("## ⚠️ СЕРЬЕЗНАЯ ПРОБЛЕМА")
            report.append("**БОЛЬШИНСТВО АТАК НЕ ПРИМЕНЯЕТСЯ**")
            report.append("")
            report.append("Требуется детальная диагностика кода применения атак")
            report.append("")
        else:
            report.append("## ✅ АТАКИ ПРИМЕНЯЮТСЯ")
            report.append("Большинство атак работает корректно")
            report.append("")
        
        return "\n".join(report)
    
    def verify_attacks(self, log_file: str, pcap_file: str) -> str:
        """Основной метод верификации атак."""
        print("🔍 Верификация применения DPI-атак...")
        
        # Парсим стратегии из лога
        strategies = self.parse_strategy_tests(log_file)
        if not strategies:
            return "❌ Не найдено стратегий в логе"
        
        print(f"Найдено {len(strategies)} стратегий для верификации")
        
        # Группируем пакеты по потокам
        flows = self.group_packets_by_flows(pcap_file)
        if not flows:
            return "❌ Не найдено потоков в PCAP"
        
        print(f"Найдено {len(flows)} потоков в PCAP")
        
        # Генерируем отчет
        report = self.generate_verification_report(strategies, flows)
        
        # Сохраняем отчет
        report_file = f"dpi_attack_verification_{int(time.time())}.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"📄 Отчет верификации сохранен в {report_file}")
        return report

def main():
    """Основная функция."""
    verifier = DPIAttackVerifier()
    report = verifier.verify_attacks("test_new.txt", "test_new.pcap")
    
    print("\n" + "="*70)
    print("ВЕРИФИКАЦИЯ ПРИМЕНЕНИЯ DPI-АТАК")
    print("="*70)
    print(report)

if __name__ == "__main__":
    main()