#!/usr/bin/env python3
"""
Log-PCAP Validator - Сопоставление логов тестирования с PCAP файлами
Проверяет что атаки в логах соответствуют пакетам в PCAP
"""
import sys
import os
import re
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from scapy.all import rdpcap, TCP, IP, Raw
from collections import defaultdict

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class LogPcapValidator:
    def __init__(self, log_file: str, pcap_dir: str):
        self.log_file = log_file
        self.pcap_dir = Path(pcap_dir)
        self.results = []
        
    def parse_log_strategies(self) -> List[Dict]:
        """Извлекает информацию о стратегиях из лога"""
        strategies = []
        
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        # Новый подход: ищем записи "Loading strategy" из UnifiedStrategyLoader
        # Формат: [DEBUG] core.unified_strategy_loader: Loading strategy: type=fake, attacks=['fake']
        for i, line in enumerate(lines):
            # Ищем загрузку стратегии
            if 'Loading strategy:' in line and 'type=' in line:
                strategy = {
                    'line_num': i + 1,
                    'line': line,
                    'type': None,
                    'attacks': [],
                    'params': {},
                    'timestamp': None,
                    'domain': 'www.googlevideo.com'  # Из контекста теста
                }
                
                # Извлекаем timestamp
                ts_match = re.search(r'(\d{2}:\d{2}:\d{2})', line)
                if ts_match:
                    strategy['timestamp'] = ts_match.group(1)
                
                # Извлекаем type
                type_match = re.search(r'type=(\w+)', line)
                if type_match:
                    strategy['type'] = type_match.group(1)
                
                # Извлекаем attacks
                attacks_match = re.search(r"attacks=\[([^\]]+)\]", line)
                if attacks_match:
                    attacks_str = attacks_match.group(1)
                    strategy['attacks'] = [
                        a.strip().strip('"\'') 
                        for a in attacks_str.split(',')
                    ]
                
                if strategy['type']:
                    strategies.append(strategy)
        
        return strategies
    
    def analyze_pcap(self, pcap_file: Path) -> Dict:
        """Анализирует PCAP файл и определяет примененную стратегию"""
        try:
            packets = rdpcap(str(pcap_file))
            
            analysis = {
                'file': pcap_file.name,
                'total_packets': len(packets),
                'tcp_packets': 0,
                'clienthello_packets': 0,
                'detected_strategy': None,
                'evidence': [],
                'packet_sizes': [],
                'ttl_values': set(),
                'has_fake_packets': False,
                'has_disorder': False,
                'has_split': False,
            }
            
            clienthello_packets = []
            
            for pkt in packets:
                if TCP in pkt:
                    analysis['tcp_packets'] += 1
                    
                    # Собираем TTL
                    if IP in pkt:
                        analysis['ttl_values'].add(pkt[IP].ttl)
                    
                    # Ищем ClientHello
                    if Raw in pkt:
                        payload = bytes(pkt[Raw].load)
                        
                        # TLS ClientHello signature: 16 03 (01|02|03)
                        if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
                            analysis['clienthello_packets'] += 1
                            clienthello_packets.append({
                                'size': len(payload),
                                'seq': pkt[TCP].seq if TCP in pkt else 0,
                                'ttl': pkt[IP].ttl if IP in pkt else 0,
                                'packet': pkt
                            })
                            analysis['packet_sizes'].append(len(payload))
            
            # Определяем стратегию по признакам
            if len(clienthello_packets) >= 1:
                # Проверяем на fake (низкий TTL)
                low_ttl_packets = [p for p in clienthello_packets if p['ttl'] < 10]
                if low_ttl_packets:
                    analysis['has_fake_packets'] = True
                    analysis['evidence'].append(f"Found {len(low_ttl_packets)} packets with TTL < 10")
                    analysis['detected_strategy'] = 'fake'
                
                # Проверяем на split (разные размеры) только если > 1 пакета
                if len(clienthello_packets) > 1:
                    if len(set(analysis['packet_sizes'])) > 1:
                        analysis['has_split'] = True
                        analysis['evidence'].append(f"Multiple packet sizes: {analysis['packet_sizes']}")
                    
                    # Проверяем на disorder (неправильный порядок seq)
                    seqs = [p['seq'] for p in clienthello_packets]
                    if seqs != sorted(seqs):
                        analysis['has_disorder'] = True
                        analysis['evidence'].append(f"Out-of-order sequences: {seqs}")
                    
                    # Определяем тип стратегии для множественных пакетов
                    if analysis['has_fake_packets'] and analysis['has_disorder']:
                        analysis['detected_strategy'] = 'fakeddisorder'
                    elif analysis['has_disorder']:
                        analysis['detected_strategy'] = 'disorder'
                    elif analysis['has_split']:
                        if len(clienthello_packets) > 2:
                            analysis['detected_strategy'] = 'multisplit'
                        else:
                            analysis['detected_strategy'] = 'split'
                
                # Если только 1 пакет и нет fake - возможно стратегия не применилась
                if len(clienthello_packets) == 1 and not analysis['has_fake_packets']:
                    analysis['detected_strategy'] = 'none'
                    analysis['evidence'].append("Single packet, no attack detected")
            
            return analysis
            
        except Exception as e:
            return {
                'file': pcap_file.name,
                'error': str(e),
                'detected_strategy': None
            }
    
    def match_log_to_pcap(self, strategy: Dict, pcap_analysis: Dict) -> Dict:
        """Сопоставляет стратегию из лога с PCAP анализом"""
        match = {
            'strategy_type': strategy['type'],
            'strategy_attacks': strategy.get('attacks', []),
            'detected_strategy': pcap_analysis.get('detected_strategy'),
            'match': False,
            'confidence': 0.0,
            'issues': []
        }
        
        expected_type = strategy['type']
        detected_type = pcap_analysis.get('detected_strategy')
        
        # Прямое совпадение типа
        if expected_type == detected_type:
            match['match'] = True
            match['confidence'] = 1.0
            return match
        
        # Проверяем attacks для combo стратегий
        if strategy.get('attacks'):
            attacks = strategy['attacks']
            
            # Проверяем каждую атаку
            detected_attacks = []
            if pcap_analysis.get('has_fake_packets'):
                detected_attacks.append('fake')
            if pcap_analysis.get('has_disorder'):
                detected_attacks.append('disorder')
            if pcap_analysis.get('has_split'):
                detected_attacks.append('split')
            
            # Сравниваем
            expected_set = set(attacks)
            detected_set = set(detected_attacks)
            
            if expected_set == detected_set:
                match['match'] = True
                match['confidence'] = 1.0
            elif expected_set & detected_set:  # Частичное совпадение
                match['match'] = True
                match['confidence'] = len(expected_set & detected_set) / len(expected_set)
                match['issues'].append(
                    f"Partial match: expected {attacks}, detected {detected_attacks}"
                )
            else:
                match['issues'].append(
                    f"No match: expected {attacks}, detected {detected_attacks}"
                )
        
        # Алиасы и варианты
        aliases = {
            'fakeddisorder': ['fake', 'disorder'],
            'fake_disorder': ['fake', 'disorder'],
            'seqovl': ['split', 'overlap'],
            'multisplit': ['split'],
            'multidisorder': ['disorder'],
        }
        
        if expected_type in aliases:
            expected_attacks = aliases[expected_type]
            if detected_type in expected_attacks:
                match['match'] = True
                match['confidence'] = 0.8
                match['issues'].append(
                    f"Alias match: {expected_type} -> {detected_type}"
                )
        
        return match
    
    def validate(self) -> Dict:
        """Выполняет полную валидацию"""
        print("="*60)
        print("LOG-PCAP VALIDATION")
        print("="*60)
        
        # 1. Парсим лог
        print(f"\n📄 Parsing log file: {self.log_file}")
        strategies = self.parse_log_strategies()
        print(f"   Found {len(strategies)} strategy tests in log")
        
        # 2. Анализируем PCAP файлы
        print(f"\n📦 Analyzing PCAP files in: {self.pcap_dir}")
        pcap_files = list(self.pcap_dir.glob("*.pcap"))
        print(f"   Found {len(pcap_files)} PCAP files")
        
        pcap_analyses = {}
        for pcap_file in pcap_files:
            print(f"   Analyzing: {pcap_file.name}")
            pcap_analyses[pcap_file.name] = self.analyze_pcap(pcap_file)
        
        # 3. Сопоставляем
        print(f"\n🔍 Matching strategies to PCAPs...")
        
        matches = []
        mismatches = []
        
        # Сортируем стратегии и PCAP по времени
        strategies_sorted = sorted(strategies, key=lambda s: s.get('timestamp', ''))
        pcap_files_sorted = sorted(pcap_files, key=lambda p: p.stat().st_mtime)
        
        # Простое сопоставление по порядку (стратегия N -> PCAP N)
        for idx, strategy in enumerate(strategies_sorted):
            if idx < len(pcap_files_sorted):
                pcap_file = pcap_files_sorted[idx]
                pcap_name = pcap_file.name
                pcap_analysis = pcap_analyses.get(pcap_name, {})
                
                match_result = self.match_log_to_pcap(strategy, pcap_analysis)
                
                match_entry = {
                    'strategy': strategy,
                    'pcap': pcap_name,
                    'pcap_analysis': pcap_analysis,
                    'match_result': match_result
                }
                
                if match_result['match']:
                    matches.append(match_entry)
                else:
                    mismatches.append(match_entry)
        
        # 4. Отчет
        print("\n" + "="*60)
        print("VALIDATION RESULTS")
        print("="*60)
        
        total = len(matches) + len(mismatches)
        if total > 0:
            match_rate = len(matches) / total * 100
            print(f"\n✅ Matches: {len(matches)} ({match_rate:.1f}%)")
            print(f"❌ Mismatches: {len(mismatches)} ({100-match_rate:.1f}%)")
        else:
            print("\n⚠️ No matches found")
        
        # Детали совпадений
        if matches:
            print("\n" + "-"*60)
            print("SUCCESSFUL MATCHES:")
            print("-"*60)
            for m in matches:
                strategy = m['strategy']
                pcap = m['pcap_analysis']
                result = m['match_result']
                
                print(f"\n✅ {m['pcap']}")
                print(f"   Strategy: {strategy['type']}")
                if strategy.get('attacks'):
                    print(f"   Attacks: {strategy['attacks']}")
                print(f"   Detected: {pcap.get('detected_strategy')}")
                print(f"   Confidence: {result['confidence']*100:.0f}%")
                print(f"   Evidence: {', '.join(pcap.get('evidence', []))}")
        
        # Детали несовпадений
        if mismatches:
            print("\n" + "-"*60)
            print("MISMATCHES (ТРЕБУЮТ ИСПРАВЛЕНИЯ):")
            print("-"*60)
            for m in mismatches:
                strategy = m['strategy']
                pcap = m['pcap_analysis']
                result = m['match_result']
                
                print(f"\n❌ {m['pcap']}")
                print(f"   Expected: {strategy['type']}")
                if strategy.get('attacks'):
                    print(f"   Expected attacks: {strategy['attacks']}")
                print(f"   Detected: {pcap.get('detected_strategy', 'NONE')}")
                print(f"   Issues: {', '.join(result['issues'])}")
                print(f"   Evidence: {', '.join(pcap.get('evidence', ['No evidence']))}")
                print(f"   Line in log: {strategy['line_num']}")
        
        return {
            'total_strategies': len(strategies),
            'total_pcaps': len(pcap_files),
            'matches': len(matches),
            'mismatches': len(mismatches),
            'match_rate': len(matches) / total * 100 if total > 0 else 0,
            'details': {
                'matches': matches,
                'mismatches': mismatches
            }
        }

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate log entries against PCAP files')
    parser.add_argument('--log', default='test_googlevideo_FIXED4.txt',
                       help='Log file to analyze')
    parser.add_argument('--pcap-dir', 
                       default=r'C:\Users\admin\AppData\Local\Temp\recon_pcap',
                       help='Directory containing PCAP files')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.log):
        print(f"❌ Log file not found: {args.log}")
        return 1
    
    if not os.path.exists(args.pcap_dir):
        print(f"❌ PCAP directory not found: {args.pcap_dir}")
        return 1
    
    validator = LogPcapValidator(args.log, args.pcap_dir)
    results = validator.validate()
    
    print("\n" + "="*60)
    if results['match_rate'] >= 80:
        print("🎉 ОТЛИЧНЫЙ РЕЗУЛЬТАТ! СИСТЕМА РАБОТАЕТ КОРРЕКТНО!")
        print(f"Match rate: {results['match_rate']:.1f}%")
        return 0
    elif results['match_rate'] >= 70:
        print("✅ ХОРОШИЙ РЕЗУЛЬТАТ! СИСТЕМА РАБОТАЕТ!")
        print(f"Match rate: {results['match_rate']:.1f}%")
        print("\nНесовпадения могут быть из-за:")
        print("  - PCAP capture timing")
        print("  - Недетектируемых атак (payload_encryption)")
        print("\nСмотрите VALIDATION_SUCCESS.md для деталей.")
        return 1
    elif results['match_rate'] >= 60:
        print("⚠️ ПРИЕМЛЕМЫЙ РЕЗУЛЬТАТ")
        print(f"Match rate: {results['match_rate']:.1f}%")
        print("\nРекомендуется диагностика несовпадений.")
        return 1
    else:
        print("❌ НИЗКИЙ MATCH RATE - ТРЕБУЕТСЯ ДИАГНОСТИКА")
        print(f"Match rate: {results['match_rate']:.1f}%")
        return 2

if __name__ == "__main__":
    sys.exit(main())
