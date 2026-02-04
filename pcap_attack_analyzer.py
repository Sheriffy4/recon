#!/usr/bin/env python3
"""
Детальный анализатор PCAP файлов для проверки атак
Использует tshark для глубокого анализа пакетов
"""

import os
import subprocess
import json
import sys
from pathlib import Path
from datetime import datetime

class PCAPAttackAnalyzer:
    """Анализатор атак в PCAP файлах"""
    
    def __init__(self):
        self.tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
        if not os.path.exists(self.tshark_path):
            raise FileNotFoundError(f"tshark не найден: {self.tshark_path}")
    
    def analyze_tcp_attacks(self, pcap_file):
        """Анализирует TCP атаки в PCAP"""
        print("🔍 Анализ TCP атак...")
        
        attacks_found = {
            'split_attacks': [],
            'disorder_attacks': [],
            'fake_packets': [],
            'ttl_manipulation': [],
            'window_manipulation': []
        }
        
        try:
            # Поиск split атак (фрагментированные TCP пакеты)
            split_cmd = [
                self.tshark_path, "-r", pcap_file,
                "-Y", "tcp.len < 100 and tcp.len > 0",  # Маленькие TCP пакеты
                "-T", "fields",
                "-e", "frame.number",
                "-e", "ip.src", "-e", "ip.dst",
                "-e", "tcp.srcport", "-e", "tcp.dstport",
                "-e", "tcp.len", "-e", "tcp.seq"
            ]
            
            result = subprocess.run(split_cmd, capture_output=True, text=True, timeout=30)
            if result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 7:
                            attacks_found['split_attacks'].append({
                                'frame': parts[0],
                                'src': parts[1], 'dst': parts[2],
                                'sport': parts[3], 'dport': parts[4],
                                'length': parts[5], 'seq': parts[6]
                            })
            
            # Поиск disorder атак (нарушение порядка пакетов)
            disorder_cmd = [
                self.tshark_path, "-r", pcap_file,
                "-Y", "tcp.analysis.out_of_order",
                "-T", "fields",
                "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
                "-e", "tcp.seq", "-e", "tcp.analysis.out_of_order"
            ]
            
            result = subprocess.run(disorder_cmd, capture_output=True, text=True, timeout=30)
            if result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 4:
                            attacks_found['disorder_attacks'].append({
                                'frame': parts[0],
                                'src': parts[1], 'dst': parts[2],
                                'seq': parts[3]
                            })
            
            # Поиск fake пакетов (дублированные или поддельные)
            fake_cmd = [
                self.tshark_path, "-r", pcap_file,
                "-Y", "tcp.analysis.duplicate_ack or tcp.analysis.retransmission",
                "-T", "fields",
                "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
                "-e", "tcp.analysis.duplicate_ack", "-e", "tcp.analysis.retransmission"
            ]
            
            result = subprocess.run(fake_cmd, capture_output=True, text=True, timeout=30)
            if result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            attacks_found['fake_packets'].append({
                                'frame': parts[0],
                                'src': parts[1], 'dst': parts[2],
                                'type': 'duplicate_ack' if len(parts) > 3 and parts[3] else 'retransmission'
                            })
            
            # Поиск TTL манипуляций
            ttl_cmd = [
                self.tshark_path, "-r", pcap_file,
                "-T", "fields",
                "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-e", "ip.ttl"
            ]
            
            result = subprocess.run(ttl_cmd, capture_output=True, text=True, timeout=30)
            if result.stdout.strip():
                ttl_values = {}
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 4:
                            src_dst = f"{parts[1]}->{parts[2]}"
                            ttl = parts[3]
                            if src_dst not in ttl_values:
                                ttl_values[src_dst] = []
                            ttl_values[src_dst].append((parts[0], ttl))
                
                # Ищем изменения TTL
                for src_dst, values in ttl_values.items():
                    if len(set(v[1] for v in values)) > 1:  # Разные TTL
                        attacks_found['ttl_manipulation'].append({
                            'connection': src_dst,
                            'ttl_changes': values
                        })
            
        except Exception as e:
            print(f"   ❌ Ошибка анализа TCP: {e}")
        
        return attacks_found
    
    def analyze_tls_attacks(self, pcap_file, domain):
        """Анализирует TLS/SSL атаки"""
        print("🔒 Анализ TLS атак...")
        
        tls_attacks = {
            'sni_manipulation': [],
            'tls_fragmentation': [],
            'handshake_manipulation': []
        }
        
        try:
            # Анализ SNI
            sni_cmd = [
                self.tshark_path, "-r", pcap_file,
                "-Y", "tls.handshake.extensions_server_name",
                "-T", "fields",
                "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
                "-e", "tls.handshake.extensions_server_name"
            ]
            
            result = subprocess.run(sni_cmd, capture_output=True, text=True, timeout=30)
            if result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 4:
                            sni = parts[3]
                            if sni != domain:  # SNI не совпадает с доменом
                                tls_attacks['sni_manipulation'].append({
                                    'frame': parts[0],
                                    'src': parts[1], 'dst': parts[2],
                                    'sni': sni, 'expected': domain
                                })
            
            # Анализ фрагментации TLS
            frag_cmd = [
                self.tshark_path, "-r", pcap_file,
                "-Y", "tls and tcp.len < 200",  # Маленькие TLS пакеты
                "-T", "fields",
                "-e", "frame.number", "-e", "tcp.len", "-e", "tls.record.length"
            ]
            
            result = subprocess.run(frag_cmd, capture_output=True, text=True, timeout=30)
            if result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            tls_attacks['tls_fragmentation'].append({
                                'frame': parts[0],
                                'tcp_len': parts[1],
                                'tls_len': parts[2]
                            })
            
        except Exception as e:
            print(f"   ❌ Ошибка анализа TLS: {e}")
        
        return tls_attacks
    
    def analyze_http_attacks(self, pcap_file, domain):
        """Анализирует HTTP атаки"""
        print("🌐 Анализ HTTP атак...")
        
        http_attacks = {
            'header_manipulation': [],
            'method_manipulation': [],
            'host_header_attacks': []
        }
        
        try:
            # Анализ HTTP заголовков
            http_cmd = [
                self.tshark_path, "-r", pcap_file,
                "-Y", f"http.host == \"{domain}\"",
                "-T", "fields",
                "-e", "frame.number", "-e", "http.request.method",
                "-e", "http.host", "-e", "http.user_agent"
            ]
            
            result = subprocess.run(http_cmd, capture_output=True, text=True, timeout=30)
            if result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            http_attacks['header_manipulation'].append({
                                'frame': parts[0],
                                'method': parts[1] if len(parts) > 1 else '',
                                'host': parts[2] if len(parts) > 2 else '',
                                'user_agent': parts[3] if len(parts) > 3 else ''
                            })
            
        except Exception as e:
            print(f"   ❌ Ошибка анализа HTTP: {e}")
        
        return http_attacks
    
    def generate_attack_summary(self, tcp_attacks, tls_attacks, http_attacks):
        """Генерирует сводку найденных атак"""
        summary = {
            'total_attacks': 0,
            'attack_types': {},
            'confidence_score': 0.0
        }
        
        # Подсчитываем атаки
        for category, attacks in tcp_attacks.items():
            if attacks:
                summary['attack_types'][category] = len(attacks)
                summary['total_attacks'] += len(attacks)
        
        for category, attacks in tls_attacks.items():
            if attacks:
                summary['attack_types'][category] = len(attacks)
                summary['total_attacks'] += len(attacks)
        
        for category, attacks in http_attacks.items():
            if attacks:
                summary['attack_types'][category] = len(attacks)
                summary['total_attacks'] += len(attacks)
        
        # Вычисляем уверенность
        if summary['total_attacks'] > 0:
            # Больше атак = выше уверенность в том, что система работает
            summary['confidence_score'] = min(1.0, summary['total_attacks'] / 10.0)
        
        return summary
    
    def analyze_pcap_comprehensive(self, pcap_file, domain):
        """Комплексный анализ PCAP файла"""
        if not os.path.exists(pcap_file):
            return {'error': f'PCAP файл не найден: {pcap_file}'}
        
        if os.path.getsize(pcap_file) == 0:
            return {'error': 'PCAP файл пуст'}
        
        print(f"\n📊 АНАЛИЗ PCAP: {os.path.basename(pcap_file)}")
        print(f"🎯 Домен: {domain}")
        print("-" * 50)
        
        # Базовая информация
        basic_info = self.get_basic_pcap_info(pcap_file)
        
        # Анализ атак
        tcp_attacks = self.analyze_tcp_attacks(pcap_file)
        tls_attacks = self.analyze_tls_attacks(pcap_file, domain)
        http_attacks = self.analyze_http_attacks(pcap_file, domain)
        
        # Сводка
        summary = self.generate_attack_summary(tcp_attacks, tls_attacks, http_attacks)
        
        result = {
            'pcap_file': pcap_file,
            'domain': domain,
            'basic_info': basic_info,
            'tcp_attacks': tcp_attacks,
            'tls_attacks': tls_attacks,
            'http_attacks': http_attacks,
            'summary': summary,
            'timestamp': datetime.now().isoformat()
        }
        
        # Выводим результаты
        print(f"\n📈 РЕЗУЛЬТАТЫ АНАЛИЗА:")
        print(f"Всего пакетов: {basic_info.get('total_packets', 0)}")
        print(f"Найдено атак: {summary['total_attacks']}")
        print(f"Уверенность: {summary['confidence_score']:.2f}")
        
        if summary['attack_types']:
            print(f"\nТипы атак:")
            for attack_type, count in summary['attack_types'].items():
                print(f"  {attack_type}: {count}")
        
        return result
    
    def get_basic_pcap_info(self, pcap_file):
        """Получает базовую информацию о PCAP файле"""
        try:
            # Общая статистика
            info_cmd = [
                self.tshark_path, "-r", pcap_file, "-q", "-z", "io,stat,0"
            ]
            
            result = subprocess.run(info_cmd, capture_output=True, text=True, timeout=30)
            
            # Подсчет пакетов
            count_cmd = [
                self.tshark_path, "-r", pcap_file, "-T", "fields", "-e", "frame.number"
            ]
            
            count_result = subprocess.run(count_cmd, capture_output=True, text=True, timeout=30)
            packet_count = len([line for line in count_result.stdout.strip().split('\n') if line])
            
            return {
                'file_size': os.path.getsize(pcap_file),
                'total_packets': packet_count,
                'statistics': result.stdout
            }
            
        except Exception as e:
            return {'error': f'Ошибка получения информации: {e}'}

def main():
    """Основная функция"""
    
    if len(sys.argv) < 3:
        print("Использование: python pcap_attack_analyzer.py <pcap_file> <domain>")
        print("Пример: python pcap_attack_analyzer.py pcap/youtube.com_discovery.pcap youtube.com")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    domain = sys.argv[2]
    
    try:
        analyzer = PCAPAttackAnalyzer()
        result = analyzer.analyze_pcap_comprehensive(pcap_file, domain)
        
        # Сохраняем результат
        output_file = f"reports/pcap_analysis_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        Path("reports").mkdir(exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Результат сохранен: {output_file}")
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")

if __name__ == "__main__":
    main()