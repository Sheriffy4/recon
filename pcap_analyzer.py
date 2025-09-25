# pcap_analyzer.py
import struct
import dpkt
import os
import socket
from typing import List, Dict, Tuple, Optional
import json
from datetime import datetime

class PCAPAnalyzer:
    """Анализатор PCAP для сравнения с эталонным zapret.pcap"""
    
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.packets = []
        self.tls_flows = {}
        
    def analyze(self) -> Dict:
        """Полный анализ PCAP файла"""
        with open(self.pcap_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                self._process_packet(ts, buf)
        
        return self._generate_report()
    
    def _process_packet(self, ts: float, buf: bytes):
        """Обработка одного пакета"""
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                return
                
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                return
                
            tcp = ip.data
            
            # Ключ потока
            flow_key = (
                socket.inet_ntoa(ip.src),
                tcp.sport,
                socket.inet_ntoa(ip.dst),
                tcp.dport
            )
            
            # Анализ TLS ClientHello
            if tcp.dport == 443 and len(tcp.data) > 5:
                if tcp.data[0] == 0x16 and tcp.data[5] == 0x01:
                    if flow_key not in self.tls_flows:
                        self.tls_flows[flow_key] = {
                            'clienthello_ts': ts,
                            'segments': [],
                            'strategy_detected': None
                        }
                    
            # Сохраняем все сегменты для потока
            if flow_key in self.tls_flows:
                segment_info = {
                    'ts': ts,
                    'seq': tcp.seq,
                    'ack': tcp.ack,
                    'flags': self._get_tcp_flags(tcp),
                    'ttl': ip.ttl,
                    'ip_id': ip.id,
                    'window': tcp.win,
                    'payload_len': len(tcp.data),
                    'payload_start': tcp.data[:20].hex() if tcp.data else '',
                    'checksum': tcp.sum,
                    'checksum_valid': self._verify_tcp_checksum(ip, tcp)
                }
                self.tls_flows[flow_key]['segments'].append(segment_info)
                
        except Exception as e:
            pass
    
    def _get_tcp_flags(self, tcp) -> List[str]:
        """Получение TCP флагов"""
        flags = []
        if tcp.flags & dpkt.tcp.TH_FIN: flags.append('FIN')
        if tcp.flags & dpkt.tcp.TH_SYN: flags.append('SYN')
        if tcp.flags & dpkt.tcp.TH_RST: flags.append('RST')
        if tcp.flags & dpkt.tcp.TH_PUSH: flags.append('PSH')
        if tcp.flags & dpkt.tcp.TH_ACK: flags.append('ACK')
        if tcp.flags & dpkt.tcp.TH_URG: flags.append('URG')
        return flags
    
    def _verify_tcp_checksum(self, ip, tcp) -> bool:
        """Проверка TCP checksum"""
        # Simplified check - в реальности нужен полный расчет
        return tcp.sum != 0
    
    def _detect_strategy(self, segments: List[Dict]) -> Dict:
        """Определение стратегии по паттерну сегментов"""
        if len(segments) < 2:
            return {'type': 'unknown', 'confidence': 0}
        
        # Анализ паттернов fakeddisorder
        patterns = {
            'fakeddisorder': {
                'markers': [
                    ('low_ttl_first', lambda s: s[0]['ttl'] <= 3),
                    ('bad_checksum', lambda s: not s[0]['checksum_valid']),
                    ('seq_overlap', lambda s: len(s) >= 2 and s[1]['seq'] < s[0]['seq'] + s[0]['payload_len']),
                    ('psh_on_second', lambda s: len(s) >= 2 and 'PSH' in s[1]['flags']),
                ],
                'confidence': 0
            },
            'multisplit': {
                'markers': [
                    ('many_segments', lambda s: len(s) >= 3),
                    ('sequential', lambda s: all(s[i]['seq'] <= s[i+1]['seq'] for i in range(len(s)-1))),
                ],
                'confidence': 0
            }
        }
        
        # Подсчет уверенности для каждого паттерна
        for strategy, data in patterns.items():
            for marker_name, check_func in data['markers']:
                try:
                    if check_func(segments):
                        data['confidence'] += 25
                except:
                    pass
        
        # Выбор наиболее вероятной стратегии
        best_strategy = max(patterns.items(), key=lambda x: x[1]['confidence'])
        return {
            'type': best_strategy[0],
            'confidence': best_strategy[1]['confidence'],
            'details': self._get_strategy_details(segments, best_strategy[0])
        }
    
    def _get_strategy_details(self, segments: List[Dict], strategy_type: str) -> Dict:
        """Детальный анализ параметров стратегии"""
        if not segments:
            return {}
            
        details = {}
        
        if strategy_type == 'fakeddisorder':
            # Анализ fakeddisorder параметров
            if len(segments) >= 2:
                # TTL фейкового сегмента
                details['fake_ttl'] = segments[0]['ttl']
                details['real_ttl'] = segments[1]['ttl'] if len(segments) > 1 else None
                
                # Overlap size
                if segments[0]['seq'] + segments[0]['payload_len'] > segments[1]['seq']:
                    details['overlap_size'] = segments[0]['seq'] + segments[0]['payload_len'] - segments[1]['seq']
                else:
                    details['overlap_size'] = 0
                
                # Split position
                details['split_pos'] = segments[1]['seq'] - segments[0]['seq'] if len(segments) > 1 else 0
                
                # Fooling methods
                fooling = []
                if not segments[0]['checksum_valid']:
                    fooling.append('badsum')
                if segments[0]['seq'] != segments[1]['seq'] - segments[0]['payload_len']:
                    fooling.append('badseq')
                details['fooling'] = fooling
                
                # Timing
                if len(segments) >= 2:
                    details['delay_ms'] = int((segments[1]['ts'] - segments[0]['ts']) * 1000)
        
        return details
    
    def _generate_report(self) -> Dict:
        """Генерация отчета"""
        report = {
            'pcap_file': self.pcap_path,
            'analysis_time': datetime.now().isoformat(),
            'total_flows': len(self.tls_flows),
            'flows': []
        }
        
        for flow_key, flow_data in self.tls_flows.items():
            segments = flow_data['segments']
            strategy = self._detect_strategy(segments)
            
            flow_report = {
                'src': f"{flow_key[0]}:{flow_key[1]}",
                'dst': f"{flow_key[2]}:{flow_key[3]}",
                'segments_count': len(segments),
                'strategy': strategy,
                'segments': segments[:10]  # Первые 10 сегментов для анализа
            }
            report['flows'].append(flow_report)
        
        return report

def compare_pcaps(original_pcap: str, zapret_pcap: str) -> Dict:
    """Сравнение двух PCAP файлов"""
    original_analysis = PCAPAnalyzer(original_pcap).analyze()
    zapret_analysis = PCAPAnalyzer(zapret_pcap).analyze()
    
    comparison = {
        'timestamp': datetime.now().isoformat(),
        'differences': [],
        'similarities': [],
        'recommendations': []
    }
    
    # Сравнение стратегий
    orig_strategies = {f['strategy']['type'] for f in original_analysis['flows']}
    zap_strategies = {f['strategy']['type'] for f in zapret_analysis['flows']}
    
    if orig_strategies != zap_strategies:
        comparison['differences'].append({
            'type': 'strategy_mismatch',
            'original': list(orig_strategies),
            'zapret': list(zap_strategies)
        })
    
    # Детальное сравнение параметров fakeddisorder
    for orig_flow in original_analysis['flows']:
        if orig_flow['strategy']['type'] == 'fakeddisorder':
            for zap_flow in zapret_analysis['flows']:
                if zap_flow['strategy']['type'] == 'fakeddisorder':
                    orig_details = orig_flow['strategy']['details']
                    zap_details = zap_flow['strategy']['details']
                    
                    # Сравнение ключевых параметров
                    params_to_check = ['fake_ttl', 'overlap_size', 'split_pos', 'fooling', 'delay_ms']
                    for param in params_to_check:
                        if orig_details.get(param) != zap_details.get(param):
                            comparison['differences'].append({
                                'type': f'param_{param}',
                                'original': orig_details.get(param),
                                'zapret': zap_details.get(param),
                                'recommendation': f"Change {param} from {orig_details.get(param)} to {zap_details.get(param)}"
                            })
                    
                    # Проверка порядка сегментов
                    if len(orig_flow['segments']) >= 2 and len(zap_flow['segments']) >= 2:
                        orig_order = 'fake_first' if orig_flow['segments'][0]['ttl'] < orig_flow['segments'][1]['ttl'] else 'real_first'
                        zap_order = 'fake_first' if zap_flow['segments'][0]['ttl'] < zap_flow['segments'][1]['ttl'] else 'real_first'
                        
                        if orig_order != zap_order:
                            comparison['differences'].append({
                                'type': 'segment_order',
                                'original': orig_order,
                                'zapret': zap_order,
                                'recommendation': f"Change segment order to {zap_order}"
                            })
    
    return comparison

# Использование:
if __name__ == "__main__":
    # Анализ вашего PCAP
    analyzer = PCAPAnalyzer("out2.pcap")
    report = analyzer.analyze()
    
    with open("pcap_analysis.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print("Analysis complete. Check pcap_analysis.json")
    
    # Сравнение с zapret
    if os.path.exists("zapret.pcap"):
        comparison = compare_pcaps("out2.pcap", "zapret.pcap")
        with open("pcap_comparison.json", "w") as f:
            json.dump(comparison, f, indent=2)
        print("Comparison complete. Check pcap_comparison.json")