#!/usr/bin/env python3
"""
Flow-based PCAP Analyzer - Разделение TCP потоков и сравнение стратегий

Анализирует PCAP файлы по TCP потокам для точного сравнения
того, как стратегии применяются в режиме поиска vs службы.

Игнорирует логи - анализирует только реальные пакеты.
"""

import sys
from pathlib import Path
from collections import defaultdict, namedtuple
from typing import Dict, List, Tuple, Optional, Set
import json

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    from scapy.layers.tls import TLS, TLSClientHello
except ImportError:
    print("❌ Scapy не установлен: pip install scapy")
    sys.exit(1)

# TCP Flow identifier
TCPFlow = namedtuple('TCPFlow', ['src_ip', 'dst_ip', 'src_port', 'dst_port'])

class FlowPacket:
    """Пакет в TCP потоке"""
    def __init__(self, packet, timestamp, seq, ack, flags, payload_len, is_clienthello=False):
        self.packet = packet
        self.timestamp = timestamp
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload_len = payload_len
        self.is_clienthello = is_clienthello
        self.direction = None  # 'outgoing' or 'incoming'
        
    def __repr__(self):
        direction = f"[{self.direction}]" if self.direction else ""
        ch_mark = "[CH]" if self.is_clienthello else ""
        return f"{direction}{ch_mark} seq={self.seq} ack={self.ack} flags={self.flags:02x} len={self.payload_len}"

class TCPFlowAnalyzer:
    """Анализатор TCP потоков"""
    
    def __init__(self):
        self.flows: Dict[TCPFlow, List[FlowPacket]] = defaultdict(list)
        self.googlevideo_flows: Dict[TCPFlow, List[FlowPacket]] = defaultdict(list)
        
    def analyze_pcap(self, pcap_path: str, mode_name: str) -> Dict:
        """
        Анализирует PCAP файл и разделяет на TCP потоки
        
        Args:
            pcap_path: Путь к PCAP файлу
            mode_name: Название режима (для логирования)
            
        Returns:
            Словарь с результатами анализа
        """
        print(f"\n🔍 Анализ PCAP: {pcap_path} ({mode_name})")
        
        if not Path(pcap_path).exists():
            print(f"❌ Файл не найден: {pcap_path}")
            return {}
            
        try:
            packets = rdpcap(pcap_path)
            print(f"📦 Загружено {len(packets)} пакетов")
        except Exception as e:
            print(f"❌ Ошибка чтения PCAP: {e}")
            return {}
        
        # Анализируем каждый пакет
        for i, pkt in enumerate(packets):
            if not (IP in pkt and TCP in pkt):
                continue
                
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            
            # Создаем идентификатор потока
            flow = TCPFlow(
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=tcp_layer.sport,
                dst_port=tcp_layer.dport
            )
            
            # Определяем payload
            payload_len = 0
            is_clienthello = False
            
            if Raw in pkt:
                payload_len = len(pkt[Raw].load)
                
                # Проверяем на ClientHello
                try:
                    if TLS in pkt:
                        tls_layer = pkt[TLS]
                        if TLSClientHello in tls_layer:
                            is_clienthello = True
                except:
                    # Простая проверка по сигнатуре TLS ClientHello
                    raw_data = pkt[Raw].load
                    if len(raw_data) > 6 and raw_data[0] == 0x16 and raw_data[5] == 0x01:
                        is_clienthello = True
            
            # Создаем объект пакета
            flow_packet = FlowPacket(
                packet=pkt,
                timestamp=float(pkt.time),
                seq=tcp_layer.seq,
                ack=tcp_layer.ack,
                flags=tcp_layer.flags,
                payload_len=payload_len,
                is_clienthello=is_clienthello
            )
            
            # Добавляем в общий список потоков
            self.flows[flow].append(flow_packet)
            
            # Если это googlevideo - добавляем в специальный список
            if 'googlevideo' in ip_layer.dst.lower():
                self.googlevideo_flows[flow].append(flow_packet)
        
        # Определяем направления пакетов в каждом потоке
        self._determine_directions()
        
        # Анализируем googlevideo потоки
        googlevideo_analysis = self._analyze_googlevideo_flows(mode_name)
        
        return {
            'mode': mode_name,
            'total_flows': len(self.flows),
            'googlevideo_flows': len(self.googlevideo_flows),
            'googlevideo_analysis': googlevideo_analysis
        }
    
    def _determine_directions(self):
        """Определяет направления пакетов (исходящие/входящие)"""
        for flow, packets in self.flows.items():
            # Предполагаем, что первый пакет с данными - исходящий
            for packet in packets:
                if packet.payload_len > 0:
                    # Исходящий: от клиента к серверу
                    if packet.packet[IP].src == flow.src_ip:
                        packet.direction = 'outgoing'
                    else:
                        packet.direction = 'incoming'
                else:
                    # Для пакетов без данных определяем по SYN/ACK
                    if packet.flags & 0x02:  # SYN
                        if packet.flags & 0x10:  # SYN+ACK
                            packet.direction = 'incoming'
                        else:  # SYN
                            packet.direction = 'outgoing'
                    elif packet.packet[IP].src == flow.src_ip:
                        packet.direction = 'outgoing'
                    else:
                        packet.direction = 'incoming'
    
    def _analyze_googlevideo_flows(self, mode_name: str) -> Dict:
        """Анализирует потоки к googlevideo"""
        if not self.googlevideo_flows:
            return {'error': 'No googlevideo flows found'}
        
        analysis = {
            'flows_count': len(self.googlevideo_flows),
            'flows': []
        }
        
        for flow, packets in self.googlevideo_flows.items():
            flow_analysis = self._analyze_single_flow(flow, packets, mode_name)
            analysis['flows'].append(flow_analysis)
        
        return analysis
    
    def _analyze_single_flow(self, flow: TCPFlow, packets: List[FlowPacket], mode_name: str) -> Dict:
        """Анализирует один TCP поток"""
        outgoing_packets = [p for p in packets if p.direction == 'outgoing']
        incoming_packets = [p for p in packets if p.direction == 'incoming']
        
        # Ищем ClientHello пакеты
        clienthello_packets = [p for p in outgoing_packets if p.is_clienthello]
        
        # Анализируем сегментацию ClientHello
        ch_segmentation = self._analyze_clienthello_segmentation(clienthello_packets)
        
        # Подсчитываем ретрансмиссии
        retransmissions = self._count_retransmissions(outgoing_packets)
        
        # Анализируем тайминги
        timing_analysis = self._analyze_timing(packets)
        
        return {
            'flow': f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}",
            'total_packets': len(packets),
            'outgoing_packets': len(outgoing_packets),
            'incoming_packets': len(incoming_packets),
            'clienthello_packets': len(clienthello_packets),
            'clienthello_segmentation': ch_segmentation,
            'retransmissions': retransmissions,
            'timing': timing_analysis,
            'mode': mode_name
        }
    
    def _analyze_clienthello_segmentation(self, ch_packets: List[FlowPacket]) -> Dict:
        """Анализирует сегментацию ClientHello"""
        if not ch_packets:
            return {'segments': 0, 'total_size': 0, 'segment_sizes': []}
        
        # Сортируем по sequence number
        ch_packets.sort(key=lambda p: p.seq)
        
        segment_sizes = [p.payload_len for p in ch_packets]
        total_size = sum(segment_sizes)
        
        # Проверяем на разделение (split)
        is_split = len(ch_packets) > 1
        
        return {
            'segments': len(ch_packets),
            'total_size': total_size,
            'segment_sizes': segment_sizes,
            'is_split': is_split,
            'sequences': [p.seq for p in ch_packets]
        }
    
    def _count_retransmissions(self, packets: List[FlowPacket]) -> Dict:
        """Подсчитывает ретрансмиссии"""
        seq_counts = defaultdict(int)
        
        for packet in packets:
            if packet.payload_len > 0:  # Только пакеты с данными
                seq_counts[packet.seq] += 1
        
        retrans_count = sum(1 for count in seq_counts.values() if count > 1)
        total_retrans = sum(count - 1 for count in seq_counts.values() if count > 1)
        
        return {
            'retransmitted_sequences': retrans_count,
            'total_retransmissions': total_retrans,
            'unique_sequences': len(seq_counts)
        }
    
    def _analyze_timing(self, packets: List[FlowPacket]) -> Dict:
        """Анализирует тайминги пакетов"""
        if len(packets) < 2:
            return {'duration': 0, 'avg_interval': 0}
        
        packets.sort(key=lambda p: p.timestamp)
        
        start_time = packets[0].timestamp
        end_time = packets[-1].timestamp
        duration = end_time - start_time
        
        # Вычисляем интервалы между пакетами
        intervals = []
        for i in range(1, len(packets)):
            interval = packets[i].timestamp - packets[i-1].timestamp
            intervals.append(interval)
        
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        
        return {
            'duration': duration,
            'avg_interval': avg_interval,
            'packet_count': len(packets),
            'start_time': start_time,
            'end_time': end_time
        }

def compare_modes(search_analysis: Dict, service_analysis: Dict) -> Dict:
    """Сравнивает результаты анализа двух режимов"""
    comparison = {
        'search_mode': search_analysis,
        'service_mode': service_analysis,
        'differences': {}
    }
    
    # Сравниваем googlevideo потоки
    search_gv = search_analysis.get('googlevideo_analysis', {})
    service_gv = service_analysis.get('googlevideo_analysis', {})
    
    if 'flows' in search_gv and 'flows' in service_gv:
        comparison['differences']['flow_count'] = {
            'search': len(search_gv['flows']),
            'service': len(service_gv['flows'])
        }
        
        # Сравниваем первые потоки (основные)
        if search_gv['flows'] and service_gv['flows']:
            search_flow = search_gv['flows'][0]
            service_flow = service_gv['flows'][0]
            
            comparison['differences']['clienthello_segmentation'] = {
                'search': search_flow['clienthello_segmentation'],
                'service': service_flow['clienthello_segmentation']
            }
            
            comparison['differences']['retransmissions'] = {
                'search': search_flow['retransmissions'],
                'service': service_flow['retransmissions']
            }
            
            comparison['differences']['timing'] = {
                'search': search_flow['timing'],
                'service': service_flow['timing']
            }
    
    return comparison

def main():
    """Основная функция"""
    print("="*80)
    print("FLOW-BASED PCAP ANALYZER")
    print("Анализ TCP потоков для сравнения режимов поиска и службы")
    print("="*80)
    
    # Файлы для анализа
    search_pcap = "log2.pcap"  # Режим поиска
    service_pcap = "log.pcap"  # Режим службы
    
    # Создаем анализаторы
    search_analyzer = TCPFlowAnalyzer()
    service_analyzer = TCPFlowAnalyzer()
    
    # Анализируем оба файла
    search_results = search_analyzer.analyze_pcap(search_pcap, "search_mode")
    service_results = service_analyzer.analyze_pcap(service_pcap, "service_mode")
    
    # Сравниваем результаты
    comparison = compare_modes(search_results, service_results)
    
    # Сохраняем результаты
    output_file = "flow_based_analysis_results.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(comparison, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 Результаты сохранены в: {output_file}")
    
    # Выводим краткую сводку
    print("\n" + "="*80)
    print("КРАТКАЯ СВОДКА РАЗЛИЧИЙ")
    print("="*80)
    
    if 'differences' in comparison:
        diff = comparison['differences']
        
        if 'flow_count' in diff:
            print(f"📊 Количество googlevideo потоков:")
            print(f"   Режим поиска: {diff['flow_count']['search']}")
            print(f"   Режим службы: {diff['flow_count']['service']}")
        
        if 'clienthello_segmentation' in diff:
            search_ch = diff['clienthello_segmentation']['search']
            service_ch = diff['clienthello_segmentation']['service']
            
            print(f"\n🔍 Сегментация ClientHello:")
            print(f"   Режим поиска: {search_ch['segments']} сегментов, размеры: {search_ch['segment_sizes']}")
            print(f"   Режим службы: {service_ch['segments']} сегментов, размеры: {service_ch['segment_sizes']}")
            
            if search_ch['segments'] != service_ch['segments']:
                print("   ⚠️ РАЗЛИЧИЕ: Разное количество сегментов!")
            
            if search_ch['segment_sizes'] != service_ch['segment_sizes']:
                print("   ⚠️ РАЗЛИЧИЕ: Разные размеры сегментов!")
        
        if 'retransmissions' in diff:
            search_ret = diff['retransmissions']['search']
            service_ret = diff['retransmissions']['service']
            
            print(f"\n🔄 Ретрансмиссии:")
            print(f"   Режим поиска: {search_ret['total_retransmissions']} ретрансмиссий")
            print(f"   Режим службы: {service_ret['total_retransmissions']} ретрансмиссий")
            
            if search_ret['total_retransmissions'] != service_ret['total_retransmissions']:
                diff_count = service_ret['total_retransmissions'] - search_ret['total_retransmissions']
                print(f"   ⚠️ РАЗЛИЧИЕ: +{diff_count} ретрансмиссий в режиме службы!")
        
        if 'timing' in diff:
            search_timing = diff['timing']['search']
            service_timing = diff['timing']['service']
            
            print(f"\n⏱️ Тайминги:")
            print(f"   Режим поиска: {search_timing['duration']:.3f}с, интервал: {search_timing['avg_interval']*1000:.1f}мс")
            print(f"   Режим службы: {service_timing['duration']:.3f}с, интервал: {service_timing['avg_interval']*1000:.1f}мс")
    
    print("\n✅ Анализ завершен!")
    print(f"📄 Подробные результаты в файле: {output_file}")

if __name__ == "__main__":
    main()