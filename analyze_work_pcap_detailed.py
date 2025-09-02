#!/usr/bin/env python3
"""
Detailed analysis of work.pcap to understand DPI bypass behavior.
This pcap was captured during strategy discovery with cli.py -d sites.txt --advanced-dns --debug --fingerprint --optimize-parameters
"""

import os
import sys
from pathlib import Path

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    import json
    from collections import defaultdict, Counter
except ImportError as e:
    print(f"❌ Требуется установка: pip install scapy")
    print(f"Ошибка: {e}")
    sys.exit(1)

def extract_sni_from_packet(packet):
    """Extract SNI from TLS ClientHello packet using manual parsing."""
    try:
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            if len(payload) > 43 and payload[0] == 0x16:  # TLS Handshake
                # Look for SNI extension (0x00, 0x00)
                try:
                    # Find TLS extensions
                    if len(payload) > 100:
                        # Look for SNI pattern
                        for i in range(40, len(payload) - 20):
                            if (payload[i] == 0x00 and payload[i+1] == 0x00 and  # SNI extension type
                                i + 9 < len(payload)):
                                # Try to extract server name
                                try:
                                    name_len_pos = i + 7
                                    if name_len_pos + 2 < len(payload):
                                        name_len = int.from_bytes(payload[name_len_pos:name_len_pos+2], 'big')
                                        name_start = name_len_pos + 2
                                        if (name_len > 0 and name_len < 300 and 
                                            name_start + name_len <= len(payload)):
                                            sni = payload[name_start:name_start + name_len].decode('utf-8', errors='ignore')
                                            if sni and '.' in sni and len(sni) > 3:
                                                return sni
                                except:
                                    continue
                except:
                    pass
    except Exception:
        pass
    return None

def analyze_work_pcap():
    """Analyze work.pcap file for DPI bypass patterns."""
    pcap_file = "work.pcap"
    
    if not os.path.exists(pcap_file):
        print(f"❌ Файл {pcap_file} не найден")
        return
    
    print(f"🔍 Анализ файла {pcap_file}")
    print(f"📁 Размер файла: {os.path.getsize(pcap_file):,} байт")
    
    try:
        packets = rdpcap(pcap_file)
        print(f"📦 Загружено пакетов: {len(packets)}")
    except Exception as e:
        print(f"❌ Ошибка загрузки pcap: {e}")
        return
    
    # Статистика
    tcp_packets = 0
    tls_packets = 0
    client_hello_packets = 0
    domain_stats = defaultdict(lambda: {
        'packets': 0,
        'tcp_packets': 0,
        'tls_attempts': 0,
        'client_hellos': 0,
        'ip_addresses': set(),
        'ports': set(),
        'packet_sizes': [],
        'timestamps': []
    })
    
    fragmented_packets = []
    suspicious_patterns = []
    
    print("\n🔍 Анализируем пакеты...")
    
    for i, packet in enumerate(packets):
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            
            if packet.haslayer(TCP):
                tcp_packets += 1
                tcp_layer = packet[TCP]
                
                # Check for TLS
                is_tls = False
                sni = None
                
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw])
                    if len(payload) > 0 and payload[0] == 0x16:  # TLS Handshake
                        tls_packets += 1
                        is_tls = True
                        
                        # Check for ClientHello
                        if len(payload) > 5 and payload[5] == 0x01:  # ClientHello
                            client_hello_packets += 1
                            sni = extract_sni_from_packet(packet)
                
                # Analyze packet characteristics
                dst_ip = ip_layer.dst
                dst_port = tcp_layer.dport
                packet_size = len(packet)
                
                # Check for fragmented/modified packets
                if ip_layer.flags & 0x1:  # More fragments flag
                    fragmented_packets.append({
                        'packet_num': i,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'size': packet_size,
                        'frag_offset': ip_layer.frag * 8
                    })
                
                # Check for suspicious TCP patterns (bypass indicators)
                if tcp_layer.flags & 0x08:  # PSH flag
                    if packet_size < 100:  # Small packets with PSH might indicate splitting
                        suspicious_patterns.append({
                            'type': 'small_psh_packet',
                            'packet_num': i,
                            'dst_ip': dst_ip,
                            'size': packet_size,
                            'sni': sni
                        })
                
                # Collect domain statistics
                if sni:
                    domain_stats[sni]['packets'] += 1
                    domain_stats[sni]['tcp_packets'] += 1
                    domain_stats[sni]['ip_addresses'].add(dst_ip)
                    domain_stats[sni]['ports'].add(dst_port)
                    domain_stats[sni]['packet_sizes'].append(packet_size)
                    domain_stats[sni]['timestamps'].append(float(packet.time))
                    
                    if is_tls:
                        domain_stats[sni]['tls_attempts'] += 1
                        if sni and payload[5] == 0x01:
                            domain_stats[sni]['client_hellos'] += 1
                elif dst_port in [443, 80]:  # HTTPS/HTTP traffic without SNI
                    unknown_key = f"unknown_{dst_ip}:{dst_port}"
                    domain_stats[unknown_key]['packets'] += 1
                    domain_stats[unknown_key]['tcp_packets'] += 1
                    domain_stats[unknown_key]['ip_addresses'].add(dst_ip)
                    domain_stats[unknown_key]['ports'].add(dst_port)
                    domain_stats[unknown_key]['packet_sizes'].append(packet_size)
    
    # Результаты анализа
    print(f"\n📊 ОБЩАЯ СТАТИСТИКА:")
    print(f"   TCP пакетов: {tcp_packets}")
    print(f"   TLS пакетов: {tls_packets}")
    print(f"   ClientHello пакетов: {client_hello_packets}")
    print(f"   Фрагментированных пакетов: {len(fragmented_packets)}")
    print(f"   Подозрительных паттернов: {len(suspicious_patterns)}")
    
    print(f"\n🌐 АНАЛИЗ ПО ДОМЕНАМ:")
    for domain, stats in sorted(domain_stats.items()):
        if stats['packets'] > 5:  # Show only domains with significant traffic
            ips = list(stats['ip_addresses'])
            ports = list(stats['ports'])
            avg_size = sum(stats['packet_sizes']) / len(stats['packet_sizes']) if stats['packet_sizes'] else 0
            
            print(f"\n🔸 {domain}")
            print(f"   Пакетов: {stats['packets']}")
            print(f"   TLS попыток: {stats['tls_attempts']}")
            print(f"   ClientHello: {stats['client_hellos']}")
            print(f"   IP адреса: {ips[:3]}{'...' if len(ips) > 3 else ''}")
            print(f"   Порты: {ports}")
            print(f"   Средний размер пакета: {avg_size:.1f} байт")
            
            # Analyze packet timing for potential splitting
            if len(stats['timestamps']) > 1:
                timestamps = sorted(stats['timestamps'])
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                quick_succession = sum(1 for interval in intervals if interval < 0.001)  # < 1ms
                if quick_succession > 0:
                    print(f"   ⚡ Быстрые пакеты (< 1мс): {quick_succession} - возможное разделение")
    
    print(f"\n🔍 ПОДОЗРИТЕЛЬНЫЕ ПАТТЕРНЫ:")
    if suspicious_patterns:
        pattern_types = Counter(p['type'] for p in suspicious_patterns)
        for pattern_type, count in pattern_types.items():
            print(f"   {pattern_type}: {count} случаев")
        
        # Show examples
        for pattern in suspicious_patterns[:5]:
            print(f"   📦 Пакет #{pattern['packet_num']}: {pattern['type']} "
                  f"-> {pattern['dst_ip']} (размер: {pattern['size']})")
            if pattern.get('sni'):
                print(f"      SNI: {pattern['sni']}")
    
    print(f"\n📋 ФРАГМЕНТИРОВАННЫЕ ПАКЕТЫ:")
    if fragmented_packets:
        for frag in fragmented_packets[:10]:
            print(f"   📦 Пакет #{frag['packet_num']}: {frag['dst_ip']}:{frag['dst_port']} "
                  f"(размер: {frag['size']}, offset: {frag['frag_offset']})")
    
    # Save detailed results
    results = {
        'total_packets': len(packets),
        'tcp_packets': tcp_packets,
        'tls_packets': tls_packets,
        'client_hello_packets': client_hello_packets,
        'fragmented_packets': len(fragmented_packets),
        'suspicious_patterns': len(suspicious_patterns),
        'domain_stats': {
            domain: {
                'packets': stats['packets'],
                'tls_attempts': stats['tls_attempts'],
                'client_hellos': stats['client_hellos'],
                'ip_addresses': list(stats['ip_addresses']),
                'ports': list(stats['ports']),
                'avg_packet_size': sum(stats['packet_sizes']) / len(stats['packet_sizes']) if stats['packet_sizes'] else 0
            }
            for domain, stats in domain_stats.items() if stats['packets'] > 0
        }
    }
    
    with open('work_pcap_detailed_analysis.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Детальный анализ сохранен в work_pcap_detailed_analysis.json")

if __name__ == "__main__":
    analyze_work_pcap()