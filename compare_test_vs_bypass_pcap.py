#!/usr/bin/env python3
"""
Детальное сравнение применения стратегии в режиме тестирования (log1.pcap) 
и режиме обхода (log2.pcap).
"""

from scapy.all import rdpcap, TCP, IP, Raw
import struct
from typing import List, Dict, Any, Tuple

def extract_sni(payload):
    """Extract SNI from TLS ClientHello."""
    try:
        if len(payload) < 43:
            return None
        if payload[0] != 0x16:
            return None
        if payload[5] != 0x01:
            return None
        
        offset = 43
        if offset >= len(payload):
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        
        if offset + 2 > len(payload):
            return None
        cipher_len = struct.unpack(">H", payload[offset:offset+2])[0]
        offset += 2 + cipher_len
        
        if offset >= len(payload):
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len
        
        if offset + 2 > len(payload):
            return None
        ext_len = struct.unpack(">H", payload[offset:offset+2])[0]
        offset += 2
        ext_end = offset + ext_len
        
        while offset + 4 <= ext_end and offset + 4 <= len(payload):
            ext_type = struct.unpack(">H", payload[offset:offset+2])[0]
            ext_data_len = struct.unpack(">H", payload[offset+2:offset+4])[0]
            
            if ext_type == 0x0000:
                sni_data = payload[offset+4:offset+4+ext_data_len]
                if len(sni_data) >= 5:
                    name_len = struct.unpack(">H", sni_data[3:5])[0]
                    if len(sni_data) >= 5 + name_len:
                        return sni_data[5:5+name_len].decode('ascii', errors='ignore')
            
            offset += 4 + ext_data_len
        
        return None
    except Exception:
        return None

def analyze_stream(packets: List, stream_name: str) -> Dict[str, Any]:
    """Analyze a single TCP stream."""
    result = {
        'stream_name': stream_name,
        'total_packets': len(packets),
        'handshake_packets': [],
        'data_packets': [],
        'fake_packets': [],
        'real_packets': [],
        'issues': []
    }
    
    for i, p in enumerate(packets):
        ip = p[IP]
        tcp = p[TCP]
        payload = bytes(tcp.payload) if tcp.payload else b''
        
        packet_info = {
            'index': i,
            'seq': tcp.seq,
            'ack': tcp.ack,
            'flags': tcp.flags,
            'ttl': ip.ttl,
            'checksum': tcp.chksum,
            'payload_len': len(payload),
            'payload': payload
        }
        
        if len(payload) == 0:
            result['handshake_packets'].append(packet_info)
        else:
            result['data_packets'].append(packet_info)
            
            # Detect fake packets
            is_fake = False
            fake_reasons = []
            
            if ip.ttl <= 3:
                is_fake = True
                fake_reasons.append(f"TTL={ip.ttl}")
            
            if tcp.chksum == 0xDEAD:
                is_fake = True
                fake_reasons.append("badsum=0xDEAD")
            
            packet_info['is_fake'] = is_fake
            packet_info['fake_reasons'] = fake_reasons
            
            if is_fake:
                result['fake_packets'].append(packet_info)
            else:
                result['real_packets'].append(packet_info)
    
    return result

def compare_streams(test_stream: Dict, bypass_stream: Dict) -> List[str]:
    """Compare two streams and find differences."""
    differences = []
    
    # Compare packet counts
    if len(test_stream['data_packets']) != len(bypass_stream['data_packets']):
        differences.append(
            f"Packet count mismatch: "
            f"test={len(test_stream['data_packets'])}, "
            f"bypass={len(bypass_stream['data_packets'])}"
        )
    
    # Compare fake packet counts
    if len(test_stream['fake_packets']) != len(bypass_stream['fake_packets']):
        differences.append(
            f"Fake packet count mismatch: "
            f"test={len(test_stream['fake_packets'])}, "
            f"bypass={len(bypass_stream['fake_packets'])}"
        )
    
    # Compare real packet counts
    if len(test_stream['real_packets']) != len(bypass_stream['real_packets']):
        differences.append(
            f"Real packet count mismatch: "
            f"test={len(test_stream['real_packets'])}, "
            f"bypass={len(bypass_stream['real_packets'])}"
        )
    
    # Compare each data packet
    max_packets = max(len(test_stream['data_packets']), len(bypass_stream['data_packets']))
    
    for i in range(max_packets):
        test_pkt = test_stream['data_packets'][i] if i < len(test_stream['data_packets']) else None
        bypass_pkt = bypass_stream['data_packets'][i] if i < len(bypass_stream['data_packets']) else None
        
        if test_pkt is None:
            differences.append(f"Packet #{i+1}: Missing in test mode")
            continue
        
        if bypass_pkt is None:
            differences.append(f"Packet #{i+1}: Missing in bypass mode")
            continue
        
        # Compare TTL
        if test_pkt['ttl'] != bypass_pkt['ttl']:
            differences.append(
                f"Packet #{i+1}: TTL mismatch - "
                f"test={test_pkt['ttl']}, bypass={bypass_pkt['ttl']}"
            )
        
        # Compare checksum
        if test_pkt['checksum'] != bypass_pkt['checksum']:
            differences.append(
                f"Packet #{i+1}: Checksum mismatch - "
                f"test=0x{test_pkt['checksum']:04X}, bypass=0x{bypass_pkt['checksum']:04X}"
            )
        
        # Compare payload length
        if test_pkt['payload_len'] != bypass_pkt['payload_len']:
            differences.append(
                f"Packet #{i+1}: Payload length mismatch - "
                f"test={test_pkt['payload_len']}, bypass={bypass_pkt['payload_len']}"
            )
        
        # Compare fake status
        if test_pkt['is_fake'] != bypass_pkt['is_fake']:
            differences.append(
                f"Packet #{i+1}: Fake status mismatch - "
                f"test={test_pkt['is_fake']}, bypass={bypass_pkt['is_fake']}"
            )
        
        # Compare sequence numbers (relative)
        if i > 0:
            test_prev = test_stream['data_packets'][i-1]
            bypass_prev = bypass_stream['data_packets'][i-1]
            
            test_seq_diff = test_pkt['seq'] - test_prev['seq']
            bypass_seq_diff = bypass_pkt['seq'] - bypass_prev['seq']
            
            if test_seq_diff != bypass_seq_diff:
                differences.append(
                    f"Packet #{i+1}: Sequence offset mismatch - "
                    f"test={test_seq_diff}, bypass={bypass_seq_diff}"
                )
    
    return differences

def main():
    print("="*80)
    print("СРАВНЕНИЕ РЕЖИМОВ ТЕСТИРОВАНИЯ И ОБХОДА")
    print("="*80)
    print()
    
    # Load PCAPs
    print("Загрузка PCAP файлов...")
    test_pkts = rdpcap('log1.pcap')
    bypass_pkts = rdpcap('log2.pcap')
    
    print(f"  log1.pcap (test): {len(test_pkts)} пакетов")
    print(f"  log2.pcap (bypass): {len(bypass_pkts)} пакетов")
    print()
    
    # Group by streams
    def group_streams(pkts):
        streams = {}
        for p in pkts:
            if p.haslayer(TCP) and p.haslayer(IP):
                ip = p[IP]
                tcp = p[TCP]
                key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                if key not in streams:
                    streams[key] = []
                streams[key].append(p)
        return streams
    
    test_streams = group_streams(test_pkts)
    bypass_streams = group_streams(bypass_pkts)
    
    print(f"TCP потоков в test: {len(test_streams)}")
    print(f"TCP потоков в bypass: {len(bypass_streams)}")
    print()
    
    # Find main streams (to port 443 with data)
    def find_main_stream(streams):
        for key, packets in streams.items():
            src_ip, src_port, dst_ip, dst_port = key
            if dst_port == 443:
                # Check if has data packets
                data_packets = [p for p in packets if len(bytes(p[TCP].payload)) > 0]
                if data_packets:
                    return key, packets
        return None, None
    
    test_key, test_main = find_main_stream(test_streams)
    bypass_key, bypass_main = find_main_stream(bypass_streams)
    
    if not test_main or not bypass_main:
        print("❌ Не найдены основные потоки с данными")
        return
    
    print("="*80)
    print("АНАЛИЗ ОСНОВНОГО ПОТОКА (ТЕСТИРОВАНИЕ)")
    print("="*80)
    print(f"Поток: {test_key[0]}:{test_key[1]} -> {test_key[2]}:{test_key[3]}")
    print()
    
    test_analysis = analyze_stream(test_main, "test")
    
    print(f"Всего пакетов: {test_analysis['total_packets']}")
    print(f"Пакеты рукопожатия: {len(test_analysis['handshake_packets'])}")
    print(f"Пакеты с данными: {len(test_analysis['data_packets'])}")
    print(f"  - Fake пакеты: {len(test_analysis['fake_packets'])}")
    print(f"  - Real пакеты: {len(test_analysis['real_packets'])}")
    print()
    
    print("Детали пакетов с данными:")
    for pkt in test_analysis['data_packets']:
        fake_str = f" [FAKE: {', '.join(pkt['fake_reasons'])}]" if pkt['is_fake'] else " [REAL]"
        print(f"  Пакет #{pkt['index']+1}: seq={pkt['seq']}, len={pkt['payload_len']}, "
              f"ttl={pkt['ttl']}, csum=0x{pkt['checksum']:04X}{fake_str}")
    print()
    
    print("="*80)
    print("АНАЛИЗ ОСНОВНОГО ПОТОКА (ОБХОД)")
    print("="*80)
    print(f"Поток: {bypass_key[0]}:{bypass_key[1]} -> {bypass_key[2]}:{bypass_key[3]}")
    print()
    
    bypass_analysis = analyze_stream(bypass_main, "bypass")
    
    print(f"Всего пакетов: {bypass_analysis['total_packets']}")
    print(f"Пакеты рукопожатия: {len(bypass_analysis['handshake_packets'])}")
    print(f"Пакеты с данными: {len(bypass_analysis['data_packets'])}")
    print(f"  - Fake пакеты: {len(bypass_analysis['fake_packets'])}")
    print(f"  - Real пакеты: {len(bypass_analysis['real_packets'])}")
    print()
    
    print("Детали пакетов с данными:")
    for pkt in bypass_analysis['data_packets']:
        fake_str = f" [FAKE: {', '.join(pkt['fake_reasons'])}]" if pkt['is_fake'] else " [REAL]"
        print(f"  Пакет #{pkt['index']+1}: seq={pkt['seq']}, len={pkt['payload_len']}, "
              f"ttl={pkt['ttl']}, csum=0x{pkt['checksum']:04X}{fake_str}")
    print()
    
    print("="*80)
    print("СРАВНЕНИЕ ПОТОКОВ")
    print("="*80)
    print()
    
    differences = compare_streams(test_analysis, bypass_analysis)
    
    if not differences:
        print("✅ Потоки идентичны!")
    else:
        print(f"❌ Найдено {len(differences)} различий:")
        print()
        for i, diff in enumerate(differences, 1):
            print(f"{i}. {diff}")
    
    print()
    print("="*80)
    print("ДЕТАЛЬНОЕ СРАВНЕНИЕ ПАКЕТОВ")
    print("="*80)
    print()
    
    max_packets = max(len(test_analysis['data_packets']), len(bypass_analysis['data_packets']))
    
    for i in range(max_packets):
        test_pkt = test_analysis['data_packets'][i] if i < len(test_analysis['data_packets']) else None
        bypass_pkt = bypass_analysis['data_packets'][i] if i < len(bypass_analysis['data_packets']) else None
        
        print(f"--- Пакет #{i+1} ---")
        
        if test_pkt:
            print(f"TEST:   seq={test_pkt['seq']:10d}, len={test_pkt['payload_len']:3d}, "
                  f"ttl={test_pkt['ttl']:3d}, csum=0x{test_pkt['checksum']:04X}, "
                  f"fake={test_pkt['is_fake']}")
        else:
            print(f"TEST:   ОТСУТСТВУЕТ")
        
        if bypass_pkt:
            print(f"BYPASS: seq={bypass_pkt['seq']:10d}, len={bypass_pkt['payload_len']:3d}, "
                  f"ttl={bypass_pkt['ttl']:3d}, csum=0x{bypass_pkt['checksum']:04X}, "
                  f"fake={bypass_pkt['is_fake']}")
        else:
            print(f"BYPASS: ОТСУТСТВУЕТ")
        
        # Compare
        if test_pkt and bypass_pkt:
            issues = []
            
            if test_pkt['ttl'] != bypass_pkt['ttl']:
                issues.append(f"TTL: {test_pkt['ttl']} vs {bypass_pkt['ttl']}")
            
            if test_pkt['checksum'] != bypass_pkt['checksum']:
                issues.append(f"Checksum: 0x{test_pkt['checksum']:04X} vs 0x{bypass_pkt['checksum']:04X}")
            
            if test_pkt['payload_len'] != bypass_pkt['payload_len']:
                issues.append(f"Length: {test_pkt['payload_len']} vs {bypass_pkt['payload_len']}")
            
            if test_pkt['is_fake'] != bypass_pkt['is_fake']:
                issues.append(f"Fake: {test_pkt['is_fake']} vs {bypass_pkt['is_fake']}")
            
            # Compare payload
            if test_pkt['payload'] != bypass_pkt['payload']:
                issues.append("Payload differs")
            
            if issues:
                print(f"❌ РАЗЛИЧИЯ: {', '.join(issues)}")
            else:
                print(f"✅ ИДЕНТИЧНЫ")
        
        print()
    
    print("="*80)
    print("ИТОГОВАЯ ОЦЕНКА")
    print("="*80)
    print()
    
    if not differences:
        print("✅ Стратегия применяется ИДЕНТИЧНО в обоих режимах")
    else:
        print("❌ Обнаружены РАЗЛИЧИЯ в применении стратегии:")
        print()
        for diff in differences:
            print(f"  - {diff}")
        print()
        print("💡 Это объясняет почему стратегия работает в одном режиме и не работает в другом!")

if __name__ == '__main__':
    main()
