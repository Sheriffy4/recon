#!/usr/bin/env python3
"""
Глубокий анализ тестового соединения в PCAP
"""
import sys
from pathlib import Path
from scapy.all import rdpcap, TCP, IP, Raw

def analyze_test_connection(pcap_path, test_port):
    """Анализирует PCAP файл для конкретного тестового порта"""
    
    print(f"\n{'='*80}")
    print(f"АНАЛИЗ: {pcap_path.name}")
    print(f"Тестовый порт источника: {test_port}")
    print(f"{'='*80}\n")
    
    try:
        packets = rdpcap(str(pcap_path))
        
        # Найти все соединения
        connections = {}
        test_conn_packets = []
        
        for i, pkt in enumerate(packets):
            if TCP in pkt and IP in pkt:
                # Исходящие пакеты (от клиента к серверу)
                if pkt[TCP].sport == test_port and pkt[TCP].dport == 443:
                    conn_key = f"{pkt[IP].src}:{pkt[TCP].sport} → {pkt[IP].dst}:{pkt[TCP].dport}"
                    if conn_key not in connections:
                        connections[conn_key] = {'outbound': 0, 'inbound': 0, 'packets': []}
                    connections[conn_key]['outbound'] += 1
                    connections[conn_key]['packets'].append((i, 'OUT', pkt))
                    test_conn_packets.append((i, 'OUT', pkt))
                
                # Входящие пакеты (от сервера к клиенту)
                elif pkt[TCP].dport == test_port and pkt[TCP].sport == 443:
                    conn_key = f"{pkt[IP].dst}:{pkt[TCP].dport} → {pkt[IP].src}:{pkt[TCP].sport}"
                    if conn_key not in connections:
                        connections[conn_key] = {'outbound': 0, 'inbound': 0, 'packets': []}
                    connections[conn_key]['inbound'] += 1
                    connections[conn_key]['packets'].append((i, 'IN', pkt))
                    test_conn_packets.append((i, 'IN', pkt))
        
        print(f"📊 Найдено соединений с портом {test_port}: {len(connections)}")
        print()
        
        for conn_key, stats in connections.items():
            print(f"Соединение: {conn_key}")
            print(f"  Исходящих: {stats['outbound']}, Входящих: {stats['inbound']}")
            
            # Проверить наличие ClientHello и ServerHello
            has_clienthello = False
            has_serverhello = False
            
            for pkt_num, direction, pkt in stats['packets']:
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    if len(payload) > 5:
                        # ClientHello
                        if payload[0] == 0x16 and payload[5] == 0x01:
                            has_clienthello = True
                            print(f"  ✅ ClientHello найден (пакет #{pkt_num}, {direction})")
                        # ServerHello
                        if payload[0] == 0x16 and payload[5] == 0x02:
                            has_serverhello = True
                            print(f"  ✅ ServerHello найден (пакет #{pkt_num}, {direction})")
            
            if not has_clienthello:
                print(f"  ❌ ClientHello НЕ найден")
            if not has_serverhello:
                print(f"  ❌ ServerHello НЕ найден")
            print()
        
        # Детальный анализ всех пакетов тестового соединения
        print(f"\n{'='*80}")
        print(f"ДЕТАЛЬНЫЙ АНАЛИЗ ПАКЕТОВ ТЕСТОВОГО СОЕДИНЕНИЯ")
        print(f"{'='*80}\n")
        
        for pkt_num, direction, pkt in test_conn_packets:
            flags = []
            if pkt[TCP].flags.S: flags.append('SYN')
            if pkt[TCP].flags.A: flags.append('ACK')
            if pkt[TCP].flags.F: flags.append('FIN')
            if pkt[TCP].flags.R: flags.append('RST')
            if pkt[TCP].flags.P: flags.append('PSH')
            
            payload_info = ""
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                if len(payload) > 5 and payload[0] == 0x16:
                    if payload[5] == 0x01:
                        payload_info = " [ClientHello]"
                    elif payload[5] == 0x02:
                        payload_info = " [ServerHello]"
                    elif payload[5] == 0x0b:
                        payload_info = " [Certificate]"
                    else:
                        payload_info = f" [TLS Handshake type={payload[5]}]"
                elif len(payload) > 0 and payload[0] == 0x17:
                    payload_info = " [Application Data]"
                else:
                    payload_info = f" [Payload {len(payload)} bytes]"
            
            print(f"Пакет #{pkt_num:3d} [{direction:3s}] {pkt[IP].src}:{pkt[TCP].sport} → {pkt[IP].dst}:{pkt[TCP].dport} "
                  f"Flags: {','.join(flags) if flags else 'None':15s}{payload_info}")
        
        return len(connections) > 0 and any(stats['inbound'] > 0 for stats in connections.values())
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    # Анализируем последние PCAP с известными портами
    pcap_dir = Path(r"C:\Users\admin\AppData\Local\Temp\recon_pcap")
    
    # Порты из лога
    test_cases = [
        ("capture_www.googlevideo.com_1763733805.pcap", 51425),  # Успешный PCAP
        ("capture_www.googlevideo.com_1763733801.pcap", 51428),  # Успешный PCAP
        ("capture_www.googlevideo.com_1763733777.pcap", 51432),  # Успешный PCAP
        ("capture_www.googlevideo.com_1763733831.pcap", 55463),  # Неуспешный PCAP
    ]
    
    for pcap_name, test_port in test_cases:
        pcap_path = pcap_dir / pcap_name
        if pcap_path.exists():
            analyze_test_connection(pcap_path, test_port)
        else:
            print(f"⚠️ Файл не найден: {pcap_path}")

if __name__ == "__main__":
    main()
