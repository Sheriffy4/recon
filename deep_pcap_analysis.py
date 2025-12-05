#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Глубокий анализ PCAP файла для понимания проблемы с badseq стратегией
"""

import sys
import io
from collections import defaultdict

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

try:
    from scapy.all import rdpcap, TCP, IP, Raw
except ImportError:
    print("ERROR: scapy не установлен. Установите: pip install scapy")
    sys.exit(1)


def analyze_pcap_deep(pcap_file):
    """Детальный анализ PCAP файла"""
    print(f"\n{'='*100}")
    print(f"ГЛУБОКИЙ АНАЛИЗ PCAP: {pcap_file}")
    print(f"{'='*100}\n")
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"❌ Ошибка чтения PCAP: {e}")
        return
    
    print(f"Всего пакетов: {len(packets)}")
    
    # Найти все YouTube/Google IP адреса
    youtube_ips = set()
    for pkt in packets:
        if IP in pkt:
            dst_ip = pkt[IP].dst
            src_ip = pkt[IP].src
            # Google/YouTube IP диапазоны
            if (dst_ip.startswith('74.125.') or dst_ip.startswith('142.250.') or 
                dst_ip.startswith('172.217.') or dst_ip.startswith('216.58.')):
                youtube_ips.add(dst_ip)
            if (src_ip.startswith('74.125.') or src_ip.startswith('142.250.') or 
                src_ip.startswith('172.217.') or src_ip.startswith('216.58.')):
                youtube_ips.add(src_ip)
    
    print(f"YouTube/Google IP адреса: {sorted(youtube_ips)}\n")
    
    # Анализ по каждому IP
    for target_ip in sorted(youtube_ips):
        analyze_ip_traffic(packets, target_ip)


def analyze_ip_traffic(packets, target_ip):
    """Анализ трафика для конкретного IP"""
    print(f"\n{'='*100}")
    print(f"АНАЛИЗ ТРАФИКА: {target_ip}")
    print(f"{'='*100}\n")
    
    # Собрать все TCP потоки для этого IP
    flows = defaultdict(list)
    
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            if dst_ip == target_ip or src_ip == target_ip:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                
                # Нормализовать поток (всегда клиент -> сервер)
                if dst_ip == target_ip:
                    flow_key = (src_ip, src_port, dst_ip, dst_port)
                    direction = "C->S"
                else:
                    flow_key = (dst_ip, dst_port, src_ip, src_port)
                    direction = "S->C"
                
                flows[flow_key].append((pkt, direction))
    
    print(f"Найдено TCP потоков: {len(flows)}\n")
    
    # Анализ каждого потока
    for flow_idx, (flow_key, flow_packets) in enumerate(flows.items(), 1):
        src_ip, src_port, dst_ip, dst_port = flow_key
        print(f"\n{'─'*100}")
        print(f"ПОТОК #{flow_idx}: {src_ip}:{src_port} ↔ {dst_ip}:{dst_port}")
        print(f"Пакетов в потоке: {len(flow_packets)}")
        print(f"{'─'*100}\n")
        
        # Разделить на клиентские и серверные пакеты
        client_packets = [(pkt, idx) for idx, (pkt, direction) in enumerate(flow_packets) if direction == "C->S"]
        server_packets = [(pkt, idx) for idx, (pkt, direction) in enumerate(flow_packets) if direction == "S->C"]
        
        print(f"📤 Клиент → Сервер: {len(client_packets)} пакетов")
        print(f"📥 Сервер → Клиент: {len(server_packets)} пакетов\n")
        
        # Анализ клиентских пакетов
        print(f"{'─'*100}")
        print(f"КЛИЕНТСКИЕ ПАКЕТЫ (первые 20):")
        print(f"{'─'*100}\n")
        
        # Группировка по sequence number для поиска FAKE/REAL пар
        seq_groups = defaultdict(list)
        
        for pkt, global_idx in client_packets[:20]:
            if TCP in pkt and IP in pkt:
                seq = pkt[TCP].seq
                ack = pkt[TCP].ack
                flags = pkt[TCP].flags
                ttl = pkt[IP].ttl
                payload_len = len(pkt[TCP].payload) if pkt[TCP].payload else 0
                
                # Определить тип пакета
                packet_type = "FAKE?" if ttl <= 3 else "REAL"
                if payload_len == 0:
                    packet_type = "ACK"
                
                # Группировать по базовому seq (для поиска дубликатов)
                base_seq = seq & 0xFFFFF000  # Группировать по 4KB блокам
                seq_groups[base_seq].append({
                    'seq': seq,
                    'ttl': ttl,
                    'flags': str(flags),
                    'payload_len': payload_len,
                    'type': packet_type,
                    'global_idx': global_idx
                })
                
                # Вывести информацию о пакете
                flags_str = str(flags)
                print(f"  [{global_idx:3d}] {packet_type:6s} | "
                      f"Seq=0x{seq:08X} Ack=0x{ack:08X} | "
                      f"Flags={flags_str:4s} TTL={ttl:3d} | "
                      f"Len={payload_len:4d}")
        
        # Анализ дубликатов sequence numbers
        print(f"\n{'─'*100}")
        print(f"АНАЛИЗ ДУБЛИКАТОВ SEQUENCE NUMBERS:")
        print(f"{'─'*100}\n")
        
        duplicates_found = False
        for base_seq, seq_list in sorted(seq_groups.items()):
            if len(seq_list) > 1:
                duplicates_found = True
                print(f"  Группа Seq ~0x{base_seq:08X}:")
                for item in seq_list:
                    print(f"    [{item['global_idx']:3d}] {item['type']:6s} | "
                          f"Seq=0x{item['seq']:08X} | "
                          f"TTL={item['ttl']:3d} Flags={item['flags']:4s} Len={item['payload_len']:4d}")
                print()
        
        if not duplicates_found:
            print("  ⚠️  Дубликаты sequence numbers не найдены!")
            print("  Это означает, что badseq стратегия НЕ АКТИВНА или")
            print("  FAKE и REAL пакеты имеют совершенно разные sequence numbers\n")
        
        # Анализ серверных ответов
        print(f"{'─'*100}")
        print(f"СЕРВЕРНЫЕ ОТВЕТЫ (первые 10):")
        print(f"{'─'*100}\n")
        
        if len(server_packets) == 0:
            print("  ❌ СЕРВЕР НЕ ОТВЕЧАЕТ!")
            print("  Возможные причины:")
            print("    1. FAKE пакет достиг сервера и запутал его")
            print("    2. REAL пакет был отклонен сервером")
            print("    3. DPI заблокировал соединение")
            print("    4. Проблема с сетью\n")
        else:
            for pkt, global_idx in server_packets[:10]:
                if TCP in pkt:
                    seq = pkt[TCP].seq
                    ack = pkt[TCP].ack
                    flags = pkt[TCP].flags
                    payload_len = len(pkt[TCP].payload) if pkt[TCP].payload else 0
                    
                    # Проверить на RST или FIN
                    special = ""
                    if 'R' in str(flags):
                        special = " ⚠️ RST (сброс соединения)"
                    elif 'F' in str(flags):
                        special = " ⚠️ FIN (закрытие соединения)"
                    
                    flags_str = str(flags)
                    print(f"  [{global_idx:3d}] Seq=0x{seq:08X} Ack=0x{ack:08X} | "
                          f"Flags={flags_str:4s} Len={payload_len:4d}{special}")
        
        # Анализ ретрансмиссий
        print(f"\n{'─'*100}")
        print(f"АНАЛИЗ РЕТРАНСМИССИЙ:")
        print(f"{'─'*100}\n")
        
        seq_counts = defaultdict(int)
        seq_details = defaultdict(list)
        
        for pkt, global_idx in client_packets:
            if TCP in pkt:
                seq = pkt[TCP].seq
                payload_len = len(pkt[TCP].payload) if pkt[TCP].payload else 0
                if payload_len > 0:  # Только пакеты с данными
                    seq_counts[seq] += 1
                    seq_details[seq].append({
                        'idx': global_idx,
                        'ttl': pkt[IP].ttl,
                        'flags': str(pkt[TCP].flags),
                        'len': payload_len
                    })
        
        retrans = {seq: count for seq, count in seq_counts.items() if count > 1}
        
        if retrans:
            print(f"  ⚠️  Найдено {len(retrans)} ретранслируемых sequence numbers:\n")
            for seq, count in sorted(retrans.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"    Seq=0x{seq:08X} отправлен {count} раз:")
                for detail in seq_details[seq]:
                    print(f"      [{detail['idx']:3d}] TTL={detail['ttl']:3d} "
                          f"Flags={detail['flags']:4s} Len={detail['len']:4d}")
                print()
        else:
            print("  ✅ Ретрансмиссий не обнаружено\n")
        
        # Проверка на TLS ClientHello
        print(f"{'─'*100}")
        print(f"ПРОВЕРКА TLS CLIENTHELLO:")
        print(f"{'─'*100}\n")
        
        clienthello_found = False
        for pkt, global_idx in client_packets:
            if TCP in pkt and pkt[TCP].payload:
                payload = bytes(pkt[TCP].payload)
                # Проверить на TLS ClientHello (0x16 0x03 0x01/0x03)
                if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
                    clienthello_found = True
                    flags_str = str(pkt[TCP].flags)
                    print(f"  ✅ TLS ClientHello найден в пакете [{global_idx}]")
                    print(f"     Seq=0x{pkt[TCP].seq:08X} TTL={pkt[IP].ttl} "
                          f"Flags={flags_str} Len={len(payload)}\n")
                    break
        
        if not clienthello_found:
            print("  ⚠️  TLS ClientHello не найден в этом потоке\n")


def main():
    if len(sys.argv) < 2:
        print("Использование: python deep_pcap_analysis.py <pcap_file>")
        print("Пример: python deep_pcap_analysis.py log1.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyze_pcap_deep(pcap_file)
    
    print(f"\n{'='*100}")
    print("ИТОГОВЫЕ ВЫВОДЫ:")
    print(f"{'='*100}\n")
    print("1. Проверьте, активна ли badseq стратегия (должны быть дубликаты seq с разными TTL)")
    print("2. Проверьте, отвечает ли сервер на пакеты")
    print("3. Проверьте наличие ретрансмиссий (признак проблем с доставкой)")
    print("4. Проверьте, что FAKE пакеты имеют TTL=1, а REAL пакеты TTL=128")
    print("5. Проверьте, что все пакеты с данными имеют флаг PSH (PA)\n")


if __name__ == "__main__":
    main()
