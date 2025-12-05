#!/usr/bin/env python3
"""
Глубокое сравнение PCAP файлов для pagead2.googlesyndication.com
"""

from scapy.all import rdpcap, TCP, IP, Raw
from collections import defaultdict
import sys

def analyze_pcap(pcap_file, label):
    """Детальный анализ PCAP файла"""
    print(f"\n{'='*80}")
    print(f"АНАЛИЗ: {label}")
    print(f"Файл: {pcap_file}")
    print(f"{'='*80}")
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Ошибка чтения: {e}")
        return None
    
    print(f"Всего пакетов: {len(packets)}")
    
    # Фильтруем только TCP с payload на порт 443
    tcp_with_payload = []
    for pkt in packets:
        if TCP in pkt and IP in pkt and Raw in pkt:
            if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                tcp_with_payload.append(pkt)
    
    print(f"TCP пакетов с payload на порт 443: {len(tcp_with_payload)}")
    
    # Группируем по потокам (src_ip:src_port -> dst_ip:dst_port)
    streams = defaultdict(list)
    for pkt in tcp_with_payload:
        if pkt[TCP].dport == 443:  # Исходящие к серверу
            key = f"{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:443"
            streams[key].append(pkt)
    
    print(f"\nИсходящих потоков к :443: {len(streams)}")
    
    # Анализируем каждый поток
    for stream_key, stream_pkts in list(streams.items())[:5]:  # Первые 5 потоков
        print(f"\n--- Поток: {stream_key} ({len(stream_pkts)} пакетов) ---")
        
        # Сортируем по времени
        stream_pkts.sort(key=lambda p: float(p.time))
        
        # Ищем ClientHello
        clienthello_pkts = []
        for pkt in stream_pkts:
            payload = bytes(pkt[TCP].payload)
            if len(payload) > 5 and payload[0] == 0x16:  # TLS Handshake
                if len(payload) > 9 and payload[5] == 0x01:  # ClientHello
                    clienthello_pkts.append(pkt)
                elif payload[0:3] == b'\x16\x03\x01':  # TLS record header only
                    clienthello_pkts.append(pkt)
        
        if not clienthello_pkts:
            # Показываем все пакеты потока
            print("  Нет ClientHello, показываем все пакеты:")
            for i, pkt in enumerate(stream_pkts[:10]):
                payload = bytes(pkt[TCP].payload)
                ttl = pkt[IP].ttl
                seq = pkt[TCP].seq
                print(f"    [{i}] TTL={ttl:3d} SEQ={seq:10d} Len={len(payload):4d} Hex={payload[:20].hex()}")
        else:
            print(f"  ClientHello пакетов: {len(clienthello_pkts)}")
            
            # Анализируем фрагментацию ClientHello
            base_seq = clienthello_pkts[0][TCP].seq
            
            # Собираем все пакеты с этим base_seq или близкими
            related_pkts = []
            for pkt in stream_pkts:
                seq = pkt[TCP].seq
                payload_len = len(bytes(pkt[TCP].payload))
                # Пакеты в диапазоне ClientHello (обычно ~1900 байт)
                if base_seq <= seq <= base_seq + 2000 or seq == base_seq:
                    related_pkts.append(pkt)
            
            print(f"  Связанных пакетов (seq в диапазоне ClientHello): {len(related_pkts)}")
            
            # Показываем детали
            print(f"\n  {'Idx':>3} {'TTL':>4} {'SEQ':>12} {'Len':>5} {'Type':>8} {'Hex (first 30)':>60}")
            print("  " + "-"*100)
            
            for i, pkt in enumerate(related_pkts[:20]):
                payload = bytes(pkt[TCP].payload)
                ttl = pkt[IP].ttl
                seq = pkt[TCP].seq
                
                # Определяем тип пакета
                pkt_type = "DATA"
                if ttl <= 5:
                    pkt_type = "FAKE"
                elif len(payload) > 5 and payload[0] == 0x16:
                    if len(payload) > 9 and payload[5] == 0x01:
                        pkt_type = "CH_FULL"
                    elif payload[0:3] == b'\x16\x03\x01':
                        pkt_type = "CH_HDR"
                
                hex_preview = payload[:30].hex()
                print(f"  {i:>3} {ttl:>4} {seq:>12} {len(payload):>5} {pkt_type:>8} {hex_preview}")
            
            # Проверяем SNI
            for pkt in clienthello_pkts:
                payload = bytes(pkt[TCP].payload)
                if b'pagead2.googlesyndication.com' in payload:
                    sni_pos = payload.find(b'pagead2.googlesyndication.com')
                    print(f"\n  SNI найден на позиции {sni_pos} в пакете с SEQ={pkt[TCP].seq}")
    
    return {
        'total': len(packets),
        'tcp_payload': len(tcp_with_payload),
        'streams': len(streams)
    }

def compare_strategies():
    """Сравниваем стратегии между файлами"""
    print("\n" + "="*80)
    print("СРАВНЕНИЕ СТРАТЕГИЙ")
    print("="*80)
    
    files = [
        ('capture_pagead2_googlesyndication_com_1764871079.pcap', 'Режим поиска (WinDivert)'),
        ('log3.pcap', 'Режим поиска (Wireshark)'),
        ('log2.pcap', 'Режим службы'),
    ]
    
    results = {}
    for pcap_file, label in files:
        try:
            results[label] = analyze_pcap(pcap_file, label)
        except Exception as e:
            print(f"Ошибка анализа {pcap_file}: {e}")
    
    # Итоговое сравнение
    print("\n" + "="*80)
    print("ИТОГОВОЕ СРАВНЕНИЕ")
    print("="*80)
    
    for label, data in results.items():
        if data:
            print(f"\n{label}:")
            print(f"  Всего пакетов: {data['total']}")
            print(f"  TCP с payload: {data['tcp_payload']}")
            print(f"  Потоков: {data['streams']}")

if __name__ == '__main__':
    compare_strategies()
