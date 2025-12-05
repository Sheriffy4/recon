#!/usr/bin/env python3
"""
Глубокое сравнение Testing vs Production PCAP
Находит РЕАЛЬНЫЕ различия в применении стратегий
"""

import sys
from scapy.all import rdpcap, TCP, IP, Raw
from collections import defaultdict

def analyze_tcp_stream(packets, stream_id):
    """Анализирует TCP поток детально"""
    result = {
        'stream_id': stream_id,
        'packets': [],
        'has_clienthello': False,
        'has_serverhello': False,
        'clienthello_packets': [],
        'fake_packets': [],
        'split_packets': [],
        'disorder_detected': False,
        'total_data_sent': 0,
        'retransmissions': 0
    }
    
    seen_seqs = set()
    
    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue
            
        tcp = pkt[TCP]
        flags = tcp.flags
        seq = tcp.seq
        ack = tcp.ack
        
        # Проверка на ретрансмиссию
        if seq in seen_seqs and len(pkt[TCP].payload) > 0:
            result['retransmissions'] += 1
        seen_seqs.add(seq)
        
        payload = bytes(pkt[TCP].payload) if pkt.haslayer(Raw) else b''
        payload_len = len(payload)
        
        pkt_info = {
            'seq': seq,
            'ack': ack,
            'flags': flags,
            'len': payload_len,
            'payload_preview': payload[:20].hex() if payload else ''
        }
        
        result['packets'].append(pkt_info)
        
        # Проверка на ClientHello
        if payload_len > 0 and payload[0:1] == b'\x16':  # TLS Handshake
            if payload_len > 5 and payload[5:6] == b'\x01':  # ClientHello
                result['has_clienthello'] = True
                result['clienthello_packets'].append(pkt_info)
                print(f"  ✅ ClientHello найден: seq={seq}, len={payload_len}")
        
        # Проверка на ServerHello
        if payload_len > 0 and payload[0:1] == b'\x16':
            if payload_len > 5 and payload[5:6] == b'\x02':  # ServerHello
                result['has_serverhello'] = True
                print(f"  ✅ ServerHello найден: seq={seq}, len={payload_len}")
        
        # Проверка на fake пакеты (очень маленькие с PSH+ACK)
        if payload_len > 0 and payload_len <= 10 and flags & 0x18 == 0x18:
            result['fake_packets'].append(pkt_info)
            print(f"  🔍 Возможный FAKE пакет: seq={seq}, len={payload_len}, flags={flags:#x}")
        
        if payload_len > 0:
            result['total_data_sent'] += payload_len
    
    return result

def find_nnmclub_streams(pcap_file):
    """Находит все потоки к nnmclub.to (104.21.112.1)"""
    print(f"\n📂 Анализ PCAP: {pcap_file}")
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"❌ Ошибка чтения PCAP: {e}")
        return []
    
    # Группируем пакеты по TCP потокам
    streams = defaultdict(list)
    
    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
        
        ip = pkt[IP]
        tcp = pkt[TCP]
        
        # Ищем потоки к 104.21.112.1:443
        if ip.dst == "104.21.112.1" and tcp.dport == 443:
            stream_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
            streams[stream_key].append(pkt)
        elif ip.src == "104.21.112.1" and tcp.sport == 443:
            stream_key = (ip.dst, tcp.dport, ip.src, tcp.sport)
            streams[stream_key].append(pkt)
    
    print(f"📊 Найдено {len(streams)} TCP потоков к 104.21.112.1:443")
    
    results = []
    for stream_id, (stream_key, pkts) in enumerate(streams.items(), 1):
        print(f"\n{'='*80}")
        print(f"Stream #{stream_id}: {stream_key[0]}:{stream_key[1]} → {stream_key[2]}:{stream_key[3]}")
        print(f"{'='*80}")
        
        result = analyze_tcp_stream(pkts, stream_id)
        results.append(result)
        
        print(f"\n📊 Статистика потока:")
        print(f"  - Всего пакетов: {len(result['packets'])}")
        print(f"  - ClientHello: {'✅ ДА' if result['has_clienthello'] else '❌ НЕТ'}")
        print(f"  - ServerHello: {'✅ ДА' if result['has_serverhello'] else '❌ НЕТ'}")
        print(f"  - Fake пакетов: {len(result['fake_packets'])}")
        print(f"  - Ретрансмиссий: {result['retransmissions']}")
        print(f"  - Всего данных отправлено: {result['total_data_sent']} байт")
    
    return results

def compare_results(testing_results, production_results):
    """Сравнивает результаты testing и production"""
    print(f"\n{'='*80}")
    print("📊 СРАВНЕНИЕ TESTING vs PRODUCTION")
    print(f"{'='*80}")
    
    # Находим успешные потоки
    testing_success = [r for r in testing_results if r['has_serverhello']]
    production_success = [r for r in production_results if r['has_serverhello']]
    
    print(f"\nTesting:")
    print(f"  - Всего потоков: {len(testing_results)}")
    print(f"  - Успешных (с ServerHello): {len(testing_success)}")
    print(f"  - Неуспешных: {len(testing_results) - len(testing_success)}")
    
    print(f"\nProduction:")
    print(f"  - Всего потоков: {len(production_results)}")
    print(f"  - Успешных (с ServerHello): {len(production_success)}")
    print(f"  - Неуспешных: {len(production_results) - len(production_success)}")
    
    # Анализируем первый успешный production поток
    if production_success:
        print(f"\n{'='*80}")
        print("✅ УСПЕШНЫЙ PRODUCTION ПОТОК (детали):")
        print(f"{'='*80}")
        
        prod = production_success[0]
        print(f"\nStream #{prod['stream_id']}:")
        print(f"  - ClientHello пакетов: {len(prod['clienthello_packets'])}")
        print(f"  - Fake пакетов: {len(prod['fake_packets'])}")
        print(f"  - Всего данных: {prod['total_data_sent']} байт")
        
        if prod['clienthello_packets']:
            print(f"\n  ClientHello детали:")
            for ch in prod['clienthello_packets']:
                print(f"    seq={ch['seq']}, len={ch['len']}, payload={ch['payload_preview']}")
        
        if prod['fake_packets']:
            print(f"\n  Fake пакеты:")
            for fake in prod['fake_packets']:
                print(f"    seq={fake['seq']}, len={fake['len']}, flags={fake['flags']:#x}")
    
    # Анализируем первый неуспешный testing поток
    testing_failed = [r for r in testing_results if not r['has_serverhello']]
    if testing_failed:
        print(f"\n{'='*80}")
        print("❌ НЕУСПЕШНЫЙ TESTING ПОТОК (детали):")
        print(f"{'='*80}")
        
        test = testing_failed[0]
        print(f"\nStream #{test['stream_id']}:")
        print(f"  - ClientHello пакетов: {len(test['clienthello_packets'])}")
        print(f"  - Fake пакетов: {len(test['fake_packets'])}")
        print(f"  - Всего данных: {test['total_data_sent']} байт")
        print(f"  - Ретрансмиссий: {test['retransmissions']}")
        
        if test['clienthello_packets']:
            print(f"\n  ClientHello детали:")
            for ch in test['clienthello_packets']:
                print(f"    seq={ch['seq']}, len={ch['len']}, payload={ch['payload_preview']}")
        
        if test['fake_packets']:
            print(f"\n  Fake пакеты:")
            for fake in test['fake_packets']:
                print(f"    seq={fake['seq']}, len={fake['len']}, flags={fake['flags']:#x}")
        
        print(f"\n  Первые 10 пакетов:")
        for i, pkt in enumerate(test['packets'][:10], 1):
            print(f"    #{i}: seq={pkt['seq']}, ack={pkt['ack']}, flags={pkt['flags']:#x}, len={pkt['len']}")

def compare_with_compliance_checker(testing_pcap, production_pcap):
    """
    Compare testing and production PCAPs using ComplianceChecker.
    
    Args:
        testing_pcap: Path to testing PCAP file
        production_pcap: Path to production PCAP file
        
    Returns:
        Comparison results dictionary
    """
    testing_results = find_nnmclub_streams(testing_pcap)
    production_results = find_nnmclub_streams(production_pcap)
    
    return {
        'testing': testing_results,
        'production': production_results,
        'testing_success_count': len([r for r in testing_results if r['has_serverhello']]),
        'production_success_count': len([r for r in production_results if r['has_serverhello']])
    }


def compare_ja3_fingerprints(testing_pcap, production_pcap):
    """
    Compare JA3 fingerprints between testing and production PCAPs.
    
    Args:
        testing_pcap: Path to testing PCAP file
        production_pcap: Path to production PCAP file
        
    Returns:
        JA3 comparison results
    """
    # Placeholder for JA3 comparison
    return {
        'testing_ja3': None,
        'production_ja3': None,
        'match': False
    }


if __name__ == "__main__":
    print("🔍 Глубокое сравнение Testing vs Production PCAP")
    print("="*80)
    
    # Анализируем оба PCAP
    testing_results = find_nnmclub_streams("log1.pcap")
    production_results = find_nnmclub_streams("log2.pcap")
    
    # Сравниваем результаты
    compare_results(testing_results, production_results)
    
    print(f"\n{'='*80}")
    print("💡 КЛЮЧЕВЫЕ ВЫВОДЫ:")
    print(f"{'='*80}")
    
    if not any(r['has_serverhello'] for r in testing_results):
        print("\n❌ В TESTING режиме НИ ОДИН поток не получил ServerHello!")
        print("   Это означает, что:")
        print("   1. Стратегии НЕ применяются корректно")
        print("   2. Или ClientHello НЕ отправляется")
        print("   3. Или соединение закрывается до TLS handshake")
    
    if any(r['has_serverhello'] for r in production_results):
        print("\n✅ В PRODUCTION режиме есть успешные потоки с ServerHello")
        print("   Стратегия работает корректно")
    
    # Проверяем наличие ClientHello в testing
    testing_with_ch = [r for r in testing_results if r['has_clienthello']]
    if not testing_with_ch:
        print("\n🚨 КРИТИЧНО: В TESTING режиме НЕТ ClientHello!")
        print("   Проблема: ClientHello НЕ отправляется вообще!")
        print("   Возможные причины:")
        print("   1. socket.connect() не завершается (timeout)")
        print("   2. SSL handshake не начинается")
        print("   3. WinDivert блокирует пакеты")
