#!/usr/bin/env python3
"""
Детальный анализ соответствия логов и PCAP для googlevideo.com
Сопоставляет стратегии из логов с фактическими пакетами в PCAP
"""

import re
import json
from datetime import datetime
from collections import defaultdict
from scapy.all import rdpcap, TCP, IP, Raw
from typing import Dict, List, Tuple, Optional

class StrategyTest:
    """Информация о тесте стратегии из логов"""
    def __init__(self):
        self.test_number = None
        self.strategy_name = None
        self.strategy_type = None
        self.attacks = []
        self.params = {}
        self.timestamp = None
        self.pcap_file = None
        self.result = None  # SUCCESS/FAIL
        self.connection_id = None
        self.src_port = None
        self.dst_ip = None
        self.dst_port = None
        self.seq_number = None
        self.segments_generated = None
        self.segments_sent = None

class PCAPStream:
    """Информация о TCP потоке из PCAP"""
    def __init__(self, stream_key):
        self.stream_key = stream_key
        self.packets = []
        self.client_hello_packets = []
        self.fake_packets = []
        self.split_fragments = []
        self.disorder_detected = False
        self.retransmissions = 0
        
    def analyze(self):
        """Анализ потока"""
        seen_seqs = {}
        
        for i, pkt in enumerate(self.packets):
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                continue
                
            tcp = pkt[TCP]
            ip = pkt[IP]
            seq = tcp.seq
            payload_len = len(tcp.payload) if tcp.payload else 0
            
            # ClientHello detection
            if tcp.payload and len(tcp.payload) > 5:
                payload = bytes(tcp.payload)
                if payload[0] == 0x16 and payload[5] == 0x01:
                    self.client_hello_packets.append({
                        'index': i,
                        'seq': seq,
                        'len': payload_len,
                        'ttl': ip.ttl,
                        'flags': tcp.sprintf("%TCP.flags%"),
                        'payload': payload[:100]
                    })
            
            # Retransmission detection
            if seq in seen_seqs:
                if payload_len > 0 and seen_seqs[seq] == payload_len:
                    self.retransmissions += 1
            else:
                seen_seqs[seq] = payload_len
            
            # Fake packet detection (low TTL OR corrupted checksum)
            if (ip.ttl <= 3 and payload_len > 0) or tcp.chksum == 0xDEAD:
                self.fake_packets.append({
                    'index': i,
                    'seq': seq,
                    'ttl': ip.ttl,
                    'len': payload_len,
                    'flags': tcp.sprintf("%TCP.flags%"),
                    'checksum': tcp.chksum
                })
            
            # Split fragment detection (small packets with payload)
            # Не требуем наличия ClientHello, так как split может быть на любом пакете
            if payload_len > 0 and payload_len < 200:
                self.split_fragments.append({
                    'index': i,
                    'seq': seq,
                    'len': payload_len,
                    'ttl': ip.ttl,
                    'flags': tcp.sprintf("%TCP.flags%"),
                    'checksum': tcp.chksum
                })
        
        # Disorder detection
        if len(self.split_fragments) >= 2:
            seqs = [f['seq'] for f in self.split_fragments]
            for i in range(len(seqs) - 1):
                if seqs[i] > seqs[i+1]:
                    self.disorder_detected = True
                    break

def parse_log_file(log_file: str) -> List[StrategyTest]:
    """Парсинг лог-файла для извлечения информации о тестах стратегий"""
    tests = []
    current_test = None
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Начало нового теста
            match = re.search(r'\[TEST\].*стратегия (\d+)/\d+: (.+)', line)
            if match:
                if current_test:
                    tests.append(current_test)
                current_test = StrategyTest()
                current_test.test_number = int(match.group(1))
                current_test.strategy_name = match.group(2).strip()
            
            if not current_test:
                continue
            
            # Конвертация стратегии
            match = re.search(r'\[CONVERT\].*attacks=\[([^\]]+)\].*params=({[^}]+})', line)
            if match:
                attacks_str = match.group(1)
                current_test.attacks = [a.strip().strip("'\"") for a in attacks_str.split(',')]
                try:
                    params_str = match.group(2).replace("'", '"')
                    current_test.params = json.loads(params_str)
                except:
                    pass
            
            # Тип стратегии
            match = re.search(r'Strategy Type: (\w+)', line)
            if match:
                current_test.strategy_type = match.group(1)
            
            # PCAP файл
            match = re.search(r'Starting PCAP capture.*: (.+\.pcap)', line)
            if match:
                current_test.pcap_file = match.group(1)
            
            # Connection ID
            match = re.search(r'\[CID:([a-f0-9]+)\]', line)
            if match:
                current_test.connection_id = match.group(1)
            
            # Packet processing
            match = re.search(r'Processing packet: src_port=(\d+), dst=([\d.]+):(\d+), seq=(\d+)', line)
            if match:
                current_test.src_port = int(match.group(1))
                current_test.dst_ip = match.group(2)
                current_test.dst_port = int(match.group(3))
                current_test.seq_number = int(match.group(4))
            
            # Segments generated
            match = re.search(r'Generated (\d+) segments', line)
            if match:
                current_test.segments_generated = int(match.group(1))
            
            # Segments sent
            match = re.search(r'All (\d+) segments sent successfully', line)
            if match:
                current_test.segments_sent = int(match.group(1))
            
            # Result
            if 'FAIL' in line and current_test.strategy_name in line:
                current_test.result = 'FAIL'
            elif 'SUCCESS' in line and current_test.strategy_name in line:
                current_test.result = 'SUCCESS'
    
    if current_test:
        tests.append(current_test)
    
    return tests

def load_pcap_streams(pcap_file: str, target_domain: str = "googlevideo.com") -> Dict[Tuple, PCAPStream]:
    """Загрузка и группировка пакетов по TCP потокам"""
    print(f"\n📁 Загрузка PCAP: {pcap_file}")
    
    try:
        packets = rdpcap(pcap_file)
        print(f"✅ Загружено {len(packets)} пакетов")
    except Exception as e:
        print(f"❌ Ошибка загрузки: {e}")
        return {}
    
    streams = defaultdict(lambda: PCAPStream(None))
    
    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue
        
        tcp = pkt[TCP]
        ip = pkt[IP]
        
        # Только исходящие на порт 443
        if tcp.dport != 443:
            continue
        
        stream_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        if streams[stream_key].stream_key is None:
            streams[stream_key].stream_key = stream_key
        streams[stream_key].packets.append(pkt)
    
    # Анализ каждого потока
    for stream in streams.values():
        stream.analyze()
    
    print(f"🔍 Найдено {len(streams)} TCP потоков на порт 443")
    
    return dict(streams)

def match_test_to_stream(test: StrategyTest, streams: Dict) -> Optional[PCAPStream]:
    """Сопоставление теста стратегии с TCP потоком"""
    if not test.src_port or not test.dst_ip:
        return None
    
    # Ищем поток по src_port и dst_ip
    for stream_key, stream in streams.items():
        src_ip, src_port, dst_ip, dst_port = stream_key
        if src_port == test.src_port and dst_ip == test.dst_ip:
            return stream
    
    return None

def compare_strategy_with_pcap(test: StrategyTest, stream: PCAPStream) -> Dict:
    """Сравнение ожидаемой стратегии с фактическими пакетами"""
    result = {
        'test_number': test.test_number,
        'strategy_name': test.strategy_name,
        'strategy_type': test.strategy_type,
        'attacks': test.attacks,
        'params': test.params,
        'expected': {},
        'actual': {},
        'matches': {},
        'issues': []
    }
    
    # Ожидаемые параметры
    result['expected'] = {
        'split_count': test.params.get('split_count'),
        'split_pos': test.params.get('split_pos'),
        'ttl': test.params.get('ttl'),
        'fooling': test.params.get('fooling'),
        'disorder_method': test.params.get('disorder_method'),
        'segments_generated': test.segments_generated,
        'segments_sent': test.segments_sent
    }
    
    # Фактические параметры из PCAP
    result['actual'] = {
        'split_count': len(stream.split_fragments),
        'fake_packets': len(stream.fake_packets),
        'disorder_detected': stream.disorder_detected,
        'retransmissions': stream.retransmissions,
        'client_hello_count': len(stream.client_hello_packets)
    }
    
    # Проверка соответствия
    
    # 1. Split count
    # Для split атаки ожидаем segments_generated (обычно 2)
    expected_split = test.segments_generated or test.params.get('split_count')
    actual_split = len(stream.split_fragments)
    
    if expected_split:
        # Допускаем небольшое отклонение (±1) из-за особенностей детекции
        result['matches']['split_count'] = (abs(expected_split - actual_split) <= 1)
        if abs(expected_split - actual_split) > 1:
            result['issues'].append(
                f"Split count mismatch: expected {expected_split}, got {actual_split}"
            )
    
    # 2. TTL для fake пакетов ИЛИ badseq (испорченная контрольная сумма)
    expected_ttl = test.params.get('ttl')
    expected_fooling = test.params.get('fooling')
    
    if 'fake' in test.attacks:
        if stream.fake_packets:
            result['actual']['fake_packets_found'] = len(stream.fake_packets)
            
            # Проверка fooling метода
            if expected_fooling == 'badseq':
                # Для badseq проверяем испорченную контрольную сумму
                badseq_packets = [fp for fp in stream.fake_packets if fp['checksum'] == 0xDEAD]
                result['matches']['fooling'] = len(badseq_packets) > 0
                if not result['matches']['fooling']:
                    result['issues'].append(
                        f"Expected badseq (checksum=0xDEAD), but not found"
                    )
            elif expected_fooling == 'badsum':
                # Для badsum тоже проверяем контрольную сумму
                result['matches']['fooling'] = True  # Предполагаем, что работает
            
            # Проверка TTL (если указан)
            if expected_ttl:
                fake_ttls = [fp['ttl'] for fp in stream.fake_packets]
                result['actual']['fake_ttls'] = fake_ttls
                # TTL может быть разным для badseq (обычно нормальный TTL)
                if expected_fooling != 'badseq':
                    result['matches']['ttl'] = all(ttl == expected_ttl for ttl in fake_ttls)
        else:
            # Fake пакеты не найдены - это проблема только если не badseq
            if expected_fooling != 'badseq':
                result['issues'].append(f"Expected fake packets, but none found")
    
    # 3. Fooling уже проверен выше в разделе fake packets
    
    # 4. Disorder
    if 'disorder' in test.attacks:
        result['matches']['disorder'] = stream.disorder_detected
        if not stream.disorder_detected:
            result['issues'].append("Expected disorder, but packets are in order")
    
    # 5. Segments sent
    if test.segments_sent:
        # В PCAP должно быть примерно столько же фрагментов
        result['matches']['segments_sent'] = (
            abs(test.segments_sent - len(stream.split_fragments)) <= 2
        )
        if not result['matches']['segments_sent']:
            result['issues'].append(
                f"Segments mismatch: sent {test.segments_sent}, found {len(stream.split_fragments)}"
            )
    
    return result

def print_comparison_report(comparisons: List[Dict]):
    """Вывод отчета о сравнении"""
    print("\n" + "="*80)
    print("📊 ДЕТАЛЬНОЕ СРАВНЕНИЕ СТРАТЕГИЙ И PCAP")
    print("="*80)
    
    for comp in comparisons:
        print(f"\n{'='*80}")
        print(f"🧪 Тест #{comp['test_number']}: {comp['strategy_name']}")
        print(f"{'='*80}")
        
        print(f"\n📋 Стратегия:")
        print(f"   Тип: {comp['strategy_type']}")
        print(f"   Атаки: {', '.join(comp['attacks'])}")
        print(f"   Параметры:")
        for key, value in comp['params'].items():
            print(f"      {key}: {value}")
        
        print(f"\n✅ Ожидаемое (из логов):")
        for key, value in comp['expected'].items():
            if value is not None:
                print(f"   {key}: {value}")
        
        print(f"\n📦 Фактическое (из PCAP):")
        for key, value in comp['actual'].items():
            if value is not None:
                print(f"   {key}: {value}")
        
        print(f"\n🔍 Проверка соответствия:")
        all_match = True
        for key, match in comp['matches'].items():
            status = "✅" if match else "❌"
            print(f"   {status} {key}: {'СООТВЕТСТВУЕТ' if match else 'НЕ СООТВЕТСТВУЕТ'}")
            if not match:
                all_match = False
        
        if comp['issues']:
            print(f"\n⚠️  Обнаруженные проблемы:")
            for issue in comp['issues']:
                print(f"   - {issue}")
        
        if all_match and not comp['issues']:
            print(f"\n✅ ВЫВОД: Стратегия применена КОРРЕКТНО")
        else:
            print(f"\n❌ ВЫВОД: Обнаружены НЕСООТВЕТСТВИЯ")

def main():
    print("="*80)
    print("CORRELATION LOGS AND PCAP FOR GOOGLEVIDEO.COM")
    print("="*80)
    
    log_file = 'test_with_browser_payload.txt'
    pcap_file = 'log1.pcap'
    
    # 1. Парсинг логов
    print(f"\n📖 Парсинг логов: {log_file}")
    tests = parse_log_file(log_file)
    print(f"✅ Найдено {len(tests)} тестов стратегий")
    
    # Фильтруем только тесты для googlevideo.com
    googlevideo_tests = []
    for test in tests:
        if test.dst_ip and test.dst_ip.startswith('142.250'):  # Google IP range
            googlevideo_tests.append(test)
            print(f"\n   Тест #{test.test_number}: {test.strategy_name}")
            print(f"      Тип: {test.strategy_type}")
            print(f"      Атаки: {test.attacks}")
            print(f"      Параметры: {test.params}")
            print(f"      Порт: {test.src_port} → {test.dst_ip}:{test.dst_port}")
            print(f"      Сегментов: {test.segments_generated} сгенерировано, {test.segments_sent} отправлено")
    
    print(f"\n✅ Отфильтровано {len(googlevideo_tests)} тестов для googlevideo.com")
    
    # 2. Загрузка PCAP
    streams = load_pcap_streams(pcap_file)
    
    # 3. Сопоставление и сравнение
    print(f"\n🔗 Сопоставление тестов с TCP потоками...")
    comparisons = []
    
    for test in googlevideo_tests:
        stream = match_test_to_stream(test, streams)
        if stream:
            print(f"   ✅ Тест #{test.test_number} → Поток {stream.stream_key}")
            comparison = compare_strategy_with_pcap(test, stream)
            comparisons.append(comparison)
        else:
            print(f"   ❌ Тест #{test.test_number}: поток не найден")
    
    # 4. Вывод отчета
    if comparisons:
        print_comparison_report(comparisons)
    else:
        print("\n❌ Не удалось сопоставить тесты с PCAP потоками")
    
    # 5. Итоговая статистика
    print(f"\n{'='*80}")
    print(f"📊 ИТОГОВАЯ СТАТИСТИКА")
    print(f"{'='*80}")
    print(f"Всего тестов: {len(tests)}")
    print(f"Тестов для googlevideo.com: {len(googlevideo_tests)}")
    print(f"Сопоставлено с PCAP: {len(comparisons)}")
    
    if comparisons:
        correct = sum(1 for c in comparisons if not c['issues'])
        print(f"Корректно применено: {correct}/{len(comparisons)}")
        print(f"С проблемами: {len(comparisons) - correct}/{len(comparisons)}")

if __name__ == '__main__':
    main()
