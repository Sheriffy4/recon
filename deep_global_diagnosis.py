#!/usr/bin/env python3
"""
ГЛУБОКИЙ ГЛОБАЛЬНЫЙ АНАЛИЗ ВСЕХ ПРОБЛЕМ RECON
Анализирует PCAP, логи, код и выявляет ВСЕ проблемы
"""

import json
import re
from scapy.all import rdpcap, TCP, IP, Raw
from pathlib import Path
from collections import defaultdict

def analyze_pcap(pcap_file):
    """Детальный анализ PCAP файла"""
    print(f"\n{'='*80}")
    print(f"📦 АНАЛИЗ PCAP: {pcap_file}")
    print(f"{'='*80}")
    
    try:
        packets = rdpcap(pcap_file)
        print(f"✓ Загружено пакетов: {len(packets)}")
        
        stats = {
            'total': len(packets),
            'tcp': 0,
            'with_payload': 0,
            'client_hello': 0,
            'server_hello': 0,
            'rst': 0,
            'syn': 0,
            'ack': 0,
            'psh_ack': 0,
            'ttl_values': defaultdict(int),
            'fake_packets': 0,
            'real_packets': 0,
            'bad_checksum': 0,
            'good_checksum': 0
        }
        
        sequences = []
        
        for i, pkt in enumerate(packets):
            if IP in pkt and TCP in pkt:
                stats['tcp'] += 1
                ip = pkt[IP]
                tcp = pkt[TCP]
                
                # TTL анализ
                stats['ttl_values'][ip.ttl] += 1
                
                # Флаги
                if tcp.flags.R:
                    stats['rst'] += 1
                if tcp.flags.S:
                    stats['syn'] += 1
                if tcp.flags.A:
                    stats['ack'] += 1
                if tcp.flags.P and tcp.flags.A:
                    stats['psh_ack'] += 1
                
                # Payload анализ
                if Raw in pkt:
                    stats['with_payload'] += 1
                    payload = bytes(pkt[Raw].load)
                    
                    # TLS Client Hello
                    if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                        stats['client_hello'] += 1
                        
                        # Определяем fake/real по TTL
                        if ip.ttl <= 10:
                            stats['fake_packets'] += 1
                            pkt_type = "FAKE"
                        else:
                            stats['real_packets'] += 1
                            pkt_type = "REAL"
                        
                        # Checksum анализ
                        if tcp.chksum == 0xDEAD:
                            stats['bad_checksum'] += 1
                            chk_status = "BAD"
                        else:
                            stats['good_checksum'] += 1
                            chk_status = "GOOD"
                        
                        sequences.append({
                            'index': i,
                            'type': pkt_type,
                            'src': f"{ip.src}:{tcp.sport}",
                            'dst': f"{ip.dst}:{tcp.dport}",
                            'seq': tcp.seq,
                            'ack': tcp.ack,
                            'ttl': ip.ttl,
                            'len': len(payload),
                            'flags': str(tcp.flags),
                            'checksum': f"0x{tcp.chksum:04X}",
                            'chk_status': chk_status
                        })
                    
                    # TLS Server Hello
                    if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x02:
                        stats['server_hello'] += 1
        
        # Вывод статистики
        print(f"\n📊 СТАТИСТИКА:")
        print(f"  TCP пакетов: {stats['tcp']}")
        print(f"  С payload: {stats['with_payload']}")
        print(f"  Client Hello: {stats['client_hello']}")
        print(f"  Server Hello: {stats['server_hello']}")
        print(f"  RST пакетов: {stats['rst']}")
        print(f"  SYN пакетов: {stats['syn']}")
        print(f"  PSH+ACK: {stats['psh_ack']}")
        
        print(f"\n🔢 TTL РАСПРЕДЕЛЕНИЕ:")
        for ttl, count in sorted(stats['ttl_values'].items()):
            print(f"  TTL={ttl}: {count} пакетов")
        
        print(f"\n🎭 FAKE/REAL ПАКЕТЫ:")
        print(f"  Fake (TTL≤10): {stats['fake_packets']}")
        print(f"  Real (TTL>10): {stats['real_packets']}")
        
        print(f"\n✓ CHECKSUM:")
        print(f"  Bad (0xDEAD): {stats['bad_checksum']}")
        print(f"  Good: {stats['good_checksum']}")
        
        if sequences:
            print(f"\n📋 ПОСЛЕДОВАТЕЛЬНОСТЬ CLIENT HELLO ПАКЕТОВ:")
            for seq in sequences:
                print(f"  [{seq['index']}] {seq['type']:4s} {seq['dst']:21s} "
                      f"seq=0x{seq['seq']:08X} len={seq['len']:3d} "
                      f"ttl={seq['ttl']:2d} chk={seq['checksum']} ({seq['chk_status']})")
        
        return stats, sequences
        
    except Exception as e:
        print(f"❌ Ошибка анализа PCAP: {e}")
        return None, None


def analyze_logs(log_file, summary_file):
    """Анализ логов и summary"""
    print(f"\n{'='*80}")
    print(f"📝 АНАЛИЗ ЛОГОВ")
    print(f"{'='*80}")
    
    issues = []
    
    # Анализ summary
    try:
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        
        print(f"\n📊 SUMMARY АНАЛИЗ:")
        print(f"  Success rate: {summary['success_rate']}%")
        print(f"  Strategies tested: {summary['total_strategies_tested']}")
        print(f"  Working strategies: {summary['working_strategies_found']}")
        
        if summary['success_rate'] == 0:
            issues.append("КРИТИЧНО: Success rate = 0% - обход НЕ РАБОТАЕТ")
        
        # Анализ telemetry
        for result in summary.get('all_results', []):
            telemetry = result.get('engine_telemetry', {})
            print(f"\n  Стратегия: {result['strategy_id']}")
            print(f"    segments_sent: {telemetry.get('segments_sent', 0)}")
            print(f"    fake_packets_sent: {telemetry.get('fake_packets_sent', 0)}")
            print(f"    CH: {telemetry.get('CH', 0)}")
            print(f"    SH: {telemetry.get('SH', 0)}")
            print(f"    RST: {telemetry.get('RST', 0)}")
            
            if telemetry.get('segments_sent', 0) == 0:
                issues.append(f"КРИТИЧНО: segments_sent=0 для стратегии {result['strategy_id']}")
            if telemetry.get('fake_packets_sent', 0) == 0:
                issues.append(f"КРИТИЧНО: fake_packets_sent=0 для стратегии {result['strategy_id']}")
    
    except Exception as e:
        print(f"❌ Ошибка анализа summary: {e}")
        issues.append(f"Ошибка чтения summary: {e}")
    
    # Анализ log.txt
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            log_content = f.read()
        
        print(f"\n📝 LOG.TXT АНАЛИЗ:")
        
        # Поиск ключевых паттернов
        patterns = {
            'bypass_applied': r'\[INFO\] 🎯 Applying bypass',
            'packets_sent': r'\[INFO\] 📤 (FAKE|REAL)',
            'rst_received': r'RST \(',
            'timeout': r'TIMEOUT \(',
            'ssl_error': r'ClientConnectorSSLError',
            'segments_sent': r'SegsSent=(\d+)',
            'fakes_sent': r'FakesSent=(\d+)',
        }
        
        for name, pattern in patterns.items():
            matches = re.findall(pattern, log_content)
            count = len(matches)
            print(f"  {name}: {count}")
            
            if name == 'bypass_applied' and count == 0:
                issues.append("КРИТИЧНО: Bypass не применялся ни разу!")
            elif name == 'packets_sent' and count == 0:
                issues.append("КРИТИЧНО: Пакеты не отправлялись!")
            elif name == 'rst_received' and count > 0:
                issues.append(f"ПРОБЛЕМА: Получено {count} RST пакетов")
        
        # Проверка на ошибки
        error_patterns = [
            r'\[ERROR\]',
            r'\[CRITICAL\]',
            r'Exception',
            r'Traceback',
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            if matches:
                issues.append(f"Найдены ошибки: {pattern} ({len(matches)} раз)")
        
    except Exception as e:
        print(f"❌ Ошибка анализа log.txt: {e}")
        issues.append(f"Ошибка чтения log.txt: {e}")
    
    return issues


def compare_pcaps(recon_pcap, zapret_pcap):
    """Сравнение PCAP файлов Recon vs Zapret"""
    print(f"\n{'='*80}")
    print(f"🔍 СРАВНЕНИЕ RECON vs ZAPRET")
    print(f"{'='*80}")
    
    try:
        recon_pkts = rdpcap(recon_pcap)
        zapret_pkts = rdpcap(zapret_pcap)
        
        print(f"\nКоличество пакетов:")
        print(f"  Recon:  {len(recon_pkts)}")
        print(f"  Zapret: {len(zapret_pkts)}")
        
        # Извлекаем Client Hello пакеты
        def extract_ch_packets(packets):
            ch_packets = []
            for pkt in packets:
                if IP in pkt and TCP in pkt and Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                        ch_packets.append({
                            'ttl': pkt[IP].ttl,
                            'seq': pkt[TCP].seq,
                            'len': len(payload),
                            'checksum': pkt[TCP].chksum,
                            'flags': str(pkt[TCP].flags)
                        })
            return ch_packets
        
        recon_ch = extract_ch_packets(recon_pkts)
        zapret_ch = extract_ch_packets(zapret_pkts)
        
        print(f"\nClient Hello пакетов:")
        print(f"  Recon:  {len(recon_ch)}")
        print(f"  Zapret: {len(zapret_ch)}")
        
        differences = []
        
        if len(recon_ch) != len(zapret_ch):
            diff = f"РАЗНИЦА: Количество CH пакетов (Recon={len(recon_ch)}, Zapret={len(zapret_ch)})"
            differences.append(diff)
            print(f"\n❌ {diff}")
        
        # Сравниваем пакеты
        print(f"\n📋 ДЕТАЛЬНОЕ СРАВНЕНИЕ:")
        for i, (r, z) in enumerate(zip(recon_ch, zapret_ch)):
            print(f"\n  Пакет {i+1}:")
            print(f"    Recon:  TTL={r['ttl']:2d} len={r['len']:3d} chk=0x{r['checksum']:04X} seq=0x{r['seq']:08X}")
            print(f"    Zapret: TTL={z['ttl']:2d} len={z['len']:3d} chk=0x{z['checksum']:04X} seq=0x{z['seq']:08X}")
            
            if r['ttl'] != z['ttl']:
                diff = f"Пакет {i+1}: TTL различается (Recon={r['ttl']}, Zapret={z['ttl']})"
                differences.append(diff)
                print(f"    ❌ {diff}")
            
            if r['len'] != z['len']:
                diff = f"Пакет {i+1}: Длина различается (Recon={r['len']}, Zapret={z['len']})"
                differences.append(diff)
                print(f"    ❌ {diff}")
            
            if r['checksum'] != z['checksum']:
                diff = f"Пакет {i+1}: Checksum различается (Recon=0x{r['checksum']:04X}, Zapret=0x{z['checksum']:04X})"
                differences.append(diff)
                print(f"    ❌ {diff}")
        
        return differences
        
    except Exception as e:
        print(f"❌ Ошибка сравнения PCAP: {e}")
        return [f"Ошибка сравнения: {e}"]


def analyze_code_issues():
    """Анализ потенциальных проблем в коде"""
    print(f"\n{'='*80}")
    print(f"🔍 АНАЛИЗ КОДА")
    print(f"{'='*80}")
    
    issues = []
    
    # Проверяем ключевые файлы
    files_to_check = [
        'cli.py',
        'core/bypass/engine/base_engine.py',
        'core/bypass/packet/builder.py',
        'core/bypass/packet/sender.py',
        'core/bypass/attacks/tcp/fake_disorder_attack.py'
    ]
    
    for file_path in files_to_check:
        full_path = Path(file_path)
        if not full_path.exists():
            issues.append(f"Файл не найден: {file_path}")
            continue
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Проверяем на потенциальные проблемы
            if 'TODO' in content or 'FIXME' in content:
                issues.append(f"{file_path}: Содержит TODO/FIXME")
            
            if 'raise NotImplementedError' in content:
                issues.append(f"{file_path}: Содержит NotImplementedError")
            
            if file_path == 'core/bypass/packet/builder.py':
                # Проверяем TTL
                if 'ttl = 128' in content:
                    issues.append(f"{file_path}: КРИТИЧНО - используется TTL=128 вместо 64")
                
                # Проверяем checksum
                if '0xDEAD' not in content:
                    issues.append(f"{file_path}: Возможно отсутствует bad checksum (0xDEAD)")
        
        except Exception as e:
            issues.append(f"Ошибка чтения {file_path}: {e}")
    
    return issues


def main():
    print("="*80)
    print("🔍 ГЛУБОКИЙ ГЛОБАЛЬНЫЙ АНАЛИЗ RECON")
    print("="*80)
    
    all_issues = []
    
    # 1. Анализ PCAP файлов
    recon_stats, recon_seq = analyze_pcap('recon_x1.pcap')
    zapret_stats, zapret_seq = analyze_pcap('zapret_x.pcap')
    
    # 2. Сравнение PCAP
    pcap_diffs = compare_pcaps('recon_x1.pcap', 'zapret_x.pcap')
    all_issues.extend(pcap_diffs)
    
    # 3. Анализ логов
    log_issues = analyze_logs('log.txt', 'recon_summary.json')
    all_issues.extend(log_issues)
    
    # 4. Анализ кода
    code_issues = analyze_code_issues()
    all_issues.extend(code_issues)
    
    # ИТОГОВЫЙ ОТЧЕТ
    print(f"\n{'='*80}")
    print(f"📋 ИТОГОВЫЙ ОТЧЕТ - ВСЕ НАЙДЕННЫЕ ПРОБЛЕМЫ")
    print(f"{'='*80}")
    
    if all_issues:
        print(f"\n❌ НАЙДЕНО {len(all_issues)} ПРОБЛЕМ:\n")
        for i, issue in enumerate(all_issues, 1):
            print(f"{i}. {issue}")
    else:
        print("\n✓ Критических проблем не найдено")
    
    # Сохраняем отчет
    report = {
        'timestamp': '2025-10-03',
        'total_issues': len(all_issues),
        'issues': all_issues,
        'recon_stats': recon_stats,
        'zapret_stats': zapret_stats,
        'pcap_differences': pcap_diffs
    }
    
    with open('DEEP_DIAGNOSIS_REPORT.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n✓ Отчет сохранен в DEEP_DIAGNOSIS_REPORT.json")


if __name__ == '__main__':
    main()
