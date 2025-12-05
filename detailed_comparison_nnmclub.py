#!/usr/bin/env python3
"""
Детальное сравнение применения стратегии для nnmclub.to
в режиме тестирования (log1.pcap) и режиме обхода (log2.pcap).
"""

from scapy.all import rdpcap, TCP, IP
import struct
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.validation.tls_version_checker import TLSVersionChecker


def log_tls_diagnostics(clienthello_payload, mode_name):
    """
    Log TLS version and ClientHello size diagnostics.
    
    Args:
        clienthello_payload: Raw ClientHello bytes
        mode_name: Name of the mode (e.g., "TEST", "BYPASS")
    """
    if not clienthello_payload:
        print(f"⚠️  No ClientHello found in {mode_name} mode")
        return None
    
    tls_version = TLSVersionChecker.extract_tls_version(clienthello_payload)
    size = len(clienthello_payload)
    
    print(f"📋 {mode_name} TLS Diagnostics:")
    print(f"  TLS Version: {tls_version or 'Unknown'}")
    print(f"  ClientHello Size: {size} bytes")
    
    return {
        'version': tls_version,
        'size': size,
        'payload': clienthello_payload
    }


def extract_sni(payload):
    """Extract SNI from TLS ClientHello."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
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

def find_nnmclub_stream(pkts):
    """Find main nnmclub.to stream."""
    streams = {}
    for p in pkts:
        if p.haslayer(TCP) and p.haslayer(IP):
            ip = p[IP]
            tcp = p[TCP]
            key = (ip.src, tcp.sport, ip.dst, tcp.dport)
            if key not in streams:
                streams[key] = []
            streams[key].append(p)
    
    # Find stream with nnmclub.to SNI and port 443 (not 20)
    for key, packets in streams.items():
        src_ip, src_port, dst_ip, dst_port = key
        
        if dst_port != 443 or src_port == 20:
            continue
        
        for p in packets:
            tcp = p[TCP]
            payload = bytes(tcp.payload) if tcp.payload else b''
            
            if len(payload) > 0:
                sni = extract_sni(payload)
                if sni and 'nnmclub' in sni.lower():
                    return key, packets
    
    return None, None

def analyze_packets(packets, mode_name):
    """Analyze packets in detail."""
    print(f"="*80)
    print(f"АНАЛИЗ ПАКЕТОВ: {mode_name}")
    print(f"="*80)
    print()
    
    # Separate handshake and data
    handshake = []
    data_packets = []
    clienthello_payload = None
    
    for p in packets:
        tcp = p[TCP]
        payload = bytes(tcp.payload) if tcp.payload else b''
        
        if len(payload) == 0:
            handshake.append(p)
        else:
            data_packets.append(p)
            # Try to find ClientHello (first data packet with TLS handshake)
            if clienthello_payload is None and len(payload) > 6 and payload[0] == 0x16:
                clienthello_payload = payload
    
    print(f"Всего пакетов: {len(packets)}")
    print(f"Пакеты рукопожатия: {len(handshake)}")
    print(f"Пакеты с данными: {len(data_packets)}")
    print()
    
    # Extract and log TLS version
    if clienthello_payload:
        tls_version = TLSVersionChecker.extract_tls_version(clienthello_payload)
        clienthello_size = len(clienthello_payload)
        
        print(f"📋 TLS Information:")
        print(f"  TLS Version: {tls_version or 'Unknown'}")
        print(f"  ClientHello Size: {clienthello_size} bytes")
        print()
    
    # Analyze each data packet
    print("Детальный анализ каждого пакета с данными:")
    print()
    
    fake_packets = []
    real_packets = []
    
    for i, p in enumerate(data_packets):
        ip = p[IP]
        tcp = p[TCP]
        payload = bytes(tcp.payload)
        
        # Detect fake
        is_fake = False
        fake_reasons = []
        
        if ip.ttl <= 3:
            is_fake = True
            fake_reasons.append(f"TTL={ip.ttl}")
        
        if tcp.chksum == 0xDEAD:
            is_fake = True
            fake_reasons.append("badsum=0xDEAD")
        
        packet_type = "FAKE" if is_fake else "REAL"
        
        print(f"Пакет #{i+1} [{packet_type}]:")
        print(f"  SEQ: {tcp.seq} (0x{tcp.seq:08X})")
        print(f"  ACK: {tcp.ack} (0x{tcp.ack:08X})")
        print(f"  Flags: {tcp.flags}")
        print(f"  TTL: {ip.ttl}")
        print(f"  Checksum: 0x{tcp.chksum:04X}")
        print(f"  Payload length: {len(payload)} bytes")
        
        if is_fake:
            print(f"  ⚠️  FAKE причины: {', '.join(fake_reasons)}")
            fake_packets.append((i, p, payload))
        else:
            print(f"  ✅ REAL packet")
            real_packets.append((i, p, payload))
        
        # Show first bytes
        if len(payload) > 0:
            print(f"  First 32 bytes: {payload[:32].hex()}")
        
        # Calculate relative SEQ
        if i > 0:
            prev_tcp = data_packets[i-1][TCP]
            seq_diff = tcp.seq - prev_tcp.seq
            print(f"  SEQ offset from prev: {seq_diff}")
        
        print()
    
    print(f"Итого:")
    print(f"  Fake пакеты: {len(fake_packets)}")
    print(f"  Real пакеты: {len(real_packets)}")
    print()
    
    return {
        'data_packets': data_packets,
        'fake_packets': fake_packets,
        'real_packets': real_packets,
        'clienthello_payload': clienthello_payload
    }

def compare_implementations(test_data, bypass_data):
    """Compare test and bypass implementations."""
    print("="*80)
    print("СРАВНЕНИЕ РЕАЛИЗАЦИЙ")
    print("="*80)
    print()
    
    differences = []
    
    # Compare TLS versions
    test_hello = test_data.get('clienthello_payload')
    bypass_hello = bypass_data.get('clienthello_payload')
    
    if test_hello and bypass_hello:
        print("🔍 TLS Version Comparison:")
        is_consistent, details = TLSVersionChecker.check_consistency(test_hello, bypass_hello)
        
        print(f"  TEST:   {details['test_version']} ({details['test_size']} bytes)")
        print(f"  BYPASS: {details['bypass_version']} ({details['bypass_size']} bytes)")
        
        if not is_consistent:
            differences.append(
                f"TLS version mismatch: TEST={details['test_version']}, "
                f"BYPASS={details['bypass_version']}"
            )
            print(f"  ❌ VERSION MISMATCH - This explains testing inconsistencies!")
        else:
            print(f"  ✅ VERSIONS MATCH")
        
        # Check size difference
        size_diff_percent = details['size_diff_percent']
        if size_diff_percent > 50:
            differences.append(
                f"ClientHello size differs by {size_diff_percent:.1f}%: "
                f"TEST={details['test_size']}, BYPASS={details['bypass_size']}"
            )
            print(f"  ⚠️  SIZE DIFFERS BY {size_diff_percent:.1f}%")
            print(f"     This large size difference may indicate TLS version mismatch.")
            print(f"     💡 Suggestion: Check TLS version configuration in TEST mode.")
            print(f"     Configure TEST mode to use the same TLS version as BYPASS mode.")
        else:
            print(f"  ✅ SIZE DIFFERENCE: {size_diff_percent:.1f}%")
        
        print()
    else:
        print("⚠️  Could not extract ClientHello from one or both modes")
        print()
    
    # Compare counts
    test_count = len(test_data['data_packets'])
    bypass_count = len(bypass_data['data_packets'])
    
    print(f"Количество пакетов с данными:")
    print(f"  TEST:   {test_count}")
    print(f"  BYPASS: {bypass_count}")
    
    if test_count != bypass_count:
        differences.append(f"Packet count: test={test_count}, bypass={bypass_count}")
        print(f"  ❌ РАЗЛИЧИЕ")
    else:
        print(f"  ✅ СОВПАДАЕТ")
    print()
    
    # Compare fake counts
    test_fake = len(test_data['fake_packets'])
    bypass_fake = len(bypass_data['fake_packets'])
    
    print(f"Количество fake пакетов:")
    print(f"  TEST:   {test_fake}")
    print(f"  BYPASS: {bypass_fake}")
    
    if test_fake != bypass_fake:
        differences.append(f"Fake count: test={test_fake}, bypass={bypass_fake}")
        print(f"  ❌ РАЗЛИЧИЕ")
    else:
        print(f"  ✅ СОВПАДАЕТ")
    print()
    
    # Compare real counts
    test_real = len(test_data['real_packets'])
    bypass_real = len(bypass_data['real_packets'])
    
    print(f"Количество real пакетов:")
    print(f"  TEST:   {test_real}")
    print(f"  BYPASS: {bypass_real}")
    
    if test_real != bypass_real:
        differences.append(f"Real count: test={test_real}, bypass={bypass_real}")
        print(f"  ❌ РАЗЛИЧИЕ")
    else:
        print(f"  ✅ СОВПАДАЕТ")
    print()
    
    # Compare packet by packet
    print("="*80)
    print("ПОПАКЕТНОЕ СРАВНЕНИЕ")
    print("="*80)
    print()
    
    max_packets = max(test_count, bypass_count)
    
    for i in range(max_packets):
        test_pkt = test_data['data_packets'][i] if i < test_count else None
        bypass_pkt = bypass_data['data_packets'][i] if i < bypass_count else None
        
        print(f"--- Пакет #{i+1} ---")
        
        if test_pkt:
            test_ip = test_pkt[IP]
            test_tcp = test_pkt[TCP]
            test_payload = bytes(test_tcp.payload)
            test_fake = test_ip.ttl <= 3 or test_tcp.chksum == 0xDEAD
            
            print(f"TEST:   seq={test_tcp.seq:10d}, len={len(test_payload):4d}, "
                  f"ttl={test_ip.ttl:3d}, csum=0x{test_tcp.chksum:04X}, fake={test_fake}")
        else:
            print(f"TEST:   ОТСУТСТВУЕТ")
        
        if bypass_pkt:
            bypass_ip = bypass_pkt[IP]
            bypass_tcp = bypass_pkt[TCP]
            bypass_payload = bytes(bypass_tcp.payload)
            bypass_fake = bypass_ip.ttl <= 3 or bypass_tcp.chksum == 0xDEAD
            
            print(f"BYPASS: seq={bypass_tcp.seq:10d}, len={len(bypass_payload):4d}, "
                  f"ttl={bypass_ip.ttl:3d}, csum=0x{bypass_tcp.chksum:04X}, fake={bypass_fake}")
        else:
            print(f"BYPASS: ОТСУТСТВУЕТ")
        
        # Compare
        if test_pkt and bypass_pkt:
            issues = []
            
            if test_ip.ttl != bypass_ip.ttl:
                issues.append(f"TTL: {test_ip.ttl} vs {bypass_ip.ttl}")
                differences.append(f"Packet #{i+1}: TTL mismatch")
            
            if test_tcp.chksum != bypass_tcp.chksum:
                issues.append(f"Checksum: 0x{test_tcp.chksum:04X} vs 0x{bypass_tcp.chksum:04X}")
                differences.append(f"Packet #{i+1}: Checksum mismatch")
            
            if len(test_payload) != len(bypass_payload):
                issues.append(f"Length: {len(test_payload)} vs {len(bypass_payload)}")
                differences.append(f"Packet #{i+1}: Length mismatch")
            
            if test_fake != bypass_fake:
                issues.append(f"Fake: {test_fake} vs {bypass_fake}")
                differences.append(f"Packet #{i+1}: Fake status mismatch")
            
            # Compare first bytes of payload
            if len(test_payload) > 0 and len(bypass_payload) > 0:
                test_first = test_payload[:min(32, len(test_payload))]
                bypass_first = bypass_payload[:min(32, len(bypass_payload))]
                
                if test_first != bypass_first:
                    issues.append("Payload content differs")
                    differences.append(f"Packet #{i+1}: Payload differs")
            
            if issues:
                print(f"❌ РАЗЛИЧИЯ: {', '.join(issues)}")
            else:
                print(f"✅ ИДЕНТИЧНЫ")
        elif not test_pkt:
            differences.append(f"Packet #{i+1}: Missing in test")
        elif not bypass_pkt:
            differences.append(f"Packet #{i+1}: Missing in bypass")
        
        print()
    
    return differences

def main():
    print("="*80)
    print("ДЕТАЛЬНОЕ СРАВНЕНИЕ СТРАТЕГИИ ДЛЯ NNMCLUB.TO")
    print("="*80)
    print()
    
    # Load PCAPs
    print("Загрузка PCAP файлов...")
    test_pkts = rdpcap('log1.pcap')
    bypass_pkts = rdpcap('log2.pcap')
    print(f"  log1.pcap: {len(test_pkts)} пакетов")
    print(f"  log2.pcap: {len(bypass_pkts)} пакетов")
    print()
    
    # Find nnmclub.to streams
    print("Поиск потоков nnmclub.to...")
    test_key, test_stream = find_nnmclub_stream(test_pkts)
    bypass_key, bypass_stream = find_nnmclub_stream(bypass_pkts)
    
    if not test_stream:
        print("❌ Не найден поток nnmclub.to в log1.pcap")
        return
    
    if not bypass_stream:
        print("❌ Не найден поток nnmclub.to в log2.pcap")
        return
    
    print(f"✅ TEST:   {test_key[0]}:{test_key[1]} -> {test_key[2]}:{test_key[3]}")
    print(f"✅ BYPASS: {bypass_key[0]}:{bypass_key[1]} -> {bypass_key[2]}:{bypass_key[3]}")
    print()
    
    # Analyze both
    test_data = analyze_packets(test_stream, "РЕЖИМ ТЕСТИРОВАНИЯ (log1.pcap)")
    bypass_data = analyze_packets(bypass_stream, "РЕЖИМ ОБХОДА (log2.pcap)")
    
    # Compare
    differences = compare_implementations(test_data, bypass_data)
    
    # Summary
    print("="*80)
    print("ИТОГОВАЯ ОЦЕНКА")
    print("="*80)
    print()
    
    if not differences:
        print("✅ Стратегия применяется ИДЕНТИЧНО в обоих режимах!")
        print()
        print("Это означает, что проблема НЕ в различии реализаций,")
        print("а в самой стратегии (например, неправильный TTL).")
    else:
        print(f"❌ Обнаружено {len(differences)} различий:")
        print()
        for i, diff in enumerate(differences, 1):
            print(f"{i}. {diff}")
        print()
        print("💡 Эти различия объясняют почему стратегия работает по-разному!")

if __name__ == '__main__':
    main()
