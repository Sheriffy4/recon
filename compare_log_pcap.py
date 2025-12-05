#!/usr/bin/env python3
"""
Compare log file strategies with actual PCAP behavior.
Identifies discrepancies between expected and actual attack application.
"""

import re
import sys
from pathlib import Path
from scapy.all import rdpcap, TCP, IP, Raw
import struct

def parse_log_strategies(log_file):
    """Extract strategy information from log file."""
    strategies = []
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Find strategy applications
    pattern = r"APPLY_BYPASS.*?strategy=(\w+),\s*params=(\{[^}]+\})"
    matches = re.findall(pattern, content)
    
    for strategy_type, params_str in matches:
        try:
            # Parse params dict
            params = eval(params_str)
            strategies.append({
                'type': strategy_type,
                'params': params
            })
        except:
            strategies.append({
                'type': strategy_type,
                'params_raw': params_str
            })
    
    # Find combination attacks
    combo_pattern = r"Using combination attack.*?attacks=\[([^\]]+)\]"
    combo_matches = re.findall(combo_pattern, content)
    
    for combo in combo_matches:
        attacks = [a.strip().strip("'\"") for a in combo.split(',')]
        strategies.append({
            'type': 'combo',
            'attacks': attacks
        })
    
    return strategies

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
    except:
        return None

def analyze_pcap_attacks(pcap_file, target_domain=None):
    """Analyze PCAP for actual attack patterns."""
    pkts = rdpcap(pcap_file)
    
    # Group by stream
    streams = {}
    for p in pkts:
        if not p.haslayer(TCP) or not p.haslayer(IP):
            continue
        ip = p[IP]
        tcp = p[TCP]
        if tcp.dport != 443:
            continue
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        if key not in streams:
            streams[key] = []
        streams[key].append(p)
    
    results = []
    
    for stream_key, packets in streams.items():
        src_ip, src_port, dst_ip, dst_port = stream_key
        
        # Analyze stream
        fake_packets = []
        real_packets = []
        payloads = []
        
        for p in packets:
            ip = p[IP]
            tcp = p[TCP]
            payload = bytes(tcp.payload) if tcp.payload else b''
            
            is_fake = False
            fake_indicators = []
            
            if ip.ttl <= 3:
                is_fake = True
                fake_indicators.append(f"low_ttl={ip.ttl}")
            
            if tcp.chksum == 0xDEAD:
                is_fake = True
                fake_indicators.append("badsum=0xDEAD")
            
            if is_fake:
                fake_packets.append({
                    'ttl': ip.ttl,
                    'chksum': hex(tcp.chksum),
                    'seq': tcp.seq,
                    'len': len(payload),
                    'indicators': fake_indicators
                })
            elif len(payload) > 0:
                real_packets.append({
                    'ttl': ip.ttl,
                    'seq': tcp.seq,
                    'len': len(payload)
                })
                payloads.append((tcp.seq, payload))
        
        if not payloads:
            continue
        
        # Reassemble and get SNI
        payloads.sort(key=lambda x: x[0])
        reassembled = b''.join([p[1] for p in payloads])
        sni = extract_sni(reassembled)
        
        if target_domain and sni and target_domain not in sni:
            continue
        
        # Detect attacks
        detected = {
            'stream': f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
            'sni': sni,
            'fake_detected': len(fake_packets) > 0,
            'fake_count': len(fake_packets),
            'fake_ttls': list(set(f['ttl'] for f in fake_packets)) if fake_packets else [],
            'fake_methods': list(set(ind for f in fake_packets for ind in f['indicators'])),
            'split_detected': len(real_packets) > 1,
            'fragment_count': len(real_packets),
            'fragment_sizes': [p['len'] for p in real_packets],
            'disorder_detected': False,
            'real_ttls': list(set(p['ttl'] for p in real_packets))
        }
        
        # Check for disorder
        if len(real_packets) > 1:
            seqs = [p['seq'] for p in real_packets]
            if seqs != sorted(seqs):
                detected['disorder_detected'] = True
        
        results.append(detected)
    
    return results

def compare_strategies(log_strategies, pcap_attacks, target_domain):
    """Compare expected strategies with actual PCAP behavior."""
    print("\n" + "="*80)
    print("STRATEGY vs PCAP COMPARISON")
    print("="*80)
    
    # Find relevant PCAP streams
    relevant_attacks = [a for a in pcap_attacks if a['sni'] and target_domain in a['sni']]
    
    print(f"\nTarget domain: {target_domain}")
    print(f"Strategies in log: {len(log_strategies)}")
    print(f"Relevant streams in PCAP: {len(relevant_attacks)}")
    
    # Expected from log
    print("\n--- EXPECTED (from log) ---")
    for i, strat in enumerate(log_strategies[:5]):  # Show first 5
        print(f"\n[{i+1}] Type: {strat.get('type', 'unknown')}")
        if 'params' in strat:
            params = strat['params']
            print(f"    TTL: {params.get('ttl', 'N/A')}")
            print(f"    Fooling: {params.get('fooling', 'N/A')}")
            print(f"    Split pos: {params.get('split_pos', 'N/A')}")
            print(f"    Split count: {params.get('split_count', 'N/A')}")
            print(f"    Disorder: {params.get('disorder_method', 'N/A')}")
        if 'attacks' in strat:
            print(f"    Attacks: {strat['attacks']}")
    
    # Actual from PCAP
    print("\n--- ACTUAL (from PCAP) ---")
    for i, attack in enumerate(relevant_attacks[:5]):  # Show first 5
        print(f"\n[{i+1}] Stream: {attack['stream']}")
        print(f"    SNI: {attack['sni']}")
        print(f"    Fake detected: {attack['fake_detected']} (count: {attack['fake_count']})")
        if attack['fake_detected']:
            print(f"    Fake TTLs: {attack['fake_ttls']}")
            print(f"    Fake methods: {attack['fake_methods']}")
        print(f"    Split detected: {attack['split_detected']} (fragments: {attack['fragment_count']})")
        print(f"    Fragment sizes: {attack['fragment_sizes']}")
        print(f"    Disorder detected: {attack['disorder_detected']}")
        print(f"    Real packet TTLs: {attack['real_ttls']}")
    
    # Discrepancies
    print("\n--- DISCREPANCIES ---")
    discrepancies = []
    
    if log_strategies:
        expected = log_strategies[0].get('params', {})
        
        for attack in relevant_attacks:
            issues = []
            
            # Check TTL
            expected_ttl = expected.get('ttl')
            if expected_ttl and attack['fake_detected']:
                if expected_ttl not in attack['fake_ttls']:
                    issues.append(f"TTL mismatch: expected {expected_ttl}, got {attack['fake_ttls']}")
            
            # Check split count
            expected_split = expected.get('split_count')
            if expected_split and attack['split_detected']:
                if attack['fragment_count'] != expected_split:
                    issues.append(f"Split count mismatch: expected {expected_split}, got {attack['fragment_count']}")
            
            # Check fooling method
            expected_fooling = expected.get('fooling')
            if expected_fooling and attack['fake_detected']:
                if expected_fooling == 'badseq' and 'badsum=0xDEAD' in attack['fake_methods']:
                    issues.append(f"Fooling mismatch: expected badseq, got badsum")
                elif expected_fooling == 'badsum' and 'low_ttl' in str(attack['fake_methods']):
                    issues.append(f"Fooling mismatch: expected badsum, got low_ttl only")
            
            if issues:
                discrepancies.append({
                    'stream': attack['stream'],
                    'sni': attack['sni'],
                    'issues': issues
                })
    
    if discrepancies:
        for d in discrepancies:
            print(f"\n  Stream: {d['stream']} ({d['sni']})")
            for issue in d['issues']:
                print(f"    ⚠️  {issue}")
    else:
        print("\n  No major discrepancies found.")
    
    return discrepancies

def main():
    log_file = "test_no_time_filter.txt"
    pcap_file = "log1.pcap"
    target_domain = "nnmclub.to"
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    if len(sys.argv) > 2:
        pcap_file = sys.argv[2]
    if len(sys.argv) > 3:
        target_domain = sys.argv[3]
    
    print(f"Log file: {log_file}")
    print(f"PCAP file: {pcap_file}")
    print(f"Target domain: {target_domain}")
    
    # Parse log
    print("\nParsing log file...")
    log_strategies = parse_log_strategies(log_file)
    print(f"Found {len(log_strategies)} strategy entries")
    
    # Analyze PCAP
    print("\nAnalyzing PCAP file...")
    pcap_attacks = analyze_pcap_attacks(pcap_file, target_domain)
    print(f"Found {len(pcap_attacks)} relevant streams")
    
    # Compare
    discrepancies = compare_strategies(log_strategies, pcap_attacks, target_domain)
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total discrepancies: {len(discrepancies)}")
    
    if discrepancies:
        print("\n⚠️  There are mismatches between expected and actual attack application!")
        print("   This may indicate bugs in the attack dispatcher or parameter handling.")
    else:
        print("\n✅ Strategy application appears consistent with expectations.")

if __name__ == '__main__':
    main()
