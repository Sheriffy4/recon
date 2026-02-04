#!/usr/bin/env python3

import scapy.all as scapy
import sys

def analyze_pcap(filename):
    try:
        packets = scapy.rdpcap(filename)
        print(f'Total packets: {len(packets)}')
        
        # Анализ пакетов
        tcp_packets = [p for p in packets if scapy.TCP in p]
        print(f'TCP packets: {len(tcp_packets)}')
        
        # Группировка по потокам
        flows = {}
        for p in tcp_packets:
            if scapy.IP in p:
                flow_key = (p[scapy.IP].src, p[scapy.TCP].sport, p[scapy.IP].dst, p[scapy.TCP].dport)
                if flow_key not in flows:
                    flows[flow_key] = []
                flows[flow_key].append(p)
        
        print(f'Unique flows: {len(flows)}')
        
        # Анализ каждого потока
        for i, (flow_key, flow_packets) in enumerate(flows.items()):
            src_ip, src_port, dst_ip, dst_port = flow_key
            print(f'\nFlow {i+1}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}')
            print(f'  Packets: {len(flow_packets)}')
            
            # Анализ флагов TCP
            flags_count = {}
            for p in flow_packets:
                flags = p[scapy.TCP].flags
                flags_count[flags] = flags_count.get(flags, 0) + 1
            
            print(f'  TCP flags: {flags_count}')
            
            # Проверка на TLS ClientHello
            tls_packets = []
            for p in flow_packets:
                if scapy.Raw in p:
                    payload = bytes(p[scapy.Raw])
                    if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:  # TLS Handshake
                        if len(payload) > 5 and payload[5] == 0x01:  # ClientHello
                            tls_packets.append(p)
            
            print(f'  TLS ClientHello packets: {len(tls_packets)}')
            
            # Анализ последовательности пакетов
            if flow_packets:
                seq_nums = [p[scapy.TCP].seq for p in flow_packets]
                print(f'  Sequence numbers: {seq_nums[:5]}...' if len(seq_nums) > 5 else f'  Sequence numbers: {seq_nums}')
                
            # Проверка на RST пакеты
            rst_packets = [p for p in flow_packets if p[scapy.TCP].flags & 0x04]  # RST flag
            if rst_packets:
                print(f'  RST packets found: {len(rst_packets)}')
                for rst in rst_packets:
                    print(f'    RST: seq={rst[scapy.TCP].seq}, ack={rst[scapy.TCP].ack}')
            
            # Детальный анализ первых пакетов
            if len(flow_packets) > 0:
                print(f'  First packet details:')
                p = flow_packets[0]
                print(f'    Seq: {p[scapy.TCP].seq}, Ack: {p[scapy.TCP].ack}, Flags: {p[scapy.TCP].flags}')
                if scapy.Raw in p:
                    payload = bytes(p[scapy.Raw])
                    print(f'    Payload length: {len(payload)}')
                    if len(payload) > 0:
                        print(f'    First 20 bytes: {payload[:20].hex()}')

    except Exception as e:
        print(f'Error analyzing PCAP: {e}')
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    analyze_pcap('test_fix.pcap')