#!/usr/bin/env python3

import scapy.all as scapy

def analyze_last_flow():
    try:
        packets = scapy.rdpcap('test_fix.pcap')
        print(f'Total packets: {len(packets)}')
        
        # Найдем последний поток к googlevideo.com (142.250.74.100)
        googlevideo_flows = {}
        for p in packets:
            if scapy.TCP in p and scapy.IP in p:
                if p[scapy.IP].dst == '142.250.74.100' or p[scapy.IP].src == '142.250.74.100':
                    flow_key = (p[scapy.IP].src, p[scapy.TCP].sport, p[scapy.IP].dst, p[scapy.TCP].dport)
                    if flow_key not in googlevideo_flows:
                        googlevideo_flows[flow_key] = []
                    googlevideo_flows[flow_key].append(p)
        
        print(f'GoogleVideo flows: {len(googlevideo_flows)}')
        
        # Найдем поток с портом 63513 (из лога)
        target_flow = None
        for flow_key, flow_packets in googlevideo_flows.items():
            src_ip, src_port, dst_ip, dst_port = flow_key
            if src_port == 63513 or dst_port == 63513:
                target_flow = (flow_key, flow_packets)
                break
        
        if target_flow:
            flow_key, flow_packets = target_flow
            src_ip, src_port, dst_ip, dst_port = flow_key
            print(f'\nTarget flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}')
            print(f'Packets: {len(flow_packets)}')
            
            # Анализ пакетов по времени
            for i, p in enumerate(flow_packets):
                flags = p[scapy.TCP].flags
                seq = p[scapy.TCP].seq
                ack = p[scapy.TCP].ack
                payload_len = len(p[scapy.Raw]) if scapy.Raw in p else 0
                
                print(f'  Packet {i+1}: flags={flags}, seq={seq:08x}, ack={ack:08x}, len={payload_len}')
                
                if scapy.Raw in p and payload_len > 0:
                    payload = bytes(p[scapy.Raw])
                    # Проверка на TLS ClientHello
                    if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03 and payload[5] == 0x01:
                        print(f'    -> TLS ClientHello detected')
                        # Проверим SNI
                        try:
                            # Простой поиск SNI в payload
                            if b'googlevideo.com' in payload:
                                print(f'    -> SNI: googlevideo.com found')
                        except:
                            pass
                    
                    # Показать первые байты
                    print(f'    -> First 20 bytes: {payload[:20].hex()}')
                
                # Проверка на RST
                if flags & 0x04:  # RST flag
                    print(f'    -> RST packet detected!')
        
        # Также проверим все потоки с RST пакетами
        print(f'\n=== RST Analysis ===')
        rst_count = 0
        for flow_key, flow_packets in googlevideo_flows.items():
            src_ip, src_port, dst_ip, dst_port = flow_key
            rst_packets = [p for p in flow_packets if p[scapy.TCP].flags & 0x04]
            if rst_packets:
                rst_count += len(rst_packets)
                print(f'Flow {src_ip}:{src_port} -> {dst_ip}:{dst_port}: {len(rst_packets)} RST packets')
                for rst in rst_packets:
                    print(f'  RST: seq={rst[scapy.TCP].seq:08x}, ack={rst[scapy.TCP].ack:08x}')
        
        print(f'Total RST packets to/from googlevideo: {rst_count}')

    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    analyze_last_flow()