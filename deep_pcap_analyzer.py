#!/usr/bin/env python3
"""
Deep PCAP Analysis Tool - Task 2
Analyzes PCAP files to identify TCP connections, TLS handshakes, and false positives
"""

import os
import sys
from scapy.all import rdpcap, TCP, IP, Raw
from collections import defaultdict
from datetime import datetime

class DeepPCAPAnalyzer:
    def __init__(self, pcap_dir):
        self.pcap_dir = pcap_dir
        self.connections = []
        
    def analyze_pcap_file(self, pcap_path):
        """Analyze single PCAP file and extract all TCP connections"""
        print(f"\n{'='*80}")
        print(f"📁 Analyzing: {os.path.basename(pcap_path)}")
        print(f"{'='*80}")
        
        try:
            packets = rdpcap(pcap_path)
            print(f"📦 Total packets: {len(packets)}")
            
            # Group packets by TCP connection
            connections = defaultdict(list)
            
            for i, pkt in enumerate(packets, 1):
                if IP in pkt and TCP in pkt:
                    ip_layer = pkt[IP]
                    tcp_layer = pkt[TCP]
                    
                    # Create connection tuple (src_ip:port -> dst_ip:port)
                    conn_key = (
                        ip_layer.src, tcp_layer.sport,
                        ip_layer.dst, tcp_layer.dport
                    )
                    
                    connections[conn_key].append({
                        'packet_num': i,
                        'timestamp': float(pkt.time) if hasattr(pkt, 'time') else 0,
                        'flags': tcp_layer.flags,
                        'seq': tcp_layer.seq,
                        'ack': tcp_layer.ack,
                        'payload_len': len(tcp_layer.payload) if tcp_layer.payload else 0,
                        'packet': pkt
                    })
            
            print(f"\n🔗 TCP Connections found: {len(connections)}")
            
            # Analyze each connection
            connection_results = []
            for conn_key, pkts in connections.items():
                result = self.analyze_connection(conn_key, pkts, pcap_path)
                connection_results.append(result)
            
            return {
                'file': pcap_path,
                'total_packets': len(packets),
                'connections': connection_results
            }
            
        except Exception as e:
            print(f"❌ Error analyzing {pcap_path}: {e}")
            return None
    
    def analyze_connection(self, conn_key, packets, pcap_path):
        """Analyze single TCP connection for TLS handshake"""
        src_ip, src_port, dst_ip, dst_port = conn_key
        
        print(f"\n{'─'*80}")
        print(f"🔗 Connection: {src_ip}:{src_port} → {dst_ip}:{dst_port}")
        print(f"   Packets: {len(packets)}")
        
        # Analyze TLS handshake
        client_hello = None
        server_hello = None
        sni = None
        
        for pkt_info in packets:
            pkt = pkt_info['packet']
            
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                
                # Check for TLS handshake
                if len(payload) >= 6 and payload[0] == 0x16:  # TLS Handshake
                    handshake_type = payload[5] if len(payload) > 5 else None
                    
                    # ClientHello (0x01)
                    if handshake_type == 0x01:
                        client_hello = pkt_info['packet_num']
                        sni = self.extract_sni(payload)
                        print(f"   📤 ClientHello: packet #{client_hello}")
                        if sni:
                            print(f"      SNI: {sni}")
                    
                    # ServerHello (0x02)
                    elif handshake_type == 0x02:
                        server_hello = pkt_info['packet_num']
                        print(f"   📥 ServerHello: packet #{server_hello}")
        
        # Determine connection status
        if client_hello and server_hello:
            status = "✅ COMPLETE (CH + SH)"
        elif client_hello:
            status = "⚠️ INCOMPLETE (CH only)"
        elif server_hello:
            status = "🚨 SUSPICIOUS (SH without CH)"
        else:
            status = "❌ NO TLS"
        
        print(f"   Status: {status}")
        
        return {
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'packet_count': len(packets),
            'client_hello_packet': client_hello,
            'server_hello_packet': server_hello,
            'sni': sni,
            'status': status,
            'pcap_file': os.path.basename(pcap_path)
        }
    
    def extract_sni(self, payload):
        """Extract SNI from ClientHello payload"""
        try:
            # Simple SNI extraction (not complete TLS parser)
            # Look for SNI extension (0x0000)
            if b'\x00\x00' in payload:
                idx = payload.find(b'\x00\x00')
                # Try to find domain name after SNI marker
                for i in range(idx, min(idx + 200, len(payload))):
                    if payload[i:i+1].isalpha():
                        # Found potential domain start
                        end = i
                        while end < len(payload) and (payload[end:end+1].isalnum() or payload[end:end+1] in b'.-'):
                            end += 1
                        domain = payload[i:end].decode('ascii', errors='ignore')
                        if '.' in domain and len(domain) > 5:
                            return domain
            return None
        except:
            return None
    
    def analyze_all_googlevideo_pcaps(self):
        """Analyze all googlevideo.com PCAP files"""
        pcap_files = []
        
        # Find all googlevideo.com PCAP files
        for filename in os.listdir(self.pcap_dir):
            if 'googlevideo' in filename and filename.endswith('.pcap'):
                pcap_files.append(os.path.join(self.pcap_dir, filename))
        
        pcap_files.sort()
        
        print(f"\n{'='*80}")
        print(f"🎯 Found {len(pcap_files)} googlevideo.com PCAP files")
        print(f"{'='*80}")
        
        all_results = []
        for pcap_file in pcap_files:
            result = self.analyze_pcap_file(pcap_file)
            if result:
                all_results.append(result)
        
        return all_results
    
    def generate_summary_report(self, results):
        """Generate summary report of all analyses"""
        print(f"\n\n{'='*80}")
        print(f"📊 SUMMARY REPORT")
        print(f"{'='*80}")
        
        total_files = len(results)
        total_connections = sum(len(r['connections']) for r in results)
        
        # Count connections by status
        status_counts = defaultdict(int)
        connections_with_sh = []
        
        for result in results:
            for conn in result['connections']:
                status_counts[conn['status']] += 1
                if conn['server_hello_packet']:
                    connections_with_sh.append({
                        'file': result['file'],
                        'connection': f"{conn['src_ip']}:{conn['src_port']} → {conn['dst_ip']}:{conn['dst_port']}",
                        'sni': conn['sni'],
                        'sh_packet': conn['server_hello_packet'],
                        'ch_packet': conn['client_hello_packet']
                    })
        
        print(f"\n📁 Files analyzed: {total_files}")
        print(f"🔗 Total connections: {total_connections}")
        print(f"\n📊 Connection Status:")
        for status, count in sorted(status_counts.items()):
            print(f"   {status}: {count}")
        
        print(f"\n\n{'='*80}")
        print(f"🔍 CONNECTIONS WITH ServerHello ({len(connections_with_sh)})")
        print(f"{'='*80}")
        
        for i, conn in enumerate(connections_with_sh, 1):
            print(f"\n{i}. File: {os.path.basename(conn['file'])}")
            print(f"   Connection: {conn['connection']}")
            print(f"   SNI: {conn['sni']}")
            print(f"   ClientHello: packet #{conn['ch_packet']}")
            print(f"   ServerHello: packet #{conn['sh_packet']}")
        
        return {
            'total_files': total_files,
            'total_connections': total_connections,
            'status_counts': dict(status_counts),
            'connections_with_sh': connections_with_sh
        }


def main():
    pcap_dir = r"C:\Users\admin\Downloads\zapretttt\DPI_Blockcheck\recon_v109\recon_v09\combo\recon\recon_pcap"
    
    if not os.path.exists(pcap_dir):
        print(f"❌ PCAP directory not found: {pcap_dir}")
        return
    
    analyzer = DeepPCAPAnalyzer(pcap_dir)
    results = analyzer.analyze_all_googlevideo_pcaps()
    summary = analyzer.generate_summary_report(results)
    
    # Save detailed report
    print(f"\n\n{'='*80}")
    print(f"💾 Saving detailed report...")
    print(f"{'='*80}")
    
    with open('TASK2_PCAP_ANALYSIS.md', 'w', encoding='utf-8') as f:
        f.write("# Task 2: Deep PCAP Analysis - Complete\n\n")
        f.write(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**PCAP Directory**: {pcap_dir}\n\n")
        f.write("---\n\n")
        
        f.write("## Executive Summary\n\n")
        f.write(f"- **Files analyzed**: {summary['total_files']}\n")
        f.write(f"- **Total connections**: {summary['total_connections']}\n")
        f.write(f"- **Connections with ServerHello**: {len(summary['connections_with_sh'])}\n\n")
        
        f.write("### Connection Status Distribution\n\n")
        for status, count in sorted(summary['status_counts'].items()):
            f.write(f"- {status}: {count}\n")
        
        f.write("\n---\n\n")
        f.write("## Detailed Analysis\n\n")
        
        for result in results:
            f.write(f"### {os.path.basename(result['file'])}\n\n")
            f.write(f"- **Total packets**: {result['total_packets']}\n")
            f.write(f"- **Connections**: {len(result['connections'])}\n\n")
            
            for conn in result['connections']:
                f.write(f"#### Connection: {conn['src_ip']}:{conn['src_port']} → {conn['dst_ip']}:{conn['dst_port']}\n\n")
                f.write(f"- **Packets**: {conn['packet_count']}\n")
                f.write(f"- **Status**: {conn['status']}\n")
                if conn['sni']:
                    f.write(f"- **SNI**: {conn['sni']}\n")
                if conn['client_hello_packet']:
                    f.write(f"- **ClientHello**: packet #{conn['client_hello_packet']}\n")
                if conn['server_hello_packet']:
                    f.write(f"- **ServerHello**: packet #{conn['server_hello_packet']}\n")
                f.write("\n")
        
        f.write("\n---\n\n")
        f.write("## Connections with ServerHello\n\n")
        
        for i, conn in enumerate(summary['connections_with_sh'], 1):
            f.write(f"### {i}. {os.path.basename(conn['file'])}\n\n")
            f.write(f"- **Connection**: {conn['connection']}\n")
            f.write(f"- **SNI**: {conn['sni']}\n")
            f.write(f"- **ClientHello**: packet #{conn['ch_packet']}\n")
            f.write(f"- **ServerHello**: packet #{conn['sh_packet']}\n\n")
    
    print(f"✅ Report saved to: TASK2_PCAP_ANALYSIS.md")


if __name__ == '__main__':
    main()
