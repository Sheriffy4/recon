#!/usr/bin/env python3
"""
Focused analysis of work.pcap for problematic domains
Analyzes Instagram, X.com, and YouTube traffic patterns
"""

import os
import struct
import socket
from collections import defaultdict, Counter
import json
from datetime import datetime

class WorkPcapFocusedAnalyzer:
    def __init__(self, pcap_file="work.pcap"):
        self.pcap_file = pcap_file
        self.target_domains = [
            'instagram.com', 'www.instagram.com', 'static.cdninstagram.com', 
            'scontent-arn2-1.cdninstagram.com', 'edge-chat.instagram.com',
            'x.com', 'www.x.com', 'api.x.com', 'mobile.x.com',
            'youtube.com', 'www.youtube.com', 'youtubei.googleapis.com',
            'rutracker.org', 'www.rutracker.org'
        ]
        
        self.tls_handshakes = []
        self.domain_connections = defaultdict(list)
        self.strategy_attempts = defaultdict(list)
        self.dpi_patterns = []
        
    def analyze(self):
        """Main analysis method"""
        print("🔍 Focused Analysis of work.pcap")
        print("=" * 60)
        print(f"Target domains: {', '.join(self.target_domains)}")
        print()
        
        if not os.path.exists(self.pcap_file):
            print(f"❌ File {self.pcap_file} not found")
            return False
        
        file_size = os.path.getsize(self.pcap_file)
        print(f"📁 File size: {file_size:,} bytes ({file_size/1024/1024:.1f} MB)")
        
        try:
            with open(self.pcap_file, 'rb') as f:
                # Check file format
                magic = struct.unpack('<I', f.read(4))[0]
                f.seek(0)
                
                if magic == 0xa1b2c3d4:
                    print("✅ Classic PCAP format")
                    self._analyze_classic_pcap(f, file_size)
                elif magic == 0x0a0d0d0a:
                    print("✅ PCAP-NG format")
                    self._analyze_pcapng(f, file_size)
                else:
                    print(f"❌ Unknown format (magic: {hex(magic)})")
                    return False
                
                self._generate_focused_report()
                return True
                
        except Exception as e:
            print(f"❌ Analysis error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _analyze_classic_pcap(self, f, file_size):
        """Analyze classic PCAP format"""
        f.seek(24)  # Skip global header
        packet_count = 0
        
        while f.tell() < file_size - 16:
            try:
                # Read packet header
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break
                
                ts_sec, ts_usec, caplen, orig_len = struct.unpack('<IIII', packet_header)
                
                if caplen > 65536 or caplen == 0:
                    break
                
                # Read packet data
                packet_data = f.read(caplen)
                if len(packet_data) < caplen:
                    break
                
                self._analyze_packet(packet_data, ts_sec + ts_usec/1000000)
                packet_count += 1
                
            except Exception as e:
                break
        
        print(f"📊 Analyzed {packet_count:,} packets")
    
    def _analyze_pcapng(self, f, file_size):
        """Analyze PCAP-NG format"""
        packet_count = 0
        
        while f.tell() < file_size - 12:
            pos = f.tell()
            
            try:
                # Read block header
                block_type_data = f.read(4)
                if len(block_type_data) < 4:
                    break
                
                block_type = struct.unpack('<I', block_type_data)[0]
                block_length = struct.unpack('<I', f.read(4))[0]
                
                if block_length < 12 or block_length > file_size:
                    f.seek(pos + 1)
                    continue
                
                # Enhanced Packet Block
                if block_type == 0x00000006:
                    try:
                        # Skip EPB header fields
                        f.read(16)  # interface_id, timestamp_high, timestamp_low, captured_len, original_len
                        
                        # Read captured length again for packet data
                        f.seek(pos + 16)
                        captured_len = struct.unpack('<I', f.read(4))[0]
                        
                        if 0 < captured_len < 65536:
                            packet_data = f.read(captured_len)
                            if len(packet_data) == captured_len:
                                self._analyze_packet(packet_data, 0)  # timestamp not critical for this analysis
                                packet_count += 1
                    except:
                        pass
                
                f.seek(pos + block_length)
                
            except Exception as e:
                f.seek(pos + 1)
                continue
        
        print(f"📊 Analyzed {packet_count:,} packets")
    
    def _analyze_packet(self, packet_data, timestamp):
        """Analyze individual packet"""
        if len(packet_data) < 14:  # Minimum Ethernet header
            return
        
        try:
            # Parse Ethernet header
            eth_type = struct.unpack('!H', packet_data[12:14])[0]
            
            # IPv4 packets
            if eth_type == 0x0800 and len(packet_data) >= 34:
                ip_header = struct.unpack('!BBHHHBBH4s4s', packet_data[14:34])
                protocol = ip_header[6]
                src_ip = socket.inet_ntoa(ip_header[8])
                dst_ip = socket.inet_ntoa(ip_header[9])
                
                # TCP packets
                if protocol == 6 and len(packet_data) >= 54:
                    tcp_header = struct.unpack('!HHLLBBHHH', packet_data[34:54])
                    src_port = tcp_header[0]
                    dst_port = tcp_header[1]
                    flags = tcp_header[5]
                    
                    # Check for TLS handshake (port 443)
                    if dst_port == 443 or src_port == 443:
                        self._analyze_tls_packet(packet_data, src_ip, dst_ip, src_port, dst_port, timestamp)
                    
                    # Check for HTTP (port 80)
                    elif dst_port == 80 or src_port == 80:
                        self._analyze_http_packet(packet_data, src_ip, dst_ip, src_port, dst_port, timestamp)
        
        except Exception as e:
            pass
    
    def _analyze_tls_packet(self, packet_data, src_ip, dst_ip, src_port, dst_port, timestamp):
        """Analyze TLS packets for ClientHello and SNI"""
        if len(packet_data) < 100:
            return
        
        try:
            # Find TLS handshake
            tcp_header_len = ((packet_data[46] >> 4) & 0x0f) * 4
            tls_start = 34 + tcp_header_len
            
            if tls_start + 5 >= len(packet_data):
                return
            
            # Check for TLS handshake
            if (packet_data[tls_start] == 0x16 and  # Handshake
                packet_data[tls_start + 5] == 0x01):  # ClientHello
                
                sni = self._extract_sni(packet_data[tls_start:])
                if sni:
                    handshake_info = {
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'sni': sni,
                        'is_target': any(domain in sni for domain in self.target_domains)
                    }
                    
                    self.tls_handshakes.append(handshake_info)
                    
                    if handshake_info['is_target']:
                        self.domain_connections[sni].append(handshake_info)
                        
                        # Look for bypass patterns
                        self._detect_bypass_patterns(packet_data, sni, timestamp)
        
        except Exception as e:
            pass
    
    def _extract_sni(self, tls_data):
        """Extract SNI from TLS ClientHello"""
        try:
            if len(tls_data) < 100:
                return None
            
            # Skip TLS record header (5 bytes) and handshake header (4 bytes)
            pos = 9
            
            # Skip client version (2 bytes) and random (32 bytes)
            pos += 34
            
            # Skip session ID
            if pos >= len(tls_data):
                return None
            session_id_len = tls_data[pos]
            pos += 1 + session_id_len
            
            # Skip cipher suites
            if pos + 2 >= len(tls_data):
                return None
            cipher_suites_len = struct.unpack('!H', tls_data[pos:pos+2])[0]
            pos += 2 + cipher_suites_len
            
            # Skip compression methods
            if pos >= len(tls_data):
                return None
            compression_len = tls_data[pos]
            pos += 1 + compression_len
            
            # Extensions
            if pos + 2 >= len(tls_data):
                return None
            extensions_len = struct.unpack('!H', tls_data[pos:pos+2])[0]
            pos += 2
            
            # Parse extensions
            extensions_end = pos + extensions_len
            while pos + 4 < extensions_end and pos + 4 < len(tls_data):
                ext_type = struct.unpack('!H', tls_data[pos:pos+2])[0]
                ext_len = struct.unpack('!H', tls_data[pos+2:pos+4])[0]
                pos += 4
                
                # SNI extension
                if ext_type == 0x0000 and ext_len > 5:
                    sni_data = tls_data[pos:pos+ext_len]
                    if len(sni_data) >= 9:
                        # Parse SNI list
                        list_len = struct.unpack('!H', sni_data[0:2])[0]
                        if list_len > 0 and len(sni_data) >= list_len + 2:
                            # First entry should be hostname (type 0)
                            if sni_data[2] == 0x00:  # hostname type
                                name_len = struct.unpack('!H', sni_data[3:5])[0]
                                if name_len > 0 and len(sni_data) >= 5 + name_len:
                                    return sni_data[5:5+name_len].decode('utf-8', errors='ignore')
                
                pos += ext_len
            
        except Exception as e:
            pass
        
        return None
    
    def _analyze_http_packet(self, packet_data, src_ip, dst_ip, src_port, dst_port, timestamp):
        """Analyze HTTP packets for Host headers"""
        try:
            tcp_header_len = ((packet_data[46] >> 4) & 0x0f) * 4
            http_start = 34 + tcp_header_len
            
            if http_start >= len(packet_data):
                return
            
            http_data = packet_data[http_start:].decode('utf-8', errors='ignore')
            
            # Look for Host header
            if 'Host: ' in http_data:
                for line in http_data.split('\n'):
                    if line.startswith('Host: '):
                        host = line[6:].strip().split(':')[0]
                        if any(domain in host for domain in self.target_domains):
                            self.domain_connections[host].append({
                                'timestamp': timestamp,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'protocol': 'HTTP',
                                'host': host
                            })
                        break
        
        except Exception as e:
            pass
    
    def _detect_bypass_patterns(self, packet_data, sni, timestamp):
        """Detect DPI bypass patterns in packet"""
        try:
            # Look for packet fragmentation
            packet_size = len(packet_data)
            
            # Small packets might indicate fragmentation
            if packet_size < 100:
                self.strategy_attempts[sni].append({
                    'timestamp': timestamp,
                    'strategy': 'fragmentation',
                    'packet_size': packet_size,
                    'pattern': 'small_packet'
                })
            
            # Look for unusual TCP flags or patterns
            tcp_flags = packet_data[47] if len(packet_data) > 47 else 0
            if tcp_flags & 0x08:  # PSH flag
                self.strategy_attempts[sni].append({
                    'timestamp': timestamp,
                    'strategy': 'tcp_flags',
                    'flags': tcp_flags,
                    'pattern': 'psh_flag'
                })
        
        except Exception as e:
            pass
    
    def _generate_focused_report(self):
        """Generate focused analysis report"""
        print("\n" + "="*60)
        print("📋 FOCUSED ANALYSIS REPORT")
        print("="*60)
        
        # TLS Handshakes Summary
        print(f"\n🔐 TLS Handshakes Found: {len(self.tls_handshakes)}")
        target_handshakes = [h for h in self.tls_handshakes if h['is_target']]
        print(f"🎯 Target Domain Handshakes: {len(target_handshakes)}")
        
        # Domain breakdown
        print(f"\n📊 Domain Connection Analysis:")
        domain_stats = Counter()
        for handshake in target_handshakes:
            domain_stats[handshake['sni']] += 1
        
        for domain, count in domain_stats.most_common():
            print(f"   {domain}: {count} connections")
            
            # Check if domain has specific strategy
            is_problematic = any(prob in domain for prob in [
                'static.cdninstagram.com', 'scontent-arn2-1.cdninstagram.com',
                'api.x.com', 'youtubei.googleapis.com'
            ])
            
            if is_problematic:
                print(f"   ⚠️  {domain} - PROBLEMATIC SUBDOMAIN (needs specific strategy)")
        
        # Strategy Analysis
        print(f"\n🎯 Strategy Attempt Analysis:")
        for domain, attempts in self.strategy_attempts.items():
            if attempts:
                print(f"   {domain}: {len(attempts)} bypass attempts detected")
                
                patterns = Counter(attempt['pattern'] for attempt in attempts)
                for pattern, count in patterns.items():
                    print(f"     - {pattern}: {count} times")
        
        # Problem Detection
        print(f"\n⚠️  IDENTIFIED ISSUES:")
        
        problematic_domains = []
        for handshake in target_handshakes:
            sni = handshake['sni']
            if any(prob in sni for prob in [
                'static.cdninstagram.com', 'scontent-arn2-1.cdninstagram.com',
                'api.x.com', 'mobile.x.com', 'youtubei.googleapis.com',
                '*.googleapis.com', '*.ytimg.com'
            ]):
                problematic_domains.append(sni)
        
        if problematic_domains:
            print("   The following critical subdomains were detected:")
            for domain in set(problematic_domains):
                print(f"   ❌ {domain} - Missing from current strategy configuration")
        else:
            print("   ✅ No critical subdomain issues detected in this capture")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        print("   1. Ensure enhanced strategies.json is loaded (33 strategies vs current 14)")
        print("   2. Add missing subdomain strategies for:")
        print("      - static.cdninstagram.com")
        print("      - scontent-arn2-1.cdninstagram.com") 
        print("      - api.x.com")
        print("      - youtubei.googleapis.com")
        print("   3. Restart recon_service.py to reload enhanced configuration")
        
        # Save detailed report
        report_data = {
            'analysis_time': datetime.now().isoformat(),
            'total_handshakes': len(self.tls_handshakes),
            'target_handshakes': len(target_handshakes),
            'domain_stats': dict(domain_stats),
            'problematic_domains': list(set(problematic_domains)),
            'strategy_attempts': dict(self.strategy_attempts)
        }
        
        with open('work_pcap_focused_analysis.json', 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: work_pcap_focused_analysis.json")

if __name__ == "__main__":
    analyzer = WorkPcapFocusedAnalyzer()
    analyzer.analyze()