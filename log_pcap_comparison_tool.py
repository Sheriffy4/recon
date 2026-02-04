#!/usr/bin/env python3
"""
Simple Log-to-PCAP Comparison Tool

This tool parses CLI logs and PCAP files to compare what was logged
vs what actually happened in the network.

Requirements: 1.4, 3.3
"""

import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

# Try to import scapy for PCAP analysis
try:
    from scapy.all import rdpcap, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not available. PCAP analysis will be limited.")
    SCAPY_AVAILABLE = False

@dataclass
class AttackLogEntry:
    """Represents an attack entry extracted from logs"""
    timestamp: Optional[datetime]
    domain: str
    attack_type: str
    parameters: Dict[str, Any]
    success: bool
    source_mode: str  # 'cli' or 'service'
    raw_log_line: str

@dataclass
class NetworkAttack:
    """Represents a network attack detected in PCAP"""
    timestamp: Optional[datetime]
    src_ip: str
    dst_ip: str
    domain: str
    attack_type: str
    parameters: Dict[str, Any]
    packet_details: Dict[str, Any]
    flow_id: str

@dataclass
class ComparisonResult:
    """Results of log-to-PCAP comparison"""
    matched_attacks: List[Tuple[AttackLogEntry, NetworkAttack]]
    missing_in_pcap: List[AttackLogEntry]
    missing_in_logs: List[NetworkAttack]
    log_entries: List[AttackLogEntry]
    pcap_attacks: List[NetworkAttack]
    summary: Dict[str, Any]

class LogParser:
    """Parser for CLI/Service log files"""
    
    def __init__(self):
        # Patterns to match different types of log entries
        self.attack_patterns = [
            # Strategy application patterns
            r'Strategy:\s*(\w+)',
            r'Attack:\s*(\w+)',
            r'Использована стратегия.*:\s*(\w+)',
            r'Applied strategy.*:\s*(\w+)',
            r'Executing attack.*:\s*(\w+)',
            r'Running.*attack.*:\s*(\w+)',
            
            # Parameter patterns
            r'split_pos[:\s=]+(\d+)',
            r'split_count[:\s=]+(\d+)',
            r'ttl[:\s=]+(\d+)',
            r'fooling[:\s=]+(\w+)',
            r'disorder_method[:\s=]+(\w+)',
        ]
        
        # Success/failure patterns
        self.success_patterns = [
            r'\[OK\]\s*SUCCESS',
            r'SUCCESS',
            r'✅',
            r'Working',
            r'Successful',
        ]
        
        self.failure_patterns = [
            r'\[ERROR\]',
            r'FAILED',
            r'❌',
            r'Failed',
            r'Error',
        ]
    
    def parse_log_file(self, log_file_path: str, source_mode: str = 'cli') -> List[AttackLogEntry]:
        """Parse a log file and extract attack entries"""
        entries = []
        
        if not os.path.exists(log_file_path):
            print(f"Warning: Log file not found: {log_file_path}")
            return entries
        
        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading log file {log_file_path}: {e}")
            return entries
        
        print(f"Parsing {len(lines)} lines from {log_file_path}")
        
        current_attack = None
        current_params = {}
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            # Extract timestamp if available
            timestamp = self._extract_timestamp(line)
            
            # Look for attack/strategy mentions
            attack_type = self._extract_attack_type(line)
            if attack_type:
                # If we have a previous attack, save it
                if current_attack:
                    entries.append(AttackLogEntry(
                        timestamp=timestamp,
                        domain=self._extract_domain(line) or "unknown",
                        attack_type=current_attack,
                        parameters=current_params.copy(),
                        success=self._is_success_line(line),
                        source_mode=source_mode,
                        raw_log_line=line
                    ))
                
                current_attack = attack_type
                current_params = {}
            
            # Extract parameters
            params = self._extract_parameters(line)
            current_params.update(params)
            
            # Check for success/failure indicators
            if current_attack and (self._is_success_line(line) or self._is_failure_line(line)):
                entries.append(AttackLogEntry(
                    timestamp=timestamp,
                    domain=self._extract_domain(line) or "unknown",
                    attack_type=current_attack,
                    parameters=current_params.copy(),
                    success=self._is_success_line(line),
                    source_mode=source_mode,
                    raw_log_line=line
                ))
                current_attack = None
                current_params = {}
        
        # Save any remaining attack
        if current_attack:
            entries.append(AttackLogEntry(
                timestamp=None,
                domain="unknown",
                attack_type=current_attack,
                parameters=current_params,
                success=False,  # Unknown success status
                source_mode=source_mode,
                raw_log_line=""
            ))
        
        print(f"Extracted {len(entries)} attack entries from log")
        return entries
    
    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        """Extract timestamp from log line"""
        # Common timestamp patterns
        patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    if len(match.group(1)) > 8:  # Full date
                        return datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
                    else:  # Time only
                        today = datetime.now().date()
                        time_part = datetime.strptime(match.group(1), '%H:%M:%S').time()
                        return datetime.combine(today, time_part)
                except ValueError:
                    continue
        return None
    
    def _extract_attack_type(self, line: str) -> Optional[str]:
        """Extract attack type from log line"""
        for pattern in self.attack_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1).lower()
        return None
    
    def _extract_domain(self, line: str) -> Optional[str]:
        """Extract domain from log line"""
        # Look for domain patterns
        domain_patterns = [
            r'Target:\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            r'Domain:\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            r'([a-zA-Z0-9.-]+\.(?:com|org|net|ru|to|tv))',
        ]
        
        for pattern in domain_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        return None
    
    def _extract_parameters(self, line: str) -> Dict[str, Any]:
        """Extract attack parameters from log line"""
        params = {}
        
        # Parameter patterns
        param_patterns = {
            'split_pos': r'split_pos[:\s=]+(\d+)',
            'split_count': r'split_count[:\s=]+(\d+)',
            'ttl': r'ttl[:\s=]+(\d+)',
            'fooling': r'fooling[:\s=]+(\w+)',
            'disorder_method': r'disorder_method[:\s=]+(\w+)',
        }
        
        for param_name, pattern in param_patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                value = match.group(1)
                # Convert to int if it's a number
                if value.isdigit():
                    params[param_name] = int(value)
                else:
                    params[param_name] = value
        
        return params
    
    def _is_success_line(self, line: str) -> bool:
        """Check if line indicates success"""
        for pattern in self.success_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False
    
    def _is_failure_line(self, line: str) -> bool:
        """Check if line indicates failure"""
        for pattern in self.failure_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False

class PCAPAnalyzer:
    """Analyzer for PCAP files to detect network attacks"""
    
    def __init__(self):
        self.attack_signatures = {
            'split': self._detect_split_attack,
            'multisplit': self._detect_multisplit_attack,
            'disorder': self._detect_disorder_attack,
            'fake': self._detect_fake_attack,
            'badsum': self._detect_badsum_attack,
            'badseq': self._detect_badseq_attack,
        }
    
    def analyze_pcap_file(self, pcap_file_path: str) -> List[NetworkAttack]:
        """Analyze PCAP file and detect network attacks"""
        attacks = []
        
        if not SCAPY_AVAILABLE:
            print("Warning: Scapy not available, cannot analyze PCAP file")
            return attacks
        
        if not os.path.exists(pcap_file_path):
            print(f"Warning: PCAP file not found: {pcap_file_path}")
            return attacks
        
        try:
            packets = rdpcap(pcap_file_path)
            print(f"Loaded {len(packets)} packets from {pcap_file_path}")
        except Exception as e:
            print(f"Error reading PCAP file {pcap_file_path}: {e}")
            return attacks
        
        # Group packets by flow
        flows = self._group_packets_by_flow(packets)
        print(f"Grouped packets into {len(flows)} flows")
        
        # Analyze each flow for attacks
        for flow_id, flow_packets in flows.items():
            flow_attacks = self._analyze_flow(flow_id, flow_packets)
            attacks.extend(flow_attacks)
        
        print(f"Detected {len(attacks)} potential attacks in PCAP")
        return attacks
    
    def _group_packets_by_flow(self, packets) -> Dict[str, List]:
        """Group packets by network flow"""
        flows = {}
        
        for packet in packets:
            if IP in packet:
                # Create flow ID from src/dst IP and ports
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                src_port = dst_port = 0
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                
                # Normalize flow ID (smaller IP first)
                if src_ip < dst_ip:
                    flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                else:
                    flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
                
                if flow_id not in flows:
                    flows[flow_id] = []
                flows[flow_id].append(packet)
        
        return flows
    
    def _analyze_flow(self, flow_id: str, packets: List) -> List[NetworkAttack]:
        """Analyze a network flow for attacks"""
        attacks = []
        
        # Look for TLS/HTTP traffic (port 443/80)
        has_tls = any(TCP in pkt and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443) for pkt in packets)
        has_http = any(TCP in pkt and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80) for pkt in packets)
        
        if not (has_tls or has_http):
            return attacks
        
        # Extract flow info
        src_ip = dst_ip = "unknown"
        if packets and IP in packets[0]:
            src_ip = packets[0][IP].src
            dst_ip = packets[0][IP].dst
        
        # Check for each attack type
        for attack_type, detector in self.attack_signatures.items():
            detected = detector(packets)
            if detected:
                attacks.append(NetworkAttack(
                    timestamp=datetime.fromtimestamp(packets[0].time) if packets else None,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    domain="unknown",  # Would need DNS resolution
                    attack_type=attack_type,
                    parameters=detected.get('parameters', {}),
                    packet_details=detected.get('details', {}),
                    flow_id=flow_id
                ))
        
        return attacks
    
    def _detect_split_attack(self, packets: List) -> Optional[Dict]:
        """Detect packet splitting attacks"""
        # Look for TCP packets with unusual fragmentation
        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        
        if len(tcp_packets) < 2:
            return None
        
        # Check for small initial packets followed by larger ones
        for i in range(len(tcp_packets) - 1):
            pkt1 = tcp_packets[i]
            pkt2 = tcp_packets[i + 1]
            
            if (len(pkt1) < 100 and len(pkt2) > len(pkt1) * 2 and
                pkt1[TCP].seq + len(pkt1[TCP].payload) == pkt2[TCP].seq):
                return {
                    'parameters': {'split_detected': True, 'split_size': len(pkt1)},
                    'details': {'packet_count': len(tcp_packets)}
                }
        
        return None
    
    def _detect_multisplit_attack(self, packets: List) -> Optional[Dict]:
        """Detect multi-split attacks"""
        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        
        if len(tcp_packets) < 3:
            return None
        
        # Look for multiple small packets in sequence
        small_packets = [pkt for pkt in tcp_packets if len(pkt) < 100]
        
        if len(small_packets) >= 3:
            return {
                'parameters': {'multisplit_detected': True, 'split_count': len(small_packets)},
                'details': {'packet_count': len(tcp_packets)}
            }
        
        return None
    
    def _detect_disorder_attack(self, packets: List) -> Optional[Dict]:
        """Detect packet reordering attacks"""
        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        
        if len(tcp_packets) < 2:
            return None
        
        # Check for out-of-order sequence numbers
        seq_numbers = [pkt[TCP].seq for pkt in tcp_packets]
        
        # Simple check: if sequence numbers are not monotonic
        is_ordered = all(seq_numbers[i] <= seq_numbers[i+1] for i in range(len(seq_numbers)-1))
        
        if not is_ordered:
            return {
                'parameters': {'disorder_detected': True},
                'details': {'packet_count': len(tcp_packets)}
            }
        
        return None
    
    def _detect_fake_attack(self, packets: List) -> Optional[Dict]:
        """Detect fake packet attacks"""
        # Look for packets with unusual TTL or other indicators
        for pkt in packets:
            if IP in pkt and pkt[IP].ttl <= 2:
                return {
                    'parameters': {'fake_detected': True, 'ttl': pkt[IP].ttl},
                    'details': {'packet_count': len(packets)}
                }
        
        return None
    
    def _detect_badsum_attack(self, packets: List) -> Optional[Dict]:
        """Detect bad checksum attacks"""
        # This would require more sophisticated analysis
        # For now, just check if we have TCP packets
        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        
        if tcp_packets:
            # Placeholder detection
            return {
                'parameters': {'badsum_possible': True},
                'details': {'packet_count': len(tcp_packets)}
            }
        
        return None
    
    def _detect_badseq_attack(self, packets: List) -> Optional[Dict]:
        """Detect bad sequence number attacks"""
        # Similar placeholder for badseq detection
        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        
        if tcp_packets:
            return {
                'parameters': {'badseq_possible': True},
                'details': {'packet_count': len(tcp_packets)}
            }
        
        return None

class LogPCAPComparator:
    """Main comparison tool"""
    
    def __init__(self):
        self.log_parser = LogParser()
        self.pcap_analyzer = PCAPAnalyzer()
    
    def compare_log_and_pcap(self, log_file: str, pcap_file: str, source_mode: str = 'cli') -> ComparisonResult:
        """Compare log file and PCAP file"""
        print(f"\n=== Comparing {log_file} and {pcap_file} ===")
        
        # Parse log file
        log_entries = self.log_parser.parse_log_file(log_file, source_mode)
        
        # Analyze PCAP file
        pcap_attacks = self.pcap_analyzer.analyze_pcap_file(pcap_file)
        
        # Perform comparison
        matched_attacks = []
        missing_in_pcap = []
        missing_in_logs = []
        
        # Find matches between log entries and PCAP attacks
        for log_entry in log_entries:
            matched = False
            for pcap_attack in pcap_attacks:
                if self._attacks_match(log_entry, pcap_attack):
                    matched_attacks.append((log_entry, pcap_attack))
                    matched = True
                    break
            
            if not matched:
                missing_in_pcap.append(log_entry)
        
        # Find PCAP attacks not in logs
        for pcap_attack in pcap_attacks:
            matched = False
            for log_entry in log_entries:
                if self._attacks_match(log_entry, pcap_attack):
                    matched = True
                    break
            
            if not matched:
                missing_in_logs.append(pcap_attack)
        
        # Create summary
        summary = {
            'total_log_entries': len(log_entries),
            'total_pcap_attacks': len(pcap_attacks),
            'matched_attacks': len(matched_attacks),
            'missing_in_pcap': len(missing_in_pcap),
            'missing_in_logs': len(missing_in_logs),
            'match_rate': len(matched_attacks) / max(len(log_entries), 1) * 100,
        }
        
        return ComparisonResult(
            matched_attacks=matched_attacks,
            missing_in_pcap=missing_in_pcap,
            missing_in_logs=missing_in_logs,
            log_entries=log_entries,
            pcap_attacks=pcap_attacks,
            summary=summary
        )
    
    def _attacks_match(self, log_entry: AttackLogEntry, pcap_attack: NetworkAttack) -> bool:
        """Check if a log entry matches a PCAP attack"""
        # Simple matching based on attack type
        log_type = log_entry.attack_type.lower()
        pcap_type = pcap_attack.attack_type.lower()
        
        # Handle attack type variations
        type_matches = (
            log_type == pcap_type or
            log_type in pcap_type or
            pcap_type in log_type or
            self._are_similar_attacks(log_type, pcap_type)
        )
        
        return type_matches
    
    def _are_similar_attacks(self, type1: str, type2: str) -> bool:
        """Check if two attack types are similar"""
        similar_groups = [
            ['split', 'multisplit'],
            ['fake', 'badsum', 'badseq'],
            ['disorder', 'reorder'],
        ]
        
        for group in similar_groups:
            if any(t in type1 for t in group) and any(t in type2 for t in group):
                return True
        
        return False
    
    def generate_report(self, result: ComparisonResult, output_file: str = None) -> str:
        """Generate a comparison report"""
        report_lines = []
        
        report_lines.append("=" * 60)
        report_lines.append("LOG-TO-PCAP COMPARISON REPORT")
        report_lines.append("=" * 60)
        report_lines.append(f"Generated: {datetime.now()}")
        report_lines.append("")
        
        # Summary
        report_lines.append("SUMMARY:")
        report_lines.append(f"  Total log entries: {result.summary['total_log_entries']}")
        report_lines.append(f"  Total PCAP attacks: {result.summary['total_pcap_attacks']}")
        report_lines.append(f"  Matched attacks: {result.summary['matched_attacks']}")
        report_lines.append(f"  Missing in PCAP: {result.summary['missing_in_pcap']}")
        report_lines.append(f"  Missing in logs: {result.summary['missing_in_logs']}")
        report_lines.append(f"  Match rate: {result.summary['match_rate']:.1f}%")
        report_lines.append("")
        
        # Matched attacks
        if result.matched_attacks:
            report_lines.append("MATCHED ATTACKS:")
            for i, (log_entry, pcap_attack) in enumerate(result.matched_attacks, 1):
                report_lines.append(f"  {i}. {log_entry.attack_type} <-> {pcap_attack.attack_type}")
                report_lines.append(f"     Log: {log_entry.raw_log_line[:100]}...")
                report_lines.append(f"     PCAP: Flow {pcap_attack.flow_id}")
                report_lines.append("")
        
        # Missing in PCAP
        if result.missing_in_pcap:
            report_lines.append("ATTACKS LOGGED BUT NOT IN PCAP:")
            for i, log_entry in enumerate(result.missing_in_pcap, 1):
                report_lines.append(f"  {i}. {log_entry.attack_type}")
                report_lines.append(f"     Parameters: {log_entry.parameters}")
                report_lines.append(f"     Log line: {log_entry.raw_log_line[:100]}...")
                report_lines.append("")
        
        # Missing in logs
        if result.missing_in_logs:
            report_lines.append("ATTACKS IN PCAP BUT NOT LOGGED:")
            for i, pcap_attack in enumerate(result.missing_in_logs, 1):
                report_lines.append(f"  {i}. {pcap_attack.attack_type}")
                report_lines.append(f"     Parameters: {pcap_attack.parameters}")
                report_lines.append(f"     Flow: {pcap_attack.flow_id}")
                report_lines.append("")
        
        report_text = "\n".join(report_lines)
        
        # Save to file if specified
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report_text)
                print(f"Report saved to: {output_file}")
            except Exception as e:
                print(f"Error saving report: {e}")
        
        return report_text

def main():
    """Main function"""
    if len(sys.argv) < 3:
        print("Usage: python log_pcap_comparison_tool.py <log_file> <pcap_file> [source_mode]")
        print("  source_mode: 'cli' or 'service' (default: 'cli')")
        return
    
    log_file = sys.argv[1]
    pcap_file = sys.argv[2]
    source_mode = sys.argv[3] if len(sys.argv) > 3 else 'cli'
    
    # Create comparator
    comparator = LogPCAPComparator()
    
    # Perform comparison
    result = comparator.compare_log_and_pcap(log_file, pcap_file, source_mode)
    
    # Generate report
    report_file = f"comparison_report_{source_mode}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    report = comparator.generate_report(result, report_file)
    
    # Print summary
    print("\n" + "=" * 60)
    print("COMPARISON SUMMARY")
    print("=" * 60)
    print(f"Log entries: {result.summary['total_log_entries']}")
    print(f"PCAP attacks: {result.summary['total_pcap_attacks']}")
    print(f"Matched: {result.summary['matched_attacks']}")
    print(f"Missing in PCAP: {result.summary['missing_in_pcap']}")
    print(f"Missing in logs: {result.summary['missing_in_logs']}")
    print(f"Match rate: {result.summary['match_rate']:.1f}%")
    print(f"\nFull report saved to: {report_file}")

if __name__ == "__main__":
    main()