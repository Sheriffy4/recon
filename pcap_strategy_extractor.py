#!/usr/bin/env python3
# File: pcap_strategy_extractor.py
"""
PCAP Strategy Extractor - Extract and validate DPI bypass strategies from PCAP

This tool analyzes PCAP files to identify which bypass strategies were applied,
extracts packet examples for each strategy, and validates their correctness.

Features:
1. Identify applied strategies by packet analysis
2. Extract example packets for each unique strategy
3. Validate strategy implementation (correct TTL, checksum, order, etc.)
4. Generate detailed report with strategy characteristics
5. Save separate PCAP files for each strategy
6. Detect implementation errors

Usage:
    python pcap_strategy_extractor.py out2.pcap
    python pcap_strategy_extractor.py out2.pcap --output-dir strategies
    python pcap_strategy_extractor.py out2.pcap --validate-only
"""

import os
import sys
import json
import struct
import logging
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict, Counter
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from scapy.all import rdpcap, wrpcap, PcapReader, IP, TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    print("[ERROR] Scapy not available. Install with: pip install scapy")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
LOG = logging.getLogger("strategy_extractor")


@dataclass
class PacketCharacteristics:
    """Характеристики одного пакета"""
    packet_num: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    ttl: int
    payload_len: int
    ip_checksum: int
    tcp_checksum: int
    ip_checksum_valid: bool
    tcp_checksum_valid: bool
    is_fake_candidate: bool  # TTL=1-4 + badsum
    
    def to_dict(self):
        return asdict(self)


@dataclass
class StrategySignature:
    """Сигнатура обнаруженной стратегии"""
    strategy_name: str
    confidence: float  # 0.0-1.0
    characteristics: Dict[str, any]
    packet_indices: List[int]
    validation_issues: List[str]
    
    def to_dict(self):
        return asdict(self)


class ChecksumValidator:
    """Валидатор контрольных сумм"""
    
    @staticmethod
    def calculate_ip_checksum(ip_header: bytes) -> int:
        """Вычислить IP checksum"""
        # Zero out checksum field
        header = bytearray(ip_header)
        header[10:12] = b'\x00\x00'
        
        # Calculate
        if len(header) % 2:
            header += b'\x00'
        
        checksum = 0
        for i in range(0, len(header), 2):
            word = (header[i] << 8) + header[i + 1]
            checksum += word
        
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        return (~checksum) & 0xFFFF
    
    @staticmethod
    def calculate_tcp_checksum(ip_header: bytes, tcp_segment: bytes) -> int:
        """Вычислить TCP checksum с pseudo-header"""
        # Build pseudo-header
        src_ip = ip_header[12:16]
        dst_ip = ip_header[16:20]
        proto = ip_header[9]
        tcp_len = len(tcp_segment)
        
        pseudo_header = src_ip + dst_ip + bytes([0, proto]) + struct.pack("!H", tcp_len)
        
        # Zero out checksum field in TCP header
        tcp_data = bytearray(tcp_segment)
        tcp_data[16:18] = b'\x00\x00'
        
        # Calculate
        data = pseudo_header + bytes(tcp_data)
        if len(data) % 2:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        return (~checksum) & 0xFFFF
    
    @staticmethod
    def validate_packet(pkt) -> Tuple[bool, bool]:
        """
        Validate IP and TCP checksums
        
        Returns:
            (ip_valid, tcp_valid)
        """
        if not (IP in pkt and TCP in pkt):
            return (False, False)
        
        try:
            # Get raw data
            raw = bytes(pkt)
            ip_hl = (raw[0] & 0x0F) * 4
            
            # Extract headers
            ip_header = raw[:ip_hl]
            
            # Find TCP segment
            tcp_offset = ip_hl
            total_len = struct.unpack("!H", raw[2:4])[0]
            tcp_segment = raw[tcp_offset:total_len]
            
            # Validate IP checksum
            recorded_ip_csum = struct.unpack("!H", raw[10:12])[0]
            calculated_ip_csum = ChecksumValidator.calculate_ip_checksum(ip_header)
            ip_valid = (recorded_ip_csum == calculated_ip_csum)
            
            # Validate TCP checksum
            recorded_tcp_csum = struct.unpack("!H", raw[tcp_offset + 16:tcp_offset + 18])[0]
            calculated_tcp_csum = ChecksumValidator.calculate_tcp_checksum(ip_header, tcp_segment)
            tcp_valid = (recorded_tcp_csum == calculated_tcp_csum)
            
            return (ip_valid, tcp_valid)
            
        except Exception as e:
            LOG.debug(f"Checksum validation error: {e}")
            return (False, False)


class PacketAnalyzer:
    """Анализатор характеристик пакета"""
    
    def __init__(self):
        self.validator = ChecksumValidator()
    
    def analyze_packet(self, pkt, packet_num: int) -> Optional[PacketCharacteristics]:
        """Извлечь характеристики пакета"""
        if not (IP in pkt and TCP in pkt):
            return None
        
        try:
            # Validate checksums
            ip_valid, tcp_valid = self.validator.validate_packet(pkt)
            
            # Extract fields
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            
            payload = bytes(tcp_layer.payload) if tcp_layer.payload else b""
            
            # Determine if fake candidate (low TTL + bad checksum)
            is_fake = (ip_layer.ttl <= 4 and not tcp_valid)
            
            return PacketCharacteristics(
                packet_num=packet_num,
                timestamp=float(pkt.time),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=tcp_layer.sport,
                dst_port=tcp_layer.dport,
                seq=tcp_layer.seq,
                ack=tcp_layer.ack,
                flags=tcp_layer.flags,
                ttl=ip_layer.ttl,
                payload_len=len(payload),
                ip_checksum=ip_layer.chksum,
                tcp_checksum=tcp_layer.chksum,
                ip_checksum_valid=ip_valid,
                tcp_checksum_valid=tcp_valid,
                is_fake_candidate=is_fake
            )
            
        except Exception as e:
            LOG.debug(f"Packet analysis error: {e}")
            return None


class StrategyDetector:
    """Детектор стратегий обхода DPI"""
    
    def __init__(self):
        self.patterns = {
            'fake': self._detect_fake,
            'disorder': self._detect_disorder,
            'split': self._detect_split,
            'multidisorder': self._detect_multidisorder,
            'badsum': self._detect_badsum,
            'badseq': self._detect_badseq,
            'md5sig': self._detect_md5sig,
        }
    
    def detect_strategy(self, packets: List[PacketCharacteristics]) -> List[StrategySignature]:
        """
        Определить применённые стратегии по набору пакетов
        
        Returns:
            List of detected strategies with confidence scores
        """
        if not packets:
            return []
        
        strategies = []
        
        # Run all detectors
        for strategy_name, detector_func in self.patterns.items():
            result = detector_func(packets)
            if result:
                strategies.append(result)
        
        # Sort by confidence
        strategies.sort(key=lambda x: x.confidence, reverse=True)
        
        return strategies
    
    def _detect_fake(self, packets: List[PacketCharacteristics]) -> Optional[StrategySignature]:
        """Detect fake packet strategy"""
        fake_packets = [p for p in packets if p.is_fake_candidate]
        
        if not fake_packets:
            return None
        
        # Check if fake packets come before real packets
        first_fake_idx = min(p.packet_num for p in fake_packets)
        real_packets = [p for p in packets if not p.is_fake_candidate and p.payload_len > 0]
        
        if not real_packets:
            return None
        
        first_real_idx = min(p.packet_num for p in real_packets)
        
        # Fake should come first
        if first_fake_idx < first_real_idx:
            confidence = 0.9
            characteristics = {
                'fake_count': len(fake_packets),
                'fake_ttl': [p.ttl for p in fake_packets],
                'fake_first': True,
                'badsum_used': not any(p.tcp_checksum_valid for p in fake_packets)
            }
            
            return StrategySignature(
                strategy_name='fake',
                confidence=confidence,
                characteristics=characteristics,
                packet_indices=[p.packet_num for p in fake_packets],
                validation_issues=[]
            )
        
        return None
    
    def _detect_disorder(self, packets: List[PacketCharacteristics]) -> Optional[StrategySignature]:
        """Detect disorder strategy (reversed packet order)"""
        # Look for packets with overlapping/reverse sequence numbers
        if len(packets) < 2:
            return None
        
        # Sort by packet number (transmission order)
        sorted_by_time = sorted(packets, key=lambda p: p.packet_num)
        
        # Sort by sequence number (data order)
        sorted_by_seq = sorted([p for p in packets if p.payload_len > 0], 
                               key=lambda p: p.seq)
        
        if len(sorted_by_seq) < 2:
            return None
        
        # Check if transmission order differs from sequence order
        disorder_detected = False
        for i in range(len(sorted_by_seq) - 1):
            time_idx1 = sorted_by_time.index(sorted_by_seq[i])
            time_idx2 = sorted_by_time.index(sorted_by_seq[i+1])
            
            if time_idx1 > time_idx2:  # Later packet has earlier sequence
                disorder_detected = True
                break
        
        if disorder_detected:
            return StrategySignature(
                strategy_name='disorder',
                confidence=0.85,
                characteristics={
                    'packet_count': len(packets),
                    'disorder_detected': True
                },
                packet_indices=[p.packet_num for p in packets],
                validation_issues=[]
            )
        
        return None
    
    def _detect_split(self, packets: List[PacketCharacteristics]) -> Optional[StrategySignature]:
        """Detect split strategy (payload fragmentation)"""
        payload_packets = [p for p in packets if p.payload_len > 0 and not p.is_fake_candidate]
        
        if len(payload_packets) < 2:
            return None
        
        # Check if packets have sequential sequence numbers (split payload)
        sorted_packets = sorted(payload_packets, key=lambda p: p.seq)
        
        is_sequential = True
        for i in range(len(sorted_packets) - 1):
            expected_next_seq = sorted_packets[i].seq + sorted_packets[i].payload_len
            actual_next_seq = sorted_packets[i+1].seq
            
            if expected_next_seq != actual_next_seq:
                is_sequential = False
                break
        
        if is_sequential:
            return StrategySignature(
                strategy_name='split',
                confidence=0.8,
                characteristics={
                    'fragment_count': len(payload_packets),
                    'fragment_sizes': [p.payload_len for p in sorted_packets]
                },
                packet_indices=[p.packet_num for p in payload_packets],
                validation_issues=[]
            )
        
        return None
    
    def _detect_multidisorder(self, packets: List[PacketCharacteristics]) -> Optional[StrategySignature]:
        """Detect multidisorder (combination of fake + disorder)"""
        fake_detected = self._detect_fake(packets)
        disorder_detected = self._detect_disorder(packets)
        
        if fake_detected and disorder_detected:
            return StrategySignature(
                strategy_name='multidisorder',
                confidence=0.95,
                characteristics={
                    **fake_detected.characteristics,
                    **disorder_detected.characteristics
                },
                packet_indices=list(set(fake_detected.packet_indices + disorder_detected.packet_indices)),
                validation_issues=[]
            )
        
        return None
    
    def _detect_badsum(self, packets: List[PacketCharacteristics]) -> Optional[StrategySignature]:
        """Detect badsum strategy"""
        badsum_packets = [p for p in packets if not p.tcp_checksum_valid and p.payload_len > 0]
        
        if not badsum_packets:
            return None
        
        # Check checksum values
        bad_checksums = set(p.tcp_checksum for p in badsum_packets)
        expected_bad_values = {0xDEAD, 0xBEEF}
        
        uses_expected_bad = bool(bad_checksums & expected_bad_values)
        
        return StrategySignature(
            strategy_name='badsum',
            confidence=0.9 if uses_expected_bad else 0.7,
            characteristics={
                'badsum_count': len(badsum_packets),
                'checksum_values': list(bad_checksums),
                'uses_standard_bad_values': uses_expected_bad
            },
            packet_indices=[p.packet_num for p in badsum_packets],
            validation_issues=[]
        )
    
    def _detect_badseq(self, packets: List[PacketCharacteristics]) -> Optional[StrategySignature]:
        """Detect badseq strategy (intentionally wrong sequence numbers)"""
        # This is harder to detect - need to look for sequence number anomalies
        # For now, return None (would need more context)
        return None
    
    def _detect_md5sig(self, packets: List[PacketCharacteristics]) -> Optional[StrategySignature]:
        """Detect md5sig strategy"""
        # Would need to parse TCP options - simplified for now
        # md5sig uses checksum 0xBEEF
        badsum_with_beef = [p for p in packets if p.tcp_checksum == 0xBEEF]
        
        if badsum_with_beef:
            return StrategySignature(
                strategy_name='md5sig',
                confidence=0.85,
                characteristics={
                    'md5sig_count': len(badsum_with_beef),
                    'checksum_value': '0xBEEF'
                },
                packet_indices=[p.packet_num for p in badsum_with_beef],
                validation_issues=[]
            )
        
        return None


class StrategyExtractor:
    """Извлечение и группировка стратегий из PCAP"""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.analyzer = PacketAnalyzer()
        self.detector = StrategyDetector()
        self.flows = defaultdict(list)  # {flow_key: [PacketCharacteristics]}
        self.flow_packets = defaultdict(list)  # {flow_key: [scapy packets]}
        
    def _get_flow_key(self, pkt) -> Optional[str]:
        """Generate flow key from packet"""
        if not (IP in pkt and TCP in pkt):
            return None
        
        # Use sorted tuple to normalize bidirectional flow
        endpoints = tuple(sorted([
            (pkt[IP].src, pkt[TCP].sport),
            (pkt[IP].dst, pkt[TCP].dport)
        ]))
        
        return f"{endpoints[0][0]}:{endpoints[0][1]}<->{endpoints[1][0]}:{endpoints[1][1]}"
    
    def extract_strategies(self) -> Dict[str, any]:
        """
        Extract all strategies from PCAP
        
        Returns:
            Dict with extracted strategies and statistics
        """
        LOG.info(f"Loading PCAP file: {self.pcap_file}")
        
        try:
            packets = rdpcap(self.pcap_file)
        except Exception as e:
            LOG.error(f"Failed to read PCAP: {e}")
            return {}
        
        LOG.info(f"Loaded {len(packets)} packets")
        
        # Analyze each packet
        LOG.info("Analyzing packets...")
        for i, pkt in enumerate(packets, 1):
            flow_key = self._get_flow_key(pkt)
            if not flow_key:
                continue
            
            characteristics = self.analyzer.analyze_packet(pkt, i)
            if characteristics:
                self.flows[flow_key].append(characteristics)
                self.flow_packets[flow_key].append(pkt)
        
        LOG.info(f"Found {len(self.flows)} flows")
        
        # Detect strategies in each flow
        LOG.info("Detecting strategies...")
        detected_strategies = {}
        
        for flow_key, flow_packets in self.flows.items():
            strategies = self.detector.detect_strategy(flow_packets)
            
            if strategies:
                detected_strategies[flow_key] = {
                    'flow': flow_key,
                    'packet_count': len(flow_packets),
                    'strategies': strategies,
                    'packets': self.flow_packets[flow_key]
                }
        
        LOG.info(f"Detected strategies in {len(detected_strategies)} flows")
        
        # Generate summary
        summary = self._generate_summary(detected_strategies)
        
        return {
            'pcap_file': self.pcap_file,
            'total_packets': len(packets),
            'total_flows': len(self.flows),
            'flows_with_strategies': len(detected_strategies),
            'detected_strategies': detected_strategies,
            'summary': summary,
            'timestamp': datetime.now().isoformat()
        }
    
    def _generate_summary(self, detected_strategies: Dict) -> Dict:
        """Generate summary statistics"""
        strategy_counts = Counter()
        strategy_examples = defaultdict(list)
        
        for flow_key, data in detected_strategies.items():
            for strategy in data['strategies']:
                strategy_name = strategy.strategy_name
                strategy_counts[strategy_name] += 1
                
                # Save first example of each strategy
                if len(strategy_examples[strategy_name]) == 0:
                    strategy_examples[strategy_name].append({
                        'flow': flow_key,
                        'confidence': strategy.confidence,
                        'characteristics': strategy.characteristics,
                        'packet_indices': strategy.packet_indices
                    })
        
        return {
            'strategy_counts': dict(strategy_counts),
            'unique_strategies': len(strategy_counts),
            'strategy_examples': dict(strategy_examples)
        }
    
    def save_strategy_examples(self, output_dir: str):
        """Save separate PCAP files for each detected strategy"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        results = self.extract_strategies()
        detected = results.get('detected_strategies', {})
        
        if not detected:
            LOG.warning("No strategies detected to save")
            return
        
        # Group flows by primary strategy
        strategy_groups = defaultdict(list)
        
        for flow_key, data in detected.items():
            if data['strategies']:
                # Use highest confidence strategy
                primary_strategy = data['strategies'][0].strategy_name
                strategy_groups[primary_strategy].append(data)
        
        # Save PCAP for each strategy
        for strategy_name, flows in strategy_groups.items():
            # Take first flow as example
            example_flow = flows[0]
            packets_to_save = example_flow['packets']
            
            output_file = os.path.join(output_dir, f"strategy_{strategy_name}.pcap")
            
            try:
                wrpcap(output_file, packets_to_save)
                LOG.info(f"Saved {len(packets_to_save)} packets for '{strategy_name}' to {output_file}")
            except Exception as e:
                LOG.error(f"Failed to save {output_file}: {e}")
        
        # Save JSON report
        report_file = os.path.join(output_dir, "strategy_report.json")
        try:
            # Convert to JSON-serializable format
            json_results = {
                'pcap_file': results['pcap_file'],
                'total_packets': results['total_packets'],
                'total_flows': results['total_flows'],
                'flows_with_strategies': results['flows_with_strategies'],
                'summary': results['summary'],
                'timestamp': results['timestamp']
            }
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(json_results, f, indent=2, ensure_ascii=False)
            
            LOG.info(f"Saved strategy report to {report_file}")
        except Exception as e:
            LOG.error(f"Failed to save report: {e}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Extract and validate DPI bypass strategies from PCAP files",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "pcap_file",
        help="PCAP file to analyze"
    )
    
    parser.add_argument(
        "--output-dir",
        default="strategy_examples",
        help="Output directory for strategy examples (default: strategy_examples)"
    )
    
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate strategies, don't save PCAP files"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if not os.path.exists(args.pcap_file):
        LOG.error(f"PCAP file not found: {args.pcap_file}")
        return 1
    
    # Extract strategies
    extractor = StrategyExtractor(args.pcap_file)
    
    if args.validate_only:
        # Just analyze and print results
        results = extractor.extract_strategies()
        print("\n" + "="*80)
        print("STRATEGY EXTRACTION REPORT")
        print("="*80)
        print(f"PCAP File: {results['pcap_file']}")
        print(f"Total Packets: {results['total_packets']}")
        print(f"Total Flows: {results['total_flows']}")
        print(f"Flows with Strategies: {results['flows_with_strategies']}")
        
        summary = results.get('summary', {})
        print(f"\nDetected Strategies:")
        for strategy, count in summary.get('strategy_counts', {}).items():
            print(f"  - {strategy}: {count} flows")
        
        print(f"\nStrategy Examples:")
        for strategy, examples in summary.get('strategy_examples', {}).items():
            if examples:
                ex = examples[0]
                print(f"  {strategy}:")
                print(f"    Flow: {ex['flow']}")
                print(f"    Confidence: {ex['confidence']:.2f}")
                print(f"    Characteristics: {json.dumps(ex['characteristics'], indent=6)}")
        
        print("="*80)
    else:
        # Extract and save examples
        extractor.save_strategy_examples(args.output_dir)
        print(f"\n✅ Strategy examples saved to: {args.output_dir}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())