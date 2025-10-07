"""
Simple Packet Validator - Quick validation for seq numbers, checksums, and TTL.

This is a lightweight validator for quick packet validation during development and testing.
It focuses on the three most critical aspects:
1. Sequence numbers - Ensures packets have correct TCP sequence numbers
2. Checksums - Validates TCP checksums are correct or intentionally corrupted
3. TTL - Verifies Time-To-Live values match expectations

Usage:
    validator = SimplePacketValidator()
    result = validator.validate_pcap('test.pcap', attack_type='fake', params={'ttl': 1})
    if result['passed']:
        print("Validation passed!")
    else:
        print(f"Validation failed: {result['errors']}")
"""

import struct
import socket
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


class SimplePacketValidator:
    """
    Simple packet validator for quick validation of seq numbers, checksums, and TTL.
    
    This validator provides lightweight validation without the complexity of the full
    PacketValidator. It's designed for quick checks during development.
    """
    
    def __init__(self, debug: bool = False):
        """
        Initialize simple packet validator.
        
        Args:
            debug: Enable debug output
        """
        self.debug = debug
    
    def validate_pcap(self, pcap_file: str, attack_type: str = None, 
                     params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Validate a PCAP file for correct packet structure.
        
        Args:
            pcap_file: Path to PCAP file
            attack_type: Type of attack (fake, split, fakeddisorder, etc.)
            params: Attack parameters
        
        Returns:
            Dictionary with validation results:
            {
                'passed': bool,
                'packet_count': int,
                'errors': List[str],
                'warnings': List[str],
                'details': Dict[str, Any]
            }
        """
        params = params or {}
        result = {
            'passed': True,
            'packet_count': 0,
            'errors': [],
            'warnings': [],
            'details': {}
        }
        
        try:
            # Parse PCAP file
            packets = self._parse_pcap(pcap_file)
            result['packet_count'] = len(packets)
            
            if not packets:
                result['passed'] = False
                result['errors'].append("No packets found in PCAP file")
                return result
            
            # Validate sequence numbers
            seq_result = self.validate_seq_numbers(packets, attack_type, params)
            result['details']['sequence_numbers'] = seq_result
            if not seq_result['passed']:
                result['passed'] = False
                result['errors'].extend(seq_result['errors'])
            
            # Validate checksums
            checksum_result = self.validate_checksums(packets, attack_type, params)
            result['details']['checksums'] = checksum_result
            if not checksum_result['passed']:
                result['passed'] = False
                result['errors'].extend(checksum_result['errors'])
            
            # Validate TTL
            ttl_result = self.validate_ttl(packets, attack_type, params)
            result['details']['ttl'] = ttl_result
            if not ttl_result['passed']:
                result['passed'] = False
                result['errors'].extend(ttl_result['errors'])
            
            # Collect warnings
            result['warnings'].extend(seq_result.get('warnings', []))
            result['warnings'].extend(checksum_result.get('warnings', []))
            result['warnings'].extend(ttl_result.get('warnings', []))
            
        except Exception as e:
            result['passed'] = False
            result['errors'].append(f"Validation failed: {str(e)}")
            if self.debug:
                import traceback
                result['errors'].append(traceback.format_exc())
        
        return result
    
    def validate_seq_numbers(self, packets: List[Dict], attack_type: str = None,
                            params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Validate TCP sequence numbers.
        
        Checks:
        - For fakeddisorder: fake packet seq should equal first real packet seq
        - For split attacks: second packet seq should be first_seq + first_payload_len
        - For all: sequence numbers should be consistent
        
        Args:
            packets: List of parsed packet dictionaries
            attack_type: Type of attack
            params: Attack parameters
        
        Returns:
            Validation result dictionary
        """
        params = params or {}
        result = {
            'passed': True,
            'errors': [],
            'warnings': [],
            'details': []
        }
        
        if not packets:
            result['errors'].append("No packets to validate")
            result['passed'] = False
            return result
        
        # Separate fake and real packets
        fake_packets = [p for p in packets if self._is_fake_packet(p)]
        real_packets = [p for p in packets if not self._is_fake_packet(p)]
        
        # Validate based on attack type
        if attack_type == 'fakeddisorder':
            if not fake_packets:
                result['errors'].append("No fake packet found in fakeddisorder attack")
                result['passed'] = False
            elif len(real_packets) < 2:
                result['errors'].append(f"Expected at least 2 real packets, found {len(real_packets)}")
                result['passed'] = False
            else:
                # Validate fake packet seq equals first real packet seq
                fake_seq = fake_packets[0]['seq']
                real_packets_sorted = sorted(real_packets, key=lambda p: p['seq'])
                original_seq = real_packets_sorted[0]['seq']
                
                if fake_seq != original_seq:
                    result['errors'].append(
                        f"Fake packet seq ({fake_seq}) != original seq ({original_seq})"
                    )
                    result['passed'] = False
                else:
                    result['details'].append(f"✓ Fake packet seq correct: {fake_seq}")
                
                # Validate real packets are sequential
                for i in range(len(real_packets_sorted) - 1):
                    curr = real_packets_sorted[i]
                    next_pkt = real_packets_sorted[i + 1]
                    expected_seq = curr['seq'] + curr['payload_len']
                    
                    if next_pkt['seq'] != expected_seq:
                        result['warnings'].append(
                            f"Packet {i+1} seq ({next_pkt['seq']}) != expected ({expected_seq})"
                        )
        
        elif attack_type in ['split', 'disorder']:
            if len(packets) < 2:
                result['errors'].append(f"Expected at least 2 packets for {attack_type}, found {len(packets)}")
                result['passed'] = False
            else:
                # Validate split packets have correct sequence numbers
                packets_sorted = sorted(packets, key=lambda p: p['seq'])
                for i in range(len(packets_sorted) - 1):
                    curr = packets_sorted[i]
                    next_pkt = packets_sorted[i + 1]
                    expected_seq = curr['seq'] + curr['payload_len']
                    
                    # Account for overlap if specified
                    overlap = params.get('overlap_size', 0)
                    if overlap > 0:
                        expected_seq -= overlap
                    
                    if next_pkt['seq'] != expected_seq:
                        result['errors'].append(
                            f"Packet {i+1} seq ({next_pkt['seq']}) != expected ({expected_seq})"
                        )
                        result['passed'] = False
                    else:
                        result['details'].append(f"✓ Packet {i+1} seq correct: {next_pkt['seq']}")
        
        else:
            # Generic validation - just check packets are sequential
            if len(packets) > 1:
                packets_sorted = sorted(packets, key=lambda p: p['seq'])
                for i in range(len(packets_sorted) - 1):
                    curr = packets_sorted[i]
                    next_pkt = packets_sorted[i + 1]
                    
                    if next_pkt['seq'] < curr['seq']:
                        result['warnings'].append(
                            f"Packet {i+1} seq ({next_pkt['seq']}) < previous ({curr['seq']})"
                        )
        
        return result
    
    def validate_checksums(self, packets: List[Dict], attack_type: str = None,
                          params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Validate TCP checksums.
        
        Checks:
        - For attacks with badsum fooling: fake packet should have bad checksum
        - Real packets should always have good checksums
        - Detects WinDivert checksum recalculation issues
        
        Args:
            packets: List of parsed packet dictionaries
            attack_type: Type of attack
            params: Attack parameters
        
        Returns:
            Validation result dictionary
        """
        params = params or {}
        result = {
            'passed': True,
            'errors': [],
            'warnings': [],
            'details': []
        }
        
        if not packets:
            result['errors'].append("No packets to validate")
            result['passed'] = False
            return result
        
        fooling = params.get('fooling', [])
        has_badsum = 'badsum' in fooling if isinstance(fooling, list) else fooling == 'badsum'
        
        # Separate fake and real packets
        fake_packets = [p for p in packets if self._is_fake_packet(p)]
        real_packets = [p for p in packets if not self._is_fake_packet(p)]
        
        if has_badsum:
            # Validate fake packets have bad checksums
            for i, pkt in enumerate(fake_packets):
                if pkt['checksum_valid']:
                    result['errors'].append(
                        f"Fake packet {i} should have bad checksum but has good checksum"
                    )
                    result['passed'] = False
                else:
                    result['details'].append(f"✓ Fake packet {i} has bad checksum as expected")
            
            # Validate real packets have good checksums
            for i, pkt in enumerate(real_packets):
                if not pkt['checksum_valid']:
                    result['errors'].append(
                        f"Real packet {i} should have good checksum but has bad checksum"
                    )
                    result['passed'] = False
                else:
                    result['details'].append(f"✓ Real packet {i} has good checksum")
        
        else:
            # All packets should have good checksums
            for i, pkt in enumerate(packets):
                if not pkt['checksum_valid']:
                    result['warnings'].append(
                        f"Packet {i} has invalid checksum (not expected for this attack)"
                    )
        
        return result
    
    def validate_ttl(self, packets: List[Dict], attack_type: str = None,
                    params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Validate TTL (Time-To-Live) values.
        
        Checks:
        - For fake attacks: fake packet should have specified TTL (usually low, like 1-3)
        - Real packets should have normal TTL (64 or 128)
        - TTL values match parameters
        
        Args:
            packets: List of parsed packet dictionaries
            attack_type: Type of attack
            params: Attack parameters
        
        Returns:
            Validation result dictionary
        """
        params = params or {}
        result = {
            'passed': True,
            'errors': [],
            'warnings': [],
            'details': []
        }
        
        if not packets:
            result['errors'].append("No packets to validate")
            result['passed'] = False
            return result
        
        expected_ttl = params.get('ttl')
        expected_fake_ttl = params.get('fake_ttl', expected_ttl)
        
        # Separate fake and real packets
        fake_packets = [p for p in packets if self._is_fake_packet(p)]
        real_packets = [p for p in packets if not self._is_fake_packet(p)]
        
        if attack_type in ['fake', 'fakeddisorder'] and expected_fake_ttl is not None:
            # Validate fake packets have correct TTL
            for i, pkt in enumerate(fake_packets):
                if pkt['ttl'] != expected_fake_ttl:
                    result['errors'].append(
                        f"Fake packet {i} TTL ({pkt['ttl']}) != expected ({expected_fake_ttl})"
                    )
                    result['passed'] = False
                else:
                    result['details'].append(f"✓ Fake packet {i} TTL correct: {pkt['ttl']}")
            
            # Validate real packets have normal TTL
            for i, pkt in enumerate(real_packets):
                if pkt['ttl'] not in [64, 128, 255]:  # Common default TTLs
                    result['warnings'].append(
                        f"Real packet {i} has unusual TTL: {pkt['ttl']} (expected 64, 128, or 255)"
                    )
                else:
                    result['details'].append(f"✓ Real packet {i} TTL normal: {pkt['ttl']}")
        
        elif expected_ttl is not None:
            # For non-fake attacks, check if TTL matches parameter
            for i, pkt in enumerate(packets):
                if pkt['ttl'] != expected_ttl:
                    result['warnings'].append(
                        f"Packet {i} TTL ({pkt['ttl']}) != expected ({expected_ttl})"
                    )
        
        return result
    
    def _parse_pcap(self, pcap_file: str) -> List[Dict]:
        """
        Parse PCAP file and extract packet information.
        
        Args:
            pcap_file: Path to PCAP file
        
        Returns:
            List of packet dictionaries with keys:
            - index, timestamp, src_ip, dst_ip, src_port, dst_port
            - seq, ack, ttl, flags, checksum, checksum_valid
            - payload, payload_len
        """
        packets = []
        
        try:
            pcap_path = Path(pcap_file)
            if not pcap_path.exists():
                if self.debug:
                    print(f"PCAP file not found: {pcap_file}")
                return packets
            
            with open(pcap_file, 'rb') as f:
                # Read PCAP global header
                global_header = f.read(24)
                if len(global_header) < 24:
                    return packets
                
                # Check magic number
                magic = struct.unpack('<I', global_header[:4])[0]
                if magic not in [0xa1b2c3d4, 0xd4c3b2a1]:
                    if self.debug:
                        print(f"Invalid PCAP magic number: {hex(magic)}")
                    return packets
                
                # Determine byte order
                little_endian = magic == 0xa1b2c3d4
                endian = '<' if little_endian else '>'
                
                packet_index = 0
                while packet_index < 10000:  # Safety limit
                    # Read packet record header
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break
                    
                    # Parse packet header
                    ts_sec, ts_usec, caplen, origlen = struct.unpack(f'{endian}IIII', packet_header)
                    timestamp = ts_sec + ts_usec / 1000000.0
                    
                    # Read packet data
                    packet_data = f.read(caplen)
                    if len(packet_data) < caplen:
                        break
                    
                    # Parse packet
                    packet = self._parse_packet(packet_data, packet_index, timestamp)
                    if packet:
                        packets.append(packet)
                    
                    packet_index += 1
                    
        except Exception as e:
            if self.debug:
                print(f"Error parsing PCAP {pcap_file}: {e}")
                import traceback
                traceback.print_exc()
        
        return packets
    
    def _parse_packet(self, raw_data: bytes, index: int, timestamp: float) -> Optional[Dict]:
        """
        Parse raw packet data into dictionary.
        
        Args:
            raw_data: Raw packet bytes
            index: Packet index
            timestamp: Packet timestamp
        
        Returns:
            Packet dictionary or None if parsing fails
        """
        try:
            if len(raw_data) < 34:  # Minimum Ethernet + IP + TCP
                return None
            
            # Skip Ethernet header (14 bytes)
            ip_data = raw_data[14:]
            
            if len(ip_data) < 20:
                return None
            
            # Parse IP header
            version_ihl = ip_data[0]
            version = (version_ihl >> 4) & 0xF
            
            if version != 4:  # Only IPv4
                return None
            
            ihl = (version_ihl & 0xF) * 4
            ttl = ip_data[8]
            protocol = ip_data[9]
            src_ip = socket.inet_ntoa(ip_data[12:16])
            dst_ip = socket.inet_ntoa(ip_data[16:20])
            
            if protocol != 6:  # Only TCP
                return None
            
            # Parse TCP header
            tcp_data = ip_data[ihl:]
            if len(tcp_data) < 20:
                return None
            
            src_port = struct.unpack('>H', tcp_data[0:2])[0]
            dst_port = struct.unpack('>H', tcp_data[2:4])[0]
            seq_num = struct.unpack('>I', tcp_data[4:8])[0]
            ack_num = struct.unpack('>I', tcp_data[8:12])[0]
            
            # TCP flags
            flags_byte = tcp_data[13]
            flags = []
            flag_names = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
            for i, flag_name in enumerate(flag_names):
                if flags_byte & (1 << i):
                    flags.append(flag_name)
            
            # Window size
            window_size = struct.unpack('>H', tcp_data[14:16])[0]
            
            # Checksum
            checksum = struct.unpack('>H', tcp_data[16:18])[0]
            
            # TCP header length
            tcp_header_len = ((tcp_data[12] >> 4) & 0xF) * 4
            
            # Payload
            payload = tcp_data[tcp_header_len:] if tcp_header_len < len(tcp_data) else b""
            
            # Validate checksum
            checksum_valid = self._validate_tcp_checksum(
                ip_data[:ihl], tcp_data[:tcp_header_len], payload
            )
            
            return {
                'index': index,
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'seq': seq_num,
                'ack': ack_num,
                'ttl': ttl,
                'flags': flags,
                'window_size': window_size,
                'checksum': checksum,
                'checksum_valid': checksum_valid,
                'payload': payload,
                'payload_len': len(payload)
            }
            
        except Exception as e:
            if self.debug:
                print(f"Error parsing packet {index}: {e}")
            return None
    
    def _validate_tcp_checksum(self, ip_header: bytes, tcp_header: bytes, 
                               payload: bytes) -> bool:
        """
        Validate TCP checksum.
        
        Args:
            ip_header: IP header bytes
            tcp_header: TCP header bytes
            payload: TCP payload bytes
        
        Returns:
            True if checksum is valid
        """
        try:
            # Extract source and destination IPs
            src_ip = ip_header[12:16]
            dst_ip = ip_header[16:20]
            
            # Build pseudo header
            pseudo_header = src_ip + dst_ip
            pseudo_header += struct.pack('>BBH', 0, 6, len(tcp_header) + len(payload))
            
            # Zero out checksum field in TCP header for calculation
            tcp_header_copy = bytearray(tcp_header)
            tcp_header_copy[16:18] = b'\x00\x00'
            
            # Combine all parts
            data = pseudo_header + bytes(tcp_header_copy) + payload
            
            # Calculate checksum
            calculated_checksum = self._calculate_checksum(data)
            
            # Get original checksum
            original_checksum = struct.unpack('>H', tcp_header[16:18])[0]
            
            return calculated_checksum == original_checksum
            
        except Exception:
            return False
    
    def _calculate_checksum(self, data: bytes) -> int:
        """
        Calculate Internet checksum.
        
        Args:
            data: Data to checksum
        
        Returns:
            Checksum value
        """
        # Pad data to even length
        if len(data) % 2 == 1:
            data += b'\x00'
        
        # Sum all 16-bit words
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        
        # Add carry bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        # One's complement
        checksum = ~checksum & 0xFFFF
        
        return checksum
    
    def _is_fake_packet(self, packet: Dict) -> bool:
        """
        Detect if packet is likely a fake packet.
        
        Fake packets typically have:
        - Low TTL (1-3)
        - Bad checksum (if badsum fooling is used)
        
        Args:
            packet: Packet dictionary
        
        Returns:
            True if packet appears to be fake
        """
        return packet['ttl'] <= 3 or not packet['checksum_valid']


# Convenience function for quick validation
def quick_validate(pcap_file: str, attack_type: str = None, 
                  params: Dict[str, Any] = None, debug: bool = False) -> Dict[str, Any]:
    """
    Quick validation of a PCAP file.
    
    Args:
        pcap_file: Path to PCAP file
        attack_type: Type of attack (fake, split, fakeddisorder, etc.)
        params: Attack parameters
        debug: Enable debug output
    
    Returns:
        Validation result dictionary
    
    Example:
        result = quick_validate('test.pcap', 'fake', {'ttl': 1, 'fooling': ['badsum']})
        if result['passed']:
            print("✓ Validation passed!")
        else:
            print(f"✗ Validation failed:")
            for error in result['errors']:
                print(f"  - {error}")
    """
    validator = SimplePacketValidator(debug=debug)
    return validator.validate_pcap(pcap_file, attack_type, params)