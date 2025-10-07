"""
PacketValidator - Validates generated packets against attack specifications.

This module provides comprehensive validation of DPI bypass attack packets,
ensuring they match expected behavior for sequence numbers, checksums, TTL,
packet counts, and other critical parameters.
"""

import struct
import socket
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Import spec loader
try:
    from core.attack_spec_loader import get_spec_loader, AttackSpec, ValidationRule
except ImportError:
    # Fallback for different import paths
    try:
        from recon.core.attack_spec_loader import get_spec_loader, AttackSpec, ValidationRule
    except ImportError:
        get_spec_loader = None
        AttackSpec = None
        ValidationRule = None


class ValidationSeverity(Enum):
    """Severity levels for validation issues."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ValidationDetail:
    """Details of a specific validation check."""
    aspect: str
    passed: bool
    expected: Any = None
    actual: Any = None
    message: str = ""
    severity: ValidationSeverity = ValidationSeverity.ERROR
    packet_index: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'aspect': self.aspect,
            'passed': self.passed,
            'expected': str(self.expected) if self.expected is not None else None,
            'actual': str(self.actual) if self.actual is not None else None,
            'message': self.message,
            'severity': self.severity.value,
            'packet_index': self.packet_index
        }


@dataclass
class ValidationResult:
    """Result of packet validation."""
    attack_name: str
    params: Dict[str, Any]
    passed: bool = False
    details: List[ValidationDetail] = field(default_factory=list)
    packet_count: int = 0
    error: Optional[str] = None
    
    def add_detail(self, detail: ValidationDetail):
        """Add validation detail."""
        self.details.append(detail)
        if not detail.passed and detail.severity in [ValidationSeverity.ERROR, ValidationSeverity.CRITICAL]:
            self.passed = False
    
    def get_critical_issues(self) -> List[ValidationDetail]:
        """Get all critical validation issues."""
        return [d for d in self.details if d.severity == ValidationSeverity.CRITICAL and not d.passed]
    
    def get_errors(self) -> List[ValidationDetail]:
        """Get all error-level issues."""
        return [d for d in self.details if d.severity == ValidationSeverity.ERROR and not d.passed]
    
    def get_warnings(self) -> List[ValidationDetail]:
        """Get all warnings."""
        return [d for d in self.details if d.severity == ValidationSeverity.WARNING and not d.passed]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'attack_name': self.attack_name,
            'params': self.params,
            'passed': self.passed,
            'packet_count': self.packet_count,
            'error': self.error,
            'details': [d.to_dict() for d in self.details],
            'critical_issues': len(self.get_critical_issues()),
            'errors': len(self.get_errors()),
            'warnings': len(self.get_warnings())
        }


@dataclass
class PacketData:
    """Parsed packet data for validation."""
    index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    sequence_num: int
    ack_num: int
    ttl: int
    flags: List[str]
    window_size: int
    checksum: int
    checksum_valid: bool
    payload: bytes
    payload_length: int
    raw_data: bytes
    
    def is_fake_packet(self) -> bool:
        """Detect if this is likely a fake packet."""
        return self.ttl <= 3 or not self.checksum_valid
    
    def has_flag(self, flag: str) -> bool:
        """Check if packet has specific TCP flag."""
        return flag in self.flags


class PacketValidator:
    """
    Validates generated packets against attack specifications.
    
    This class provides comprehensive validation including:
    - Sequence number validation
    - Checksum validation
    - TTL validation
    - Packet count validation
    - Visual diff generation
    """
    
    def __init__(self, debug_mode: bool = False):
        """
        Initialize PacketValidator.
        
        Args:
            debug_mode: Enable debug output
        """
        self.debug_mode = debug_mode
        self.max_packets = 10000
        self.spec_loader = get_spec_loader() if get_spec_loader else None
    
    def validate_attack(self, attack_name: str, params: Dict[str, Any], 
                       pcap_file: str) -> ValidationResult:
        """
        Validate that attack generated correct packets.
        
        Args:
            attack_name: Name of attack (e.g., 'fake', 'split', 'fakeddisorder')
            params: Attack parameters
            pcap_file: Path to PCAP file
        
        Returns:
            ValidationResult with pass/fail and details
        """
        result = ValidationResult(
            attack_name=attack_name,
            params=params,
            passed=True  # Assume pass until proven otherwise
        )
        
        try:
            # Parse PCAP file
            packets = self.parse_pcap(pcap_file)
            result.packet_count = len(packets)
            
            if not packets:
                result.passed = False
                result.error = "No packets found in PCAP file"
                return result
            
            # Validate based on attack type
            if attack_name in ['fake', 'fakeddisorder']:
                self._validate_fake_attack(packets, params, result)
            
            if attack_name in ['split', 'fakeddisorder', 'disorder']:
                self._validate_split_attack(packets, params, result)
            
            if attack_name in ['fakeddisorder', 'disorder', 'multidisorder']:
                self._validate_disorder_attack(packets, params, result)
            
            # Common validations for all attacks
            self._validate_sequence_numbers(packets, params, result)
            self._validate_checksums(packets, params, result)
            self._validate_ttl(packets, params, result)
            self._validate_packet_count(packets, params, result)
            
        except Exception as e:
            result.passed = False
            result.error = f"Validation failed: {str(e)}"
            if self.debug_mode:
                import traceback
                result.error += f"\n{traceback.format_exc()}"
        
        return result
    
    def validate_attack_with_spec(self, attack_name: str, params: Dict[str, Any], 
                                   pcap_file: str) -> ValidationResult:
        """
        Validate attack using YAML specification.
        
        Args:
            attack_name: Name of attack
            params: Attack parameters
            pcap_file: Path to PCAP file
        
        Returns:
            ValidationResult with spec-based validation
        """
        result = ValidationResult(
            attack_name=attack_name,
            params=params,
            passed=True
        )
        
        if not self.spec_loader:
            result.passed = False
            result.error = "Spec loader not available"
            return result
        
        try:
            # Load attack specification
            spec = self.spec_loader.load_spec(attack_name)
            if not spec:
                result.passed = False
                result.error = f"No specification found for attack: {attack_name}"
                return result
            
            # Validate parameters against spec
            param_errors = self.spec_loader.validate_parameters(attack_name, params)
            if param_errors:
                result.passed = False
                result.error = f"Parameter validation failed: {'; '.join(param_errors)}"
                for error in param_errors:
                    result.add_detail(ValidationDetail(
                        aspect="parameters",
                        passed=False,
                        message=error,
                        severity=ValidationSeverity.CRITICAL
                    ))
                return result
            
            # Parse PCAP file
            packets = self.parse_pcap(pcap_file)
            result.packet_count = len(packets)
            
            if not packets:
                result.passed = False
                result.error = "No packets found in PCAP file"
                return result
            
            # Apply validation rules from spec
            self._apply_spec_validation_rules(spec, packets, params, result)
            
        except Exception as e:
            result.passed = False
            result.error = f"Spec-based validation failed: {str(e)}"
            if self.debug_mode:
                import traceback
                result.error += f"\n{traceback.format_exc()}"
        
        return result
    
    def _apply_spec_validation_rules(self, spec: 'AttackSpec', packets: List[PacketData],
                                     params: Dict[str, Any], result: ValidationResult):
        """
        Apply validation rules from spec to packets.
        
        Args:
            spec: Attack specification
            packets: Parsed packets
            params: Attack parameters
            result: ValidationResult to update
        """
        # Apply each category of validation rules
        for category, rules in spec.validation_rules.items():
            for rule in rules:
                try:
                    # Evaluate rule
                    rule_passed = self._evaluate_validation_rule(rule, packets, params, spec)
                    
                    severity = ValidationSeverity.CRITICAL
                    if rule.severity == 'warning':
                        severity = ValidationSeverity.WARNING
                    elif rule.severity == 'info':
                        severity = ValidationSeverity.INFO
                    elif rule.severity == 'error':
                        severity = ValidationSeverity.ERROR
                    
                    detail = ValidationDetail(
                        aspect=category,
                        passed=rule_passed,
                        message=rule.description,
                        severity=severity
                    )
                    
                    result.add_detail(detail)
                    
                except Exception as e:
                    # Rule evaluation failed
                    result.add_detail(ValidationDetail(
                        aspect=category,
                        passed=False,
                        message=f"Rule evaluation failed: {rule.description} - {str(e)}",
                        severity=ValidationSeverity.ERROR
                    ))
    
    def _evaluate_validation_rule(self, rule: 'ValidationRule', packets: List[PacketData],
                                  params: Dict[str, Any], spec: 'AttackSpec') -> bool:
        """
        Evaluate a single validation rule.
        
        Args:
            rule: Validation rule to evaluate
            packets: Parsed packets
            params: Attack parameters
            spec: Attack specification
        
        Returns:
            True if rule passes, False otherwise
        """
        # This is a simplified evaluation - in production, you'd want a proper
        # expression evaluator or DSL interpreter
        
        rule_str = rule.rule
        
        # Simple rule evaluation based on common patterns
        if "len(packets)" in rule_str:
            # Packet count rules
            expected_count = self._extract_expected_count(rule_str, params, spec)
            actual_count = len(packets)
            return eval(rule_str.replace("len(packets)", str(actual_count)))
        
        elif "checksum_valid" in rule_str:
            # Checksum rules
            return self._evaluate_checksum_rule(rule_str, packets, params)
        
        elif ".ttl" in rule_str:
            # TTL rules
            return self._evaluate_ttl_rule(rule_str, packets, params)
        
        elif ".seq" in rule_str:
            # Sequence number rules
            return self._evaluate_seq_rule(rule_str, packets, params)
        
        else:
            # Default: try to evaluate as Python expression
            # This is simplified - production code should use a safe evaluator
            try:
                return bool(eval(rule_str))
            except:
                return False
    
    def _extract_expected_count(self, rule_str: str, params: Dict[str, Any], 
                               spec: 'AttackSpec') -> int:
        """Extract expected packet count from spec."""
        expected_packets = spec.expected_packets
        count = expected_packets.get('count', 0)
        
        # Handle dynamic counts
        if isinstance(count, str):
            # Evaluate expression
            try:
                return eval(count, {"params": params, "len": len})
            except:
                return 0
        
        return count
    
    def _evaluate_checksum_rule(self, rule_str: str, packets: List[PacketData],
                                params: Dict[str, Any]) -> bool:
        """Evaluate checksum validation rule."""
        # Simplified checksum evaluation
        if "all(" in rule_str and "checksum_valid" in rule_str:
            return all(p.checksum_valid for p in packets)
        
        if "fake_packet.checksum_valid" in rule_str:
            if packets:
                fake_packet = packets[0]  # Assume first is fake
                if "== False" in rule_str:
                    return not fake_packet.checksum_valid
                elif "== True" in rule_str:
                    return fake_packet.checksum_valid
        
        return True
    
    def _evaluate_ttl_rule(self, rule_str: str, packets: List[PacketData],
                          params: Dict[str, Any]) -> bool:
        """Evaluate TTL validation rule."""
        # Simplified TTL evaluation
        if "fake_packet.ttl" in rule_str and packets:
            fake_packet = packets[0]
            expected_ttl = params.get('ttl') or params.get('fake_ttl', 1)
            return fake_packet.ttl == expected_ttl
        
        if "all(" in rule_str and ".ttl in" in rule_str:
            return all(p.ttl in [64, 128] for p in packets)
        
        return True
    
    def _evaluate_seq_rule(self, rule_str: str, packets: List[PacketData],
                          params: Dict[str, Any]) -> bool:
        """Evaluate sequence number validation rule."""
        # Simplified sequence number evaluation
        if len(packets) < 2:
            return True
        
        if "fake_packet.seq == real_packet.seq" in rule_str:
            return packets[0].seq == packets[1].seq
        
        if "packets[0].seq < packets[1].seq" in rule_str:
            return packets[0].seq < packets[1].seq
        
        return True

    
    def parse_pcap(self, pcap_file: str) -> List[PacketData]:
        """
        Parse PCAP file and extract packet data.
        
        Args:
            pcap_file: Path to PCAP file
        
        Returns:
            List of PacketData objects
        """
        packets = []
        
        try:
            pcap_path = Path(pcap_file)
            if not pcap_path.exists():
                if self.debug_mode:
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
                    if self.debug_mode:
                        print(f"Invalid PCAP magic number: {hex(magic)}")
                    return packets
                
                # Determine byte order
                little_endian = magic == 0xa1b2c3d4
                endian = '<' if little_endian else '>'
                
                packet_index = 0
                while packet_index < self.max_packets:
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
            if self.debug_mode:
                print(f"Error parsing PCAP {pcap_file}: {e}")
        
        return packets
    
    def _parse_packet(self, raw_data: bytes, index: int, timestamp: float) -> Optional[PacketData]:
        """
        Parse raw packet data into PacketData object.
        
        Args:
            raw_data: Raw packet bytes
            index: Packet index in sequence
            timestamp: Packet timestamp
        
        Returns:
            PacketData object or None if parsing fails
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
            
            if version != 4:  # Only IPv4 supported
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
            
            return PacketData(
                index=index,
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                sequence_num=seq_num,
                ack_num=ack_num,
                ttl=ttl,
                flags=flags,
                window_size=window_size,
                checksum=checksum,
                checksum_valid=checksum_valid,
                payload=payload,
                payload_length=len(payload),
                raw_data=raw_data
            )
            
        except Exception as e:
            if self.debug_mode:
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
            # If checksum validation fails, assume it's invalid
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

    
    def _validate_sequence_numbers(self, packets: List[PacketData], params: Dict[str, Any],
                                   result: ValidationResult):
        """
        Validate sequence numbers are correct.
        
        For fakeddisorder:
        - fake_seq should equal original_seq (first real packet seq)
        - real packets should have sequential seq numbers
        - overlap calculations should be correct
        
        Args:
            packets: List of parsed packets
            params: Attack parameters
            result: ValidationResult to update
        """
        attack_name = result.attack_name
        
        if attack_name == 'fakeddisorder':
            self._validate_fakeddisorder_sequence(packets, params, result)
        elif attack_name in ['split', 'disorder', 'multisplit', 'multidisorder']:
            self._validate_split_sequence(packets, params, result)
        else:
            # Generic sequence validation
            self._validate_generic_sequence(packets, params, result)
    
    def _validate_fakeddisorder_sequence(self, packets: List[PacketData], 
                                        params: Dict[str, Any], result: ValidationResult):
        """
        Validate sequence numbers for fakeddisorder attack.
        
        Expected pattern:
        1. Fake packet with seq = original_seq
        2. Real packet 2 with seq = original_seq + split_pos
        3. Real packet 1 with seq = original_seq
        """
        if len(packets) < 3:
            result.add_detail(ValidationDetail(
                aspect='sequence_numbers',
                passed=False,
                expected='At least 3 packets',
                actual=f'{len(packets)} packets',
                message='Fakeddisorder requires at least 3 packets (fake + 2 real)',
                severity=ValidationSeverity.CRITICAL
            ))
            return
        
        # Identify fake and real packets
        fake_packets = [p for p in packets if p.is_fake_packet()]
        real_packets = [p for p in packets if not p.is_fake_packet()]
        
        if not fake_packets:
            result.add_detail(ValidationDetail(
                aspect='sequence_numbers',
                passed=False,
                expected='At least 1 fake packet',
                actual='0 fake packets',
                message='No fake packet detected in fakeddisorder attack',
                severity=ValidationSeverity.CRITICAL
            ))
            return
        
        if len(real_packets) < 2:
            result.add_detail(ValidationDetail(
                aspect='sequence_numbers',
                passed=False,
                expected='At least 2 real packets',
                actual=f'{len(real_packets)} real packets',
                message='Fakeddisorder requires at least 2 real packets',
                severity=ValidationSeverity.CRITICAL
            ))
            return
        
        # Get first fake packet and real packets
        fake_packet = fake_packets[0]
        
        # Find the real packet with lowest sequence number (original_seq)
        real_packets_sorted = sorted(real_packets, key=lambda p: p.sequence_num)
        original_seq = real_packets_sorted[0].sequence_num
        
        # Validate fake packet sequence number
        if fake_packet.sequence_num != original_seq:
            result.add_detail(ValidationDetail(
                aspect='sequence_numbers',
                passed=False,
                expected=f'fake_seq={original_seq}',
                actual=f'fake_seq={fake_packet.sequence_num}',
                message=f'Fake packet has wrong sequence number (packet {fake_packet.index})',
                severity=ValidationSeverity.CRITICAL,
                packet_index=fake_packet.index
            ))
        else:
            result.add_detail(ValidationDetail(
                aspect='sequence_numbers',
                passed=True,
                message=f'Fake packet sequence number correct: {fake_packet.sequence_num}',
                severity=ValidationSeverity.INFO,
                packet_index=fake_packet.index
            ))
        
        # Validate real packets are sequential
        split_pos = params.get('split_pos', 0)
        overlap_size = params.get('overlap_size', 0)
        
        for i in range(len(real_packets_sorted) - 1):
            current_packet = real_packets_sorted[i]
            next_packet = real_packets_sorted[i + 1]
            
            # Calculate expected next sequence number
            expected_next_seq = current_packet.sequence_num + current_packet.payload_length
            
            # Account for overlap
            if overlap_size > 0:
                expected_next_seq -= overlap_size
            
            if next_packet.sequence_num != expected_next_seq:
                result.add_detail(ValidationDetail(
                    aspect='sequence_numbers',
                    passed=False,
                    expected=f'seq={expected_next_seq}',
                    actual=f'seq={next_packet.sequence_num}',
                    message=f'Real packet {i+1} has wrong sequence number (packet {next_packet.index})',
                    severity=ValidationSeverity.ERROR,
                    packet_index=next_packet.index
                ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='sequence_numbers',
                    passed=True,
                    message=f'Real packet {i+1} sequence number correct',
                    severity=ValidationSeverity.INFO,
                    packet_index=next_packet.index
                ))
        
        # Validate overlap calculations if specified
        if overlap_size > 0:
            self._validate_overlap(real_packets_sorted, overlap_size, result)
    
    def _validate_split_sequence(self, packets: List[PacketData], 
                                 params: Dict[str, Any], result: ValidationResult):
        """
        Validate sequence numbers for split/disorder attacks.
        """
        if len(packets) < 2:
            result.add_detail(ValidationDetail(
                aspect='sequence_numbers',
                passed=False,
                expected='At least 2 packets',
                actual=f'{len(packets)} packets',
                message='Split attack requires at least 2 packets',
                severity=ValidationSeverity.ERROR
            ))
            return
        
        # Get packets with payload (skip handshake packets)
        payload_packets = [p for p in packets if p.payload_length > 0]
        
        if len(payload_packets) < 2:
            result.add_detail(ValidationDetail(
                aspect='sequence_numbers',
                passed=False,
                expected='At least 2 packets with payload',
                actual=f'{len(payload_packets)} packets with payload',
                message='Split attack requires at least 2 packets with payload',
                severity=ValidationSeverity.ERROR
            ))
            return
        
        # Sort by sequence number
        sorted_packets = sorted(payload_packets, key=lambda p: p.sequence_num)
        
        # Validate sequential sequence numbers
        for i in range(len(sorted_packets) - 1):
            current = sorted_packets[i]
            next_pkt = sorted_packets[i + 1]
            
            expected_seq = current.sequence_num + current.payload_length
            
            if next_pkt.sequence_num != expected_seq:
                result.add_detail(ValidationDetail(
                    aspect='sequence_numbers',
                    passed=False,
                    expected=f'seq={expected_seq}',
                    actual=f'seq={next_pkt.sequence_num}',
                    message=f'Packet {i+1} has non-sequential sequence number',
                    severity=ValidationSeverity.ERROR,
                    packet_index=next_pkt.index
                ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='sequence_numbers',
                    passed=True,
                    message=f'Packet {i+1} sequence number correct',
                    severity=ValidationSeverity.INFO,
                    packet_index=next_pkt.index
                ))
    
    def _validate_generic_sequence(self, packets: List[PacketData], 
                                   params: Dict[str, Any], result: ValidationResult):
        """
        Generic sequence number validation for other attacks.
        """
        payload_packets = [p for p in packets if p.payload_length > 0]
        
        if len(payload_packets) < 2:
            return  # Not enough packets to validate sequence
        
        # Check for reasonable sequence numbers
        for packet in payload_packets:
            if packet.sequence_num == 0:
                result.add_detail(ValidationDetail(
                    aspect='sequence_numbers',
                    passed=False,
                    expected='Non-zero sequence number',
                    actual='seq=0',
                    message=f'Packet {packet.index} has zero sequence number',
                    severity=ValidationSeverity.WARNING,
                    packet_index=packet.index
                ))
    
    def _validate_overlap(self, packets: List[PacketData], overlap_size: int, 
                         result: ValidationResult):
        """
        Validate overlap calculations for fakeddisorder.
        """
        if len(packets) < 2:
            return
        
        for i in range(len(packets) - 1):
            current = packets[i]
            next_pkt = packets[i + 1]
            
            # Check if there's actual overlap
            overlap_start = current.sequence_num + current.payload_length - overlap_size
            overlap_end = current.sequence_num + current.payload_length
            
            if next_pkt.sequence_num >= overlap_start and next_pkt.sequence_num < overlap_end:
                result.add_detail(ValidationDetail(
                    aspect='sequence_numbers',
                    passed=True,
                    message=f'Overlap detected between packets {i} and {i+1}: {overlap_size} bytes',
                    severity=ValidationSeverity.INFO
                ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='sequence_numbers',
                    passed=False,
                    expected=f'Overlap of {overlap_size} bytes',
                    actual='No overlap detected',
                    message=f'Expected overlap not found between packets {i} and {i+1}',
                    severity=ValidationSeverity.WARNING
                ))

    
    def _validate_checksums(self, packets: List[PacketData], params: Dict[str, Any],
                           result: ValidationResult):
        """
        Validate checksums are correct/corrupted as specified.
        
        For attacks with badsum fooling:
        - Fake packets should have bad checksum
        - Real packets should have good checksum
        - Detect WinDivert checksum recalculation
        
        Args:
            packets: List of parsed packets
            params: Attack parameters
            result: ValidationResult to update
        """
        fooling = params.get('fooling', [])
        
        # Check if badsum is specified
        has_badsum = 'badsum' in fooling if isinstance(fooling, list) else fooling == 'badsum'
        
        if not has_badsum:
            # No badsum specified, all packets should have good checksums
            self._validate_all_good_checksums(packets, result)
            return
        
        # Identify fake and real packets
        fake_packets = [p for p in packets if p.is_fake_packet()]
        real_packets = [p for p in packets if not p.is_fake_packet()]
        
        # Validate fake packets have bad checksums
        for fake_packet in fake_packets:
            if fake_packet.checksum_valid:
                result.add_detail(ValidationDetail(
                    aspect='checksum',
                    passed=False,
                    expected='bad checksum',
                    actual='good checksum',
                    message=f'Fake packet {fake_packet.index} should have bad checksum but has good checksum',
                    severity=ValidationSeverity.CRITICAL,
                    packet_index=fake_packet.index
                ))
                
                # Check if this might be WinDivert recalculation
                if fake_packet.ttl <= 3:
                    result.add_detail(ValidationDetail(
                        aspect='checksum',
                        passed=False,
                        expected='bad checksum preserved',
                        actual='checksum recalculated',
                        message=f'WinDivert may have recalculated checksum for packet {fake_packet.index}',
                        severity=ValidationSeverity.CRITICAL,
                        packet_index=fake_packet.index
                    ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='checksum',
                    passed=True,
                    message=f'Fake packet {fake_packet.index} has bad checksum as expected',
                    severity=ValidationSeverity.INFO,
                    packet_index=fake_packet.index
                ))
        
        # Validate real packets have good checksums
        for real_packet in real_packets:
            if not real_packet.checksum_valid:
                result.add_detail(ValidationDetail(
                    aspect='checksum',
                    passed=False,
                    expected='good checksum',
                    actual='bad checksum',
                    message=f'Real packet {real_packet.index} should have good checksum but has bad checksum',
                    severity=ValidationSeverity.ERROR,
                    packet_index=real_packet.index
                ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='checksum',
                    passed=True,
                    message=f'Real packet {real_packet.index} has good checksum',
                    severity=ValidationSeverity.INFO,
                    packet_index=real_packet.index
                ))
        
        # Check for WinDivert recalculation pattern
        self._detect_windivert_recalculation(packets, result)
    
    def _validate_all_good_checksums(self, packets: List[PacketData], result: ValidationResult):
        """
        Validate all packets have good checksums when badsum is not specified.
        """
        for packet in packets:
            if not packet.checksum_valid:
                result.add_detail(ValidationDetail(
                    aspect='checksum',
                    passed=False,
                    expected='good checksum',
                    actual='bad checksum',
                    message=f'Packet {packet.index} has bad checksum but badsum not specified',
                    severity=ValidationSeverity.WARNING,
                    packet_index=packet.index
                ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='checksum',
                    passed=True,
                    message=f'Packet {packet.index} has good checksum',
                    severity=ValidationSeverity.INFO,
                    packet_index=packet.index
                ))
    
    def _detect_windivert_recalculation(self, packets: List[PacketData], result: ValidationResult):
        """
        Detect if WinDivert is recalculating checksums.
        
        WinDivert may recalculate checksums even when we want bad checksums.
        This is a critical issue that breaks badsum fooling.
        """
        fake_packets = [p for p in packets if p.is_fake_packet()]
        
        # If all fake packets have good checksums, WinDivert is likely recalculating
        if fake_packets and all(p.checksum_valid for p in fake_packets):
            result.add_detail(ValidationDetail(
                aspect='checksum',
                passed=False,
                expected='At least one fake packet with bad checksum',
                actual='All fake packets have good checksums',
                message='WinDivert is recalculating checksums - badsum fooling will not work',
                severity=ValidationSeverity.CRITICAL
            ))

    
    def _validate_ttl(self, packets: List[PacketData], params: Dict[str, Any],
                     result: ValidationResult):
        """
        Validate TTL values are correct.
        
        For fake attacks:
        - Fake packets should have specified TTL (or fake_ttl)
        - Real packets should have default TTL (64 or 128)
        
        Args:
            packets: List of parsed packets
            params: Attack parameters
            result: ValidationResult to update
        """
        attack_name = result.attack_name
        
        # Get expected TTL values
        expected_ttl = params.get('ttl')
        expected_fake_ttl = params.get('fake_ttl', expected_ttl)
        
        if attack_name in ['fake', 'fakeddisorder']:
            self._validate_fake_attack_ttl(packets, expected_fake_ttl, result)
        else:
            # For other attacks, just check for reasonable TTL values
            self._validate_generic_ttl(packets, result)
    
    def _validate_fake_attack_ttl(self, packets: List[PacketData], 
                                  expected_fake_ttl: Optional[int], result: ValidationResult):
        """
        Validate TTL for fake attacks.
        """
        if expected_fake_ttl is None:
            result.add_detail(ValidationDetail(
                aspect='ttl',
                passed=False,
                expected='TTL parameter specified',
                actual='No TTL parameter',
                message='TTL parameter not specified for fake attack',
                severity=ValidationSeverity.WARNING
            ))
            return
        
        # Identify fake and real packets
        fake_packets = [p for p in packets if p.is_fake_packet()]
        real_packets = [p for p in packets if not p.is_fake_packet()]
        
        # Validate fake packets have correct TTL
        for fake_packet in fake_packets:
            if fake_packet.ttl != expected_fake_ttl:
                result.add_detail(ValidationDetail(
                    aspect='ttl',
                    passed=False,
                    expected=f'ttl={expected_fake_ttl}',
                    actual=f'ttl={fake_packet.ttl}',
                    message=f'Fake packet {fake_packet.index} has wrong TTL',
                    severity=ValidationSeverity.CRITICAL,
                    packet_index=fake_packet.index
                ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='ttl',
                    passed=True,
                    message=f'Fake packet {fake_packet.index} has correct TTL: {fake_packet.ttl}',
                    severity=ValidationSeverity.INFO,
                    packet_index=fake_packet.index
                ))
        
        # Validate real packets have default TTL
        default_ttls = [64, 128, 255]  # Common default TTLs
        for real_packet in real_packets:
            if real_packet.ttl not in default_ttls:
                result.add_detail(ValidationDetail(
                    aspect='ttl',
                    passed=False,
                    expected=f'ttl in {default_ttls}',
                    actual=f'ttl={real_packet.ttl}',
                    message=f'Real packet {real_packet.index} has unexpected TTL',
                    severity=ValidationSeverity.WARNING,
                    packet_index=real_packet.index
                ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='ttl',
                    passed=True,
                    message=f'Real packet {real_packet.index} has default TTL: {real_packet.ttl}',
                    severity=ValidationSeverity.INFO,
                    packet_index=real_packet.index
                ))
    
    def _validate_generic_ttl(self, packets: List[PacketData], result: ValidationResult):
        """
        Generic TTL validation for non-fake attacks.
        """
        for packet in packets:
            # Check for unreasonably low TTL
            if packet.ttl < 1:
                result.add_detail(ValidationDetail(
                    aspect='ttl',
                    passed=False,
                    expected='ttl >= 1',
                    actual=f'ttl={packet.ttl}',
                    message=f'Packet {packet.index} has invalid TTL',
                    severity=ValidationSeverity.ERROR,
                    packet_index=packet.index
                ))
            # Check for unreasonably high TTL
            elif packet.ttl > 255:
                result.add_detail(ValidationDetail(
                    aspect='ttl',
                    passed=False,
                    expected='ttl <= 255',
                    actual=f'ttl={packet.ttl}',
                    message=f'Packet {packet.index} has invalid TTL',
                    severity=ValidationSeverity.ERROR,
                    packet_index=packet.index
                ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='ttl',
                    passed=True,
                    message=f'Packet {packet.index} has valid TTL: {packet.ttl}',
                    severity=ValidationSeverity.INFO,
                    packet_index=packet.index
                ))

    
    def _validate_packet_count(self, packets: List[PacketData], params: Dict[str, Any],
                               result: ValidationResult):
        """
        Validate correct number of packets generated.
        
        Different attacks generate different packet counts:
        - fake: 2 packets (fake + real)
        - split: 2+ packets (split segments)
        - fakeddisorder: 3+ packets (fake + 2 real segments)
        - disorder: 2+ packets (reordered segments)
        
        Args:
            packets: List of parsed packets
            params: Attack parameters
            result: ValidationResult to update
        """
        attack_name = result.attack_name
        actual_count = len(packets)
        
        # Determine expected packet count based on attack type
        expected_count = self._get_expected_packet_count(attack_name, params)
        
        if expected_count is None:
            # Can't determine expected count, skip validation
            result.add_detail(ValidationDetail(
                aspect='packet_count',
                passed=True,
                message=f'Packet count validation skipped for {attack_name}',
                severity=ValidationSeverity.INFO
            ))
            return
        
        # Validate packet count
        if isinstance(expected_count, tuple):
            # Range of expected counts
            min_count, max_count = expected_count
            if actual_count < min_count or actual_count > max_count:
                result.add_detail(ValidationDetail(
                    aspect='packet_count',
                    passed=False,
                    expected=f'{min_count}-{max_count} packets',
                    actual=f'{actual_count} packets',
                    message=f'Unexpected packet count for {attack_name}',
                    severity=ValidationSeverity.ERROR
                ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='packet_count',
                    passed=True,
                    message=f'Packet count correct: {actual_count} packets',
                    severity=ValidationSeverity.INFO
                ))
        else:
            # Exact expected count
            if actual_count != expected_count:
                result.add_detail(ValidationDetail(
                    aspect='packet_count',
                    passed=False,
                    expected=f'{expected_count} packets',
                    actual=f'{actual_count} packets',
                    message=f'Unexpected packet count for {attack_name}',
                    severity=ValidationSeverity.ERROR
                ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='packet_count',
                    passed=True,
                    message=f'Packet count correct: {actual_count} packets',
                    severity=ValidationSeverity.INFO
                ))
        
        # Validate packet order
        self._validate_packet_order(packets, attack_name, result)
        
        # Validate packet sizes
        self._validate_packet_sizes(packets, params, result)
    
    def _get_expected_packet_count(self, attack_name: str, params: Dict[str, Any]) -> Optional[int | Tuple[int, int]]:
        """
        Get expected packet count for attack type.
        
        Returns:
            Expected count (int), range (tuple), or None if unknown
        """
        if attack_name == 'fake':
            return 2  # fake + real
        elif attack_name == 'split':
            return 2  # 2 segments
        elif attack_name == 'fakeddisorder':
            return 3  # fake + 2 real segments
        elif attack_name == 'disorder':
            return (2, 10)  # 2-10 segments
        elif attack_name == 'multisplit':
            return (3, 10)  # 3-10 segments
        elif attack_name == 'multidisorder':
            return (3, 10)  # 3-10 segments
        else:
            return None  # Unknown attack type
    
    def _validate_packet_order(self, packets: List[PacketData], attack_name: str,
                               result: ValidationResult):
        """
        Validate packet order is correct for attack type.
        """
        if attack_name == 'fakeddisorder':
            # Expected order: fake, real_part2, real_part1
            if len(packets) < 3:
                return
            
            fake_packets = [p for p in packets if p.is_fake_packet()]
            real_packets = [p for p in packets if not p.is_fake_packet()]
            
            if not fake_packets or len(real_packets) < 2:
                return
            
            # Check if fake packet comes first
            fake_index = packets.index(fake_packets[0])
            if fake_index != 0:
                result.add_detail(ValidationDetail(
                    aspect='packet_order',
                    passed=False,
                    expected='Fake packet first',
                    actual=f'Fake packet at index {fake_index}',
                    message='Fake packet should be sent first in fakeddisorder',
                    severity=ValidationSeverity.WARNING
                ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='packet_order',
                    passed=True,
                    message='Fake packet sent first as expected',
                    severity=ValidationSeverity.INFO
                ))
            
            # Check if real packets are in disorder (part2 before part1)
            real_sorted = sorted(real_packets, key=lambda p: p.sequence_num)
            real_indices = [packets.index(p) for p in real_packets]
            
            # In disorder, higher seq should come before lower seq
            if len(real_packets) >= 2:
                first_real = real_packets[0]
                second_real = real_packets[1]
                
                if first_real.sequence_num < second_real.sequence_num:
                    result.add_detail(ValidationDetail(
                        aspect='packet_order',
                        passed=False,
                        expected='Real packets in disorder (part2 before part1)',
                        actual='Real packets in order',
                        message='Real packets should be sent in disorder',
                        severity=ValidationSeverity.WARNING
                    ))
                else:
                    result.add_detail(ValidationDetail(
                        aspect='packet_order',
                        passed=True,
                        message='Real packets sent in disorder as expected',
                        severity=ValidationSeverity.INFO
                    ))
        
        elif attack_name == 'disorder':
            # Check if packets are actually disordered
            payload_packets = [p for p in packets if p.payload_length > 0]
            if len(payload_packets) < 2:
                return
            
            # Check if sequence numbers are not in order
            seq_nums = [p.sequence_num for p in payload_packets]
            is_ordered = all(seq_nums[i] <= seq_nums[i+1] for i in range(len(seq_nums)-1))
            
            if is_ordered:
                result.add_detail(ValidationDetail(
                    aspect='packet_order',
                    passed=False,
                    expected='Packets in disorder',
                    actual='Packets in order',
                    message='Packets should be sent in disorder',
                    severity=ValidationSeverity.WARNING
                ))
            else:
                result.add_detail(ValidationDetail(
                    aspect='packet_order',
                    passed=True,
                    message='Packets sent in disorder as expected',
                    severity=ValidationSeverity.INFO
                ))
    
    def _validate_packet_sizes(self, packets: List[PacketData], params: Dict[str, Any],
                               result: ValidationResult):
        """
        Validate packet sizes are reasonable.
        """
        for packet in packets:
            # Check for unreasonably large packets
            if packet.payload_length > 65535:
                result.add_detail(ValidationDetail(
                    aspect='packet_size',
                    passed=False,
                    expected='payload_length <= 65535',
                    actual=f'payload_length={packet.payload_length}',
                    message=f'Packet {packet.index} has unreasonably large payload',
                    severity=ValidationSeverity.ERROR,
                    packet_index=packet.index
                ))
            
            # Check for split position if specified
            split_pos = params.get('split_pos')
            if split_pos is not None:
                # At least one packet should have payload_length close to split_pos
                if abs(packet.payload_length - split_pos) <= 10:
                    result.add_detail(ValidationDetail(
                        aspect='packet_size',
                        passed=True,
                        message=f'Packet {packet.index} size matches split_pos: {packet.payload_length}',
                        severity=ValidationSeverity.INFO,
                        packet_index=packet.index
                    ))

    
    def _validate_fake_attack(self, packets: List[PacketData], params: Dict[str, Any],
                             result: ValidationResult):
        """Validate fake attack specific requirements."""
        fake_packets = [p for p in packets if p.is_fake_packet()]
        
        if not fake_packets:
            result.add_detail(ValidationDetail(
                aspect='fake_attack',
                passed=False,
                expected='At least 1 fake packet',
                actual='0 fake packets',
                message='No fake packet detected',
                severity=ValidationSeverity.CRITICAL
            ))
    
    def _validate_split_attack(self, packets: List[PacketData], params: Dict[str, Any],
                              result: ValidationResult):
        """Validate split attack specific requirements."""
        split_pos = params.get('split_pos')
        if split_pos is None:
            return
        
        payload_packets = [p for p in packets if p.payload_length > 0]
        if len(payload_packets) < 2:
            result.add_detail(ValidationDetail(
                aspect='split_attack',
                passed=False,
                expected='At least 2 packets with payload',
                actual=f'{len(payload_packets)} packets',
                message='Split attack requires at least 2 packets',
                severity=ValidationSeverity.ERROR
            ))
    
    def _validate_disorder_attack(self, packets: List[PacketData], params: Dict[str, Any],
                                  result: ValidationResult):
        """Validate disorder attack specific requirements."""
        payload_packets = [p for p in packets if p.payload_length > 0]
        
        if len(payload_packets) < 2:
            result.add_detail(ValidationDetail(
                aspect='disorder_attack',
                passed=False,
                expected='At least 2 packets with payload',
                actual=f'{len(payload_packets)} packets',
                message='Disorder attack requires at least 2 packets',
                severity=ValidationSeverity.ERROR
            ))
    
    def generate_visual_diff(self, expected_packets: List[Dict[str, Any]], 
                            actual_packets: List[PacketData],
                            output_format: str = 'text') -> str:
        """
        Generate visual diff between expected and actual packets.
        
        Args:
            expected_packets: List of expected packet specifications
            actual_packets: List of actual parsed packets
            output_format: Output format ('text' or 'html')
        
        Returns:
            Visual diff as string
        """
        if output_format == 'html':
            return self._generate_html_diff(expected_packets, actual_packets)
        else:
            return self._generate_text_diff(expected_packets, actual_packets)
    
    def _generate_text_diff(self, expected_packets: List[Dict[str, Any]], 
                           actual_packets: List[PacketData]) -> str:
        """
        Generate text-based visual diff.
        """
        lines = []
        lines.append("=" * 80)
        lines.append("PACKET VALIDATION DIFF")
        lines.append("=" * 80)
        lines.append("")
        
        max_packets = max(len(expected_packets), len(actual_packets))
        
        for i in range(max_packets):
            lines.append(f"--- Packet {i} ---")
            lines.append("")
            
            # Expected packet
            if i < len(expected_packets):
                expected = expected_packets[i]
                lines.append("EXPECTED:")
                for key, value in expected.items():
                    lines.append(f"  {key:20s}: {value}")
            else:
                lines.append("EXPECTED: (none)")
            
            lines.append("")
            
            # Actual packet
            if i < len(actual_packets):
                actual = actual_packets[i]
                lines.append("ACTUAL:")
                lines.append(f"  {'index':20s}: {actual.index}")
                lines.append(f"  {'timestamp':20s}: {actual.timestamp:.6f}")
                lines.append(f"  {'src_ip':20s}: {actual.src_ip}")
                lines.append(f"  {'dst_ip':20s}: {actual.dst_ip}")
                lines.append(f"  {'src_port':20s}: {actual.src_port}")
                lines.append(f"  {'dst_port':20s}: {actual.dst_port}")
                lines.append(f"  {'sequence_num':20s}: {actual.sequence_num}")
                lines.append(f"  {'ack_num':20s}: {actual.ack_num}")
                lines.append(f"  {'ttl':20s}: {actual.ttl}")
                lines.append(f"  {'flags':20s}: {', '.join(actual.flags)}")
                lines.append(f"  {'window_size':20s}: {actual.window_size}")
                lines.append(f"  {'checksum':20s}: 0x{actual.checksum:04x}")
                lines.append(f"  {'checksum_valid':20s}: {actual.checksum_valid}")
                lines.append(f"  {'payload_length':20s}: {actual.payload_length}")
                lines.append(f"  {'is_fake':20s}: {actual.is_fake_packet()}")
            else:
                lines.append("ACTUAL: (none)")
            
            lines.append("")
            
            # Highlight differences
            if i < len(expected_packets) and i < len(actual_packets):
                expected = expected_packets[i]
                actual = actual_packets[i]
                
                differences = []
                
                # Compare TTL
                if 'ttl' in expected and expected['ttl'] != actual.ttl:
                    differences.append(f"TTL: expected {expected['ttl']}, got {actual.ttl}")
                
                # Compare checksum validity
                if 'checksum_valid' in expected and expected['checksum_valid'] != actual.checksum_valid:
                    differences.append(f"Checksum: expected {'valid' if expected['checksum_valid'] else 'invalid'}, got {'valid' if actual.checksum_valid else 'invalid'}")
                
                # Compare sequence number
                if 'sequence_num' in expected and expected['sequence_num'] != actual.sequence_num:
                    differences.append(f"Sequence: expected {expected['sequence_num']}, got {actual.sequence_num}")
                
                # Compare payload length
                if 'payload_length' in expected and expected['payload_length'] != actual.payload_length:
                    differences.append(f"Payload length: expected {expected['payload_length']}, got {actual.payload_length}")
                
                if differences:
                    lines.append("DIFFERENCES:")
                    for diff in differences:
                        lines.append(f"  ❌ {diff}")
                else:
                    lines.append("✓ No differences")
            
            lines.append("")
            lines.append("-" * 80)
            lines.append("")
        
        return "\n".join(lines)
    
    def _generate_html_diff(self, expected_packets: List[Dict[str, Any]], 
                           actual_packets: List[PacketData]) -> str:
        """
        Generate HTML-based visual diff.
        """
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html>")
        html.append("<head>")
        html.append("<title>Packet Validation Diff</title>")
        html.append("<style>")
        html.append("body { font-family: monospace; margin: 20px; }")
        html.append("table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }")
        html.append("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
        html.append("th { background-color: #4CAF50; color: white; }")
        html.append(".expected { background-color: #e3f2fd; }")
        html.append(".actual { background-color: #fff3e0; }")
        html.append(".diff { background-color: #ffebee; font-weight: bold; }")
        html.append(".match { background-color: #e8f5e9; }")
        html.append(".header { font-size: 24px; font-weight: bold; margin-bottom: 20px; }")
        html.append("</style>")
        html.append("</head>")
        html.append("<body>")
        html.append("<div class='header'>Packet Validation Diff</div>")
        
        max_packets = max(len(expected_packets), len(actual_packets))
        
        for i in range(max_packets):
            html.append(f"<h3>Packet {i}</h3>")
            html.append("<table>")
            html.append("<tr><th>Field</th><th>Expected</th><th>Actual</th><th>Status</th></tr>")
            
            if i < len(expected_packets) and i < len(actual_packets):
                expected = expected_packets[i]
                actual = actual_packets[i]
                
                # Compare fields
                fields = ['ttl', 'sequence_num', 'checksum_valid', 'payload_length', 'flags']
                
                for field in fields:
                    expected_val = expected.get(field, 'N/A')
                    
                    if field == 'ttl':
                        actual_val = actual.ttl
                    elif field == 'sequence_num':
                        actual_val = actual.sequence_num
                    elif field == 'checksum_valid':
                        actual_val = actual.checksum_valid
                    elif field == 'payload_length':
                        actual_val = actual.payload_length
                    elif field == 'flags':
                        actual_val = ', '.join(actual.flags)
                    else:
                        actual_val = 'N/A'
                    
                    match = str(expected_val) == str(actual_val)
                    status_class = 'match' if match else 'diff'
                    status_text = '✓' if match else '❌'
                    
                    html.append(f"<tr class='{status_class}'>")
                    html.append(f"<td>{field}</td>")
                    html.append(f"<td class='expected'>{expected_val}</td>")
                    html.append(f"<td class='actual'>{actual_val}</td>")
                    html.append(f"<td>{status_text}</td>")
                    html.append("</tr>")
            
            elif i < len(expected_packets):
                html.append("<tr class='diff'>")
                html.append("<td colspan='4'>Expected packet but not found in actual</td>")
                html.append("</tr>")
            else:
                html.append("<tr class='diff'>")
                html.append("<td colspan='4'>Unexpected packet in actual</td>")
                html.append("</tr>")
            
            html.append("</table>")
        
        html.append("</body>")
        html.append("</html>")
        
        return "\n".join(html)
    
    def export_diff(self, diff: str, output_file: str):
        """
        Export visual diff to file.
        
        Args:
            diff: Visual diff string
            output_file: Output file path
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(diff)
            
            if self.debug_mode:
                print(f"Diff exported to: {output_file}")
        
        except Exception as e:
            if self.debug_mode:
                print(f"Error exporting diff: {e}")


# Convenience functions for common use cases

def validate_pcap(attack_name: str, params: Dict[str, Any], pcap_file: str,
                 debug: bool = False) -> ValidationResult:
    """
    Convenience function to validate a PCAP file.
    
    Args:
        attack_name: Name of attack
        params: Attack parameters
        pcap_file: Path to PCAP file
        debug: Enable debug mode
    
    Returns:
        ValidationResult
    """
    validator = PacketValidator(debug_mode=debug)
    return validator.validate_attack(attack_name, params, pcap_file)


def generate_diff_report(expected: List[Dict[str, Any]], actual: List[PacketData],
                        output_file: str, format: str = 'html') -> str:
    """
    Generate and export diff report.
    
    Args:
        expected: Expected packet specifications
        actual: Actual parsed packets
        output_file: Output file path
        format: Output format ('text' or 'html')
    
    Returns:
        Diff string
    """
    validator = PacketValidator()
    diff = validator.generate_visual_diff(expected, actual, format)
    validator.export_diff(diff, output_file)
    return diff
