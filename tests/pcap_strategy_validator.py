"""
PCAP Strategy Validator

This module provides the PCAPStrategyValidator class, which is responsible for
analyzing PCAP files to validate whether specific DPI bypass strategies were
correctly applied. It checks for patterns like packet splitting, bad checksums,
and SNI manipulation.

This validator is a key component of the integrated analysis and validation
system, providing concrete evidence of strategy execution from network traffic.

Requirements: 5.3, 5.4, 5.5
"""

import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

# Import scapy with graceful failure handling
try:
    from scapy.all import rdpcap, TCP, IP, Raw
    from scapy.packet import Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = object  # Dummy for type hinting

# Setup logger
logger = logging.getLogger(__name__)


# --- Data Classes for Results ---

@dataclass
class StrategyValidationResult:
    """Result of validating a single DPI bypass strategy against a PCAP."""
    strategy_name: str
    validation_passed: bool
    confidence_score: float = 0.0
    expected_behavior: str = ""
    observed_behavior: str = ""
    evidence: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)


@dataclass
class PCAPValidationResult:
    """Overall result of validating a PCAP file against multiple strategies."""
    pcap_file: str
    strategy_validations: List[StrategyValidationResult] = field(default_factory=list)
    checksum_analysis: Dict[str, int] = field(default_factory=dict)
    packet_size_distribution: Dict[str, int] = field(default_factory=dict)
    total_packets: int = 0
    tcp_packets: int = 0


# --- Main Validator Class ---

class PCAPStrategyValidator:
    """
    Validates PCAP files to confirm that DPI bypass strategies were applied correctly.

    This class analyzes packet captures to detect patterns characteristic of specific
    bypass strategies, such as packet splitting, bad checksums, and SNI manipulation.
    """

    def __init__(self):
        """Initialize the validator and strategy mapping."""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for PCAPStrategyValidator. Please install it.")

        self.logger = logger
        self.validators = {
            "split_3": self._validate_split_3,
            "split_10": self._validate_split_10,
            "split_sni": self._validate_split_sni,
            "badsum": self._validate_badsum,
        }

    def validate_pcap_file(self, pcap_file: str, expected_strategies: List[str]) -> PCAPValidationResult:
        """
        Validate a PCAP file against a list of expected strategies.

        Args:
            pcap_file: Path to the PCAP file.
            expected_strategies: A list of strategy names to validate.

        Returns:
            A PCAPValidationResult object with detailed analysis.
        """
        self.logger.info(f"Validating PCAP file '{pcap_file}' for strategies: {expected_strategies}")

        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            self.logger.error(f"Failed to read PCAP file '{pcap_file}': {e}")
            return PCAPValidationResult(pcap_file=pcap_file)

        overall_result = PCAPValidationResult(pcap_file=pcap_file, total_packets=len(packets))

        # Filter for relevant TCP packets (e.g., outbound to port 443)
        tcp_packets = [p for p in packets if p.haslayer(TCP) and p.haslayer(IP) and p[TCP].dport == 443]
        overall_result.tcp_packets = len(tcp_packets)

        # Perform general analysis
        overall_result.checksum_analysis = self._analyze_checksums(tcp_packets)
        overall_result.packet_size_distribution = self._analyze_packet_sizes(tcp_packets)

        # Validate each expected strategy
        for strategy_name in expected_strategies:
            validator_func = self.validators.get(strategy_name)
            if validator_func:
                self.logger.debug(f"Running validator for strategy: {strategy_name}")
                strategy_result = validator_func(tcp_packets)
                overall_result.strategy_validations.append(strategy_result)
            else:
                self.logger.warning(f"No validator found for strategy: {strategy_name}")
                overall_result.strategy_validations.append(
                    StrategyValidationResult(
                        strategy_name=strategy_name,
                        validation_passed=False,
                        confidence_score=0.0,
                        issues=[f"Validator for '{strategy_name}' is not implemented."]
                    )
                )

        return overall_result

    # --- General Analysis Methods ---

    def _analyze_checksums(self, packets: List[Packet]) -> Dict[str, int]:
        """Analyze TCP checksums for all packets."""
        analysis = {"valid": 0, "invalid": 0, "zero": 0, "total_tcp": len(packets)}
        for pkt in packets:
            if self._is_checksum_valid(pkt):
                analysis["valid"] += 1
            else:
                analysis["invalid"] += 1
                if pkt[TCP].chksum == 0:
                    analysis["zero"] += 1
        return analysis

    def _analyze_packet_sizes(self, packets: List[Packet]) -> Dict[str, int]:
        """Analyze distribution of packet payload sizes."""
        distribution = {"small": 0, "medium": 0, "large": 0, "empty": 0}
        for pkt in packets:
            payload_size = len(pkt[TCP].payload)
            if payload_size == 0:
                distribution["empty"] += 1
            elif payload_size <= 64:
                distribution["small"] += 1
            elif payload_size <= 1000:
                distribution["medium"] += 1
            else:
                distribution["large"] += 1
        return distribution

    # --- Specific Strategy Validators ---

    def _validate_split_3(self, packets: List[Packet]) -> StrategyValidationResult:
        """Validator for 'split_3' strategy."""
        return self._validate_split_position(packets, 3, "split_3")

    def _validate_split_10(self, packets: List[Packet]) -> StrategyValidationResult:
        """Validator for 'split_10' strategy."""
        return self._validate_split_position(packets, 10, "split_10")

    def _validate_split_position(self, packets: List[Packet], expected_pos: int, strategy_name: str) -> StrategyValidationResult:
        """Generic validator for split position strategies."""
        result = StrategyValidationResult(
            strategy_name=strategy_name,
            validation_passed=False,
            expected_behavior=f"First data packet payload size should be {expected_pos} bytes."
        )

        flows = self._group_packets_by_flow(packets)
        found_evidence = False

        for flow_key, flow_packets in flows.items():
            data_packets = [p for p in flow_packets if p.haslayer(Raw) and len(p[Raw].load) > 0]
            if not data_packets:
                continue

            first_data_pkt = data_packets[0]
            payload_size = len(first_data_pkt[Raw].load)

            if payload_size == expected_pos:
                result.validation_passed = True
                result.confidence_score = 0.9
                result.observed_behavior = f"Detected first data packet with payload size {payload_size}."
                result.evidence.append(f"Flow {flow_key}: Packet with index in original pcap (approx) #{packets.index(first_data_pkt)} has payload size {payload_size}.")
                found_evidence = True
                break  # Found it in one flow, that's enough

        if not found_evidence:
            result.issues.append(f"No flow found with a first data packet of size {expected_pos}.")
            result.observed_behavior = "No packets matching the split position were found."
            result.confidence_score = 0.1

        return result

    def _validate_split_sni(self, packets: List[Packet]) -> StrategyValidationResult:
        """Validator for 'split_sni' strategy."""
        result = StrategyValidationResult(
            strategy_name="split_sni",
            validation_passed=False,
            expected_behavior="A small packet split before or at the SNI position in ClientHello."
        )

        flows = self._group_packets_by_flow(packets)
        found_evidence = False

        for flow_key, flow_packets in flows.items():
            # Look for a ClientHello split across two packets
            for i in range(len(flow_packets) - 1):
                p1 = flow_packets[i]
                p2 = flow_packets[i+1]

                # Check for two consecutive data packets in the same flow
                if not (p1.haslayer(Raw) and p2.haslayer(Raw)):
                    continue

                # Heuristic: first packet is small, second follows closely
                if 20 < len(p1[Raw].load) < 100 and p2[TCP].seq == p1[TCP].seq + len(p1[Raw].load):
                    # Try to parse SNI from the reassembled payload
                    reassembled_payload = p1[Raw].load + p2[Raw].load
                    if self._is_tls_clienthello(reassembled_payload):
                        result.validation_passed = True
                        result.confidence_score = 0.75
                        result.observed_behavior = f"Detected a likely ClientHello split at size {len(p1[Raw].load)}."
                        result.evidence.append(f"Flow {flow_key}: Packets (approx indices #{packets.index(p1)}, #{packets.index(p2)}) form a ClientHello.")
                        found_evidence = True
                        break
            if found_evidence:
                break

        if not found_evidence:
            result.issues.append("No clear evidence of SNI splitting found.")
            result.observed_behavior = "No split ClientHello packets detected."
            result.confidence_score = 0.2

        return result

    def _validate_badsum(self, packets: List[Packet]) -> StrategyValidationResult:
        """Validator for 'badsum' strategy."""
        result = StrategyValidationResult(
            strategy_name="badsum",
            validation_passed=False,
            expected_behavior="At least one TCP packet with an invalid checksum."
        )

        invalid_packets = []
        for i, pkt in enumerate(packets):
            if not self._is_checksum_valid(pkt):
                invalid_packets.append(i)

        if invalid_packets:
            result.validation_passed = True
            result.confidence_score = 0.95
            result.observed_behavior = f"Found {len(invalid_packets)} packet(s) with invalid checksums."
            result.evidence.append(f"Packet indices (within filtered TCP list) with bad checksums: {invalid_packets[:5]}")
        else:
            result.issues.append("No packets with invalid TCP checksums were found.")
            result.observed_behavior = "All TCP checksums appear to be valid."
            result.confidence_score = 0.05

        return result

    # --- Helper Methods ---

    def _group_packets_by_flow(self, packets: List[Packet]) -> Dict[str, List[Packet]]:
        """Group packets into TCP flows."""
        flows = {}
        for pkt in packets:
            if IP in pkt and TCP in pkt:
                flow_key = f"{pkt[IP].src}:{pkt[TCP].sport}-{pkt[IP].dst}:{pkt[TCP].dport}"
                if flow_key not in flows:
                    flows[flow_key] = []
                flows[flow_key].append(pkt)
        return flows

    def _is_checksum_valid(self, pkt: Packet) -> bool:
        """Verify the TCP checksum of a Scapy packet."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return True  # Not a TCP/IP packet, can't validate

        original_chksum = pkt[TCP].chksum
        del pkt[TCP].chksum  # Scapy will recalculate it on the fly

        # Create a copy to avoid modifying the original packet list
        pkt_copy = pkt.copy()
        recalculated_chksum = pkt_copy[TCP].chksum

        # Restore original checksum to the packet in the list
        pkt[TCP].chksum = original_chksum

        return original_chksum == recalculated_chksum

    def _is_tls_clienthello(self, payload: bytes) -> bool:
        """Check if a payload is a TLS ClientHello message."""
        # Basic checks: Handshake type (22), version, ClientHello type (1)
        return (
            len(payload) > 9 and
            payload[0] == 0x16 and  # Content Type: Handshake
            payload[1] == 0x03 and  # Version major
            payload[5] == 0x01      # Handshake Type: ClientHello
        )