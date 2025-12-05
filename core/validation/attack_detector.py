"""
AttackDetector - Detection of DPI bypass attacks in network traffic.

This module implements attack detection algorithms for:
- Fake packets (low TTL)
- Split/multisplit (fragmentation)
- Disorder (out-of-order packets)
- Badsum (corrupted TCP checksums)

Requirements: 3.3, 3.4, 3.5, 7.3
"""

import logging
from dataclasses import dataclass, field
from typing import Any, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DetectedAttacks:
    """Detected attacks in network traffic."""
    fake: bool = False
    fake_count: int = 0
    fake_ttl: float = 0.0
    
    split: bool = False
    fragment_count: int = 0
    split_near_sni: bool = False
    split_positions: List[int] = field(default_factory=list)
    
    disorder: bool = False
    disorder_type: str = ""
    
    badsum: bool = False
    badseq: bool = False


class AttackDetector:
    """
    Detector for DPI bypass attacks in network traffic.
    
    Implements detection algorithms for:
    - Fake packets with low TTL
    - Split/multisplit fragmentation
    - Disorder (out-of-order or overlapping packets)
    - Badsum (corrupted TCP checksums)
    
    Requirements: 3.3, 3.4, 3.5, 7.3
    """
    
    def __init__(self):
        """Initialize attack detector."""
        pass
    
    def detect_attacks(
        self,
        packets: List[Any],
        sni_offset: Optional[int] = None
    ) -> DetectedAttacks:
        """
        Detect all attacks in packet list.
        
        Args:
            packets: List of packets with TCP and Raw layers
            sni_offset: Optional SNI offset for split position validation
            
        Returns:
            DetectedAttacks with all detected attack types
        """
        attacks = DetectedAttacks()
        
        if not packets:
            return attacks
        
        # Detect each attack type
        self._detect_fake(packets, attacks)
        self._detect_split(packets, attacks, sni_offset)
        self._detect_disorder(packets, attacks)
        self._detect_badsum(packets, attacks)
        
        return attacks
    
    def detect_fake(self, packets: List[Any]) -> DetectedAttacks:
        """
        Detect fake packets (low TTL).
        
        Fake packets are characterized by:
        - TTL <= 3 (will be dropped by intermediate routers)
        - Small payload size (typically)
        
        Args:
            packets: List of packets with IP layer
            
        Returns:
            DetectedAttacks with fake detection results
        """
        attacks = DetectedAttacks()
        self._detect_fake(packets, attacks)
        return attacks
    
    def detect_split(
        self,
        packets: List[Any],
        sni_offset: Optional[int] = None
    ) -> DetectedAttacks:
        """
        Detect split/multisplit attacks.
        
        Split attacks fragment the ClientHello into multiple TCP packets.
        Multisplit creates more than 2 fragments.
        
        Args:
            packets: List of packets with TCP and Raw layers
            sni_offset: Optional SNI offset to check if split is near SNI
            
        Returns:
            DetectedAttacks with split detection results
        """
        attacks = DetectedAttacks()
        self._detect_split(packets, attacks, sni_offset)
        return attacks
    
    def detect_disorder(self, packets: List[Any]) -> DetectedAttacks:
        """
        Detect disorder attacks.
        
        Disorder attacks send packets out-of-order or with overlapping
        sequence numbers to confuse DPI systems.
        
        Args:
            packets: List of packets with TCP layer
            
        Returns:
            DetectedAttacks with disorder detection results
        """
        attacks = DetectedAttacks()
        self._detect_disorder(packets, attacks)
        return attacks
    
    def detect_badsum(self, packets: List[Any]) -> DetectedAttacks:
        """
        Detect badsum attacks.
        
        Badsum attacks use incorrect TCP checksums to fool DPI systems
        that don't verify checksums.
        
        Args:
            packets: List of packets with TCP layer
            
        Returns:
            DetectedAttacks with badsum detection results
        """
        attacks = DetectedAttacks()
        self._detect_badsum(packets, attacks)
        return attacks
    
    # ========================================================================
    # Internal detection methods
    # ========================================================================
    
    def _detect_fake(self, packets: List[Any], attacks: DetectedAttacks):
        """Internal: Detect fake packets by TTL."""
        try:
            from scapy.all import IP
        except ImportError:
            logger.warning("Scapy not available for fake detection")
            return
        
        fake_ttl_values = []
        for pkt in packets:
            if pkt.haslayer(IP):
                ttl = pkt[IP].ttl
                if ttl <= 3:
                    attacks.fake = True
                    attacks.fake_count += 1
                    fake_ttl_values.append(ttl)
        
        # Calculate average TTL of fake packets only
        if fake_ttl_values:
            attacks.fake_ttl = sum(fake_ttl_values) / len(fake_ttl_values)
    
    def _detect_split(
        self,
        packets: List[Any],
        attacks: DetectedAttacks,
        sni_offset: Optional[int]
    ):
        """Internal: Detect split/multisplit by fragment count."""
        try:
            from scapy.all import Raw, IP
        except ImportError:
            logger.warning("Scapy not available for split detection")
            return
        
        # Count all packets as fragments (including fake packets)
        # This allows detection of combined fake+split attacks
        attacks.fragment_count = len(packets)
        if attacks.fragment_count > 1:
            attacks.split = True
            
            # Calculate split positions (cumulative payload lengths)
            # For position calculation, we use all packets
            cumulative = 0
            for i, pkt in enumerate(packets[:-1]):
                if pkt.haslayer(Raw):
                    payload_len = len(bytes(pkt[Raw].load))
                    cumulative += payload_len
                    attacks.split_positions.append(cumulative)
            
            # Check if split is near SNI (within ±8 bytes)
            if sni_offset is not None:
                for pos in attacks.split_positions:
                    if abs(pos - sni_offset) <= 8:
                        attacks.split_near_sni = True
                        break
    
    def _detect_disorder(self, packets: List[Any], attacks: DetectedAttacks):
        """Internal: Detect disorder by sequence number analysis."""
        try:
            from scapy.all import TCP, Raw
        except ImportError:
            logger.warning("Scapy not available for disorder detection")
            return
        
        if len(packets) <= 1:
            return
        
        # Get sequence numbers
        seq_numbers = []
        for pkt in packets:
            if pkt.haslayer(TCP):
                seq_numbers.append(pkt[TCP].seq)
        
        if not seq_numbers:
            return
        
        # Check if packets are out of order
        sorted_seq = sorted(seq_numbers)
        if seq_numbers != sorted_seq:
            attacks.disorder = True
            attacks.disorder_type = "out-of-order"
        
        # Check for overlapping packets
        for i in range(len(packets) - 1):
            pkt1 = packets[i]
            pkt2 = packets[i + 1]
            
            if not (pkt1.haslayer(TCP) and pkt1.haslayer(Raw)):
                continue
            if not (pkt2.haslayer(TCP) and pkt2.haslayer(Raw)):
                continue
            
            seq1 = pkt1[TCP].seq
            len1 = len(bytes(pkt1[Raw].load))
            seq2 = pkt2[TCP].seq
            
            # If next packet starts before current packet ends, it's overlapping
            if seq2 < seq1 + len1:
                attacks.disorder = True
                attacks.disorder_type = "overlap"
                break
    
    def _detect_badsum(self, packets: List[Any], attacks: DetectedAttacks):
        """Internal: Detect badsum by checksum verification."""
        try:
            from scapy.all import TCP
        except ImportError:
            logger.warning("Scapy not available for badsum detection")
            return
        
        for pkt in packets:
            if not pkt.haslayer(TCP):
                continue
            
            stored_chksum = pkt[TCP].chksum
            if stored_chksum is None:
                continue
            
            # Calculate correct checksum
            calculated = self._calculate_tcp_checksum(pkt)
            if calculated is not None and stored_chksum != calculated:
                attacks.badsum = True
                break
    
    def _calculate_tcp_checksum(self, pkt: Any) -> Optional[int]:
        """Calculate correct TCP checksum for packet."""
        try:
            from scapy.all import IP, TCP
            import copy
            
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                return None
            
            # Create copy and recalculate checksum
            pkt_copy = copy.deepcopy(pkt)
            del pkt_copy[TCP].chksum
            pkt_copy = pkt_copy.__class__(bytes(pkt_copy))
            
            return pkt_copy[TCP].chksum
        except Exception as e:
            logger.debug(f"Failed to calculate checksum: {e}")
            return None
