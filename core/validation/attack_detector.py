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
                # Changed threshold from 3 to 5 to match analyze_raw_pcap.py
                if ttl <= 5:
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
        """
        Internal: Detect split/multisplit by fragment count.
        
        IMPORTANT: Only counts REAL packets (TTL > 5) within ClientHello sequence range.
        This matches analyze_raw_pcap.py logic exactly:
        1. Find ClientHello packet
        2. Get its sequence range [seq, seq+len)
        3. Count only real packets in that range
        4. Exclude fake packets, retransmissions, and post-ClientHello data
        """
        try:
            from scapy.all import Raw, IP, TCP
        except ImportError:
            logger.warning("Scapy not available for split detection")
            return
        
        # Step 1: Find ClientHello packet to determine sequence range
        clienthello_seq = None
        clienthello_len = None
        
        for pkt in packets:
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                continue
            
            payload = bytes(pkt[Raw].load)
            
            # Check if this is TLS ClientHello (starts with 0x16 0x03)
            if len(payload) >= 6 and payload[0] == 0x16 and payload[1] == 0x03:
                # This looks like TLS handshake, likely ClientHello
                clienthello_seq = pkt[TCP].seq
                clienthello_len = len(payload)
                logger.debug(
                    f"Found ClientHello: seq={clienthello_seq}, len={clienthello_len}"
                )
                break
        
        if clienthello_seq is None:
            logger.debug("No ClientHello found, skipping split detection")
            return
        
        # Step 2: Calculate ClientHello sequence range
        clienthello_end_seq = clienthello_seq + clienthello_len
        
        # Step 3: Filter for REAL packets (TTL > 5) within ClientHello sequence range
        real_packets = []
        for pkt in packets:
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                continue
            
            # Skip fake packets (TTL <= 5)
            if pkt[IP].ttl <= 5:
                continue
            
            # Check payload
            if not pkt.haslayer(Raw) or len(bytes(pkt[Raw].load)) == 0:
                continue
            
            # Only include packets within ClientHello sequence range
            seq = pkt[TCP].seq
            if seq >= clienthello_seq and seq < clienthello_end_seq:
                real_packets.append(pkt)
        
        # Sort by sequence number to handle out-of-order packets
        real_packets.sort(key=lambda p: p[TCP].seq)
        
        # Update fragment count based on REAL packets in ClientHello range only
        attacks.fragment_count = len(real_packets)
        if attacks.fragment_count > 1:
            attacks.split = True
        
        logger.debug(
            f"Split detection: {attacks.fragment_count} real fragments "
            f"in ClientHello range [{clienthello_seq}, {clienthello_end_seq})"
        )
        
        # Calculate split positions based on sequence numbers
        if not real_packets:
            return
        
        base_seq = real_packets[0][TCP].seq
        
        # Collect split positions (end of each fragment relative to base)
        positions = set()
        for pkt in real_packets[:-1]:  # Exclude last packet end
            seq = pkt[TCP].seq
            length = len(bytes(pkt[Raw].load))
            relative_end = (seq - base_seq) + length
            if relative_end > 0:
                positions.add(relative_end)
        
        attacks.split_positions = sorted(list(positions))
        
        # Check if split is near SNI (increased tolerance to ±10 bytes)
        if sni_offset is not None:
            for pos in attacks.split_positions:
                if abs(pos - sni_offset) <= 10:
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
