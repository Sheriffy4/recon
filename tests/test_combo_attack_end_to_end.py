"""
Integration test for combo attack end-to-end workflow.

This test verifies the complete workflow:
1. Create strategy with fake+multisplit+disorder
2. Apply via UnifiedAttackDispatcher
3. Capture result packets
4. Validate all three attacks detected

Requirements: 2.1, 2.5
Feature: attack-application-parity, Task 18
"""

import logging
import pytest
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Any

# Add recon directory to path
recon_dir = Path(__file__).parent.parent
sys.path.insert(0, str(recon_dir))

from core.strategy.combo_builder import ComboAttackBuilder, AttackRecipe
from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
from core.validation.attack_detector import AttackDetector, DetectedAttacks

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MockPacket:
    """Mock packet for simulating network packets without Scapy."""
    
    def __init__(
        self,
        payload: bytes,
        src_ip: str = "192.168.1.1",
        dst_ip: str = "8.8.8.8",
        src_port: int = 12345,
        dst_port: int = 443,
        seq: int = 1000,
        ttl: int = 64
    ):
        self.payload = payload
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ttl = ttl
        self.tcp_flags = {"PSH": 1, "ACK": 1}
        
    def __bytes__(self):
        return self.payload
    
    def __repr__(self):
        return (
            f"MockPacket(seq={self.seq}, ttl={self.ttl}, "
            f"payload_len={len(self.payload)})"
        )


def create_clienthello_payload() -> bytes:
    """
    Create a realistic TLS ClientHello payload for testing.
    
    Returns:
        Bytes representing a TLS ClientHello packet
    """
    # TLS Record Header
    # Content Type: Handshake (0x16)
    # Version: TLS 1.0 (0x0301)
    # Length: will be calculated
    
    # Handshake Header
    # Type: ClientHello (0x01)
    # Length: will be calculated
    
    # ClientHello content
    client_version = b'\x03\x03'  # TLS 1.2
    random = b'\x00' * 32  # 32 bytes of random data
    session_id_len = b'\x00'  # No session ID
    cipher_suites_len = b'\x00\x02'  # 2 bytes
    cipher_suites = b'\x00\x2f'  # TLS_RSA_WITH_AES_128_CBC_SHA
    compression_len = b'\x01'  # 1 byte
    compression = b'\x00'  # No compression
    
    # Extensions
    # SNI extension
    sni_name = b'example.com'
    sni_name_len = len(sni_name).to_bytes(2, 'big')
    sni_list_len = (len(sni_name) + 3).to_bytes(2, 'big')
    sni_ext_len = (len(sni_name) + 5).to_bytes(2, 'big')
    
    sni_extension = (
        b'\x00\x00' +  # Extension type: SNI
        sni_ext_len +  # Extension length
        sni_list_len +  # Server name list length
        b'\x00' +  # Server name type: hostname
        sni_name_len +  # Server name length
        sni_name  # Server name
    )
    
    extensions_len = len(sni_extension).to_bytes(2, 'big')
    
    # Build ClientHello
    clienthello_content = (
        client_version +
        random +
        session_id_len +
        cipher_suites_len +
        cipher_suites +
        compression_len +
        compression +
        extensions_len +
        sni_extension
    )
    
    # Handshake header
    hs_len = len(clienthello_content).to_bytes(3, 'big')
    handshake = b'\x01' + hs_len + clienthello_content
    
    # TLS record header
    record_len = len(handshake).to_bytes(2, 'big')
    record = b'\x16\x03\x01' + record_len + handshake
    
    return record


def segments_to_mock_packets(
    segments: List[Tuple[bytes, int, Dict[str, Any]]],
    base_seq: int = 1000
) -> List[MockPacket]:
    """
    Convert dispatcher segments to mock packets for analysis.
    
    The sequence number for each packet is determined by:
    1. If 'seq' is in options, use that
    2. Otherwise, use base_seq + offset (from the segment tuple)
    
    This ensures that when disorder is applied, the sequence numbers
    reflect the original order, not the reordered position.
    
    Args:
        segments: List of (data, offset, options) tuples from dispatcher
        base_seq: Base sequence number
        
    Returns:
        List of MockPacket objects
    """
    packets = []
    
    for data, offset, options in segments:
        ttl = options.get('ttl', 64)
        # Use offset to determine sequence number if not explicitly set
        # This preserves the original sequence even after disorder
        seq = options.get('seq', base_seq + offset)
        
        pkt = MockPacket(
            payload=data,
            seq=seq,
            ttl=ttl
        )
        packets.append(pkt)
    
    return packets


def analyze_mock_packets(packets: List[MockPacket]) -> Dict[str, Any]:
    """
    Analyze mock packets to detect attacks.
    
    Args:
        packets: List of MockPacket objects
        
    Returns:
        Dictionary with detected attack characteristics
    """
    analysis = {
        'packet_count': len(packets),
        'has_fake': False,
        'fake_count': 0,
        'has_split': False,
        'fragment_count': 0,
        'has_disorder': False,
        'ttl_values': [],
        'payload_sizes': [],
        'sequence_numbers': []
    }
    
    # Separate fake packets from real packets
    fake_packets = []
    real_packets = []
    
    for pkt in packets:
        # Check for fake packets (low TTL)
        if pkt.ttl <= 3:
            analysis['has_fake'] = True
            analysis['fake_count'] += 1
            fake_packets.append(pkt)
        else:
            real_packets.append(pkt)
        
        analysis['ttl_values'].append(pkt.ttl)
        analysis['payload_sizes'].append(len(pkt.payload))
        analysis['sequence_numbers'].append(pkt.seq)
    
    # Check for split (multiple real packets with payload)
    # We only count real packets (not fake) for split detection
    payload_packets = [p for p in real_packets if len(p.payload) > 0]
    if len(payload_packets) > 1:
        analysis['has_split'] = True
        analysis['fragment_count'] = len(payload_packets)
    
    # Check for disorder (real packets not in sequence order)
    # We only check real packets for disorder
    if len(real_packets) > 1:
        real_seqs = [p.seq for p in real_packets]
        if real_seqs != sorted(real_seqs):
            analysis['has_disorder'] = True
            logger.debug(f"Disorder detected: sequences {real_seqs} != sorted {sorted(real_seqs)}")
        else:
            logger.debug(f"No disorder: sequences {real_seqs} == sorted {sorted(real_seqs)}")
    
    return analysis


class TestComboAttackEndToEnd:
    """
    End-to-end integration test for combo attacks.
    
    Validates Requirements 2.1, 2.5:
    - AttackDispatcher can execute combo recipes
    - All valid combinations are supported
    """
    
    def test_fake_multisplit_disorder_combo(self):
        """
        Test complete workflow with fake+multisplit+disorder combo.
        
        This is the main end-to-end test that validates:
        1. Strategy creation with combo attacks
        2. Recipe building via ComboAttackBuilder
        3. Attack application via UnifiedAttackDispatcher
        4. Detection of all three attacks in result
        
        Requirements: 2.1, 2.5
        """
        logger.info("=" * 70)
        logger.info("TEST: Fake + Multisplit + Disorder Combo (End-to-End)")
        logger.info("=" * 70)
        
        # Step 1: Create strategy with fake+multisplit+disorder
        attacks = ['fake', 'multisplit', 'disorder']
        params = {
            'ttl': 2,  # Low TTL for fake packets
            'fooling': 'badsum',
            'split_pos': 3,
            'split_count': 3,  # Split into 3 fragments
            'disorder_method': 'reverse'  # Reverse packet order
        }
        
        logger.info(f"Step 1: Created strategy with attacks: {attacks}")
        logger.info(f"        Parameters: {params}")
        
        # Step 2: Build recipe using ComboAttackBuilder
        builder = ComboAttackBuilder()
        recipe = builder.build_recipe(attacks, params)
        
        assert recipe is not None, "Recipe should not be None"
        assert len(recipe.steps) == 3, f"Expected 3 steps, got {len(recipe.steps)}"
        
        logger.info(f"Step 2: Built recipe with {len(recipe.steps)} steps")
        for i, step in enumerate(recipe.steps):
            logger.info(f"        Step {i+1}: {step.attack_type} (order={step.order})")
        
        # Verify attack order: fake → multisplit → disorder
        assert recipe.steps[0].attack_type == 'fake', "First step should be fake"
        assert recipe.steps[1].attack_type == 'multisplit', "Second step should be multisplit"
        assert recipe.steps[2].attack_type == 'disorder', "Third step should be disorder"
        
        # Step 3: Create test payload (ClientHello)
        payload = create_clienthello_payload()
        logger.info(f"Step 3: Created ClientHello payload ({len(payload)} bytes)")
        
        # Step 4: Apply recipe using UnifiedAttackDispatcher
        dispatcher = UnifiedAttackDispatcher()
        
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        assert segments is not None, "Segments should not be None"
        assert len(segments) > 0, "Should generate at least one segment"
        
        logger.info(f"Step 4: Applied recipe, generated {len(segments)} segments")
        
        # Step 5: Convert segments to mock packets for analysis
        packets = segments_to_mock_packets(segments)
        
        logger.info(f"Step 5: Converted to {len(packets)} mock packets")
        for i, pkt in enumerate(packets):
            logger.info(f"        Packet {i+1}: {pkt}")
        
        # Step 6: Analyze packets to detect attacks
        analysis = analyze_mock_packets(packets)
        
        logger.info("Step 6: Attack detection results:")
        logger.info(f"        Fake detected: {analysis['has_fake']} (count={analysis['fake_count']})")
        logger.info(f"        Split detected: {analysis['has_split']} (fragments={analysis['fragment_count']})")
        logger.info(f"        Disorder detected: {analysis['has_disorder']}")
        
        # Step 7: Validate all three attacks are detected
        assert analysis['has_fake'], "Fake attack should be detected"
        assert analysis['fake_count'] > 0, "Should have at least one fake packet"
        
        assert analysis['has_split'], "Split attack should be detected"
        assert analysis['fragment_count'] >= 3, f"Should have at least 3 fragments, got {analysis['fragment_count']}"
        
        assert analysis['has_disorder'], "Disorder attack should be detected"
        
        logger.info("✅ All three attacks successfully detected!")
        logger.info("=" * 70)
    
    def test_fake_split_combo(self):
        """
        Test fake+split combo (simpler case).
        
        Requirements: 2.1, 2.5
        """
        logger.info("TEST: Fake + Split Combo")
        
        # Create strategy
        attacks = ['fake', 'split']
        params = {
            'ttl': 1,
            'fooling': 'badseq',
            'split_pos': 2
        }
        
        # Build and apply recipe
        builder = ComboAttackBuilder()
        recipe = builder.build_recipe(attacks, params)
        
        dispatcher = UnifiedAttackDispatcher()
        payload = create_clienthello_payload()
        
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        packets = segments_to_mock_packets(segments)
        analysis = analyze_mock_packets(packets)
        
        # Validate
        assert analysis['has_fake'], "Fake attack should be detected"
        assert analysis['has_split'], "Split attack should be detected"
        
        logger.info("✅ Fake + Split combo test passed")
    
    def test_split_disorder_combo(self):
        """
        Test split+disorder combo (no fake).
        
        Requirements: 2.1, 2.5
        """
        logger.info("TEST: Split + Disorder Combo")
        
        # Create strategy
        attacks = ['split', 'disorder']
        params = {
            'split_pos': 5,
            'disorder_method': 'reverse'
        }
        
        # Build and apply recipe
        builder = ComboAttackBuilder()
        recipe = builder.build_recipe(attacks, params)
        
        dispatcher = UnifiedAttackDispatcher()
        payload = create_clienthello_payload()
        
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        packets = segments_to_mock_packets(segments)
        analysis = analyze_mock_packets(packets)
        
        # Validate
        assert analysis['has_split'], "Split attack should be detected"
        assert analysis['has_disorder'], "Disorder attack should be detected"
        assert not analysis['has_fake'], "Fake attack should NOT be detected"
        
        logger.info("✅ Split + Disorder combo test passed")
    
    def test_single_attack_fake(self):
        """
        Test single fake attack (baseline).
        
        Requirements: 2.1
        """
        logger.info("TEST: Single Fake Attack")
        
        # Create strategy
        attacks = ['fake']
        params = {
            'ttl': 3,
            'fooling': 'badsum'
        }
        
        # Build and apply recipe
        builder = ComboAttackBuilder()
        recipe = builder.build_recipe(attacks, params)
        
        dispatcher = UnifiedAttackDispatcher()
        payload = create_clienthello_payload()
        
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        packets = segments_to_mock_packets(segments)
        analysis = analyze_mock_packets(packets)
        
        # Validate
        assert analysis['has_fake'], "Fake attack should be detected"
        assert not analysis['has_split'], "Split attack should NOT be detected"
        assert not analysis['has_disorder'], "Disorder attack should NOT be detected"
        
        logger.info("✅ Single fake attack test passed")
    
    def test_attack_order_enforcement(self):
        """
        Test that attacks are applied in correct order regardless of input order.
        
        Requirements: 2.1
        """
        logger.info("TEST: Attack Order Enforcement")
        
        # Provide attacks in wrong order
        attacks = ['disorder', 'fake', 'multisplit']
        params = {
            'ttl': 2,
            'split_pos': 3,
            'split_count': 2,
            'disorder_method': 'reverse'
        }
        
        # Build recipe
        builder = ComboAttackBuilder()
        recipe = builder.build_recipe(attacks, params)
        
        # Verify order is corrected: fake → multisplit → disorder
        assert recipe.steps[0].attack_type == 'fake', "First should be fake"
        assert recipe.steps[1].attack_type == 'multisplit', "Second should be multisplit"
        assert recipe.steps[2].attack_type == 'disorder', "Third should be disorder"
        
        logger.info("✅ Attack order correctly enforced")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
