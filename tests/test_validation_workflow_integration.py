"""
Integration test for validation workflow.

This test verifies the complete validation workflow:
1. Create PCAP with known attacks
2. Create corresponding domain_rules.json entry
3. Run ComplianceChecker
4. Assert 100% compliance
5. Modify PCAP to remove attack
6. Assert compliance drops and issue reported

Requirements: 3.2, 3.6, 9.1
Feature: attack-application-parity, Task 19
"""

import json
import logging
import tempfile
from pathlib import Path
from typing import List, Dict, Any
import pytest

from core.strategy.loader import Strategy
from core.validation.compliance_checker import ComplianceChecker, ComplianceReport
from core.validation.pcap_validator import PCAPValidator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_test_pcap_with_attacks(
    pcap_path: str,
    attacks: List[str],
    params: Dict[str, Any]
) -> None:
    """
    Create a test PCAP file with specified attacks applied.
    
    Args:
        pcap_path: Path where PCAP should be saved
        attacks: List of attack types to apply
        params: Attack parameters
    """
    try:
        from scapy.all import IP, TCP, Raw, wrpcap
    except ImportError:
        pytest.skip("Scapy not installed")
    
    # Create ClientHello payload
    clienthello = create_clienthello_payload()
    
    # Base packet parameters
    src_ip = "192.168.1.100"
    dst_ip = "8.8.8.8"
    src_port = 54321
    dst_port = 443
    base_seq = 1000
    base_ack = 2000
    
    packets = []
    real_packets = []  # Store real packets separately
    
    # Apply attacks based on the list
    has_fake = 'fake' in attacks or 'fakeddisorder' in attacks
    has_split = 'split' in attacks or 'multisplit' in attacks
    has_disorder = 'disorder' in attacks or 'fakeddisorder' in attacks
    
    # Generate fake packet if needed (will be added before real packets)
    fake_packet = None
    if has_fake:
        ttl = params.get('ttl', 1)
        # Create a small fake ClientHello-like packet
        fake_payload = b'\x16\x03\x01\x00\x10' + b'FAKE' * 4  # Small fake TLS record
        fake_packet = IP(src=src_ip, dst=dst_ip, ttl=ttl) / \
                    TCP(sport=src_port, dport=dst_port, seq=base_seq, ack=base_ack, flags='PA') / \
                    Raw(load=fake_payload)
        logger.debug(f"Created fake packet with TTL={ttl}")
    
    # Split payload if needed (creates real packets)
    if has_split:
        split_count = params.get('split_count', 2)
        split_pos = params.get('split_pos', 2)
        
        # Calculate split positions
        if isinstance(split_pos, str) and split_pos == 'sni':
            # Split near SNI (around byte 50 for our test ClientHello)
            split_positions = [50]
        elif isinstance(split_pos, int):
            split_positions = [split_pos]
        else:
            split_positions = [2]
        
        # For multisplit, add more positions
        if split_count > 2:
            chunk_size = len(clienthello) // split_count
            split_positions = [chunk_size * i for i in range(1, split_count)]
        
        # Create fragments
        fragments = []
        prev_pos = 0
        for pos in split_positions:
            if pos < len(clienthello):
                fragments.append(clienthello[prev_pos:pos])
                prev_pos = pos
        fragments.append(clienthello[prev_pos:])
        
        # Create packets for each fragment
        seq = base_seq
        for i, fragment in enumerate(fragments):
            if fragment:
                pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / \
                      TCP(sport=src_port, dport=dst_port, seq=seq, ack=base_ack, flags='PA') / \
                      Raw(load=fragment)
                real_packets.append(pkt)
                seq += len(fragment)
                logger.debug(f"Created fragment {i+1}/{len(fragments)}: {len(fragment)} bytes, seq={seq-len(fragment)}")
    else:
        # Single packet with full payload
        pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=dst_port, seq=base_seq, ack=base_ack, flags='PA') / \
              Raw(load=clienthello)
        real_packets.append(pkt)
        logger.debug(f"Created single packet: {len(clienthello)} bytes")
    
    # Apply disorder if needed (only to real packets)
    if has_disorder:
        disorder_method = params.get('disorder_method', 'reverse')
        
        if disorder_method == 'reverse':
            real_packets.reverse()
            logger.debug("Applied reverse disorder to real packets")
    
    # Combine fake and real packets (fake first, then real)
    if fake_packet:
        packets.append(fake_packet)
    packets.extend(real_packets)
    
    # Write PCAP directly (Scapy will handle layer construction)
    wrpcap(pcap_path, packets)
    logger.info(f"Created PCAP with {len(packets)} packets at {pcap_path}")


def create_clienthello_payload() -> bytes:
    """
    Create a realistic TLS ClientHello payload for testing.
    
    Returns:
        Bytes representing a TLS ClientHello packet
    """
    # TLS Record Header
    client_version = b'\x03\x03'  # TLS 1.2
    random = b'\x00' * 32  # 32 bytes of random data
    session_id_len = b'\x00'  # No session ID
    cipher_suites_len = b'\x00\x02'  # 2 bytes
    cipher_suites = b'\x00\x2f'  # TLS_RSA_WITH_AES_128_CBC_SHA
    compression_len = b'\x01'  # 1 byte
    compression = b'\x00'  # No compression
    
    # Extensions - SNI extension
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


class TestValidationWorkflow:
    """
    Integration test for validation workflow.
    
    Validates Requirements 3.2, 3.6, 9.1:
    - PCAP validation against expected strategy
    - Compliance checking and scoring
    - Issue detection and reporting
    """
    
    def test_full_compliance_with_fake_attack(self):
        """
        Test validation workflow with fake attack - should achieve 100% compliance.
        
        Requirements: 3.2, 3.6, 9.1
        """
        logger.info("=" * 70)
        logger.info("TEST: Full Compliance with Fake Attack")
        logger.info("=" * 70)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Step 1: Create PCAP with fake attack
            pcap_path = Path(tmpdir) / "test_fake.pcap"
            attacks = ['fake']
            params = {'ttl': 1, 'fooling': 'badseq'}
            
            create_test_pcap_with_attacks(str(pcap_path), attacks, params)
            logger.info(f"Step 1: Created PCAP with attacks: {attacks}")
            
            # Debug: Check what's in the PCAP
            try:
                from scapy.all import rdpcap, TCP
                debug_packets = rdpcap(str(pcap_path))
                logger.info(f"        PCAP contains {len(debug_packets)} packets")
                for i, pkt in enumerate(debug_packets):
                    has_raw = pkt.haslayer('Raw')
                    has_tcp = pkt.haslayer('TCP')
                    ttl = pkt['IP'].ttl if pkt.haslayer('IP') else 'N/A'
                    payload_len = len(pkt['Raw'].load) if has_raw else 0
                    # Also check TCP payload
                    tcp_payload_len = len(bytes(pkt[TCP].payload)) if has_tcp and pkt[TCP].payload else 0
                    logger.info(f"        Packet {i+1}: TTL={ttl}, has_TCP={has_tcp}, has_Raw={has_raw}, payload_len={payload_len}, tcp_payload_len={tcp_payload_len}")
            except Exception as e:
                logger.warning(f"        Could not debug PCAP: {e}")
            
            # Step 2: Create expected strategy
            expected_strategy = Strategy(
                type='fake',
                attacks=attacks,
                params=params,
                metadata={'test': True}
            )
            logger.info(f"Step 2: Created expected strategy")
            
            # Step 3: Run ComplianceChecker
            checker = ComplianceChecker()
            report = checker.check_compliance(
                pcap_path=str(pcap_path),
                domain='example.com',
                expected_strategy=expected_strategy
            )
            
            logger.info(f"Step 3: Compliance check complete")
            logger.info(f"        Score: {report.score}/{report.max_score} ({report.compliance_percentage:.1f}%)")
            logger.info(f"        Issues: {len(report.issues)}")
            if report.issues:
                for issue in report.issues:
                    logger.info(f"          - {issue}")
            logger.info(f"        Detected attacks: fake={report.detected_attacks.fake}, split={report.detected_attacks.split}, disorder={report.detected_attacks.disorder}")
            
            # Step 4: Assert 100% compliance
            assert report.score == report.max_score, \
                f"Expected 100% compliance, got {report.compliance_percentage:.1f}%"
            assert len(report.issues) == 0, \
                f"Expected no issues, got: {report.issues}"
            assert report.verdicts.get('fake', False), \
                "Fake attack should be detected"
            
            logger.info("✅ 100% compliance achieved!")
            logger.info("=" * 70)
    
    def test_compliance_drop_when_attack_removed(self):
        """
        Test that compliance drops when attack is removed from PCAP.
        
        Requirements: 3.2, 3.6, 9.1
        """
        logger.info("=" * 70)
        logger.info("TEST: Compliance Drop When Attack Removed")
        logger.info("=" * 70)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Step 1: Create PCAP with fake+split attacks
            pcap_path_full = Path(tmpdir) / "test_full.pcap"
            attacks_full = ['fake', 'split']
            params_full = {'ttl': 2, 'fooling': 'badsum', 'split_pos': 2}
            
            create_test_pcap_with_attacks(str(pcap_path_full), attacks_full, params_full)
            logger.info(f"Step 1: Created PCAP with attacks: {attacks_full}")
            
            # Step 2: Create expected strategy (expects both attacks)
            expected_strategy = Strategy(
                type='fake',
                attacks=attacks_full,
                params=params_full,
                metadata={'test': True}
            )
            
            # Step 3: Check compliance with full PCAP
            checker = ComplianceChecker()
            report_full = checker.check_compliance(
                pcap_path=str(pcap_path_full),
                domain='example.com',
                expected_strategy=expected_strategy
            )
            
            logger.info(f"Step 3: Full PCAP compliance: {report_full.compliance_percentage:.1f}%")
            
            # Step 4: Create PCAP with only split (fake removed)
            pcap_path_partial = Path(tmpdir) / "test_partial.pcap"
            attacks_partial = ['split']
            params_partial = {'split_pos': 2}
            
            create_test_pcap_with_attacks(str(pcap_path_partial), attacks_partial, params_partial)
            logger.info(f"Step 4: Created PCAP with attacks: {attacks_partial} (fake removed)")
            
            # Step 5: Check compliance with partial PCAP
            report_partial = checker.check_compliance(
                pcap_path=str(pcap_path_partial),
                domain='example.com',
                expected_strategy=expected_strategy
            )
            
            logger.info(f"Step 5: Partial PCAP compliance: {report_partial.compliance_percentage:.1f}%")
            logger.info(f"        Issues: {report_partial.issues}")
            
            # Step 6: Assert compliance dropped
            assert report_partial.score < report_full.score, \
                "Compliance score should drop when attack is removed"
            assert report_partial.compliance_percentage < 100.0, \
                "Compliance should be less than 100% when attack is missing"
            assert len(report_partial.issues) > 0, \
                "Should report issues when attack is missing"
            assert not report_partial.verdicts.get('fake', True), \
                "Fake attack should NOT be detected in partial PCAP"
            assert report_partial.verdicts.get('split', False), \
                "Split attack should still be detected"
            
            # Check that issue mentions missing fake attack
            issue_text = ' '.join(report_partial.issues).lower()
            assert 'fake' in issue_text, \
                "Issues should mention missing fake attack"
            
            logger.info("✅ Compliance correctly dropped when attack removed!")
            logger.info("=" * 70)
    
    def test_combo_attack_full_compliance(self):
        """
        Test validation workflow with combo attack (fake+multisplit+disorder).
        
        Requirements: 3.2, 3.6, 9.1
        """
        logger.info("=" * 70)
        logger.info("TEST: Combo Attack Full Compliance")
        logger.info("=" * 70)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Step 1: Create PCAP with combo attack
            pcap_path = Path(tmpdir) / "test_combo.pcap"
            attacks = ['fake', 'multisplit', 'disorder']
            params = {
                'ttl': 2,
                'fooling': 'badsum',
                'split_pos': 3,
                'split_count': 3,
                'disorder_method': 'reverse'
            }
            
            create_test_pcap_with_attacks(str(pcap_path), attacks, params)
            logger.info(f"Step 1: Created PCAP with combo attacks: {attacks}")
            
            # Step 2: Create expected strategy
            expected_strategy = Strategy(
                type='fake',
                attacks=attacks,
                params=params,
                metadata={'test': True}
            )
            
            # Step 3: Run ComplianceChecker
            checker = ComplianceChecker()
            report = checker.check_compliance(
                pcap_path=str(pcap_path),
                domain='example.com',
                expected_strategy=expected_strategy
            )
            
            logger.info(f"Step 3: Compliance check complete")
            logger.info(f"        Score: {report.score}/{report.max_score} ({report.compliance_percentage:.1f}%)")
            logger.info(f"        Verdicts: {report.verdicts}")
            logger.info(f"        Issues: {report.issues}")
            
            # Step 4: Assert all attacks detected
            assert report.verdicts.get('fake', False), "Fake attack should be detected"
            assert report.verdicts.get('multisplit', False), "Multisplit attack should be detected"
            assert report.verdicts.get('disorder', False), "Disorder attack should be detected"
            
            # Should have high compliance (may not be 100% due to parameter matching)
            assert report.compliance_percentage >= 80.0, \
                f"Expected high compliance, got {report.compliance_percentage:.1f}%"
            
            logger.info("✅ Combo attack validation successful!")
            logger.info("=" * 70)
    
    def test_proposed_patch_generation(self):
        """
        Test that ComplianceChecker generates proposed patch when compliance is not 100%.
        
        Requirements: 9.1, 9.2
        """
        logger.info("=" * 70)
        logger.info("TEST: Proposed Patch Generation")
        logger.info("=" * 70)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Step 1: Create PCAP with split attack
            pcap_path = Path(tmpdir) / "test_split.pcap"
            actual_attacks = ['split']
            actual_params = {'split_pos': 2}
            
            create_test_pcap_with_attacks(str(pcap_path), actual_attacks, actual_params)
            logger.info(f"Step 1: Created PCAP with attacks: {actual_attacks}")
            
            # Step 2: Create expected strategy (expects fake, but PCAP has split)
            expected_strategy = Strategy(
                type='fake',
                attacks=['fake'],
                params={'ttl': 1},
                metadata={'test': True}
            )
            logger.info(f"Step 2: Created expected strategy with attacks: {expected_strategy.attacks}")
            
            # Step 3: Run ComplianceChecker
            checker = ComplianceChecker()
            report = checker.check_compliance(
                pcap_path=str(pcap_path),
                domain='example.com',
                expected_strategy=expected_strategy
            )
            
            logger.info(f"Step 3: Compliance: {report.compliance_percentage:.1f}%")
            logger.info(f"        Issues: {report.issues}")
            
            # Step 4: Assert proposed patch is generated
            assert report.proposed_patch is not None, \
                "Proposed patch should be generated when compliance < 100%"
            
            patch = report.proposed_patch
            logger.info(f"Step 4: Proposed patch: {json.dumps(patch, indent=2)}")
            
            # Verify patch structure
            assert 'domain' in patch, "Patch should contain domain"
            assert 'operation' in patch, "Patch should contain operation"
            assert 'value' in patch, "Patch should contain value"
            
            # Verify patch suggests split attack
            patch_attacks = patch['value'].get('attacks', [])
            assert 'split' in patch_attacks, \
                "Patch should suggest split attack based on detected attacks"
            
            logger.info("✅ Proposed patch correctly generated!")
            logger.info("=" * 70)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
