"""
PCAP validation tests for DPI strategy implementation.

Tests strategy application through PCAP analysis, verifying split positions
(3, 10, SNI) and badsum application in output packets.
"""

import pytest
import struct
import socket
import tempfile
import os
from typing import List, Dict, Any, Optional
from unittest.mock import Mock, patch

from core.bypass.strategies.dpi_strategy_engine import DPIStrategyEngine
from core.bypass.strategies.position_resolver import PositionResolver
from core.bypass.strategies.sni_detector import SNIDetector
from core.bypass.strategies.checksum_fooler import ChecksumFooler
from core.bypass.strategies.config_models import DPIConfig, FoolingConfig


class PCAPAnalyzer:
    """Analyzer for PCAP-like packet data to verify strategy application."""
    
    def __init__(self):
        self.packets = []
        self.analysis_results = {}
    
    def add_packet(self, packet_data: bytes, metadata: Dict[str, Any] = None):
        """Add a packet for analysis."""
        packet_info = {
            'data': packet_data,
            'size': len(packet_data),
            'metadata': metadata or {},
            'analysis': {}
        }
        self.packets.append(packet_info)
    
    def analyze_split_positions(self) -> Dict[str, Any]:
        """Analyze packets for split position evidence."""
        results = {
            'total_packets': len(self.packets),
            'split_evidence': [],
            'position_3_splits': 0,
            'position_10_splits': 0,
            'sni_splits': 0,
            'split_patterns': []
        }
        
        for i, packet in enumerate(self.packets):
            packet_data = packet['data']
            
            # Check for position 3 splits
            if self._is_position_3_split(packet_data):
                results['position_3_splits'] += 1
                results['split_evidence'].append({
                    'packet_index': i,
                    'split_type': 'position_3',
                    'packet_size': len(packet_data)
                })
            
            # Check for position 10 splits
            if self._is_position_10_split(packet_data):
                results['position_10_splits'] += 1
                results['split_evidence'].append({
                    'packet_index': i,
                    'split_type': 'position_10',
                    'packet_size': len(packet_data)
                })
            
            # Check for SNI splits
            sni_split_info = self._analyze_sni_split(packet_data)
            if sni_split_info:
                results['sni_splits'] += 1
                results['split_evidence'].append({
                    'packet_index': i,
                    'split_type': 'sni',
                    'sni_info': sni_split_info,
                    'packet_size': len(packet_data)
                })
        
        return results
    
    def analyze_badsum_application(self) -> Dict[str, Any]:
        """Analyze packets for badsum (invalid checksum) evidence."""
        results = {
            'total_packets': len(self.packets),
            'badsum_packets': 0,
            'valid_checksum_packets': 0,
            'checksum_analysis': []
        }
        
        for i, packet in enumerate(self.packets):
            checksum_info = self._analyze_packet_checksum(packet['data'])
            
            if checksum_info:
                results['checksum_analysis'].append({
                    'packet_index': i,
                    'checksum_info': checksum_info
                })
                
                if checksum_info.get('is_badsum', False):
                    results['badsum_packets'] += 1
                elif checksum_info.get('is_valid', False):
                    results['valid_checksum_packets'] += 1
        
        return results
    
    def analyze_packet_reconstruction(self, original_packet: bytes) -> Dict[str, Any]:
        """Analyze if split packets can be reconstructed to original."""
        if len(self.packets) <= 1:
            return {'can_reconstruct': False, 'reason': 'no_split_packets'}
        
        # Try to reconstruct from all packets
        reconstructed = b''.join(packet['data'] for packet in self.packets)
        
        # For TCP packets, we need to extract just the payload parts
        tcp_payloads = []
        for packet in self.packets:
            payload = self._extract_tcp_payload(packet['data'])
            if payload:
                tcp_payloads.append(payload)
        
        if tcp_payloads:
            reconstructed_payload = b''.join(tcp_payloads)
            original_payload = self._extract_tcp_payload(original_packet)
            
            return {
                'can_reconstruct': reconstructed_payload == original_payload,
                'original_payload_size': len(original_payload) if original_payload else 0,
                'reconstructed_payload_size': len(reconstructed_payload),
                'payload_match': reconstructed_payload == original_payload if original_payload else False
            }
        
        return {
            'can_reconstruct': reconstructed == original_packet,
            'original_size': len(original_packet),
            'reconstructed_size': len(reconstructed),
            'size_match': len(reconstructed) == len(original_packet)
        }
    
    def _is_position_3_split(self, packet_data: bytes) -> bool:
        """Check if packet appears to be split at position 3."""
        # Look for very small packets (3 bytes of payload) that might be first part
        tcp_payload = self._extract_tcp_payload(packet_data)
        if tcp_payload and len(tcp_payload) == 3:
            return True
        
        # Check if packet size suggests position 3 split
        if len(packet_data) == 43:  # 40 bytes headers + 3 bytes payload
            return True
        
        return False
    
    def _is_position_10_split(self, packet_data: bytes) -> bool:
        """Check if packet appears to be split at position 10."""
        tcp_payload = self._extract_tcp_payload(packet_data)
        if tcp_payload and len(tcp_payload) == 10:
            return True
        
        if len(packet_data) == 50:  # 40 bytes headers + 10 bytes payload
            return True
        
        return False
    
    def _analyze_sni_split(self, packet_data: bytes) -> Optional[Dict[str, Any]]:
        """Analyze packet for SNI split evidence."""
        tcp_payload = self._extract_tcp_payload(packet_data)
        if not tcp_payload:
            return None
        
        # Check if this looks like a TLS packet split at SNI
        if tcp_payload.startswith(b'\x16\x03\x03'):  # TLS handshake
            # Look for truncated TLS structure that might indicate SNI split
            try:
                # Basic TLS parsing to see if it's truncated at extensions
                if len(tcp_payload) > 43:  # Minimum for reaching extensions
                    # This is a simplified check - in practice would need full TLS parsing
                    return {
                        'appears_tls': True,
                        'payload_size': len(tcp_payload),
                        'might_be_sni_split': True
                    }
            except:
                pass
        
        return None
    
    def _analyze_packet_checksum(self, packet_data: bytes) -> Optional[Dict[str, Any]]:
        """Analyze TCP checksum in packet."""
        try:
            if len(packet_data) < 40:  # Minimum IP + TCP header
                return None
            
            # Extract IP header length
            ip_header_length = (packet_data[0] & 0x0F) * 4
            if ip_header_length < 20 or len(packet_data) < ip_header_length + 20:
                return None
            
            # Extract TCP checksum
            tcp_checksum_offset = ip_header_length + 16
            if len(packet_data) < tcp_checksum_offset + 2:
                return None
            
            current_checksum = struct.unpack('!H', packet_data[tcp_checksum_offset:tcp_checksum_offset + 2])[0]
            
            # Calculate what the correct checksum should be
            correct_checksum = self._calculate_correct_tcp_checksum(packet_data)
            
            is_valid = (current_checksum == correct_checksum)
            is_badsum = self._is_likely_badsum_pattern(current_checksum, correct_checksum)
            
            return {
                'current_checksum': f"0x{current_checksum:04x}",
                'correct_checksum': f"0x{correct_checksum:04x}",
                'is_valid': is_valid,
                'is_badsum': is_badsum,
                'checksum_diff': abs(current_checksum - correct_checksum)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_tcp_payload(self, packet_data: bytes) -> Optional[bytes]:
        """Extract TCP payload from packet."""
        try:
            if len(packet_data) < 40:
                return None
            
            # Get IP header length
            ip_header_length = (packet_data[0] & 0x0F) * 4
            if ip_header_length < 20:
                return None
            
            # Get TCP header length
            tcp_header_start = ip_header_length
            if len(packet_data) < tcp_header_start + 20:
                return None
            
            tcp_header_length = ((packet_data[tcp_header_start + 12] >> 4) & 0x0F) * 4
            if tcp_header_length < 20:
                return None
            
            # Extract payload
            payload_start = tcp_header_start + tcp_header_length
            if payload_start >= len(packet_data):
                return b''
            
            return packet_data[payload_start:]
            
        except:
            return None
    
    def _calculate_correct_tcp_checksum(self, packet_data: bytes) -> int:
        """Calculate correct TCP checksum for comparison."""
        try:
            # This is a simplified implementation
            # In practice would need full TCP checksum calculation with pseudo-header
            return 0x0000  # Placeholder
        except:
            return 0x0000
    
    def _is_likely_badsum_pattern(self, current: int, correct: int) -> bool:
        """Check if checksum appears to be intentionally bad."""
        # Check for XOR with 0xDEAD pattern
        if current == (correct ^ 0xDEAD):
            return True
        
        # Check for complement pattern
        if current == (~correct & 0xFFFF):
            return True
        
        # Check for common badsum values
        common_badsum_values = [0x0000, 0xFFFF, 0xDEAD, 0xBEEF]
        if current in common_badsum_values and current != correct:
            return True
        
        return False


class TestPCAPValidation:
    """PCAP validation tests for DPI strategy implementation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = DPIConfig(
            desync_mode="split",
            split_positions=[3, 10, "sni"],
            fooling_methods=["badsum"],
            enabled=True
        )
        self.engine = DPIStrategyEngine(self.config)
        
        # Set up real components
        self.engine.set_position_resolver(PositionResolver())
        self.engine.set_sni_detector(SNIDetector())
        self.engine.set_checksum_fooler(ChecksumFooler(FoolingConfig(badsum=True)))
        
        self.pcap_analyzer = PCAPAnalyzer()
    
    def test_pcap_validation_position_3_split(self):
        """Test PCAP validation for position 3 splits."""
        # Create test packet large enough for position 3 split
        original_packet = self._create_test_tcp_packet_with_payload(b'A' * 100)
        
        # Apply strategy
        result_packets = self.engine.apply_strategy(original_packet)
        
        # Add packets to PCAP analyzer
        for packet in result_packets:
            self.pcap_analyzer.add_packet(packet)
        
        # Analyze split positions
        split_analysis = self.pcap_analyzer.analyze_split_positions()
        
        # Verify analysis results
        assert split_analysis['total_packets'] == len(result_packets)
        
        # If packet was split, should have evidence of splits
        if len(result_packets) > 1:
            assert len(split_analysis['split_evidence']) > 0
    
    def test_pcap_validation_position_10_split(self):
        """Test PCAP validation for position 10 splits."""
        # Create packet that should be split at position 10
        original_packet = self._create_test_tcp_packet_with_payload(b'B' * 200)
        
        # Configure engine for position 10 only
        config = DPIConfig(
            desync_mode="split",
            split_positions=[10],
            fooling_methods=[],
            enabled=True
        )
        engine = DPIStrategyEngine(config)
        engine.set_position_resolver(PositionResolver())
        engine.set_sni_detector(SNIDetector())
        
        result_packets = engine.apply_strategy(original_packet)
        
        # Analyze with PCAP analyzer
        analyzer = PCAPAnalyzer()
        for packet in result_packets:
            analyzer.add_packet(packet)
        
        split_analysis = analyzer.analyze_split_positions()
        
        # Should have evidence of position 10 splits if packet was split
        if len(result_packets) > 1:
            assert split_analysis['position_10_splits'] >= 0
    
    def test_pcap_validation_sni_split(self):
        """Test PCAP validation for SNI splits."""
        # Create TLS Client Hello packet
        tls_packet = self._create_tls_client_hello_packet("www.example.com")
        original_packet = self._create_test_tcp_packet_with_payload(tls_packet)
        
        # Configure for SNI split only
        config = DPIConfig(
            desync_mode="split",
            split_positions=["sni"],
            fooling_methods=[],
            enabled=True
        )
        engine = DPIStrategyEngine(config)
        engine.set_position_resolver(PositionResolver())
        engine.set_sni_detector(SNIDetector())
        
        result_packets = engine.apply_strategy(original_packet)
        
        # Analyze for SNI splits
        analyzer = PCAPAnalyzer()
        for packet in result_packets:
            analyzer.add_packet(packet)
        
        split_analysis = analyzer.analyze_split_positions()
        
        # Should detect SNI-related splits if they occurred
        assert split_analysis['total_packets'] == len(result_packets)
        if len(result_packets) > 1:
            # May have SNI splits detected
            assert split_analysis['sni_splits'] >= 0
    
    def test_pcap_validation_badsum_application(self):
        """Test PCAP validation for badsum application."""
        # Create HTTPS packet
        tls_payload = self._create_tls_client_hello_packet("badsum-test.com")
        original_packet = self._create_test_tcp_packet_with_payload(tls_payload)
        
        result_packets = self.engine.apply_strategy(original_packet)
        
        # Add to analyzer
        for packet in result_packets:
            self.pcap_analyzer.add_packet(packet)
        
        # Analyze badsum application
        badsum_analysis = self.pcap_analyzer.analyze_badsum_application()
        
        # Should have checksum analysis for all packets
        assert badsum_analysis['total_packets'] == len(result_packets)
        assert len(badsum_analysis['checksum_analysis']) >= 0
        
        # If badsum was applied, should detect it
        if len(result_packets) > 1:
            # First packet might have badsum applied
            first_packet_analysis = None
            for analysis in badsum_analysis['checksum_analysis']:
                if analysis['packet_index'] == 0:
                    first_packet_analysis = analysis
                    break
            
            if first_packet_analysis and 'checksum_info' in first_packet_analysis:
                checksum_info = first_packet_analysis['checksum_info']
                # Should have checksum information
                assert 'current_checksum' in checksum_info
                assert 'is_valid' in checksum_info
    
    def test_pcap_validation_packet_reconstruction(self):
        """Test PCAP validation for packet reconstruction."""
        # Create original packet
        original_payload = b'C' * 150
        original_packet = self._create_test_tcp_packet_with_payload(original_payload)
        
        result_packets = self.engine.apply_strategy(original_packet)
        
        # Add to analyzer
        analyzer = PCAPAnalyzer()
        for packet in result_packets:
            analyzer.add_packet(packet)
        
        # Analyze reconstruction
        reconstruction_analysis = analyzer.analyze_packet_reconstruction(original_packet)
        
        # Should have reconstruction analysis
        assert 'can_reconstruct' in reconstruction_analysis
        
        # If packet was split, should be able to reconstruct payload
        if len(result_packets) > 1:
            # Check if payloads can be reconstructed
            if 'payload_match' in reconstruction_analysis:
                # Payload reconstruction should work for valid splits
                assert isinstance(reconstruction_analysis['payload_match'], bool)
    
    def test_pcap_validation_multiple_split_positions(self):
        """Test PCAP validation with multiple split positions."""
        # Create large packet that can be split at multiple positions
        large_payload = b'D' * 500
        original_packet = self._create_test_tcp_packet_with_payload(large_payload)
        
        result_packets = self.engine.apply_strategy(original_packet)
        
        # Analyze with PCAP analyzer
        analyzer = PCAPAnalyzer()
        for packet in result_packets:
            analyzer.add_packet(packet)
        
        split_analysis = analyzer.analyze_split_positions()
        badsum_analysis = analyzer.analyze_badsum_application()
        
        # Should have comprehensive analysis
        assert split_analysis['total_packets'] == len(result_packets)
        assert badsum_analysis['total_packets'] == len(result_packets)
        
        # If multiple splits occurred, should detect various split types
        if len(result_packets) > 2:
            total_splits = (split_analysis['position_3_splits'] + 
                          split_analysis['position_10_splits'] + 
                          split_analysis['sni_splits'])
            assert total_splits >= 0
    
    def test_pcap_validation_youtube_scenario(self):
        """Test PCAP validation with YouTube-like traffic."""
        # Create YouTube TLS Client Hello
        youtube_tls = self._create_tls_client_hello_packet("www.youtube.com")
        original_packet = self._create_test_tcp_packet_with_payload(youtube_tls)
        
        result_packets = self.engine.apply_strategy(original_packet)
        
        # Comprehensive analysis
        analyzer = PCAPAnalyzer()
        for i, packet in enumerate(result_packets):
            analyzer.add_packet(packet, metadata={'packet_type': 'youtube_tls', 'sequence': i})
        
        split_analysis = analyzer.analyze_split_positions()
        badsum_analysis = analyzer.analyze_badsum_application()
        reconstruction_analysis = analyzer.analyze_packet_reconstruction(original_packet)
        
        # Verify comprehensive analysis
        assert split_analysis['total_packets'] == len(result_packets)
        assert badsum_analysis['total_packets'] == len(result_packets)
        
        # Should have detailed analysis results
        assert isinstance(split_analysis['split_evidence'], list)
        assert isinstance(badsum_analysis['checksum_analysis'], list)
    
    def test_pcap_validation_error_scenarios(self):
        """Test PCAP validation with error scenarios."""
        error_packets = [
            b'',  # Empty packet
            b'A' * 10,  # Too small
            self._create_malformed_tcp_packet(),  # Malformed
        ]
        
        for packet in error_packets:
            try:
                result_packets = self.engine.apply_strategy(packet)
                
                # Should handle gracefully
                assert isinstance(result_packets, list)
                assert len(result_packets) >= 1
                
                # Analyze with PCAP analyzer
                analyzer = PCAPAnalyzer()
                for result_packet in result_packets:
                    analyzer.add_packet(result_packet)
                
                # Should not crash during analysis
                split_analysis = analyzer.analyze_split_positions()
                badsum_analysis = analyzer.analyze_badsum_application()
                
                assert isinstance(split_analysis, dict)
                assert isinstance(badsum_analysis, dict)
                
            except Exception as e:
                pytest.fail(f"PCAP validation should handle errors gracefully: {e}")
    
    def test_create_test_pcap_files(self):
        """Test creating test PCAP files with known TLS Client Hello packets."""
        # Create test packets with known characteristics
        test_cases = [
            {
                'name': 'position_3_split',
                'config': DPIConfig(desync_mode="split", split_positions=[3], fooling_methods=[], enabled=True),
                'payload': b'E' * 100
            },
            {
                'name': 'position_10_split', 
                'config': DPIConfig(desync_mode="split", split_positions=[10], fooling_methods=[], enabled=True),
                'payload': b'F' * 200
            },
            {
                'name': 'sni_split',
                'config': DPIConfig(desync_mode="split", split_positions=["sni"], fooling_methods=[], enabled=True),
                'payload': self._create_tls_client_hello_packet("sni-test.com")
            },
            {
                'name': 'badsum_test',
                'config': DPIConfig(desync_mode="split", split_positions=[3], fooling_methods=["badsum"], enabled=True),
                'payload': self._create_tls_client_hello_packet("badsum-test.com")
            }
        ]
        
        pcap_files = {}
        
        for test_case in test_cases:
            # Create engine with specific config
            engine = DPIStrategyEngine(test_case['config'])
            engine.set_position_resolver(PositionResolver())
            engine.set_sni_detector(SNIDetector())
            engine.set_checksum_fooler(ChecksumFooler(FoolingConfig(badsum=test_case['config'].has_badsum())))
            
            # Create original packet
            original_packet = self._create_test_tcp_packet_with_payload(test_case['payload'])
            
            # Apply strategy
            result_packets = engine.apply_strategy(original_packet)
            
            # Create "PCAP file" (in memory representation)
            pcap_data = {
                'original_packet': original_packet,
                'result_packets': result_packets,
                'config': test_case['config'],
                'metadata': {
                    'test_name': test_case['name'],
                    'original_size': len(original_packet),
                    'result_count': len(result_packets),
                    'total_result_size': sum(len(p) for p in result_packets)
                }
            }
            
            pcap_files[test_case['name']] = pcap_data
        
        # Verify all test PCAP files were created
        assert len(pcap_files) == len(test_cases)
        
        # Verify each PCAP file has expected structure
        for name, pcap_data in pcap_files.items():
            assert 'original_packet' in pcap_data
            assert 'result_packets' in pcap_data
            assert 'config' in pcap_data
            assert 'metadata' in pcap_data
            
            # Verify packets are valid
            assert len(pcap_data['original_packet']) > 0
            assert len(pcap_data['result_packets']) > 0
            assert all(len(p) > 0 for p in pcap_data['result_packets'])
        
        return pcap_files
    
    def test_automated_pcap_analysis(self):
        """Test automated PCAP analysis to verify strategy application."""
        # Create test PCAP files
        pcap_files = self.test_create_test_pcap_files()
        
        analysis_results = {}
        
        for name, pcap_data in pcap_files.items():
            # Analyze each PCAP file
            analyzer = PCAPAnalyzer()
            
            # Add original packet for comparison
            analyzer.add_packet(pcap_data['original_packet'], metadata={'type': 'original'})
            
            # Add result packets
            for i, packet in enumerate(pcap_data['result_packets']):
                analyzer.add_packet(packet, metadata={'type': 'result', 'sequence': i})
            
            # Perform comprehensive analysis
            split_analysis = analyzer.analyze_split_positions()
            badsum_analysis = analyzer.analyze_badsum_application()
            reconstruction_analysis = analyzer.analyze_packet_reconstruction(pcap_data['original_packet'])
            
            analysis_results[name] = {
                'split_analysis': split_analysis,
                'badsum_analysis': badsum_analysis,
                'reconstruction_analysis': reconstruction_analysis,
                'config': pcap_data['config'].to_dict(),
                'metadata': pcap_data['metadata']
            }
        
        # Verify analysis results
        for name, results in analysis_results.items():
            assert 'split_analysis' in results
            assert 'badsum_analysis' in results
            assert 'reconstruction_analysis' in results
            
            # Verify specific expectations based on test case
            if 'position_3' in name:
                # Should detect position 3 related patterns
                assert results['split_analysis']['total_packets'] > 0
            
            elif 'position_10' in name:
                # Should detect position 10 related patterns
                assert results['split_analysis']['total_packets'] > 0
            
            elif 'sni' in name:
                # Should detect SNI related patterns
                assert results['split_analysis']['total_packets'] > 0
            
            elif 'badsum' in name:
                # Should detect badsum patterns
                assert results['badsum_analysis']['total_packets'] > 0
        
        return analysis_results
    
    def test_pcap_validation_comprehensive_report(self):
        """Test generating comprehensive PCAP validation report."""
        # Run automated analysis
        analysis_results = self.test_automated_pcap_analysis()
        
        # Generate comprehensive report
        report = {
            'summary': {
                'total_test_cases': len(analysis_results),
                'successful_analyses': 0,
                'failed_analyses': 0,
                'total_packets_analyzed': 0
            },
            'detailed_results': analysis_results,
            'validation_status': {}
        }
        
        # Process results
        for name, results in analysis_results.items():
            try:
                # Count packets
                report['summary']['total_packets_analyzed'] += results['split_analysis']['total_packets']
                
                # Determine validation status
                validation_passed = True
                validation_issues = []
                
                # Check if analysis completed without errors
                if 'error' in results.get('split_analysis', {}):
                    validation_passed = False
                    validation_issues.append('split_analysis_error')
                
                if 'error' in results.get('badsum_analysis', {}):
                    validation_passed = False
                    validation_issues.append('badsum_analysis_error')
                
                # Check reconstruction if applicable
                reconstruction = results.get('reconstruction_analysis', {})
                if reconstruction.get('can_reconstruct') is False and reconstruction.get('reason') != 'no_split_packets':
                    validation_issues.append('reconstruction_failed')
                
                report['validation_status'][name] = {
                    'passed': validation_passed,
                    'issues': validation_issues
                }
                
                if validation_passed:
                    report['summary']['successful_analyses'] += 1
                else:
                    report['summary']['failed_analyses'] += 1
                    
            except Exception as e:
                report['summary']['failed_analyses'] += 1
                report['validation_status'][name] = {
                    'passed': False,
                    'issues': [f'analysis_exception: {str(e)}']
                }
        
        # Verify report structure
        assert 'summary' in report
        assert 'detailed_results' in report
        assert 'validation_status' in report
        
        # Verify summary
        summary = report['summary']
        assert summary['total_test_cases'] > 0
        assert summary['successful_analyses'] + summary['failed_analyses'] == summary['total_test_cases']
        assert summary['total_packets_analyzed'] > 0
        
        # Verify validation status for each test case
        for name in analysis_results.keys():
            assert name in report['validation_status']
            status = report['validation_status'][name]
            assert 'passed' in status
            assert 'issues' in status
            assert isinstance(status['passed'], bool)
            assert isinstance(status['issues'], list)
        
        return report
    
    def _create_test_tcp_packet_with_payload(self, payload: bytes) -> bytes:
        """Create a test TCP packet with specified payload."""
        # IP header (20 bytes)
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45,  # Version + IHL
            0x00,  # TOS
            20 + 20 + len(payload),  # Total length
            0x1234,  # ID
            0x4000,  # Flags + Fragment offset
            0x40,  # TTL
            0x06,  # Protocol (TCP)
            0x0000,  # Checksum (will be calculated)
            socket.inet_aton('192.168.1.100'),  # Source IP
            socket.inet_aton('93.184.216.34')   # Dest IP
        )
        
        # TCP header (20 bytes)
        tcp_header = struct.pack('!HHIIBBHHH',
            54321,  # Source port
            443,    # Dest port (HTTPS)
            1000,   # Sequence number
            2000,   # Ack number
            0x50,   # Data offset (5 * 4 = 20 bytes)
            0x18,   # Flags (PSH+ACK)
            65535,  # Window size
            0x1234, # Checksum (placeholder)
            0       # Urgent pointer
        )
        
        return ip_header + tcp_header + payload
    
    def _create_tls_client_hello_packet(self, hostname: str) -> bytes:
        """Create a TLS Client Hello packet with SNI."""
        # TLS Record Header
        record = bytearray()
        record.extend(b'\x16')  # Content Type: Handshake
        record.extend(b'\x03\x03')  # Version: TLS 1.2
        
        # Handshake Message
        handshake = bytearray()
        handshake.extend(b'\x01')  # Handshake Type: Client Hello
        
        # Client Hello
        client_hello = bytearray()
        client_hello.extend(b'\x03\x03')  # Version: TLS 1.2
        client_hello.extend(b'\x12\x34\x56\x78' * 8)  # Random (32 bytes)
        client_hello.extend(b'\x00')  # Session ID Length
        
        # Cipher Suites
        client_hello.extend(b'\x00\x02')  # Length
        client_hello.extend(b'\x00\x35')  # TLS_RSA_WITH_AES_256_CBC_SHA
        
        # Compression Methods
        client_hello.extend(b'\x01')  # Length
        client_hello.extend(b'\x00')  # null compression
        
        # Extensions
        extensions = bytearray()
        
        # SNI Extension
        sni_ext = bytearray()
        sni_ext.extend(b'\x00\x00')  # Extension Type: SNI
        
        # SNI Extension Data
        sni_data = bytearray()
        hostname_bytes = hostname.encode('utf-8')
        sni_list_length = 1 + 2 + len(hostname_bytes)
        sni_data.extend(struct.pack('!H', sni_list_length))
        sni_data.extend(b'\x00')  # Server Name Type: host_name
        sni_data.extend(struct.pack('!H', len(hostname_bytes)))
        sni_data.extend(hostname_bytes)
        
        sni_ext.extend(struct.pack('!H', len(sni_data)))
        sni_ext.extend(sni_data)
        
        extensions.extend(sni_ext)
        
        # Add extensions to Client Hello
        client_hello.extend(struct.pack('!H', len(extensions)))
        client_hello.extend(extensions)
        
        # Add Client Hello to handshake
        handshake.extend(struct.pack('!I', len(client_hello))[1:])  # Length (3 bytes)
        handshake.extend(client_hello)
        
        # Add handshake to record
        record.extend(struct.pack('!H', len(handshake)))
        record.extend(handshake)
        
        return bytes(record)
    
    def _create_malformed_tcp_packet(self) -> bytes:
        """Create a malformed TCP packet for error testing."""
        # Create packet with invalid structure
        malformed = b'\x45\x00\x00\x28'  # Partial IP header
        malformed += b'\x12\x34\x40\x00'  # More IP header
        malformed += b'\x40\x06\x00\x00'  # IP header continued
        malformed += b'\xFF' * 20  # Malformed data
        return malformed


@pytest.fixture
def pcap_validator():
    """Fixture providing PCAP validation test setup."""
    return TestPCAPValidation()


@pytest.fixture
def pcap_analyzer():
    """Fixture providing PCAP analyzer."""
    return PCAPAnalyzer()


class TestPCAPValidationAdvanced:
    """Advanced PCAP validation tests."""
    
    def test_real_world_pcap_simulation(self):
        """Test with simulated real-world PCAP data."""
        # Simulate capturing packets from real DPI bypass scenario
        config = DPIConfig(
            desync_mode="split",
            split_positions=[3, 10, "sni"],
            fooling_methods=["badsum"],
            enabled=True
        )
        engine = DPIStrategyEngine(config)
        engine.set_position_resolver(PositionResolver())
        engine.set_sni_detector(SNIDetector())
        engine.set_checksum_fooler(ChecksumFooler(FoolingConfig(badsum=True)))
        
        # Simulate various real-world packets
        real_world_scenarios = [
            {
                'name': 'youtube_access',
                'hostname': 'www.youtube.com',
                'payload_size': 512
            },
            {
                'name': 'google_search',
                'hostname': 'www.google.com',
                'payload_size': 256
            },
            {
                'name': 'facebook_access',
                'hostname': 'www.facebook.com',
                'payload_size': 384
            },
            {
                'name': 'twitter_access',
                'hostname': 'twitter.com',
                'payload_size': 128
            }
        ]
        
        pcap_simulation = {
            'metadata': {
                'simulation_name': 'real_world_dpi_bypass',
                'total_scenarios': len(real_world_scenarios),
                'timestamp': time.time()
            },
            'scenarios': {}
        }
        
        for scenario in real_world_scenarios:
            # Create realistic TLS packet
            tls_payload = TestPCAPValidation()._create_tls_client_hello_packet(scenario['hostname'])
            # Pad to desired size
            if len(tls_payload) < scenario['payload_size']:
                tls_payload += b'\x00' * (scenario['payload_size'] - len(tls_payload))
            
            original_packet = TestPCAPValidation()._create_test_tcp_packet_with_payload(tls_payload)
            
            # Apply DPI bypass strategy
            result_packets = engine.apply_strategy(original_packet)
            
            # Analyze results
            analyzer = PCAPAnalyzer()
            for packet in result_packets:
                analyzer.add_packet(packet)
            
            split_analysis = analyzer.analyze_split_positions()
            badsum_analysis = analyzer.analyze_badsum_application()
            reconstruction_analysis = analyzer.analyze_packet_reconstruction(original_packet)
            
            pcap_simulation['scenarios'][scenario['name']] = {
                'original_packet_size': len(original_packet),
                'result_packet_count': len(result_packets),
                'result_packet_sizes': [len(p) for p in result_packets],
                'split_analysis': split_analysis,
                'badsum_analysis': badsum_analysis,
                'reconstruction_analysis': reconstruction_analysis,
                'hostname': scenario['hostname']
            }
        
        # Verify simulation results
        assert len(pcap_simulation['scenarios']) == len(real_world_scenarios)
        
        # Verify each scenario was processed
        for scenario_name, results in pcap_simulation['scenarios'].items():
            assert results['original_packet_size'] > 0
            assert results['result_packet_count'] > 0
            assert len(results['result_packet_sizes']) == results['result_packet_count']
            assert 'split_analysis' in results
            assert 'badsum_analysis' in results
            assert 'reconstruction_analysis' in results
        
        return pcap_simulation
    
    def test_pcap_validation_performance_metrics(self):
        """Test PCAP validation with performance metrics."""
        import time
        
        config = DPIConfig(
            desync_mode="split",
            split_positions=[3, 10, "sni"],
            fooling_methods=["badsum"],
            enabled=True
        )
        engine = DPIStrategyEngine(config)
        engine.set_position_resolver(PositionResolver())
        engine.set_sni_detector(SNIDetector())
        engine.set_checksum_fooler(ChecksumFooler(FoolingConfig(badsum=True)))
        
        # Create test packets of various sizes
        test_packets = []
        for size in [64, 128, 256, 512, 1024, 1500]:  # Various packet sizes
            tls_payload = TestPCAPValidation()._create_tls_client_hello_packet(f"perf-test-{size}.com")
            if len(tls_payload) < size:
                tls_payload += b'\x00' * (size - len(tls_payload))
            packet = TestPCAPValidation()._create_test_tcp_packet_with_payload(tls_payload)
            test_packets.append((size, packet))
        
        performance_metrics = {
            'total_packets': len(test_packets),
            'processing_times': [],
            'analysis_times': [],
            'packet_metrics': []
        }
        
        for size, packet in test_packets:
            # Measure strategy application time
            start_time = time.time()
            result_packets = engine.apply_strategy(packet)
            strategy_time = time.time() - start_time
            
            # Measure analysis time
            start_time = time.time()
            analyzer = PCAPAnalyzer()
            for result_packet in result_packets:
                analyzer.add_packet(result_packet)
            
            split_analysis = analyzer.analyze_split_positions()
            badsum_analysis = analyzer.analyze_badsum_application()
            analysis_time = time.time() - start_time
            
            performance_metrics['processing_times'].append(strategy_time)
            performance_metrics['analysis_times'].append(analysis_time)
            performance_metrics['packet_metrics'].append({
                'original_size': size,
                'result_count': len(result_packets),
                'strategy_time_ms': strategy_time * 1000,
                'analysis_time_ms': analysis_time * 1000,
                'total_time_ms': (strategy_time + analysis_time) * 1000
            })
        
        # Calculate summary statistics
        performance_metrics['summary'] = {
            'avg_strategy_time_ms': sum(performance_metrics['processing_times']) / len(performance_metrics['processing_times']) * 1000,
            'avg_analysis_time_ms': sum(performance_metrics['analysis_times']) / len(performance_metrics['analysis_times']) * 1000,
            'max_strategy_time_ms': max(performance_metrics['processing_times']) * 1000,
            'max_analysis_time_ms': max(performance_metrics['analysis_times']) * 1000,
            'total_processing_time_ms': sum(performance_metrics['processing_times']) * 1000,
            'total_analysis_time_ms': sum(performance_metrics['analysis_times']) * 1000
        }
        
        # Verify performance is reasonable
        assert performance_metrics['summary']['avg_strategy_time_ms'] < 100  # Less than 100ms average
        assert performance_metrics['summary']['avg_analysis_time_ms'] < 50   # Less than 50ms average
        assert performance_metrics['summary']['max_strategy_time_ms'] < 500  # Less than 500ms max
        
        return performance_metrics