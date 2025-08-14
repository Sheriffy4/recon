# recon/core/fingerprint/test_advanced_models.py
"""
Unit tests for advanced DPI fingerprinting models - Task 1 Implementation
Tests for data models, serialization, and error handling.
"""

import unittest
import json
import time
from typing import Dict, Any

from advanced_models import (
    DPIFingerprint, DPIType, ConfidenceLevel,
    FingerprintingError, NetworkAnalysisError, MLClassificationError,
    CacheError, MetricsCollectionError
)


class TestDPIType(unittest.TestCase):
    """Test DPIType enum"""
    
    def test_dpi_type_values(self):
        """Test that all DPI types have correct string values"""
        self.assertEqual(DPIType.UNKNOWN.value, "unknown")
        self.assertEqual(DPIType.ROSKOMNADZOR_TSPU.value, "roskomnadzor_tspu")
        self.assertEqual(DPIType.ROSKOMNADZOR_DPI.value, "roskomnadzor_dpi")
        self.assertEqual(DPIType.COMMERCIAL_DPI.value, "commercial_dpi")
        self.assertEqual(DPIType.FIREWALL_BASED.value, "firewall_based")
        self.assertEqual(DPIType.ISP_TRANSPARENT_PROXY.value, "isp_proxy")
        self.assertEqual(DPIType.CLOUDFLARE_PROTECTION.value, "cloudflare")
        self.assertEqual(DPIType.GOVERNMENT_CENSORSHIP.value, "government")
    
    def test_dpi_type_from_string(self):
        """Test creating DPIType from string values"""
        self.assertEqual(DPIType("unknown"), DPIType.UNKNOWN)
        self.assertEqual(DPIType("roskomnadzor_tspu"), DPIType.ROSKOMNADZOR_TSPU)
        self.assertEqual(DPIType("commercial_dpi"), DPIType.COMMERCIAL_DPI)


class TestConfidenceLevel(unittest.TestCase):
    """Test ConfidenceLevel enum"""
    
    def test_confidence_level_values(self):
        """Test that confidence levels have correct numeric values"""
        self.assertEqual(ConfidenceLevel.VERY_LOW.value, 0.2)
        self.assertEqual(ConfidenceLevel.LOW.value, 0.4)
        self.assertEqual(ConfidenceLevel.MEDIUM.value, 0.6)
        self.assertEqual(ConfidenceLevel.HIGH.value, 0.8)
        self.assertEqual(ConfidenceLevel.VERY_HIGH.value, 0.9)
    
    def test_confidence_level_ordering(self):
        """Test that confidence levels are properly ordered"""
        levels = [
            ConfidenceLevel.VERY_LOW,
            ConfidenceLevel.LOW,
            ConfidenceLevel.MEDIUM,
            ConfidenceLevel.HIGH,
            ConfidenceLevel.VERY_HIGH
        ]
        
        for i in range(len(levels) - 1):
            self.assertLess(levels[i].value, levels[i + 1].value)


class TestFingerprintingExceptions(unittest.TestCase):
    """Test exception hierarchy"""
    
    def test_exception_hierarchy(self):
        """Test that all exceptions inherit from FingerprintingError"""
        self.assertTrue(issubclass(NetworkAnalysisError, FingerprintingError))
        self.assertTrue(issubclass(MLClassificationError, FingerprintingError))
        self.assertTrue(issubclass(CacheError, FingerprintingError))
        self.assertTrue(issubclass(MetricsCollectionError, FingerprintingError))
    
    def test_exception_raising(self):
        """Test that exceptions can be raised and caught properly"""
        with self.assertRaises(FingerprintingError):
            raise NetworkAnalysisError("Network error")
        
        with self.assertRaises(NetworkAnalysisError):
            raise NetworkAnalysisError("Specific network error")
        
        with self.assertRaises(FingerprintingError):
            raise MLClassificationError("ML error")
        
        with self.assertRaises(FingerprintingError):
            raise CacheError("Cache error")
        
        with self.assertRaises(FingerprintingError):
            raise MetricsCollectionError("Metrics error")


class TestDPIFingerprint(unittest.TestCase):
    """Test DPIFingerprint dataclass"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.sample_fingerprint = DPIFingerprint(
            target="example.com",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.85,
            rst_injection_detected=True,
            http_header_filtering=True,
            dns_hijacking_detected=True,
            supports_ipv6=False
        )
    
    def test_fingerprint_creation(self):
        """Test basic fingerprint creation"""
        fp = DPIFingerprint(target="test.com")
        
        self.assertEqual(fp.target, "test.com")
        self.assertEqual(fp.dpi_type, DPIType.UNKNOWN)
        self.assertEqual(fp.confidence, 0.0)
        self.assertIsInstance(fp.timestamp, float)
        self.assertGreater(fp.timestamp, 0)
    
    def test_fingerprint_with_all_metrics(self):
        """Test fingerprint creation with all metrics"""
        fp = DPIFingerprint(
            target="comprehensive.test",
            dpi_type=DPIType.COMMERCIAL_DPI,
            confidence=0.95,
            # TCP metrics
            rst_injection_detected=True,
            rst_source_analysis="middlebox",
            tcp_window_manipulation=True,
            sequence_number_anomalies=True,
            tcp_options_filtering=True,
            connection_reset_timing=0.05,
            handshake_anomalies=["window_scaling", "timestamp_option"],
            fragmentation_handling="blocked",
            mss_clamping_detected=True,
            tcp_timestamp_manipulation=True,
            # HTTP metrics
            http_header_filtering=True,
            content_inspection_depth=2048,
            user_agent_filtering=True,
            host_header_manipulation=True,
            http_method_restrictions=["PATCH", "DELETE"],
            content_type_filtering=True,
            redirect_injection=True,
            http_response_modification=True,
            keep_alive_manipulation=True,
            chunked_encoding_handling="blocked",
            # DNS metrics
            dns_hijacking_detected=True,
            dns_response_modification=True,
            dns_query_filtering=True,
            doh_blocking=True,
            dot_blocking=True,
            dns_cache_poisoning=True,
            dns_timeout_manipulation=True,
            recursive_resolver_blocking=True,
            dns_over_tcp_blocking=True,
            edns_support=False,
            # Additional metrics
            supports_ipv6=False,
            ip_fragmentation_handling="reassembled",
            packet_size_limitations=1400,
            protocol_whitelist=["HTTP", "HTTPS"],
            geographic_restrictions=True,
            time_based_filtering=True
        )
        
        # Verify all metrics are set correctly
        self.assertEqual(fp.target, "comprehensive.test")
        self.assertEqual(fp.dpi_type, DPIType.COMMERCIAL_DPI)
        self.assertEqual(fp.confidence, 0.95)
        self.assertTrue(fp.rst_injection_detected)
        self.assertEqual(fp.rst_source_analysis, "middlebox")
        self.assertEqual(fp.content_inspection_depth, 2048)
        self.assertEqual(fp.http_method_restrictions, ["PATCH", "DELETE"])
        self.assertTrue(fp.dns_hijacking_detected)
        self.assertEqual(fp.packet_size_limitations, 1400)
        self.assertEqual(fp.protocol_whitelist, ["HTTP", "HTTPS"])
    
    def test_to_dict_serialization(self):
        """Test fingerprint serialization to dictionary"""
        fp = self.sample_fingerprint
        fp_dict = fp.to_dict()
        
        self.assertIsInstance(fp_dict, dict)
        self.assertEqual(fp_dict['target'], "example.com")
        self.assertEqual(fp_dict['dpi_type'], "roskomnadzor_tspu")
        self.assertEqual(fp_dict['confidence'], 0.85)
        self.assertTrue(fp_dict['rst_injection_detected'])
        self.assertTrue(fp_dict['http_header_filtering'])
        self.assertTrue(fp_dict['dns_hijacking_detected'])
        self.assertFalse(fp_dict['supports_ipv6'])
    
    def test_from_dict_deserialization(self):
        """Test fingerprint deserialization from dictionary"""
        fp_dict = {
            'target': 'test.example.com',
            'dpi_type': 'commercial_dpi',
            'confidence': 0.75,
            'rst_injection_detected': True,
            'http_header_filtering': False,
            'dns_hijacking_detected': True,
            'alternative_types': [('roskomnadzor_dpi', 0.6), ('firewall_based', 0.4)]
        }
        
        fp = DPIFingerprint.from_dict(fp_dict)
        
        self.assertEqual(fp.target, 'test.example.com')
        self.assertEqual(fp.dpi_type, DPIType.COMMERCIAL_DPI)
        self.assertEqual(fp.confidence, 0.75)
        self.assertTrue(fp.rst_injection_detected)
        self.assertFalse(fp.http_header_filtering)
        self.assertTrue(fp.dns_hijacking_detected)
        self.assertEqual(len(fp.alternative_types), 2)
        self.assertEqual(fp.alternative_types[0][0], DPIType.ROSKOMNADZOR_DPI)
        self.assertEqual(fp.alternative_types[0][1], 0.6)
    
    def test_json_serialization(self):
        """Test JSON serialization and deserialization"""
        fp = self.sample_fingerprint
        json_str = fp.to_json()
        
        self.assertIsInstance(json_str, str)
        
        # Verify it's valid JSON
        parsed = json.loads(json_str)
        self.assertIsInstance(parsed, dict)
        self.assertEqual(parsed['target'], "example.com")
        
        # Test round-trip
        fp_restored = DPIFingerprint.from_json(json_str)
        self.assertEqual(fp_restored.target, fp.target)
        self.assertEqual(fp_restored.dpi_type, fp.dpi_type)
        self.assertEqual(fp_restored.confidence, fp.confidence)
    
    def test_get_confidence_level(self):
        """Test confidence level calculation"""
        test_cases = [
            (0.1, ConfidenceLevel.VERY_LOW),
            (0.4, ConfidenceLevel.LOW),
            (0.6, ConfidenceLevel.MEDIUM),
            (0.8, ConfidenceLevel.HIGH),
            (0.95, ConfidenceLevel.VERY_HIGH)
        ]
        
        for confidence, expected_level in test_cases:
            fp = DPIFingerprint(target="test.com", confidence=confidence)
            self.assertEqual(fp.get_confidence_level(), expected_level)
    
    def test_get_recommended_strategies(self):
        """Test strategy recommendation based on DPI type"""
        # Test ROSKOMNADZOR_TSPU strategies
        fp = DPIFingerprint(target="test.com", dpi_type=DPIType.ROSKOMNADZOR_TSPU)
        strategies = fp.get_recommended_strategies()
        self.assertIn("tcp_fragmentation", strategies)
        self.assertIn("http_host_header_case", strategies)
        self.assertIn("tls_sni_fragmentation", strategies)
        
        # Test additional strategies based on characteristics
        fp.dns_hijacking_detected = True
        fp.supports_ipv6 = False
        fp.fragmentation_handling = "blocked"
        
        strategies = fp.get_recommended_strategies()
        self.assertIn("dns_over_tls", strategies)
        self.assertIn("ipv6_tunneling", strategies)
        self.assertIn("large_packet_avoidance", strategies)
    
    def test_calculate_evasion_difficulty(self):
        """Test evasion difficulty calculation"""
        # Easy target (no advanced features)
        easy_fp = DPIFingerprint(target="easy.com")
        easy_difficulty = easy_fp.calculate_evasion_difficulty()
        self.assertEqual(easy_difficulty, 0.0)
        
        # Hard target (many advanced features)
        hard_fp = DPIFingerprint(
            target="hard.com",
            rst_injection_detected=True,
            tcp_window_manipulation=True,
            sequence_number_anomalies=True,
            http_header_filtering=True,
            content_inspection_depth=2000,
            dns_hijacking_detected=True,
            doh_blocking=True,
            dot_blocking=True,
            geographic_restrictions=True,
            packet_size_limitations=500
        )
        hard_difficulty = hard_fp.calculate_evasion_difficulty()
        self.assertGreater(hard_difficulty, 0.5)
        self.assertLessEqual(hard_difficulty, 1.0)
    
    def test_merge_with(self):
        """Test fingerprint merging"""
        fp1 = DPIFingerprint(
            target="merge.test",
            dpi_type=DPIType.UNKNOWN,
            confidence=0.3,
            rst_injection_detected=False,
            http_header_filtering=True,
            content_inspection_depth=100,
            handshake_anomalies=["option1"],
            reliability_score=0.5
        )
        
        fp2 = DPIFingerprint(
            target="merge.test",
            dpi_type=DPIType.COMMERCIAL_DPI,
            confidence=0.8,
            rst_injection_detected=True,
            http_header_filtering=False,
            content_inspection_depth=500,
            handshake_anomalies=["option2"],
            reliability_score=0.7
        )
        
        merged = fp1.merge_with(fp2)
        
        # Should use higher confidence classification
        self.assertEqual(merged.dpi_type, DPIType.COMMERCIAL_DPI)
        self.assertEqual(merged.confidence, 0.8)
        
        # Boolean flags should be OR'd
        self.assertTrue(merged.rst_injection_detected)
        self.assertTrue(merged.http_header_filtering)
        
        # Should take maximum inspection depth
        self.assertEqual(merged.content_inspection_depth, 500)
        
        # Lists should be merged
        self.assertIn("option1", merged.handshake_anomalies)
        self.assertIn("option2", merged.handshake_anomalies)
    
    def test_validation(self):
        """Test fingerprint validation"""
        # Valid fingerprint
        valid_fp = DPIFingerprint(
            target="valid.com",
            confidence=0.8,
            reliability_score=0.7,
            content_inspection_depth=1000,
            connection_reset_timing=0.05,
            packet_size_limitations=1400
        )
        errors = valid_fp.validate()
        self.assertEqual(len(errors), 0)
        
        # Invalid fingerprint
        invalid_fp = DPIFingerprint(
            target="",  # Empty target
            confidence=1.5,  # Invalid confidence
            reliability_score=-0.1,  # Invalid reliability
            content_inspection_depth=-100,  # Negative depth
            connection_reset_timing=-1.0,  # Negative timing
            packet_size_limitations=0  # Invalid packet size
        )
        errors = invalid_fp.validate()
        self.assertGreater(len(errors), 0)
        self.assertIn("Target cannot be empty", errors)
        self.assertIn("Confidence must be between 0.0 and 1.0", errors)
        self.assertIn("Reliability score must be between 0.0 and 1.0", errors)
        self.assertIn("Content inspection depth cannot be negative", errors)
        self.assertIn("Connection reset timing cannot be negative", errors)
        self.assertIn("Packet size limitations must be positive", errors)
    
    def test_get_summary(self):
        """Test fingerprint summary generation"""
        fp = DPIFingerprint(
            target="summary.test",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.85
        )
        
        summary = fp.get_summary()
        self.assertIn("Roskomnadzor Tspu", summary)
        self.assertIn("HIGH", summary)
        self.assertIn("/1.0", summary)
    
    def test_alternative_types_handling(self):
        """Test handling of alternative DPI type classifications"""
        fp = DPIFingerprint(
            target="alt.test",
            dpi_type=DPIType.COMMERCIAL_DPI,
            confidence=0.7,
            alternative_types=[
                (DPIType.FIREWALL_BASED, 0.6),
                (DPIType.ISP_TRANSPARENT_PROXY, 0.4)
            ]
        )
        
        # Test serialization with alternative types
        fp_dict = fp.to_dict()
        self.assertEqual(len(fp_dict['alternative_types']), 2)
        self.assertEqual(fp_dict['alternative_types'][0][0], 'firewall_based')
        self.assertEqual(fp_dict['alternative_types'][0][1], 0.6)
        
        # Test deserialization with alternative types
        fp_restored = DPIFingerprint.from_dict(fp_dict)
        self.assertEqual(len(fp_restored.alternative_types), 2)
        self.assertEqual(fp_restored.alternative_types[0][0], DPIType.FIREWALL_BASED)
        self.assertEqual(fp_restored.alternative_types[0][1], 0.6)


if __name__ == '__main__':
    unittest.main()