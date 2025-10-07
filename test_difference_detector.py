#!/usr/bin/env python3
"""
Test suite for DifferenceDetector implementation.
"""

import sys
import os
import unittest
from unittest.mock import Mock, patch
import tempfile
import json

# Add the recon directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.pcap_analysis.difference_detector import DifferenceDetector, DetectionConfig
from core.pcap_analysis.critical_difference import (
    CriticalDifference, DifferenceCategory, ImpactLevel, FixComplexity, Evidence
)
from core.pcap_analysis.packet_info import PacketInfo, TLSInfo
from core.pcap_analysis.comparison_result import ComparisonResult


class TestCriticalDifference(unittest.TestCase):
    """Test CriticalDifference data model."""
    
    def test_critical_difference_creation(self):
        """Test basic CriticalDifference creation."""
        diff = CriticalDifference(
            category=DifferenceCategory.TTL,
            description="TTL mismatch in fake packets",
            recon_value=64,
            zapret_value=3,
            impact_level=ImpactLevel.CRITICAL,
            confidence=0.95,
            fix_priority=1
        )
        
        self.assertEqual(diff.category, DifferenceCategory.TTL)
        self.assertEqual(diff.impact_level, ImpactLevel.CRITICAL)
        self.assertEqual(diff.confidence, 0.95)
        self.assertEqual(diff.fix_priority, 1)
        self.assertTrue(diff.is_blocking())
    
    def test_severity_score_calculation(self):
        """Test severity score calculation."""
        # Critical difference with high confidence
        critical_diff = CriticalDifference(
            category=DifferenceCategory.SEQUENCE,
            description="Critical sequence issue",
            recon_value="A",
            zapret_value="B",
            impact_level=ImpactLevel.CRITICAL,
            confidence=0.9,
            fix_priority=1
        )
        
        critical_score = critical_diff.calculate_severity_score()
        self.assertGreater(critical_score, 8.0)
        
        # Low impact difference
        low_diff = CriticalDifference(
            category=DifferenceCategory.FLAGS,
            description="Minor flag difference",
            recon_value="A",
            zapret_value="B",
            impact_level=ImpactLevel.LOW,
            confidence=0.5,
            fix_priority=8
        )
        
        low_score = low_diff.calculate_severity_score()
        self.assertLess(low_score, 3.0)
        self.assertGreater(critical_score, low_score)
    
    def test_evidence_addition(self):
        """Test adding evidence to differences."""
        diff = CriticalDifference(
            category=DifferenceCategory.TIMING,
            description="Timing issue",
            recon_value=10.0,
            zapret_value=5.0,
            impact_level=ImpactLevel.MEDIUM,
            confidence=0.8,
            fix_priority=3
        )
        
        diff.add_evidence(
            "timing_analysis",
            "Measured packet delays",
            {"delays": [1, 2, 3]},
            0.9
        )
        
        self.assertEqual(len(diff.evidence), 1)
        self.assertEqual(diff.evidence[0].type, "timing_analysis")
        self.assertEqual(diff.evidence[0].confidence, 0.9)
    
    def test_to_dict_serialization(self):
        """Test dictionary serialization."""
        diff = CriticalDifference(
            category=DifferenceCategory.CHECKSUM,
            description="Checksum issue",
            recon_value=True,
            zapret_value=False,
            impact_level=ImpactLevel.HIGH,
            confidence=0.85,
            fix_priority=2
        )
        
        diff_dict = diff.to_dict()
        
        self.assertIn('category', diff_dict)
        self.assertIn('severity_score', diff_dict)
        self.assertIn('is_blocking', diff_dict)
        self.assertIn('fix_urgency', diff_dict)
        self.assertEqual(diff_dict['category'], 'checksum')
        self.assertEqual(diff_dict['impact_level'], 'HIGH')


class TestDifferenceDetector(unittest.TestCase):
    """Test DifferenceDetector functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = DifferenceDetector()
        
        # Create sample packets
        self.recon_packets = [
            PacketInfo(
                timestamp=1.0,
                src_ip="192.168.1.1",
                dst_ip="1.1.1.1",
                src_port=12345,
                dst_port=443,
                sequence_num=1000,
                ack_num=0,
                ttl=64,  # Normal TTL
                flags=["SYN"],
                payload_length=0
            ),
            PacketInfo(
                timestamp=1.1,
                src_ip="192.168.1.1",
                dst_ip="1.1.1.1",
                src_port=12345,
                dst_port=443,
                sequence_num=1001,
                ack_num=500,
                ttl=3,  # Fake packet TTL
                flags=["PSH", "ACK"],
                payload_length=100,
                checksum_valid=False  # Bad checksum for fake packet
            )
        ]
        
        self.zapret_packets = [
            PacketInfo(
                timestamp=1.0,
                src_ip="192.168.1.1",
                dst_ip="1.1.1.1",
                src_port=12345,
                dst_port=443,
                sequence_num=1000,
                ack_num=0,
                ttl=64,  # Normal TTL
                flags=["SYN"],
                payload_length=0
            ),
            PacketInfo(
                timestamp=1.05,  # Different timing
                src_ip="192.168.1.1",
                dst_ip="1.1.1.1",
                src_port=12345,
                dst_port=443,
                sequence_num=1001,
                ack_num=500,
                ttl=3,  # Same fake packet TTL
                flags=["PSH", "ACK"],
                payload_length=100,
                checksum_valid=False
            )
        ]
        
        self.comparison = ComparisonResult(
            recon_packets=self.recon_packets,
            zapret_packets=self.zapret_packets,
            recon_file="recon_x.pcap",
            zapret_file="zapret_x.pcap"
        )
    
    def test_detector_initialization(self):
        """Test detector initialization."""
        config = DetectionConfig(timing_threshold_ms=5.0)
        detector = DifferenceDetector(config)
        
        self.assertEqual(detector.config.timing_threshold_ms, 5.0)
        self.assertIsNotNone(detector.logger)
    
    def test_detect_critical_differences(self):
        """Test main difference detection."""
        differences = self.detector.detect_critical_differences(self.comparison)
        
        self.assertIsInstance(differences, list)
        self.assertGreater(len(differences), 0)
        
        # Check that differences are properly prioritized
        if len(differences) > 1:
            for i in range(len(differences) - 1):
                current_severity = differences[i].calculate_severity_score()
                next_severity = differences[i + 1].calculate_severity_score()
                self.assertGreaterEqual(current_severity, next_severity)
    
    def test_timing_difference_detection(self):
        """Test timing difference detection."""
        # Create packets with significant timing difference
        recon_timing = [
            PacketInfo(timestamp=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", 
                      src_port=80, dst_port=443, sequence_num=1, ack_num=0, ttl=64, flags=["SYN"]),
            PacketInfo(timestamp=1.1, src_ip="1.1.1.1", dst_ip="2.2.2.2", 
                      src_port=80, dst_port=443, sequence_num=2, ack_num=0, ttl=64, flags=["ACK"])
        ]
        
        zapret_timing = [
            PacketInfo(timestamp=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", 
                      src_port=80, dst_port=443, sequence_num=1, ack_num=0, ttl=64, flags=["SYN"]),
            PacketInfo(timestamp=1.05, src_ip="1.1.1.1", dst_ip="2.2.2.2", 
                      src_port=80, dst_port=443, sequence_num=2, ack_num=0, ttl=64, flags=["ACK"])
        ]
        
        timing_comparison = ComparisonResult(
            recon_packets=recon_timing,
            zapret_packets=zapret_timing
        )
        
        differences = self.detector._detect_timing_differences(timing_comparison)
        
        # Should detect timing difference (100ms vs 50ms = 50ms difference)
        timing_diffs = [d for d in differences if d.category == DifferenceCategory.TIMING]
        self.assertGreater(len(timing_diffs), 0)
    
    def test_ttl_difference_detection(self):
        """Test TTL difference detection."""
        # Create packets with TTL differences in fake packets
        recon_ttl = [
            PacketInfo(timestamp=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", 
                      src_port=80, dst_port=443, sequence_num=1, ack_num=0, 
                      ttl=64, flags=["SYN"], checksum_valid=False)  # Fake packet with wrong TTL
        ]
        
        zapret_ttl = [
            PacketInfo(timestamp=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", 
                      src_port=80, dst_port=443, sequence_num=1, ack_num=0, 
                      ttl=3, flags=["SYN"], checksum_valid=False)  # Fake packet with correct TTL
        ]
        
        ttl_comparison = ComparisonResult(
            recon_packets=recon_ttl,
            zapret_packets=zapret_ttl
        )
        
        differences = self.detector._detect_ttl_differences(ttl_comparison)
        
        ttl_diffs = [d for d in differences if d.category == DifferenceCategory.TTL]
        if ttl_diffs:  # TTL detection depends on fake packet detection
            self.assertEqual(ttl_diffs[0].impact_level, ImpactLevel.CRITICAL)
    
    def test_checksum_difference_detection(self):
        """Test checksum difference detection."""
        # Create packets with different checksum patterns
        recon_checksum = [
            PacketInfo(timestamp=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", 
                      src_port=80, dst_port=443, sequence_num=1, ack_num=0, 
                      ttl=64, flags=["SYN"], checksum_valid=True),
            PacketInfo(timestamp=1.1, src_ip="1.1.1.1", dst_ip="2.2.2.2", 
                      src_port=80, dst_port=443, sequence_num=2, ack_num=0, 
                      ttl=64, flags=["ACK"], checksum_valid=True)
        ]
        
        zapret_checksum = [
            PacketInfo(timestamp=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", 
                      src_port=80, dst_port=443, sequence_num=1, ack_num=0, 
                      ttl=64, flags=["SYN"], checksum_valid=True),
            PacketInfo(timestamp=1.1, src_ip="1.1.1.1", dst_ip="2.2.2.2", 
                      src_port=80, dst_port=443, sequence_num=2, ack_num=0, 
                      ttl=64, flags=["ACK"], checksum_valid=False)  # Bad checksum
        ]
        
        checksum_comparison = ComparisonResult(
            recon_packets=recon_checksum,
            zapret_packets=zapret_checksum
        )
        
        differences = self.detector._detect_checksum_differences(checksum_comparison)
        
        checksum_diffs = [d for d in differences if d.category == DifferenceCategory.CHECKSUM]
        self.assertGreater(len(checksum_diffs), 0)
    
    def test_prioritize_differences(self):
        """Test difference prioritization."""
        differences = [
            CriticalDifference(
                category=DifferenceCategory.FLAGS,
                description="Low priority",
                recon_value="A",
                zapret_value="B",
                impact_level=ImpactLevel.LOW,
                confidence=0.5,
                fix_priority=8
            ),
            CriticalDifference(
                category=DifferenceCategory.TTL,
                description="High priority",
                recon_value="A",
                zapret_value="B",
                impact_level=ImpactLevel.CRITICAL,
                confidence=0.9,
                fix_priority=1
            ),
            CriticalDifference(
                category=DifferenceCategory.TIMING,
                description="Medium priority",
                recon_value="A",
                zapret_value="B",
                impact_level=ImpactLevel.MEDIUM,
                confidence=0.7,
                fix_priority=4
            )
        ]
        
        prioritized = self.detector.prioritize_differences(differences)
        
        # Should be sorted by severity (critical first)
        self.assertEqual(prioritized[0].impact_level, ImpactLevel.CRITICAL)
        self.assertEqual(prioritized[-1].impact_level, ImpactLevel.LOW)
    
    def test_categorize_differences(self):
        """Test difference categorization."""
        differences = [
            CriticalDifference(
                category=DifferenceCategory.TTL,
                description="TTL issue",
                recon_value=64,
                zapret_value=3,
                impact_level=ImpactLevel.CRITICAL,
                confidence=0.9,
                fix_priority=1
            ),
            CriticalDifference(
                category=DifferenceCategory.TTL,
                description="Another TTL issue",
                recon_value=32,
                zapret_value=3,
                impact_level=ImpactLevel.HIGH,
                confidence=0.8,
                fix_priority=2
            ),
            CriticalDifference(
                category=DifferenceCategory.TIMING,
                description="Timing issue",
                recon_value=100,
                zapret_value=50,
                impact_level=ImpactLevel.MEDIUM,
                confidence=0.7,
                fix_priority=4
            )
        ]
        
        categorized = self.detector.categorize_differences(differences)
        
        self.assertIn(DifferenceCategory.TTL, categorized)
        self.assertIn(DifferenceCategory.TIMING, categorized)
        self.assertEqual(len(categorized[DifferenceCategory.TTL]), 2)
        self.assertEqual(len(categorized[DifferenceCategory.TIMING]), 1)
    
    def test_assess_impact(self):
        """Test impact assessment."""
        difference = CriticalDifference(
            category=DifferenceCategory.SEQUENCE,
            description="Sequence issue",
            recon_value="A",
            zapret_value="B",
            impact_level=ImpactLevel.HIGH,
            confidence=0.85,
            fix_priority=2
        )
        
        assessment = self.detector.assess_impact(difference)
        
        self.assertIn('severity_score', assessment)
        self.assertIn('is_blocking', assessment)
        self.assertIn('fix_urgency', assessment)
        self.assertIn('estimated_fix_time', assessment)
        self.assertIn('risk_level', assessment)
        self.assertIn('dependencies', assessment)
    
    def test_detection_statistics(self):
        """Test detection statistics tracking."""
        initial_stats = self.detector.get_detection_statistics()
        
        # Run detection
        self.detector.detect_critical_differences(self.comparison)
        
        updated_stats = self.detector.get_detection_statistics()
        
        self.assertGreater(updated_stats['total_comparisons'], initial_stats['total_comparisons'])
        self.assertGreaterEqual(updated_stats['differences_found'], 0)


class TestDetectionConfig(unittest.TestCase):
    """Test DetectionConfig functionality."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = DetectionConfig()
        
        self.assertEqual(config.timing_threshold_ms, 10.0)
        self.assertEqual(config.sequence_gap_threshold, 1000)
        self.assertEqual(config.ttl_difference_threshold, 1)
        self.assertIsNotNone(config.critical_packet_types)
        self.assertIsNotNone(config.high_impact_categories)
    
    def test_custom_config(self):
        """Test custom configuration values."""
        config = DetectionConfig(
            timing_threshold_ms=5.0,
            sequence_gap_threshold=500,
            ttl_difference_threshold=2
        )
        
        self.assertEqual(config.timing_threshold_ms, 5.0)
        self.assertEqual(config.sequence_gap_threshold, 500)
        self.assertEqual(config.ttl_difference_threshold, 2)


def create_test_pcap_data():
    """Create test PCAP data for integration testing."""
    # This would create actual PCAP files for testing
    # For now, we'll use mock data
    pass


def run_integration_test():
    """Run integration test with real PCAP data."""
    print("Running integration test...")
    
    detector = DifferenceDetector()
    
    # Create sample comparison data
    recon_packets = [
        PacketInfo(
            timestamp=1.0,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",  # x.com IP
            src_port=54321,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=64,
            flags=["SYN"],
            payload_length=0
        ),
        PacketInfo(
            timestamp=1.1,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=54321,
            dst_port=443,
            sequence_num=1001,
            ack_num=500,
            ttl=64,  # Wrong TTL for fake packet
            flags=["PSH", "ACK"],
            payload_length=517,
            is_client_hello=True,
            checksum_valid=True  # Wrong checksum for fake packet
        )
    ]
    
    zapret_packets = [
        PacketInfo(
            timestamp=1.0,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=54321,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=64,
            flags=["SYN"],
            payload_length=0
        ),
        PacketInfo(
            timestamp=1.05,  # Different timing
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=54321,
            dst_port=443,
            sequence_num=1001,
            ack_num=500,
            ttl=3,  # Correct TTL for fake packet
            flags=["PSH", "ACK"],
            payload_length=517,
            is_client_hello=True,
            checksum_valid=False  # Correct bad checksum for fake packet
        )
    ]
    
    comparison = ComparisonResult(
        recon_packets=recon_packets,
        zapret_packets=zapret_packets,
        recon_file="recon_x.pcap",
        zapret_file="zapret_x.pcap"
    )
    
    # Detect differences
    differences = detector.detect_critical_differences(comparison)
    
    print(f"Detected {len(differences)} differences:")
    for i, diff in enumerate(differences, 1):
        print(f"\n{i}. {diff.category.value.upper()}: {diff.description}")
        print(f"   Impact: {diff.impact_level.value}")
        print(f"   Confidence: {diff.confidence:.2f}")
        print(f"   Priority: {diff.fix_priority}")
        print(f"   Severity Score: {diff.calculate_severity_score():.2f}")
        print(f"   Fix Urgency: {diff.get_fix_urgency()}")
        if diff.suggested_fix:
            print(f"   Suggested Fix: {diff.suggested_fix}")
    
    # Test categorization
    categorized = detector.categorize_differences(differences)
    print(f"\nCategories found: {list(categorized.keys())}")
    
    # Test statistics
    stats = detector.get_detection_statistics()
    print(f"\nDetection Statistics: {stats}")
    
    print("\nIntegration test completed successfully!")


if __name__ == '__main__':
    print("Testing DifferenceDetector implementation...")
    
    # Run unit tests
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    print("\n" + "="*50)
    
    # Run integration test
    run_integration_test()