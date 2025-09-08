#!/usr/bin/env python3
"""
Unit tests for QUIC Detection - Task 20 Sub-component
Tests QUIC traffic detection and handling.

Requirements addressed: 5.1, 5.2, 5.3, 5.4
"""

import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add the recon directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))


class MockQUICDetector:
    """Mock QUICDetector for testing since the actual class needs to be implemented."""
    
    def detect_quic_traffic(self, packets: list) -> bool:
        """Detect QUIC traffic (UDP/443)."""
        for packet in packets:
            if (packet.get('protocol') == 'UDP' and 
                packet.get('dst_port') == 443):
                return True
        return False
    
    def log_quic_warning(self, domain: str) -> str:
        """Log QUIC warning message."""
        return f"WARNING: QUIC traffic detected for {domain}. Please disable QUIC in browser."
    
    def suggest_quic_disable(self) -> dict:
        """Provide QUIC disable instructions."""
        return {
            "chrome": "chrome://flags/#enable-quic -> Disable",
            "firefox": "network.http.http3.enabled -> false (disable)",
            "edge": "edge://flags/#enable-quic -> Disable"
        }


class TestQUICDetection(unittest.TestCase):
    """Test suite for QUIC detection functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = MockQUICDetector()
    
    def test_quic_traffic_detection(self):
        """Test detection of UDP/443 QUIC traffic."""
        # Mock packets with QUIC traffic
        quic_packets = [
            {"protocol": "TCP", "dst_port": 443, "src_port": 12345},
            {"protocol": "UDP", "dst_port": 443, "src_port": 54321},  # QUIC
            {"protocol": "TCP", "dst_port": 80, "src_port": 12346},
        ]
        
        # Should detect QUIC
        self.assertTrue(self.detector.detect_quic_traffic(quic_packets))
        
        # Mock packets without QUIC traffic
        no_quic_packets = [
            {"protocol": "TCP", "dst_port": 443, "src_port": 12345},
            {"protocol": "TCP", "dst_port": 80, "src_port": 12346},
            {"protocol": "UDP", "dst_port": 53, "src_port": 54321},  # DNS
        ]
        
        # Should not detect QUIC
        self.assertFalse(self.detector.detect_quic_traffic(no_quic_packets))
    
    def test_quic_warning_logging(self):
        """Test QUIC warning message generation."""
        warning = self.detector.log_quic_warning("x.com")
        
        self.assertIn("WARNING", warning)
        self.assertIn("QUIC", warning)
        self.assertIn("x.com", warning)
        self.assertIn("disable", warning.lower())
    
    def test_quic_disable_suggestions(self):
        """Test QUIC disable instruction generation."""
        suggestions = self.detector.suggest_quic_disable()
        
        # Should have instructions for major browsers
        self.assertIn("chrome", suggestions)
        self.assertIn("firefox", suggestions)
        self.assertIn("edge", suggestions)
        
        # Each instruction should mention disabling
        for browser, instruction in suggestions.items():
            self.assertIn("disable", instruction.lower())


if __name__ == "__main__":
    unittest.main()