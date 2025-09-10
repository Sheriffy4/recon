import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from packet_pattern_validator import PacketPatternValidator, PacketAnalysis

class TestPacketPatternValidatorComparison(unittest.TestCase):

    def setUp(self):
        # Prevent logging to file during tests by mocking the logger setup
        with patch('packet_pattern_validator.logging.getLogger') as mock_log:
            self.validator = PacketPatternValidator()
            self.validator.close_logging = MagicMock()

    @patch('packet_pattern_validator.PacketPatternValidator.analyze_pcap_file')
    def test_ttl_normalization_match(self, mock_analyze):
        """Test that bucketized TTL values are considered a match."""
        recon_analysis = PacketAnalysis(total_packets=3, fake_packets=1, real_packets=2, split_packets=1,
                                      ttl_values=[8, 32, 64, 96, 128, 200], sequence_overlaps=[], split_positions=[],
                                      attack_pattern="fakedisorder", patterns=[])
        zapret_analysis = PacketAnalysis(total_packets=3, fake_packets=1, real_packets=2, split_packets=1,
                                       ttl_values=[1, 30, 60, 90, 120, 250], sequence_overlaps=[], split_positions=[],
                                       attack_pattern="fakedisorder", patterns=[])
        mock_analyze.side_effect = [recon_analysis, zapret_analysis]

        result = self.validator.compare_packet_patterns("r.pcap", "z.pcap", "cmd")

        self.assertEqual(len(result.minor_differences), 0)
        self.assertTrue(result.pattern_match_score > 0.4)

    @patch('packet_pattern_validator.PacketPatternValidator.analyze_pcap_file')
    def test_ttl_normalization_mismatch(self, mock_analyze):
        """Test that different bucketized TTLs are a minor difference."""
        recon_analysis = PacketAnalysis(total_packets=3, fake_packets=1, real_packets=2, split_packets=1,
                                      ttl_values=[10, 40, 70], sequence_overlaps=[], split_positions=[],
                                      attack_pattern="fakedisorder", patterns=[])
        zapret_analysis = PacketAnalysis(total_packets=3, fake_packets=1, real_packets=2, split_packets=1,
                                       ttl_values=[8, 32, 64], sequence_overlaps=[], split_positions=[],
                                       attack_pattern="fakedisorder", patterns=[])
        mock_analyze.side_effect = [recon_analysis, zapret_analysis]

        result = self.validator.compare_packet_patterns("r.pcap", "z.pcap", "cmd")

        self.assertEqual(len(result.minor_differences), 1)
        self.assertIn("TTL bucket difference", result.minor_differences[0])

    @patch('packet_pattern_validator.PacketPatternValidator.analyze_pcap_file')
    def test_split_pos_tolerance_match(self, mock_analyze):
        """Test that split positions within tolerance are a match."""
        recon_analysis = PacketAnalysis(total_packets=2, fake_packets=0, real_packets=2, split_packets=1,
                                      ttl_values=[64, 64], sequence_overlaps=[], split_positions=[76],
                                      attack_pattern="fakedisorder", patterns=[])
        zapret_analysis = PacketAnalysis(total_packets=2, fake_packets=0, real_packets=2, split_packets=1,
                                       ttl_values=[64, 64], sequence_overlaps=[], split_positions=[76],
                                       attack_pattern="fakedisorder", patterns=[])
        mock_analyze.side_effect = [recon_analysis, zapret_analysis]

        result = self.validator.compare_packet_patterns("r.pcap", "z.pcap", "cmd")

        self.assertEqual(len(result.critical_differences), 0)
        self.assertEqual(len(result.minor_differences), 0)

    @patch('packet_pattern_validator.PacketPatternValidator.analyze_pcap_file')
    def test_split_pos_tolerance_mismatch(self, mock_analyze):
        """Test that split positions outside tolerance are a minor mismatch."""
        recon_analysis = PacketAnalysis(total_packets=2, fake_packets=0, real_packets=2, split_packets=1,
                                      ttl_values=[64, 64], sequence_overlaps=[], split_positions=[70],
                                      attack_pattern="fakedisorder", patterns=[])
        zapret_analysis = PacketAnalysis(total_packets=2, fake_packets=0, real_packets=2, split_packets=1,
                                       ttl_values=[64, 64], sequence_overlaps=[], split_positions=[80],
                                       attack_pattern="fakedisorder", patterns=[])
        mock_analyze.side_effect = [recon_analysis, zapret_analysis]

        result = self.validator.compare_packet_patterns("r.pcap", "z.pcap", "cmd")

        self.assertEqual(len(result.critical_differences), 0)
        self.assertEqual(len(result.minor_differences), 1)
        self.assertIn("Split positions mismatch", result.minor_differences[0])

if __name__ == '__main__':
    unittest.main()
