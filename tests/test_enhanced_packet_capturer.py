import unittest
import sys
import os
import time
from unittest import mock

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock scapy before importing the module that uses it
sys.modules['scapy'] = mock.Mock()
sys.modules['scapy.all'] = mock.Mock()
TCP = mock.Mock(name="TCP")
Raw = mock.Mock(name="Raw")
sys.modules['scapy.all'].TCP = TCP
sys.modules['scapy.all'].Raw = Raw

from core.pcap.enhanced_packet_capturer import create_enhanced_packet_capturer, EnhancedPacketCapturer

class ScapyPacketMock:
    def __init__(self, time, layers):
        self.time = time
        self._layers = layers

    def __contains__(self, item):
        return item in self._layers

    def __getitem__(self, item):
        return self._layers[item]

class RawLayerMock:
    def __init__(self, payload):
        self._payload = payload
    def __bytes__(self):
        return self._payload

class TestEnhancedPacketCapturer(unittest.TestCase):

    def test_create_capturer_bpf(self):
        """Tests the factory function for creating BPF filters."""
        target_ips = {"1.1.1.1", "8.8.8.8"}
        capturer = create_enhanced_packet_capturer("test.pcap", target_ips, 443)

        self.assertIn("(host 1.1.1.1 and port 443)", capturer.bpf)
        self.assertIn("(host 8.8.8.8 and port 443)", capturer.bpf)
        self.assertIn(" or ", capturer.bpf)

    def test_time_window_marking(self):
        """Tests that strategy markers correctly create time windows."""
        capturer = EnhancedPacketCapturer("test.pcap")

        capturer.mark_strategy_start("strat1")
        time.sleep(0.1)
        capturer.mark_strategy_start("strat2")
        time.sleep(0.1)
        capturer.mark_strategy_end("strat1")
        time.sleep(0.1)
        capturer.mark_strategy_end("strat2")

        windows = capturer._get_strategy_windows()

        self.assertEqual(len(windows), 2)

        s1_win = next(w for w in windows if w[0] == "strat1")
        self.assertAlmostEqual(s1_win[2] - s1_win[1], 0.2, delta=0.05)

        s2_win = next(w for w in windows if w[0] == "strat2")
        self.assertAlmostEqual(s2_win[2] - s2_win[1], 0.2, delta=0.05)

    @mock.patch('core.pcap.enhanced_packet_capturer.rdpcap')
    def test_analyze_pcap_file(self, mock_rdpcap):
        """Tests the offline PCAP analysis logic."""
        mock_packets = []
        for i in range(10):
            tcp_layer = mock.Mock()
            tcp_layer.flags = 0x10

            payload = b''
            if i == 2:
                payload = b'\x16\x03\x01\x00\x58\x01' + os.urandom(87)
            elif i == 3:
                payload = b'\x16\x03\x03\x00\x30\x02' + os.urandom(46)
            elif i == 6:
                payload = b'\x16\x03\x01\x00\x58\x01' + os.urandom(87)
            elif i == 8:
                tcp_layer.flags = 0x04
                payload = b''
            else:
                payload = os.urandom(20)

            raw_layer = RawLayerMock(payload)
            layers = {TCP: tcp_layer, Raw: raw_layer}

            pkt = ScapyPacketMock(time=float(1000 + i * 0.1), layers=layers)
            mock_packets.append(pkt)

        mock_rdpcap.return_value = mock_packets

        capturer = EnhancedPacketCapturer("dummy.pcap")
        capturer.strategy_markers = {
            1000.15: ('start', 'strat1'),
            1000.45: ('end', 'strat1'),
            1000.55: ('start', 'strat2'),
            1000.85: ('end', 'strat2')
        }

        analysis = capturer.analyze_pcap_file()

        self.assertIn('strat1', analysis)
        self.assertIn('strat2', analysis)

        self.assertEqual(analysis['strat1']['tls_clienthellos'], 1)
        self.assertEqual(analysis['strat1']['tls_serverhellos'], 1)
        self.assertTrue(analysis['strat1']['success_indicator'])
        self.assertEqual(analysis['strat1']['success_score'], 1.0)

        self.assertEqual(analysis['strat2']['tls_clienthellos'], 1)
        self.assertEqual(analysis['strat2']['tls_serverhellos'], 0)
        self.assertEqual(analysis['strat2']['rst_packets'], 1)
        self.assertFalse(analysis['strat2']['success_indicator'])
        self.assertEqual(analysis['strat2']['success_score'], 0.0)

if __name__ == '__main__':
    unittest.main()
