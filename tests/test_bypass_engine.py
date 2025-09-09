import unittest
import sys
import os
import time
from unittest import mock

# Add project root to path to allow imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock platform-specific modules before importing the code under test
sys.modules['pydivert'] = mock.Mock()
with mock.patch('platform.system', return_value='Windows'):
    from core.bypass_engine import BypassEngine, BypassTechniques

class TestBypassTechniques(unittest.TestCase):

    def test_apply_tlsrec_split_simple(self):
        """Test simple TLS record split."""
        client_hello_header = b'\x16\x03\x01\x00\x58'
        client_hello_body = b'\x01\x00\x00\x54' + os.urandom(88 - 4)
        client_hello = client_hello_header + client_hello_body
        split_pos = 10
        split_payload = BypassTechniques.apply_tlsrec_split(client_hello, split_pos=split_pos)
        self.assertEqual(len(split_payload), 15 + 83)
        self.assertEqual(split_payload[0:5], b'\x16\x03\x01\x00\x0a')
        self.assertEqual(split_payload[5:15], client_hello[5:15])
        self.assertEqual(split_payload[15:20], b'\x16\x03\x01\x00\x4e')
        self.assertEqual(split_payload[20:], client_hello[15:])

    def test_apply_tlsrec_split_with_tail(self):
        """Test TLS record split with extra data at the end."""
        client_hello_header = b'\x16\x03\x01\x00\x58'
        client_hello_body = b'\x01\x00\x00\x54' + os.urandom(88 - 4)
        client_hello = client_hello_header + client_hello_body
        tail = b'\x17\x03\x01\x00\x10' + os.urandom(16)
        payload_with_tail = client_hello + tail
        split_payload = BypassTechniques.apply_tlsrec_split(payload_with_tail, split_pos=20)
        self.assertTrue(split_payload.endswith(tail))
        self.assertEqual(len(split_payload), len(client_hello) + 5 + len(tail))

    def test_apply_tlsrec_split_tls12(self):
        """Test TLS record split for TLS 1.2."""
        client_hello_header = b'\x16\x03\x03\x00\x30'
        client_hello_body = b'\x01\x00\x00\x2c' + os.urandom(48-4)
        client_hello_tls12 = client_hello_header + client_hello_body
        split_payload = BypassTechniques.apply_tlsrec_split(client_hello_tls12, split_pos=5)
        self.assertEqual(split_payload[0:3], b'\x16\x03\x03')
        self.assertEqual(split_payload[10:13], b'\x16\x03\x03')

    def test_apply_tlsrec_split_invalid_split_pos(self):
        """Test that invalid split positions are handled gracefully."""
        client_hello_header = b'\x16\x03\x01\x00\x58'
        client_hello_body = b'\x01\x00\x00\x54' + os.urandom(88-4)
        client_hello = client_hello_header + client_hello_body
        split_payload_large = BypassTechniques.apply_tlsrec_split(client_hello, split_pos=100)
        self.assertEqual(split_payload_large, client_hello)
        split_payload_small = BypassTechniques.apply_tlsrec_split(client_hello, split_pos=0)
        self.assertEqual(split_payload_small, client_hello)

    def test_apply_tlsrec_split_not_tls(self):
        """Test that non-TLS payloads are not modified."""
        http_payload = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        unmodified_payload = BypassTechniques.apply_tlsrec_split(http_payload, split_pos=10)
        self.assertEqual(unmodified_payload, http_payload)

class TestBypassEngineTelemetry(unittest.TestCase):
    def setUp(self):
        self.engine = BypassEngine(debug=False)
        self.engine._telemetry_max_targets = 5

    def test_cleanup_old_telemetry_per_target(self):
        """Tests that old per_target telemetry entries are cleaned up."""
        with self.engine._tlock:
            for i in range(10):
                self.engine._telemetry["per_target"][f"1.1.1.{i}"] = {
                    "last_outcome_ts": time.time() - (10 - i)
                }
        self.assertEqual(len(self.engine._telemetry["per_target"]), 10)
        self.engine._cleanup_old_telemetry()
        with self.engine._tlock:
            self.assertEqual(len(self.engine._telemetry["per_target"]), self.engine._telemetry_max_targets)
            for i in range(5, 10):
                self.assertIn(f"1.1.1.{i}", self.engine._telemetry["per_target"])

    def test_cleanup_old_telemetry_flow_table(self):
        """Tests that old flow_table entries are cleaned up."""
        with self.engine._lock:
            for i in range(5):
                self.engine.flow_table[("1.1.1.1", 100+i, "2.2.2.2", 443)] = {"start_ts": time.time() - 60}
            for i in range(5):
                self.engine.flow_table[("1.1.1.1", 200+i, "2.2.2.2", 443)] = {"start_ts": time.time() - 10}
        self.assertEqual(len(self.engine.flow_table), 10)
        self.engine._cleanup_old_telemetry()
        with self.engine._lock:
            self.assertEqual(len(self.engine.flow_table), 5)
            for i in range(5):
                self.assertIn(("1.1.1.1", 200+i, "2.2.2.2", 443), self.engine.flow_table)

class TestBypassEngineTTL(unittest.TestCase):
    def setUp(self):
        with mock.patch('platform.system', return_value='Windows'):
            from core.bypass_engine import BypassEngine
            self.engine = BypassEngine(debug=False)
        self.mock_packet = mock.Mock()
        self.mock_packet.dst_addr = "1.2.3.4"
        self.mock_packet.payload = b'\x16\x03\x01\x00\x58\x01\x00\x00\x54' + os.urandom(84)
        self.mock_packet.raw = bytearray(b'\x45\x00\x00\x74' + os.urandom(112))
        self.mock_w = mock.Mock()

    @mock.patch('core.bypass_engine.BypassEngine._send_aligned_fake_segment')
    @mock.patch('core.bypass_engine.Calibrator.sweep')
    def test_ttl_clamping_for_fakeddisorder(self, mock_sweep, mock_send_aligned):
        """Test that TTL is clamped to 8 for fakeddisorder if it's too high."""
        mock_sweep.return_value = None
        strategy_task = {'type': 'fakeddisorder', 'params': {'ttl': 15}}
        self.engine.apply_bypass(self.mock_packet, self.mock_w, strategy_task)
        self.assertEqual(self.engine.current_params['fake_ttl'], 8)

    @mock.patch('core.bypass_engine.BypassEngine._send_segments')
    def test_ttl_clamping_for_multisplit(self, mock_send):
        """Test that TTL is clamped to 8 for multisplit if it's too high."""
        strategy_task = {'type': 'multisplit', 'params': {'ttl': 20}}
        self.engine.apply_bypass(self.mock_packet, self.mock_w, strategy_task)
        self.assertEqual(self.engine.current_params['fake_ttl'], 8)

    @mock.patch('core.bypass_engine.BypassEngine._send_fake_packet')
    @mock.patch('core.bypass_engine.BypassEngine._send_modified_packet')
    def test_ttl_not_clamped_if_low(self, mock_modified, mock_fake):
        """Test that TTL is not clamped if it is below the threshold."""
        strategy_task = {'type': 'fake', 'params': {'ttl': 5}}
        self.engine.apply_bypass(self.mock_packet, self.mock_w, strategy_task)
        self.assertEqual(self.engine.current_params['fake_ttl'], 5)

    @mock.patch('core.bypass_engine.BypassEngine._send_fragmented_fallback')
    def test_ttl_not_clamped_for_other_types(self, mock_fallback):
        """Test that TTL is not clamped for attack types not in the clamp list."""
        strategy_task = {'type': 'some_other_attack', 'params': {'ttl': 15}}
        self.engine.apply_bypass(self.mock_packet, self.mock_w, strategy_task)
        self.assertEqual(self.engine.current_params['fake_ttl'], 15)


if __name__ == '__main__':
    unittest.main()
