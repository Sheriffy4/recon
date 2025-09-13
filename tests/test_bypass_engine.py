import unittest
import sys
import os
import time
import platform
from unittest import mock

# Add project root to path to allow imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock platform-specific modules before importing the code under test
sys.modules['pydivert'] = mock.Mock()
if platform.system() == "Windows":
    from core.bypass.engine.windows_engine import WindowsBypassEngine
from core.bypass.techniques.primitives import BypassTechniques

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

@unittest.skipIf(platform.system() != "Windows", "Windows-only test")
class TestBypassEngineTelemetry(unittest.TestCase):
    def setUp(self):
        from core.bypass.engine.base_engine import EngineConfig
        self.engine = WindowsBypassEngine(config=EngineConfig(debug=False))
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

@unittest.skipIf(platform.system() != "Windows", "Windows-only test")
class TestBypassEngineTTL(unittest.TestCase):
    def setUp(self):
        from core.bypass.engine.base_engine import EngineConfig
        with mock.patch('platform.system', return_value='Windows'):
            self.engine = WindowsBypassEngine(config=EngineConfig(debug=False))
        self.mock_packet = mock.Mock()
        self.mock_packet.dst_addr = "1.2.3.4"
        self.mock_packet.payload = b'\x16\x03\x01\x00\x58\x01\x00\x00\x54' + os.urandom(84)
        self.mock_packet.raw = bytearray(b'\x45\x00\x00\x74' + os.urandom(112))
        self.mock_w = mock.Mock()

    @mock.patch('core.bypass.engine.windows_engine.WindowsBypassEngine._send_aligned_fake_segment')
    @mock.patch('core.bypass.engine.windows_engine.Calibrator.sweep')
    def test_ttl_clamping_for_fakeddisorder(self, mock_sweep, mock_send_aligned):
        """Test that TTL is clamped to 8 for fakeddisorder if it's too high."""
        mock_sweep.return_value = None
        strategy_task = {'type': 'fakeddisorder', 'params': {'ttl': 15}}
        self.engine.apply_bypass(self.mock_packet, self.mock_w, strategy_task)
        self.assertEqual(self.engine.current_params['fake_ttl'], 8)

    @mock.patch('core.bypass.engine.windows_engine.WindowsBypassEngine._send_segments')
    def test_ttl_clamping_for_multisplit(self, mock_send):
        """Test that TTL is clamped to 8 for multisplit if it's too high."""
        strategy_task = {'type': 'multisplit', 'params': {'ttl': 20}}
        self.engine.apply_bypass(self.mock_packet, self.mock_w, strategy_task)
        self.assertEqual(self.engine.current_params['fake_ttl'], 8)

    @mock.patch('core.bypass.engine.windows_engine.WindowsBypassEngine._send_fake_packet')
    @mock.patch('core.bypass.engine.windows_engine.WindowsBypassEngine._send_modified_packet')
    def test_ttl_not_clamped_if_low(self, mock_modified, mock_fake):
        """Test that TTL is not clamped if it is below the threshold."""
        strategy_task = {'type': 'fake', 'params': {'ttl': 5}}
        self.engine.apply_bypass(self.mock_packet, self.mock_w, strategy_task)
        self.assertEqual(self.engine.current_params['fake_ttl'], 5)

    @mock.patch('core.bypass.engine.windows_engine.WindowsBypassEngine._send_fragmented_fallback')
    def test_ttl_not_clamped_for_other_types(self, mock_fallback):
        """Test that TTL is not clamped for attack types not in the clamp list."""
        strategy_task = {'type': 'some_other_attack', 'params': {'ttl': 15}}
        self.engine.apply_bypass(self.mock_packet, self.mock_w, strategy_task)
        self.assertEqual(self.engine.current_params['fake_ttl'], 15)


@unittest.skipIf(platform.system() != "Windows", "Windows-only test")
class TestSendAttackSegments(unittest.TestCase):
    def setUp(self):
        from core.bypass.engine.base_engine import EngineConfig
        with mock.patch('platform.system', return_value='Windows'):
            self.engine = WindowsBypassEngine(config=EngineConfig(debug=False))
        self.mock_w = mock.Mock()

        # Create a realistic-looking packet mock
        self.mock_packet = mock.Mock()
        self.mock_packet.src_addr = "192.168.1.100"
        self.mock_packet.dst_addr = "8.8.8.8"
        self.mock_packet.src_port = 12345
        self.mock_packet.dst_port = 443

        ip_header = b'\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\xb5\xb5\xc0\xa8\x01\x64\x08\x08\x08\x08'
        tcp_header = b'\x30\x39\x01\xbb\x00\x00\x00\x01\x00\x00\x00\x02\x50\x18\xfa\xf0\xfe\x18\x00\x00'
        payload = b"test_payload"
        self.mock_packet.raw = bytearray(ip_header + tcp_header + payload)
        self.mock_packet.payload = payload

        self.engine.current_params = {'fake_ttl': 2}
        self.engine._safe_send_packet = mock.Mock(return_value=True)
        self.engine._inject_md5sig_option = mock.Mock(side_effect=lambda x: x)
        self.engine._tcp_checksum = mock.Mock(return_value=0xABCD)
        self.engine._ip_header_checksum = mock.Mock(return_value=0x1234)

    def test_explicit_ttl(self):
        segments = [(b'data', 0, {'ttl': 123})]
        self.engine._send_attack_segments(self.mock_packet, self.mock_w, segments)
        sent_packet = self.engine._safe_send_packet.call_args[0][1]
        self.assertEqual(sent_packet[8], 123)

    def test_fake_ttl(self):
        segments = [(b'data', 0, {'is_fake': True})]
        self.engine._send_attack_segments(self.mock_packet, self.mock_w, segments)
        sent_packet = self.engine._safe_send_packet.call_args[0][1]
        self.assertEqual(sent_packet[8], 2)

    def test_base_ttl(self):
        segments = [(b'data', 0, {})]
        self.engine._send_attack_segments(self.mock_packet, self.mock_w, segments)
        sent_packet = self.engine._safe_send_packet.call_args[0][1]
        base_ttl = self.mock_packet.raw[8]
        self.assertEqual(sent_packet[8], base_ttl)

    def test_seq_offset(self):
        segments = [(b'data', 10, {'seq_offset': -5})]
        self.engine._send_attack_segments(self.mock_packet, self.mock_w, segments)
        sent_packet = self.engine._safe_send_packet.call_args[0][1]
        base_seq = 1
        expected_seq = (base_seq + 10 - 5) & 0xFFFFFFFF
        sent_seq = int.from_bytes(sent_packet[24:28], 'big')
        self.assertEqual(sent_seq, expected_seq)

    def test_corrupt_sequence(self):
        segments = [(b'data', 0, {'corrupt_sequence': True})]
        self.engine._send_attack_segments(self.mock_packet, self.mock_w, segments)
        sent_packet = self.engine._safe_send_packet.call_args[0][1]
        base_seq = 1
        expected_seq = (base_seq - 10000) & 0xFFFFFFFF
        sent_seq = int.from_bytes(sent_packet[24:28], 'big')
        self.assertEqual(sent_seq, expected_seq)

    def test_tcp_flags(self):
        segments = [(b'data1', 0, {}), (b'data2', 5, {'tcp_flags': 0x19})]
        self.engine._send_attack_segments(self.mock_packet, self.mock_w, segments)

        # First segment should have ACK flag
        sent_packet1 = self.engine._safe_send_packet.call_args_list[0][0][1]
        self.assertEqual(sent_packet1[33], 0x10) # ACK

        # Second segment should have custom flags
        sent_packet2 = self.engine._safe_send_packet.call_args_list[1][0][1]
        self.assertEqual(sent_packet2[33], 0x19) # FIN + PSH + ACK

    def test_last_segment_psh_flag(self):
        segments = [(b'data1', 0, {}), (b'data2', 5, {})]
        self.engine._send_attack_segments(self.mock_packet, self.mock_w, segments)

        # Last segment should have PSH + ACK
        sent_packet = self.engine._safe_send_packet.call_args_list[1][0][1]
        self.assertEqual(sent_packet[33], 0x18) # PSH + ACK

    def test_corrupt_tcp_checksum(self):
        segments = [(b'data', 0, {'corrupt_tcp_checksum': True})]
        self.engine._send_attack_segments(self.mock_packet, self.mock_w, segments)
        sent_packet = self.engine._safe_send_packet.call_args[0][1]
        sent_csum = int.from_bytes(sent_packet[36:38], 'big')
        self.assertEqual(sent_csum, 0xABCD ^ 0xFFFF)

    def test_add_md5sig_option(self):
        segments = [(b'data', 0, {'add_md5sig_option': True})]
        self.engine._send_attack_segments(self.mock_packet, self.mock_w, segments)
        self.engine._inject_md5sig_option.assert_called_once()

    @mock.patch('time.sleep')
    def test_delay_ms(self, mock_sleep):
        segments = [(b'data1', 0, {'delay_ms': 50}), (b'data2', 5, {})]
        self.engine._send_attack_segments(self.mock_packet, self.mock_w, segments)
        mock_sleep.assert_called_once_with(0.05)


if __name__ == '__main__':
    unittest.main()
