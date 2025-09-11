import unittest
import sys
import os
import time
from unittest import mock

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock platform-specific modules before importing the code under test
sys.modules["pydivert"] = mock.Mock()
with mock.patch("platform.system", return_value="Windows"):
    from core.bypass_engine import BypassEngine
    from core.bypass.engine.windows_engine import WindowsBypassEngine
    from core.bypass.techniques.primitives import BypassTechniques


class TestBypassTechniques(unittest.TestCase):
    # This class remains valid as it tests the static methods of BypassTechniques
    def test_apply_tlsrec_split_simple(self):
        """Test simple TLS record split."""
        client_hello_header = b"\x16\x03\x01\x00\x58"
        client_hello_body = b"\x01\x00\x00\x54" + os.urandom(88 - 4)
        client_hello = client_hello_header + client_hello_body
        split_pos = 10
        split_payload = BypassTechniques.apply_tlsrec_split(
            client_hello, split_pos=split_pos
        )
        self.assertEqual(len(split_payload), 15 + 83)
        self.assertEqual(split_payload[0:5], b"\x16\x03\x01\x00\x0a")
        self.assertEqual(split_payload[5:15], client_hello[5:15])
        self.assertEqual(split_payload[15:20], b"\x16\x03\x01\x00\x4e")
        self.assertEqual(split_payload[20:], client_hello[15:])


class TestBypassEngineWrapper(unittest.TestCase):
    """
    Tests for the backward-compatible BypassEngine wrapper.
    """

    def setUp(self):
        with mock.patch("platform.system", return_value="Windows"):
            self.engine = BypassEngine(debug=False)
            self.win_engine = self.engine._engine

    def test_wrapper_initialization(self):
        """Test that the wrapper initializes the WindowsBypassEngine."""
        self.assertIsInstance(self.win_engine, WindowsBypassEngine)
        self.assertEqual(self.engine.logger, self.win_engine.logger)

    def test_start_stop_delegation(self):
        """Test that start and stop calls are delegated."""
        self.win_engine.start = mock.Mock()
        self.win_engine.stop = mock.Mock()

        self.engine.start(set(), {})
        self.win_engine.start.assert_called_once()

        self.engine.stop()
        self.win_engine.stop.assert_called_once()

    def test_telemetry_snapshot_delegation(self):
        """Test that get_telemetry_snapshot is delegated."""
        self.win_engine.get_telemetry_snapshot = mock.Mock(return_value={"test": "ok"})
        result = self.engine.get_telemetry_snapshot()
        self.win_engine.get_telemetry_snapshot.assert_called_once()
        self.assertEqual(result, {"test": "ok"})

    def test_legacy_attribute_access(self):
        """
        Test that legacy attributes point to the new component's data
        for backward compatibility.
        """
        self.assertIs(self.engine.stats, self.win_engine.stats)
        self.assertIs(self.engine.current_params, self.win_engine.current_params)
        self.assertIs(self.engine._telemetry, self.win_engine.telemetry._data)
        self.assertIs(self.engine._tlock, self.win_engine.telemetry._lock)
        self.assertIs(self.engine.flow_table, self.win_engine.flow_manager._flows)


class TestWindowsBypassEngine(unittest.TestCase):
    """
    Tests for the new WindowsBypassEngine component.
    """

    def setUp(self):
        with mock.patch("platform.system", return_value="Windows"):
            self.engine = WindowsBypassEngine(debug=False)
        self.mock_packet = mock.Mock()
        self.mock_packet.dst_addr = "1.2.3.4"
        self.mock_packet.payload = b"\x16\x03\x01\x00\x58\x01\x00\x00\x54" + os.urandom(
            84
        )
        self.mock_packet.raw = bytearray(b"\x45\x00\x00\x74" + os.urandom(112))
        self.mock_w = mock.Mock()

    def test_apply_bypass_with_registry(self):
        """
        Test that apply_bypass correctly uses the TechniqueRegistry.
        """
        strategy = {"type": "fakeddisorder", "params": {}}
        mock_result = mock.Mock()
        mock_result.segments = [("payload", 0, {})]
        mock_result.metadata = {"overlap_size": 100}

        self.engine.technique_registry.apply_technique = mock.Mock(return_value=mock_result)
        self.engine._send_attack_segments = mock.Mock(return_value=True)
        self.engine.telemetry.record_overlap = mock.Mock()

        self.engine.apply_bypass(self.mock_packet, self.mock_w, strategy)

        self.engine.technique_registry.apply_technique.assert_called_once_with(
            "fakeddisorder", mock.ANY, mock.ANY
        )
        self.engine._send_attack_segments.assert_called_once_with(
            self.mock_packet, self.mock_w, mock_result.segments
        )
        self.engine.telemetry.record_overlap.assert_called_once_with(100)

    @mock.patch("core.bypass.engine.windows_engine.pydivert")
    def test_inbound_observer_outcome(self, mock_pydivert):
        """
        Test that the inbound observer correctly records outcomes.
        """
        # Setup mocks for the observer loop
        mock_w = mock.Mock()
        mock_pydivert.WinDivert.return_value.__enter__.return_value = mock_w

        server_hello_pkt = mock.Mock()
        server_hello_pkt.payload = b'\x16\x03\x03\x00\x02\x02\x28' # ServerHello
        server_hello_pkt.tcp.rst = False
        server_hello_pkt.dst_addr = "1.1.1.1"
        server_hello_pkt.dst_port = 12345
        server_hello_pkt.src_addr = "8.8.8.8"
        server_hello_pkt.src_port = 443

        rst_pkt = mock.Mock()
        rst_pkt.payload = b''
        rst_pkt.tcp.rst = True
        rst_pkt.dst_addr = "1.1.1.1"
        rst_pkt.dst_port = 12346
        rst_pkt.src_addr = "8.8.8.8"
        rst_pkt.src_port = 443

        mock_w.recv.side_effect = [server_hello_pkt, rst_pkt, None]

        self.engine.flow_manager.set_outcome = mock.Mock()
        self.engine.telemetry.record_outcome = mock.Mock()
        self.engine.telemetry.record_serverhello = mock.Mock()
        self.engine.telemetry.record_rst = mock.Mock()

        # Run observer in a thread
        self.engine.running = True
        observer_thread = self.engine._start_inbound_observer()

        # Give the thread a moment to run and exit
        time.sleep(0.1)
        self.engine.running = False
        observer_thread.join()

        # Check if outcomes were recorded
        self.engine.telemetry.record_serverhello.assert_called_once()
        self.engine.telemetry.record_rst.assert_called_once()

        self.assertEqual(self.engine.flow_manager.set_outcome.call_count, 2)
        self.assertEqual(self.engine.telemetry.record_outcome.call_count, 2)


if __name__ == "__main__":
    unittest.main()
