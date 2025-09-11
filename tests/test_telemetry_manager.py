import unittest
import time
from collections import defaultdict
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.bypass.telemetry.manager import TelemetryManager

class TestTelemetryManager(unittest.TestCase):

    def setUp(self):
        self.tm = TelemetryManager(max_targets=5)

    def test_initialization(self):
        self.assertEqual(self.tm.max_targets, 5)
        self.assertIsNotNone(self.tm._data)
        self.assertEqual(self.tm._data['aggregate']['segments_sent'], 0)

    def test_reset(self):
        self.tm.record_segment_sent("1.1.1.1")
        self.assertNotEqual(self.tm._data['aggregate']['segments_sent'], 0)
        self.tm.reset()
        self.assertEqual(self.tm._data['aggregate']['segments_sent'], 0)

    def test_record_segment_sent(self):
        self.tm.record_segment_sent("1.1.1.1", seq_offset=10, ttl=64, is_fake=False)
        data = self.tm.get_snapshot()

        self.assertEqual(data['aggregate']['segments_sent'], 1)
        self.assertEqual(data['aggregate']['fake_packets_sent'], 0)
        self.assertEqual(data['ttls']['real'][64], 1)
        self.assertEqual(data['seq_offsets'][10], 1)

        target_data = data['per_target']['1.1.1.1']
        self.assertEqual(target_data['segments_sent'], 1)
        self.assertEqual(target_data['ttls_real'][64], 1)
        self.assertEqual(target_data['seq_offsets'][10], 1)

    def test_record_fake_packet(self):
        self.tm.record_fake_packet("2.2.2.2", ttl=2)
        data = self.tm.get_snapshot()

        self.assertEqual(data['aggregate']['fake_packets_sent'], 1)
        self.assertEqual(data['ttls']['fake'][2], 1)

        target_data = data['per_target']['2.2.2.2']
        self.assertEqual(target_data['fake_packets_sent'], 1)
        self.assertEqual(target_data['ttls_fake'][2], 1)

    def test_record_outcome(self):
        # First, ensure the target exists
        self.tm.record_clienthello("3.3.3.3")
        self.tm.record_outcome("3.3.3.3", "ok")
        data = self.tm.get_snapshot()
        target_data = data['per_target']['3.3.3.3']
        self.assertEqual(target_data['last_outcome'], "ok")
        self.assertAlmostEqual(target_data['last_outcome_ts'], time.time(), delta=1)

    def test_cleanup_old_targets(self):
        # Create 6 targets to exceed the max of 5
        for i in range(6):
            target_ip = f"1.1.1.{i}"
            # record_segment_sent is the method that triggers the cleanup
            self.tm.record_segment_sent(target_ip)
            # We need to set a timestamp for the sorting to work as expected
            self.tm.record_outcome(target_ip, "ok")
            time.sleep(0.01)

        data = self.tm.get_snapshot()
        self.assertEqual(len(data['per_target']), 5)

        # The oldest target ("1.1.1.0") should be gone
        self.assertNotIn("1.1.1.0", data['per_target'])
        # The newest target ("1.1.1.5") should be present
        self.assertIn("1.1.1.5", data['per_target'])

    def test_get_snapshot_serialization(self):
        self.tm.record_segment_sent("1.1.1.1", ttl=64)
        data = self.tm.get_snapshot()

        self.assertIsInstance(data['ttls']['fake'], dict)
        self.assertNotIsInstance(data['ttls']['fake'], defaultdict)
        self.assertIsInstance(data['per_target']['1.1.1.1']['ttls_real'], dict)
        self.assertNotIsInstance(data['per_target']['1.1.1.1']['ttls_real'], defaultdict)

if __name__ == '__main__':
    unittest.main()
