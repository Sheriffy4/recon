import unittest
import time
import threading
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.bypass.flow.manager import FlowManager, FlowId

class TestFlowManager(unittest.TestCase):

    def setUp(self):
        self.fm = FlowManager(ttl_sec=0.1)

    def tearDown(self):
        self.fm.shutdown()

    def test_register_flow(self):
        flow_id: FlowId = ("1.1.1.1", 12345, "8.8.8.8", 443)
        strategy = {"type": "test"}

        # Register a new flow
        registered = self.fm.register_flow(flow_id, "example.com", strategy)
        self.assertTrue(registered)
        self.assertTrue(self.fm.is_flow_active(flow_id))

        # Try to register the same flow again
        registered_again = self.fm.register_flow(flow_id, "example.com", strategy)
        self.assertFalse(registered_again)

    def test_get_and_pop_flow(self):
        flow_id: FlowId = ("1.1.1.1", 12345, "8.8.8.8", 443)
        strategy = {"type": "test"}
        self.fm.register_flow(flow_id, "example.com", strategy)

        flow_info = self.fm.get_flow(flow_id)
        self.assertIsNotNone(flow_info)
        self.assertEqual(flow_info.key, "example.com")

        popped_info = self.fm.pop_flow(flow_id)
        self.assertIsNotNone(popped_info)
        self.assertIsNone(self.fm.get_flow(flow_id))
        self.assertFalse(self.fm.is_flow_active(flow_id))

    def test_flow_ttl(self):
        flow_id: FlowId = ("1.1.1.1", 12345, "8.8.8.8", 443)
        strategy = {"type": "test"}
        self.fm.register_flow(flow_id, "example.com", strategy)

        self.assertTrue(self.fm.is_flow_active(flow_id))

        # Wait for TTL to expire
        time.sleep(0.15)

        self.assertFalse(self.fm.is_flow_active(flow_id))
        self.assertIsNone(self.fm.get_flow(flow_id))

    def test_event_management(self):
        flow_id: FlowId = ("1.1.1.1", 12345, "8.8.8.8", 443)

        # Get event for a flow
        event = self.fm.get_event(flow_id)
        self.assertIsInstance(event, threading.Event)
        self.assertFalse(event.is_set())

        # Set outcome, which should trigger the event
        self.fm.set_outcome(flow_id, "ok")
        self.assertTrue(event.wait(timeout=0.1))

        # Check result
        result = self.fm.get_result(flow_id)
        self.assertEqual(result, "ok")

        # Clear event
        self.fm.clear_event(flow_id)
        self.assertFalse(event.is_set())
        self.assertIsNone(self.fm.get_result(flow_id))

    def test_cleanup_old_flows(self):
        # This test relies on the internal timer, so we'll test the manual method
        self.fm.shutdown() # Stop the automatic timer
        self.fm = FlowManager(ttl_sec=10)

        flow_id1: FlowId = ("1.1.1.1", 1, "8.8.8.8", 443)
        flow_id2: FlowId = ("1.1.1.1", 2, "8.8.8.8", 443)
        strategy = {"type": "test"}

        # Register two flows, one with an old timestamp
        self.fm.register_flow(flow_id1, "example.com", strategy)
        with self.fm._lock:
            # Manually set the timestamp to be old
            self.fm._flows[flow_id1].start_ts = time.time() - 40

        self.fm.register_flow(flow_id2, "example.com", strategy)

        self.assertEqual(len(self.fm._flows), 2)

        self.fm.cleanup_old_flows(max_age_sec=30)

        self.assertEqual(len(self.fm._flows), 1)
        self.assertIsNone(self.fm.get_flow(flow_id1))
        self.assertIsNotNone(self.fm.get_flow(flow_id2))


if __name__ == '__main__':
    unittest.main()
