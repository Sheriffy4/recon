import unittest
import sys
import os
import time
from unittest import mock

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.calibration.calibrator import Calibrator, CalibCandidate

class TestCalibrator(unittest.TestCase):
    def test_estimate_split_pos_from_ch_short(self):
        payload = b"A" * 40
        sp = Calibrator.estimate_split_pos_from_ch(payload)
        self.assertTrue(20 <= sp <= 40)

    def test_estimate_split_pos_from_ch_long(self):
        payload = b"A" * 100
        sp = Calibrator.estimate_split_pos_from_ch(payload)
        self.assertEqual(sp, 76)

    def test_estimate_overlap_size(self):
        ov = Calibrator.estimate_overlap_size(50, 60, 40)
        self.assertEqual(ov, 40)
        ov2 = Calibrator.estimate_overlap_size(200, 300, 336)
        self.assertEqual(ov2, 200)
        ov3 = Calibrator.estimate_overlap_size(0, 10, 5)
        self.assertEqual(ov3, 0)

    def test_prepare_candidates(self):
        payload = b"A" * 100
        candidates = Calibrator.prepare_candidates(payload)
        self.assertTrue(len(candidates) > 0)
        for c in candidates:
            self.assertTrue(c.split_pos > 0)
            self.assertTrue(c.overlap_size > 0)

    def test_sweep_success(self):
        payload = b"A" * 100
        candidates = [CalibCandidate(50, 40), CalibCandidate(60, 30)]
        ttl_list = [1]
        delays = [2]
        called = []
        def send_func(cand, t, d):
            called.append((cand, t, d))
        def wait_func(timeout=0.25):
            return "ok"
        result = Calibrator.sweep(payload, candidates, ttl_list, delays, send_func, wait_func)
        self.assertEqual(result, candidates[0])
        self.assertEqual(called[0][0], candidates[0])

    def test_sweep_time_budget(self):
        payload = b"A" * 100
        candidates = [CalibCandidate(50, 40)]
        ttl_list = [1]
        delays = [2]
        def send_func(cand, t, d):
            pass
        def wait_func(timeout=0.25):
            return None
        result = Calibrator.sweep(payload, candidates, ttl_list, delays, send_func, wait_func, time_budget_ms=1)
        self.assertIsNone(result)

    def test_sweep_early_stop(self):
        """Tests that Calibrator.sweep stops early on a successful outcome."""

        # Mock payload and candidates
        payload = os.urandom(200)
        candidates = Calibrator.prepare_candidates(payload, initial_split_pos=76)

        # Mock send_func and wait_func
        send_func = mock.Mock()

        # wait_func will return 'ok' on the 3rd call, simulating a ServerHello
        wait_func = mock.Mock(side_effect=[None, None, 'ok', None, None])

        # Run the sweep with a long time budget to ensure it's not the reason for stopping
        best_candidate = Calibrator.sweep(
            payload=payload,
            candidates=candidates,
            ttl_list=[1, 2],
            delays=[1, 2],
            send_func=send_func,
            wait_func=wait_func,
            time_budget_ms=5000
        )

        # We expect a best candidate to be found
        self.assertIsNotNone(best_candidate)

        # The key assertion: check that send_func was not called for all possible combinations.
        # Total combinations = len(candidates) * len(ttl_list) * len(delays)
        # We expect it to stop after the 3rd call to wait_func, which corresponds to the 3rd call to send_func.
        self.assertEqual(send_func.call_count, 3)
        self.assertEqual(wait_func.call_count, 3)

if __name__ == '__main__':
    unittest.main()
