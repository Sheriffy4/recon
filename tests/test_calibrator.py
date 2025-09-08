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
