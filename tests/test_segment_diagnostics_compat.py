#!/usr/bin/env python3
"""
Test backward compatibility facade for SegmentDiagnostics.

Ensures that CLI tooling can use SegmentDiagnostics with the expected interface.
"""

import unittest


class TestSegmentDiagnosticsCompat(unittest.TestCase):
    """Test SegmentDiagnostics facade compatibility."""

    def test_segment_diagnostics_facade_exists_and_works(self):
        """Test that SegmentDiagnostics facade exists and provides CLI-compatible interface."""
        from core.bypass.diagnostics.segment_diagnostics import SegmentDiagnostics

        d = SegmentDiagnostics()
        
        # Old CLI-style call: one argument (session_id only)
        d.start_session("conn_1")
        
        # Get snapshot without ending session
        snap = d.get_session_summary("conn_1")
        
        self.assertIsInstance(snap, dict)
        self.assertEqual(snap.get("session_id"), "conn_1")
        self.assertEqual(snap.get("connection_id"), "conn_1")
        self.assertEqual(snap.get("total_segments"), 0)
        self.assertEqual(snap.get("successful_segments"), 0)
        self.assertEqual(snap.get("failed_segments"), 0)

    def test_segment_diagnostics_with_explicit_connection_id(self):
        """Test that SegmentDiagnostics can accept explicit connection_id."""
        from core.bypass.diagnostics.segment_diagnostics import SegmentDiagnostics

        d = SegmentDiagnostics()
        
        # New style: explicit connection_id
        d.start_session("session_1", "connection_1")
        
        snap = d.get_session_summary("session_1")
        
        self.assertEqual(snap.get("session_id"), "session_1")
        self.assertEqual(snap.get("connection_id"), "connection_1")

    def test_segment_diagnostics_logger_still_works(self):
        """Test that underlying SegmentDiagnosticLogger still works with 2 args."""
        from core.bypass.diagnostics.segment_diagnostics import SegmentDiagnosticLogger

        logger = SegmentDiagnosticLogger()
        
        # Logger requires both arguments
        logger.start_session("session_2", "connection_2")
        
        snap = logger.get_session_snapshot("session_2")
        
        self.assertEqual(snap.get("session_id"), "session_2")
        self.assertEqual(snap.get("connection_id"), "connection_2")


if __name__ == "__main__":
    unittest.main()
