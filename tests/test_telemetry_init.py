"""
Tests for telemetry initialization utilities.

This test suite validates telemetry structure initialization.
"""

import time
from collections import defaultdict
from core.bypass.engine.telemetry_init import create_telemetry_structure


class TestTelemetryInitialization:
    """Test telemetry structure initialization."""

    def test_create_telemetry_structure_basic(self):
        """Test basic telemetry structure creation."""
        telemetry = create_telemetry_structure()

        # Verify top-level keys exist
        assert "start_ts" in telemetry
        assert "strategy_key" in telemetry
        assert "aggregate" in telemetry
        assert "ttls" in telemetry
        assert "seq_offsets" in telemetry
        assert "overlaps" in telemetry
        assert "clienthellos" in telemetry
        assert "serverhellos" in telemetry
        assert "rst_count" in telemetry
        assert "packets_captured" in telemetry
        assert "total_retransmissions_detected" in telemetry
        assert "per_target" in telemetry

    def test_start_timestamp(self):
        """Test that start_ts is set to current time."""
        before = time.time()
        telemetry = create_telemetry_structure()
        after = time.time()

        assert before <= telemetry["start_ts"] <= after

    def test_strategy_key_initial_value(self):
        """Test that strategy_key is initially None."""
        telemetry = create_telemetry_structure()
        assert telemetry["strategy_key"] is None

    def test_aggregate_counters(self):
        """Test aggregate counter initialization."""
        telemetry = create_telemetry_structure()

        assert telemetry["aggregate"]["segments_sent"] == 0
        assert telemetry["aggregate"]["fake_packets_sent"] == 0
        assert telemetry["aggregate"]["modified_packets_sent"] == 0
        assert telemetry["aggregate"]["quic_segments_sent"] == 0

    def test_ttls_structure(self):
        """Test TTL structure initialization."""
        telemetry = create_telemetry_structure()

        assert "fake" in telemetry["ttls"]
        assert "real" in telemetry["ttls"]
        assert isinstance(telemetry["ttls"]["fake"], defaultdict)
        assert isinstance(telemetry["ttls"]["real"], defaultdict)

    def test_defaultdict_behavior(self):
        """Test that defaultdicts work correctly."""
        telemetry = create_telemetry_structure()

        # Test seq_offsets defaultdict
        assert telemetry["seq_offsets"]["test_key"] == 0
        telemetry["seq_offsets"]["test_key"] += 1
        assert telemetry["seq_offsets"]["test_key"] == 1

        # Test overlaps defaultdict
        assert telemetry["overlaps"]["test_key"] == 0

        # Test ttls defaultdict
        assert telemetry["ttls"]["fake"][5] == 0
        telemetry["ttls"]["fake"][5] += 1
        assert telemetry["ttls"]["fake"][5] == 1

    def test_handshake_counters(self):
        """Test TLS handshake counter initialization."""
        telemetry = create_telemetry_structure()

        assert telemetry["clienthellos"] == 0
        assert telemetry["serverhellos"] == 0

    def test_packet_counters(self):
        """Test packet counter initialization."""
        telemetry = create_telemetry_structure()

        assert telemetry["rst_count"] == 0
        assert telemetry["packets_captured"] == 0
        assert telemetry["total_retransmissions_detected"] == 0

    def test_per_target_structure(self):
        """Test per-target statistics structure."""
        telemetry = create_telemetry_structure()

        # Access a target that doesn't exist yet
        target_stats = telemetry["per_target"]["192.168.1.1"]

        # Verify structure is created automatically
        assert target_stats["segments_sent"] == 0
        assert target_stats["fake_packets_sent"] == 0
        assert isinstance(target_stats["seq_offsets"], defaultdict)
        assert isinstance(target_stats["ttls_fake"], defaultdict)
        assert isinstance(target_stats["ttls_real"], defaultdict)
        assert isinstance(target_stats["overlaps"], defaultdict)
        assert target_stats["last_outcome"] is None
        assert target_stats["last_outcome_ts"] is None

    def test_per_target_independence(self):
        """Test that per-target stats are independent."""
        telemetry = create_telemetry_structure()

        # Modify stats for target 1
        telemetry["per_target"]["192.168.1.1"]["segments_sent"] = 10

        # Verify target 2 is unaffected
        assert telemetry["per_target"]["192.168.1.2"]["segments_sent"] == 0

    def test_max_targets_parameter(self):
        """Test that max_targets parameter is accepted."""
        # Should not raise an error
        telemetry = create_telemetry_structure(max_targets=500)
        assert telemetry is not None

        telemetry = create_telemetry_structure(max_targets=2000)
        assert telemetry is not None

    def test_telemetry_mutability(self):
        """Test that telemetry structure can be modified."""
        telemetry = create_telemetry_structure()

        # Modify various counters
        telemetry["aggregate"]["segments_sent"] = 100
        telemetry["clienthellos"] = 5
        telemetry["per_target"]["10.0.0.1"]["fake_packets_sent"] = 20

        # Verify modifications persist
        assert telemetry["aggregate"]["segments_sent"] == 100
        assert telemetry["clienthellos"] == 5
        assert telemetry["per_target"]["10.0.0.1"]["fake_packets_sent"] == 20


class TestBackwardCompatibility:
    """Test backward compatibility with base_engine.py."""

    def test_import_from_base_engine(self):
        """Test that create_telemetry_structure can be imported from base_engine."""
        from core.bypass.engine.base_engine import (
            create_telemetry_structure as base_create_telemetry,
        )

        # Verify it's the same function
        assert base_create_telemetry is create_telemetry_structure

    def test_engine_uses_telemetry_init(self):
        """Test that WindowsBypassEngine uses telemetry_init."""
        from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig

        try:
            engine = WindowsBypassEngine(EngineConfig(debug=False))

            # Verify telemetry structure is initialized
            assert hasattr(engine, "_telemetry")
            assert "start_ts" in engine._telemetry
            assert "aggregate" in engine._telemetry
            assert "per_target" in engine._telemetry

            # Verify it's a proper telemetry structure
            assert engine._telemetry["clienthellos"] == 0
            assert engine._telemetry["serverhellos"] == 0
        except ImportError:
            import pytest

            pytest.skip("pydivert not available")

    def test_telemetry_structure_compatibility(self):
        """Test that telemetry structure matches expected format."""
        telemetry = create_telemetry_structure()

        # These keys are critical for validation and must exist
        critical_keys = [
            "serverhellos",  # IMPORTANT for validation
            "packets_captured",  # IMPORTANT for validation
            "total_retransmissions_detected",  # IMPORTANT for validation
        ]

        for key in critical_keys:
            assert key in telemetry, f"Critical key '{key}' missing from telemetry"
