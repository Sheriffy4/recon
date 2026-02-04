"""
Tests for strategy configuration converter.

This test suite validates strategy configuration conversion logic.
"""

import pytest
from core.bypass.engine.strategy_converter import (
    config_to_strategy_task,
    build_multisplit_positions,
)


class TestMultisplitPositions:
    """Test multisplit position generation."""

    def test_build_positions_zero_count(self):
        """Test with zero split count."""
        positions = build_multisplit_positions(0)
        assert positions == []

    def test_build_positions_negative_count(self):
        """Test with negative split count."""
        positions = build_multisplit_positions(-1)
        assert positions == []

    def test_build_positions_one_split(self):
        """Test with one split."""
        positions = build_multisplit_positions(1)
        assert positions == [6]

    def test_build_positions_two_splits(self):
        """Test with two splits."""
        positions = build_multisplit_positions(2)
        assert positions == [6, 12]

    def test_build_positions_three_splits(self):
        """Test with three splits."""
        positions = build_multisplit_positions(3)
        assert positions == [6, 12, 18]

    def test_build_positions_four_splits(self):
        """Test with four splits (progressive gaps)."""
        positions = build_multisplit_positions(4)
        assert len(positions) == 4
        assert positions[0] == 6
        # Verify positions are increasing
        for i in range(len(positions) - 1):
            assert positions[i] < positions[i + 1]

    def test_build_positions_many_splits(self):
        """Test with many splits."""
        positions = build_multisplit_positions(10)
        assert len(positions) == 10
        # Verify all positions are unique and increasing
        assert positions == sorted(set(positions))


class TestStrategyConverter:
    """Test strategy configuration conversion."""

    def test_multisplit_strategy(self):
        """Test multisplit strategy conversion."""
        config = {"desync_method": "multisplit", "split_count": 3, "ttl": 5}

        task = config_to_strategy_task(config)

        assert task["type"] == "multisplit"
        assert "params" in task
        assert task["params"]["ttl"] == 5
        assert task["params"]["positions"] == [6, 12, 18]
        assert task["params"]["window_div"] == 2
        assert task["params"]["ipid_step"] == 2048

    def test_multisplit_with_custom_overlap(self):
        """Test multisplit with custom overlap size."""
        config = {
            "desync_method": "multisplit",
            "split_count": 2,
            "overlap_size": 30,
        }

        task = config_to_strategy_task(config)

        assert task["type"] == "multisplit"
        assert task["params"]["overlap_size"] == 30

    def test_badsum_race_strategy(self):
        """Test badsum race strategy conversion."""
        config = {"desync_method": "fake", "fooling": "badsum", "ttl": 4}

        task = config_to_strategy_task(config)

        assert task["type"] == "badsum_race"
        assert task["params"]["ttl"] == 4
        assert task["params"]["extra_ttl"] == 5  # ttl + 1
        assert task["params"]["delay_ms"] == 5
        assert task["no_fallbacks"] is True
        assert task["forced"] is True

    def test_md5sig_race_strategy(self):
        """Test md5sig race strategy conversion."""
        config = {"desync_method": "fake", "fooling": "md5sig", "ttl": 3}

        task = config_to_strategy_task(config)

        assert task["type"] == "md5sig_race"
        assert task["params"]["ttl"] == 3
        assert task["params"]["extra_ttl"] == 5  # ttl + 2
        assert task["params"]["delay_ms"] == 7

    def test_seqovl_strategy(self):
        """Test sequence overlap strategy conversion."""
        config = {
            "desync_method": "seqovl",
            "overlap_size": 25,
            "ttl": 2,
        }

        task = config_to_strategy_task(config)

        assert task["type"] == "seqovl"
        assert task["params"]["overlap_size"] == 25
        assert task["params"]["ttl"] == 2

    def test_fakeddisorder_strategy(self):
        """Test fakeddisorder strategy conversion."""
        config = {"desync_method": "fakeddisorder", "ttl": 6}

        task = config_to_strategy_task(config)

        assert task["type"] == "fakeddisorder"
        assert task["params"]["ttl"] == 6
        assert task["params"]["window_div"] == 8

    def test_default_strategy(self):
        """Test default strategy when method is unknown."""
        config = {"desync_method": "unknown_method"}

        task = config_to_strategy_task(config)

        # Should fall back to fakeddisorder
        assert task["type"] == "fakeddisorder"
        assert "params" in task

    def test_empty_config(self):
        """Test with empty configuration."""
        config = {}

        task = config_to_strategy_task(config)

        # Should use defaults
        assert task["type"] == "fakeddisorder"
        assert task["params"]["ttl"] == 3  # default
        assert task["params"]["split_pos"] == 3  # default

    def test_tcp_flags_in_multisplit(self):
        """Test TCP flags in multisplit strategy."""
        config = {"desync_method": "multisplit"}

        task = config_to_strategy_task(config)

        tcp_flags = task["params"]["tcp_flags"]
        assert tcp_flags["psh"] is True
        assert tcp_flags["ack"] is True
        assert tcp_flags["no_fallbacks"] is True
        assert tcp_flags["forced"] is True

    def test_tcp_flags_in_fake_strategy(self):
        """Test TCP flags in fake strategy."""
        config = {"desync_method": "fake"}

        task = config_to_strategy_task(config)

        tcp_flags = task["params"]["tcp_flags"]
        assert tcp_flags["psh"] is True
        assert tcp_flags["ack"] is True

    def test_split_pos_parameter(self):
        """Test split_pos parameter handling."""
        config = {"desync_method": "fake", "split_pos": 10}

        task = config_to_strategy_task(config)

        assert task["params"]["split_pos"] == 10


class TestBackwardCompatibility:
    """Test backward compatibility with base_engine.py."""

    def test_import_from_base_engine(self):
        """Test that functions can be imported from base_engine."""
        from core.bypass.engine.base_engine import (
            config_to_strategy_task as base_config_to_strategy,
            build_multisplit_positions as base_build_positions,
        )

        # Verify they're the same functions
        assert base_config_to_strategy is config_to_strategy_task
        assert base_build_positions is build_multisplit_positions

    def test_engine_uses_strategy_converter(self):
        """Test that WindowsBypassEngine uses strategy_converter."""
        from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig

        try:
            engine = WindowsBypassEngine(EngineConfig(debug=False))

            # Test the method exists and works
            config = {"desync_method": "multisplit", "split_count": 2}
            task = engine._config_to_strategy_task(config)

            assert task["type"] == "multisplit"
            assert len(task["params"]["positions"]) == 2
        except ImportError:
            pytest.skip("pydivert not available")

    def test_strategy_task_structure(self):
        """Test that strategy task structure is consistent."""
        configs = [
            {"desync_method": "multisplit"},
            {"desync_method": "fake", "fooling": "badsum"},
            {"desync_method": "seqovl"},
        ]

        for config in configs:
            task = config_to_strategy_task(config)

            # All tasks should have these keys
            assert "type" in task
            assert "params" in task
            assert isinstance(task["params"], dict)
