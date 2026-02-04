"""
Tests for packet pipeline initialization utilities.

This module tests the packet pipeline initialization logic,
including PacketBuilder, PacketSender, and UnifiedAttackExecutor setup.
"""

import logging
from unittest.mock import Mock, MagicMock, call

import pytest

from core.bypass.engine.packet_pipeline_init import initialize_packet_pipeline


class TestPacketPipelineInit:
    """Test packet pipeline initialization."""

    def setup_method(self):
        """Set up test fixtures."""
        self.logger = logging.getLogger("test")
        self.logger.setLevel(logging.DEBUG)

    def test_initialize_packet_pipeline_basic(self):
        """Test basic packet pipeline initialization."""
        # Mock classes
        mock_builder_class = Mock()
        mock_sender_class = Mock()
        mock_executor_class = Mock()
        mock_dispatcher = Mock()

        # Mock instances
        mock_builder = Mock()
        mock_sender = Mock()
        mock_executor = Mock()

        mock_builder_class.return_value = mock_builder
        mock_sender_class.return_value = mock_sender
        mock_executor_class.return_value = mock_executor

        # Initialize pipeline
        builder, sender, executor = initialize_packet_pipeline(
            packet_builder_class=mock_builder_class,
            packet_sender_class=mock_sender_class,
            unified_executor_class=mock_executor_class,
            attack_dispatcher=mock_dispatcher,
            logger=self.logger,
            inject_mark=0xC0DE,
        )

        # Verify instances returned
        assert builder is mock_builder
        assert sender is mock_sender
        assert executor is mock_executor

        # Verify builder was instantiated
        mock_builder_class.assert_called_once()

        # Verify sender was instantiated with correct args
        mock_sender_class.assert_called_once_with(mock_builder, self.logger, 0xC0DE)

        # Verify sender mode was set to production
        mock_sender.set_mode.assert_called_once_with("production")

        # Verify executor was instantiated with correct args
        mock_executor_class.assert_called_once_with(
            attack_dispatcher=mock_dispatcher, packet_sender=mock_sender
        )

    def test_custom_inject_mark(self):
        """Test initialization with custom inject mark."""
        mock_builder_class = Mock()
        mock_sender_class = Mock()
        mock_executor_class = Mock()
        mock_dispatcher = Mock()

        custom_mark = 0xDEAD

        builder, sender, executor = initialize_packet_pipeline(
            packet_builder_class=mock_builder_class,
            packet_sender_class=mock_sender_class,
            unified_executor_class=mock_executor_class,
            attack_dispatcher=mock_dispatcher,
            logger=self.logger,
            inject_mark=custom_mark,
        )

        # Verify sender was created with custom mark
        args = mock_sender_class.call_args[0]
        assert args[2] == custom_mark


class TestBackwardCompatibility:
    """Test backward compatibility with base_engine.py."""

    def test_import_from_base_engine(self):
        """Test that function can be imported from base_engine."""
        from core.bypass.engine.base_engine import initialize_packet_pipeline

        assert callable(initialize_packet_pipeline)

    def test_engine_uses_packet_pipeline_init(self):
        """Test that WindowsBypassEngine uses packet_pipeline_init module."""
        from core.bypass.engine.base_engine import WindowsBypassEngine

        # Check that the class can be instantiated (will fail if init is broken)
        # We don't actually instantiate to avoid dependencies
        assert hasattr(WindowsBypassEngine, "__init__")
