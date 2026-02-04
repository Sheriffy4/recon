"""
Packet Pipeline Initialization Utilities

This module provides utilities for initializing the packet processing pipeline,
including PacketBuilder, PacketSender, and UnifiedAttackExecutor components.

Extracted from base_engine.py to reduce god class complexity and improve testability.
"""

import logging
from typing import Tuple, Any


def initialize_packet_pipeline(
    packet_builder_class: type,
    packet_sender_class: type,
    unified_executor_class: type,
    attack_dispatcher: Any,
    logger: logging.Logger,
    inject_mark: int = 0xC0DE,
) -> Tuple[Any, Any, Any]:
    """
    Initialize packet processing pipeline components.

    This function creates and configures the packet builder, packet sender,
    and unified attack executor for the bypass engine.

    Args:
        packet_builder_class: PacketBuilder class to instantiate
        packet_sender_class: PacketSender class to instantiate
        unified_executor_class: UnifiedAttackExecutor class to instantiate
        attack_dispatcher: AttackDispatcher instance for attack execution
        logger: Logger instance for status messages
        inject_mark: WinDivert mark for injected packets (default: 0xC0DE)

    Returns:
        Tuple of (packet_builder, packet_sender, unified_executor):
        - packet_builder: Initialized PacketBuilder instance
        - packet_sender: Initialized PacketSender instance
        - unified_executor: Initialized UnifiedAttackExecutor instance

    Examples:
        >>> from core.bypass.packet.builder import PacketBuilder
        >>> from core.bypass.packet.sender import PacketSender
        >>> logger = logging.getLogger("test")
        >>> builder, sender, executor = initialize_packet_pipeline(
        ...     PacketBuilder, PacketSender, UnifiedAttackExecutor,
        ...     attack_dispatcher, logger
        ... )
    """
    # Initialize packet builder
    packet_builder = packet_builder_class()

    # Initialize packet sender with builder and inject mark
    packet_sender = packet_sender_class(packet_builder, logger, inject_mark)

    logger.info("Modern packet pipeline (PacketSender/Builder) integrated directly.")

    # Set default mode to production
    packet_sender.set_mode("production")

    # Initialize unified attack executor for testing-production parity
    unified_executor = unified_executor_class(
        attack_dispatcher=attack_dispatcher, packet_sender=packet_sender
    )

    logger.info("✅ UnifiedAttackExecutor initialized for testing-production parity")

    return packet_builder, packet_sender, unified_executor
