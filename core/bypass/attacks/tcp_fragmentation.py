#!/usr/bin/env python3
"""
TCP Fragmentation Attacks Implementation

This module implements comprehensive TCP fragmentation attacks for DPI bypass.
Based on the requirements from task 5 of the bypass engine modernization spec.

Implements:
- TCP packet fragmentation techniques
- TCP window manipulation attacks
- TCP sequence number manipulation
- TCP options modification attacks

All attacks follow the modern attack architecture with segments orchestration.
"""

import time
import random
import struct
import logging
from typing import Optional, List
from dataclasses import dataclass

from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus, SegmentTuple
from attack_definition import (
    AttackDefinition,
    AttackCategory,
    AttackComplexity,
    AttackStability,
    CompatibilityMode,
    TestCase,
)
from registry import register_attack

LOG = logging.getLogger("TCPFragmentationAttacks")


@dataclass
class TCPFragmentationConfig:
    """Configuration for TCP fragmentation attacks."""

    split_positions: List[int]
    fragment_count: int = 3
    randomize_order: bool = False
    fake_ttl: int = 2
    delay_between_fragments_ms: float = 1.0
    window_size_override: Optional[int] = None
    bad_checksum: bool = False
    sequence_overlap: int = 0
    tcp_options: bytes = b""


class BaseTCPFragmentationAttack(BaseAttack):
    """Base class for all TCP fragmentation attacks."""

    def __init__(self):
        super().__init__()
        self.logger = LOG

    def _create_tcp_segments(
        self, context: AttackContext, config: TCPFragmentationConfig
    ) -> List[SegmentTuple]:
        """
        Create TCP segments based on fragmentation configuration.

        Args:
            context: Attack execution context
            config: Fragmentation configuration

        Returns:
            List of segment tuples for orchestrated execution
        """
        payload = context.payload
        if not payload:
            return []

        segments = []

        # Determine split positions
        split_positions = self._calculate_split_positions(payload, config)

        # Create fragments
        fragments = self._split_payload(payload, split_positions)

        # Randomize order if requested
        if config.randomize_order:
            random.shuffle(fragments)

        # Create segments with proper sequence offsets
        current_seq_offset = 0

        for i, fragment_data in enumerate(fragments):
            # Create transmission options
            options = {}

            # Set TTL for fake packets
            if config.fake_ttl > 0 and i == 0:  # First fragment as fake
                options["ttl"] = config.fake_ttl

            # Set delay between fragments
            if i > 0 and config.delay_between_fragments_ms > 0:
                options["delay_ms"] = config.delay_between_fragments_ms

            # Set window size override
            if config.window_size_override is not None:
                options["window_size"] = config.window_size_override

            # Set bad checksum
            if config.bad_checksum:
                options["bad_checksum"] = True

            # Add TCP options
            if config.tcp_options:
                options["tcp_options"] = config.tcp_options

            # Handle sequence overlap
            seq_offset = current_seq_offset
            if config.sequence_overlap > 0 and i > 0:
                seq_offset -= config.sequence_overlap

            # Create segment
            segment = (fragment_data, seq_offset, options)
            segments.append(segment)

            # Update sequence offset for next fragment
            current_seq_offset += len(fragment_data)

        return segments

    def _calculate_split_positions(
        self, payload: bytes, config: TCPFragmentationConfig
    ) -> List[int]:
        """Calculate where to split the payload."""
        if config.split_positions:
            # Use provided positions, but ensure they're within payload bounds
            positions = [
                pos for pos in config.split_positions if 0 < pos < len(payload)
            ]
            return sorted(positions)

        # Auto-calculate positions based on fragment count
        if config.fragment_count <= 1:
            return []

        payload_len = len(payload)
        fragment_size = payload_len // config.fragment_count

        positions = []
        for i in range(1, config.fragment_count):
            pos = i * fragment_size
            if pos < payload_len:
                positions.append(pos)

        return positions

    def _split_payload(self, payload: bytes, split_positions: List[int]) -> List[bytes]:
        """Split payload at specified positions."""
        if not split_positions:
            return [payload]

        fragments = []
        start = 0

        for pos in split_positions:
            if start < pos <= len(payload):
                fragments.append(payload[start:pos])
                start = pos

        # Add remaining data
        if start < len(payload):
            fragments.append(payload[start:])

        return fragments


@register_attack("simple_fragment")
class SimpleTCPFragmentationAttack(BaseTCPFragmentationAttack):
    """
    Simple TCP fragmentation attack.
    Splits TCP payload at fixed positions into multiple fragments.
    """

    @property
    def name(self) -> str:
        return "simple_fragment"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute simple TCP fragmentation."""
        start_time = time.time()

        try:
            # Get parameters
            split_pos = context.params.get("split_pos", 3)
            fragment_count = context.params.get("fragment_count", 3)

            # Create configuration
            config = TCPFragmentationConfig(
                split_positions=[split_pos] if split_pos > 0 else [],
                fragment_count=fragment_count,
            )

            # Create segments
            segments = self._create_tcp_segments(context, config)

            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created - payload may be empty",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="simple_fragment",
                )

            # Create successful result with segments
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="simple_fragment",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
            )

            result.segments = segments
            result.set_metadata("fragmentation_type", "simple")
            result.set_metadata("split_position", split_pos)
            result.set_metadata("fragment_count", len(segments))

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Simple fragmentation failed: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="simple_fragment",
            )


@register_attack("fake_disorder")
class FakeDisorderAttack(BaseTCPFragmentationAttack):
    """
    Fake disorder attack.
    Sends fake packet with low TTL, then real packet fragments in reverse order.
    """

    @property
    def name(self) -> str:
        return "fake_disorder"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute fake disorder attack."""
        start_time = time.time()

        try:
            # Get parameters
            split_pos = context.params.get("split_pos", 3)
            fake_ttl = context.params.get("fake_ttl", 2)
            delay_ms = context.params.get("delay_ms", 2.0)

            # Create configuration
            config = TCPFragmentationConfig(
                split_positions=[split_pos],
                fake_ttl=fake_ttl,
                delay_between_fragments_ms=delay_ms,
                randomize_order=True,  # Send in reverse order
            )

            # Create segments
            segments = self._create_tcp_segments(context, config)

            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for fake disorder",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="fake_disorder",
                )

            # Reverse the order of segments (except fake packet)
            if len(segments) > 1:
                fake_segment = segments[0]  # First segment with low TTL
                real_segments = segments[1:]
                real_segments.reverse()
                segments = [fake_segment] + real_segments

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="fake_disorder",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
            )

            result.segments = segments
            result.set_metadata("fragmentation_type", "fake_disorder")
            result.set_metadata("fake_ttl", fake_ttl)
            result.set_metadata("disorder_applied", True)

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Fake disorder attack failed: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="fake_disorder",
            )


@register_attack("multisplit")
class MultiSplitAttack(BaseTCPFragmentationAttack):
    """
    Multi-split attack.
    Splits TCP payload at multiple positions simultaneously.
    """

    @property
    def name(self) -> str:
        return "multisplit"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute multi-split attack."""
        start_time = time.time()

        try:
            # Get parameters
            positions = context.params.get("positions", [1, 3, 10])
            randomize = context.params.get("randomize", False)

            # Ensure positions are valid
            if not isinstance(positions, list) or len(positions) < 2:
                positions = [1, 3, 10]

            # Create configuration
            config = TCPFragmentationConfig(
                split_positions=positions, randomize_order=randomize
            )

            # Create segments
            segments = self._create_tcp_segments(context, config)

            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for multi-split",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="multisplit",
                )

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="multisplit",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
            )

            result.segments = segments
            result.set_metadata("fragmentation_type", "multisplit")
            result.set_metadata("split_positions", positions)
            result.set_metadata("randomized", randomize)

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Multi-split attack failed: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="multisplit",
            )


@register_attack("sequence_overlap")
class SequenceOverlapAttack(BaseTCPFragmentationAttack):
    """
    Sequence overlap attack.
    Creates overlapping TCP sequence numbers to confuse DPI.
    """

    @property
    def name(self) -> str:
        return "sequence_overlap"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute sequence overlap attack."""
        start_time = time.time()

        try:
            # Get parameters
            split_pos = context.params.get("split_pos", 3)
            overlap_size = context.params.get("overlap_size", 10)
            fake_ttl = context.params.get("fake_ttl", 2)

            # Create configuration
            config = TCPFragmentationConfig(
                split_positions=[split_pos],
                sequence_overlap=overlap_size,
                fake_ttl=fake_ttl,
            )

            # Create segments
            segments = self._create_tcp_segments(context, config)

            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for sequence overlap",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="sequence_overlap",
                )

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="sequence_overlap",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
            )

            result.segments = segments
            result.set_metadata("fragmentation_type", "sequence_overlap")
            result.set_metadata("overlap_size", overlap_size)
            result.set_metadata("fake_ttl", fake_ttl)

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Sequence overlap attack failed: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="sequence_overlap",
            )


@register_attack("window_manipulation")
class WindowManipulationAttack(BaseTCPFragmentationAttack):
    """
    TCP window manipulation attack.
    Manipulates TCP window size to force small segments and control flow.
    """

    @property
    def name(self) -> str:
        return "window_manipulation"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute window manipulation attack."""
        start_time = time.time()

        try:
            # Get parameters
            window_size = context.params.get("window_size", 1)
            delay_ms = context.params.get("delay_ms", 50.0)
            fragment_count = context.params.get("fragment_count", 5)

            # Create configuration
            config = TCPFragmentationConfig(
                split_positions=[],  # Auto-calculate based on fragment count
                fragment_count=fragment_count,
                window_size_override=window_size,
                delay_between_fragments_ms=delay_ms,
            )

            # Create segments
            segments = self._create_tcp_segments(context, config)

            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for window manipulation",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="window_manipulation",
                )

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="window_manipulation",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
            )

            result.segments = segments
            result.set_metadata("fragmentation_type", "window_manipulation")
            result.set_metadata("window_size", window_size)
            result.set_metadata("delay_ms", delay_ms)

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Window manipulation attack failed: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="window_manipulation",
            )


@register_attack("tcp_options_modification")
class TCPOptionsModificationAttack(BaseTCPFragmentationAttack):
    """
    TCP options modification attack.
    Modifies TCP options to evade DPI detection while fragmenting.
    """

    @property
    def name(self) -> str:
        return "tcp_options_modification"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TCP options modification attack."""
        start_time = time.time()

        try:
            # Get parameters
            split_pos = context.params.get("split_pos", 5)
            options_type = context.params.get("options_type", "mss")
            bad_checksum = context.params.get("bad_checksum", False)

            # Create TCP options based on type
            tcp_options = self._create_tcp_options(options_type)

            # Create configuration
            config = TCPFragmentationConfig(
                split_positions=[split_pos],
                tcp_options=tcp_options,
                bad_checksum=bad_checksum,
            )

            # Create segments
            segments = self._create_tcp_segments(context, config)

            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for TCP options modification",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="tcp_options_modification",
                )

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="tcp_options_modification",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
            )

            result.segments = segments
            result.set_metadata("fragmentation_type", "tcp_options_modification")
            result.set_metadata("options_type", options_type)
            result.set_metadata("bad_checksum", bad_checksum)
            result.set_metadata("tcp_options_length", len(tcp_options))

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"TCP options modification attack failed: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="tcp_options_modification",
            )

    def _create_tcp_options(self, options_type: str) -> bytes:
        """Create TCP options based on specified type."""
        if options_type == "mss":
            # Maximum Segment Size option
            return struct.pack("!BBH", 2, 4, 1460)  # MSS = 1460

        elif options_type == "window_scale":
            # Window Scale option
            return struct.pack("!BBB", 3, 3, 7)  # Scale factor = 7

        elif options_type == "timestamp":
            # Timestamp option
            return struct.pack("!BBII", 8, 10, int(time.time()), 0)

        elif options_type == "sack_permitted":
            # SACK Permitted option
            return struct.pack("!BB", 4, 2)

        elif options_type == "md5_signature":
            # MD5 Signature option (fake)
            fake_signature = b"\xde\xad\xbe\xef" * 4  # 16 bytes
            return struct.pack("!BB", 19, 18) + fake_signature

        elif options_type == "custom":
            # Custom option for evasion
            return struct.pack("!BB", 254, 4) + b"\x00\x00"  # Experimental option

        else:
            # Default: No-op padding
            return b"\x01\x01\x01\x01"  # 4 bytes of NOP


# Register attack definitions with the modern registry
def register_tcp_fragmentation_attacks():
    """Register all TCP fragmentation attacks with their definitions."""
    try:
        from modern_registry import get_modern_registry

        registry = get_modern_registry()
    except ImportError as e:
        print(f"Failed to auto-register TCP fragmentation attacks: {e}")
        return 0

    # Simple Fragment Attack
    simple_fragment_def = AttackDefinition(
        id="simple_fragment",
        name="Simple TCP Fragmentation",
        description="Basic TCP payload fragmentation at fixed positions",
        category=AttackCategory.TCP_FRAGMENTATION,
        complexity=AttackComplexity.SIMPLE,
        stability=AttackStability.STABLE,
        compatibility=[
            CompatibilityMode.NATIVE,
            CompatibilityMode.ZAPRET,
            CompatibilityMode.GOODBYEDPI,
        ],
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        parameters={
            "split_pos": {
                "type": "int",
                "default": 3,
                "min": 1,
                "max": 100,
                "description": "Position to split payload",
            },
            "fragment_count": {
                "type": "int",
                "default": 3,
                "min": 2,
                "max": 10,
                "description": "Number of fragments",
            },
        },
        default_parameters={"split_pos": 3, "fragment_count": 3},
        required_parameters=["split_pos"],
        external_tool_mappings={
            "zapret": "--dpi-desync=split --dpi-desync-split-pos={split_pos}",
            "goodbyedpi": "-f {split_pos}",
        },
        tags={"basic", "fragmentation", "tcp", "stable"},
        test_cases=[
            TestCase(
                id="simple_fragment_basic",
                name="Basic fragmentation test",
                description="Test simple fragmentation with default parameters",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"split_pos": 3, "fragment_count": 3},
            ),
            TestCase(
                id="simple_fragment_large_split",
                name="Large split position test",
                description="Test fragmentation with larger split position",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"split_pos": 10, "fragment_count": 2},
            ),
        ],
    )

    # Fake Disorder Attack
    fake_disorder_def = AttackDefinition(
        id="fake_disorder",
        name="Fake Packet Disorder",
        description="Send fake packet with low TTL, then real packet fragments in reverse order",
        category=AttackCategory.TCP_FRAGMENTATION,
        complexity=AttackComplexity.MODERATE,
        stability=AttackStability.STABLE,
        compatibility=[CompatibilityMode.NATIVE, CompatibilityMode.ZAPRET],
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        parameters={
            "split_pos": {
                "type": "int",
                "default": 3,
                "min": 1,
                "max": 50,
                "description": "Position to split payload",
            },
            "fake_ttl": {
                "type": "int",
                "default": 2,
                "min": 1,
                "max": 10,
                "description": "TTL for fake packet",
            },
            "delay_ms": {
                "type": "float",
                "default": 2.0,
                "min": 0.1,
                "max": 10.0,
                "description": "Delay between fragments",
            },
        },
        default_parameters={"split_pos": 3, "fake_ttl": 2, "delay_ms": 2.0},
        required_parameters=["split_pos"],
        external_tool_mappings={
            "zapret": "--dpi-desync=fake,disorder --dpi-desync-split-pos={split_pos} --dpi-desync-ttl={fake_ttl}"
        },
        tags={"fake", "disorder", "ttl", "advanced"},
        test_cases=[
            TestCase(
                id="fake_disorder_basic",
                name="Basic fake disorder test",
                description="Test fake disorder with default parameters",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"split_pos": 3, "fake_ttl": 2},
            )
        ],
    )

    # Multi Split Attack
    multisplit_def = AttackDefinition(
        id="multisplit",
        name="Multiple Position Split",
        description="Split TCP payload at multiple positions simultaneously",
        category=AttackCategory.TCP_FRAGMENTATION,
        complexity=AttackComplexity.MODERATE,
        stability=AttackStability.STABLE,
        compatibility=[CompatibilityMode.NATIVE, CompatibilityMode.ZAPRET],
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        parameters={
            "positions": {
                "type": "list",
                "default": [1, 3, 10],
                "description": "List of split positions",
            },
            "randomize": {
                "type": "bool",
                "default": False,
                "description": "Randomize fragment order",
            },
        },
        default_parameters={"positions": [1, 3, 10], "randomize": False},
        required_parameters=["positions"],
        external_tool_mappings={
            "zapret": "--dpi-desync=split --dpi-desync-split-pos={positions}"
        },
        tags={"multisplit", "advanced", "fragmentation"},
        test_cases=[
            TestCase(
                id="multisplit_basic",
                name="Basic multi-split test",
                description="Test multi-split with default positions",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"positions": [1, 3, 10]},
            )
        ],
    )

    # Sequence Overlap Attack
    sequence_overlap_def = AttackDefinition(
        id="sequence_overlap",
        name="Sequence Overlap",
        description="Create overlapping TCP sequence numbers to confuse DPI",
        category=AttackCategory.TCP_FRAGMENTATION,
        complexity=AttackComplexity.ADVANCED,
        stability=AttackStability.MODERATE,
        compatibility=[CompatibilityMode.NATIVE, CompatibilityMode.ZAPRET],
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        parameters={
            "split_pos": {
                "type": "int",
                "default": 3,
                "min": 1,
                "max": 50,
                "description": "Position to split payload",
            },
            "overlap_size": {
                "type": "int",
                "default": 10,
                "min": 1,
                "max": 100,
                "description": "Size of sequence overlap",
            },
            "fake_ttl": {
                "type": "int",
                "default": 2,
                "min": 1,
                "max": 10,
                "description": "TTL for fake packet",
            },
        },
        default_parameters={"split_pos": 3, "overlap_size": 10, "fake_ttl": 2},
        required_parameters=["split_pos", "overlap_size"],
        external_tool_mappings={
            "zapret": "--dpi-desync=fake,split --dpi-desync-split-seqovl={overlap_size}"
        },
        tags={"sequence", "overlap", "advanced", "tcp"},
        test_cases=[
            TestCase(
                id="sequence_overlap_basic",
                name="Basic sequence overlap test",
                description="Test sequence overlap with default parameters",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"split_pos": 3, "overlap_size": 10},
            )
        ],
    )

    # Window Manipulation Attack
    window_manipulation_def = AttackDefinition(
        id="window_manipulation",
        name="TCP Window Manipulation",
        description="Manipulate TCP window size to force small segments and control flow",
        category=AttackCategory.TCP_FRAGMENTATION,
        complexity=AttackComplexity.MODERATE,
        stability=AttackStability.STABLE,
        compatibility=[CompatibilityMode.NATIVE, CompatibilityMode.ZAPRET],
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        parameters={
            "window_size": {
                "type": "int",
                "default": 1,
                "min": 1,
                "max": 10,
                "description": "TCP window size",
            },
            "delay_ms": {
                "type": "float",
                "default": 50.0,
                "min": 1.0,
                "max": 100.0,
                "description": "Delay between segments",
            },
            "fragment_count": {
                "type": "int",
                "default": 5,
                "min": 2,
                "max": 20,
                "description": "Number of fragments",
            },
        },
        default_parameters={"window_size": 1, "delay_ms": 50.0, "fragment_count": 5},
        required_parameters=["window_size"],
        external_tool_mappings={"zapret": "--wssize={window_size}"},
        tags={"window", "size", "tcp", "timing"},
        test_cases=[
            TestCase(
                id="window_manipulation_basic",
                name="Basic window manipulation test",
                description="Test window manipulation with small window size",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"window_size": 1, "fragment_count": 5},
            )
        ],
    )

    # TCP Options Modification Attack
    tcp_options_def = AttackDefinition(
        id="tcp_options_modification",
        name="TCP Options Modification",
        description="Modify TCP options to evade DPI detection while fragmenting",
        category=AttackCategory.TCP_FRAGMENTATION,
        complexity=AttackComplexity.ADVANCED,
        stability=AttackStability.MODERATE,
        compatibility=[CompatibilityMode.NATIVE],
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        parameters={
            "split_pos": {
                "type": "int",
                "default": 5,
                "min": 1,
                "max": 50,
                "description": "Position to split payload",
            },
            "options_type": {
                "type": "str",
                "default": "mss",
                "choices": [
                    "mss",
                    "window_scale",
                    "timestamp",
                    "sack_permitted",
                    "md5_signature",
                    "custom",
                ],
                "description": "Type of TCP options to add",
            },
            "bad_checksum": {
                "type": "bool",
                "default": False,
                "description": "Use bad TCP checksum",
            },
        },
        default_parameters={
            "split_pos": 5,
            "options_type": "mss",
            "bad_checksum": False,
        },
        required_parameters=["split_pos", "options_type"],
        tags={"tcp", "options", "modification", "advanced"},
        test_cases=[
            TestCase(
                id="tcp_options_mss",
                name="TCP options with MSS test",
                description="Test TCP options modification with MSS option",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"split_pos": 5, "options_type": "mss"},
            ),
            TestCase(
                id="tcp_options_timestamp",
                name="TCP options with timestamp test",
                description="Test TCP options modification with timestamp option",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"split_pos": 5, "options_type": "timestamp"},
            ),
        ],
    )

    # Register all attacks
    attacks = [
        (simple_fragment_def, SimpleTCPFragmentationAttack),
        (fake_disorder_def, FakeDisorderAttack),
        (multisplit_def, MultiSplitAttack),
        (sequence_overlap_def, SequenceOverlapAttack),
        (window_manipulation_def, WindowManipulationAttack),
        (tcp_options_def, TCPOptionsModificationAttack),
    ]

    registered_count = 0
    for definition, attack_class in attacks:
        if registry.register_attack(definition, attack_class):
            registered_count += 1
            LOG.info(f"Registered TCP fragmentation attack: {definition.id}")
        else:
            LOG.error(f"Failed to register TCP fragmentation attack: {definition.id}")

    LOG.info(f"Successfully registered {registered_count} TCP fragmentation attacks")
    return registered_count


# Auto-register attacks when module is imported
if __name__ != "__main__":
    try:
        register_tcp_fragmentation_attacks()
    except Exception as e:
        LOG.error(f"Failed to auto-register TCP fragmentation attacks: {e}")
