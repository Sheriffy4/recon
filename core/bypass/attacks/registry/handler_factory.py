"""
Attack Handler Factory for the refactored Attack Registry system.

This module provides the AttackHandlerFactory class that extracts all
handler creation logic from the monolithic AttackRegistry class.

The factory is responsible for:
- Creating specialized handlers for different attack types
- Managing handler builders and registration
- Providing a clean interface for handler creation
- Supporting extensibility through custom handler builders
"""

import logging
from typing import Any, Callable, Dict, List, Tuple
from ..base import AttackContext
from .models import AttackMetadata

logger = logging.getLogger(__name__)


class AttackHandlerFactory:
    """
    Factory for creating attack handlers.

    This class extracts all the _create_*_handler() methods from AttackRegistry
    and provides a clean, extensible interface for handler creation.

    Key features:
    - Centralized handler creation logic
    - Support for custom handler builders
    - Consistent parameter handling
    - Extensible architecture for new attack types
    """

    def __init__(self):
        """Initialize the handler factory."""
        self._handler_builders: Dict[str, Callable] = {}
        self._setup_builtin_handlers()
        logger.debug("AttackHandlerFactory initialized")

    def create_handler(self, attack_type: str, metadata: AttackMetadata) -> Callable:
        """
        Create a handler for the specified attack type.

        Args:
            attack_type: Type of attack to create handler for
            metadata: Attack metadata containing parameter information

        Returns:
            Callable handler function

        Raises:
            ValueError: If attack type is not supported
        """
        logger.debug(f"Creating handler for attack type: {attack_type}")

        if attack_type in self._handler_builders:
            builder = self._handler_builders[attack_type]
            handler = builder()
            logger.debug(f"Created handler for {attack_type} using custom builder")
            return handler

        # Try to create handler using primitives method
        if hasattr(self, f"_create_{attack_type}_handler"):
            method = getattr(self, f"_create_{attack_type}_handler")
            handler = method()
            logger.debug(f"Created handler for {attack_type} using built-in method")
            return handler

        # Fallback to primitives handler if method exists
        try:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()
            if hasattr(techniques, attack_type):
                handler = self._create_primitives_handler(attack_type)
                logger.debug(f"Created handler for {attack_type} using primitives fallback")
                return handler
        except (AttributeError, ImportError):
            pass

        raise ValueError(f"No handler builder found for attack type: {attack_type}")

    def register_handler_builder(self, attack_type: str, builder: Callable) -> None:
        """
        Register a custom handler builder for an attack type.

        Args:
            attack_type: Attack type to register builder for
            builder: Function that returns a handler when called
        """
        self._handler_builders[attack_type] = builder
        logger.info(f"Registered custom handler builder for: {attack_type}")

    def _setup_builtin_handlers(self) -> None:
        """Set up built-in handler builders."""
        # Register built-in handlers that have special creation methods
        builtin_handlers = [
            "fakeddisorder",
            "seqovl",
            "multidisorder",
            "disorder",
            "disorder2",
            "multisplit",
            "split",
            "fake",
            "disorder_split",
            "window_manipulation",
            "tcp_options_modification",
            "advanced_timing",
            "badsum",
            "badseq",
            "md5sig",
            "passthrough",
            "ttl",
        ]

        for handler_type in builtin_handlers:
            if hasattr(self, f"_create_{handler_type}_handler"):
                # Don't register in _handler_builders - let create_handler find the method directly
                logger.debug(f"Built-in handler available: {handler_type}")

    def _create_primitives_handler(self, method_name: str) -> Callable:
        """Create a handler for a method from primitives.py."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()
            method = getattr(techniques, method_name)

            # Filter parameters according to method signature
            import inspect

            sig = inspect.signature(method)
            filtered_params = {}

            for param_name, param in sig.parameters.items():
                if param_name in ["payload"]:  # Skip payload, it's passed separately
                    continue
                if param_name in context.params:
                    filtered_params[param_name] = context.params[param_name]
                elif param.default != inspect.Parameter.empty:
                    # Parameter has default value, don't add it
                    continue

            return method(context.payload, **filtered_params)

        return handler

    def _create_disorder2_handler(self) -> Callable:
        """Create special handler for disorder2."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()
            split_pos = context.params.get("split_pos", 3)
            return techniques.apply_disorder(context.payload, split_pos, ack_first=True)

        return handler

    def _create_disorder_handler(self) -> Callable:
        """Create handler for simple disorder (uses apply_disorder from primitives)."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()
            split_pos = context.params.get("split_pos", 3)
            ack_first = context.params.get("ack_first", False)
            return techniques.apply_disorder(context.payload, split_pos, ack_first=ack_first)

        return handler

    def _create_split_handler(self) -> Callable:
        """Create handler for simple split (converts to multisplit)."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()
            split_pos = context.params.get("split_pos", 3)

            # Filter parameters for multisplit
            filtered_params = {}
            if "fooling" in context.params:
                filtered_params["fooling"] = context.params["fooling"]

            return techniques.apply_multisplit(
                context.payload, positions=[split_pos], **filtered_params
            )

        return handler

    def _create_disorder_split_handler(self) -> Callable:
        """Create handler for disorder_split (split + disorder)."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()
            split_pos = context.params.get("split_pos", 3)

            # Apply disorder (sends segments in reverse order)
            return techniques.apply_disorder(context.payload, split_pos, ack_first=False)

        return handler

    def _create_seqovl_handler(self) -> Callable:
        """Create special handler for seqovl with correct parameters."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            split_pos = context.params.get("split_pos", 3)
            overlap_size = context.params.get("overlap_size", 1)

            # Convert parameters to correct format
            fake_ttl = context.params.get("fake_ttl", context.params.get("ttl", 3))
            fooling_methods = context.params.get(
                "fooling_methods", context.params.get("fooling", ["badsum"])
            )

            # Pass resolved custom SNI to the primitives method
            kwargs = {}
            if "resolved_custom_sni" in context.params:
                kwargs["resolved_custom_sni"] = context.params["resolved_custom_sni"]

            return techniques.apply_seqovl(
                context.payload, split_pos, overlap_size, fake_ttl, fooling_methods, **kwargs
            )

        return handler

    def _create_fake_handler(self) -> Callable:
        """Create special handler for fake with correct parameters."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            # Convert parameters to correct format
            ttl = context.params.get("ttl", context.params.get("fake_ttl", 3))
            fooling = context.params.get(
                "fooling", context.params.get("fooling_methods", ["badsum"])
            )

            # Pass through resolved_custom_sni if available
            kwargs = {}
            if "resolved_custom_sni" in context.params:
                kwargs["resolved_custom_sni"] = context.params["resolved_custom_sni"]

            return techniques.apply_fake_packet_race(context.payload, ttl, fooling, **kwargs)

        return handler

    def _generate_positions(self, split_pos: any, split_count: any, payload_len: int) -> List[int]:
        """
        Standardized position generation for multisplit attacks.

        This method ensures consistent position generation between testing and production modes.

        Algorithm:
        1. If positions explicitly provided, use them
        2. If split_pos AND split_count provided, generate positions starting from split_pos
        3. If only split_pos provided, use single position
        4. If only split_count provided, distribute evenly across payload
        5. Default: middle of payload

        Position generation formula (when both split_pos and split_count are provided):
        - Start at split_pos
        - Generate split_count positions with fixed gap of 6 bytes
        - positions = [split_pos, split_pos+6, split_pos+12, ..., split_pos+(split_count-1)*6]

        Args:
            split_pos: Starting position for splits (int or str)
            split_count: Number of split positions to generate (int or str)
            payload_len: Length of payload for validation

        Returns:
            List of integer positions, validated to be within payload bounds

        Examples:
            >>> _generate_positions(3, 8, 100)
            [3, 9, 15, 21, 27, 33, 39, 45]

            >>> _generate_positions(5, None, 100)
            [5]

            >>> _generate_positions(None, 4, 100)
            [25, 50, 75]
        """
        # Log position generation parameters
        logger.info(
            f"🔢 Generating positions: split_pos={split_pos}, split_count={split_count}, payload_len={payload_len}"
        )

        # Case 1: Both split_pos AND split_count provided
        if split_pos is not None and split_count is not None:
            # Convert split_pos to int if string
            if isinstance(split_pos, str):
                try:
                    split_pos = int(split_pos)
                except ValueError:
                    logger.warning(f"Invalid split_pos string '{split_pos}', using default 3")
                    split_pos = 3

            # Validate and clamp split_pos
            base_pos = max(1, min(int(split_pos), payload_len - 1))
            count = max(1, int(split_count))

            # Calculate step size to distribute positions evenly across payload
            # This creates equal-sized segments like Case 3
            remaining_payload = payload_len - base_pos
            step = max(1, remaining_payload // count)

            positions = []
            for i in range(
                count - 1
            ):  # count-1 because we need count segments, not count positions
                pos = base_pos + (i * step)
                if pos < payload_len:
                    positions.append(pos)

            # Ensure we have at least one position
            if not positions:
                positions = [base_pos]

            # Log generated positions for debugging
            logger.info(
                f"✅ Generated {len(positions)} positions from split_pos={split_pos}, "
                f"split_count={split_count}: {positions}"
            )

            return positions

        # Case 2: Only split_pos provided
        elif split_pos is not None:
            if isinstance(split_pos, str):
                try:
                    split_pos = int(split_pos)
                except ValueError:
                    logger.warning(f"Invalid split_pos string '{split_pos}', using middle")
                    split_pos = payload_len // 2

            base_pos = max(1, min(int(split_pos), payload_len - 1))
            positions = [base_pos]

            logger.info(f"✅ Single position from split_pos={split_pos}: {positions}")
            return positions

        # Case 3: Only split_count provided
        elif split_count is not None:
            count = max(1, int(split_count))

            if count == 1:
                positions = [payload_len // 2]
            else:
                # Distribute evenly across payload
                step = payload_len // count
                positions = [i * step for i in range(1, count) if i * step < payload_len]

                # Ensure we have at least one position
                if not positions:
                    positions = [payload_len // 2]

            logger.info(
                f"✅ Generated {len(positions)} positions from split_count={split_count}: {positions}"
            )
            return positions

        # Case 4: No parameters provided - use default
        else:
            positions = [payload_len // 2]
            logger.info(f"✅ Using default position (middle): {positions}")
            return positions

    def _create_multisplit_handler(self) -> Callable:
        """Create special handler for multisplit with correct parameters."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            # Log complete strategy parameters
            logger.info(f"📋 Multisplit handler called with params: {context.params}")

            # CRITICAL FIX: Always use split_count if provided, even if positions exists
            # This fixes the issue where split_pos=2 is converted to positions=[2] and split_count is ignored
            split_pos = context.params.get("split_pos")
            split_count = context.params.get("split_count")

            # Use standardized position generation
            if split_count is not None:
                # If split_count is provided, always generate positions from it
                # This takes priority over any pre-set positions parameter
                logger.info(
                    f"🔧 Using split_count={split_count} to generate positions (ignoring pre-set positions if any)"
                )
                positions = self._generate_positions(split_pos, split_count, len(context.payload))
            else:
                # No split_count, check if positions are explicitly provided
                positions = context.params.get("positions")

                if not positions:
                    # No positions and no split_count, generate from split_pos only
                    positions = self._generate_positions(split_pos, None, len(context.payload))
                else:
                    # Validate explicitly provided positions
                    logger.info(f"📋 Using explicit positions: {positions}")

                    # Validate positions are within bounds
                    valid_positions = [
                        p for p in positions if isinstance(p, int) and 0 < p < len(context.payload)
                    ]

                    if len(valid_positions) != len(positions):
                        logger.warning(
                            f"⚠️ Filtered invalid positions: {len(positions)} → {len(valid_positions)}"
                        )

                    positions = valid_positions if valid_positions else [len(context.payload) // 2]

            # Validate final positions
            if not positions:
                logger.error("❌ No valid positions generated, using default")
                positions = [len(context.payload) // 2]

            # Log final positions being used
            logger.info(f"🎯 Final positions for multisplit: {positions}")

            # Get fooling parameter
            fooling = context.params.get("fooling")

            # CRITICAL TTL FIX: Extract TTL parameters and apply them to segments
            ttl = context.params.get("ttl")
            fake_ttl = context.params.get("fake_ttl")

            # Get segments from apply_multisplit
            segments = techniques.apply_multisplit(context.payload, positions, fooling)

            # Apply TTL parameters to all segments if specified
            if ttl is not None or fake_ttl is not None:
                # Use ttl if specified, otherwise use fake_ttl, otherwise use default
                segment_ttl = ttl if ttl is not None else (fake_ttl if fake_ttl is not None else 64)
                logger.info(f"🔧 Applying TTL={segment_ttl} to all multisplit segments")

                # Update segment options with TTL
                updated_segments = []
                for payload_part, seq_offset, options in segments:
                    updated_options = options.copy()
                    updated_options["ttl"] = segment_ttl
                    updated_segments.append((payload_part, seq_offset, updated_options))

                return updated_segments

            return segments

        return handler

    def _create_fakeddisorder_handler(self) -> Callable:
        """Create special handler for fakeddisorder with correct parameters."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            # Handle split_pos - can be int, str or list
            split_pos = context.params.get("split_pos")
            if isinstance(split_pos, list):
                if len(split_pos) == 0:
                    split_pos = len(context.payload) // 2
                else:
                    split_pos = split_pos[0]
                logger.debug(f"Converted split_pos list to single value: {split_pos}")
            elif split_pos is None:
                split_pos = len(context.payload) // 2

            # Handle TTL parameters
            fake_ttl = context.params.get("fake_ttl", context.params.get("ttl", 3))

            # Handle fooling methods
            fooling_methods = context.params.get(
                "fooling_methods", context.params.get("fooling", ["badsum"])
            )

            # Filter only supported parameters for apply_fakeddisorder
            filtered_params = {
                "split_pos": split_pos,
                "fake_ttl": fake_ttl,
                "fooling_methods": fooling_methods,
            }

            # Pass resolved custom SNI to the primitives method
            if "resolved_custom_sni" in context.params:
                filtered_params["resolved_custom_sni"] = context.params["resolved_custom_sni"]

            return techniques.apply_fakeddisorder(context.payload, **filtered_params)

        return handler

    def _create_multidisorder_handler(self) -> Callable:
        """Create special handler for multidisorder with correct parameters."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            logger.info(f"🔍 multidisorder handler CALLED! payload_len={len(context.payload)}")
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            # Convert parameters to correct format
            positions = context.params.get("positions")

            # CRITICAL DEBUG: Log what positions we received
            logger.info(
                f"🔍 multidisorder handler: positions={positions}, payload_len={len(context.payload)}"
            )

            # If positions not specified but split_pos exists, create positions from split_pos
            if not positions and "split_pos" in context.params:
                split_pos = context.params["split_pos"]
                if isinstance(split_pos, (int, str)):
                    # Create multiple positions based on split_pos
                    if isinstance(split_pos, str):
                        try:
                            split_pos = int(split_pos)
                        except ValueError:
                            split_pos = len(context.payload) // 2

                    # Create reasonable positions based on split_pos
                    base_pos = max(1, min(split_pos, len(context.payload) - 1))
                    positions = []

                    # Add positions before split_pos
                    if base_pos > 2:
                        positions.append(base_pos // 2)

                    # Add split_pos itself
                    positions.append(base_pos)

                    # Add position after split_pos
                    if base_pos < len(context.payload) - 2:
                        positions.append(min(base_pos + (base_pos // 2), len(context.payload) - 1))

                    # Remove duplicates and sort
                    positions = sorted(list(set(positions)))

                    logger.debug(
                        f"Converted split_pos={split_pos} to positions={positions} for payload length {len(context.payload)}"
                    )
                else:
                    positions = [1, 5, 10]  # Default values
            elif not positions:
                positions = [1, 5, 10]  # Default values

            fake_ttl = context.params.get("fake_ttl", context.params.get("ttl", 3))
            fooling_raw = context.params.get("fooling", context.params.get("fooling_methods"))

            # CRITICAL DEBUG: Log what we got from params
            logger.info(
                f"🔧 multidisorder handler: fooling_raw={fooling_raw}, type={type(fooling_raw)}"
            )

            # CRITICAL: Convert fooling="none" string to empty list (no fooling)
            if fooling_raw is None:
                fooling = ["badsum"]  # Default
                logger.info("🔧 multidisorder: fooling is None, using default ['badsum']")
            elif fooling_raw == "none" or fooling_raw == ["none"]:
                fooling = []
                logger.info(
                    "🔧 multidisorder: fooling='none' detected, disabling all fooling methods"
                )
            elif isinstance(fooling_raw, str):
                fooling = [fooling_raw]
                logger.info(f"🔧 multidisorder: converted string to list: {fooling}")
            elif isinstance(fooling_raw, list):
                fooling = fooling_raw
                logger.info(f"🔧 multidisorder: using list as-is: {fooling}")
            else:
                fooling = ["badsum"]  # Fallback
                logger.warning("🔧 multidisorder: unexpected fooling type, using default")

            logger.info(f"🔧 multidisorder handler FINAL: fooling={fooling}, fake_ttl={fake_ttl}")

            return techniques.apply_multidisorder(context.payload, positions, fooling, fake_ttl)

        return handler

    def _create_window_manipulation_handler(self) -> Callable:
        """Create handler for TCP window manipulation."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            # Extract parameters with defaults
            window_size = context.params.get("window_size", 1)
            delay_ms = context.params.get("delay_ms", 50.0)
            fragment_count = context.params.get("fragment_count", 5)
            fooling_methods = context.params.get("fooling", ["badsum"])

            return BypassTechniques.apply_window_manipulation(
                context.payload, window_size, delay_ms, fragment_count, fooling_methods
            )

        return handler

    def _create_tcp_options_modification_handler(self) -> Callable:
        """Create handler for TCP options modification."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            # Extract parameters with defaults
            split_pos = context.params.get("split_pos", 5)
            options_type = context.params.get("options_type", "mss")
            bad_checksum = context.params.get("bad_checksum", False)
            fooling_methods = context.params.get("fooling", ["badsum"])

            return BypassTechniques.apply_tcp_options_modification(
                context.payload, split_pos, options_type, bad_checksum, fooling_methods
            )

        return handler

    def _create_advanced_timing_handler(self) -> Callable:
        """Create handler for advanced timing control."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            # Extract parameters with defaults
            split_pos = context.params.get("split_pos", 3)
            delays = context.params.get("delays", [1.0, 2.0])
            jitter = context.params.get("jitter", False)
            fooling_methods = context.params.get("fooling", ["badsum"])

            return BypassTechniques.apply_advanced_timing_control(
                context.payload, split_pos, delays, jitter, fooling_methods
            )

        return handler

    def _create_badsum_handler(self) -> Callable:
        """Create handler for badsum fooling attack."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            # Apply badsum fooling
            return techniques.apply_fake_packet_race(
                context.payload,
                ttl=context.params.get("ttl", context.params.get("fake_ttl", 3)),
                fooling=["badsum"],
                **{k: v for k, v in context.params.items() if k not in ["ttl", "fake_ttl"]},
            )

        return handler

    def _create_badseq_handler(self) -> Callable:
        """Create handler for badseq fooling attack."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            # Apply badseq fooling
            return techniques.apply_fake_packet_race(
                context.payload,
                ttl=context.params.get("ttl", context.params.get("fake_ttl", 3)),
                fooling=["badseq"],
                **{k: v for k, v in context.params.items() if k not in ["ttl", "fake_ttl"]},
            )

        return handler

    def _create_md5sig_handler(self) -> Callable:
        """Create handler for md5sig fooling attack."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            # Apply md5sig fooling
            return techniques.apply_fake_packet_race(
                context.payload,
                ttl=context.params.get("ttl", context.params.get("fake_ttl", 3)),
                fooling=["md5sig"],
                **{k: v for k, v in context.params.items() if k not in ["ttl", "fake_ttl"]},
            )

        return handler

    def _create_passthrough_handler(self) -> Callable:
        """Create handler for passthrough (no-op) attack."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            # Return packet as-is with no modifications (baseline test)
            return [(context.payload, 0, {})]

        return handler

    def _create_ttl_handler(self) -> Callable:
        """Create handler for TTL manipulation attack."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            # Get TTL value
            ttl = context.params.get("ttl", 3)

            # Apply TTL manipulation using fake packet with specified TTL
            return techniques.apply_fake_packet_race(
                context.payload,
                ttl=ttl,
                fooling=context.params.get("fooling", ["badsum"]),
                **{k: v for k, v in context.params.items() if k not in ["ttl", "fooling"]},
            )

        return handler

    def get_supported_attack_types(self) -> List[str]:
        """
        Get list of all supported attack types.

        Returns:
            List of attack type names that can be handled
        """
        supported = list(self._handler_builders.keys())

        # Add built-in handlers
        for attr_name in dir(self):
            if attr_name.startswith("_create_") and attr_name.endswith("_handler"):
                attack_type = attr_name[8:-8]  # Remove '_create_' and '_handler'
                if attack_type not in supported:
                    supported.append(attack_type)

        return sorted(supported)

    def has_handler(self, attack_type: str) -> bool:
        """
        Check if a handler exists for the given attack type.

        Args:
            attack_type: Attack type to check

        Returns:
            True if handler exists, False otherwise
        """
        return attack_type in self._handler_builders or hasattr(
            self, f"_create_{attack_type}_handler"
        )
