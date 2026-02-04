# path: core/bypass/techniques/faked_disorder_core.py
"""
Core logic for FakedDisorderAttack.

This module contains the core execution logic extracted from FakedDisorderAttack
to reduce the god_class smell and improve maintainability.

The core handles:
    - Configuration validation
    - Split position resolution
    - TTL calculation with X.COM fix
    - Attack execution orchestration
"""

import logging
from typing import List, Tuple, Dict, Any


class FakedDisorderCore:
    """
    Core logic for FakedDisorderAttack execution.

    This class encapsulates the core attack logic, separated from the
    main FakedDisorderAttack class to reduce complexity and improve
    maintainability.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize core with configuration.

        Args:
            config: Configuration dictionary with attack parameters
        """
        self.config = config
        self.logger = logging.getLogger("FakedDisorderCore")

        # Extract configuration
        self.split_pos = config.get("split_pos", 76)
        self.split_seqovl = config.get("split_seqovl", 336)
        self.ttl = config.get("ttl", 1)
        self.autottl = config.get("autottl")
        self.repeats = config.get("repeats", 1)
        self.fooling_methods = config.get("fooling_methods", ["badsum", "badseq"])
        self.fake_payload_type = config.get("fake_payload_type", "PAYLOADTLS")
        self.custom_fake_payload = config.get("custom_fake_payload")
        self.enable_monitoring = config.get("enable_monitoring", False)
        self.enable_injection = config.get("enable_injection", False)
        self.kwargs = config.get("kwargs", {})

    def validate_config(self) -> None:
        """
        Validate configuration parameters with comprehensive checks.

        Raises:
            ValueError: If any configuration parameter is invalid
        """
        # Validate split_seqovl
        if not isinstance(self.split_seqovl, int) or self.split_seqovl < 0:
            raise ValueError(f"split_seqovl must be non-negative integer, got {self.split_seqovl}")

        # Validate TTL range
        if not isinstance(self.ttl, int) or self.ttl < 1 or self.ttl > 255:
            raise ValueError(f"ttl must be between 1 and 255, got {self.ttl}")

        # Validate autottl if specified
        if self.autottl is not None:
            if not isinstance(self.autottl, int) or self.autottl < 1 or self.autottl > 10:
                raise ValueError(f"autottl must be between 1 and 10, got {self.autottl}")

        # Validate repeats
        if not isinstance(self.repeats, int) or self.repeats < 1:
            raise ValueError(f"repeats must be >= 1, got {self.repeats}")

        # Validate fooling methods
        valid_fooling = ["badseq", "badsum", "md5sig", "datanoack"]
        for method in self.fooling_methods:
            if method not in valid_fooling:
                raise ValueError(f"Invalid fooling method: {method}. Valid: {valid_fooling}")

    def resolve_split_position(self, payload: bytes) -> int:
        """
        Resolve split position with special value support.

        Special values:
        - "sni": Position 43 (TLS SNI extension)
        - "cipher": Position 11 (TLS cipher suites)
        - "midsld": Middle of payload
        - int: Direct position value

        Args:
            payload: Payload bytes to split

        Returns:
            Resolved integer split position
        """
        if isinstance(self.split_pos, str):
            if self.split_pos == "sni":
                # TLS SNI extension typically at position 43
                pos = min(43, len(payload) // 2) if len(payload) > 43 else len(payload) // 2
                self.logger.debug(f"SNI split position: {pos}")
                return pos
            elif self.split_pos == "cipher":
                # TLS cipher suites typically at position 11
                pos = min(11, len(payload) // 2) if len(payload) > 11 else len(payload) // 2
                self.logger.debug(f"Cipher split position: {pos}")
                return pos
            elif self.split_pos == "midsld":
                # Middle of payload
                pos = len(payload) // 2
                self.logger.debug(f"Mid-SLD split position: {pos}")
                return pos
            else:
                self.logger.warning(f"Unknown special position '{self.split_pos}', using middle")
                return len(payload) // 2
        else:
            # Numeric position with validation
            pos = int(self.split_pos)
            if pos >= len(payload):
                pos = len(payload) // 2
                self.logger.warning(
                    f"Split position {self.split_pos} >= payload length, using {pos}"
                )
            return max(1, pos)

    def calculate_effective_ttl(self) -> int:
        """
        Calculate effective TTL with X.COM fix.

        This is the CRITICAL optimization that makes fakeddisorder work on x.com.
        The TTL must be limited to 3 or lower for maximum effectiveness.

        Returns:
            Effective TTL value (limited to 3)
        """
        if self.autottl is not None and self.autottl > 1:
            # For AutoTTL, use effective range
            effective_ttl = min(3, self.autottl)
            self.logger.debug(f"AutoTTL effective: {effective_ttl} from range 1-{self.autottl}")
            return effective_ttl
        else:
            # CRITICAL X.COM FIX: Force TTL limitation for fakeddisorder
            effective_ttl = min(3, self.ttl)
            if effective_ttl != self.ttl:
                self.logger.info(f"X.COM TTL fix: limited {self.ttl} -> {effective_ttl}")
            return effective_ttl

    def execute(
        self,
        payload: bytes,
        generate_fake_payload_func,
        create_segments_func,
        apply_repeats_func=None,
        monitor_results_func=None,
        execute_with_autottl_func=None,
        **context,
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Execute unified fakeddisorder attack with all optimizations.

        This method orchestrates the attack execution by calling provided
        functions for different stages. This allows the main class to
        provide implementations while keeping the core logic here.

        Args:
            payload: Original packet data (usually TLS ClientHello)
            generate_fake_payload_func: Function to generate fake payload
            create_segments_func: Function to create attack segments
            apply_repeats_func: Optional function to apply repeats
            monitor_results_func: Optional function to monitor results
            execute_with_autottl_func: Optional function for AutoTTL execution
            **context: Additional context (dst_ip, dst_port, etc.)

        Returns:
            List of segments: [(data, seq_offset, options), ...]
        """
        try:
            self.logger.info("Executing UNIFIED fakeddisorder attack")

            if not payload:
                raise ValueError("Empty payload provided")

            # Step 1: Resolve split position
            resolved_split_pos = self.resolve_split_position(payload)

            # Step 2: Generate fake payload
            fake_payload = generate_fake_payload_func(payload, **context)

            # Step 3: Calculate effective TTL
            effective_ttl = self.calculate_effective_ttl()

            # Step 4: Execute with AutoTTL if enabled
            if self.autottl is not None and self.autottl > 1 and execute_with_autottl_func:
                return execute_with_autottl_func(
                    payload, fake_payload, resolved_split_pos, **context
                )

            # Step 5: Create segments using unified algorithm
            segments = create_segments_func(
                payload, fake_payload, resolved_split_pos, effective_ttl
            )

            # Step 6: Apply repeats if configured
            if self.repeats > 1 and apply_repeats_func:
                segments = apply_repeats_func(segments)

            # Step 7: Monitor results if enabled
            if self.enable_monitoring and monitor_results_func:
                monitor_results_func(segments, **context)

            self.logger.info(f"UNIFIED fakeddisorder: {len(segments)} segments generated")
            return segments

        except Exception as e:
            self.logger.error(f"UNIFIED fakeddisorder failed: {e}")
            raise


def create_core_from_attack(attack_instance) -> FakedDisorderCore:
    """
    Create FakedDisorderCore from FakedDisorderAttack instance.

    Helper function to extract configuration from attack instance
    and create a core object.

    Args:
        attack_instance: FakedDisorderAttack instance

    Returns:
        FakedDisorderCore instance with extracted configuration
    """
    config = {
        "split_pos": attack_instance.split_pos,
        "split_seqovl": attack_instance.split_seqovl,
        "ttl": attack_instance.ttl,
        "autottl": attack_instance.autottl,
        "repeats": attack_instance.repeats,
        "fooling_methods": attack_instance.fooling_methods,
        "fake_payload_type": attack_instance.fake_payload_type,
        "custom_fake_payload": attack_instance.custom_fake_payload,
        "enable_monitoring": attack_instance.enable_monitoring,
        "enable_injection": attack_instance.enable_injection,
        "kwargs": attack_instance.kwargs,
    }
    return FakedDisorderCore(config)
