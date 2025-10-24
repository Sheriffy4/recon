"""
Attack Parameter Mapper - Maps test parameters to attack-specific parameters

This module provides parameter mapping functionality to bridge the gap between
test orchestrator parameters and attack constructor/execution parameters.
"""

import logging
import inspect
from typing import Dict, Any, Optional, Callable, Type, List
from dataclasses import dataclass


@dataclass
class ParameterMapping:
    """Defines a parameter mapping rule."""

    test_param: str
    attack_param: str
    transformer: Optional[Callable[[Any], Any]] = None
    default: Any = None


class ParameterMappingError(Exception):
    """Raised when parameter mapping fails."""

    pass


class ParameterMapper:
    """
    Maps test parameters to attack-specific parameters.

    This mapper handles:
    - Parameter name transformations
    - Type conversions
    - Default value handling
    - Attack-specific parameter requirements
    """

    # Tunneling Attack Parameter Mappings
    # Based on analysis, tunneling attacks take no constructor params
    # All parameters are passed via execute() context.params
    TUNNELING_ATTACK_MAPPINGS = {
        # ICMP Tunneling
        "icmp_data_tunneling": {},
        "icmp_timestamp_tunneling": {},
        "icmp_redirect_tunneling": {},
        "icmp_covert_channel": {},
        # Protocol Tunneling
        "http_tunneling": {},
        "websocket_tunneling": {},
        "ssh_tunneling": {},
        "vpn_tunneling": {},
        # DNS Tunneling
        "dns_tunneling": {},
        "dns_txt_tunneling": {},
        # QUIC Fragmentation
        "quic_fragmentation": {},
    }

    # IP Fragmentation Attack Parameter Mappings
    # Based on analysis, fragmentation attacks take no constructor params
    # All parameters are passed via execute() context.params
    FRAGMENTATION_ATTACK_MAPPINGS = {
        "ip_fragmentation_advanced": {},
        "ip_fragmentation_disorder": {},
        "ip_fragmentation_random": {},
        "simple_fragment": {},
    }

    # TLS Attack Parameter Mappings
    # Based on analysis, TLS attacks take no constructor params
    # All parameters are passed via execute() context.params
    TLS_ATTACK_MAPPINGS = {
        # TLS Handshake Manipulation
        "tls_handshake_manipulation": {},
        "tls_version_downgrade": {},
        "tls_extension_manipulation": {},
        # TLS Record Manipulation
        "tlsrec_split": {},
        "tls_record_padding": {},
        "tls_record_fragmentation": {},
        # TLS Extension Attacks
        "sni_manipulation": {},
        "alpn_manipulation": {},
        "grease_injection": {},
        # TLS Confusion Attacks
        "protocol_confusion": {},
        "tls_version_confusion": {},
        "tls_content_type_confusion": {},
        # TLS Early Data & ECH
        "early_data_smuggling": {},
        "early_data_tunnel": {},
        "ech_attacks": {},
        # TLS JA3 Mimicry
        "ja3_mimicry": {},
        # Additional TLS attacks
        "tls_evasion": {},
        "tls_confusion": {},
    }

    # TCP Attack Parameter Mappings
    # Based on analysis from task 1.1, most TCP attacks take no constructor params
    # but may accept config objects for stateful/race attacks
    # Attack names match the attack.name property (e.g., 'fake_disorder', not 'tcp_fakeddisorder')
    TCP_ATTACK_MAPPINGS = {
        # Stateful attacks that accept StatefulAttackConfig
        "fake_disorder": {
            "split_pos": ParameterMapping("split_pos", "split_pos"),
            "fake_ttl": ParameterMapping("fake_ttl", "fake_ttl"),
            "disorder_window": ParameterMapping("disorder_window", "disorder_window"),
            "config": ParameterMapping("config", "config"),
        },
        "tcp_multidisorder": {
            "split_positions": ParameterMapping("split_positions", "split_positions"),
            "fake_ttl": ParameterMapping("fake_ttl", "fake_ttl"),
            "disorder_count": ParameterMapping("disorder_count", "disorder_count"),
            "config": ParameterMapping("config", "config"),
        },
        "tcp_seqovl": {
            "overlap_size": ParameterMapping("overlap_size", "overlap_size"),
            "overlap_data": ParameterMapping("overlap_data", "overlap_data"),
            "config": ParameterMapping("config", "config"),
        },
        "tcp_timing_manipulation": {
            "delay_ms": ParameterMapping("delay_ms", "delay_ms"),
            "jitter_ms": ParameterMapping("jitter_ms", "jitter_ms"),
            "config": ParameterMapping("config", "config"),
        },
        # Race attacks that accept RaceAttackConfig
        "badsum_race": {
            "race_window_ms": ParameterMapping("race_window_ms", "race_window_ms"),
            "config": ParameterMapping("config", "config"),
        },
        "low_ttl_poisoning": {
            "poison_ttl": ParameterMapping("poison_ttl", "poison_ttl"),
            "race_window_ms": ParameterMapping("race_window_ms", "race_window_ms"),
            "config": ParameterMapping("config", "config"),
        },
        "cache_confusion_race": {
            "race_window_ms": ParameterMapping("race_window_ms", "race_window_ms"),
            "confusion_count": ParameterMapping("confusion_count", "confusion_count"),
            "config": ParameterMapping("config", "config"),
        },
        "md5sig_race": {
            "race_window_ms": ParameterMapping("race_window_ms", "race_window_ms"),
            "config": ParameterMapping("config", "config"),
        },
        "drip_feed": {
            "drip_rate_ms": ParameterMapping("drip_rate_ms", "drip_rate_ms"),
            "chunk_size": ParameterMapping("chunk_size", "chunk_size"),
            "config": ParameterMapping("config", "config"),
        },
        # Manipulation attacks (no constructor params, params passed via execute)
        "tcp_window_scaling": {},
        "tcp_options_modification": {},
        "tcp_sequence_manipulation": {},
        "tcp_window_manipulation": {},
        "tcp_fragmentation": {},
        "urgent_pointer_manipulation": {},
        "tcp_options_padding": {},
        "tcp_multisplit": {},
        "tcp_timestamp_manipulation": {},
        "tcp_wssize_limit": {},
        # Fooling attacks (no constructor params)
        "badsum_fooling": {},
        "md5sig_fooling": {},
        "badseq_fooling": {},
        "ttl_manipulation": {},
        # Timing attacks (no constructor params)
        "timing_based_evasion": {},
        "burst_timing_evasion": {},
        # Simple attacks (no constructor params)
        "simple_fragment": {},
        "multisplit": {},
        "window_manipulation": {},
    }

    def __init__(self):
        """Initialize the parameter mapper."""
        self.logger = logging.getLogger(__name__)
        self._signature_cache: Dict[str, inspect.Signature] = {}

    def map_parameters(
        self,
        attack_name: str,
        params: Dict[str, Any],
        attack_class: Optional[Type] = None,
    ) -> Dict[str, Any]:
        """
        Map test parameters to attack-specific parameters.

        Args:
            attack_name: Name of the attack
            params: Test parameters to map
            attack_class: Optional attack class for introspection

        Returns:
            Mapped parameters ready for attack instantiation

        Raises:
            ParameterMappingError: If mapping fails
        """
        try:
            # Get mapping rules for this attack
            mappings = self._get_mappings(attack_name)

            # If no mappings defined, return empty dict (most attacks take no constructor params)
            if not mappings:
                self.logger.debug(
                    f"No parameter mappings for {attack_name}, using empty constructor"
                )
                return {}

            # Apply mappings
            mapped_params = {}
            for test_param, value in params.items():
                if test_param in mappings:
                    mapping = mappings[test_param]

                    # Apply transformer if defined
                    if mapping.transformer:
                        value = mapping.transformer(value)

                    mapped_params[mapping.attack_param] = value
                else:
                    # Pass through unmapped parameters
                    self.logger.debug(
                        f"No mapping for parameter '{test_param}', passing through"
                    )
                    mapped_params[test_param] = value

            # Add default values for missing required parameters
            for param_name, mapping in mappings.items():
                if (
                    mapping.attack_param not in mapped_params
                    and mapping.default is not None
                ):
                    mapped_params[mapping.attack_param] = mapping.default

            self.logger.debug(f"Mapped parameters for {attack_name}: {mapped_params}")
            return mapped_params

        except Exception as e:
            raise ParameterMappingError(
                f"Failed to map parameters for {attack_name}: {e}"
            )

    def _get_mappings(self, attack_name: str) -> Dict[str, ParameterMapping]:
        """Get parameter mappings for an attack."""
        # Normalize attack name
        attack_name = attack_name.lower().replace("-", "_")

        # Check tunneling attacks
        if attack_name in self.TUNNELING_ATTACK_MAPPINGS:
            return self.TUNNELING_ATTACK_MAPPINGS[attack_name]

        # Check fragmentation attacks
        if attack_name in self.FRAGMENTATION_ATTACK_MAPPINGS:
            return self.FRAGMENTATION_ATTACK_MAPPINGS[attack_name]

        # Check TLS attacks
        if attack_name in self.TLS_ATTACK_MAPPINGS:
            return self.TLS_ATTACK_MAPPINGS[attack_name]

        # Check TCP attacks
        if attack_name in self.TCP_ATTACK_MAPPINGS:
            return self.TCP_ATTACK_MAPPINGS[attack_name]

        # No mappings found
        return {}

    def get_attack_signature(self, attack_class: Type) -> Dict[str, Any]:
        """
        Get the constructor signature of an attack class.

        Args:
            attack_class: Attack class to inspect

        Returns:
            Dictionary of parameter information
        """
        class_name = attack_class.__name__

        # Check cache
        if class_name in self._signature_cache:
            return self._signature_cache[class_name]

        try:
            sig = inspect.signature(attack_class.__init__)
            params = {}

            for param_name, param in sig.parameters.items():
                if param_name == "self":
                    continue

                params[param_name] = {
                    "name": param_name,
                    "default": (
                        param.default
                        if param.default != inspect.Parameter.empty
                        else None
                    ),
                    "annotation": (
                        str(param.annotation)
                        if param.annotation != inspect.Parameter.empty
                        else None
                    ),
                    "kind": str(param.kind),
                }

            self._signature_cache[class_name] = params
            return params

        except Exception as e:
            self.logger.error(f"Failed to get signature for {class_name}: {e}")
            return {}

    def validate_parameters(
        self,
        attack_name: str,
        params: Dict[str, Any],
        attack_class: Optional[Type] = None,
    ) -> List[str]:
        """
        Validate parameters for an attack.

        Args:
            attack_name: Name of the attack
            params: Parameters to validate
            attack_class: Optional attack class for validation

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        try:
            # Get mappings
            mappings = self._get_mappings(attack_name)

            # If attack has no mappings, it likely takes no constructor params
            if not mappings:
                if params:
                    self.logger.debug(
                        f"{attack_name} takes no constructor params, but {len(params)} provided"
                    )
                return errors

            # Check for unknown parameters
            for param_name in params:
                if param_name not in mappings:
                    errors.append(
                        f"Unknown parameter '{param_name}' for attack '{attack_name}'"
                    )

            # If attack class provided, validate against signature
            if attack_class:
                sig_params = self.get_attack_signature(attack_class)
                mapped_params = self.map_parameters(attack_name, params, attack_class)

                for param_name in mapped_params:
                    if param_name not in sig_params:
                        errors.append(
                            f"Parameter '{param_name}' not in attack signature"
                        )

        except Exception as e:
            errors.append(f"Validation failed: {e}")

        return errors

    def register_mapping(
        self,
        attack_name: str,
        param_mappings: Dict[str, ParameterMapping],
        category: str = "tcp",
    ):
        """
        Register custom parameter mappings for an attack.

        Args:
            attack_name: Name of the attack
            param_mappings: Dictionary of parameter mappings
            category: Attack category ('tcp', 'tls', 'tunneling', 'fragmentation', etc.)
        """
        attack_name = attack_name.lower().replace("-", "_")

        if category == "tls":
            self.TLS_ATTACK_MAPPINGS[attack_name] = param_mappings
        elif category == "tunneling":
            self.TUNNELING_ATTACK_MAPPINGS[attack_name] = param_mappings
        elif category == "fragmentation":
            self.FRAGMENTATION_ATTACK_MAPPINGS[attack_name] = param_mappings
        else:
            self.TCP_ATTACK_MAPPINGS[attack_name] = param_mappings

        self.logger.info(
            f"Registered parameter mappings for {attack_name} ({category})"
        )

    def get_supported_attacks(self) -> List[str]:
        """Get list of attacks with parameter mappings."""
        return (
            list(self.TUNNELING_ATTACK_MAPPINGS.keys())
            + list(self.FRAGMENTATION_ATTACK_MAPPINGS.keys())
            + list(self.TLS_ATTACK_MAPPINGS.keys())
            + list(self.TCP_ATTACK_MAPPINGS.keys())
        )


# Global mapper instance
_mapper_instance = None


def get_parameter_mapper() -> ParameterMapper:
    """Get the global parameter mapper instance."""
    global _mapper_instance
    if _mapper_instance is None:
        _mapper_instance = ParameterMapper()
    return _mapper_instance
