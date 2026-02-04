#!/usr/bin/env python3
"""
Comprehensive Attack Mapping System

This module provides a centralized mapping system for all available attacks,
ensuring the CLI supports every attack registered in the AttackRegistry.
"""

import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AttackInfo:
    """Information about an attack including its parameters and zapret mapping."""

    name: str
    category: str
    zapret_args: str
    parameters: List[str]
    default_params: Dict[str, Any]
    description: str
    aliases: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.aliases is None:
            self.aliases = []


class ComprehensiveAttackMapping:
    """
    Comprehensive mapping system for all available attacks.

    This class automatically discovers all registered attacks and provides
    mappings to zapret-compatible command strings.
    """

    def __init__(self):
        """Initialize the attack mapping system."""
        self.attacks: Dict[str, AttackInfo] = {}
        self.categories: Dict[str, Set[str]] = {}
        self.aliases: Dict[str, str] = {}
        self._load_all_attacks()
        self._build_mappings()

    def _load_all_attacks(self):
        """Load all attacks from the registry."""
        # Import all attack modules to ensure registration
        import importlib
        import pkgutil
        import core.bypass.attacks

        for _, module_name, _ in pkgutil.walk_packages(
            core.bypass.attacks.__path__, core.bypass.attacks.__name__ + "."
        ):
            try:
                importlib.import_module(module_name)
            except ImportError as e:
                if "demo_" not in module_name and "test_" not in module_name:
                    logger.warning(f"Could not import attack module {module_name}: {e}")

    def _build_mappings(self):
        """Build comprehensive attack mappings."""
        from core.bypass.attacks.attack_registry import get_attack_registry

        self.registry = get_attack_registry()
        registered_attacks = self.registry.list_attacks()
        logger.info(f"Building mappings for {len(registered_attacks)} registered attacks")

        for attack_name in registered_attacks:
            try:
                attack_info = self._create_attack_info(attack_name)
                if attack_info:
                    self.attacks[attack_name] = attack_info

                    # Add to category
                    if attack_info.category not in self.categories:
                        self.categories[attack_info.category] = set()
                    self.categories[attack_info.category].add(attack_name)

                    # Add aliases
                    for alias in attack_info.aliases:
                        self.aliases[alias] = attack_name

            except Exception as e:
                logger.warning(f"Failed to create mapping for attack {attack_name}: {e}")

        logger.info(
            f"Successfully mapped {len(self.attacks)} attacks across {len(self.categories)} categories"
        )

    def _create_attack_info(self, attack_name: str) -> Optional[AttackInfo]:
        """Create AttackInfo for a specific attack."""
        try:
            # Получаем метаданные атаки из registry
            attack_def = self.registry.get_attack_definition(attack_name)
            if not attack_def:
                return None

            # Get basic info from attack definition
            category = attack_def.category if hasattr(attack_def, "category") else "unknown"
            description = (
                attack_def.description
                if hasattr(attack_def, "description")
                else f"{attack_name} attack"
            )

            # Generate zapret mapping and parameters
            zapret_args, parameters, default_params, aliases = self._generate_zapret_mapping(
                attack_name, attack_def
            )

            return AttackInfo(
                name=attack_name,
                category=category,
                zapret_args=zapret_args,
                parameters=parameters,
                default_params=default_params,
                description=description,
                aliases=aliases,
            )

        except Exception as e:
            logger.warning(f"Failed to create attack info for {attack_name}: {e}")
            return None

    def _generate_zapret_mapping(
        self, attack_name: str, attack_def
    ) -> Tuple[str, List[str], Dict[str, Any], List[str]]:
        """Generate zapret command mapping for an attack."""

        # Define comprehensive mappings for all known attack types
        zapret_mappings = {
            # TCP Fragmentation attacks
            "fake_disorder": {
                "zapret": "--dpi-desync=fake,disorder",
                "params": ["split_pos", "ttl", "fooling"],
                "defaults": {"split_pos": 3, "ttl": 4, "fooling": "badsum"},
                "aliases": ["fakedisorder", "fakeddisorder"],
            },
            "tcp_fakeddisorder": {
                "zapret": "--dpi-desync=fake,disorder",
                "params": ["split_pos", "ttl", "fooling"],
                "defaults": {"split_pos": 3, "ttl": 4, "fooling": "badsum"},
                "aliases": ["fakedisorder", "fakeddisorder"],
            },
            "multisplit": {
                "zapret": "--dpi-desync=multisplit",
                "params": ["split_count", "split_seqovl", "fooling", "repeats", "ttl"],
                "defaults": {
                    "split_count": 5,
                    "split_seqovl": 20,
                    "fooling": "badsum",
                    "repeats": 2,
                    "ttl": 4,
                },
                "aliases": ["tcp_multisplit"],
            },
            "tcp_multisplit": {
                "zapret": "--dpi-desync=multisplit",
                "params": ["split_count", "split_seqovl", "fooling", "repeats", "ttl"],
                "defaults": {
                    "split_count": 5,
                    "split_seqovl": 20,
                    "fooling": "badsum",
                    "repeats": 2,
                    "ttl": 4,
                },
                "aliases": ["multisplit"],
            },
            "tcp_multidisorder": {
                "zapret": "--dpi-desync=multidisorder",
                "params": ["split_pos", "ttl", "fooling"],
                "defaults": {"split_pos": 3, "ttl": 4, "fooling": "badsum"},
                "aliases": ["multidisorder"],
            },
            "multidisorder": {
                "zapret": "--dpi-desync=multidisorder",
                "params": ["split_pos", "ttl", "fooling"],
                "defaults": {"split_pos": 3, "ttl": 4, "fooling": "badsum"},
                "aliases": ["tcp_multidisorder"],
            },
            "sequence_overlap": {
                "zapret": "--dpi-desync=fake,disorder",
                "params": ["split_pos", "split_seqovl", "fooling", "ttl"],
                "defaults": {
                    "split_pos": 3,
                    "split_seqovl": 20,
                    "fooling": "badsum",
                    "ttl": 4,
                },
                "aliases": ["seqovl", "tcp_seqovl"],
            },
            "tcp_seqovl": {
                "zapret": "--dpi-desync=fake,disorder",
                "params": ["split_pos", "split_seqovl", "fooling", "ttl"],
                "defaults": {
                    "split_pos": 3,
                    "split_seqovl": 20,
                    "fooling": "badsum",
                    "ttl": 4,
                },
                "aliases": ["seqovl", "sequence_overlap"],
            },
            # Race attacks
            "badsum_race": {
                "zapret": "--dpi-desync=fake --dpi-desync-fooling=badsum",
                "params": ["ttl", "split_pos"],
                "defaults": {"ttl": 4, "split_pos": 3},
                "aliases": ["badsum_fooling"],
            },
            "md5sig_race": {
                "zapret": "--dpi-desync=fake --dpi-desync-fooling=md5sig",
                "params": ["ttl", "split_pos"],
                "defaults": {"ttl": 6, "split_pos": 3},
                "aliases": ["md5sig_fooling"],
            },
            "badseq_fooling": {
                "zapret": "--dpi-desync=fake --dpi-desync-fooling=badseq",
                "params": ["ttl", "split_pos"],
                "defaults": {"ttl": 4, "split_pos": 3},
                "aliases": [],
            },
            # IP Fragmentation
            "ip_fragmentation_advanced": {
                "zapret": "--dpi-desync=ipfrag2",
                "params": ["fragment_size", "ttl", "fooling"],
                "defaults": {"fragment_size": 8, "ttl": 4, "fooling": "badsum"},
                "aliases": ["ip_fragmentation", "ipfrag2"],
            },
            # TCP Options
            "tcp_options_modification": {
                "zapret": "--dpi-desync=disorder --tcp-options-modify",
                "params": ["split_pos", "ttl"],
                "defaults": {"split_pos": 3, "ttl": 4},
                "aliases": [],
            },
            # Window manipulation
            "window_manipulation": {
                "zapret": "--dpi-desync=fake --tcp-window-scale",
                "params": ["window_size", "ttl"],
                "defaults": {"window_size": 1024, "ttl": 4},
                "aliases": ["tcp_window_manipulation"],
            },
            # QUIC attacks
            "quic_fragmentation": {
                "zapret": "--filter-udp=443 --dpi-desync=fake",
                "params": ["fragment_size", "ttl"],
                "defaults": {"fragment_size": 16, "ttl": 4},
                "aliases": [],
            },
            # Force TCP (disable QUIC)
            "force_tcp": {
                "zapret": "--filter-udp=443 --dpi-desync=fake,disorder",
                "params": ["split_pos", "ttl"],
                "defaults": {"split_pos": 3, "ttl": 4},
                "aliases": ["disable_quic", "filter-udp"],
            },
            # Simple fragment
            "simple_fragment": {
                "zapret": "--dpi-desync=split",
                "params": ["split_pos", "ttl"],
                "defaults": {"split_pos": 3, "ttl": 4},
                "aliases": ["tcp_fragmentation"],
            },
            # Timing attacks
            "timing_based_evasion": {
                "zapret": "--dpi-desync=fake --dpi-desync-delay=10",
                "params": ["delay", "ttl"],
                "defaults": {"delay": 10, "ttl": 4},
                "aliases": [],
            },
            # TLS attacks
            "tls_record_fragmentation": {
                "zapret": "--dpi-desync=fake --tls-record-split",
                "params": ["split_pos", "ttl"],
                "defaults": {"split_pos": 3, "ttl": 4},
                "aliases": [],
            },
            # HTTP attacks
            "http_header_case": {
                "zapret": "--dpi-desync=fake --http-header-case",
                "params": ["split_pos", "ttl"],
                "defaults": {"split_pos": 3, "ttl": 4},
                "aliases": [],
            },
        }

        # Check if we have a specific mapping
        if attack_name in zapret_mappings:
            mapping = zapret_mappings[attack_name]
            return (
                mapping["zapret"],
                mapping["params"],
                mapping["defaults"],
                mapping["aliases"],
            )

        # Generate generic mapping based on attack category/name
        return self._generate_generic_mapping(attack_name, attack_def)

    def _generate_generic_mapping(
        self, attack_name: str, attack_instance
    ) -> Tuple[str, List[str], Dict[str, Any], List[str]]:
        """Generate generic zapret mapping for unknown attacks."""

        # Default parameters that most attacks can use
        default_params = ["split_pos", "ttl", "fooling"]
        default_values = {"split_pos": 3, "ttl": 4, "fooling": "badsum"}

        # Generate zapret command based on attack name patterns
        if "fragment" in attack_name.lower():
            zapret_cmd = "--dpi-desync=split"
        elif "disorder" in attack_name.lower():
            zapret_cmd = "--dpi-desync=fake,disorder"
        elif "split" in attack_name.lower():
            zapret_cmd = "--dpi-desync=multisplit"
        elif "race" in attack_name.lower():
            zapret_cmd = "--dpi-desync=fake"
        elif "quic" in attack_name.lower():
            zapret_cmd = "--filter-udp=443 --dpi-desync=fake"
        elif "tls" in attack_name.lower():
            zapret_cmd = "--dpi-desync=fake"
        elif "http" in attack_name.lower():
            zapret_cmd = "--dpi-desync=fake"
        else:
            # Generic fallback
            zapret_cmd = "--dpi-desync=fake"

        return zapret_cmd, default_params, default_values, []

    def get_attack_info(self, attack_name: str) -> Optional[AttackInfo]:
        """Get attack information by name or alias."""
        # Check direct name
        if attack_name in self.attacks:
            return self.attacks[attack_name]

        # Check aliases
        if attack_name in self.aliases:
            return self.attacks[self.aliases[attack_name]]

        return None

    def get_all_attacks(self) -> Dict[str, AttackInfo]:
        """Get all attack information."""
        return self.attacks.copy()

    def get_attacks_by_category(self, category: str) -> Dict[str, AttackInfo]:
        """Get attacks by category."""
        if category not in self.categories:
            return {}

        return {
            name: self.attacks[name] for name in self.categories[category] if name in self.attacks
        }

    def get_categories(self) -> List[str]:
        """Get all available categories."""
        return sorted(list(self.categories.keys()))

    def is_supported(self, attack_name: str) -> bool:
        """Check if an attack is supported."""
        return attack_name in self.attacks or attack_name in self.aliases

    def get_zapret_command(
        self, attack_name: str, params: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Generate zapret command for an attack with given parameters."""
        attack_info = self.get_attack_info(attack_name)
        if not attack_info:
            return None

        # Start with base command
        cmd_parts = [attack_info.zapret_args]

        # Add parameters
        if params is None:
            params = attack_info.default_params

        # Add parameter-specific arguments with special handling for certain attacks
        param_mappings = {
            "split_pos": "--dpi-desync-split-pos",
            "split_count": "--dpi-desync-split-count",
            "split_seqovl": "--dpi-desync-split-seqovl",
            "ttl": "--dpi-desync-ttl",
            "fooling": "--dpi-desync-fooling",
            "repeats": "--dpi-desync-repeats",
            "delay": "--dpi-desync-delay",
            "fragment_size": "--dpi-desync-split-pos",  # For IP fragmentation
            "window_size": "--tcp-window-size",
        }

        # Special handling for specific attack types
        if attack_name in ["seqovl", "sequence_overlap", "tcp_seqovl"]:
            # For seqovl attacks, use overlap_size as split_seqovl if available
            if "overlap_size" in params and "split_seqovl" not in params:
                params = params.copy()
                params["split_seqovl"] = params["overlap_size"]

        elif attack_name in ["multisplit", "tcp_multisplit"]:
            # For multisplit attacks, calculate split_count from positions if available
            if "positions" in params and "split_count" not in params:
                params = params.copy()
                positions = params["positions"]
                params["split_count"] = len(positions) if positions else 3
            # Set default split_seqovl to 0 if not specified
            if "split_seqovl" not in params:
                params = params.copy()
                params["split_seqovl"] = 0

        # Add parameters
        for param_name in attack_info.parameters:
            if param_name in params:
                value = params[param_name]
                # Special handling for list parameters - convert to comma-separated string
                if isinstance(value, list):
                    if param_name == "positions":
                        # For positions parameter, convert to comma-separated string without brackets
                        value = ",".join(str(v) for v in value)
                    else:
                        # For other list parameters, convert to comma-separated string
                        value = ",".join(str(v) for v in value)
                if param_name in param_mappings:
                    cmd_parts.append(f"{param_mappings[param_name]}={value}")

        # Add additional parameters that might not be in attack_info.parameters
        additional_params = [
            "split_pos",
            "split_count",
            "split_seqovl",
            "ttl",
            "fooling",
        ]
        for param_name in additional_params:
            if param_name in params and param_name not in attack_info.parameters:
                # Special handling for list parameters - convert to comma-separated string
                value = params[param_name]
                if isinstance(value, list):
                    if param_name == "positions":
                        # For positions parameter, convert to comma-separated string without brackets
                        value = ",".join(str(v) for v in value)
                    else:
                        # For other list parameters, convert to comma-separated string
                        value = ",".join(str(v) for v in value)
                if param_name in param_mappings:
                    cmd_parts.append(f"{param_mappings[param_name]}={value}")

        return " ".join(cmd_parts)

    def extract_strategy_type(self, strategy: str) -> str:
        """Extract attack type from zapret strategy string."""
        strategy_lower = strategy.lower()

        # Check for specific patterns in the strategy string with FIXED priorities
        # Order matters - most specific patterns first
        type_patterns = [
            # Priority 1: Very specific multi-component patterns (highest priority)
            ("fake_fakeddisorder", ["fake,fakeddisorder"]),
            ("tcp_multisplit", ["tcp.*multisplit", "multisplit.*tcp"]),
            ("tcp_multidisorder", ["tcp.*multidisorder", "multidisorder.*tcp"]),
            ("tcp_seqovl", ["tcp.*seqovl", "seqovl.*tcp"]),
            # Priority 2: Specific zapret command patterns (very specific)
            ("ip_fragmentation_advanced", ["ipfrag2"]),
            ("timing_based_evasion", ["dpi-desync-delay", "delay="]),
            ("force_tcp", ["filter-udp=443"]),
            ("badsum_race", ["dpi-desync-fooling=badsum", "fooling.*badsum", "badsum"]),
            ("md5sig_race", ["dpi-desync-fooling=md5sig", "fooling.*md5sig", "md5sig"]),
            ("badseq_fooling", ["dpi-desync-fooling=badseq", "fooling.*badseq"]),
            # Priority 3: Fake disorder patterns (must come before generic disorder)
            ("fake_disorder", ["fake,disorder", "fakeddisorder", "fake.*disorder"]),
            # Priority 4: Multi-attack patterns (must come before single variants)
            ("multisplit", ["multisplit"]),
            ("multidisorder", ["multidisorder"]),
            ("sequence_overlap", ["seqovl"]),
            # Priority 5: TLS/HTTP specific patterns
            ("tls_record_fragmentation", ["tls.*record.*split", "tls-record-split"]),
            ("http_header_case", ["http.*header.*case", "http-header-case"]),
            ("h2_frame_splitting", ["h2.*frame.*split", "http2.*frame"]),
            ("sni_manipulation", ["sni.*manip", "host.*header"]),
            # Priority 6: QUIC patterns
            ("quic_fragmentation", ["quic.*frag", "udp.*443.*frag"]),
            ("quic_bypass", ["quic.*bypass", "disable.*quic"]),
            # Priority 7: Window and TCP options patterns
            ("window_manipulation", ["tcp.*window", "window.*scale"]),
            ("tcp_options_modification", ["tcp.*options", "tcp-options-modify"]),
            # Priority 8: Basic fragmentation patterns (lower priority)
            (
                "simple_fragment",
                ["\\bsplit\\b(?!.*multi)", "split"],
            ),  # split but not multisplit
            (
                "tcp_fragmentation",
                ["tcp.*split(?!.*multi)"],
            ),  # tcp split but not multisplit
            ("ip_fragmentation", ["ip.*frag(?!2)"]),  # ip frag but not ipfrag2
            # Priority 9: Timing patterns (generic, lower priority)
            ("timing_based", ["\\bdelay\\b", "timing"]),
            # Priority 10: Generic patterns (lowest priority)
            (
                "disorder",
                ["\\bdisorder\\b(?!.*multi)(?!.*fake)"],
            ),  # disorder but not multidisorder or fake disorder
        ]

        import re

        for attack_type, patterns in type_patterns:
            for pattern in patterns:
                try:
                    if re.search(pattern, strategy_lower):
                        return attack_type
                except re.error:
                    # Fallback to simple string matching for invalid regex
                    if pattern in strategy_lower:
                        return attack_type

        # Check against all registered attacks
        for attack_name in self.attacks:
            if attack_name.lower() in strategy_lower:
                return attack_name

        return "unknown"

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the attack mapping."""
        return {
            "total_attacks": len(self.attacks),
            "categories": {cat: len(attacks) for cat, attacks in self.categories.items()},
            "total_aliases": len(self.aliases),
            "supported_zapret_commands": len([a for a in self.attacks.values() if a.zapret_args]),
        }


# Global instance
_attack_mapping = None


def get_attack_mapping() -> ComprehensiveAttackMapping:
    """Get the global attack mapping instance."""
    global _attack_mapping
    if _attack_mapping is None:
        _attack_mapping = ComprehensiveAttackMapping()
    return _attack_mapping


def is_attack_supported(attack_name: str) -> bool:
    """Check if an attack is supported."""
    return get_attack_mapping().is_supported(attack_name)


def get_supported_attacks() -> List[str]:
    """Get list of all supported attack names."""
    return list(get_attack_mapping().get_all_attacks().keys())


def generate_zapret_command(
    attack_name: str, params: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """Generate zapret command for an attack."""
    return get_attack_mapping().get_zapret_command(attack_name, params)


if __name__ == "__main__":
    # Test the mapping system
    mapping = ComprehensiveAttackMapping()

    print("Attack Mapping Statistics:")
    stats = mapping.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print(f"\nSupported attacks ({len(mapping.get_all_attacks())}):")
    for attack_name in sorted(mapping.get_all_attacks().keys()):
        attack_info = mapping.get_attack_info(attack_name)
        if attack_info:
            print(f"  {attack_name}: {attack_info.zapret_args}")
        else:
            print(f"  {attack_name}: No attack info available")

    print(f"\nCategories ({len(mapping.get_categories())}):")
    for category in mapping.get_categories():
        attacks = mapping.get_attacks_by_category(category)
        print(f"  {category}: {len(attacks)} attacks")
