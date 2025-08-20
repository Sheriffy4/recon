"""
GoodbyeDPI Configuration Parser

Parser for GoodbyeDPI command-line syntax and configuration.
Handles all GoodbyeDPI parameters and converts them to native format.
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field

LOG = logging.getLogger(__name__)


@dataclass
class GoodbyeDPIParameter:
    """GoodbyeDPI parameter with value and metadata."""

    name: str
    value: Any
    raw_value: str
    parameter_type: str  # 'flag', 'value', 'position'
    description: str = ""


@dataclass
class GoodbyeDPIConfig:
    """Parsed GoodbyeDPI configuration."""

    parameters: Dict[str, GoodbyeDPIParameter] = field(default_factory=dict)
    raw_command: str = ""
    active_flags: Set[str] = field(default_factory=set)
    fragment_positions: List[int] = field(default_factory=list)

    def to_native_format(self) -> Dict[str, Any]:
        """Convert to native bypass engine format."""
        attack_methods = []

        # Map GoodbyeDPI flags to native attacks
        if "f" in self.active_flags:
            attack_methods.append("tcp_fragmentation")
        if "m" in self.active_flags:
            attack_methods.append("http_header_modification")
        if "e" in self.active_flags:
            attack_methods.append("fake_packet_injection")
        if "p" in self.active_flags:
            attack_methods.append("http_persistence_fix")
        if "r" in self.active_flags:
            attack_methods.append("fragment_replacement")
        if "s" in self.active_flags:
            attack_methods.append("sni_removal")
        if "w" in self.active_flags:
            attack_methods.append("wrong_checksum")

        return {
            "attack_type": "goodbyedpi_combo",
            "parameters": {
                "methods": attack_methods,
                "fragment_positions": self.fragment_positions,
                "max_payload": (
                    self.parameters.get("max-payload", {}).value
                    if "max-payload" in self.parameters
                    else None
                ),
                "set_ttl": (
                    self.parameters.get("set-ttl", {}).value
                    if "set-ttl" in self.parameters
                    else None
                ),
                "auto_ttl": "auto-ttl" in self.parameters,
                "wrong_checksum": "wrong-chksum" in self.parameters,
                "wrong_seq": "wrong-seq" in self.parameters,
                "ip_id": (
                    self.parameters.get("ip-id", {}).value
                    if "ip-id" in self.parameters
                    else None
                ),
                "blacklist": (
                    self.parameters.get("blacklist", {}).value
                    if "blacklist" in self.parameters
                    else None
                ),
            },
            "metadata": {
                "source": "goodbyedpi",
                "raw_command": self.raw_command,
                "active_flags": list(self.active_flags),
            },
        }


class GoodbyeDPIParser:
    """
    Comprehensive parser for GoodbyeDPI command-line syntax.

    Handles all GoodbyeDPI parameters including:
    - Single-letter flags (-f, -m, -e, etc.)
    - Long options (--max-payload, --set-ttl, etc.)
    - Fragment positions and sizes
    - Blacklist and whitelist files
    """

    def __init__(self):
        self.logger = LOG
        self._initialize_parameter_definitions()

    def _initialize_parameter_definitions(self):
        """Initialize GoodbyeDPI parameter definitions."""

        # Single-letter flag definitions
        self.flag_defs = {
            "p": {
                "name": "http_persistence",
                "description": "Handle HTTP persistent (keep-alive) connections",
            },
            "r": {
                "name": "fragment_replace",
                "description": "Replace fragment with original packet",
            },
            "s": {
                "name": "sni_remove",
                "description": "Remove SNI extension from TLS ClientHello",
            },
            "m": {"name": "http_modify", "description": "Modify HTTP request headers"},
            "f": {
                "name": "fragment",
                "description": "Fragment TCP packets at specified position",
                "has_value": True,
            },
            "k": {
                "name": "fragment_fake",
                "description": "Fragment and send fake packet",
                "has_value": True,
            },
            "e": {
                "name": "fake_packet",
                "description": "Send fake packet with wrong checksum",
            },
            "w": {
                "name": "window_size",
                "description": "Set TCP window size",
                "has_value": True,
            },
            "W": {
                "name": "window_scale",
                "description": "Set TCP window scale factor",
                "has_value": True,
            },
        }

        # Long option definitions
        self.long_option_defs = {
            "max-payload": {
                "type": "integer",
                "description": "Maximum payload size for processing",
            },
            "set-ttl": {
                "type": "integer",
                "description": "Set TTL for outgoing packets",
            },
            "auto-ttl": {"type": "flag", "description": "Automatically determine TTL"},
            "wrong-chksum": {
                "type": "flag",
                "description": "Use wrong TCP checksum for fake packets",
            },
            "wrong-seq": {
                "type": "flag",
                "description": "Use wrong TCP sequence number",
            },
            "native-frag": {"type": "flag", "description": "Use native fragmentation"},
            "reverse-frag": {"type": "flag", "description": "Reverse fragment order"},
            "ip-id": {"type": "integer", "description": "Set IP identification field"},
            "blacklist": {"type": "string", "description": "Path to blacklist file"},
            "dns-addr": {"type": "string", "description": "DNS server address"},
            "dns-port": {"type": "integer", "description": "DNS server port"},
            "dnsv6-addr": {"type": "string", "description": "IPv6 DNS server address"},
            "dnsv6-port": {"type": "integer", "description": "IPv6 DNS server port"},
        }

    def parse(self, command: str) -> GoodbyeDPIConfig:
        """
        Parse GoodbyeDPI command-line string into structured configuration.

        Args:
            command: GoodbyeDPI command-line string

        Returns:
            GoodbyeDPIConfig object with parsed parameters
        """
        command = command.strip()
        config = GoodbyeDPIConfig(raw_command=command)

        self.logger.debug(f"Parsing GoodbyeDPI command: {command}")

        # Parse single-letter flags
        self._parse_single_flags(command, config)

        # Parse long options
        self._parse_long_options(command, config)

        # Extract fragment positions
        self._extract_fragment_positions(config)

        self.logger.info(
            f"Parsed GoodbyeDPI config with {len(config.parameters)} parameters"
        )
        return config

    def _parse_single_flags(self, command: str, config: GoodbyeDPIConfig):
        """Parse single-letter flags from command string."""

        # Pattern to match -flag or -flag value
        flag_pattern = re.compile(r"-([a-zA-Z])(?:\s+(\d+))?")

        for match in flag_pattern.finditer(command):
            flag = match.group(1)
            value = match.group(2)

            if flag in self.flag_defs:
                flag_def = self.flag_defs[flag]
                config.active_flags.add(flag)

                # Parse value if present
                parsed_value = True  # Default for flags
                if value and flag_def.get("has_value"):
                    try:
                        parsed_value = int(value)
                    except ValueError:
                        parsed_value = value

                config.parameters[flag] = GoodbyeDPIParameter(
                    name=flag_def["name"],
                    value=parsed_value,
                    raw_value=value or "",
                    parameter_type="flag",
                    description=flag_def["description"],
                )

    def _parse_long_options(self, command: str, config: GoodbyeDPIConfig):
        """Parse long options from command string."""

        # Pattern to match --option=value or --option
        option_pattern = re.compile(r"--([a-zA-Z0-9-]+)(?:=([^\s]+))?")

        for match in option_pattern.finditer(command):
            option_name = match.group(1)
            option_value = match.group(2)

            if option_name in self.long_option_defs:
                option_def = self.long_option_defs[option_name]

                # Parse value based on type
                parsed_value = self._parse_option_value(option_value, option_def)

                config.parameters[option_name] = GoodbyeDPIParameter(
                    name=option_name,
                    value=parsed_value,
                    raw_value=option_value or "",
                    parameter_type=option_def["type"],
                    description=option_def["description"],
                )

    def _parse_option_value(
        self, value: Optional[str], option_def: Dict[str, Any]
    ) -> Any:
        """Parse option value based on its type."""

        option_type = option_def["type"]

        if value is None:
            return True if option_type == "flag" else None

        try:
            if option_type == "integer":
                return int(value)
            elif option_type == "flag":
                return value.lower() in ["true", "1", "yes"]
            else:
                return value

        except (ValueError, TypeError) as e:
            self.logger.warning(
                f"Failed to parse option value '{value}' as {option_type}: {e}"
            )
            return value

    def _extract_fragment_positions(self, config: GoodbyeDPIConfig):
        """Extract fragment positions from parsed parameters."""

        # Check for -f flag with position
        if "f" in config.parameters:
            f_param = config.parameters["f"]
            if isinstance(f_param.value, int):
                config.fragment_positions.append(f_param.value)

        # Check for -k flag with position
        if "k" in config.parameters:
            k_param = config.parameters["k"]
            if isinstance(k_param.value, int):
                config.fragment_positions.append(k_param.value)

    def validate_config(self, config: GoodbyeDPIConfig) -> List[str]:
        """
        Validate GoodbyeDPI configuration and return list of issues.

        Args:
            config: GoodbyeDPIConfig to validate

        Returns:
            List of validation error messages
        """
        issues = []

        # Check for conflicting flags
        if "f" in config.active_flags and "k" in config.active_flags:
            issues.append("Flags -f and -k cannot be used together")

        if "native-frag" in config.parameters and "reverse-frag" in config.parameters:
            issues.append("--native-frag and --reverse-frag cannot be used together")

        # Validate fragment positions
        for pos in config.fragment_positions:
            if pos < 1:
                issues.append(f"Fragment position {pos} must be positive")

        # Validate TTL values
        if "set-ttl" in config.parameters:
            ttl = config.parameters["set-ttl"].value
            if ttl < 1 or ttl > 255:
                issues.append(f"TTL value {ttl} must be between 1 and 255")

        # Check for required files
        if "blacklist" in config.parameters:
            # Note: In a real implementation, you might want to check if file exists
            blacklist_path = config.parameters["blacklist"].value
            if not blacklist_path:
                issues.append("Blacklist path cannot be empty")

        return issues

    def get_flag_help(self, flag: str) -> Optional[str]:
        """Get help text for a specific flag."""
        flag_def = self.flag_defs.get(flag)
        if flag_def:
            return flag_def.get("description", "")
        return None

    def get_option_help(self, option: str) -> Optional[str]:
        """Get help text for a specific long option."""
        option_def = self.long_option_defs.get(option)
        if option_def:
            return option_def.get("description", "")
        return None

    def list_all_flags(self) -> Dict[str, str]:
        """Get list of all supported flags with descriptions."""
        return {
            flag: definition.get("description", "")
            for flag, definition in self.flag_defs.items()
        }

    def list_all_options(self) -> Dict[str, str]:
        """Get list of all supported long options with descriptions."""
        return {
            option: definition.get("description", "")
            for option, definition in self.long_option_defs.items()
        }

    def get_common_combinations(self) -> Dict[str, Dict[str, Any]]:
        """Get common flag combinations with descriptions."""
        return {
            "basic_fragmentation": {
                "flags": ["-f", "2"],
                "description": "Basic TCP fragmentation at position 2",
                "use_case": "Simple DPI bypass",
            },
            "fake_packet_injection": {
                "flags": ["-e", "-f", "2"],
                "description": "Fragment with fake packet injection",
                "use_case": "Advanced DPI bypass",
            },
            "http_modification": {
                "flags": ["-m", "-p"],
                "description": "HTTP header modification with persistence",
                "use_case": "HTTP-specific bypass",
            },
            "sni_removal": {
                "flags": ["-s", "-f", "2"],
                "description": "SNI removal with fragmentation",
                "use_case": "HTTPS bypass",
            },
            "comprehensive": {
                "flags": ["-f", "2", "-e", "-m", "-p", "-s"],
                "description": "Comprehensive bypass with multiple methods",
                "use_case": "Maximum compatibility",
            },
        }


# Convenience function
def parse_goodbyedpi_command(command: str) -> GoodbyeDPIConfig:
    """Parse GoodbyeDPI command using default parser."""
    parser = GoodbyeDPIParser()
    return parser.parse(command)
