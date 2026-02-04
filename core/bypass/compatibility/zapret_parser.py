"""
Zapret Configuration Parser

Comprehensive parser for zapret command-line syntax and configuration files.
Handles all zapret parameters and converts them to native format.
"""

import re
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

LOG = logging.getLogger(__name__)


@dataclass
class ZapretParameter:
    """Zapret parameter with value and metadata."""

    name: str
    value: Any
    raw_value: str
    parameter_type: str  # 'flag', 'value', 'list'
    description: str = ""


@dataclass
class ZapretConfig:
    """Parsed zapret configuration."""

    parameters: Dict[str, ZapretParameter] = field(default_factory=dict)
    raw_command: str = ""
    desync_methods: List[str] = field(default_factory=list)
    fooling_methods: List[str] = field(default_factory=list)
    split_positions: List[Dict[str, Any]] = field(default_factory=list)
    unknown_parameters: List[str] = field(default_factory=list)

    def to_native_format(self) -> Dict[str, Any]:
        """Convert to native bypass engine format."""
        return {
            "attack_type": "zapret_combo",
            "parameters": {
                "desync_methods": self.desync_methods,
                "fooling_methods": self.fooling_methods,
                "split_positions": self.split_positions,
                "ttl": (
                    self.parameters.get("dpi-desync-ttl").value
                    if "dpi-desync-ttl" in self.parameters
                    else None
                ),
                "repeats": (
                    self.parameters.get("dpi-desync-repeats").value
                    if "dpi-desync-repeats" in self.parameters
                    else 1
                ),
                "window_size": (
                    self.parameters.get("wssize").value if "wssize" in self.parameters else None
                ),
                "auto_ttl": (
                    self.parameters.get("dpi-desync-autottl").value
                    if "dpi-desync-autottl" in self.parameters
                    else None
                ),
                "fake_tls": (
                    self.parameters.get("dpi-desync-fake-tls").value
                    if "dpi-desync-fake-tls" in self.parameters
                    else None
                ),
                "fake_http": (
                    self.parameters.get("dpi-desync-fake-http").value
                    if "dpi-desync-fake-http" in self.parameters
                    else None
                ),
                "seqovl": (
                    self.parameters.get("dpi-desync-split-seqovl").value
                    if "dpi-desync-split-seqovl" in self.parameters
                    else None
                ),
                "badseq_increment": (
                    self.parameters.get("dpi-desync-badseq-increment").value
                    if "dpi-desync-badseq-increment" in self.parameters
                    else None
                ),
            },
            "metadata": {"source": "zapret", "raw_command": self.raw_command},
        }


class ZapretConfigParser:
    """
    Comprehensive parser for zapret command-line syntax.

    Handles all zapret parameters including:
    - DPI desync methods (split, fake, disorder, etc.)
    - Fooling methods (badsum, badseq, md5sig, etc.)
    - Split positions (absolute, midsld, etc.)
    - TTL and timing parameters
    - HTTP and TLS modifications
    """

    def __init__(self):
        self.logger = LOG
        self._initialize_parameter_definitions()

    def _initialize_parameter_definitions(self):
        """Initialize zapret parameter definitions."""

        # Parameter definitions with types and descriptions
        self.parameter_defs = {
            # Core DPI desync parameters
            "dpi-desync": {
                "type": "list",
                "description": "DPI desync methods (split, fake, disorder, etc.)",
                "valid_values": [
                    "split",
                    "fake",
                    "disorder",
                    "split2",
                    "tlsrec",
                    "ipfrag1",
                    "ipfrag2",
                ],
            },
            "dpi-desync-fooling": {
                "type": "list",
                "description": "Fooling methods for fake packets",
                "valid_values": [
                    "badsum",
                    "badseq",
                    "md5sig",
                    "tcp_md5sig",
                    "hopbyhop",
                    "destopt",
                    "ipfrag1",
                ],
            },
            "dpi-desync-split-pos": {
                "type": "split_positions",
                "description": "Split positions for packet fragmentation",
            },
            "dpi-desync-ttl": {
                "type": "integer",
                "description": "TTL for fake packets",
            },
            "dpi-desync-autottl": {
                "type": "flag_or_value",
                "description": "Auto TTL detection and setting",
            },
            "dpi-desync-repeats": {
                "type": "integer",
                "description": "Number of fake packet repeats",
                "default": 1,
            },
            "dpi-desync-split-seqovl": {
                "type": "integer",
                "description": "Sequence overlap for split packets",
            },
            "dpi-desync-badseq-increment": {
                "type": "integer",
                "description": "Bad sequence number increment",
                "default": -10000,
            },
            "dpi-desync-split-count": {
                "type": "integer",
                "description": "Number of splits for multisplit",
            },
            # Fake packet parameters
            "dpi-desync-fake-tls": {
                "type": "flag_or_value",
                "description": "Fake TLS packet generation",
            },
            "dpi-desync-fake-tls-mod": {
                "type": "list",
                "description": "TLS fake packet modifications",
            },
            "dpi-desync-fake-http": {
                "type": "flag_or_value",
                "description": "Fake HTTP packet generation",
            },
            "dpi-desync-fake-syndata": {
                "type": "flag_or_value",
                "description": "Fake SYN data generation",
            },
            # Window size
            "wssize": {"type": "integer", "description": "TCP window size limit"},
            # HTTP modifications
            "hostcase": {"type": "flag", "description": "Change Host header case"},
            "hostpad": {"type": "flag", "description": "Add padding to Host header"},
            "methodspace": {
                "type": "flag",
                "description": "Add space after HTTP method",
            },
            "unixeol": {"type": "flag", "description": "Use Unix EOL in HTTP headers"},
        }

    def parse(self, command: str) -> ZapretConfig:
        """
        Parse zapret command-line string into structured configuration.

        Args:
            command: Zapret command-line string

        Returns:
            ZapretConfig object with parsed parameters
        """
        command = command.strip()
        config = ZapretConfig(raw_command=command)

        self.logger.debug(f"Parsing zapret command: {command}")

        # Parse all parameters using regex
        self._parse_parameters(command, config)

        # Extract specific parameter groups
        self._extract_desync_methods(config)
        self._extract_fooling_methods(config)
        self._extract_split_positions(config)

        self.logger.info(f"Parsed zapret config with {len(config.parameters)} parameters")
        return config

    def _parse_parameters(self, command: str, config: ZapretConfig):
        """Parse all parameters from command string."""

        # Pattern to match --parameter=value or --parameter
        param_pattern = re.compile(r"--([a-zA-Z0-9-]+)(?:=([^\s]+))?")

        for match in param_pattern.finditer(command):
            param_name = match.group(1)
            param_value = match.group(2)

            # Get parameter definition
            if param_name in self.parameter_defs:
                param_def = self.parameter_defs[param_name]
                param_type = param_def.get("type", "unknown")

                # Parse value based on type
                parsed_value = self._parse_parameter_value(param_value, param_type, param_def)

                # Store parameter
                config.parameters[param_name] = ZapretParameter(
                    name=param_name,
                    value=parsed_value,
                    raw_value=param_value or "",
                    parameter_type=param_type,
                    description=param_def.get("description", ""),
                )
            else:
                config.unknown_parameters.append(param_name)

    def _parse_parameter_value(
        self, value: Optional[str], param_type: str, param_def: Dict[str, Any]
    ) -> Any:
        """Parse parameter value based on its type."""

        if value is None:
            # Flag parameter without value
            if param_type == "flag" or param_type == "flag_or_value":
                return True
            return param_def.get("default")

        try:
            if param_type == "integer":
                return int(value)
            elif param_type == "list":
                return value.split(",")
            elif param_type == "split_positions":
                return self._parse_split_positions(value)
            elif param_type == "flag_or_value":
                # Could be a flag (True) or have a value
                if value.lower() in ["true", "1", "yes"]:
                    return True
                elif value.lower() in ["false", "0", "no"]:
                    return False
                else:
                    return value
            else:
                return value

        except (ValueError, TypeError) as e:
            self.logger.warning(f"Failed to parse parameter value '{value}' as {param_type}: {e}")
            return value

    def _parse_split_positions(self, positions_str: str) -> List[Dict[str, Any]]:
        """Parse split positions string into structured format."""
        positions = []

        for pos in positions_str.split(","):
            pos = pos.strip()

            if pos == "midsld":
                positions.append({"type": "midsld", "description": "Middle of second-level domain"})
            elif pos == "host":
                positions.append({"type": "host", "description": "Host header position"})
            elif pos == "method":
                positions.append({"type": "method", "description": "HTTP method position"})
            elif pos.isdigit() or (pos.startswith("-") and pos[1:].isdigit()):
                positions.append(
                    {
                        "type": "absolute",
                        "value": int(pos),
                        "description": f"Absolute position {pos}",
                    }
                )
            elif ":" in pos:
                # Range format like "1:10"
                try:
                    start, end = pos.split(":", 1)
                    positions.append(
                        {
                            "type": "range",
                            "start": int(start),
                            "end": int(end),
                            "description": f"Range {start}:{end}",
                        }
                    )
                except ValueError:
                    positions.append(
                        {
                            "type": "unknown",
                            "raw": pos,
                            "description": f"Unknown position format: {pos}",
                        }
                    )
            else:
                positions.append(
                    {
                        "type": "unknown",
                        "raw": pos,
                        "description": f"Unknown position format: {pos}",
                    }
                )

        return positions

    def _extract_desync_methods(self, config: ZapretConfig):
        """Extract DPI desync methods from parameters."""
        if "dpi-desync" in config.parameters:
            config.desync_methods = config.parameters["dpi-desync"].value or []

    def _extract_fooling_methods(self, config: ZapretConfig):
        """Extract fooling methods from parameters."""
        if "dpi-desync-fooling" in config.parameters:
            config.fooling_methods = config.parameters["dpi-desync-fooling"].value or []

    def _extract_split_positions(self, config: ZapretConfig):
        """Extract split positions from parameters."""
        if "dpi-desync-split-pos" in config.parameters:
            config.split_positions = config.parameters["dpi-desync-split-pos"].value or []

    def validate_config(self, config: ZapretConfig) -> List[str]:
        """
        Validate zapret configuration and return list of issues.

        Args:
            config: ZapretConfig to validate

        Returns:
            List of validation error messages
        """
        issues = []

        # Check for required parameter combinations
        if "fake" in config.desync_methods:
            if (
                "dpi-desync-ttl" not in config.parameters
                and "dpi-desync-autottl" not in config.parameters
            ):
                issues.append(
                    "Fake method requires TTL setting (--dpi-desync-ttl or --dpi-desync-autottl)"
                )

        if "split" in config.desync_methods or "split2" in config.desync_methods:
            if not config.split_positions:
                issues.append("Split method requires split positions (--dpi-desync-split-pos)")

        # Validate parameter values
        for param_name, param in config.parameters.items():
            param_def = self.parameter_defs.get(param_name, {})
            valid_values = param_def.get("valid_values")

            if valid_values and isinstance(param.value, list):
                for value in param.value:
                    if value not in valid_values:
                        issues.append(f"Invalid value '{value}' for parameter {param_name}")

        # Check for unknown parameters
        if config.unknown_parameters:
            for param_name in config.unknown_parameters:
                issues.append(f"Unknown parameter '--{param_name}'")

        return issues

    def get_parameter_help(self, parameter: str) -> Optional[str]:
        """Get help text for a specific parameter."""
        param_def = self.parameter_defs.get(parameter)
        if param_def:
            help_text = param_def.get("description", "")
            valid_values = param_def.get("valid_values")
            if valid_values:
                help_text += f"\nValid values: {', '.join(valid_values)}"
            return help_text
        return None

    def list_all_parameters(self) -> Dict[str, str]:
        """Get list of all supported parameters with descriptions."""
        return {
            param: definition.get("description", "")
            for param, definition in self.parameter_defs.items()
        }


# Convenience function
def parse_zapret_command(command: str) -> ZapretConfig:
    """Parse zapret command using default parser."""
    parser = ZapretConfigParser()
    return parser.parse(command)
