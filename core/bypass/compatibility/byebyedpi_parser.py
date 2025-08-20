"""
ByeByeDPI Configuration Parser

Parser for ByeByeDPI command-line syntax and configuration.
Handles all ByeByeDPI parameters and converts them to native format.
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field

LOG = logging.getLogger(__name__)


@dataclass
class ByeByeDPIParameter:
    """ByeByeDPI parameter with value and metadata."""

    name: str
    value: Any
    raw_value: str
    parameter_type: str  # 'flag', 'value', 'list'
    description: str = ""


@dataclass
class ByeByeDPIConfig:
    """Parsed ByeByeDPI configuration."""

    parameters: Dict[str, ByeByeDPIParameter] = field(default_factory=dict)
    raw_command: str = ""
    active_methods: Set[str] = field(default_factory=set)
    split_positions: List[int] = field(default_factory=list)

    def to_native_format(self) -> Dict[str, Any]:
        """Convert to native bypass engine format."""
        attack_methods = []

        # Map ByeByeDPI methods to native attacks
        if "split" in self.active_methods:
            attack_methods.append("tcp_splitting")
        if "disorder" in self.active_methods:
            attack_methods.append("packet_disorder")
        if "fake" in self.active_methods:
            attack_methods.append("fake_packet_injection")
        if "http-modify" in self.active_methods:
            attack_methods.append("http_modification")
        if "tls-modify" in self.active_methods:
            attack_methods.append("tls_modification")

        return {
            "attack_type": "byebyedpi_combo",
            "parameters": {
                "methods": attack_methods,
                "split_positions": self.split_positions,
                "fragment_size": (
                    self.parameters.get("fragment-size", {}).value
                    if "fragment-size" in self.parameters
                    else None
                ),
                "window_size": (
                    self.parameters.get("window-size", {}).value
                    if "window-size" in self.parameters
                    else None
                ),
                "fake_ttl": (
                    self.parameters.get("fake-ttl", {}).value
                    if "fake-ttl" in self.parameters
                    else None
                ),
                "disorder_count": (
                    self.parameters.get("disorder-count", {}).value
                    if "disorder-count" in self.parameters
                    else None
                ),
                "split_count": (
                    self.parameters.get("split-count", {}).value
                    if "split-count" in self.parameters
                    else None
                ),
            },
            "metadata": {
                "source": "byebyedpi",
                "raw_command": self.raw_command,
                "active_methods": list(self.active_methods),
            },
        }


class ByeByeDPIParser:
    """
    Comprehensive parser for ByeByeDPI command-line syntax.

    Handles all ByeByeDPI parameters including:
    - Split positions and methods
    - Packet disorder techniques
    - HTTP and TLS modifications
    - Fragment and window size controls
    """

    def __init__(self):
        self.logger = LOG
        self._initialize_parameter_definitions()

    def _initialize_parameter_definitions(self):
        """Initialize ByeByeDPI parameter definitions."""

        # Parameter definitions with types and descriptions
        self.parameter_defs = {
            # Core bypass methods
            "split-pos": {
                "type": "list",
                "description": "Packet split positions",
                "method": "split",
            },
            "split-count": {
                "type": "integer",
                "description": "Number of packet splits",
                "method": "split",
            },
            "disorder": {
                "type": "flag",
                "description": "Enable packet disorder",
                "method": "disorder",
            },
            "disorder-count": {
                "type": "integer",
                "description": "Number of disordered packets",
                "method": "disorder",
            },
            "fake-packet": {
                "type": "flag",
                "description": "Enable fake packet injection",
                "method": "fake",
            },
            "fake-ttl": {
                "type": "integer",
                "description": "TTL for fake packets",
                "method": "fake",
            },
            # Protocol modifications
            "http-modify": {
                "type": "flag",
                "description": "Enable HTTP header modification",
                "method": "http-modify",
            },
            "tls-modify": {
                "type": "flag",
                "description": "Enable TLS modification",
                "method": "tls-modify",
            },
            # Size controls
            "fragment-size": {
                "type": "integer",
                "description": "Maximum fragment size",
            },
            "window-size": {"type": "integer", "description": "TCP window size"},
            # Advanced options
            "help-bypass": {"type": "flag", "description": "Show bypass help"},
            "verbose": {"type": "flag", "description": "Enable verbose output"},
            "daemon": {"type": "flag", "description": "Run as daemon"},
            "port": {"type": "integer", "description": "Listen port"},
            "bind-addr": {"type": "string", "description": "Bind address"},
        }

    def parse(self, command: str) -> ByeByeDPIConfig:
        """
        Parse ByeByeDPI command-line string into structured configuration.

        Args:
            command: ByeByeDPI command-line string

        Returns:
            ByeByeDPIConfig object with parsed parameters
        """
        command = command.strip()
        config = ByeByeDPIConfig(raw_command=command)

        self.logger.debug(f"Parsing ByeByeDPI command: {command}")

        # Parse all parameters
        self._parse_parameters(command, config)

        # Extract split positions first
        self._extract_split_positions(config)

        # Extract active methods (after split positions)
        self._extract_active_methods(config)

        self.logger.info(
            f"Parsed ByeByeDPI config with {len(config.parameters)} parameters"
        )
        return config

    def _parse_parameters(self, command: str, config: ByeByeDPIConfig):
        """Parse all parameters from command string."""

        # Pattern to match --parameter=value, --parameter value, or --parameter
        param_pattern = re.compile(r"--([a-zA-Z0-9-]+)(?:=([^\s]+)|\s+([^\s-][^\s]*))?")

        for match in param_pattern.finditer(command):
            param_name = match.group(1)
            param_value = match.group(2) or match.group(
                3
            )  # Either =value or space value

            # Get parameter definition
            param_def = self.parameter_defs.get(param_name, {})
            param_type = param_def.get("type", "unknown")

            # Parse value based on type
            parsed_value = self._parse_parameter_value(
                param_value, param_type, param_def
            )

            # Store parameter
            config.parameters[param_name] = ByeByeDPIParameter(
                name=param_name,
                value=parsed_value,
                raw_value=param_value or "",
                parameter_type=param_type,
                description=param_def.get("description", ""),
            )

    def _parse_parameter_value(
        self, value: Optional[str], param_type: str, param_def: Dict[str, Any]
    ) -> Any:
        """Parse parameter value based on its type."""

        if value is None:
            # Flag parameter without value
            if param_type == "flag":
                return True
            return param_def.get("default")

        try:
            if param_type == "integer":
                return int(value)
            elif param_type == "list":
                # Handle comma-separated lists
                if "," in value:
                    return [
                        int(x.strip()) if x.strip().isdigit() else x.strip()
                        for x in value.split(",")
                    ]
                else:
                    return [int(value) if value.isdigit() else value]
            elif param_type == "flag":
                return value.lower() in ["true", "1", "yes"]
            else:
                return value

        except (ValueError, TypeError) as e:
            self.logger.warning(
                f"Failed to parse parameter value '{value}' as {param_type}: {e}"
            )
            return value

    def _extract_active_methods(self, config: ByeByeDPIConfig):
        """Extract active bypass methods from parameters."""

        for param_name, param in config.parameters.items():
            param_def = self.parameter_defs.get(param_name, {})
            method = param_def.get("method")

            if method and param.value:
                config.active_methods.add(method)

        # Special handling for split-pos which implies split method
        if "split-pos" in config.parameters and config.parameters["split-pos"].value:
            config.active_methods.add("split")

    def _extract_split_positions(self, config: ByeByeDPIConfig):
        """Extract split positions from parameters."""

        if "split-pos" in config.parameters:
            positions = config.parameters["split-pos"].value
            if isinstance(positions, list):
                config.split_positions = [
                    pos for pos in positions if isinstance(pos, int)
                ]
            elif isinstance(positions, int):
                config.split_positions = [positions]

    def validate_config(self, config: ByeByeDPIConfig) -> List[str]:
        """
        Validate ByeByeDPI configuration and return list of issues.

        Args:
            config: ByeByeDPIConfig to validate

        Returns:
            List of validation error messages
        """
        issues = []

        # Check for required parameter combinations
        if "split" in config.active_methods and not config.split_positions:
            issues.append("Split method requires split positions (--split-pos)")

        if "fake" in config.active_methods and "fake-ttl" not in config.parameters:
            issues.append("Fake packet method should specify TTL (--fake-ttl)")

        # Validate parameter values
        if "port" in config.parameters:
            port = config.parameters["port"].value
            if port < 1 or port > 65535:
                issues.append(f"Port {port} must be between 1 and 65535")

        if "fake-ttl" in config.parameters:
            ttl = config.parameters["fake-ttl"].value
            if ttl < 1 or ttl > 255:
                issues.append(f"TTL {ttl} must be between 1 and 255")

        if "fragment-size" in config.parameters:
            size = config.parameters["fragment-size"].value
            if size < 1:
                issues.append(f"Fragment size {size} must be positive")

        # Validate split positions
        for pos in config.split_positions:
            if pos < 1:
                issues.append(f"Split position {pos} must be positive")

        return issues

    def get_parameter_help(self, parameter: str) -> Optional[str]:
        """Get help text for a specific parameter."""
        param_def = self.parameter_defs.get(parameter)
        if param_def:
            return param_def.get("description", "")
        return None

    def list_all_parameters(self) -> Dict[str, str]:
        """Get list of all supported parameters with descriptions."""
        return {
            param: definition.get("description", "")
            for param, definition in self.parameter_defs.items()
        }

    def get_method_parameters(self, method: str) -> List[str]:
        """Get parameters associated with a specific bypass method."""
        parameters = []

        for param_name, param_def in self.parameter_defs.items():
            if param_def.get("method") == method:
                parameters.append(param_name)

        return parameters

    def get_common_configurations(self) -> Dict[str, Dict[str, Any]]:
        """Get common ByeByeDPI configurations with descriptions."""
        return {
            "basic_split": {
                "command": "--split-pos 2",
                "description": "Basic packet splitting at position 2",
                "use_case": "Simple DPI bypass",
            },
            "multi_split": {
                "command": "--split-pos 2,10,20 --split-count 3",
                "description": "Multiple split positions",
                "use_case": "Advanced fragmentation",
            },
            "fake_injection": {
                "command": "--fake-packet --fake-ttl 8 --split-pos 2",
                "description": "Fake packet injection with splitting",
                "use_case": "Sophisticated bypass",
            },
            "disorder_attack": {
                "command": "--disorder --disorder-count 3 --split-pos 2",
                "description": "Packet disorder with fragmentation",
                "use_case": "Anti-DPI reordering",
            },
            "http_modification": {
                "command": "--http-modify --split-pos 2",
                "description": "HTTP header modification with splitting",
                "use_case": "HTTP-specific bypass",
            },
            "comprehensive": {
                "command": "--split-pos 2,10 --disorder --fake-packet --fake-ttl 8 --http-modify",
                "description": "Comprehensive bypass with multiple methods",
                "use_case": "Maximum effectiveness",
            },
        }


# Convenience function
def parse_byebyedpi_command(command: str) -> ByeByeDPIConfig:
    """Parse ByeByeDPI command using default parser."""
    parser = ByeByeDPIParser()
    return parser.parse(command)
