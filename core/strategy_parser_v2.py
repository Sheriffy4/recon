"""Strategy Parser V2 - Enhanced parser with dual syntax support."""

import re
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class ParsedStrategy:
    attack_type: str
    params: Dict[str, Any]
    raw_string: str
    syntax_type: str


class StrategyParserV2:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.known_attacks = {
            "fake",
            "split",
            "disorder",
            "disorder2",
            "multisplit",
            "multidisorder",
            "fakeddisorder",
            "seqovl",
        }

    def parse(self, strategy_string: str) -> ParsedStrategy:
        if not strategy_string or not strategy_string.strip():
            raise ValueError("Empty strategy string")
        strategy_string = strategy_string.strip()
        if self._is_function_style(strategy_string):
            return self._parse_function_style(strategy_string)
        elif self._is_zapret_style(strategy_string):
            return self._parse_zapret_style(strategy_string)
        else:
            raise ValueError(f"Unknown syntax: {strategy_string}")

    def _is_function_style(self, strategy: str) -> bool:
        return bool(re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)\s*$", strategy))

    def _is_zapret_style(self, strategy: str) -> bool:
        return "--dpi-desync" in strategy

    def _parse_function_style(self, strategy: str) -> ParsedStrategy:
        match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*$", strategy)
        if not match:
            raise ValueError(f"Invalid function syntax: {strategy}")
        attack_name = match.group(1).lower().strip()
        params_str = match.group(2).strip()
        if attack_name not in self.known_attacks:
            self.logger.warning(f"Unknown attack type '{attack_name}'")
        params = self._parse_parameters(params_str) if params_str else {}
        return ParsedStrategy(
            attack_type=attack_name,
            params=params,
            raw_string=strategy,
            syntax_type="function",
        )

    def _parse_parameters(self, params_str: str) -> Dict[str, Any]:
        if not params_str:
            return {}
        params = {}
        parts = self._smart_split(params_str, ",")
        for part in parts:
            part = part.strip()
            if not part or "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key:
                params[key] = self._parse_value(value)
        return params

    def _parse_value(self, value_str: str) -> Any:
        value_str = value_str.strip()
        if not value_str:
            return None
        if value_str.startswith("[") and value_str.endswith("]"):
            return self._parse_list(value_str)
        if (value_str.startswith("'") and value_str.endswith("'")) or (
            value_str.startswith('"') and value_str.endswith('"')
        ):
            return value_str[1:-1]
        if value_str.lower() == "true":
            return True
        if value_str.lower() == "false":
            return False
        if value_str.lower() in ("none", "null"):
            return None
        try:
            if "." not in value_str and "e" not in value_str.lower():
                return int(value_str)
            return float(value_str)
        except ValueError:
            pass
        return value_str

    def _parse_list(self, list_str: str) -> List[Any]:
        content = list_str[1:-1].strip()
        if not content:
            return []
        items = self._smart_split(content, ",")
        return [self._parse_value(item.strip()) for item in items]

    def _smart_split(self, text: str, delimiter: str) -> List[str]:
        parts = []
        current = []
        depth = 0
        in_quote = None
        for char in text:
            if char in ('"', "'"):
                if in_quote is None:
                    in_quote = char
                elif in_quote == char:
                    in_quote = None
                current.append(char)
            elif char in ("[", "(", "{") and in_quote is None:
                depth += 1
                current.append(char)
            elif char in ("]", ")", "}") and in_quote is None:
                depth -= 1
                current.append(char)
            elif char == delimiter and depth == 0 and in_quote is None:
                parts.append("".join(current))
                current = []
            else:
                current.append(char)
        if current:
            parts.append("".join(current))
        return parts

    def _parse_zapret_style(self, strategy: str) -> ParsedStrategy:
        attack_match = re.search(r"--dpi-desync=([^\s]+)", strategy)
        if not attack_match:
            raise ValueError(f"No --dpi-desync found: {strategy}")
        attack_str = attack_match.group(1).lower()
        attack_parts = [p.strip() for p in attack_str.split(",")]

        # Determine attack type
        if "fake" in attack_parts and "disorder" in attack_parts:
            attack_type = "fakeddisorder"
        elif "multidisorder" in attack_parts:
            attack_type = "multidisorder"
        elif len(attack_parts) == 1:
            attack_type = attack_parts[0]
        else:
            attack_type = attack_parts[0]

        params = {}

        # Parse integer parameters
        for param_name in [
            "ttl",
            "autottl",
            "split-pos",
            "split-count",
            "split-seqovl",
            "repeats",
        ]:
            value = self._extract_zapret_int(strategy, param_name)
            if value is not None:
                key = param_name.replace("-", "_")
                params[key] = value

        # Parse string parameters
        for param_name in ["fake-sni"]:
            value = self._extract_zapret_string(strategy, param_name)
            if value is not None:
                key = param_name.replace("-", "_")
                params[key] = value

        # Parse fooling list
        fooling = self._extract_zapret_list(strategy, "fooling")
        if fooling:
            params["fooling"] = fooling

        # Map split_seqovl to overlap_size
        if "split_seqovl" in params:
            params["overlap_size"] = params["split_seqovl"]

        # Validate mutual exclusivity of ttl and autottl
        if "ttl" in params and "autottl" in params:
            raise ValueError(
                f"Cannot specify both --dpi-desync-ttl and --dpi-desync-autottl in the same strategy. "
                f"These parameters are mutually exclusive. Strategy: {strategy}"
            )

        # Set default for repeats if not specified
        if "repeats" not in params:
            params["repeats"] = 1

        return ParsedStrategy(
            attack_type=attack_type,
            params=params,
            raw_string=strategy,
            syntax_type="zapret",
        )

    def _extract_zapret_int(self, strategy: str, param_name: str) -> Optional[int]:
        pattern = rf"--dpi-desync-{param_name}=([^\s]+)"
        match = re.search(pattern, strategy)
        if not match:
            return None
        value_str = match.group(1)
        if value_str.lower() == "midsld":
            return "midsld"
        if "," in value_str:
            value_str = value_str.split(",")[0]
        try:
            return int(value_str)
        except ValueError:
            return None

    def _extract_zapret_string(self, strategy: str, param_name: str) -> Optional[str]:
        pattern = rf"--dpi-desync-{param_name}=([^\s]+)"
        match = re.search(pattern, strategy)
        return match.group(1) if match else None

    def _extract_zapret_list(self, strategy: str, param_name: str) -> List[str]:
        pattern = rf"--dpi-desync-{param_name}=([^\s]+)"
        match = re.search(pattern, strategy)
        if not match:
            return []
        value_str = match.group(1)
        return [item.strip() for item in value_str.split(",")]


class ParameterValidator:
    """Validates attack parameters against specifications."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Parameter specifications with type, range, and validation rules
        self.param_specs = {
            "ttl": {
                "type": int,
                "min": 1,
                "max": 255,
                "description": "Time-to-live value for packets",
            },
            "autottl": {
                "type": int,
                "min": 1,
                "max": 255,
                "description": "Auto TTL value",
            },
            "fake_ttl": {
                "type": int,
                "min": 1,
                "max": 255,
                "description": "TTL for fake packets",
            },
            "split_pos": {
                "type": (int, str),
                "min": 0,
                "max": 65535,
                "description": 'Position to split packet (or "midsld")',
                "allowed_strings": ["midsld"],
            },
            "split_count": {
                "type": int,
                "min": 1,
                "max": 100,
                "description": "Number of splits for multisplit",
            },
            "split_seqovl": {
                "type": int,
                "min": 0,
                "max": 65535,
                "description": "Sequence overlap size",
            },
            "overlap_size": {
                "type": int,
                "min": 0,
                "max": 65535,
                "description": "Overlap size for disorder attacks",
            },
            "repeats": {
                "type": int,
                "min": 1,
                "max": 10,
                "description": "Number of times to repeat attack",
            },
            "fooling": {
                "type": list,
                "description": "List of fooling methods",
                "allowed_values": [
                    "badsum",
                    "md5sig",
                    "badseq",
                    "hopbyhop",
                    "datanoack",
                ],
            },
            "fake_sni": {
                "type": str,
                "description": "Fake SNI hostname",
                "min_length": 1,
                "max_length": 255,
            },
            "fake_seq": {"type": int, "min": 0, "description": "Fake sequence number"},
            "enabled": {"type": bool, "description": "Enable/disable flag"},
        }

        # Required parameters for each attack type
        self.attack_requirements = {
            "split": {
                "required": ["split_pos"],
                "optional": ["ttl", "autottl", "fooling", "repeats"],
                "description": "Split packet at specified position",
            },
            "disorder": {
                "required": ["split_pos"],
                "optional": ["ttl", "autottl", "overlap_size", "fooling", "repeats"],
                "description": "Send packet fragments in disorder",
            },
            "disorder2": {
                "required": ["split_pos"],
                "optional": ["ttl", "autottl", "overlap_size", "fooling", "repeats"],
                "description": "Alternative disorder implementation",
            },
            "multisplit": {
                "required": ["split_count"],
                "optional": ["ttl", "autottl", "fooling", "repeats"],
                "description": "Split packet into multiple fragments",
            },
            "multidisorder": {
                "required": ["split_pos"],
                "optional": [
                    "ttl",
                    "autottl",
                    "overlap_size",
                    "fooling",
                    "repeats",
                    "split_seqovl",
                ],
                "description": "Multiple disorder attacks",
            },
            "fakeddisorder": {
                "required": ["split_pos"],
                "optional": [
                    "ttl",
                    "autottl",
                    "fake_ttl",
                    "overlap_size",
                    "fooling",
                    "fake_sni",
                    "repeats",
                ],
                "description": "Send fake packet then real packets in disorder",
            },
            "fake": {
                "required": [],
                "optional": [
                    "ttl",
                    "autottl",
                    "fake_ttl",
                    "fooling",
                    "fake_sni",
                    "repeats",
                ],
                "description": "Send fake packet before real packet",
            },
            "seqovl": {
                "required": ["split_pos", "overlap_size"],
                "optional": ["ttl", "autottl", "fooling", "repeats"],
                "description": "Sequence overlap attack",
            },
        }

    def validate(self, parsed: ParsedStrategy) -> bool:
        """
        Validate parsed strategy parameters.

        Args:
            parsed: ParsedStrategy object to validate

        Returns:
            True if validation passes

        Raises:
            ValueError: If validation fails with detailed error message
        """
        errors = []
        warnings = []

        # Validate attack type is known
        if parsed.attack_type not in self.attack_requirements:
            warnings.append(
                f"Unknown attack type '{parsed.attack_type}' - validation may be incomplete"
            )

        # Validate mutual exclusivity: ttl and autottl
        if "ttl" in parsed.params and "autottl" in parsed.params:
            errors.append(
                "Parameters 'ttl' and 'autottl' are mutually exclusive. "
                "Use either fixed TTL or auto-calculated TTL, not both."
            )

        # Validate required parameters are present
        attack_spec = self.attack_requirements.get(parsed.attack_type, {})
        required_params = attack_spec.get("required", [])

        for param in required_params:
            if param not in parsed.params:
                errors.append(
                    f"Missing required parameter '{param}' for attack '{parsed.attack_type}'. "
                    f"Description: {self.param_specs.get(param, {}).get('description', 'N/A')}"
                )

        # Validate each parameter
        for param_name, param_value in parsed.params.items():
            param_errors = self._validate_parameter(
                param_name, param_value, parsed.attack_type
            )
            errors.extend(param_errors)

        # Check for unknown parameters (warnings only)
        optional_params = attack_spec.get("optional", [])
        all_known_params = set(required_params + optional_params)

        for param_name in parsed.params.keys():
            if param_name not in all_known_params and param_name in self.param_specs:
                warnings.append(
                    f"Parameter '{param_name}' is not typically used with attack '{parsed.attack_type}'"
                )

        # Log warnings
        for warning in warnings:
            self.logger.warning(warning)

        # Raise error if validation failed
        if errors:
            error_msg = f"Validation failed for strategy '{parsed.raw_string}':\n"
            error_msg += "\n".join(f"  - {err}" for err in errors)
            error_msg += f"\n\nAttack: {parsed.attack_type}"
            if attack_spec:
                error_msg += f"\nDescription: {attack_spec.get('description', 'N/A')}"
                error_msg += f"\nRequired parameters: {', '.join(required_params) if required_params else 'none'}"
                error_msg += f"\nOptional parameters: {', '.join(optional_params) if optional_params else 'none'}"
            raise ValueError(error_msg)

        return True

    def _validate_parameter(
        self, param_name: str, param_value: Any, attack_type: str
    ) -> List[str]:
        """
        Validate a single parameter.

        Args:
            param_name: Name of parameter
            param_value: Value of parameter
            attack_type: Type of attack (for context)

        Returns:
            List of error messages (empty if valid)
        """
        errors = []

        # Check if parameter is known
        if param_name not in self.param_specs:
            # Unknown parameter - skip validation but don't error
            return errors

        spec = self.param_specs[param_name]
        expected_type = spec["type"]

        # Validate type
        if isinstance(expected_type, tuple):
            # Multiple allowed types
            if not isinstance(param_value, expected_type):
                type_names = " or ".join(t.__name__ for t in expected_type)
                errors.append(
                    f"Parameter '{param_name}' has wrong type. "
                    f"Expected {type_names}, got {type(param_value).__name__}. "
                    f"Description: {spec.get('description', 'N/A')}"
                )
                return errors
        else:
            # Single expected type
            if not isinstance(param_value, expected_type):
                errors.append(
                    f"Parameter '{param_name}' has wrong type. "
                    f"Expected {expected_type.__name__}, got {type(param_value).__name__}. "
                    f"Description: {spec.get('description', 'N/A')}"
                )
                return errors

        # Validate integer ranges
        if isinstance(param_value, int):
            if "min" in spec and param_value < spec["min"]:
                errors.append(
                    f"Parameter '{param_name}' value {param_value} is below minimum {spec['min']}. "
                    f"Description: {spec.get('description', 'N/A')}"
                )
            if "max" in spec and param_value > spec["max"]:
                errors.append(
                    f"Parameter '{param_name}' value {param_value} is above maximum {spec['max']}. "
                    f"Description: {spec.get('description', 'N/A')}"
                )

        # Validate string values
        if isinstance(param_value, str):
            # Check allowed strings
            if "allowed_strings" in spec and param_value not in spec["allowed_strings"]:
                errors.append(
                    f"Parameter '{param_name}' has invalid string value '{param_value}'. "
                    f"Allowed values: {', '.join(spec['allowed_strings'])}. "
                    f"Description: {spec.get('description', 'N/A')}"
                )

            # Check string length
            if "min_length" in spec and len(param_value) < spec["min_length"]:
                errors.append(
                    f"Parameter '{param_name}' string is too short (min length: {spec['min_length']})"
                )
            if "max_length" in spec and len(param_value) > spec["max_length"]:
                errors.append(
                    f"Parameter '{param_name}' string is too long (max length: {spec['max_length']})"
                )

        # Validate list values
        if isinstance(param_value, list):
            if "allowed_values" in spec:
                for item in param_value:
                    if item not in spec["allowed_values"]:
                        errors.append(
                            f"Parameter '{param_name}' contains invalid value '{item}'. "
                            f"Allowed values: {', '.join(spec['allowed_values'])}. "
                            f"Description: {spec.get('description', 'N/A')}"
                        )

        return errors

    def get_attack_info(self, attack_type: str) -> Optional[Dict[str, Any]]:
        """
        Get information about an attack type.

        Args:
            attack_type: Name of attack

        Returns:
            Dictionary with attack information or None if unknown
        """
        return self.attack_requirements.get(attack_type)

    def get_parameter_info(self, param_name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a parameter.

        Args:
            param_name: Name of parameter

        Returns:
            Dictionary with parameter information or None if unknown
        """
        return self.param_specs.get(param_name)


def parse_strategy(strategy_string: str, validate: bool = True) -> ParsedStrategy:
    parser = StrategyParserV2()
    parsed = parser.parse(strategy_string)
    if validate:
        validator = ParameterValidator()
        validator.validate(parsed)
    return parsed
