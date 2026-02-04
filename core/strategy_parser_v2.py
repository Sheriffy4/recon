#!/usr/bin/env python3

"""Strategy Parser V2 - Enhanced parser with dual syntax support."""

import logging
import re
import shlex
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

ZapretIntLike = Union[int, str]


@dataclass(frozen=True)
class ParsedStrategy:
    attack_type: str
    params: Dict[str, Any]
    raw_string: str
    syntax_type: str


class StrategyParserV2:
    """
    Parser supporting two syntaxes:
      1) function style: attack(param=value, ...)
      2) zapret style: CLI-like string containing --dpi-desync=...
    """

    _IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

    def __init__(self) -> None:
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

        if self._is_zapret_style(strategy_string):
            parsed = self._parse_zapret_style(strategy_string)
        elif self._is_function_style(strategy_string):
            parsed = self._parse_function_style(strategy_string)
        else:
            raise ValueError(f"Unknown syntax: {strategy_string}")

        # Optional consistency default (kept compatible with existing zapret default):
        parsed.params.setdefault("repeats", 1)

        return parsed

    def _is_function_style(self, strategy: str) -> bool:
        try:
            name, _ = self._split_function_call(strategy)
        except ValueError:
            return False
        return bool(self._IDENT_RE.match(name))

    def _is_zapret_style(self, strategy: str) -> bool:
        return "--dpi-desync" in strategy

    def _split_function_call(self, strategy: str) -> Tuple[str, str]:
        """
        Split `name(args...)` into (name, args_string), robust against quotes/brackets
        in args by scanning for matching closing ')'.
        """
        s = strategy.strip()

        open_idx = s.find("(")
        if open_idx <= 0:
            raise ValueError(f"Invalid function syntax: {strategy}")

        name = s[:open_idx].strip()
        if not self._IDENT_RE.match(name):
            raise ValueError(f"Invalid function name: {name}")

        # Find matching closing paren for the first '('
        depth = 0
        in_quote: Optional[str] = None
        escape = False
        close_idx: Optional[int] = None

        for i in range(open_idx, len(s)):
            ch = s[i]

            if escape:
                escape = False
                continue

            if in_quote is not None:
                if ch == "\\":
                    escape = True
                elif ch == in_quote:
                    in_quote = None
                continue

            if ch in ("'", '"'):
                in_quote = ch
                continue

            if ch == "(":
                depth += 1
                continue
            if ch == ")":
                depth -= 1
                if depth == 0:
                    close_idx = i
                    break
                if depth < 0:
                    raise ValueError(f"Unbalanced parentheses in: {strategy}")

        if close_idx is None:
            raise ValueError(f"Unclosed parentheses in: {strategy}")

        trailing = s[close_idx + 1 :].strip()
        if trailing:
            raise ValueError(f"Unexpected trailing characters after ')': {trailing}")

        args_str = s[open_idx + 1 : close_idx].strip()
        return name, args_str

    def _parse_function_style(self, strategy: str) -> ParsedStrategy:
        attack_name, params_str = self._split_function_call(strategy)
        attack_name = attack_name.lower().strip()

        if attack_name not in self.known_attacks:
            self.logger.warning("Unknown attack type '%s' in '%s'", attack_name, strategy)

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

        params: Dict[str, Any] = {}
        parts = self._smart_split(params_str, ",")

        for part in parts:
            part = part.strip()
            if not part:
                continue

            if "=" not in part:
                self.logger.warning("Skipping invalid parameter fragment '%s' (no '=')", part)
                continue

            key, value = part.split("=", 1)
            key = key.strip()
            value = value.strip()

            if not key:
                self.logger.warning("Skipping parameter with empty name in fragment '%s'", part)
                continue

            # Normalize to match validator naming (snake_case)
            key = key.replace("-", "_")

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

        lowered = value_str.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if lowered in ("none", "null"):
            return None

        try:
            # Prefer int when it looks like int; else float
            if "." not in value_str and "e" not in lowered:
                return int(value_str)
            return float(value_str)
        except ValueError:
            return value_str

    def _parse_list(self, list_str: str) -> List[Any]:
        content = list_str[1:-1].strip()
        if not content:
            return []
        items = self._smart_split(content, ",")
        return [self._parse_value(item.strip()) for item in items]

    def _smart_split(self, text: str, delimiter: str) -> List[str]:
        """
        Split by delimiter, ignoring delimiters inside quotes and nested brackets/parens/braces.
        Raises ValueError on unclosed quotes or unbalanced brackets for robustness.
        """
        if len(delimiter) != 1:
            raise ValueError("Delimiter must be a single character")

        parts: List[str] = []
        current: List[str] = []
        depth = 0
        in_quote: Optional[str] = None
        escape = False

        for ch in text:
            if escape:
                current.append(ch)
                escape = False
                continue

            if in_quote is not None:
                if ch == "\\":
                    current.append(ch)
                    escape = True
                    continue
                if ch == in_quote:
                    in_quote = None
                current.append(ch)
                continue

            if ch in ('"', "'"):
                in_quote = ch
                current.append(ch)
                continue

            if ch in ("[", "(", "{"):
                depth += 1
                current.append(ch)
                continue

            if ch in ("]", ")", "}"):
                depth -= 1
                if depth < 0:
                    raise ValueError(f"Unbalanced brackets in '{text}'")
                current.append(ch)
                continue

            if ch == delimiter and depth == 0:
                parts.append("".join(current))
                current = []
                continue

            current.append(ch)

        if in_quote is not None:
            raise ValueError(f"Unclosed quote in '{text}'")
        if depth != 0:
            raise ValueError(f"Unbalanced brackets in '{text}'")

        parts.append("".join(current))
        return parts

    def _parse_cli_options(self, strategy: str) -> Dict[str, Optional[str]]:
        """
        Parse CLI-like string into {--opt: value_or_None}.
        Supports both --opt=value and --opt value forms and respects quotes via shlex.
        """
        try:
            tokens = shlex.split(strategy)
        except ValueError as e:
            raise ValueError(f"Invalid CLI string (quoting error): {e}") from e

        opts: Dict[str, Optional[str]] = {}
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok.startswith("--"):
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    opts[k] = v
                else:
                    # if next token is a value (not another option), bind it
                    if i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
                        opts[tok] = tokens[i + 1]
                        i += 1
                    else:
                        opts[tok] = None
            i += 1

        return opts

    def _normalize_attack_type(self, parts: List[str], raw_strategy: str) -> str:
        """
        Normalize zapret --dpi-desync list to internal attack_type.
        If multiple parts are present, choose a reasonable main type and log warning.
        """
        parts = [p for p in (x.strip().lower() for x in parts) if p]
        if not parts:
            raise ValueError(f"Empty --dpi-desync value in: {raw_strategy}")

        # Known composite
        if "fake" in parts and ("disorder" in parts or "disorder2" in parts):
            return "fakeddisorder"

        # Prefer explicit known types in order
        for candidate in parts:
            if candidate in self.known_attacks:
                if len(parts) > 1:
                    self.logger.warning(
                        "Multiple --dpi-desync parts %s detected; choosing '%s' (strategy: %s)",
                        parts,
                        candidate,
                        raw_strategy,
                    )
                return candidate

        # Fallback: first token
        if len(parts) > 1:
            self.logger.warning(
                "Unknown multi-part --dpi-desync %s; falling back to '%s' (strategy: %s)",
                parts,
                parts[0],
                raw_strategy,
            )
        return parts[0]

    def _parse_zapret_style(self, strategy: str) -> ParsedStrategy:
        opts = self._parse_cli_options(strategy)

        desync_value = opts.get("--dpi-desync")
        if not desync_value:
            raise ValueError(f"No --dpi-desync found: {strategy}")

        attack_parts = [p.strip() for p in desync_value.split(",")]
        attack_type = self._normalize_attack_type(attack_parts, strategy)

        if attack_type not in self.known_attacks:
            self.logger.warning("Unknown attack type '%s' in '%s'", attack_type, strategy)

        params: Dict[str, Any] = {}

        int_params = [
            "ttl",
            "autottl",
            "split-pos",
            "split-count",
            "split-seqovl",
            "repeats",
        ]
        for param_name in int_params:
            value = self._extract_zapret_int(opts, param_name)
            if value is not None:
                key = param_name.replace("-", "_")
                params[key] = value

        for param_name in ["fake-sni"]:
            value = self._extract_zapret_string(opts, param_name)
            if value is not None:
                key = param_name.replace("-", "_")
                params[key] = value

        fooling = self._extract_zapret_list(opts, "fooling")
        if fooling:
            params["fooling"] = fooling

        # Alias for validator/consumer: overlap_size may be required for seqovl,
        # while zapret uses split-seqovl.
        if "split_seqovl" in params and "overlap_size" not in params:
            params["overlap_size"] = params["split_seqovl"]

        # Validate mutual exclusivity of ttl and autottl early (kept also in validator)
        if "ttl" in params and "autottl" in params:
            raise ValueError(
                "Cannot specify both --dpi-desync-ttl and --dpi-desync-autottl in the same strategy. "
                f"These parameters are mutually exclusive. Strategy: {strategy}"
            )

        return ParsedStrategy(
            attack_type=attack_type,
            params=params,
            raw_string=strategy,
            syntax_type="zapret",
        )

    def _extract_zapret_int(
        self, opts: Dict[str, Optional[str]], param_name: str
    ) -> Optional[ZapretIntLike]:
        key = f"--dpi-desync-{param_name}"
        raw = opts.get(key)
        if raw is None:
            return None

        value_str = raw.strip()
        if not value_str:
            return None

        lowered = value_str.lower()
        # split-pos may be special token; do not drop it
        if lowered in ("midsld", "sni", "cipher", "random"):
            return lowered

        # Some options may contain comma-separated values; take the first
        if "," in value_str:
            value_str = value_str.split(",", 1)[0].strip()

        try:
            return int(value_str)
        except ValueError:
            return None

    def _extract_zapret_string(
        self, opts: Dict[str, Optional[str]], param_name: str
    ) -> Optional[str]:
        key = f"--dpi-desync-{param_name}"
        raw = opts.get(key)
        if raw is None:
            return None
        raw = raw.strip()
        return raw if raw else None

    def _extract_zapret_list(self, opts: Dict[str, Optional[str]], param_name: str) -> List[str]:
        key = f"--dpi-desync-{param_name}"
        raw = opts.get(key)
        if raw is None:
            return []
        raw = raw.strip()
        if not raw:
            return []
        return [item.strip() for item in raw.split(",") if item.strip()]


class ParameterValidator:
    """Validates attack parameters against specifications."""

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

        self.param_specs: Dict[str, Dict[str, Any]] = {
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
                "description": 'Position to split packet (int) or special token ("midsld","sni","cipher","random")',
                "allowed_strings": ["midsld", "sni", "cipher", "random"],
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
                "description": "Sequence overlap size (zapret naming)",
            },
            "overlap_size": {
                "type": int,
                "min": 0,
                "max": 65535,
                "description": "Overlap size for disorder/seqovl attacks",
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

        self.attack_requirements: Dict[str, Dict[str, Any]] = {
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
        errors: List[str] = []
        warnings: List[str] = []

        attack_spec = self.attack_requirements.get(parsed.attack_type)
        if not attack_spec:
            warnings.append(
                f"Unknown attack type '{parsed.attack_type}' - validation may be incomplete"
            )
            attack_spec = {}

        # Mutual exclusivity: ttl and autottl
        if "ttl" in parsed.params and "autottl" in parsed.params:
            errors.append(
                "Parameters 'ttl' and 'autottl' are mutually exclusive. "
                "Use either fixed TTL or auto-calculated TTL, not both."
            )

        required_params = attack_spec.get("required", [])
        optional_params = attack_spec.get("optional", [])
        all_expected_params = set(required_params + optional_params)

        for param in required_params:
            if param not in parsed.params:
                errors.append(
                    f"Missing required parameter '{param}' for attack '{parsed.attack_type}'. "
                    f"Description: {self.param_specs.get(param, {}).get('description', 'N/A')}"
                )

        # Validate each parameter
        for param_name, param_value in parsed.params.items():
            errors.extend(self._validate_parameter(param_name, param_value, parsed.attack_type))

            # Unknown param: warn explicitly (helps observability)
            if param_name not in self.param_specs:
                warnings.append(
                    f"Unknown parameter '{param_name}' (attack '{parsed.attack_type}'): "
                    "no validation rule exists for it"
                )
                continue

            # Known but not typical for this attack: warn
            if all_expected_params and (param_name not in all_expected_params):
                warnings.append(
                    f"Parameter '{param_name}' is not typically used with attack '{parsed.attack_type}'"
                )

        for w in warnings:
            self.logger.warning(w)

        if errors:
            msg = f"Validation failed for strategy '{parsed.raw_string}':\n"
            msg += "\n".join(f"  - {err}" for err in errors)
            msg += f"\n\nAttack: {parsed.attack_type}"

            if attack_spec:
                msg += f"\nDescription: {attack_spec.get('description', 'N/A')}"
                msg += f"\nRequired parameters: {', '.join(required_params) if required_params else 'none'}"
                msg += f"\nOptional parameters: {', '.join(optional_params) if optional_params else 'none'}"
            raise ValueError(msg)

        return True

    def _type_matches(self, value: Any, expected: Any) -> bool:
        """
        isinstance() wrapper that prevents bool being accepted as int.
        """
        if expected is int:
            return isinstance(value, int) and not isinstance(value, bool)
        if expected is bool:
            return type(value) is bool
        return isinstance(value, expected)

    def _validate_parameter(self, param_name: str, param_value: Any, attack_type: str) -> List[str]:
        errors: List[str] = []

        spec = self.param_specs.get(param_name)
        if not spec:
            return errors  # Unknown param: warn handled in validate()

        expected_type = spec["type"]

        # Type validation
        if isinstance(expected_type, tuple):
            if not any(self._type_matches(param_value, t) for t in expected_type):
                type_names = " or ".join(t.__name__ for t in expected_type)
                errors.append(
                    f"Parameter '{param_name}' has wrong type for attack '{attack_type}'. "
                    f"Expected {type_names}, got {type(param_value).__name__}. "
                    f"Description: {spec.get('description', 'N/A')}"
                )
                return errors
        else:
            if not self._type_matches(param_value, expected_type):
                errors.append(
                    f"Parameter '{param_name}' has wrong type for attack '{attack_type}'. "
                    f"Expected {expected_type.__name__}, got {type(param_value).__name__}. "
                    f"Description: {spec.get('description', 'N/A')}"
                )
                return errors

        # Integer range validation (exclude bool)
        if isinstance(param_value, int) and not isinstance(param_value, bool):
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

        # String constraints
        if isinstance(param_value, str):
            if "allowed_strings" in spec and param_value not in spec["allowed_strings"]:
                errors.append(
                    f"Parameter '{param_name}' has invalid string value '{param_value}'. "
                    f"Allowed values: {', '.join(spec['allowed_strings'])}. "
                    f"Description: {spec.get('description', 'N/A')}"
                )

            if "min_length" in spec and len(param_value) < spec["min_length"]:
                errors.append(
                    f"Parameter '{param_name}' string is too short (min length: {spec['min_length']})"
                )
            if "max_length" in spec and len(param_value) > spec["max_length"]:
                errors.append(
                    f"Parameter '{param_name}' string is too long (max length: {spec['max_length']})"
                )

        # List validation
        if isinstance(param_value, list):
            if "allowed_values" in spec:
                allowed = set(spec["allowed_values"])
                for item in param_value:
                    if not isinstance(item, str):
                        errors.append(
                            f"Parameter '{param_name}' contains non-string item {item!r} "
                            f"(type {type(item).__name__}); allowed values must be strings."
                        )
                        continue
                    if item not in allowed:
                        errors.append(
                            f"Parameter '{param_name}' contains invalid value '{item}'. "
                            f"Allowed values: {', '.join(spec['allowed_values'])}. "
                            f"Description: {spec.get('description', 'N/A')}"
                        )

        return errors

    def get_attack_info(self, attack_type: str) -> Optional[Dict[str, Any]]:
        return self.attack_requirements.get(attack_type)

    def get_parameter_info(self, param_name: str) -> Optional[Dict[str, Any]]:
        return self.param_specs.get(param_name)


def parse_strategy(strategy_string: str, validate: bool = True) -> ParsedStrategy:
    parser = StrategyParserV2()
    parsed = parser.parse(strategy_string)
    if validate:
        ParameterValidator().validate(parsed)
    return parsed
