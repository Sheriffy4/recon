"""
Attack Specification Loader

Loads and parses YAML attack specifications for validation.
"""

import yaml
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AttackParameter:
    """Attack parameter specification."""

    name: str
    type: str
    default: Any
    required: bool
    description: str
    min: Optional[Any] = None
    max: Optional[Any] = None
    allowed_values: Optional[List[Any]] = None


@dataclass
class ExpectedPacket:
    """Expected packet specification."""

    packet_index: int
    name: str
    properties: Dict[str, Any]


@dataclass
class ValidationRule:
    """Validation rule specification."""

    rule: str
    description: str
    severity: str  # critical, warning, info


@dataclass
class TestVariation:
    """Test variation specification."""

    name: str
    description: str
    params: Dict[str, Any]


@dataclass
class ErrorCase:
    """Error case specification."""

    name: str
    description: str
    params: Dict[str, Any]
    expected_error: str


@dataclass
class AttackSpec:
    """Complete attack specification."""

    name: str
    aliases: List[str]
    description: str
    category: str
    parameters: List[AttackParameter]
    expected_packets: Dict[str, Any]
    validation_rules: Dict[str, List[ValidationRule]]
    test_variations: Dict[str, TestVariation]
    error_cases: Dict[str, ErrorCase]
    notes: List[str]


class AttackSpecLoader:
    """Loads attack specifications from YAML files."""

    def __init__(self, specs_dir: str = None):
        """
        Initialize the spec loader.

        Args:
            specs_dir: Directory containing attack YAML specs
        """
        if specs_dir is None:
            # Try to find specs directory relative to this file or CWD

            # Try relative to current file
            current_dir = Path(__file__).parent.parent
            specs_path = current_dir / "specs" / "attacks"
            if not specs_path.exists():
                # Try relative to CWD
                specs_path = Path("specs/attacks")
                if not specs_path.exists():
                    specs_path = Path("recon/specs/attacks")
            specs_dir = str(specs_path)

        self.specs_dir = Path(specs_dir)
        self._specs_cache: Dict[str, AttackSpec] = {}

    def load_spec(self, attack_name: str) -> Optional[AttackSpec]:
        """
        Load specification for an attack.

        Args:
            attack_name: Name of the attack

        Returns:
            AttackSpec if found, None otherwise
        """
        # Check cache first
        if attack_name in self._specs_cache:
            return self._specs_cache[attack_name]

        # Try to load from file
        spec_file = self.specs_dir / f"{attack_name}.yaml"

        if not spec_file.exists():
            # Try aliases
            for spec_path in self.specs_dir.glob("*.yaml"):
                spec = self._load_yaml_file(spec_path)
                if spec and attack_name in spec.get("aliases", []):
                    return self._parse_spec(spec)
            return None

        spec_data = self._load_yaml_file(spec_file)
        if not spec_data:
            return None

        spec = self._parse_spec(spec_data)
        self._specs_cache[attack_name] = spec
        return spec

    def load_all_specs(self) -> Dict[str, AttackSpec]:
        """
        Load all attack specifications.

        Returns:
            Dictionary mapping attack names to specs
        """
        specs = {}

        for spec_file in self.specs_dir.glob("*.yaml"):
            spec_data = self._load_yaml_file(spec_file)
            if spec_data:
                spec = self._parse_spec(spec_data)
                specs[spec.name] = spec

                # Also map aliases
                for alias in spec.aliases:
                    specs[alias] = spec

        return specs

    def _load_yaml_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load YAML file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            return None

    def _parse_spec(self, data: Dict[str, Any]) -> AttackSpec:
        """Parse YAML data into AttackSpec."""
        # Parse parameters
        parameters = []
        for param_data in data.get("parameters", []):
            param = AttackParameter(
                name=param_data["name"],
                type=param_data["type"],
                default=param_data.get("default"),
                required=param_data.get("required", False),
                description=param_data.get("description", ""),
                min=param_data.get("min"),
                max=param_data.get("max"),
                allowed_values=param_data.get("allowed_values"),
            )
            parameters.append(param)

        # Parse validation rules
        validation_rules = {}
        for category, rules_data in data.get("validation_rules", {}).items():
            rules = []
            for rule_data in rules_data:
                rule = ValidationRule(
                    rule=rule_data["rule"],
                    description=rule_data["description"],
                    severity=rule_data.get("severity", "warning"),
                )
                rules.append(rule)
            validation_rules[category] = rules

        # Parse test variations
        test_variations = {}
        for var_name, var_data in data.get("test_variations", {}).items():
            variation = TestVariation(
                name=var_name,
                description=var_data.get("description", ""),
                params=var_data.get("params", {}),
            )
            test_variations[var_name] = variation

        # Parse error cases
        error_cases = {}
        for case_name, case_data in data.get("error_cases", {}).items():
            error_case = ErrorCase(
                name=case_name,
                description=case_data.get("description", ""),
                params=case_data.get("params", {}),
                expected_error=case_data.get("expected_error", ""),
            )
            error_cases[case_name] = error_case

        return AttackSpec(
            name=data["name"],
            aliases=data.get("aliases", []),
            description=data.get("description", ""),
            category=data.get("category", ""),
            parameters=parameters,
            expected_packets=data.get("expected_packets", {}),
            validation_rules=validation_rules,
            test_variations=test_variations,
            error_cases=error_cases,
            notes=data.get("notes", []),
        )

    def get_parameter_spec(self, attack_name: str, param_name: str) -> Optional[AttackParameter]:
        """
        Get specification for a specific parameter.

        Args:
            attack_name: Name of the attack
            param_name: Name of the parameter

        Returns:
            AttackParameter if found, None otherwise
        """
        spec = self.load_spec(attack_name)
        if not spec:
            return None

        for param in spec.parameters:
            if param.name == param_name:
                return param

        return None

    def get_validation_rules(
        self, attack_name: str, category: Optional[str] = None
    ) -> List[ValidationRule]:
        """
        Get validation rules for an attack.

        Args:
            attack_name: Name of the attack
            category: Optional category filter (e.g., 'sequence_numbers', 'checksum')

        Returns:
            List of validation rules
        """
        spec = self.load_spec(attack_name)
        if not spec:
            return []

        if category:
            return spec.validation_rules.get(category, [])

        # Return all rules
        all_rules = []
        for rules in spec.validation_rules.values():
            all_rules.extend(rules)
        return all_rules

    def get_test_variations(self, attack_name: str) -> Dict[str, TestVariation]:
        """
        Get test variations for an attack.

        Args:
            attack_name: Name of the attack

        Returns:
            Dictionary of test variations
        """
        spec = self.load_spec(attack_name)
        if not spec:
            return {}

        return spec.test_variations

    def get_error_cases(self, attack_name: str) -> Dict[str, ErrorCase]:
        """
        Get error cases for an attack.

        Args:
            attack_name: Name of the attack

        Returns:
            Dictionary of error cases
        """
        spec = self.load_spec(attack_name)
        if not spec:
            return {}

        return spec.error_cases

    def validate_parameters(self, attack_name: str, params: Dict[str, Any]) -> List[str]:
        """
        Validate parameters against spec.

        Args:
            attack_name: Name of the attack
            params: Parameters to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        spec = self.load_spec(attack_name)
        if not spec:
            return [f"No specification found for attack: {attack_name}"]

        errors = []

        # Check required parameters
        for param_spec in spec.parameters:
            if param_spec.required and param_spec.name not in params:
                errors.append(f"Required parameter missing: {param_spec.name}")

        # Validate parameter values
        for param_name, param_value in params.items():
            param_spec = self.get_parameter_spec(attack_name, param_name)
            if not param_spec:
                errors.append(f"Unknown parameter: {param_name}")
                continue

            # Type validation
            expected_type = param_spec.type
            if not self._validate_type(param_value, expected_type):
                errors.append(
                    f"Parameter {param_name} has wrong type: expected {expected_type}, got {type(param_value).__name__}"
                )

            # Range validation
            if param_spec.min is not None and param_value < param_spec.min:
                errors.append(
                    f"Parameter {param_name} below minimum: {param_value} < {param_spec.min}"
                )

            if param_spec.max is not None and param_value > param_spec.max:
                errors.append(
                    f"Parameter {param_name} above maximum: {param_value} > {param_spec.max}"
                )

            # Allowed values validation
            if param_spec.allowed_values is not None:
                if isinstance(param_value, list):
                    for val in param_value:
                        if val not in param_spec.allowed_values:
                            errors.append(
                                f"Parameter {param_name} has invalid value: {val} not in {param_spec.allowed_values}"
                            )
                elif param_value not in param_spec.allowed_values:
                    errors.append(
                        f"Parameter {param_name} has invalid value: {param_value} not in {param_spec.allowed_values}"
                    )

        return errors

    def _validate_type(self, value: Any, expected_type: str) -> bool:
        """Validate value type."""
        if expected_type == "int":
            return isinstance(value, int)
        elif expected_type == "float":
            return isinstance(value, (int, float))
        elif expected_type == "str":
            return isinstance(value, str)
        elif expected_type == "bool":
            return isinstance(value, bool)
        elif expected_type.startswith("list["):
            if not isinstance(value, list):
                return False
            # Could add element type validation here
            return True
        else:
            return True  # Unknown type, assume valid


# Global instance
_spec_loader = None


def get_spec_loader() -> AttackSpecLoader:
    """Get global spec loader instance."""
    global _spec_loader
    if _spec_loader is None:
        _spec_loader = AttackSpecLoader()
    return _spec_loader
