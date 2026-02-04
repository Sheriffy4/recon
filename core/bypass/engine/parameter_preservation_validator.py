"""
Parameter Preservation Validator

This module ensures complete parameter preservation when saving strategies to domain_rules.json.
It validates that ALL required parameters for ALL attacks in a combination are saved.

Requirements: 4.1, 4.2, 4.3, 4.5
"""

import logging
from typing import Dict, Any, List, Set

logger = logging.getLogger(__name__)


class ParameterPreservationValidator:
    """
    Validates that strategies contain all required parameters before saving.

    This validator ensures:
    1. All required parameters for each attack are present
    2. For combo attacks, parameters from ALL attacks are collected
    3. Missing parameters are detected and warned
    4. Parameter inference from attack registry for missing params
    """

    def __init__(self, attack_registry=None):
        """
        Initialize the parameter preservation validator.

        Args:
            attack_registry: AttackRegistry instance for parameter lookup
        """
        self.attack_registry = attack_registry
        if not self.attack_registry:
            # Lazy load attack registry if not provided
            from ..attacks.attack_registry import AttackRegistry

            self.attack_registry = AttackRegistry()

    def validate_strategy_completeness(
        self, strategy: Dict[str, Any], domain: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Validate that strategy contains all required parameters.

        Args:
            strategy: Strategy dictionary to validate
            domain: Domain name for logging context

        Returns:
            Dict with validation results:
            {
                "valid": bool,
                "missing_params": List[str],
                "warnings": List[str],
                "inferred_params": Dict[str, Any],
                "complete_strategy": Dict[str, Any]
            }
        """
        result = {
            "valid": True,
            "missing_params": [],
            "warnings": [],
            "inferred_params": {},
            "complete_strategy": strategy.copy(),
        }

        # Get attack list from strategy
        attacks = self._extract_attacks_from_strategy(strategy)

        if not attacks:
            result["warnings"].append(f"No attacks found in strategy for domain '{domain}'")
            return result

        logger.info(
            f"🔍 Validating parameter completeness for domain '{domain}' with attacks: {attacks}"
        )

        # Collect all required parameters from all attacks
        all_required_params = self._collect_required_params(attacks)

        # Get current parameters from strategy
        current_params = strategy.get("params", {})

        # Check for missing parameters
        missing_params = []
        for param in all_required_params:
            if param not in current_params or current_params[param] is None:
                missing_params.append(param)

        if missing_params:
            result["valid"] = False
            result["missing_params"] = missing_params

            logger.warning(f"⚠️ Missing required parameters for domain '{domain}': {missing_params}")
            logger.warning(f"   Attacks: {attacks}")
            logger.warning(f"   Current params: {list(current_params.keys())}")

            # Try to infer missing parameters
            inferred = self._infer_missing_parameters(attacks, missing_params, current_params)

            if inferred:
                result["inferred_params"] = inferred
                result["warnings"].append(
                    f"Inferred {len(inferred)} missing parameters: {list(inferred.keys())}"
                )

                # Add inferred parameters to complete strategy
                complete_params = current_params.copy()
                complete_params.update(inferred)
                result["complete_strategy"]["params"] = complete_params

                logger.info(f"✅ Inferred missing parameters: {inferred}")
            else:
                result["warnings"].append(f"Could not infer missing parameters: {missing_params}")
        else:
            logger.info(f"✅ All required parameters present for domain '{domain}'")

        return result

    def _extract_attacks_from_strategy(self, strategy: Dict[str, Any]) -> List[str]:
        """
        Extract list of attacks from strategy.

        Args:
            strategy: Strategy dictionary

        Returns:
            List of attack names
        """
        # Priority 1: Use 'attacks' field if present (combo attacks)
        if "attacks" in strategy and strategy["attacks"]:
            attacks = strategy["attacks"]
            if isinstance(attacks, list):
                # Filter out None and empty strings
                return [a for a in attacks if a]
            elif isinstance(attacks, str):
                return [attacks]

        # Priority 2: Use 'type' field
        if "type" in strategy and strategy["type"]:
            return [strategy["type"]]

        return []

    def _collect_required_params(self, attacks: List[str]) -> Set[str]:
        """
        Collect all required parameters from all attacks.

        Args:
            attacks: List of attack names

        Returns:
            Set of required parameter names
        """
        all_required = set()

        for attack in attacks:
            metadata = self.attack_registry.get_attack_metadata(attack)

            if not metadata:
                logger.warning(f"⚠️ No metadata found for attack '{attack}'")
                continue

            # Add required parameters
            if hasattr(metadata, "required_params") and metadata.required_params:
                all_required.update(metadata.required_params)
                logger.debug(f"Attack '{attack}' requires: {metadata.required_params}")

        return all_required

    def _infer_missing_parameters(
        self, attacks: List[str], missing_params: List[str], current_params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Infer missing parameters from attack registry defaults.

        Args:
            attacks: List of attack names
            missing_params: List of missing parameter names
            current_params: Current parameters in strategy

        Returns:
            Dict of inferred parameters
        """
        inferred = {}

        for attack in attacks:
            metadata = self.attack_registry.get_attack_metadata(attack)

            if not metadata:
                continue

            # Check optional parameters for defaults
            if hasattr(metadata, "optional_params") and metadata.optional_params:
                for param in missing_params:
                    if param in metadata.optional_params and param not in inferred:
                        default_value = metadata.optional_params[param]
                        inferred[param] = default_value
                        logger.debug(f"Inferred '{param}' = {default_value} from attack '{attack}'")

        return inferred

    def add_parameter_completeness_check(
        self, strategy: Dict[str, Any], domain: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Add parameter completeness check and return enhanced strategy.

        This method validates the strategy and returns a complete version
        with all required parameters, either from the original strategy
        or inferred from attack registry.

        Args:
            strategy: Strategy dictionary to validate
            domain: Domain name for logging context

        Returns:
            Enhanced strategy dictionary with complete parameters
        """
        validation_result = self.validate_strategy_completeness(strategy, domain)

        if not validation_result["valid"]:
            logger.warning(f"⚠️ Strategy for domain '{domain}' is missing required parameters")

            if validation_result["inferred_params"]:
                logger.info(
                    f"✅ Added {len(validation_result['inferred_params'])} inferred parameters"
                )

        # Log warnings
        for warning in validation_result["warnings"]:
            logger.warning(f"⚠️ {warning}")

        return validation_result["complete_strategy"]

    def validate_before_save(self, domain: str, strategy: Dict[str, Any]) -> bool:
        """
        Validate strategy before saving to domain_rules.json.

        This method performs validation and logs warnings if parameters are missing.
        It returns True if validation passes or parameters can be inferred.

        Args:
            domain: Domain name
            strategy: Strategy dictionary to validate

        Returns:
            True if strategy is valid or can be completed, False otherwise
        """
        validation_result = self.validate_strategy_completeness(strategy, domain)

        if not validation_result["valid"]:
            if validation_result["inferred_params"]:
                logger.warning(
                    f"⚠️ Strategy for '{domain}' has missing parameters, but they can be inferred"
                )
                logger.warning(f"   Missing: {validation_result['missing_params']}")
                logger.warning(f"   Inferred: {list(validation_result['inferred_params'].keys())}")
                return True
            else:
                logger.error(
                    f"❌ Strategy for '{domain}' is missing required parameters and cannot be inferred"
                )
                logger.error(f"   Missing: {validation_result['missing_params']}")
                logger.error(f"   Attacks: {self._extract_attacks_from_strategy(strategy)}")
                return False

        return True


def validate_strategy_parameters(
    strategy: Dict[str, Any], domain: str = "unknown", attack_registry=None
) -> Dict[str, Any]:
    """
    Convenience function to validate strategy parameters.

    Args:
        strategy: Strategy dictionary to validate
        domain: Domain name for logging context
        attack_registry: Optional AttackRegistry instance

    Returns:
        Validation result dictionary
    """
    validator = ParameterPreservationValidator(attack_registry)
    return validator.validate_strategy_completeness(strategy, domain)


def ensure_complete_strategy(
    strategy: Dict[str, Any], domain: str = "unknown", attack_registry=None
) -> Dict[str, Any]:
    """
    Ensure strategy has all required parameters.

    This function validates the strategy and returns a complete version
    with all required parameters, either from the original strategy
    or inferred from attack registry.

    Args:
        strategy: Strategy dictionary to validate
        domain: Domain name for logging context
        attack_registry: Optional AttackRegistry instance

    Returns:
        Complete strategy dictionary
    """
    validator = ParameterPreservationValidator(attack_registry)
    return validator.add_parameter_completeness_check(strategy, domain)
