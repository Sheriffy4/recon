"""
Strategy validation and verification system.
"""

import asyncio
import json
from typing import Dict, List, Any
from datetime import datetime, timedelta
import logging

from .sharing_models import (
    SharedStrategy,
    ValidationResult,
)


class StrategyValidator:
    """Validates shared strategies for security and effectiveness."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.validation_cache: Dict[str, ValidationResult] = {}
        self.blacklisted_patterns = [
            r"exec\s*\(",
            r"eval\s*\(",
            r"__import__",
            r"subprocess",
            r"os\.system",
            r"shell=True",
        ]

    async def validate_strategy(self, strategy: SharedStrategy) -> ValidationResult:
        """Comprehensive strategy validation."""
        self.logger.info(f"Validating strategy: {strategy.id}")

        # Check cache first
        cache_key = f"{strategy.id}_{strategy.version}"
        if cache_key in self.validation_cache:
            cached = self.validation_cache[cache_key]
            if (datetime.now() - cached.validated_at) < timedelta(hours=24):
                return cached

        result = ValidationResult(
            strategy_id=strategy.id,
            is_valid=True,
            trust_score=0.0,
            validator_id="strategy_validator",
        )

        # Security validation
        security_score = await self._validate_security(strategy, result)

        # Structure validation
        structure_score = await self._validate_structure(strategy, result)

        # Signature validation
        signature_score = await self._validate_signature(strategy, result)

        # Community feedback validation
        feedback_score = await self._validate_community_feedback(strategy, result)

        # Calculate overall trust score
        result.trust_score = (
            security_score * 0.4
            + structure_score * 0.3
            + signature_score * 0.1
            + feedback_score * 0.2
        )

        # Determine validation status
        if result.trust_score >= 0.8:
            result.is_valid = True
        elif result.trust_score >= 0.6:
            result.is_valid = True
            result.warnings.append("Medium trust score - use with caution")
        else:
            result.is_valid = False
            result.issues.append("Low trust score - validation failed")

        # Cache result
        self.validation_cache[cache_key] = result

        self.logger.info(
            f"Strategy {strategy.id} validation complete: {result.trust_score:.2f}"
        )
        return result

    async def _validate_security(
        self, strategy: SharedStrategy, result: ValidationResult
    ) -> float:
        """Validate strategy for security issues."""
        score = 1.0

        try:
            # Check for dangerous patterns in strategy data
            strategy_json = json.dumps(strategy.strategy_data)

            import re

            for pattern in self.blacklisted_patterns:
                if re.search(pattern, strategy_json, re.IGNORECASE):
                    result.issues.append(f"Dangerous pattern detected: {pattern}")
                    score -= 0.3

            # Check for suspicious parameters
            if self._has_suspicious_parameters(strategy.strategy_data):
                result.warnings.append("Strategy contains suspicious parameters")
                score -= 0.1

            # Check strategy complexity
            if self._is_overly_complex(strategy.strategy_data):
                result.warnings.append("Strategy is overly complex")
                score -= 0.1

        except Exception as e:
            result.issues.append(f"Security validation error: {str(e)}")
            score = 0.0

        return max(0.0, score)

    async def _validate_structure(
        self, strategy: SharedStrategy, result: ValidationResult
    ) -> float:
        """Validate strategy structure and format."""
        score = 1.0

        try:
            # Check required fields
            required_fields = ["attacks", "parameters"]
            for field in required_fields:
                if field not in strategy.strategy_data:
                    result.issues.append(f"Missing required field: {field}")
                    score -= 0.3

            # Validate attacks list
            if "attacks" in strategy.strategy_data:
                attacks = strategy.strategy_data["attacks"]
                if not isinstance(attacks, list) or len(attacks) == 0:
                    result.issues.append("Invalid attacks list")
                    score -= 0.5  # More severe penalty for empty attacks

            # Validate parameters
            if "parameters" in strategy.strategy_data:
                params = strategy.strategy_data["parameters"]
                if not isinstance(params, dict):
                    result.issues.append("Invalid parameters format")
                    score -= 0.5  # More severe penalty for wrong parameter format

            # Check for valid attack IDs
            if not self._validate_attack_ids(strategy.strategy_data.get("attacks", [])):
                result.warnings.append("Some attack IDs may be invalid")
                score -= 0.1

        except Exception as e:
            result.issues.append(f"Structure validation error: {str(e)}")
            score = 0.0

        return max(0.0, score)

    async def _validate_signature(
        self, strategy: SharedStrategy, result: ValidationResult
    ) -> float:
        """Validate strategy cryptographic signature."""
        if not strategy.signature:
            result.warnings.append("Strategy is not signed")
            return 0.5

        try:
            # In a real implementation, we would verify against known public keys
            # For now, we'll do a basic signature format check
            if len(strategy.signature) == 64:  # SHA256 hex length
                return 1.0
            else:
                result.warnings.append("Invalid signature format")
                return 0.3

        except Exception as e:
            result.issues.append(f"Signature validation error: {str(e)}")
            return 0.0

    async def _validate_community_feedback(
        self, strategy: SharedStrategy, result: ValidationResult
    ) -> float:
        """Validate based on community feedback."""
        effectiveness = strategy.get_effectiveness_score()

        if strategy.download_count == 0:
            return 0.5  # Neutral for new strategies

        if effectiveness >= 0.8:
            return 1.0
        elif effectiveness >= 0.6:
            return 0.8
        elif effectiveness >= 0.4:
            return 0.6
        else:
            result.warnings.append("Low community effectiveness score")
            return 0.3

    def _has_suspicious_parameters(self, strategy_data: Dict[str, Any]) -> bool:
        """Check for suspicious parameters in strategy."""
        suspicious_keys = [
            "system_command",
            "shell_exec",
            "file_write",
            "network_raw",
            "admin_required",
        ]

        params = strategy_data.get("parameters", {})
        return any(key in params for key in suspicious_keys)

    def _is_overly_complex(self, strategy_data: Dict[str, Any]) -> bool:
        """Check if strategy is overly complex."""
        attacks = strategy_data.get("attacks", [])
        params = strategy_data.get("parameters", {})

        # Too many attacks
        if len(attacks) > 10:
            return True

        # Too many parameters
        if len(params) > 20:
            return True

        # Nested complexity
        def count_nested_depth(obj, depth=0):
            if depth > 5:
                return True
            if isinstance(obj, dict):
                return any(count_nested_depth(v, depth + 1) for v in obj.values())
            elif isinstance(obj, list):
                return any(count_nested_depth(item, depth + 1) for item in obj)
            return False

        return count_nested_depth(strategy_data)

    def _validate_attack_ids(self, attack_ids: List[str]) -> bool:
        """Validate that attack IDs are in expected format."""
        valid_prefixes = [
            "tcp_",
            "http_",
            "tls_",
            "dns_",
            "timing_",
            "obfuscation_",
            "header_",
        ]

        # Allow empty list
        if not attack_ids:
            return False

        for attack_id in attack_ids:
            if not any(attack_id.startswith(prefix) for prefix in valid_prefixes):
                return False

        return True

    async def batch_validate(
        self, strategies: List[SharedStrategy]
    ) -> Dict[str, ValidationResult]:
        """Validate multiple strategies in parallel."""
        tasks = [self.validate_strategy(strategy) for strategy in strategies]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        validated = {}
        for strategy, result in zip(strategies, results):
            if isinstance(result, Exception):
                validated[strategy.id] = ValidationResult(
                    strategy_id=strategy.id,
                    is_valid=False,
                    trust_score=0.0,
                    issues=[f"Validation failed: {str(result)}"],
                    validator_id="strategy_validator",
                )
            else:
                validated[strategy.id] = result

        return validated

    def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        if not self.validation_cache:
            return {"total": 0, "valid": 0, "invalid": 0, "avg_trust_score": 0.0}

        total = len(self.validation_cache)
        valid = sum(1 for r in self.validation_cache.values() if r.is_valid)
        invalid = total - valid
        avg_score = sum(r.trust_score for r in self.validation_cache.values()) / total

        return {
            "total": total,
            "valid": valid,
            "invalid": invalid,
            "avg_trust_score": avg_score,
        }
