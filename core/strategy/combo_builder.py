"""
ComboAttackBuilder - Unified recipe creation for combo attacks.

This module implements the logic for building unified attack recipes from
lists of attacks, validating compatibility, and merging parameters.

Requirements: 2.1, 2.5, 2.6
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ============================================================================
# DATA CLASSES
# ============================================================================


@dataclass
class AttackStep:
    """Represents a single step in an attack recipe."""

    attack_type: str  # e.g. "fake", "split", "multisplit", "disorder"
    order: int  # Execution order (lower = earlier)
    params: Dict[str, Any]  # Parameters specific to this attack


@dataclass
class AttackRecipe:
    """Represents a complete attack recipe with ordered steps."""

    attacks: List[str]  # Original attack list (as requested)
    steps: List[AttackStep]  # Ordered steps to execute
    params: Dict[str, Any]  # Merged parameters for all attacks

    def __post_init__(self) -> None:
        """Sort steps by order after initialization (stable)."""
        # Стабильная сортировка: атаки с одинаковым order сохраняют относительный порядок
        self.steps.sort(key=lambda step: step.order)


@dataclass
class ValidationResult:
    """Result of compatibility validation."""

    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# ============================================================================
# CONSTANTS / METADATA
# ============================================================================

# Attack execution order priority (lower = earlier)
# fake → split/multisplit → disorder; комбинированные атаки приравнены к fake-фазе
ATTACK_ORDER: Dict[str, int] = {
    "fake": 1,
    "fakeddisorder": 1,  # combined fake+disorder
    "disorder_short_ttl_decoy": 1,  # combined decoy
    "split": 2,
    "multisplit": 2,
    "disorder": 3,
    # CRITICAL FIX: Add missing attack types
    "seqovl": 2,  # sequence overlap
    "ttl": 1,  # TTL manipulation
    "ttl_manipulation": 1,  # TTL manipulation (alias)
    "passthrough": 999,  # passthrough (no modification)
    "multidisorder": 3,  # multiple disorder
    "badseq": 999,  # bad sequence fooling
    "badsum": 999,  # bad checksum fooling
    "md5sig": 999,  # MD5 signature fooling
    "fragmentation": 2,  # fragmentation attack
    "fooling": 999,  # general fooling
}

# Параметры, специфичные для каждого типа атаки
ATTACK_PARAM_MAPPING: Dict[str, List[str]] = {
    "fake": ["ttl", "fooling", "fake_sni", "fake_data", "fake_mode"],
    "split": ["split_pos", "ttl", "fake_ttl"],
    "multisplit": [
        "split_pos",
        "split_count",
        "positions",
        "fake_mode",
        "ttl",
        "fake_ttl",
        "fooling",
    ],
    "disorder": ["disorder_method"],
    "fakeddisorder": ["ttl", "fooling", "fake_sni", "disorder_method", "fake_mode"],
    "disorder_short_ttl_decoy": ["ttl", "fooling", "disorder_method", "fake_mode"],
    # CRITICAL FIX: Add missing attack parameter mappings
    "seqovl": ["split_pos", "overlap_size", "fake_ttl", "fooling", "custom_sni"],
    "ttl": ["ttl"],
    "ttl_manipulation": ["ttl"],
    "passthrough": [],  # no parameters
    "multidisorder": ["disorder_count", "disorder_method"],
    "badseq": [],  # no parameters
    "badsum": [],  # no parameters
    "md5sig": [],  # no parameters
    "fragmentation": ["split_pos", "fragment_size"],
    "fooling": ["fooling_method"],
}

# Общие параметры, которые всегда передаются шагам (если присутствуют)
COMMON_PARAMS = {"forced", "no_fallbacks", "resolved_custom_sni"}

# Набор известных атак (для проверок)
KNOWN_ATTACKS = set(ATTACK_ORDER.keys())

# Набор несовместимых комбинаций (каждый элемент — сет типов атак)
INCOMPATIBLE_COMBOS = [
    # Removed split+multisplit incompatibility to align with SmartAttackCombinator
    # {"split", "multisplit"},  # Allow but warn about functionality duplication
]

# Набор комбинаций, которые вызывают предупреждения (но не блокируются)
WARNING_COMBOS = [
    {"split", "multisplit"},  # Дублирование функциональности фрагментации
]


# ============================================================================
# BUILDER
# ============================================================================


class ComboAttackBuilder:
    """
    Builds unified attack recipes from lists of attacks.

    Responsibilities:
    1. Create AttackRecipe from attacks list
    2. Validate attack compatibility
    3. Merge parameters from multiple attacks
    4. Ensure correct execution order: fake → split/multisplit → disorder

    Requirements:
    - 2.1: Create unified recipe from attacks list
    - 2.5: Support any valid combination
    - 2.6: Detect incompatible combinations
    """

    def __init__(self) -> None:
        self.logger = logger

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def build_recipe(self, attacks: List[str], params: Dict[str, Any]) -> AttackRecipe:
        """
        Build unified recipe from attacks list.

        Order of phases:
        1. fake / fakeddisorder / disorder_short_ttl_decoy (TTL-based decoys)
        2. split / multisplit (payload fragmentation)
        3. disorder (packet reordering)

        Args:
            attacks: List of attack types to combine
            params: Parameters for all attacks

        Returns:
            AttackRecipe with ordered steps

        Raises:
            ValueError: If attacks list is empty or contains incompatible combo
        """
        if not attacks:
            raise ValueError("Attacks list cannot be empty")

        # Нормализуем список: убираем пустые строки / None
        normalized_attacks = [a for a in attacks if isinstance(a, str) and a.strip()]
        if not normalized_attacks:
            raise ValueError("Attacks list contains no valid attack names")

        self.logger.debug(f"Building recipe for attacks: {normalized_attacks}")

        # Validate compatibility first
        validation = self.validate_compatibility(normalized_attacks)
        if not validation.valid:
            error_msg = "; ".join(validation.errors)
            raise ValueError(f"Incompatible attack combination: {error_msg}")

        # Log warnings if any
        for warning in validation.warnings:
            self.logger.warning(warning)

        # Merge parameters with defaults based on attacks
        merged_params = self.merge_params(normalized_attacks, params)

        # Create attack steps with proper ordering
        steps: List[AttackStep] = []

        self.logger.info(f"📋 Creating recipe with {len(normalized_attacks)} attacks")

        for attack in normalized_attacks:
            order = ATTACK_ORDER.get(attack, 999)  # Unknown attacks go last
            attack_params = self._extract_attack_params(attack, merged_params)
            step = AttackStep(
                attack_type=attack,
                order=order,
                params=attack_params,
            )
            steps.append(step)

            self.logger.info(f"  ➤ Attack: {attack} (order={order})")
            self.logger.info(f"     Params: {attack_params}")

        recipe = AttackRecipe(
            attacks=normalized_attacks,
            steps=steps,
            params=merged_params,
        )

        self.logger.info(
            "✅ Built recipe with %d steps: %s",
            len(recipe.steps),
            " → ".join(s.attack_type for s in recipe.steps),
        )

        return recipe

    def validate_compatibility(self, attacks: List[str]) -> ValidationResult:
        """
        Check if attacks can be combined without conflicts.

        Args:
            attacks: List of attack types to validate

        Returns:
            ValidationResult with validation status and messages
        """
        errors: List[str] = []
        warnings: List[str] = []

        if not attacks:
            errors.append("Attacks list cannot be empty")
            return ValidationResult(valid=False, errors=errors, warnings=warnings)

        attack_set = set(attacks)

        # Incompatible combinations
        for incompatible_combo in INCOMPATIBLE_COMBOS:
            if incompatible_combo.issubset(attack_set):
                errors.append(
                    f"Incompatible combination: {', '.join(sorted(incompatible_combo))} "
                    "cannot be used together"
                )

        # Warning combinations (allowed but not recommended)
        for warning_combo in WARNING_COMBOS:
            if warning_combo.issubset(attack_set):
                warnings.append(
                    f"Potentially redundant combination: {', '.join(sorted(warning_combo))} "
                    "may duplicate functionality. Consider using only one."
                )

        # Unknown attacks
        unknown_attacks = attack_set - KNOWN_ATTACKS
        if unknown_attacks:
            warnings.append(
                f"Unknown attack types: {', '.join(sorted(unknown_attacks))}. "
                "These will be executed last."
            )

        # Duplicates: предупреждаем, но НЕ удаляем (атак может быть несколько раз)
        if len(attacks) != len(attack_set):
            warnings.append(
                "Duplicate attacks detected; they will be executed in the order specified"
            )

        # Комбинированная атака вместе с её компонентами
        if "fakeddisorder" in attack_set:
            if "fake" in attack_set or "disorder" in attack_set:
                warnings.append(
                    "fakeddisorder is a combined attack. "
                    "Separate fake/disorder entries are usually redundant."
                )

        is_valid = not errors

        if is_valid:
            self.logger.debug(f"Attack combination is valid: {attacks}")
        else:
            self.logger.error(f"Invalid attack combination: {errors}")

        return ValidationResult(valid=is_valid, errors=errors, warnings=warnings)

    def merge_params(self, attacks: List[str], params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge parameters for all attacks, applying sensible defaults.

        Defaults (applied only if параметр отсутствует в params):
        - fake / fakeddisorder / disorder_short_ttl_decoy:
            ttl=3, fooling="badsum", fake_sni=True
        - split / multisplit:
            split_pos=2, multisplit: split_count=8, positions (равномерно)
        - disorder / fakeddisorder:
            disorder_method="reverse"

        Args:
            attacks: List of attack types
            params: Input parameters

        Returns:
            Merged parameters dictionary (copy; исходный params не модифицируется)
        """
        merged = dict(params)  # защитная копия

        attack_set = set(attacks)

        # Fake-like attacks
        if {"fake", "fakeddisorder", "disorder_short_ttl_decoy"} & attack_set:
            merged.setdefault("ttl", 3)
            merged.setdefault("fooling", "badsum")
            merged.setdefault("fake_sni", True)

        # Split / multisplit
        if {"split", "multisplit"} & attack_set:
            merged.setdefault("split_pos", 2)

            if "multisplit" in attack_set:
                merged.setdefault("split_count", 8)
                if "positions" not in merged or merged["positions"] is None:
                    split_count = int(merged["split_count"])
                    base_pos = int(merged.get("split_pos", 3))
                    # Простейшая равномерная генерация позиций
                    merged["positions"] = [base_pos + i * 6 for i in range(split_count)]

        # Disorder-like attacks
        if {"disorder", "fakeddisorder"} & attack_set:
            merged.setdefault("disorder_method", "reverse")

        self.logger.debug(f"Merged parameters: {merged}")
        return merged

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _extract_attack_params(self, attack: str, all_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract parameters relevant to a specific attack.

        Args:
            attack: Attack type (e.g., "fake", "split")
            all_params: All merged parameters

        Returns:
            Dictionary of parameters relevant to this attack
        """
        relevant_params = ATTACK_PARAM_MAPPING.get(attack, [])

        extracted: Dict[str, Any] = {}
        for key in relevant_params:
            if key in all_params:
                extracted[key] = all_params[key]

        # Добавляем общие параметры, если они есть
        for common_key in COMMON_PARAMS:
            if common_key in all_params:
                extracted[common_key] = all_params[common_key]

        return extracted
