#!/usr/bin/env python3
"""
Strategy Application Logger

Provides detailed logging of strategy application in production mode,
helping diagnose testing-production parity issues.

Requirements: 7.1, 7.2, 7.3, 7.4
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
from .strategy_validator import ValidationResult

LOG = logging.getLogger(__name__)


class StrategyApplicationLogger:
    """
    Logs detailed information about strategy application.

    This logger provides comprehensive diagnostics for strategy application,
    including domain matching, validation results, and recommendations when
    strategies fail to apply correctly.
    """

    def __init__(self, verbose: bool = False, log_file: Optional[str] = None):
        """
        Initialize the Strategy Application Logger.

        Args:
            verbose: If True, log additional debug information
            log_file: Optional file path to write verbose logs to
        """
        self.verbose = verbose
        self.log_file = log_file
        self.application_count = 0
        self.validation_failures = 0
        self.validation_warnings = 0

        # Set up file handler if log_file is provided
        if self.log_file:
            try:
                file_handler = logging.FileHandler(self.log_file, mode="a", encoding="utf-8")
                file_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
                formatter = logging.Formatter(
                    "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
                file_handler.setFormatter(formatter)
                LOG.addHandler(file_handler)
                LOG.info(f"Verbose strategy logging enabled, writing to: {self.log_file}")
            except Exception as e:
                LOG.error(f"Failed to set up log file handler: {e}")

    def log_strategy_application(
        self,
        domain: str,
        sni: str,
        matched_rule: Optional[str],
        match_type: str,
        strategy: Dict[str, Any],
        validation_result: ValidationResult,
    ):
        """
        Log detailed information about strategy application.

        Args:
            domain: Domain being accessed
            sni: SNI extracted from packet
            matched_rule: The rule that was matched (or None)
            match_type: Type of match ('exact', 'wildcard', 'parent', 'none')
            strategy: Strategy configuration being applied
            validation_result: Result of strategy validation

        Requirements: 7.1, 7.2, 7.3, 7.4
        """
        self.application_count += 1

        # Log header
        LOG.info("=" * 80)
        LOG.info("STRATEGY APPLICATION")
        LOG.info("=" * 80)

        # Log domain information (Requirement 7.1)
        LOG.info(f"Domain: {domain}")
        LOG.info(f"SNI: {sni}")
        LOG.info(f"Matched Rule: {matched_rule if matched_rule else 'None (using default)'}")
        LOG.info(f"Match Type: {match_type}")

        # Log strategy information (Requirement 7.1)
        strategy_type = strategy.get("type", "unknown")
        LOG.info(f"Strategy Type: {strategy_type}")

        # Log strategy parameters (Requirement 7.1)
        params = strategy.get("params", {})
        if params:
            LOG.info("Strategy Parameters:")
            for key, value in params.items():
                LOG.info(f"  - {key}: {value}")
        else:
            LOG.info("Strategy Parameters: None")

        # Log attack combination if present
        if "attacks" in strategy:
            attacks = strategy["attacks"]
            LOG.info(f"Attack Combination: {attacks}")
            if len(attacks) > 1:
                LOG.info(f"  → Combo strategy with {len(attacks)} attacks")

        # Log validation results (Requirement 7.2, 7.3)
        if validation_result.valid:
            LOG.info("Validation: ✅ PASSED")

            # Log warnings if present (Requirement 7.3)
            if validation_result.warning:
                self.validation_warnings += 1
                LOG.warning(f"⚠️ Warning: {validation_result.warning}")
                if validation_result.recommendation:
                    LOG.warning(f"💡 Recommendation: {validation_result.recommendation}")
        else:
            self.validation_failures += 1
            LOG.error("Validation: ❌ FAILED")
            LOG.error(f"Reason: {validation_result.reason}")

            # Log parameter mismatches if present
            if validation_result.mismatches:
                LOG.error("Parameter Mismatches:")
                for mismatch in validation_result.mismatches:
                    LOG.error(f"  - {mismatch}")

            # Log recommendation (Requirement 7.4)
            if validation_result.recommendation:
                LOG.error(f"💡 Recommendation: {validation_result.recommendation}")

        # Log match type specific information
        if match_type == "parent":
            LOG.warning(f"⚠️ Using parent domain fallback for {domain}")
            LOG.warning(f"💡 Consider creating a specific rule for '{domain}' in domain_rules.json")
        elif match_type == "wildcard":
            LOG.info(f"✅ Using wildcard rule: {matched_rule}")
        elif match_type == "exact":
            LOG.info(f"✅ Using exact match rule: {matched_rule}")
        elif match_type == "none":
            LOG.warning("⚠️ No matching rule found, using default strategy")
            LOG.warning(f"💡 Run 'cli.py auto {domain}' to find a working strategy")

        # Log verbose information if enabled
        if self.verbose:
            LOG.debug(f"Application Count: {self.application_count}")
            LOG.debug(f"Validation Failures: {self.validation_failures}")
            LOG.debug(f"Validation Warnings: {self.validation_warnings}")
            LOG.debug(f"Timestamp: {datetime.now().isoformat()}")

        LOG.info("=" * 80)

    def log_strategy_failure(
        self,
        domain: str,
        strategy: Dict[str, Any],
        retransmissions: int,
        reason: Optional[str] = None,
    ):
        """
        Log strategy failure with retransmission information.

        Args:
            domain: Domain that failed
            strategy: Strategy that was applied
            retransmissions: Number of retransmissions detected
            reason: Optional reason for failure

        Requirements: 7.2, 7.3, 7.4, 8.1, 8.2, 8.3
        """
        LOG.error("=" * 80)
        LOG.error("STRATEGY FAILURE DETECTED")
        LOG.error("=" * 80)
        LOG.error(f"Domain: {domain}")
        LOG.error(f"Strategy Type: {strategy.get('type', 'unknown')}")
        LOG.error(f"Retransmissions: {retransmissions}")

        if reason:
            LOG.error(f"Reason: {reason}")

        # Log strategy parameters for debugging (Requirement 7.3)
        params = strategy.get("params", {})
        if params:
            LOG.error("Strategy Parameters:")
            for key, value in params.items():
                LOG.error(f"  - {key}: {value}")

        # Log attack combination if present (Requirement 7.3)
        if "attacks" in strategy:
            attacks = strategy["attacks"]
            LOG.error(f"Attack Combination: {attacks}")
            if len(attacks) > 1:
                LOG.error(f"  → Combo strategy with {len(attacks)} attacks")

        # Provide detailed recommendations (Requirement 7.4, 8.2, 8.3)
        LOG.error("💡 RECOMMENDATIONS:")
        LOG.error(f"  1. Verify strategy in domain_rules.json for '{domain}'")
        LOG.error(f"  2. Run 'cli.py test {domain}' to re-test the strategy")
        LOG.error(f"  3. Run 'cli.py auto {domain}' to find a new working strategy")

        # Add parent domain recommendation if applicable (Requirement 8.2, 8.3)
        if "." in domain:
            parts = domain.split(".")
            if len(parts) > 2:  # Has subdomain
                parent_domain = ".".join(parts[1:])
                LOG.error(
                    f"  4. Try removing '{domain}' rule to use parent domain '{parent_domain}' strategy"
                )
                LOG.error(f"     Edit domain_rules.json and remove the '{domain}' entry")
                LOG.error("  5. Check if DPI behavior has changed")
            else:
                LOG.error("  4. Check if DPI behavior has changed")
        else:
            LOG.error("  4. Check if DPI behavior has changed")

        # Enhanced warning for high retransmission count (Requirement 7.3, 8.1)
        if retransmissions >= 3:
            LOG.error(
                f"⚠️ CRITICAL: High retransmission count ({retransmissions}) indicates strategy is NOT working"
            )
            LOG.error(
                "   This strategy has failed the threshold and should be replaced immediately"
            )
            LOG.error("   The connection is likely blocked by DPI despite bypass attempts")

        LOG.error("=" * 80)

    def log_retransmission_detected(
        self,
        domain: str,
        strategy: Dict[str, Any],
        retransmission_number: int,
        flow_key: tuple,
        seq_num: int,
    ):
        """
        Log individual retransmission detection with context.

        Args:
            domain: Domain being accessed
            strategy: Strategy being applied
            retransmission_number: Current retransmission count for this domain/strategy
            flow_key: TCP flow identifier (src_ip, src_port, dst_ip, dst_port)
            seq_num: TCP sequence number

        Requirements: 7.2
        """
        LOG.warning("=" * 80)
        LOG.warning(f"RETRANSMISSION #{retransmission_number} DETECTED")
        LOG.warning("=" * 80)
        LOG.warning(f"Domain: {domain}")
        LOG.warning(f"Strategy Type: {strategy.get('type', 'unknown')}")
        LOG.warning(f"Flow: {flow_key}")
        LOG.warning(f"Sequence Number: 0x{seq_num:08X}")

        # Log strategy parameters for context
        params = strategy.get("params", {})
        if params:
            LOG.warning("Strategy Parameters:")
            for key, value in params.items():
                LOG.warning(f"  - {key}: {value}")

        # Provide progressive warnings based on retransmission count
        if retransmission_number == 1:
            LOG.warning("ℹ️  First retransmission - this may be normal network behavior")
        elif retransmission_number == 2:
            LOG.warning("⚠️  Second retransmission - strategy may not be working correctly")
        elif retransmission_number >= 3:
            LOG.warning("🚨 Third+ retransmission - strategy is likely failing")
            LOG.warning("   Consider re-testing or finding a new strategy")

        LOG.warning("=" * 80)

    def log_testing_production_mismatch(
        self,
        domain: str,
        testing_strategy: Dict[str, Any],
        production_strategy: Dict[str, Any],
        differences: list,
    ):
        """
        Log when testing and production strategies differ.

        Args:
            domain: Domain being accessed
            testing_strategy: Strategy used in testing mode
            production_strategy: Strategy used in production mode
            differences: List of differences detected

        Requirements: 7.3, 7.4
        """
        LOG.error("=" * 80)
        LOG.error("TESTING-PRODUCTION PARITY ISSUE DETECTED")
        LOG.error("=" * 80)
        LOG.error(f"Domain: {domain}")
        LOG.error(f"Testing Strategy Type: {testing_strategy.get('type', 'unknown')}")
        LOG.error(f"Production Strategy Type: {production_strategy.get('type', 'unknown')}")

        LOG.error("Differences Detected:")
        for diff in differences:
            LOG.error(f"  - {diff}")

        # Provide detailed recommendations (Requirement 7.4)
        LOG.error("💡 Recommendations:")
        LOG.error(f"  1. Check domain_rules.json for '{domain}'")
        LOG.error("  2. Verify that the strategy was saved correctly after testing")
        LOG.error("  3. Ensure no manual edits were made to domain_rules.json")
        LOG.error(f"  4. Re-run 'cli.py auto {domain}' to regenerate the strategy")
        LOG.error("  5. Check for parent domain conflicts (e.g., youtube.com vs www.youtube.com)")

        LOG.error("=" * 80)

    def log_multisplit_application(
        self, domain: str, positions: list, split_count: int, fragment_count: int
    ):
        """
        Log multisplit strategy application details.

        Args:
            domain: Domain being accessed
            positions: Split positions used
            split_count: Expected split count
            fragment_count: Actual number of fragments sent

        Requirements: 7.1, 7.2
        """
        LOG.info("=" * 80)
        LOG.info("MULTISPLIT STRATEGY APPLICATION")
        LOG.info("=" * 80)
        LOG.info(f"Domain: {domain}")
        LOG.info(f"Split Positions: {positions}")
        LOG.info(f"Expected Split Count: {split_count}")
        LOG.info(f"Actual Fragment Count: {fragment_count}")

        if fragment_count != split_count:
            LOG.warning(f"⚠️ Fragment count mismatch: expected {split_count}, got {fragment_count}")
            LOG.warning("💡 This may indicate an issue with multisplit generation")
        else:
            LOG.info("✅ Fragment count matches expected split count")

        LOG.info("=" * 80)

    def log_first_connection(self, domain: str, strategy: Dict[str, Any], is_correct: bool):
        """
        Log first connection strategy application.

        Args:
            domain: Domain being accessed
            strategy: Strategy applied to first connection
            is_correct: Whether the correct strategy was applied

        Requirements: 7.1, 7.2, 7.4
        """
        LOG.info("=" * 80)
        LOG.info("FIRST CONNECTION TO DOMAIN")
        LOG.info("=" * 80)
        LOG.info(f"Domain: {domain}")
        LOG.info(f"Strategy Type: {strategy.get('type', 'unknown')}")

        if is_correct:
            LOG.info("✅ Correct strategy applied to first connection")
        else:
            LOG.error("❌ Incorrect strategy applied to first connection")
            LOG.error("💡 Recommendations:")
            LOG.error(f"  1. Check domain_rules.json for '{domain}'")
            LOG.error("  2. Verify strategy loading at service startup")
            LOG.error("  3. Check for parent domain conflicts")

        LOG.info("=" * 80)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get logger statistics.

        Returns:
            Dictionary containing logger statistics
        """
        return {
            "application_count": self.application_count,
            "validation_failures": self.validation_failures,
            "validation_warnings": self.validation_warnings,
            "failure_rate": self.validation_failures / max(1, self.application_count),
        }

    def reset_statistics(self):
        """Reset logger statistics."""
        self.application_count = 0
        self.validation_failures = 0
        self.validation_warnings = 0
