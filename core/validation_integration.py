"""
Validation Integration Module

This module provides integration between the packet validation system
and the main CLI/service execution flows. It handles:
- Conditional validation based on --validate flag
- PCAP file discovery and validation
- Result reporting and logging
- Performance-aware validation (optional, non-blocking)

Usage:
    # In CLI auto mode:
    if args.validate:
        validator = ValidationIntegrator(args)
        validator.validate_strategy_execution(domain, strategy, pcap_file)

    # In service mode:
    if enable_validation:
        validator = ValidationIntegrator(enable_validation=True)
        validator.validate_attack_application(domain, strategy, pcap_file)
"""

import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ValidationConfig:
    """Configuration for validation integration."""

    enabled: bool = False
    verbose: bool = False
    save_reports: bool = True
    report_dir: str = "validation_results"
    fail_on_validation_error: bool = False
    timeout_seconds: float = 5.0


class ValidationIntegrator:
    """
    Integrates packet validation into CLI and service execution flows.

    This class provides a clean interface for optional validation that:
    - Doesn't block main execution
    - Provides clear logging
    - Handles errors gracefully
    - Supports both CLI and service modes
    - Automatically enables PCAP capture when validation is enabled
    """

    def __init__(self, args=None, config: Optional[ValidationConfig] = None):
        """
        Initialize validation integrator.

        Args:
            args: CLI arguments (if available)
            config: Validation configuration (if not using args)
        """
        if config:
            self.config = config
        elif args:
            self.config = ValidationConfig(
                enabled=getattr(args, "validate", False),
                verbose=getattr(args, "debug", False),
                save_reports=True,
                report_dir="validation_results",
                fail_on_validation_error=False,
            )

            # CRITICAL: Auto-enable PCAP capture when validation is enabled
            if self.config.enabled and not getattr(args, "pcap", None):
                # Set default PCAP path for validation
                from pathlib import Path

                pcap_dir = Path("temp_pcap")
                pcap_dir.mkdir(exist_ok=True)

                # Use timestamp-based filename to avoid conflicts
                from datetime import datetime

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                args.pcap = str(pcap_dir / f"validation_{timestamp}.pcap")

                logger.info(f"Auto-enabled PCAP capture for validation: {args.pcap}")
        else:
            self.config = ValidationConfig()

        self.validator = None
        if self.config.enabled:
            try:
                from core.packet_validator import PacketValidator

                self.validator = PacketValidator(debug_mode=self.config.verbose)
                logger.info("Packet validator initialized")
            except ImportError as e:
                logger.warning(f"Packet validator not available: {e}")
                self.config.enabled = False

    def validate_strategy_execution(
        self,
        domain: str,
        strategy: Dict[str, Any],
        pcap_file: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate strategy execution against PCAP capture.

        Args:
            domain: Target domain
            strategy: Strategy dictionary with 'attacks' and 'params'
            pcap_file: Path to PCAP file (if None, will try to find it)

        Returns:
            Validation result dictionary or None if validation disabled/failed
        """
        if not self.config.enabled or not self.validator:
            return None

        try:
            # Find PCAP file if not provided
            if not pcap_file:
                pcap_file = self._find_pcap_file(domain)
                if not pcap_file:
                    logger.debug(f"No PCAP file found for {domain}, skipping validation")
                    return None

            # Check if PCAP file exists
            if not Path(pcap_file).exists():
                logger.warning(f"PCAP file not found: {pcap_file}")
                return None

            # Extract attack info
            attack_name = strategy.get("type", "unknown")
            attacks = strategy.get("attacks", [attack_name])
            params = strategy.get("params", {})

            # Use first attack for validation (combo attacks validated as single unit)
            primary_attack = attacks[0] if attacks else attack_name

            logger.info(f"[VALIDATION] Validating {primary_attack} for {domain}")
            logger.debug(f"  PCAP: {pcap_file}")
            logger.debug(f"  Attacks: {attacks}")
            logger.debug(f"  Params: {params}")

            # Run validation with timeout
            start_time = time.time()
            result = self.validator.validate_attack_with_spec(primary_attack, params, pcap_file)
            elapsed = time.time() - start_time

            # Log results
            if result.passed:
                logger.info(f"[VALIDATION] PASS: {primary_attack} for {domain} ({elapsed:.2f}s)")
                if self.config.verbose:
                    logger.info(f"  Packet count: {result.packet_count}")
                    logger.info(f"  Rules passed: {len([d for d in result.details if d.passed])}")
            else:
                logger.warning(f"[VALIDATION] FAIL: {primary_attack} for {domain} ({elapsed:.2f}s)")
                logger.warning(f"  Packet count: {result.packet_count}")

                # Log critical issues
                critical = result.get_critical_issues()
                if critical:
                    logger.warning(f"  Critical issues: {len(critical)}")
                    for issue in critical[:3]:  # Show first 3
                        logger.warning(f"    - {issue.aspect}: {issue.message}")

                # Log errors
                errors = result.get_errors()
                if errors:
                    logger.warning(f"  Errors: {len(errors)}")
                    if self.config.verbose:
                        for error in errors[:5]:  # Show first 5
                            logger.warning(f"    - {error.aspect}: {error.message}")

            # Save report if configured
            if self.config.save_reports:
                self._save_validation_report(domain, primary_attack, result)

            # Convert to dict for return
            return result.to_dict()

        except Exception as e:
            logger.error(f"[VALIDATION] Error validating {domain}: {e}")
            if self.config.verbose:
                import traceback

                logger.debug(traceback.format_exc())

            if self.config.fail_on_validation_error:
                raise

            return None

    def validate_attack_application(
        self,
        domain: str,
        attack_name: str,
        params: Dict[str, Any],
        pcap_file: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate attack application in service mode.

        Args:
            domain: Target domain
            attack_name: Attack type
            params: Attack parameters
            pcap_file: Path to PCAP file

        Returns:
            Validation result dictionary or None if validation disabled/failed
        """
        if not self.config.enabled or not self.validator:
            return None

        try:
            logger.info(f"[SERVICE VALIDATION] Validating {attack_name} for {domain}")

            # Run validation
            start_time = time.time()
            result = self.validator.validate_attack_with_spec(attack_name, params, pcap_file)
            elapsed = time.time() - start_time

            # Log results (more concise for service mode)
            status = "PASS" if result.passed else "FAIL"
            logger.info(
                f"[SERVICE VALIDATION] {status}: {attack_name} for {domain} "
                f"({result.packet_count} packets, {elapsed:.2f}s)"
            )

            if not result.passed and self.config.verbose:
                critical = result.get_critical_issues()
                errors = result.get_errors()
                logger.warning(f"  Issues: {len(critical)} critical, {len(errors)} errors")

            # Save report
            if self.config.save_reports:
                self._save_validation_report(domain, attack_name, result)

            return result.to_dict()

        except Exception as e:
            logger.error(f"[SERVICE VALIDATION] Error: {e}")
            if self.config.verbose:
                import traceback

                logger.debug(traceback.format_exc())
            return None

    def _find_pcap_file(self, domain: str) -> Optional[str]:
        """
        Find PCAP file for domain.

        Searches in common locations:
        - temp_pcap/{domain}.pcap
        - temp_pcap/{domain}_*.pcap
        - {domain}.pcap
        - temp_pcap/validation_*.pcap (most recent)

        Args:
            domain: Domain name

        Returns:
            Path to PCAP file or None
        """
        # Common PCAP locations
        search_paths = [
            Path("temp_pcap") / f"{domain}.pcap",
            Path("temp_pcap") / f"{domain}_test.pcap",
            Path(f"{domain}.pcap"),
        ]

        # Check exact matches first
        for path in search_paths:
            if path.exists():
                return str(path)

        # Check for wildcard matches in temp_pcap
        temp_pcap_dir = Path("temp_pcap")
        if temp_pcap_dir.exists():
            # Find most recent PCAP for domain
            pcap_files = list(temp_pcap_dir.glob(f"{domain}*.pcap"))
            if pcap_files:
                # Sort by modification time, return most recent
                pcap_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                return str(pcap_files[0])

            # Fallback: find most recent validation_*.pcap
            validation_pcaps = list(temp_pcap_dir.glob("validation_*.pcap"))
            if validation_pcaps:
                # Sort by modification time, return most recent
                validation_pcaps.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                logger.debug(f"Using most recent validation PCAP: {validation_pcaps[0]}")
                return str(validation_pcaps[0])

        return None

    def _save_validation_report(
        self,
        domain: str,
        attack_name: str,
        result,
    ):
        """
        Save validation report to file.

        Args:
            domain: Domain name
            attack_name: Attack type
            result: ValidationResult object
        """
        try:
            import json
            from datetime import datetime

            # Create report directory
            report_dir = Path(self.config.report_dir)
            report_dir.mkdir(exist_ok=True)

            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{domain}_{attack_name}_{timestamp}.json"
            report_path = report_dir / filename

            # Save report
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2)

            logger.debug(f"[VALIDATION] Report saved: {report_path}")

        except Exception as e:
            logger.warning(f"[VALIDATION] Failed to save report: {e}")


def create_validator_from_args(args) -> Optional[ValidationIntegrator]:
    """
    Create ValidationIntegrator from CLI arguments.

    Args:
        args: Parsed CLI arguments

    Returns:
        ValidationIntegrator instance or None if validation disabled
    """
    if not getattr(args, "validate", False):
        return None

    return ValidationIntegrator(args=args)


def create_validator_for_service(enable_validation: bool = False) -> Optional[ValidationIntegrator]:
    """
    Create ValidationIntegrator for service mode.

    Args:
        enable_validation: Whether to enable validation

    Returns:
        ValidationIntegrator instance or None if validation disabled
    """
    if not enable_validation:
        return None

    config = ValidationConfig(
        enabled=True,
        verbose=False,  # Less verbose in service mode
        save_reports=True,
        fail_on_validation_error=False,  # Never fail in service mode
    )

    return ValidationIntegrator(config=config)
