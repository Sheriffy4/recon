# Файл: core/unified_bypass_engine_init.py
"""
Initialization helpers for UnifiedBypassEngine.

This module extracts component initialization logic from the main engine
to reduce complexity and improve maintainability.
"""

import logging
from typing import Optional, Tuple, Any
from collections import defaultdict

# Import availability flags and components
try:
    from core.bypass.attacks.attack_registry import AttackRegistry
    from core.bypass.strategies.pool_management import StrategyPoolManager
    from core.bypass.modes.mode_controller import ModeController
    from core.bypass.validation.reliability_validator import ReliabilityValidator
    from core.bypass.protocols.multi_port_handler import MultiPortHandler

    MODERN_BYPASS_ENGINE_AVAILABLE = True
except ImportError:
    MODERN_BYPASS_ENGINE_AVAILABLE = False
    AttackRegistry = None
    StrategyPoolManager = None
    ModeController = None
    ReliabilityValidator = None
    MultiPortHandler = None

try:
    from core.fingerprint.advanced_fingerprinter import (
        AdvancedFingerprinter,
        FingerprintingConfig,
    )

    ADVANCED_FINGERPRINTING_AVAILABLE = True
except ImportError:
    ADVANCED_FINGERPRINTING_AVAILABLE = False
    AdvancedFingerprinter = None
    FingerprintingConfig = None

try:
    CdnAsnKnowledgeBase = None  # Placeholder for future implementation
except Exception:
    CdnAsnKnowledgeBase = None

from core.monitoring.accessibility_metrics import AccessibilityMetricsCollector
from core.diagnostics.accessibility_diagnostics import AccessibilityDiagnostics
from core.logging.accessibility_logging import configure_standard_logging, LogLevel


class ModernBypassComponents:
    """Container for modern bypass engine components."""

    def __init__(self):
        self.enabled = False
        self.attack_registry = None
        self.pool_manager = None
        self.mode_controller = None
        self.reliability_validator = None
        self.multi_port_handler = None


class AdvancedFingerprintingComponents:
    """Container for advanced fingerprinting components."""

    def __init__(self):
        self.enabled = False
        self.fingerprinter = None


def init_modern_bypass_components(
    enable_modern_bypass: bool, verbosity: str, debug: bool, logger: logging.Logger
) -> ModernBypassComponents:
    """
    Initialize modern bypass engine components.

    Args:
        enable_modern_bypass: Whether to enable modern bypass features
        verbosity: Logging verbosity level
        debug: Debug mode flag
        logger: Logger instance

    Returns:
        ModernBypassComponents: Container with initialized components
    """
    components = ModernBypassComponents()
    components.enabled = enable_modern_bypass and MODERN_BYPASS_ENGINE_AVAILABLE

    if components.enabled:
        try:
            # Prefer shared registry instance if available to reduce repeated init/registration logs
            try:
                from core.bypass.attacks.attack_registry import get_attack_registry
            except Exception:
                get_attack_registry = None

            components.attack_registry = (
                get_attack_registry() if get_attack_registry else AttackRegistry()
            )

            # Reduce registry log spam unless verbose/debug
            if verbosity not in ("debug", "verbose") and not debug:
                logging.getLogger("core.bypass.attacks.attack_registry").setLevel(logging.WARNING)

            components.pool_manager = StrategyPoolManager()
            components.mode_controller = ModeController()
            components.reliability_validator = ReliabilityValidator()
            components.multi_port_handler = MultiPortHandler()
            logger.info("Modern bypass engine components initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize modern bypass engine: {e}")
            components.enabled = False

    return components


def init_advanced_fingerprinting(
    enable_advanced_fingerprinting: bool, logger: logging.Logger
) -> AdvancedFingerprintingComponents:
    """
    Initialize advanced fingerprinting components.

    Args:
        enable_advanced_fingerprinting: Whether to enable advanced fingerprinting
        logger: Logger instance

    Returns:
        AdvancedFingerprintingComponents: Container with initialized components
    """
    components = AdvancedFingerprintingComponents()
    components.enabled = enable_advanced_fingerprinting and ADVANCED_FINGERPRINTING_AVAILABLE

    if components.enabled:
        try:
            fingerprint_config = FingerprintingConfig(
                cache_ttl=3600,
                enable_ml=True,
                enable_cache=True,
                timeout=15.0,
                fallback_on_error=True,
            )
            components.fingerprinter = AdvancedFingerprinter(config=fingerprint_config)
            logger.info("Advanced fingerprinting initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize advanced fingerprinting: {e}")
            components.enabled = False

    return components


def init_monitoring_components(
    verbosity: str, logger: logging.Logger
) -> Tuple[AccessibilityMetricsCollector, AccessibilityDiagnostics, Any, Any]:
    """
    Initialize monitoring and diagnostics components.

    Args:
        verbosity: Logging verbosity level
        logger: Logger instance

    Returns:
        Tuple containing:
        - AccessibilityMetricsCollector
        - AccessibilityDiagnostics
        - Logging config
        - Accessibility logger
    """
    metrics_collector = AccessibilityMetricsCollector(logger=logger)
    diagnostics = AccessibilityDiagnostics(logger=logger)
    logging_config = configure_standard_logging(log_to_file=False)

    # Configure accessibility-specific logging
    if verbosity in ("debug", "verbose"):
        logging_config.set_verbosity_level(LogLevel.DEBUG)
    elif verbosity == "silent":
        logging_config.set_verbosity_level(LogLevel.SILENT)

    accessibility_logger = logging_config.configure_logging("accessibility")

    return metrics_collector, diagnostics, logging_config, accessibility_logger


def init_cache_and_validation(
    logger: logging.Logger, validator_class: Any
) -> Tuple[dict, Any, int, Any]:
    """
    Initialize cache and validation components.

    Args:
        logger: Logger instance
        validator_class: CurlCommandValidator class (passed to avoid circular import)

    Returns:
        Tuple containing:
        - Accessibility cache dict
        - Cache lock
        - Cache TTL
        - Curl command validator
    """
    import threading

    accessibility_cache = {}
    cache_lock = threading.Lock()
    cache_ttl = 300  # Cache TTL in seconds (5 minutes)
    curl_command_validator = validator_class(logger=logger)

    return accessibility_cache, cache_lock, cache_ttl, curl_command_validator


def init_knowledge_base() -> Optional[Any]:
    """
    Initialize CDN ASN knowledge base if available.

    Returns:
        Knowledge base instance or None
    """
    return CdnAsnKnowledgeBase() if CdnAsnKnowledgeBase else None


def init_stats_and_state() -> Tuple[dict, dict, dict, int]:
    """
    Initialize statistics and state tracking.

    Returns:
        Tuple containing:
        - Fingerprint stats
        - Bypass stats
        - Strategy applications
        - Forced override count
    """
    fingerprint_stats = defaultdict(int)
    bypass_stats = defaultdict(int)
    strategy_applications = {}
    forced_override_count = 0

    return fingerprint_stats, bypass_stats, strategy_applications, forced_override_count
